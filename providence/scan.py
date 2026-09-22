"""Network/client scanning via airodump-ng.

airodump-ng writes a CSV every `--write-interval` seconds. Rather than screen-
scrape its curses UI, we run it headless into a temp CSV and parse that file on
a timer. This is the same approach wifite uses and it's far more reliable than
parsing terminal output.
"""

from __future__ import annotations

import glob
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from .util import LogFn, is_mac, spawn, terminate

# Bounds so a beacon/probe flood (thousands of forged BSSIDs) can't make the
# root process read/parse/allocate without limit.
MAX_CSV_BYTES = 4_000_000   # cap how much of the (cumulative) CSV we read
MAX_ROWS = 5000             # cap APs/stations parsed per poll


@dataclass
class AccessPoint:
    bssid: str
    channel: str
    privacy: str
    cipher: str
    auth: str
    power: str
    beacons: str
    essid: str
    clients: int = 0          # filled in from the station section

    def _priv(self) -> str:
        return (self.privacy or "").upper()

    def _auth(self) -> str:
        return (self.auth or "").upper()

    def is_wpa(self) -> bool:
        return "WPA" in self._priv()

    def is_wpa3(self) -> bool:
        return "WPA3" in self._priv() or "SAE" in self._auth()

    def is_enterprise(self) -> bool:
        return "MGT" in self._auth() or "802.1X" in self._auth()

    def is_owe(self) -> bool:
        return "OWE" in self._priv() or "OWE" in self._auth()

    def is_wep(self) -> bool:
        return "WEP" in self._priv()

    def is_open(self) -> bool:
        return "OPN" in self._priv()

    def is_sae_only(self) -> bool:
        # Pure WPA3-SAE (no WPA2 transition) has no crackable PSK 4-way handshake.
        return self.is_wpa3() and "PSK" not in self._auth()

    def is_capturable(self) -> bool:
        """True only for WPA/WPA2 (incl. WPA2/WPA3 transition) PSK networks —
        the ones that actually expose a 4-way handshake / PMKID to capture."""
        return (self.is_wpa() and not self.is_enterprise()
                and not self.is_sae_only() and not self.is_wep())

    def security_note(self) -> str:
        """Empty if capturable; otherwise why this target has nothing to grab."""
        if self.is_capturable():
            return ""
        if self.is_sae_only():
            return "WPA3-SAE: no crackable 4-way handshake / PMKID"
        if self.is_enterprise():
            return "Enterprise (802.1X/MGT): no PSK handshake to capture"
        if self.is_owe():
            return "OWE / Enhanced Open: nothing to capture"
        if self.is_wep():
            return "WEP: needs a WEP attack, not handshake capture"
        if self.is_open():
            return "Open network: no handshake"
        return "No WPA-PSK handshake to capture"


@dataclass
class Station:
    mac: str
    power: str
    packets: str
    bssid: str                # associated AP, or "(not associated)"
    probed: str


def parse_csv(text: str) -> Tuple[List[AccessPoint], List[Station]]:
    """Parse an airodump-ng CSV dump into (access_points, stations).

    The file has two sections separated by a blank line, each with its own
    header row:

        BSSID, First time seen, ... , channel(4), ... , Power(9), #beacons(10), ... , ESSID(14), Key
        <ap rows>

        Station MAC, First time seen, Last time seen, Power, #packets, BSSID, Probed ESSIDs
        <station rows>
    """
    aps: List[AccessPoint] = []
    stations: List[Station] = []

    # Split on newlines only (not str.splitlines, which also breaks on a lone
    # CR that a hostile/odd ESSID may embed, spawning a phantom row).
    lines = text.replace("\r\n", "\n").split("\n")
    # Find where the station section starts.
    station_hdr = None
    for idx, line in enumerate(lines):
        if line.strip().startswith("Station MAC"):
            station_hdr = idx
            break

    ap_lines = lines[: station_hdr] if station_hdr is not None else lines
    st_lines = lines[station_hdr + 1 :] if station_hdr is not None else []

    for line in ap_lines:
        if len(aps) >= MAX_ROWS:
            break
        s = line.strip()
        if not s or s.startswith("BSSID"):
            continue
        parts = [p.strip() for p in line.split(",")]
        if len(parts) < 14:
            continue
        # Require a well-formed MAC; guards against stray/blank/hostile rows.
        if not is_mac(parts[0]):
            continue
        # ESSID may itself contain commas; everything from field 13 up to the
        # final "Key" field is the ESSID. Strip control chars for safe display.
        essid = ",".join(parts[13:-1]).strip() if len(parts) > 14 else parts[13]
        # Keep printable ASCII, tab, and >=U+00A0 (real UTF-8 SSIDs); strip C0
        # (ANSI/CSI escapes), DEL, and C1 so nothing can inject terminal escapes
        # into the on-disk audit log when it is later cat'd.
        essid = "".join(ch for ch in essid if (" " <= ch <= "~") or ch == "\t" or ch >= "\xa0")
        aps.append(
            AccessPoint(
                bssid=parts[0],
                channel=parts[3],
                privacy=parts[5],
                cipher=parts[6],
                auth=parts[7],
                power=parts[8],
                beacons=parts[9],
                essid=essid or "<hidden>",
            )
        )

    ap_by_bssid: Dict[str, AccessPoint] = {a.bssid: a for a in aps}
    for line in st_lines:
        if len(stations) >= MAX_ROWS:
            break
        s = line.strip()
        if not s or s.startswith("Station MAC"):
            continue
        parts = [p.strip() for p in line.split(",")]
        if len(parts) < 6 or not is_mac(parts[0]):
            continue
        st = Station(
            mac=parts[0],
            power=parts[3],
            packets=parts[4],
            bssid=parts[5],
            probed=",".join(parts[6:]).strip(),
        )
        stations.append(st)
        ap = ap_by_bssid.get(st.bssid)
        if ap:
            ap.clients += 1

    return aps, stations


# choice shown in the UI -> airodump-ng --band value ('a'=5GHz, 'bg'=2.4GHz).
BANDS = {"2.4 GHz": "bg", "5 GHz": "a", "2.4 + 5 GHz": "abg"}


def airodump_band(choice: str) -> str:
    """Map a UI band choice to an airodump-ng --band flag value."""
    return BANDS.get(choice, "bg")


def scan_argv(mon_iface: str, prefix: str, band_choice: str = "2.4 GHz") -> list:
    """Build the airodump-ng argv for a channel-hopping scan.

    airodump-ng already defaults to 2.4 GHz, and passing `--band bg` there has
    been observed to capture NOTHING on several mac80211 drivers (rtl8xxxu, etc.)
    while the bare default works — so we only pass `--band` for 5 GHz / dual-band.
    """
    argv = ["airodump-ng"]
    band = airodump_band(band_choice)
    if band != "bg":                         # 2.4 GHz is the default; don't force it
        argv += ["--band", band]
    argv += ["--write-interval", "1", "--output-format", "csv", "-w", prefix, mon_iface]
    return argv


class ScanSession:
    """Runs a channel-hopping airodump-ng scan and exposes parsed results."""

    def __init__(self, mon_iface: str, band: str = "2.4 GHz", log: Optional[LogFn] = None):
        self.mon_iface = mon_iface
        self.band = band
        self.log = log
        self._proc: Optional[subprocess.Popen] = None
        self._tmpdir: Optional[str] = None
        self._prefix: Optional[str] = None
        self._logfh = None
        self._logpath: Optional[str] = None

    def start(self) -> None:
        self._tmpdir = tempfile.mkdtemp(prefix="providence-scan-")
        self._prefix = os.path.join(self._tmpdir, "scan")
        self._logpath = os.path.join(self._tmpdir, "airodump.log")
        self._logfh = open(self._logpath, "w")
        self._proc = spawn(scan_argv(self.mon_iface, self._prefix, self.band),
                           log=self.log, out=self._logfh, tty=True)

    def latest(self) -> Tuple[List[AccessPoint], List[Station]]:
        """Read and parse the most recent CSV airodump has written so far."""
        if not self._prefix:
            return [], []
        files = glob.glob(self._prefix + "-*.csv")
        if not files:
            return [], []
        # Newest by mtime — lexicographic sort puts "-100" before "-99".
        newest = max(files, key=lambda p: os.path.getmtime(p))
        try:
            with open(newest, "r", errors="replace") as f:
                text = f.read(MAX_CSV_BYTES)   # bounded read (beacon-flood safety)
        except OSError:
            return [], []
        return parse_csv(text)

    def diagnostic(self) -> str:
        """Describe the CSV state so a '0 networks' can be diagnosed from the log:
        does the file exist, how big is it, what do its first AP lines look like,
        and how many rows parse."""
        if not self._prefix:
            return "no scan prefix"
        files = glob.glob(self._prefix + "-*.csv")
        if not files:
            return f"no CSV yet at {self._prefix}-*.csv (airodump not writing?)"
        newest = max(files, key=lambda p: os.path.getmtime(p))
        try:
            with open(newest, "r", errors="replace") as f:
                text = f.read(MAX_CSV_BYTES)
        except OSError as e:
            return f"cannot read {newest}: {e}"
        aps, sta = parse_csv(text)
        # First non-empty, non-header data line, for format inspection.
        sample = ""
        for ln in text.replace("\r\n", "\n").split("\n"):
            s = ln.strip()
            if s and not s.startswith("BSSID") and not s.startswith("Station MAC"):
                sample = s[:160]
                break
        return (f"csv={os.path.basename(newest)} bytes={len(text)} parsed_aps={len(aps)} "
                f"parsed_sta={len(sta)} first_data_line={sample!r}")

    def log_tail(self, n: int = 8) -> str:
        """Last few lines airodump wrote - used to explain an unexpected exit."""
        if not self._logpath or not os.path.exists(self._logpath):
            return ""
        try:
            with open(self._logpath, "r", errors="replace") as f:
                return "\n".join(f.read().splitlines()[-n:])
        except OSError:
            return ""

    def running(self) -> bool:
        return self._proc is not None and self._proc.poll() is None

    def stop(self) -> None:
        terminate(self._proc, log=self.log)
        self._proc = None
        if self._logfh:
            try:
                self._logfh.close()
            except OSError:
                pass
            self._logfh = None
        # Scan CSVs are throwaway; clean the temp dir so /tmp doesn't accumulate.
        if self._tmpdir:
            shutil.rmtree(self._tmpdir, ignore_errors=True)
            self._tmpdir = None
