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
import time
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

from .util import LogFn, spawn, terminate


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

    def is_wpa(self) -> bool:
        return "WPA" in (self.privacy or "").upper()


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

    lines = text.splitlines()
    # Find where the station section starts.
    station_hdr = None
    for idx, line in enumerate(lines):
        if line.strip().startswith("Station MAC"):
            station_hdr = idx
            break

    ap_lines = lines[: station_hdr] if station_hdr is not None else lines
    st_lines = lines[station_hdr + 1 :] if station_hdr is not None else []

    for line in ap_lines:
        s = line.strip()
        if not s or s.startswith("BSSID"):
            continue
        parts = [p.strip() for p in line.split(",")]
        if len(parts) < 14:
            continue
        # BSSID is 6 hex pairs; guards against stray/blank rows.
        if parts[0].count(":") != 5:
            continue
        # ESSID may itself contain commas; everything from field 13 up to the
        # final "Key" field is the ESSID.
        essid = ",".join(parts[13:-1]).strip() if len(parts) > 14 else parts[13]
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
        s = line.strip()
        if not s or s.startswith("Station MAC"):
            continue
        parts = [p.strip() for p in line.split(",")]
        if len(parts) < 6 or parts[0].count(":") != 5:
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
    """Build the airodump-ng argv for a channel-hopping scan."""
    return [
        "airodump-ng",
        "--band", airodump_band(band_choice),
        "--write-interval", "1",
        "--output-format", "csv",
        "-w", prefix,
        mon_iface,
    ]


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
        self._tmpdir = tempfile.mkdtemp(prefix="wifiaudit-scan-")
        self._prefix = os.path.join(self._tmpdir, "scan")
        self._logpath = os.path.join(self._tmpdir, "airodump.log")
        self._logfh = open(self._logpath, "w")
        self._proc = spawn(scan_argv(self.mon_iface, self._prefix, self.band),
                           log=self.log, out=self._logfh)

    def latest(self) -> Tuple[List[AccessPoint], List[Station]]:
        """Read and parse the most recent CSV airodump has written so far."""
        if not self._prefix:
            return [], []
        files = sorted(glob.glob(self._prefix + "-*.csv"))
        if not files:
            return [], []
        try:
            with open(files[-1], "r", errors="replace") as f:
                text = f.read()
        except OSError:
            return [], []
        return parse_csv(text)

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
