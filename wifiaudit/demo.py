"""Fake data + no-op sessions for --demo mode.

Lets you launch the full GUI and click through the workflow on a machine with no
wireless hardware (or no root), so the interface can be developed and reviewed
without touching a radio. Nothing here transmits anything.
"""

from __future__ import annotations

from typing import List, Optional, Tuple

from .iface import Interface
from .scan import AccessPoint, Station, parse_csv


# A realistic airodump-ng CSV, used both by demo mode and the parser self-test.
SAMPLE_CSV = """\
BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key

AA:BB:CC:11:22:33, 2026-09-22 10:00:00, 2026-09-22 10:05:00,   6,  195, WPA2, CCMP, PSK, -42,      120,        0,   0.  0.  0.  0,  12, ACME-Corp,
DE:AD:BE:EF:00:11, 2026-09-22 10:00:00, 2026-09-22 10:05:00,  11,  130, WPA2, CCMP, PSK, -67,       88,        0,   0.  0.  0.  0,   9, Warehouse,
00:11:22:33:44:55, 2026-09-22 10:01:00, 2026-09-22 10:05:00,   1,   54, OPN,      ,    , -70,       40,        0,   0.  0.  0.  0,   5, Guest,

Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs

11:22:33:44:55:66, 2026-09-22 10:02:00, 2026-09-22 10:05:00, -48,      300, AA:BB:CC:11:22:33, ACME-Corp
77:88:99:AA:BB:CC, 2026-09-22 10:03:00, 2026-09-22 10:05:00, -55,      120, AA:BB:CC:11:22:33,
AB:CD:EF:12:34:56, 2026-09-22 10:03:00, 2026-09-22 10:05:00, -80,       20, (not associated), FreeWiFi,coffeeshop
"""


def demo_interfaces() -> List[Interface]:
    return [
        Interface(name="wlan0", phy="phy0", driver="mt76x2u", mode="managed", supports_monitor=True),
        Interface(name="wlan1", phy="phy1", driver="iwlwifi", mode="managed", supports_monitor=False),
    ]


class DemoScanSession:
    """Stand-in for scan.ScanSession that just replays SAMPLE_CSV."""

    def __init__(self, mon_iface: str, band: str = "2.4 GHz", log=None, **_):
        self.mon_iface = mon_iface
        self.band = band
        self.log = log
        self._on = False

    def start(self) -> None:
        self._on = True
        if self.log:
            self.log(f"[demo] scanning on {self.mon_iface} ({self.band}, simulated)")

    def latest(self) -> Tuple[List[AccessPoint], List[Station]]:
        return parse_csv(SAMPLE_CSV)

    def log_tail(self, n: int = 8) -> str:
        return ""

    def running(self) -> bool:
        return self._on

    def stop(self) -> None:
        self._on = False


class DemoCaptureSession:
    """Stand-in for capture.CaptureSession that fakes a handshake after a deauth."""

    def __init__(self, mon_iface: str, target, out_dir=None, log=None, **_):
        self.mon_iface = mon_iface
        self.target = target
        self.log = log
        self.out_dir = out_dir or "/tmp"
        self.prefix = "/tmp/demo_capture"
        self._on = False
        self._deauthed = False

    def log_tail(self, n: int = 8) -> str:
        return ""

    def start(self) -> None:
        self._on = True
        if self.log:
            self.log(f"[demo] capturing {self.target.essid} ch {self.target.channel} (simulated)")

    def running(self) -> bool:
        return self._on

    def stop(self) -> None:
        self._on = False

    def cap_file(self) -> Optional[str]:
        return self.prefix + "-01.cap" if self._deauthed else None

    def deauth(self, client=None, count: int = 5):
        self._deauthed = True
        if self.log:
            self.log(f"[demo] deauth x{count} at {client or 'broadcast'} (simulated)")

        class _R:
            ok = True
            def text(self_inner):
                return "[demo] frames sent"
        return _R()

    def has_handshake(self) -> bool:
        return self._deauthed  # pretend the deauth caught a reconnect

    def export_22000(self) -> Optional[str]:
        return self.prefix + "-01.22000" if self._deauthed else None


class DemoPmkidSession:
    """Stand-in for capture.PmkidSession that fakes a PMKID shortly after start."""

    def __init__(self, mon_iface: str, target, out_dir=None, log=None, **_):
        self.mon_iface = mon_iface
        self.target = target
        self.log = log
        self.out_dir = out_dir or "/tmp"
        self.pcapng = "/tmp/demo_pmkid.pcapng"
        self._on = False
        self._checks = 0

    def start(self) -> None:
        self._on = True
        if self.log:
            self.log(f"[demo] PMKID capture on {self.mon_iface} (simulated, no deauth)")

    def running(self) -> bool:
        return self._on

    def stop(self) -> None:
        self._on = False

    def log_tail(self, n: int = 8) -> str:
        return ""

    def cap_file(self) -> Optional[str]:
        return self.pcapng if self._on else None

    def export_22000(self) -> Optional[str]:
        return "/tmp/demo_pmkid.22000"

    def check_pmkid(self) -> bool:
        # Pretend it takes a couple of polls to see a PMKID.
        self._checks += 1
        got = self._checks >= 2
        if self.log:
            self.log("[demo] PMKID captured." if got else "[demo] No PMKID yet.")
        return got
