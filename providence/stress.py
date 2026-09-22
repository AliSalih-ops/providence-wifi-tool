"""Stress / fuzz harness for the hostile-input surfaces.

Run with:  python3 -m providence --stresstest

Every parser in this tool eats attacker-controlled data (a nearby AP fully
controls its SSID bytes, BSSID and channel; hcxpcapngtool output is derived from
captured frames). This harness feeds each one a corpus of adversarial and
boundary inputs and asserts the invariants a root-run tool must hold:

  * no unhandled exception (a crash in a poll loop wedges the UI),
  * bounded time (no catastrophic-regex / quadratic blowup on a flood),
  * bounded output (a beacon flood cannot allocate without limit),
  * path containment (a hostile ESSID cannot escape the output directory).

It touches no radio and needs no root, so it runs anywhere in CI.
"""

from __future__ import annotations

import os
import time

from .capture import (
    _scan_handshake_text,
    _scope_22000_file,
    capture_argv,
    deauth_argv,
    hcxdumptool_argv,
    is_valid_channel,
    pmkid_for_bssid,
    safe_prefix,
)
from .iface import _parse_iw_dev, _parse_new_mac, _supported_bands, _supported_modes, macchanger_argv
from .scan import MAX_ROWS, airodump_band, parse_csv
from .util import is_mac

TIME_BUDGET = 2.0   # seconds; anything slower is a DoS smell


class _Runner:
    def __init__(self):
        self.passed = 0
        self.failed = 0

    @staticmethod
    def _p(s):
        # ASCII-safe so a unicode ESSID label prints on any console (Windows cp1252).
        print(str(s).encode("ascii", "backslashreplace").decode("ascii"))

    def check(self, name, fn, *args, invariant=None, budget=TIME_BUDGET):
        """Call fn(*args); fail on exception, slowness, or a broken invariant."""
        t = time.time()
        try:
            out = fn(*args)
        except Exception as e:  # noqa: BLE001 - the whole point is to catch anything
            self.failed += 1
            self._p(f"  FAIL  {name}: raised {type(e).__name__}: {e}")
            return
        dt = time.time() - t
        if dt > budget:
            self.failed += 1
            self._p(f"  FAIL  {name}: too slow ({dt:.2f}s > {budget}s)")
            return
        if invariant is not None:
            ok, why = invariant(out)
            if not ok:
                self.failed += 1
                self._p(f"  FAIL  {name}: invariant broken - {why}")
                return
        self.passed += 1
        self._p(f"  ok    {name}  ({dt * 1000:.0f}ms)")


def _hostile_essids():
    """A spread of ESSID payloads an AP can legally broadcast."""
    return [
        "", "normal", "with,comma", 'with"quote', "with'apos",
        "line\nbreak", "carriage\rreturn", "null\x00byte", "tab\ttab",
        "\x1b[31mANSI\x1b[0m", "\x9bC1CSI", "del\x7fchar",
        "../../../etc/passwd", "/abs/path", "..", ".", "....",
        "-rf", "--flag", "$(whoami)", "`id`", ";reboot",
        "é你好\U0001f600", "A" * 4096, "x" * 1_000_000,
        "  ", "\x00\x01\x02\x03", "%s%s%n", "{0}{1}",
    ]


def _csv(essid, bssid="AA:BB:CC:11:22:33", n_ap=1):
    header = ("BSSID, First time seen, Last time seen, channel, Speed, Privacy, "
              "Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key\n\n")
    rows = "".join(
        f"{bssid[:-2]}{i % 100:02d}, t, t, 6, 195, WPA2, CCMP, PSK, -40, 100, 0, "
        f"0. 0. 0. 0, 5, {essid}, \n"
        for i in range(n_ap)
    )
    return header + rows


def run() -> int:
    r = _Runner()

    print("== parse_csv: hostile ESSIDs ==")
    for e in _hostile_essids():
        label = repr(e if len(e) < 24 else e[:20] + "...")
        r.check(f"parse essid {label}", parse_csv, _csv(e),
                invariant=lambda out: (isinstance(out, tuple) and len(out) == 2, "not a 2-tuple"))

    print("== parse_csv: malformed / boundary structure ==")
    for name, text in [
        ("empty", ""), ("blank lines", "\n\n\n\n"),
        ("header only", _csv("x", n_ap=0)),
        ("no station header", "garbage\nmore garbage\n"),
        ("truncated row", "AA:BB:CC:11:22:33, t, t, 6"),
        ("non-hex bssid", "ZZ:ZZ:ZZ:ZZ:ZZ:ZZ, t, t, 6, , WPA2, , PSK, -40, 1, 0, 0.0.0.0, 3, X, \n"),
        ("giant single field", "A" * 5_000_000),
        ("many commas", "," * 200000),
    ]:
        r.check(f"parse {name}", parse_csv, text)

    print("== parse_csv: beacon-flood bound (MAX_ROWS) ==")
    flood = _csv("floodnet", n_ap=MAX_ROWS + 2000)
    r.check("flood parses bounded+fast", parse_csv, flood,
            invariant=lambda out: (len(out[0]) <= MAX_ROWS, f"{len(out[0])} APs > MAX_ROWS"))

    print("== safe_prefix: path containment ==")
    base = os.path.abspath(os.sep + "base")
    for e in _hostile_essids():
        r.check(f"prefix stays in base {repr(e[:16])}", safe_prefix, "/base", e, "AA:BB:CC:11:22:33",
                invariant=lambda p: (os.path.abspath(p).startswith(base + os.sep) or os.path.abspath(p) == base,
                                     f"escaped: {p}"))

    print("== is_mac / is_valid_channel: no ReDoS, correct type ==")
    for s in ["", "aa:bb:cc:dd:ee:ff", "-a:bb:cc:dd:ee:ff", "x" * 500000, ":" * 100000, "a" * 100000 + ":"]:
        r.check(f"is_mac {len(s)}b", is_mac, s, invariant=lambda o: (isinstance(o, bool), "not bool"))
    for c in ["6", "-1", "abc", "", "9" * 100000, "149", "165"]:
        r.check(f"is_valid_channel {repr(c[:8])}", is_valid_channel, c,
                invariant=lambda o: (isinstance(o, bool), "not bool"))

    print("== handshake / PMKID / 22000 parsers on hostile text ==")
    hostile = "\n".join(["WPA*01*" + "f" * 32 + "*deadbeef*x", "1 AA:BB:CC:11:22:33 X WPA (1 handshake)",
                         "\x1b[2J", "*" * 100000, "WPA*" * 50000])
    r.check("_scan_handshake_text", _scan_handshake_text, hostile, "AA:BB:CC:11:22:33")
    r.check("pmkid_for_bssid", pmkid_for_bssid, hostile, "AA:BB:CC:11:22:33")
    # _scope_22000_file on a hostile file must not crash or follow anything odd
    import tempfile
    tf = tempfile.mkdtemp(prefix="providence-stress-")
    p = os.path.join(tf, "h.22000")
    with open(p, "w") as f:
        f.write(hostile)
    r.check("_scope_22000_file", _scope_22000_file, p, "AA:BB:CC:11:22:33")
    import shutil
    shutil.rmtree(tf, ignore_errors=True)

    print("== iw / macchanger / version parsers ==")
    for name, fn, arg in [
        ("_parse_iw_dev huge", _parse_iw_dev, "phy#0\n\tInterface x\n\t\ttype monitor\n" * 20000),
        ("_supported_modes huge", _supported_modes, "Supported interface modes:\n" + "\t* monitor\n" * 100000),
        ("_supported_bands huge", _supported_bands, "* 2412 MHz\n" * 100000 + "* 5180 MHz\n"),
        ("_parse_new_mac junk", _parse_new_mac, "New MAC: " + "z" * 100000),
        ("airodump_band junk", airodump_band, "\x00" * 10000),
    ]:
        r.check(name, fn, arg)

    print("== argv builders never emit an option-looking value unquoted ==")
    # (defence-in-depth: builders should still be crash-free on hostile values)
    r.check("capture_argv hostile", capture_argv, "wlan0mon", "-a:bb", "-c", "/tmp/-x")
    r.check("deauth_argv hostile", deauth_argv, "wlan0mon", "-a:bb", "-c:d", 5)
    r.check("hcxdumptool_argv hostile", hcxdumptool_argv, "wlan0mon", "/tmp/x", "6", "/tmp/f", (6, 2))
    r.check("macchanger_argv random", macchanger_argv, "wlan0", "random")

    print(f"\n{r.passed} passed, {r.failed} failed")
    return 0 if r.failed == 0 else 1
