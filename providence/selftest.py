"""Offline logic tests - no GUI, no radio, no root.

Run with:  python3 -m providence --selftest
These exercise the pure parsing/flow logic (the parts that don't touch hardware)
so the app can be sanity-checked on any machine, including the dev box.
"""

from __future__ import annotations

import os
import tempfile

from .capture import (
    CaptureSession,
    CaptureTarget,
    _scan_handshake_text,
    _scope_22000_file,
    capture_argv,
    deauth_argv,
    hash_kinds,
    hcxdumptool_argv,
    is_valid_channel,
    pmkid_for_bssid,
    pmkid_from_22000,
    safe_prefix,
)
from .demo import (
    SAMPLE_CSV,
    DemoCaptureSession,
    DemoPmkidSession,
    DemoScanSession,
    demo_interfaces,
)
from .iface import _parse_iw_dev, _parse_new_mac, _supported_bands, _supported_modes, macchanger_argv
from .scan import AccessPoint, airodump_band, parse_csv, scan_argv
from .util import is_mac


IW_DEV_SAMPLE = """\
phy#1
	Interface wlan1
		ifindex 4
		type managed
phy#0
	Interface wlan0
		ifindex 3
		type monitor
"""

IW_PHY_SAMPLE = """\
	Supported interface modes:
		 * IBSS
		 * managed
		 * AP
		 * monitor
		 * P2P-client
	Band 1:
		Capabilities: 0x1062
"""

AIRCRACK_YES = """\
   #  BSSID              ESSID                     Encryption
   1  AA:BB:CC:11:22:33  ACME-Corp                 WPA (1 handshake)
"""
AIRCRACK_NO = """\
   #  BSSID              ESSID                     Encryption
   1  AA:BB:CC:11:22:33  ACME-Corp                 WPA (0 handshake)
"""
# Two networks in one .cap; only the *other* one has a handshake.
AIRCRACK_OTHER = """\
   #  BSSID              ESSID                     Encryption
   1  AA:BB:CC:11:22:33  ACME-Corp                 WPA (0 handshake)
   2  DE:AD:BE:EF:00:11  Warehouse                 WPA (1 handshake)
"""
AIRCRACK_NONE = "No valid WPA handshakes found.\n"

# ESSID containing a comma, a hidden (empty) ESSID, and a junk line to ignore.
EDGE_CSV = """\
BSSID, First time seen, Last time seen, channel, Speed, Privacy, Cipher, Authentication, Power, # beacons, # IV, LAN IP, ID-length, ESSID, Key

11:11:11:11:11:11, t, t,   6,  195, WPA2, CCMP, PSK, -40, 100, 0,   0. 0. 0. 0, 12, Cafe, Bistro,
22:22:22:22:22:22, t, t,  36,  866, WPA2, CCMP, PSK, -55, 100, 0,   0. 0. 0. 0,  0, ,
this is not a valid row and must be skipped
33:33:33:33:33:33, t, t,  -1,   54, WPA3, CCMP, SAE, -60, 100, 0,   0. 0. 0. 0,  8, FiveG,

Station MAC, First time seen, Last time seen, Power, # packets, BSSID, Probed ESSIDs
"""


class _Check:
    def __init__(self):
        self.passed = 0
        self.failed = 0

    def eq(self, name, got, want):
        if got == want:
            self.passed += 1
            print(f"  PASS  {name}")
        else:
            self.failed += 1
            print(f"  FAIL  {name}\n          got:  {got!r}\n          want: {want!r}")

    def ok(self, name, cond):
        self.eq(name, bool(cond), True)


def run() -> int:
    c = _Check()
    print("== airodump CSV parsing ==")
    aps, stations = parse_csv(SAMPLE_CSV)
    c.eq("ap count", len(aps), 3)
    c.eq("first bssid", aps[0].bssid, "AA:BB:CC:11:22:33")
    c.eq("first essid", aps[0].essid, "ACME-Corp")
    c.eq("first channel", aps[0].channel, "6")
    c.eq("first privacy", aps[0].privacy, "WPA2")
    c.ok("first is wpa", aps[0].is_wpa())
    c.eq("acme client count", aps[0].clients, 2)
    c.eq("station count", len(stations), 3)
    c.eq("open network privacy", aps[2].privacy, "OPN")
    unassoc = [s for s in stations if s.bssid == "(not associated)"]
    c.eq("unassociated station present", len(unassoc), 1)
    c.ok("probed essid with comma kept", "coffeeshop" in unassoc[0].probed)

    print("== iw dev parsing ==")
    ifaces = _parse_iw_dev(IW_DEV_SAMPLE)
    c.eq("iface count", len(ifaces), 2)
    names = {i.name: i for i in ifaces}
    c.eq("wlan0 phy", names["wlan0"].phy, "phy0")
    c.eq("wlan0 mode", names["wlan0"].mode, "monitor")
    c.eq("wlan1 mode", names["wlan1"].mode, "managed")

    print("== iw phy supported-modes parsing ==")
    modes = _supported_modes(IW_PHY_SAMPLE)
    c.ok("monitor supported", "monitor" in modes)
    c.ok("managed supported", "managed" in modes)
    c.ok("no stray 'band' token", "band 1:" not in modes)

    print("== handshake detection parsing ==")
    c.ok("detects 1 handshake", _scan_handshake_text(AIRCRACK_YES, "AA:BB:CC:11:22:33"))
    c.ok("rejects 0 handshake", not _scan_handshake_text(AIRCRACK_NO, "AA:BB:CC:11:22:33"))
    c.ok("bssid mismatch rejected", not _scan_handshake_text(AIRCRACK_YES, "FF:FF:FF:FF:FF:FF"))
    c.ok("other-network handshake not counted for target",
         not _scan_handshake_text(AIRCRACK_OTHER, "AA:BB:CC:11:22:33"))
    c.ok("other-network handshake IS found for its own bssid",
         _scan_handshake_text(AIRCRACK_OTHER, "DE:AD:BE:EF:00:11"))
    c.ok("untargeted check sees any handshake", _scan_handshake_text(AIRCRACK_OTHER, ""))
    c.ok("'no valid handshakes' rejected", not _scan_handshake_text(AIRCRACK_NONE, ""))

    print("== CSV edge cases (comma ESSID, hidden SSID, junk line) ==")
    e_aps, _ = parse_csv(EDGE_CSV)
    c.eq("edge ap count (junk line skipped)", len(e_aps), 3)
    c.eq("comma in ESSID preserved", e_aps[0].essid, "Cafe,Bistro")
    c.eq("hidden ssid labelled", e_aps[1].essid, "<hidden>")
    c.eq("5GHz channel parsed", e_aps[1].channel, "36")
    c.ok("unknown channel is invalid", not is_valid_channel(e_aps[2].channel))

    print("== command builders & guards ==")
    c.eq("band 2.4", airodump_band("2.4 GHz"), "bg")
    c.eq("band 5", airodump_band("5 GHz"), "a")
    c.eq("band both", airodump_band("2.4 + 5 GHz"), "abg")
    c.eq("band unknown falls back", airodump_band("nonsense"), "bg")
    sv = scan_argv("wlan0mon", "/tmp/scan", "5 GHz")
    c.ok("scan argv sets 5GHz band", "a" == sv[sv.index("--band") + 1])
    c.ok("scan argv writes csv", "csv" in sv)
    c.eq("scan argv iface last", sv[-1], "wlan0mon")
    cv = capture_argv("wlan0mon", "AA:BB:CC:11:22:33", "6", "/tmp/cap")
    c.eq("capture pins bssid", cv[cv.index("--bssid") + 1], "AA:BB:CC:11:22:33")
    c.eq("capture pins channel", cv[cv.index("-c") + 1], "6")
    c.eq("capture argv iface last", cv[-1], "wlan0mon")
    dv = deauth_argv("wlan0mon", "AA:BB:CC:11:22:33", "11:22:33:44:55:66", 5)
    c.ok("deauth targets client", "-c" in dv and "11:22:33:44:55:66" in dv)
    c.eq("deauth count is string", dv[dv.index("--deauth") + 1], "5")
    dvb = deauth_argv("wlan0mon", "AA:BB:CC:11:22:33", None, 3)
    c.ok("broadcast deauth omits -c", "-c" not in dvb)
    c.ok("valid channel 11", is_valid_channel("11"))
    c.ok("valid channel int", is_valid_channel(36))
    c.ok("channel 0 invalid", not is_valid_channel("0"))
    c.ok("channel empty invalid", not is_valid_channel(""))
    c.ok("channel text invalid", not is_valid_channel("auto"))
    pfx = safe_prefix("/tmp/caps", "My Cafe/Guest, Wifi", "AA:BB:CC:11:22:33")
    c.ok("prefix strips unsafe chars", "/tmp/caps" in pfx and "," not in os.path.basename(pfx)
         and " " not in os.path.basename(pfx))
    c.ok("prefix keeps bssid hex", "AABBCC112233" in pfx)

    print("== PMKID helpers ==")
    hv = hcxdumptool_argv("wlan0mon", "/tmp/t.pcapng", "6")
    c.eq("hcxdumptool sets interface", hv[hv.index("-i") + 1], "wlan0mon")
    c.eq("hcxdumptool sets output", hv[hv.index("-w") + 1], "/tmp/t.pcapng")
    c.eq("hcxdumptool pins channel", hv[hv.index("-c") + 1], "6")
    c.ok("hcxdumptool omits channel when none", "-c" not in hcxdumptool_argv("wlan0mon", "/tmp/t.pcapng"))
    c.ok("PMKID detected (WPA*01*)", pmkid_from_22000("WPA*01*deadbeef*aabbcc*112233*7773***"))
    c.ok("EAPOL is not a PMKID", not pmkid_from_22000("WPA*02*deadbeef*aabbcc*112233*7773***"))
    c.eq("hash_kinds PMKID", hash_kinds("WPA*01*x"), {"PMKID"})
    c.eq("hash_kinds EAPOL", hash_kinds("WPA*02*x"), {"EAPOL"})
    c.eq("hash_kinds both", hash_kinds("WPA*01*x\nWPA*02*y"), {"PMKID", "EAPOL"})
    c.eq("hash_kinds none", hash_kinds("garbage"), set())

    print("== macchanger helpers ==")
    c.eq("mac random flag", macchanger_argv("wlan0", "random")[1], "-r")
    c.eq("mac permanent flag", macchanger_argv("wlan0", "permanent")[1], "-p")
    mv = macchanger_argv("wlan0", "set", "12:34:56:78:9a:bc")
    c.ok("mac set uses -m + address", mv[1] == "-m" and "12:34:56:78:9a:bc" in mv)
    c.eq("macchanger iface last", macchanger_argv("wlan0mon", "random")[-1], "wlan0mon")
    macout = ("Current MAC:   00:11:22:33:44:55 (Vendor)\n"
              "Permanent MAC: 00:11:22:33:44:55 (Vendor)\n"
              "New MAC:       12:34:56:78:9a:bc (unknown)\n")
    c.eq("parse new MAC", _parse_new_mac(macout), "12:34:56:78:9a:bc")
    c.eq("parse new MAC when absent", _parse_new_mac("no macs here"), "")

    print("== encryption classification ==")

    def ap(priv, auth):
        return AccessPoint("AA:BB:CC:11:22:33", "6", priv, "CCMP", auth, "-40", "10", "Net")

    c.ok("WPA2-PSK capturable", ap("WPA2", "PSK").is_capturable())
    c.ok("WPA/WPA2 capturable", ap("WPA2 WPA", "PSK").is_capturable())
    c.ok("WPA2/WPA3 transition capturable", ap("WPA2 WPA3", "PSK SAE").is_capturable())
    c.ok("WPA3-SAE NOT capturable", not ap("WPA3", "SAE").is_capturable())
    c.ok("WPA3-SAE flagged sae_only", ap("WPA3", "SAE").is_sae_only())
    c.ok("enterprise (MGT) NOT capturable", not ap("WPA2", "MGT").is_capturable())
    c.ok("WEP NOT capturable", not ap("WEP", "").is_capturable())
    c.ok("open NOT capturable", not ap("OPN", "").is_capturable())
    c.ok("OWE NOT capturable", not ap("OWE", "").is_capturable())
    c.ok("WPA3 note mentions SAE", "SAE" in ap("WPA3", "SAE").security_note())
    c.eq("capturable note is empty", ap("WPA2", "PSK").security_note(), "")

    print("== MAC validation (arg-injection guard) ==")
    c.ok("valid mac", is_mac("aa:bb:cc:dd:ee:ff"))
    c.ok("valid upper", is_mac("AA:BB:CC:11:22:33"))
    c.ok("reject short", not is_mac("aa:bb:cc"))
    c.ok("reject flag-like token", not is_mac("-a:bb:cc:dd:ee:ff"))
    c.ok("reject empty", not is_mac(""))
    c.ok("reject spaces", not is_mac("aa bb cc dd ee ff"))
    c.ok("reject trailing junk", not is_mac("aa:bb:cc:dd:ee:ff;rm"))

    print("== PMKID scoping ==")
    line = "WPA*01*deadbeefdeadbeefdeadbeefdeadbeef*aabbcc112233*445566778899*4d794e6574***"
    c.ok("pmkid matches target bssid", pmkid_for_bssid(line, "AA:BB:CC:11:22:33"))
    c.ok("pmkid rejects other bssid", not pmkid_for_bssid(line, "FF:FF:FF:FF:FF:FF"))
    c.ok("pmkid any when untargeted", pmkid_for_bssid(line, ""))
    c.ok("eapol line is not a pmkid", not pmkid_for_bssid("WPA*02*whatever", "AA:BB:CC:11:22:33"))
    hv62 = hcxdumptool_argv("wlan0mon", "/tmp/x.pcapng", "6", "/tmp/f", (6, 2))
    c.ok("hcxdumptool 6.2 adds filter flags", any("filterlist_ap" in a for a in hv62) and "--filtermode=2" in hv62)
    hv63 = hcxdumptool_argv("wlan0mon", "/tmp/x.pcapng", "6", "/tmp/f", (6, 3))
    c.ok("hcxdumptool 6.3 omits removed filter flags (would crash)", not any("filterlist" in a for a in hv63))
    c.ok("hcxdumptool unknown-version fail-safe omits flags",
         not any("filterlist" in a for a in hcxdumptool_argv("wlan0mon", "/tmp/x.pcapng", "6", "/tmp/f")))
    # export scoping: only the target AP's 22000 rows are kept
    tmp2 = tempfile.mkdtemp(prefix="providence-22000-")
    p22 = os.path.join(tmp2, "x.22000")
    with open(p22, "w") as f:
        f.write("WPA*01*aaaa*aabbcc112233*111111111111*4e*\n")   # target AP
        f.write("WPA*01*bbbb*ffffffffffff*222222222222*4e*\n")   # neighbour
    _scope_22000_file(p22, "AA:BB:CC:11:22:33")
    kept = open(p22).read()
    c.ok("export keeps target AP rows", "aabbcc112233" in kept)
    c.ok("export drops neighbour AP rows", "ffffffffffff" not in kept)
    import shutil as _sh2
    _sh2.rmtree(tmp2, ignore_errors=True)

    print("== adapter band detection ==")
    info_dual = "\t\t* 2412 MHz [1]\n\t\t* 5180 MHz [36]\n"
    info_24 = "\t\t* 2412.0 MHz [1]\n\t\t* 2437 MHz [6]\n"
    c.eq("dual-band phy -> {2.4,5}", _supported_bands(info_dual), {"2.4", "5"})
    c.eq("2.4-only phy -> {2.4}", _supported_bands(info_24), {"2.4"})

    print("== 5GHz channels + CRLF-safe parsing + output-format ==")
    c.ok("5GHz ch 149 valid", is_valid_channel("149"))
    c.ok("5GHz ch 165 valid", is_valid_channel("165"))
    crlf = SAMPLE_CSV.replace("ACME-Corp", "AC\rME")   # lone CR inside an ESSID
    aps_c, _ = parse_csv(crlf)
    c.eq("CR in ESSID adds no phantom rows", len(aps_c), 3)
    c.ok("CR stripped from parsed ESSID", "\r" not in aps_c[0].essid)
    cv2 = capture_argv("wlan0mon", "AA:BB:CC:11:22:33", "6", "/tmp/cap")
    c.ok("capture limits airodump output format", "pcap" in cv2 and "--output-format" in cv2)

    print("== newest capture file by mtime (not lexicographic) ==")
    tmp = tempfile.mkdtemp(prefix="providence-test-")
    cs = CaptureSession("wlan0mon", CaptureTarget("AA:BB:CC:11:22:33", "6", "Net"), out_dir=tmp)
    older, newer = cs.prefix + "-09.cap", cs.prefix + "-10.cap"
    open(older, "w").close()
    open(newer, "w").close()
    os.utime(older, (2000, 2000))
    os.utime(newer, (3000, 3000))          # -10 is newer despite sorting before -09
    c.eq("cap_file picks newest by mtime", os.path.basename(cs.cap_file()), os.path.basename(newer))
    import shutil as _sh
    _sh.rmtree(tmp, ignore_errors=True)

    print("== demo interfaces & flow ==")
    di = demo_interfaces()
    c.eq("demo iface count", len(di), 2)
    c.ok("demo wlan0 monitor-capable", di[0].supports_monitor)

    logs = []
    scan = DemoScanSession("wlan0mon", log=logs.append)
    scan.start()
    a2, s2 = scan.latest()
    c.eq("demo scan ap count", len(a2), 3)
    scan.stop()
    c.ok("demo scan stopped", not scan.running())

    cap = DemoCaptureSession("wlan0mon", CaptureTarget("AA:BB:CC:11:22:33", "6", "ACME-Corp"), log=logs.append)
    cap.start()
    c.ok("no handshake before deauth", not cap.has_handshake())
    cap.deauth(client="11:22:33:44:55:66", count=5)
    c.ok("handshake after deauth (demo)", cap.has_handshake())
    c.ok("cap file appears", cap.cap_file() is not None)
    cap.stop()

    pm = DemoPmkidSession("wlan0mon", CaptureTarget("AA:BB:CC:11:22:33", "6", "ACME-Corp"), log=logs.append)
    pm.start()
    c.ok("pmkid not captured on first check", not pm.check_pmkid())
    c.ok("pmkid captured after another check", pm.check_pmkid())
    c.ok("pmkid cap file present", pm.cap_file() is not None)
    pm.stop()
    c.ok("pmkid session stops", not pm.running())

    print(f"\n{c.passed} passed, {c.failed} failed")
    return 0 if c.failed == 0 else 1
