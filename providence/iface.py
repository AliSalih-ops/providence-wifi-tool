"""Wireless interface discovery and monitor-mode control.

This is the part that replaces the "find your card, find its driver, figure out
if it even does monitor mode, then flip it" dance. All of it is done through
`iw` and `airmon-ng`, with a manual `iw`/`ip` fallback if airmon-ng misbehaves.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import List, Optional

from .util import CmdResult, run, which, LogFn


@dataclass
class Interface:
    name: str
    phy: str = ""              # e.g. "phy0"
    driver: str = ""           # e.g. "mt76x2u", "rtl8812au"
    chipset: str = ""          # best-effort, from airmon-ng
    mode: str = ""             # "managed" / "monitor" / ...
    supports_monitor: bool = False
    bands: tuple = ()          # e.g. ("2.4",) or ("2.4", "5")

    def label(self) -> str:
        bits = [self.name]
        if self.driver:
            bits.append(self.driver)
        if self.bands:
            bits.append("/".join(self.bands) + " GHz")
        if self.supports_monitor:
            bits.append("monitor-capable")
        else:
            bits.append("NO monitor mode")
        return "  |  ".join(bits)


def _iw_dev() -> str:
    return run(["iw", "dev"]).text()


def _parse_iw_dev(text: str) -> List[Interface]:
    """Parse `iw dev` output into interfaces.

    `iw dev` groups interfaces under their phy:
        phy#0
            Interface wlan0
                type managed
    """
    interfaces: List[Interface] = []
    cur_phy = ""
    cur: Optional[Interface] = None
    for raw in text.splitlines():
        line = raw.strip()
        m = re.match(r"phy#(\d+)", line)
        if m:
            cur_phy = "phy" + m.group(1)
            continue
        m = re.match(r"Interface\s+(\S+)", line)
        if m:
            cur = Interface(name=m.group(1), phy=cur_phy)
            interfaces.append(cur)
            continue
        if cur is not None:
            m = re.match(r"type\s+(\S+)", line)
            if m:
                cur.mode = m.group(1)
    return interfaces


def _driver_of(iface: str) -> str:
    """Read the driver name from sysfs (no external tool needed)."""
    link = f"/sys/class/net/{iface}/device/driver"
    try:
        return os.path.basename(os.path.realpath(link))
    except OSError:
        return ""


def _supported_modes(info_text: str) -> set:
    """Parse the 'Supported interface modes' block of `iw phy <phy> info`.

    The block looks like:
        Supported interface modes:
             * managed
             * monitor
    """
    modes = set()
    in_modes = False
    for raw in info_text.splitlines():
        line = raw.strip()
        if line.startswith("Supported interface modes"):
            in_modes = True
            continue
        if in_modes:
            if line.startswith("*"):
                modes.add(line.lstrip("* ").strip().lower())
            elif line:
                break  # left the modes block
    return modes


def _supported_bands(info_text: str) -> set:
    """Which frequency bands a phy supports, from its `iw phy info` frequency
    list. 2.4 GHz (<3 GHz), 5 GHz (~5 GHz), 6 GHz (>5.925 GHz)."""
    bands = set()
    for m in re.finditer(r"\*\s*(\d+)(?:\.\d+)?\s*MHz", info_text):
        f = int(m.group(1))
        if f < 3000:
            bands.add("2.4")
        elif 4900 <= f <= 5925:
            bands.add("5")
        elif f > 5925:
            bands.add("6")
    return bands


def _phy_supports_monitor(phy: str) -> bool:
    """Ask `iw phy <phy> info` whether 'monitor' is a supported interface mode."""
    if not phy:
        return False
    out = run(["iw", "phy", phy, "info"]).text()
    return "monitor" in _supported_modes(out)


def list_interfaces(log: Optional[LogFn] = None) -> List[Interface]:
    """Discover wireless interfaces and annotate each with driver + capability."""
    ifaces = _parse_iw_dev(_iw_dev())
    info_cache: dict = {}
    for i in ifaces:
        i.driver = _driver_of(i.name)
        if i.phy:
            info = info_cache.get(i.phy)
            if info is None:
                info = run(["iw", "phy", i.phy, "info"]).text()  # fetch once per phy
                info_cache[i.phy] = info
            i.supports_monitor = "monitor" in _supported_modes(info)
            i.bands = tuple(b for b in ("2.4", "5", "6") if b in _supported_bands(info))
    if log:
        if ifaces:
            log(f"Found {len(ifaces)} wireless interface(s): " + ", ".join(i.name for i in ifaces))
        else:
            log("No wireless interfaces found. Is the adapter plugged in / recognized?")
    return ifaces


def restore_supplicant(log: Optional[LogFn] = None) -> None:
    """Undo a leftover wpa_supplicant mask (e.g. if a previous run was force-quit
    before restoring) so the user never has to `systemctl unmask` by hand."""
    if which("systemctl") is None:
        return
    if "masked" in run(["systemctl", "is-enabled", "wpa_supplicant"]).text().lower():
        run(["systemctl", "unmask", "wpa_supplicant"], log=log)
        run(["systemctl", "start", "wpa_supplicant"], log=log)
        if log:
            log("Cleared a leftover wpa_supplicant mask from a previous session.")


def _monitor_iface_now(prefer_phy: str = "") -> Optional[str]:
    """Return the name of an interface currently in monitor mode (optionally on a phy)."""
    for i in _parse_iw_dev(_iw_dev()):
        if i.mode == "monitor" and (not prefer_phy or i.phy == prefer_phy):
            return i.name
    return None


# In-kernel Realtek USB drivers whose monitor mode is unreliable for the popular
# 8188-class adapters — capture often shows 0 networks. The out-of-tree
# realtek-rtl8188eus-dkms (module 8188eu(s)) is the fix.
_WEAK_MONITOR_DRIVERS = {"rtl8xxxu", "r8188eu"}


def _warn_weak_driver(driver: str, log: LogFn) -> None:
    if driver in _WEAK_MONITOR_DRIVERS:
        log(f"  note: the in-kernel '{driver}' driver has weak monitor support on this chip; "
            "if scans show 0 networks, install realtek-rtl8188eus-dkms and blacklist "
            f"'{driver}', then replug the adapter.")


def enable_monitor(iface: Interface, kill_networkmanager: bool = True,
                   log: Optional[LogFn] = None) -> Optional[str]:
    """Put `iface` into monitor mode. Returns the monitor interface name.

    By DEFAULT this runs `airmon-ng check kill`, which stops NetworkManager AND
    wpa_supplicant. That is the only thing that reliably lets airodump-ng capture
    — with NetworkManager alive it keeps poking the card and the capture stays
    empty, even if the interface is unmanaged and wifi is "off". Killing NM does
    NOT drop a WIRED uplink (its existing IP/route persist), so this is safe for
    the common wired-internet + USB-monitor setup. `disable_monitor` restarts NM.

    Pass kill_networkmanager=False for the surgical path (unmanage only this
    interface + mask wpa_supplicant) — it keeps a second WiFi uplink up but may
    capture nothing on adapters/drivers where NM still interferes.
    """
    if kill_networkmanager or which("nmcli") is None:
        run(["airmon-ng", "check", "kill"], log=log)
    else:
        # Surgical: unmanage only this interface and mask wpa_supplicant so it
        # can't respawn. Keeps other links up, but NM itself may still interfere.
        run(["nmcli", "device", "set", iface.name, "managed", "no"], log=log)
        run(["systemctl", "mask", "--now", "wpa_supplicant"], log=log)
        run(["pkill", "-x", "wpa_supplicant"], log=log)

    run(["airmon-ng", "start", iface.name], timeout=30, log=log)
    mon = _monitor_iface_now(prefer_phy=iface.phy)
    if mon:
        if log:
            log(f"Monitor mode enabled: {mon}")
            _warn_weak_driver(iface.driver, log)
        return mon

    # If the interface vanished, the adapter reset/disconnected — don't thrash.
    if not any(i.name == iface.name for i in _parse_iw_dev(_iw_dev())):
        if log:
            log(f"'{iface.name}' is gone — the adapter reset/disconnected (common with VM USB "
                "passthrough when switching to monitor mode). Replug it, then click Refresh. "
                "The realtek-rtl8188eus-dkms driver + a USB 2.0 VM controller are far more stable.")
        return None

    # Fallback: manual switch on the original interface name.
    if log:
        log("airmon-ng did not produce a monitor interface; trying manual iw method.")
    run(["ip", "link", "set", iface.name, "down"], log=log)
    run(["iw", "dev", iface.name, "set", "type", "monitor"], log=log)
    run(["ip", "link", "set", iface.name, "up"], log=log)
    mon = _monitor_iface_now(prefer_phy=iface.phy)
    if mon and log:
        log(f"Monitor mode enabled (manual): {mon}")
    elif log:
        log("Failed to enable monitor mode. If the adapter keeps dropping, it's the USB "
            "passthrough resetting it — see the driver/USB notes.")
    return mon


def disable_monitor(mon_iface: str, restore_services: bool = True, log: Optional[LogFn] = None) -> None:
    """Take the card out of monitor mode and hand the interface back.

    Mirror of enable_monitor: with nmcli we just re-manage this one interface
    (the surgical path never touched anything else, so we must NOT restart
    NetworkManager and bounce other links). Only without nmcli do we restart the
    services that the blunt `airmon-ng check kill` fallback would have stopped.
    """
    run(["airmon-ng", "stop", mon_iface], timeout=30, log=log)
    if not restore_services:
        return
    # Undo whatever either enable path did, in any order: unmask wpa_supplicant,
    # turn the wifi radio back on, restart NetworkManager (the default path
    # stopped it — restarting restores WiFi and re-adopts the still-up wired
    # link), and re-manage the interface.
    run(["systemctl", "unmask", "wpa_supplicant"], log=log)
    if which("nmcli"):
        run(["nmcli", "radio", "wifi", "on"], log=log)
    r = run(["systemctl", "restart", "NetworkManager"], log=log)
    if not r.ok:
        run(["service", "network-manager", "restart"], log=log)
    if which("nmcli"):
        base = mon_iface[:-3] if mon_iface.endswith("mon") else mon_iface
        run(["nmcli", "device", "set", base, "managed", "yes"], log=log)
    if log:
        log("Monitor mode disabled; NetworkManager restarted, WiFi restored.")


# --------------------------------------------------------------------- MAC
def current_mac(iface: str) -> str:
    """Read the interface's current MAC from sysfs (no external tool)."""
    try:
        with open(f"/sys/class/net/{iface}/address", "r") as f:
            return f.read().strip()
    except OSError:
        return ""


def macchanger_argv(iface: str, mode: str, mac: Optional[str] = None) -> list:
    """Build a macchanger command.

    mode: 'random' (-r), 'permanent' (-p, restore the burned-in MAC), or
    'set' (-m <mac>, a specific address).
    """
    if mode == "random":
        flag = ["-r"]
    elif mode == "permanent":
        flag = ["-p"]
    elif mode == "set" and mac:
        flag = ["-m", mac]
    else:
        raise ValueError(f"bad macchanger mode: {mode!r}")
    return ["macchanger", *flag, iface]


def _parse_new_mac(output: str) -> str:
    """Pull the resulting address out of macchanger's 'New MAC:' line."""
    m = re.search(r"New MAC:\s*([0-9A-Fa-f:]{17})", output)
    if m:
        return m.group(1).lower()
    # Fallback: last MAC-looking token in the output.
    macs = re.findall(r"([0-9A-Fa-f]{2}(?::[0-9A-Fa-f]{2}){5})", output)
    return macs[-1].lower() if macs else ""


def set_mac(iface: str, mode: str = "random", mac: Optional[str] = None,
            log: Optional[LogFn] = None) -> Optional[str]:
    """Change (or restore) an interface's MAC. Returns the new MAC, or None.

    The link must be down to change its address, so we bounce it down/up around
    macchanger. Do this on the interface that actually transmits (the monitor
    interface once monitor mode is on) so the spoof sticks for captures/deauths.
    """
    run(["ip", "link", "set", iface, "down"], log=log)
    try:
        res = run(macchanger_argv(iface, mode, mac), timeout=15, log=log)
    finally:
        # Always bring the link back up, even if macchanger_argv raised on a
        # bad mode or run() somehow failed — never leave the card DOWN.
        run(["ip", "link", "set", iface, "up"], log=log)
    if res.rc == 127:
        if log:
            log("macchanger not installed (apt install macchanger).")
        return None
    new = _parse_new_mac(res.text()) or current_mac(iface)
    if log:
        log(f"MAC of {iface} is now {new}" if new else "MAC change did not report a new address.")
    return new or None
