"""Wireless interface discovery and monitor-mode control.

This is the part that replaces the "find your card, find its driver, figure out
if it even does monitor mode, then flip it" dance. All of it is done through
`iw` and `airmon-ng`, with a manual `iw`/`ip` fallback if airmon-ng misbehaves.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass, field
from typing import List, Optional

from .util import CmdResult, run, LogFn


@dataclass
class Interface:
    name: str
    phy: str = ""              # e.g. "phy0"
    driver: str = ""           # e.g. "mt76x2u", "rtl8812au"
    chipset: str = ""          # best-effort, from airmon-ng
    mode: str = ""             # "managed" / "monitor" / ...
    supports_monitor: bool = False

    def label(self) -> str:
        bits = [self.name]
        if self.driver:
            bits.append(self.driver)
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


def _phy_supports_monitor(phy: str) -> bool:
    """Ask `iw phy <phy> info` whether 'monitor' is a supported interface mode."""
    if not phy:
        return False
    out = run(["iw", "phy", phy, "info"]).text()
    return "monitor" in _supported_modes(out)


def list_interfaces(log: Optional[LogFn] = None) -> List[Interface]:
    """Discover wireless interfaces and annotate each with driver + capability."""
    ifaces = _parse_iw_dev(_iw_dev())
    for i in ifaces:
        i.driver = _driver_of(i.name)
        i.supports_monitor = _phy_supports_monitor(i.phy)
    if log:
        if ifaces:
            log(f"Found {len(ifaces)} wireless interface(s): " + ", ".join(i.name for i in ifaces))
        else:
            log("No wireless interfaces found. Is the adapter plugged in / recognized?")
    return ifaces


def _monitor_iface_now(prefer_phy: str = "") -> Optional[str]:
    """Return the name of an interface currently in monitor mode (optionally on a phy)."""
    for i in _parse_iw_dev(_iw_dev()):
        if i.mode == "monitor" and (not prefer_phy or i.phy == prefer_phy):
            return i.name
    return None


def enable_monitor(iface: Interface, kill_interferers: bool = True, log: Optional[LogFn] = None) -> Optional[str]:
    """Put `iface` into monitor mode. Returns the monitor interface name.

    Primary path uses airmon-ng (which also renames to e.g. wlan0mon and can kill
    NetworkManager/wpa_supplicant that otherwise fight monitor mode). If airmon-ng
    doesn't yield a monitor interface, fall back to the manual iw/ip method.
    """
    if kill_interferers:
        # Stops NetworkManager & wpa_supplicant so they don't yank the card back
        # to managed mode mid-capture. `airmon-ng stop` / restoring services undoes it.
        run(["airmon-ng", "check", "kill"], log=log)

    run(["airmon-ng", "start", iface.name], timeout=30, log=log)
    mon = _monitor_iface_now(prefer_phy=iface.phy)
    if mon:
        if log:
            log(f"Monitor mode enabled: {mon}")
        return mon

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
        log("Failed to enable monitor mode. Check the driver and that you're root.")
    return mon


def disable_monitor(mon_iface: str, restore_services: bool = True, log: Optional[LogFn] = None) -> None:
    """Take the card out of monitor mode and (optionally) bring networking back."""
    run(["airmon-ng", "stop", mon_iface], timeout=30, log=log)
    if restore_services:
        # Best-effort; different distros use different service managers.
        r = run(["systemctl", "restart", "NetworkManager"], log=log)
        if not r.ok:
            run(["service", "network-manager", "restart"], log=log)
    if log:
        log("Monitor mode disabled; networking restore attempted.")


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
    res = run(macchanger_argv(iface, mode, mac), timeout=15, log=log)
    run(["ip", "link", "set", iface, "up"], log=log)
    if res.rc == 127:
        if log:
            log("macchanger not installed (apt install macchanger).")
        return None
    new = _parse_new_mac(res.text()) or current_mac(iface)
    if log:
        log(f"MAC of {iface} is now {new}" if new else "MAC change did not report a new address.")
    return new or None
