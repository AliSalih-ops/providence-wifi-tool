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
    """Clean up leftover monitor-session state at startup so a previous run (or
    manual testing) can't leave WiFi broken: drop a stale surgical unmanage
    config, un-mask wpa_supplicant if it was left masked, and turn the WiFi radio
    back on."""
    # A crashed surgical-mode session can leave the "ignore this interface" drop-in
    # behind, which would keep the card unmanaged forever. Clear it first so the
    # rest of this restore (and any NM restart below) re-adopts the interface.
    if os.path.exists(_NM_UNMANAGE_CONF):
        try:
            os.remove(_NM_UNMANAGE_CONF)
            if log:
                log("Removed a leftover NetworkManager unmanage config from a previous session.")
        except OSError as e:
            if log:
                log(f"Could not remove leftover NM unmanage config: {e}")
        if which("nmcli"):
            run(["nmcli", "general", "reload"], log=None)
    # Reset any interface a prior crash / force-quit / failed restore left in
    # `type monitor` back to managed BEFORE the NM restart below, so NM adopts a
    # usable card and the next Enable-monitor starts clean instead of erroring on
    # an already-monitor interface. Mirrors the documented manual reset, which
    # also begins with `airmon-ng stop`.
    cleared = False
    for i in _parse_iw_dev(_iw_dev()):
        if i.mode == "monitor":
            if which("airmon-ng"):
                run(["airmon-ng", "stop", i.name], timeout=30, log=log)
            leftover = _monitor_iface_now(prefer_phy=i.phy)
            if leftover:  # airmon-ng absent or a wlan0mon survived — force it managed
                run(["ip", "link", "set", leftover, "down"], log=log)
                run(["iw", "dev", leftover, "set", "type", "managed"], log=log)
                run(["ip", "link", "set", leftover, "up"], log=log)
            cleared = True
    if cleared and log:
        log("Reset a leftover monitor-mode interface from a previous session.")
    if which("systemctl"):
        # A prior run that didn't restore may have left NetworkManager stopped —
        # revive it so the user never has to do it by hand.
        if run(["systemctl", "is-active", "NetworkManager"]).out.strip() != "active":
            run(["systemctl", "start", "NetworkManager"], log=log)
            if log:
                log("Restarted NetworkManager (a previous session had left it stopped).")
        if "masked" in run(["systemctl", "is-enabled", "wpa_supplicant"]).text().lower():
            run(["systemctl", "unmask", "wpa_supplicant"], log=log)
            run(["systemctl", "start", "wpa_supplicant"], log=log)
            if log:
                log("Cleared a leftover wpa_supplicant mask from a previous session.")
    if which("nmcli"):
        run(["nmcli", "radio", "wifi", "on"], log=None)


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


_NM_UNMANAGE_CONF = "/etc/NetworkManager/conf.d/99-pr0v1dence-unmanaged.conf"
_IFACE_NAME_RE = re.compile(r"^[A-Za-z0-9._-]{1,15}$")


def _valid_iface_name(iface: str) -> bool:
    """True if `iface` is a plausible Linux netdev name (Linux caps names at 15
    bytes). Guards the drop-in write below so a hostile interface string can't
    inject newlines/extra keys into NetworkManager's config file."""
    return bool(iface) and bool(_IFACE_NAME_RE.match(iface))


def _set_nm_unmanaged(iface: str, unmanaged: bool, log: Optional[LogFn] = None) -> None:
    """Add/remove a NetworkManager drop-in that makes it permanently ignore
    `iface`, then reload NM. This is more thorough than the runtime
    `nmcli device set … managed no` (which NM doesn't always fully honor)."""
    if not _valid_iface_name(iface):
        return
    try:
        if unmanaged:
            with open(_NM_UNMANAGE_CONF, "w") as f:
                f.write(f"[keyfile]\nunmanaged-devices=interface-name:{iface}\n")
        elif os.path.exists(_NM_UNMANAGE_CONF):
            os.remove(_NM_UNMANAGE_CONF)
    except OSError as e:
        if log:
            log(f"NM unmanage config update failed: {e}")
        return
    if which("nmcli"):
        run(["nmcli", "general", "reload"], log=log)


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
    # Record which teardown path ran so a failure can be rolled back exactly.
    # This is the crux of the "NetworkManager goes kaboot and never comes back"
    # bug: both paths tear networking DOWN *before* the fallible `airmon-ng start`,
    # so if that step fails (common when the rtl8xxxu adapter resets off the USB
    # bus) we must undo the teardown before returning, or the box is left offline.
    surgical = False
    killed_nm = False
    if kill_networkmanager or which("nmcli") is None:
        run(["airmon-ng", "check", "kill"], log=log)
        killed_nm = True
    else:
        # Surgical: make NetworkManager permanently ignore only this interface
        # (drop-in config + reload, which NM honors more fully than the runtime
        # `managed no`), then mask wpa_supplicant so it can't respawn. Keeps other
        # links up; on some drivers NM may still interfere and capture 0.
        surgical = True
        _set_nm_unmanaged(iface.name, True, log=log)
        run(["nmcli", "device", "set", iface.name, "managed", "no"], log=log)
        run(["systemctl", "mask", "--now", "wpa_supplicant"], log=log)
        run(["pkill", "-x", "wpa_supplicant"], log=log)

    def _rollback() -> None:
        """Undo the teardown above so a failed enable never strands the machine
        with NetworkManager dead / wpa_supplicant masked. Path-aware: check-kill
        only STOPPED the services, the surgical path also MASKED wpa_supplicant
        and wrote the unmanage drop-in."""
        if surgical:
            run(["systemctl", "unmask", "wpa_supplicant"], log=log)
            run(["systemctl", "start", "wpa_supplicant"], log=log)
            _set_nm_unmanaged(iface.name, False, log=log)   # remove drop-in + reload
            if which("nmcli"):
                run(["nmcli", "device", "set", iface.name, "managed", "yes"], log=log)
        elif killed_nm:
            run(["systemctl", "unmask", "wpa_supplicant"], log=log)  # harmless if not masked
            if which("nmcli"):
                run(["nmcli", "radio", "wifi", "on"], log=log)
            r = run(["systemctl", "restart", "NetworkManager"], log=log)
            if not r.ok:
                run(["service", "network-manager", "restart"], log=log)
        if log:
            log("Monitor-enable failed — restored NetworkManager / wpa_supplicant so "
                "you are not left offline.")

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
        _rollback()
        return None

    # Fallback: manual switch on the original interface name.
    if log:
        log("airmon-ng did not produce a monitor interface; trying manual iw method.")
    run(["ip", "link", "set", iface.name, "down"], log=log)
    run(["iw", "dev", iface.name, "set", "type", "monitor"], log=log)
    run(["ip", "link", "set", iface.name, "up"], log=log)
    mon = _monitor_iface_now(prefer_phy=iface.phy)
    if mon:
        if log:
            log(f"Monitor mode enabled (manual): {mon}")
        return mon
    if log:
        log("Failed to enable monitor mode. If the adapter keeps dropping, it's the USB "
            "passthrough resetting it — see the driver/USB notes.")
    _rollback()
    return None


def disable_monitor(mon_iface: str, restore_services: bool = True,
                    log: Optional[LogFn] = None) -> bool:
    """Take the card out of monitor mode and hand the interface back.

    Returns True only if the recovery actually succeeded (monitor teardown, if the
    adapter is still present, AND the NetworkManager restart), so the GUI can tell
    the user honestly whether networking is back rather than assuming it worked.

    Undoes whatever either enable path did: unmask wpa_supplicant, drop the
    surgical unmanage drop-in, turn the wifi radio back on, restart NetworkManager
    (the default `check kill` path stopped it — restarting restores WiFi and
    re-adopts the still-up wired link), and re-manage the interface.
    """
    # If the adapter reset off the bus, `mon_iface` names a device that no longer
    # exists. Running airmon-ng/nmcli against a gone device only spews scary
    # `rc!=0 Device not found` lines into the Activity log (the "error" the user
    # sees on Restore) — skip those, but STILL restart NetworkManager to recover.
    present = os.path.exists(f"/sys/class/net/{mon_iface}")
    stop_ok = True
    if present:
        stop_ok = run(["airmon-ng", "stop", mon_iface], timeout=30, log=log).ok
    elif log:
        log(f"'{mon_iface}' is no longer present (adapter reset/unplugged); skipping "
            "airmon-ng stop and restarting NetworkManager to recover networking.")
    if not restore_services:
        return stop_ok
    run(["systemctl", "unmask", "wpa_supplicant"], log=log)
    base = mon_iface[:-3] if mon_iface.endswith("mon") else mon_iface
    _set_nm_unmanaged(base, False, log=log)
    if which("nmcli"):
        run(["nmcli", "radio", "wifi", "on"], log=log)
    r = run(["systemctl", "restart", "NetworkManager"], log=log)
    nm_ok = r.ok or run(["service", "network-manager", "restart"], log=log).ok
    # Only re-manage the interface if it still exists, else nmcli's "Device not
    # found" (rc!=0) surfaces as a spurious error even though NM is already back.
    if which("nmcli") and os.path.exists(f"/sys/class/net/{base}"):
        run(["nmcli", "device", "set", base, "managed", "yes"], log=log)
    ok = nm_ok and (stop_ok or not present)
    if log:
        log("Monitor mode disabled; NetworkManager restarted, WiFi restored." if ok
            else "Restore INCOMPLETE: NetworkManager restart or monitor teardown failed — "
                 "WiFi may still be down (see the rc lines above).")
    return ok


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
