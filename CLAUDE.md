# CLAUDE.md — context for working on this repo

This is **pr0v1dence WiFi Tool** (repo `providence-wifi-tool`): a Python 3 / Tkinter
GUI over the aircrack-ng suite for **authorized** WPA/WPA2 handshake + PMKID
capture on Kali. Owner: Ali Salih. Read `ARCHITECTURE.md` for the full design.

## How to run / test
- `python3 -m providence --demo`      — GUI on simulated data (no radio/root)
- `python3 -m providence --selftest`  — 124 offline unit checks
- `python3 -m providence --stresstest`— 92 hostile-input fuzz checks
- `sudo python3 -m providence`         — the real thing (needs root + a monitor adapter)
- Package/command after install: `pr0v1dence`

Always run `--selftest` and `--stresstest` after changes; keep them green.

## Rules (important)
- **Commits: author as Ali alone. NEVER add a `Co-Authored-By: Claude` trailer**
  or any AI attribution. Use `git commit --author="Ali Salih <ali.s.mirkhan@gmail.com>"`.
- Don't weaken the security hardening (see ARCHITECTURE.md → Security model): no
  `sudo -E`; no chowning loot to the invoking user; keep the input bounds and the
  `is_mac`/channel validation; PMKID stays BSSID-scoped or refuses.

## This machine (the live test bed)
- **Kali in a VirtualBox VM.** Internet is **wired `eth0`** (survives NetworkManager
  being killed). WiFi adapter is a **TP-Link TL-WN722N v3 = Realtek RTL8188EUS**,
  USB `2357:010c`, on the **in-kernel `rtl8xxxu` driver**, as `wlan0`.
- The adapter is **2.4 GHz only** (can't see 5 GHz nets like the "…-5g" SSIDs).
- USB passthrough + rtl8xxxu is **flaky**: toggling monitor mode can reset/wedge
  the adapter off the USB bus. A stuck adapter needs an unplug/replug (re-tick in
  VirtualBox → Devices → USB) — no software can un-wedge a vanished USB device.

## The monitor-mode saga (what we learned the hard way)
Getting airodump to actually capture came down to one fact, proven by isolation
tests on this box:
- **NetworkManager itself jams the capture.** With NM alive, airodump hops
  channels but the CSV stays empty **even when** the interface is unmanaged,
  wifi radio is off, and wpa_supplicant is dead. Only killing NM (`airmon-ng
  check kill`, which also kills wpa_supplicant) lets it capture.
- **Killing NM does NOT drop the wired internet** (verified: `ping` 3/3 after
  `check kill`). So `enable_monitor` now defaults to `kill_networkmanager=True`
  (check kill); `disable_monitor` restores (unmask wpa_supplicant, `nmcli radio
  wifi on`, restart NetworkManager, re-manage). A "keep other Wi-Fi up (surgical)"
  checkbox is the opt-in no-kill path (may capture 0 — that's expected).
- Earlier dead ends (already handled, don't reopen): a TTY/pty theory (airodump
  captures fine on a pipe once NM is dead — pty was reverted); masking/stopping
  only wpa_supplicant (NM respawns it); `nmcli managed no` / `radio wifi off`
  (NM still interferes).

## The "kaboot cascade" bug — FIXED 2026-09-24 (commit 278b61c)
Symptom was: enable monitor -> NetworkManager dies AND adapter not in monitor AND
can't scan; Restore -> error; quit+relaunch+enable -> another error. A 34-agent
audit (19 confirmed findings) traced it to one structural flaw: the teardown and
the recovery gated on different things, so a failed enable orphaned NM with no
way back. Fixes now in tree:
- `enable_monitor` is **atomic** — records which teardown ran (check-kill vs
  surgical) and rolls it back on every failure path, so a failed `airmon-ng
  start` (adapter reset off USB) never leaves NM dead / wpa_supplicant masked.
- `disable_monitor` skips airmon-ng/nmcli against a **vanished** adapter (no more
  spurious "Device not found" error lines = the old "Restore error"), still
  restarts NM, returns an honest success bool.
- `restore_supplicant` startup self-heal now also **resets a leftover monitor
  iface** back to managed, so the next enable starts clean.
- GUI: `_nm_torn_down` flag (independent of `mon_iface`) lets Restore/Quit revive
  NM even after an enable that produced no monitor iface; radio buttons gated in
  `_refresh_action_states` (no overlapping workers); `_poll_scan` try/except so a
  bad Treeview insert can't kill scanning; `_refresh_ap_tree` de-dupes BSSIDs.
Verified: 132 selftest + 93 stress on Windows & Linux; full demo GUI flow under
real Tk. **Still needs one live check on the VM** (only the radio can prove it).

## Open decision — surgical vs check-kill default
The owner's stated intended behavior is the SURGICAL path (wlan0 leaves NM, NM
stays alive). It is currently the **opt-in** checkbox; the DEFAULT is still
check-kill because on this rtl8xxxu adapter NM-alive empirically gave 0 networks.
The surgical path now uses the more-thorough drop-in unmanage + has rollback, so
it may finally capture with NM alive. **Action:** tick "keep other Wi-Fi up" on
the VM and scan — if it shows networks, make surgical the default; if still 0,
it's driver interference and check-kill stays the default.

**To debug live:** reproduce a failed second scan, then check the exact state —
`iw dev` (is `wlan0` `type monitor`?), `systemctl status NetworkManager`,
`ps aux | grep -E 'wpa_supplicant|NetworkManager'`, and the app's Activity log /
the CSV at `/tmp/providence-scan-*/scan-01.csv`. The app's `ScanSession.diagnostic()`
already reports the CSV state into the log after ~8s of 0 networks. Figure out
whether it's monitor-enable failing, airodump dying (`log_tail`), the adapter
wedged, or parsing — and fix that specific link. A reliable reset for a wedged
state: `sudo airmon-ng stop wlan0; sudo systemctl unmask wpa_supplicant; sudo
nmcli radio wifi on; sudo systemctl restart NetworkManager` (then replug if
still stuck).
