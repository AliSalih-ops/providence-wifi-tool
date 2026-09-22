# Architecture

pr0v1dence is a Tkinter GUI over the aircrack-ng suite. It is deliberately
layered so the parts that face **hostile input** and **root** are small, pure,
and testable, and the GUI is a thin shell on top. This document is the map for
changing or extending it safely.

## Layers (bottom → top)

| Module | Responsibility | Touches |
|---|---|---|
| `util.py` | subprocess helpers (`run`/`spawn`/`terminate`), `is_mac` | processes |
| `deps.py` | external-tool detection + apt hints | PATH only |
| `iface.py` | adapter discovery, monitor mode, MAC, band detection | `iw`/`airmon-ng`/`macchanger` |
| `scan.py` | airodump-ng scan **+ CSV parsing** (hostile input) | `airodump-ng` |
| `capture.py` | argv builders, handshake/PMKID **sessions**, verify, export | aircrack-ng/hcxdumptool |
| `session.py` | the `Session` Protocol every capture type implements | — (typing) |
| `demo.py` | simulated sessions/data for `--demo` | nothing |
| `gui.py` | Tkinter app: widgets, threading, timers, handlers | all of the above |
| `__main__.py` | entry point, env hardening, `--demo/--selftest/--stresstest` | env |
| `selftest.py` / `stress.py` | unit tests / fuzz harness | nothing |

**Rule of thumb:** logic that parses tool output or builds a command line lives
as a **pure function** in `scan.py`/`capture.py`/`iface.py` (so `selftest.py`
asserts it and `stress.py` fuzzes it). The GUI only orchestrates.

## The `Session` contract

`session.py` defines the `Session` Protocol: `start / running / stop / log_tail /
cap_file / export_22000`. `CaptureSession` (handshake) and `PmkidSession`
implement it, as do their `Demo*` twins, and `selftest.py` asserts conformance.
The GUI drives any session through this interface only — it never reaches into a
session's internals.

### Adding a new capture type (e.g. WEP IVs, a WPA3 probe)
1. Add a **pure argv builder** in `capture.py` (like `capture_argv`) and unit-test
   it in `selftest.py`; add hostile inputs to `stress.py`.
2. Add a class implementing `Session` (copy `PmkidSession`'s shape: bounded temp
   files under `out_dir`, timestamped prefix, `is_mac`/channel validation, fail
   safe on `start`).
3. In `gui.py` add a panel and a `start/stop/tick` handler trio, reusing:
   - the **timer registry** `_schedule(name, ms, fn)` / `_cancel(name)` (never a
     raw `after()` self-loop), and
   - a **generation token** bumped on teardown so a late worker result is ignored.
No other GUI code changes.

## Threading model

Tkinter is single-threaded. Everything radio-facing runs on a **daemon worker**
via `App._run_async(work, done)`; results return to the Tk main thread through
two `queue.Queue`s drained by `_pump()` every `PUMP_MS`. Workers **never** touch
a widget. Periodic work uses the named-timer registry so Stop/Start can't stack
loops, and each verify/PMKID result is gated on a per-session generation token.

## Security model (it runs as **root**, on **hostile RF**)

- **Least environment.** Launchers elevate with plain `sudo` (never `sudo -E`)
  and forward only `DISPLAY`/`XAUTHORITY`. `__main__` additionally scrubs
  `LD_PRELOAD`/`LD_LIBRARY_PATH`/`PYTHONPATH` and pins `PATH` to system dirs, so
  a hostile env can't reach the root interpreter or the root child tools.
- **No shell.** Every external call is an argv list (`shell=False`); BSSIDs and
  MACs are validated with `is_mac`, channels with `is_valid_channel`, before they
  reach a command line.
- **Filesystem.** `umask(0o077)`; captures default to a **root-owned** dir;
  `_ensure_out_dir` refuses a symlinked target and tightens perms via an
  `O_NOFOLLOW` handle. The tool does **not** chown its output to the invoking
  user (that was a symlink-privesc primitive).
- **Bounded input.** The CSV read is byte-capped, parsing is row-capped
  (`MAX_ROWS`), the AP list/Treeview are capped (`MAX_APS`), the log queue and
  on-disk log are bounded — so a beacon flood can't exhaust memory or wedge the
  UI. ESSIDs are stripped of control chars (no terminal-escape injection).
- **Scope.** Captures pin to one BSSID (`airodump --bssid`; PMKID via an AP
  whitelist on hcxdumptool ≤6.2 or a compiled BPF on 6.3+, else it **refuses**);
  detection and 22000 export are re-scoped to the target so a neighbour's frames
  are never reported or handed off.
- **No network.** The app opens no sockets and has no telemetry/auto-update.

## Testing

- `python3 -m providence --selftest` — pure-logic unit tests (parsers, argv
  builders, classification, scoping, Session conformance).
- `python3 -m providence --stresstest` — fuzz harness: adversarial/boundary
  inputs for every parser, asserting no crash, bounded time, and path
  containment.
- `python3 -m providence --demo` — the full GUI on simulated data, no radio/root.

The live radio path can only be exercised on real Kali hardware with a
monitor-capable adapter.
