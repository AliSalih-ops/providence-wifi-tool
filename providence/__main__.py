"""Entry point:  python3 -m providence  [--demo] [--selftest]"""

from __future__ import annotations

import argparse
import os
import sys

from . import __app_name__, __version__


def _is_root() -> bool:
    return hasattr(os, "geteuid") and os.geteuid() == 0


def main(argv=None) -> int:
    # Captures and logs can contain sensitive material; keep everything this
    # process (and the child tools that inherit the umask) writes to 0600/0700
    # instead of world-readable.
    try:
        os.umask(0o077)
    except Exception:
        pass
    # Defense-in-depth (the launchers already avoid `sudo -E`): strip env vectors
    # that would otherwise be inherited by the ROOT child tools we spawn, and pin
    # PATH to system dirs so a hijacked PATH cannot shadow iw/airodump/etc.
    for _v in ("LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "PYTHONPATH", "PYTHONHOME"):
        os.environ.pop(_v, None)
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        os.environ["PATH"] = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

    p = argparse.ArgumentParser(prog="providence", description=f"{__app_name__} - authorized WPA handshake capture GUI")
    p.add_argument("--demo", action="store_true",
                   help="run with simulated data and no radio access (safe on any machine)")
    p.add_argument("--selftest", action="store_true",
                   help="run the offline logic tests and exit (no GUI, no radio)")
    p.add_argument("--stresstest", action="store_true",
                   help="fuzz every hostile-input parser and exit (no GUI, no radio)")
    p.add_argument("--version", action="store_true")
    args = p.parse_args(argv)

    if args.version:
        print(f"{__app_name__} {__version__}")
        return 0

    if args.selftest:
        from .selftest import run as run_selftest
        return run_selftest()

    if args.stresstest:
        from .stress import run as run_stress
        return run_stress()

    if not args.demo and sys.platform.startswith("linux") and not _is_root():
        print("Note: monitor mode, scanning and deauth need root. Re-run with sudo, e.g.:")
        print("  sudo python3 -m providence")
        print("(Continuing anyway - tool actions will fail without privileges. Use --demo to preview the UI.)")

    from .gui import run_gui
    run_gui(demo=args.demo)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
