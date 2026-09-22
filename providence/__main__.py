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
    p = argparse.ArgumentParser(prog="providence", description=f"{__app_name__} - authorized WPA handshake capture GUI")
    p.add_argument("--demo", action="store_true",
                   help="run with simulated data and no radio access (safe on any machine)")
    p.add_argument("--selftest", action="store_true",
                   help="run the offline logic tests and exit (no GUI, no radio)")
    p.add_argument("--version", action="store_true")
    args = p.parse_args(argv)

    if args.version:
        print(f"{__app_name__} {__version__}")
        return 0

    if args.selftest:
        from .selftest import run as run_selftest
        return run_selftest()

    if not args.demo and sys.platform.startswith("linux") and not _is_root():
        print("Note: monitor mode, scanning and deauth need root. Re-run with sudo, e.g.:")
        print("  sudo python3 -m providence")
        print("(Continuing anyway - tool actions will fail without privileges. Use --demo to preview the UI.)")

    from .gui import run_gui
    run_gui(demo=args.demo)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
