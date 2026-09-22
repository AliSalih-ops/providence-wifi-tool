#!/usr/bin/env bash
# Launcher for pr0v1dence WiFi Tool.
#
#   ./run.sh          -> launch the GUI (asks for sudo, needs it for radio work)
#   ./run.sh --demo   -> launch with simulated data, no radio, no root
#   ./run.sh --selftest -> run offline logic tests and exit
#
# On Kali/Debian the only prerequisites are python3, python3-tk, and the
# aircrack-ng suite:
#   sudo apt update && sudo apt install -y python3-tk aircrack-ng iw hcxtools
set -euo pipefail

cd "$(dirname "$0")"

# Demo/selftest don't need root; everything else does (monitor mode, deauth...).
needs_root=1
for a in "$@"; do
  case "$a" in
    --demo|--selftest|--version|-h|--help) needs_root=0 ;;
  esac
done

if ! python3 -c "import tkinter" 2>/dev/null; then
  echo "python3-tk is missing.  Install it with:  sudo apt install -y python3-tk" >&2
  exit 1
fi

if [[ "$needs_root" -eq 1 && "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "Radio actions need root; re-launching with sudo..."
  # No -E: forward only DISPLAY/XAUTHORITY so a hostile PYTHONPATH/LD_* can't
  # ride into the root interpreter and its root child tools.
  exec sudo DISPLAY="${DISPLAY:-}" XAUTHORITY="${XAUTHORITY:-}" python3 -m providence "$@"
fi

exec python3 -m providence "$@"
