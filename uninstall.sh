#!/usr/bin/env bash
# Remove providence-wifi-tool / pr0v1dence WiFi Tool. Leaves the apt packages installed.
set -euo pipefail

PREFIX="/opt/pr0v1dence"
LAUNCHER="/usr/local/bin/pr0v1dence"
DESKTOP="/usr/share/applications/pr0v1dence.desktop"

if [ "$(id -u)" -ne 0 ]; then
  exec sudo bash "$0" "$@"
fi

rm -f "$LAUNCHER"
rm -f "$DESKTOP"
rm -rf "$PREFIX"
update-desktop-database >/dev/null 2>&1 || true

echo "Removed the app, launcher and menu entry."
echo "The tools it used are still installed; remove them if you like with:"
echo "  sudo apt remove aircrack-ng hcxtools hcxdumptool macchanger"
