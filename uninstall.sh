#!/usr/bin/env bash
# Remove Wifi-Cracker01 / WiFi Audit GUI. Leaves the apt packages installed.
set -euo pipefail

PREFIX="/opt/wifi-cracker01"
LAUNCHER="/usr/local/bin/wifi-audit"
DESKTOP="/usr/share/applications/wifi-audit.desktop"

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
