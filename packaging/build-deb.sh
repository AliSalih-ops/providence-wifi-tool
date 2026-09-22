#!/usr/bin/env bash
#
# Build the pr0v1dence-wifi-tool .deb. Run on Kali/Debian (needs dpkg-deb):
#
#   bash packaging/build-deb.sh
#
# Produces dist/pr0v1dence-wifi-tool_<version>_all.deb. Install with:
#
#   sudo apt install ./dist/pr0v1dence-wifi-tool_<version>_all.deb
#
# apt then pulls any missing tools (aircrack-ng, hcxdumptool, ...) — it never
# bundles their binaries, so there is nothing to conflict with a system copy.
#
set -euo pipefail

cd "$(dirname "$0")/.."                       # repo root
PKG="pr0v1dence-wifi-tool"
VERSION="$(python3 -c 'import providence; print(providence.__version__)' 2>/dev/null || echo 1.0.0)"
ARCH="all"

command -v dpkg-deb >/dev/null 2>&1 || { echo "dpkg-deb not found — run this on Kali/Debian." >&2; exit 1; }

STAGE="$(mktemp -d)"
trap 'rm -rf "$STAGE"' EXIT
ROOT="$STAGE/$PKG"
mkdir -p "$ROOT/DEBIAN" \
         "$ROOT/usr/lib/pr0v1dence/providence" \
         "$ROOT/usr/bin" \
         "$ROOT/usr/share/applications"

# --- the Python package (no compiled cruft) ---
cp providence/*.py "$ROOT/usr/lib/pr0v1dence/providence/"

# --- control: dependencies apt will resolve (tools are pulled, never bundled) ---
cat > "$ROOT/DEBIAN/control" <<EOF
Package: $PKG
Version: $VERSION
Section: net
Priority: optional
Architecture: $ARCH
Depends: python3, python3-tk, iw, iproute2, aircrack-ng, hcxtools, hcxdumptool, macchanger
Maintainer: Ali Salih <ali.s.mirkhan@gmail.com>
Description: pr0v1dence WiFi Tool - authorized WPA/WPA2 handshake & PMKID capture GUI
 A single graphical front-end over the aircrack-ng suite that walks the whole
 WPA/WPA2 handshake and PMKID capture workflow: adapter selection, monitor mode,
 scan, deauth, capture, verify, and hashcat export. Authorized-use only.
EOF

# --- launcher on PATH (re-execs as root for radio work) ---
cat > "$ROOT/usr/bin/pr0v1dence" <<'EOF'
#!/usr/bin/env bash
# pr0v1dence launcher (installed by the .deb).
needs_root=1
for a in "$@"; do case "$a" in --demo|--selftest|--version|-h|--help) needs_root=0 ;; esac; done
if [ "$needs_root" -eq 1 ] && [ "$(id -u)" -ne 0 ]; then
  exec sudo -E "$0" "$@"
fi
export PYTHONPATH="/usr/lib/pr0v1dence${PYTHONPATH:+:$PYTHONPATH}"
exec python3 -m providence "$@"
EOF
chmod 0755 "$ROOT/usr/bin/pr0v1dence"

# --- desktop entry ---
cp pr0v1dence.desktop "$ROOT/usr/share/applications/pr0v1dence.desktop"
chmod 0644 "$ROOT/usr/share/applications/pr0v1dence.desktop"

# --- refresh the menu database after install/remove ---
cat > "$ROOT/DEBIAN/postinst" <<'EOF'
#!/bin/sh
set -e
update-desktop-database >/dev/null 2>&1 || true
EOF
chmod 0755 "$ROOT/DEBIAN/postinst"
cp "$ROOT/DEBIAN/postinst" "$ROOT/DEBIAN/postrm"

mkdir -p dist
OUT="dist/${PKG}_${VERSION}_${ARCH}.deb"
dpkg-deb --root-owned-group --build "$ROOT" "$OUT"
echo "Built $OUT"
echo "Install with:  sudo apt install ./$OUT"
