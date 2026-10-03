#!/bin/sh
# Installs Shield for the current user. No root, nothing outside your home folder.
#
#     ./install.sh                   install or upgrade
#     ./install.sh --make-default    ...and make Shield your default web browser
#     ./install.sh --uninstall       remove it (your settings, history and vault in ~/.shieldbrowser are kept)
#
# Installing under your home folder is deliberate: it is what lets Shield's own "Install and restart" update itself
# without asking for a password. Run from a different folder with:  SHIELD_PREFIX=/some/folder ./install.sh
set -eu

HERE="$(cd "$(dirname "$0")" && pwd)"
PREFIX="${SHIELD_PREFIX:-$HOME/.local/share}"
DEST="$PREFIX/Shield"
BIN="$HOME/.local/bin"
APPS="${XDG_DATA_HOME:-$HOME/.local/share}/applications"
ICONS="${XDG_DATA_HOME:-$HOME/.local/share}/icons/hicolor/512x512/apps"

refresh() {
  command -v update-desktop-database >/dev/null 2>&1 && update-desktop-database "$APPS" >/dev/null 2>&1 || true
  command -v gtk-update-icon-cache >/dev/null 2>&1 && gtk-update-icon-cache -q -t "${XDG_DATA_HOME:-$HOME/.local/share}/icons/hicolor" >/dev/null 2>&1 || true
}

if [ "${1:-}" = "--uninstall" ]; then
  rm -rf "$DEST" "$DEST.new" "$DEST.old"
  rm -f "$BIN/shield" "$APPS/shield.desktop" "$ICONS/shield.png"
  refresh
  echo "Shield was removed. Your data is still in ~/.shieldbrowser (delete that folder if you want it gone too)."
  exit 0
fi

[ -x "$HERE/Shield/Shield" ] || { echo "Run this from the unpacked Shield folder (it should contain a Shield/ folder next to install.sh)." >&2; exit 1; }
mkdir -p "$PREFIX" "$BIN" "$APPS" "$ICONS"

# Copy beside the old install, then swap, so an interrupted upgrade never leaves half a Shield.
rm -rf "$DEST.new" "$DEST.old"
cp -a "$HERE/Shield" "$DEST.new"
[ -d "$DEST" ] && mv "$DEST" "$DEST.old"
mv "$DEST.new" "$DEST"
rm -rf "$DEST.old"

ln -sf "$DEST/Shield" "$BIN/shield"
[ -f "$HERE/shield.png" ] && cp "$HERE/shield.png" "$ICONS/shield.png"
cat > "$APPS/shield.desktop" <<EOF
[Desktop Entry]
Type=Application
Name=Shield
GenericName=Web Browser
Comment=A zero-bloat, security-first browser
Exec="$DEST/Shield" %U
Icon=shield
Terminal=false
Categories=Network;WebBrowser;
MimeType=text/html;application/xhtml+xml;x-scheme-handler/http;x-scheme-handler/https;
StartupWMClass=Shield
StartupNotify=true
EOF
refresh

# Shield bundles its own web engine, but a few system libraries still have to exist. Say so now rather than fail silently.
missing=""
for lib in $(find "$DEST" \( -name 'libqxcb.so' -o -name 'libQt6WebEngineCore.so*' \) 2>/dev/null | head -n 4); do
  missing="$missing $(ldd "$lib" 2>/dev/null | sed -n 's/^[[:space:]]*\(.*\) => not found.*/\1/p')"
done
missing="$(printf '%s\n' $missing | sort -u | tr '\n' ' ')"
if [ -n "$(printf '%s' "$missing" | tr -d ' ')" ]; then
  echo
  echo "Shield is installed, but these system libraries are missing, so it may not start: $missing"
  echo "  Debian/Ubuntu:  sudo apt install libxcb-cursor0 libnss3 libasound2 libxkbcommon-x11-0"
  echo "  Fedora:         sudo dnf install xcb-util-cursor nss alsa-lib libxkbcommon-x11"
fi

echo
echo "Shield is installed in $DEST"
echo "Start it from your applications menu, or run:  shield   (make sure $BIN is on your PATH)"
if [ "${1:-}" = "--make-default" ]; then
  xdg-settings set default-web-browser shield.desktop && echo "Shield is now your default browser."
else
  echo "To make it your default browser:  xdg-settings set default-web-browser shield.desktop"
fi
