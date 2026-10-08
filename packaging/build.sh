#!/usr/bin/env bash
# Builds Shield for macOS or Linux: the program, a self-test of it, and the installer package.
#
#     bash packaging/build.sh
#
# macOS  -> release/Shield-<version>-macos-<arm64|x64>.dmg
# Linux  -> release/Shield-<version>-linux-<x64|arm64>.tar.gz   (contains install.sh)
#
# It builds for the CPU it runs on: PyInstaller can't cross-compile, so build the Apple Silicon Mac package on an Apple
# Silicon Mac, the Intel one on an Intel Mac, and the Linux one on Linux (see .github/workflows/build.yml to let GitHub do all three).
# Build Linux on the OLDEST distribution you want to support (Ubuntu 22.04 is a good choice): a build made on a new
# system won't start on older ones.
#
# Needs: Python 3.12+.  macOS also needs the Xcode command line tools (xcode-select --install).
# Optional (macOS), for a build that opens without Gatekeeper warnings (needs a paid Apple Developer account):
#     export SHIELD_CODESIGN_IDENTITY="Developer ID Application: Your Name (TEAMID)"
#     export SHIELD_NOTARY_PROFILE="shield-notary"     # made once with:  xcrun notarytool store-credentials shield-notary
set -euo pipefail
cd "$(dirname "$0")/.."
ROOT="$PWD"

SKIP_PKG=0; NO_UPGRADE=0
for a in "$@"; do
  case "$a" in
    --skip-installer) SKIP_PKG=1 ;;
    --no-upgrade) NO_UPGRADE=1 ;;
    *) echo "Unknown option: $a (use --skip-installer or --no-upgrade)"; exit 2 ;;
  esac
done

step() { printf '\n\033[36m== %s\033[0m\n' "$1"; }
fail() { printf '\n\033[31mFAILED: %s\033[0m\n' "$1" >&2; exit 1; }

case "$(uname -s)" in Darwin) OS=macos ;; Linux) OS=linux ;; *) fail "This script is for macOS and Linux. On Windows use build.ps1." ;; esac
case "$(uname -m)" in arm64|aarch64) ARCH=arm64 ;; x86_64|amd64) ARCH=x64 ;; *) fail "Unsupported CPU: $(uname -m)" ;; esac

# ---- version (single source of truth: shield_core.py) ------------------------------------------------------
VERSION="$(sed -n 's/^VERSION[[:space:]]*=[[:space:]]*"\([^"]*\)".*/\1/p' shield_core.py | head -n1)"
[ -n "$VERSION" ] || fail "Couldn't read VERSION from shield_core.py"
echo "Building Shield $VERSION for $OS-$ARCH"

# ---- python environment ------------------------------------------------------------------------------------
step "Python environment"
PYTHON="${PYTHON:-python3}"
if [ ! -x .venv-build/bin/python ]; then
  "$PYTHON" -m venv .venv-build || fail "Couldn't create a virtual environment. Is Python 3.12+ installed?"
fi
PY="$ROOT/.venv-build/bin/python"
"$PY" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 12) else 1)' || fail "Python 3.12 or newer is needed (found $("$PY" --version))"
"$PY" --version
UPGRADE=(); [ "$NO_UPGRADE" = 1 ] || UPGRADE=(--upgrade)
"$PY" -m pip install --quiet --upgrade pip
"$PY" -m pip install --quiet "${UPGRADE[@]}" -r requirements.txt pyinstaller || fail "pip couldn't install the requirements"
ENGINE="$("$PY" -c "from importlib.metadata import version; print(version('PyQt6-WebEngine'))")"
echo "Web engine: PyQt6-WebEngine $ENGINE"

# ---- icons -------------------------------------------------------------------------------------------------
NEED_ICON=""
[ "$OS" = macos ] && [ ! -f packaging/shield.icns ] && NEED_ICON=icns
[ "$OS" = linux ] && [ ! -f packaging/shield.png ] && NEED_ICON=png
if [ -n "$NEED_ICON" ]; then
  step "Icon"
  QT_QPA_PLATFORM="${QT_QPA_PLATFORM:-offscreen}" "$PY" packaging/make_icon.py "$NEED_ICON" || fail "Couldn't create the icon"
fi
# the Linux package also carries the PNG for the launcher entry
if [ "$OS" = linux ] && [ ! -f packaging/shield.png ]; then QT_QPA_PLATFORM=offscreen "$PY" packaging/make_icon.py png; fi

# ---- Tor for this system -----------------------------------------------------------------------------------
# Each package carries only its own system's Tor (tor/tor_mac_arm64, tor/tor_lin_x64, ...). get_tor.py fetches it, checked against packaging/tor_lock.json.
step "Tor (the private connection's program)"
"$PY" packaging/get_tor.py || fail "Couldn't get Tor. If packaging/tor_lock.json doesn't exist yet, run once:  python packaging/get_tor.py --update"

# ---- program -----------------------------------------------------------------------------------------------
step "Packing the program (PyInstaller)"
rm -rf dist build
"$PY" -m PyInstaller packaging/shield.spec --noconfirm --clean --distpath dist --workpath build || fail "PyInstaller failed"
if [ "$OS" = macos ]; then
  APP="dist/Shield.app"; EXE="$APP/Contents/MacOS/Shield"
else
  APP="dist/Shield"; EXE="$APP/Shield"
fi
[ -x "$EXE" ] || fail "$EXE wasn't produced"
echo "Program: $(du -sm "$APP" | cut -f1) MB"

# ---- macOS: sign (Apple Silicon refuses to run unsigned code, so even without an Apple account it gets an ad-hoc signature)
if [ "$OS" = macos ]; then
  # Tor and its bridge programs are code too. Each is signed on its own first (inside out): Apple Silicon won't run an unsigned
  # program and notarization rejects any unsigned program anywhere in the app. The Tor Project's own signature is replaced by yours.
  step "Signing Tor and the bridge programs"
  TOR_SIGN=(--force --sign "${SHIELD_CODESIGN_IDENTITY:--}")
  [ -n "${SHIELD_CODESIGN_IDENTITY:-}" ] && TOR_SIGN+=(--options runtime --timestamp)
  while IFS= read -r f; do
    if file -b "$f" | grep -q "Mach-O"; then codesign "${TOR_SIGN[@]}" "$f" || fail "couldn't sign $f"; fi
  done < <(find "$APP" -path "*/tor/tor_mac_*" -type f)
  if [ -n "${SHIELD_CODESIGN_IDENTITY:-}" ]; then
    step "Signing Shield.app (Developer ID, hardened runtime)"
    codesign --force --deep --options runtime --timestamp --entitlements packaging/macos/entitlements.plist \
             --sign "$SHIELD_CODESIGN_IDENTITY" "$APP" || fail "codesign failed"
    codesign --verify --deep --strict "$APP" || fail "The signature doesn't verify"
  else
    step "Signing Shield.app (ad-hoc)"
    codesign --force --deep --sign - "$APP" || fail "ad-hoc codesign failed"
    printf '\033[33mNot signed with a Developer ID (SHIELD_CODESIGN_IDENTITY not set). macOS will warn people who download the .dmg.\033[0m\n'
  fi
fi

# ---- self-test of the packed program -----------------------------------------------------------------------
step "Self-test of the packed program"
REPORT="$ROOT/build/selftest.json"
if [ "$OS" = linux ] && [ -z "${DISPLAY:-}${WAYLAND_DISPLAY:-}" ]; then export QT_QPA_PLATFORM=offscreen; fi
"$EXE" --selftest "$REPORT" || true
[ -f "$REPORT" ] || fail "The packed program didn't write a self-test report. Check ~/.shieldbrowser/shield.log"
"$PY" - "$REPORT" <<'PYEOF' || fail "The packed program is missing something (see above). Don't ship this build."
import json, sys
r = json.load(open(sys.argv[1], encoding="utf-8"))
for name, c in r["checks"].items():
    print(f"  [{'ok  ' if c['ok'] else 'FAIL'}] {name}: {c['detail']}")
sys.exit(0 if r.get("ok") else 1)
PYEOF
echo "Self-test passed."

[ "$SKIP_PKG" = 1 ] && { echo; echo "Done (program only): $APP"; exit 0; }

# ---- installer package -------------------------------------------------------------------------------------
mkdir -p release
if [ "$OS" = macos ]; then
  step "Building the disk image"
  OUT="release/Shield-$VERSION-macos-$ARCH.dmg"
  rm -rf build/dmg "$OUT"; mkdir -p build/dmg
  ditto "$APP" build/dmg/Shield.app
  ln -s /Applications build/dmg/Applications
  hdiutil create -volname "Shield" -srcfolder build/dmg -ov -format UDZO "$OUT" >/dev/null || fail "hdiutil failed"
  if [ -n "${SHIELD_CODESIGN_IDENTITY:-}" ]; then
    codesign --force --timestamp --sign "$SHIELD_CODESIGN_IDENTITY" "$OUT" || fail "Signing the disk image failed"
  fi
  if [ -n "${SHIELD_NOTARY_PROFILE:-}" ]; then
    [ -n "${SHIELD_CODESIGN_IDENTITY:-}" ] || fail "SHIELD_NOTARY_PROFILE is set but SHIELD_CODESIGN_IDENTITY isn't"
    step "Notarizing (Apple checks the app; this usually takes a few minutes)"
    xcrun notarytool submit "$OUT" --keychain-profile "$SHIELD_NOTARY_PROFILE" --wait || fail "Notarization failed"
    xcrun stapler staple "$OUT" || fail "Stapling the notarization ticket failed"
  elif [ -n "${SHIELD_CODESIGN_IDENTITY:-}" ]; then
    printf '\033[33mSigned but not notarized (SHIELD_NOTARY_PROFILE not set): Gatekeeper will still warn on first open.\033[0m\n'
  fi
else
  step "Building the .tar.gz"
  NAME="Shield-$VERSION-linux-$ARCH"
  OUT="release/$NAME.tar.gz"
  rm -rf "build/$NAME" "$OUT"; mkdir -p "build/$NAME"
  cp -a "$APP" "build/$NAME/Shield"
  cp packaging/linux/install.sh "build/$NAME/install.sh"; chmod 755 "build/$NAME/install.sh"
  cp packaging/shield.png "build/$NAME/shield.png"
  tar -C build --owner=0 --group=0 -czf "$OUT" "$NAME" || fail "tar failed"
fi

echo
printf '\033[32mBuilt: %s (%s MB)\033[0m\n' "$OUT" "$(( $(wc -c < "$OUT") / 1048576 ))"
echo "Next:  python packaging/release.py     (once every system's package is in release/; makes the signed update manifest)"
