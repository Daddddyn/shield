# Shipping Shield on Windows, macOS and Linux

Drop this `packaging` folder into your project next to `shield.py`, copy `.github/` to the project root, and replace
`shield.py` and `shield_update.py` with the versions in this kit. (Everything Windows-specific, `build.ps1`, `shield.iss`
and `register_windows.py`, is unchanged.)

What you get per system:

| System | Installer | In-app update |
|---|---|---|
| Windows | `Shield-Setup-<v>.exe` (Inno Setup, per user) | runs the installer silently, reopens Shield |
| macOS | `Shield-<v>-macos-arm64.dmg`, `...-x64.dmg` | copies the new `Shield.app` beside the old one, swaps after Shield quits, reopens |
| Linux | `Shield-<v>-linux-x64.tar.gz` with `install.sh` | unpacks beside the old folder, swaps after Shield quits, reopens |

Every system checks the same signed manifest, so one `release.py` run publishes for all of them.

## One-time setup

1. Do the signing-key and `UPDATE_URL` steps from before (you already have them: `UPDATE_PUBKEY` and `UPDATE_URL` stay as they are).
2. **Ship a Windows release with this kit first.** Existing Windows copies keep working untouched: the manifest's top-level
   fields still describe the Windows installer, exactly as before. Mac and Linux copies find their own entry under `platforms`.
3. Optional: put your name in `PUBLISHER` at the top of `shield.spec`, and set your own `BUNDLE_ID` there. **Never change
   `BUNDLE_ID` after people have installed:** the updater refuses an update whose bundle id differs from the installed app's.

## Every release

1. Raise `VERSION` in `shield_core.py`.
2. Build each system. PyInstaller can't cross-compile, so each package is built on its own system:
   - **Easiest: GitHub does it.** Actions tab > *Build installers* > Run workflow. When it finishes:
     `gh run download <run-id> --dir release`
   - **Or by hand:** Windows `powershell -ExecutionPolicy Bypass -File packaging\build.ps1`; on a Mac or Linux machine
     `bash packaging/build.sh`. Each one runs a self-test of the packed program and stops if it fails. Copy the results into `release/`.
3. `python packaging/release.py --notes "One sentence about what changed."`
   Finds every package for this version under `release/`, writes and signs one manifest, checks it with the same verifier
   Shield uses, and puts everything to upload in `release/upload/`. It refuses if the Windows installer is missing or your key
   doesn't match `UPDATE_PUBKEY`. A system with no package is simply not offered the update.
4. Upload installers first, manifest last:
   `gh release upload shield release/upload/Shield-* --clobber`
   `gh release upload shield release/upload/manifest.json release/upload/manifest.json.sig --clobber`

## macOS

- **Without an Apple Developer account** (free): the build is ad-hoc signed, which is enough for Apple Silicon to run it. People who
  download the `.dmg` in a browser see "can't be opened because Apple cannot check it": they right-click Shield > Open the first
  time (or System Settings > Privacy & Security > Open Anyway). **Updates from inside Shield don't trigger this**, because the
  download is made by Shield itself, not a browser.
- **With one** (US$99/year): set `SHIELD_CODESIGN_IDENTITY` ("Developer ID Application: Your Name (TEAMID)") and
  `SHIELD_NOTARY_PROFILE` (made once with `xcrun notarytool store-credentials`), and `build.sh` signs with the hardened runtime,
  notarizes and staples the `.dmg`. That removes the first-open warning. Signing in GitHub Actions needs your certificate stored as a
  secret; the simple route is to build the Mac packages on your own Mac when you want signed ones.
- Shield can only update itself if it sits somewhere you can write: `/Applications` (as an admin) or `~/Applications`. Run from
  the disk image or straight from Downloads, it saves the verified download and tells you to drag it into Applications.
- `Info.plist` already declares http/https and the camera, microphone and location reasons; without those macOS ends the app
  the moment a page asks.

## Linux

- People unpack the `.tar.gz` and run `./install.sh`. It installs to `~/.local/share/Shield`, adds a launcher entry and
  `~/.local/bin/shield`, needs no root, and tells them if a system library is missing. `./install.sh --make-default` also
  makes it the default browser; `./install.sh --uninstall` removes it (their data in `~/.shieldbrowser` stays).
- In-app updates work for that install, and for any copy in a folder the user can write to. A copy in `/opt` (root-owned)
  falls back to "downloaded and checked, here's the folder".
- Build on the **oldest** distro you want to support (the workflow uses Ubuntu 22.04). A package built on a newer system
  can fail to start on older ones.
- Not included, on purpose: `.deb`/`.rpm` (need root, so they can't update themselves) and AppImage (needs FUSE, which
  recent Ubuntu doesn't ship). Say so if you want either.

## Things to know

- **Keep the engine fresh.** Chromium security fixes arrive as new PyQt6-WebEngine releases. The build scripts upgrade them each
  build; release regularly (monthly is a good habit), not only when you change Shield.
- **One manifest, one version.** If you ship Windows first and Mac later, run `release.py` again once the Mac package exists
  (same version): it rebuilds the manifest with all of them, and Mac users are offered it from then on.
- **Windows SmartScreen, antivirus false positives, per-user install, what not to commit**: unchanged, see the Windows notes
  you already have. Add `.venv-build/` and `release/` to `.gitignore` (already there for Windows); macOS adds `packaging/shield.icns`
  and Linux `packaging/shield.png` as generated files you may commit.
- Settings, history, the vault and scanner rules live in `~/.shieldbrowser` on every system and are never touched by an update.
