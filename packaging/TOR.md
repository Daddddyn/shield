# Tor in Shield: one folder per system

Each installer carries only its own system's Tor. `packaging/get_tor.py` puts them in the (git-ignored) `tor/` folder:

    tor/tor_win/         Windows x64
    tor/tor_mac_arm64/   macOS, Apple Silicon        tor/tor_mac_x64/   macOS, Intel
    tor/tor_lin_x64/     Linux x64                   tor/tor_lin_arm64/ Linux arm64

Inside each is the Tor Project's Expert Bundle unchanged (`tor/` with the tor program and `pluggable_transports/` for obfs4 and
Snowflake, plus `data/` with the country database). `shield.spec` packs just the folder for the system it is building on, so the
Windows installer has `tor_win`, the Apple Silicon `.dmg` has `tor_mac_arm64`, and so on. At run time `shield_proxy.py` looks only
in the folder for the system it is running on (`tor_folder()`), so a mixed-up folder is never used.

## First time

    python packaging/get_tor.py --update       # needs GnuPG; writes packaging/tor_lock.json. Commit that file.

Confirm `SIGNING_KEY` in `get_tor.py` against https://support.torproject.org/tbb/how-to-verify-signature/ the first time.

## Every build

`build.ps1` and `build.sh` run `python packaging/get_tor.py` for you (also on GitHub Actions). It downloads this system's Tor,
accepts it only if it matches the SHA-256 in the lock, unpacks it safely, and leaves it in `tor/`. No GnuPG needed. Then the build:

1. packs the folder into the program;
2. macOS: signs `tor`, the bridge programs and their libraries one by one, then the whole app (Apple Silicon won't run unsigned
   programs and notarization rejects any unsigned program in the app);
3. runs the packed program's self-test, which now includes **private connection (Tor)**. On THIS system it checks that
   `tor` starts, that Tor accepts the configuration Shield writes for it (direct, obfs4, Snowflake), and that each bridge program
   starts and answers in Tor's transport protocol. It needs no network. A build that fails this is not shipped.

## Moving to a newer Tor

Run `python packaging/get_tor.py --update`, commit `tor_lock.json`, build. Do this with each Shield release: Tor versions that are
too old stop being accepted by the network. `--mirror-url https://...` adds your own copy of the files to the lock as a second
download address (handy because torproject.org removes old versions and is blocked in some places).

## What changes in size

Each installer grows by roughly the size of one Expert Bundle (tens of megabytes unpacked, much less compressed).
