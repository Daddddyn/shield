#!/usr/bin/env python3
"""
get_tor.py: puts the Tor programs for each system into its own folder, ready to be packed into that system's installer.

    tor/tor_win/         Windows x64
    tor/tor_mac_arm64/   macOS, Apple Silicon
    tor/tor_mac_x64/     macOS, Intel
    tor/tor_lin_x64/     Linux, x64
    tor/tor_lin_arm64/   Linux, arm64

(Macs and Linux each need two because the CPU differs; a Windows build is x64 only.) Inside each folder is the Tor Project's Expert
Bundle exactly as they ship it: tor/ (the tor program, pluggable_transports/ with obfs4 and Snowflake) and data/ (the country
database). shield.spec packs ONLY the folder for the system it is building on, so each installer carries just its own.

    python packaging/get_tor.py              this system's folder (what build.ps1 / build.sh run before every build)
    python packaging/get_tor.py --all        all five folders (to look at them, or to build for another system)
    python packaging/get_tor.py --only tor_mac_arm64
    python packaging/get_tor.py --update     move to the newest Tor release: needs GnuPG and a network; rewrites packaging/tor_lock.json
    python packaging/get_tor.py --check      verify the folders on disk against the lock (no network)

The lock (packaging/tor_lock.json, commit it) names the exact Tor release and the SHA-256 of every download and of every tor program.
Ordinary builds only ever accept a download that matches it, so they need no GnuPG and a changed file can't slip in. Only --update
trusts the Tor Project's own signature, and it refuses a signature made by any key but the one named below.

CONFIRM SIGNING_KEY against https://support.torproject.org/tbb/how-to-verify-signature/ the first time you use --update.
The tor/ folder is generated: keep it out of git (the build fetches it), which also keeps the programs' executable bits intact.
Standard library only.
"""
import argparse
import hashlib
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tarfile
import time
import urllib.request
from pathlib import Path, PurePosixPath

BASE = "https://dist.torproject.org/torbrowser"
ARCHIVE = "https://archive.torproject.org/tor-package-archive/torbrowser"
SIGNING_KEY = "EF6E286DDA85EA2A4BA7DE684E2C6E8793298290"       # Tor Browser Developers (signing key): CONFIRM before trusting
KEY_LOOKUP = "torbrowser@torproject.org"
FOLDERS = {"windows-x86_64": "tor_win", "macos-aarch64": "tor_mac_arm64", "macos-x86_64": "tor_mac_x64",
           "linux-x86_64": "tor_lin_x64", "linux-aarch64": "tor_lin_arm64"}
# Platforms the Tor Project does not publish in every release. --update skips them (with a note) instead of failing, and a lock
# without them is fine. Linux arm64: the stable Tor Browser series (15.x) has no build for it; only the 16.0 alpha series does.
OPTIONAL = {"linux-aarch64": "the stable Tor Browser series has no Linux arm64 build yet (only the 16.0 alpha series ships one)"}
HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
TOR_DIR = ROOT / "tor"
LOCK = HERE / "tor_lock.json"
CACHE = ROOT / "build" / "tor-download"
MAX_DOWNLOAD = 150 * 1024 * 1024
MAX_UNPACKED = 500 * 1024 * 1024
_HEX = re.compile(r"^[0-9a-f]{64}$")


class Fail(Exception):
    pass


def this_system():
    m = platform.machine().lower()
    arch = "aarch64" if m in ("arm64", "aarch64") else "x86_64" if m in ("x86_64", "amd64") else None
    system = {"win32": "windows", "darwin": "macos"}.get(sys.platform, "linux" if sys.platform.startswith("linux") else None)
    key = f"{system}-{arch}" if system and arch else None
    if key not in FOLDERS:
        raise Fail(f"No Tor folder is defined for this system ({sys.platform}, {platform.machine()}).")
    return key


def exe_name(key):
    return "tor.exe" if key.startswith("windows") else "tor"


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def read_lock():
    try:
        lock = json.loads(LOCK.read_text("utf-8"))
    except (OSError, ValueError):
        raise Fail(f"{LOCK.name} is missing or unreadable. Create it once with:  python packaging/get_tor.py --update")
    plats = lock.get("platforms") if isinstance(lock, dict) else None
    if not isinstance(plats, dict) or not plats:
        raise Fail(f"{LOCK.name} has no platforms. Recreate it with:  python packaging/get_tor.py --update")
    return lock


# --------------------------------------------------------------------------
# Download and unpack, safely
# --------------------------------------------------------------------------
def download(urls, dest, want_sha, size_hint=0, quiet=False):
    last = "no address to try"
    for url in urls:
        if not url.startswith("https://") and not os.environ.get("SHIELD_GET_TOR_ALLOW_HTTP"):
            last = f"{url} is not https"
            continue
        host = url.split("/")[2]
        try:
            h, done = hashlib.sha256(), 0
            req = urllib.request.Request(url, headers={"User-Agent": "Shield-get-tor"})
            with urllib.request.urlopen(req, timeout=60) as r, open(dest, "wb") as f:
                while True:
                    chunk = r.read(65536)
                    if not chunk:
                        break
                    done += len(chunk)
                    if done > MAX_DOWNLOAD:
                        raise Fail("larger than expected")
                    h.update(chunk)
                    f.write(chunk)
            if want_sha is None or h.hexdigest() == want_sha:
                return h.hexdigest()
            last = f"{host}: the file doesn't match the lock (SHA-256 differs), so it was discarded"
        except (OSError, Fail) as ex:
            last = f"{host}: {ex}"[:160]
        if not quiet:
            print(f"    {last}")
        try:
            os.unlink(dest)
        except OSError:
            pass
    raise Fail(last)


def _inside(root, path):
    try:
        Path(path).resolve().relative_to(root)
        return True
    except (ValueError, OSError):
        return False


def extract(archive, stage, exe):
    """Unpack by hand: nothing can land outside `stage`. Only tor/ and data/ are taken. Permissions come from the archive."""
    root = Path(stage).resolve()
    total = 0
    with tarfile.open(archive, "r:gz") as tf:
        for m in tf:
            raw = m.name.replace("\\", "/")
            parts = tuple(p for p in PurePosixPath(raw).parts if p != ".")
            if not parts:
                continue
            if raw.startswith("/") or ".." in parts or re.match(r"^[A-Za-z]:", parts[0]):
                raise Fail("the archive contains an unsafe path")
            if parts[0] not in ("tor", "data"):
                continue
            dest = root.joinpath(*parts)
            if not _inside(root, dest):
                raise Fail("the archive contains an unsafe path")
            if m.isdir():
                dest.mkdir(parents=True, exist_ok=True)
            elif m.isfile():
                total += m.size
                if total > MAX_UNPACKED:
                    raise Fail("the archive unpacks to more than expected")
                dest.parent.mkdir(parents=True, exist_ok=True)
                with open(dest, "wb") as out:
                    shutil.copyfileobj(tf.extractfile(m), out)
                if os.name != "nt":
                    os.chmod(dest, 0o755 if (m.mode & 0o111 or dest.name == exe) else 0o644)
            elif m.issym() or m.islnk():
                if os.name == "nt":
                    continue
                link = m.linkname.replace("\\", "/")
                tgt = Path(os.path.normpath(dest.parent / link)) if m.issym() else root.joinpath(*PurePosixPath(link).parts)
                if link.startswith("/") or not _inside(root, tgt):
                    raise Fail("the archive contains an unsafe link")
                dest.parent.mkdir(parents=True, exist_ok=True)
                if dest.exists() or dest.is_symlink():
                    dest.unlink()
                if m.issym():
                    os.symlink(link, dest)
                else:
                    shutil.copy2(tgt, dest)
            else:
                raise Fail("the archive contains something that isn't a file")


def transports_in(folder):
    """Which bridge programs this folder really has (listed in pt_config.json AND present on disk)."""
    pt = Path(folder) / "tor" / "pluggable_transports"
    try:
        cfg = json.loads((pt / "pt_config.json").read_text("utf-8"))
    except (OSError, ValueError):
        return []
    found = set()
    for raw in (cfg.get("pluggableTransports") or {}).values() if isinstance(cfg, dict) else []:
        m = re.match(r"\s*ClientTransportPlugin\s+([a-z0-9_,]+)\s+exec\s+(\S+)", raw if isinstance(raw, str) else "")
        if not m:
            continue
        prog = m.group(2).replace("${pt_path}", str(pt) + os.sep)
        p = Path(prog)
        if (p.is_file() or Path(str(p) + ".exe").is_file()) or (pt / Path(prog).name).is_file() or (pt / (Path(prog).name + ".exe")).is_file():
            found |= set(m.group(1).split(","))
    return sorted(found & {"obfs4", "snowflake"})


# --------------------------------------------------------------------------
# One system's folder
# --------------------------------------------------------------------------
def folder_current(key, entry):
    dest = TOR_DIR / FOLDERS[key]
    try:
        info = json.loads((dest / "VERSION.json").read_text("utf-8"))
        exe = dest / "tor" / exe_name(key)
        return info.get("sha256") == entry["sha256"] and exe.is_file() and sha256_file(exe) == entry["exe_sha256"]
    except (OSError, ValueError):
        return False


def fetch(key, lock):
    entry = lock["platforms"].get(key)
    if not entry:
        if key in OPTIONAL:
            raise Fail(f"There is no Tor for {key}: {OPTIONAL[key]}. This system can't be built with a private connection yet.")
        raise Fail(f"The lock has nothing for {key}. Run  python packaging/get_tor.py --update")
    folder = FOLDERS[key]
    dest = TOR_DIR / folder
    if folder_current(key, entry):
        print(f"{folder}: Tor {lock['version']} is already in place")
        return
    print(f"{folder}: getting Tor {lock['version']} ({entry['file']})")
    CACHE.mkdir(parents=True, exist_ok=True)
    archive = CACHE / entry["file"]
    if not (archive.is_file() and sha256_file(archive) == entry["sha256"]):
        download(entry["urls"], archive, entry["sha256"])
    stage = TOR_DIR / f".stage-{folder}"
    shutil.rmtree(stage, ignore_errors=True)
    stage.mkdir(parents=True)
    try:
        extract(archive, stage, exe_name(key))
        exe = stage / "tor" / exe_name(key)
        if not exe.is_file():
            raise Fail("the download has no tor program in it")
        if sha256_file(exe) != entry["exe_sha256"]:
            raise Fail("the tor program inside the download isn't the one the lock expects")
        have = transports_in(stage)
        if sorted(entry.get("transports", [])) != have:
            raise Fail(f"bridge programs differ from the lock: expected {entry.get('transports')}, found {have}")
        (stage / "VERSION.json").write_text(json.dumps({"version": lock["version"], "platform": key, "sha256": entry["sha256"],
                                                        "exe_sha256": entry["exe_sha256"], "transports": have}, indent=2), "utf-8")
        shutil.rmtree(dest, ignore_errors=True)
        os.replace(stage, dest)
    finally:
        shutil.rmtree(stage, ignore_errors=True)
    print(f"    ok: {dest}  (bridges: {', '.join(have) or 'none'})")


# --------------------------------------------------------------------------
# --update: choose the newest release and write the lock
# --------------------------------------------------------------------------
def http_get(url):
    req = urllib.request.Request(url, headers={"User-Agent": "Shield-get-tor"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read()


def newest_version():
    html = http_get(BASE + "/").decode("utf-8", "replace")
    found = {tuple(int(x) for x in v.split(".")): v for v in re.findall(r'href="(\d+\.\d+(?:\.\d+)?)/"', html)}
    for k in sorted(found, reverse=True):
        try:
            http_get(f"{BASE}/{found[k]}/sha256sums-signed-build.txt")
            return found[k]
        except OSError:
            continue
    raise Fail("Couldn't find a Tor Browser release with a signed checksum list at " + BASE)


def find_gpg():
    """A real GnuPG. Gpg4win's is looked for first: the gpg that comes inside Git for Windows is a cut-down copy that can't keep keys."""
    for p in (r"C:\Program Files (x86)\GnuPG\bin\gpg.exe", r"C:\Program Files\GnuPG\bin\gpg.exe",
              "/opt/homebrew/bin/gpg", "/usr/local/bin/gpg", "/usr/bin/gpg"):
        if os.path.isfile(p):
            return p
    for name in ("gpg", "gpg2"):
        found = shutil.which(name)
        if found and "\\git\\" not in found.lower():
            return found
    return None


def gpg_check(sums, asc):
    gpg = find_gpg()
    if not gpg:
        raise Fail("GnuPG (gpg) wasn't found. Install it (Windows:  winget install GnuPG.Gpg4win ; Mac:  brew install gnupg ; Linux: your package "
                   "manager's 'gnupg'), then run this again. (--no-gpg skips the signature check; weaker: trusts only HTTPS.)")
    # A keyring of our own, so nothing in the person's own GnuPG setup is touched or needed.
    home = CACHE / "gnupg"
    home.mkdir(parents=True, exist_ok=True)

    def run(*args):
        return subprocess.run([gpg, "--homedir", str(home), "--batch", *args], capture_output=True, text=True)
    run("--auto-key-locate", "nodefault,wkd", "--locate-keys", KEY_LOOKUP)
    r = run("--status-fd", "1", "--verify", str(asc), str(sums))
    if "NO_PUBKEY" in r.stdout:                                     # the website lookup didn't deliver the key: ask a key server for it
        run("--keyserver", "hkps://keys.openpgp.org", "--recv-keys", SIGNING_KEY)
        r = run("--status-fd", "1", "--verify", str(asc), str(sums))
    valid = [ln.split() for ln in r.stdout.splitlines() if ln.startswith("[GNUPG:] VALIDSIG")]
    if r.returncode != 0 or not valid:
        raise Fail(f"The signature on the checksum list is NOT valid (checked with {gpg}):\n" + r.stderr)
    primary = valid[0][-1].upper()
    if primary != SIGNING_KEY.upper():
        raise Fail(f"The checksums are signed by key {primary}, not the expected {SIGNING_KEY}. Not trusting them. If the Tor Project "
                   "changed its signing key, confirm the new fingerprint on torproject.org, then update SIGNING_KEY.")
    print(f"  signature OK (key {primary})")


def update(version, mirrors, no_gpg):
    CACHE.mkdir(parents=True, exist_ok=True)
    ver = version or newest_version()
    print(f"Tor Browser release {ver}")
    sums, asc = CACHE / f"sha256sums-{ver}.txt", CACHE / f"sha256sums-{ver}.txt.asc"
    sums.write_bytes(http_get(f"{BASE}/{ver}/sha256sums-signed-build.txt"))
    if no_gpg:
        print("WARNING: --no-gpg. Nothing but HTTPS vouches for these files. Don't ship this unless you verified them another way.")
    else:
        asc.write_bytes(http_get(f"{BASE}/{ver}/sha256sums-signed-build.txt.asc"))
        gpg_check(sums, asc)
    listed = {}
    for line in sums.read_text("utf-8").splitlines():
        m = re.match(r"^([0-9a-f]{64})\s+\*?(\S+)$", line.strip())
        if m:
            listed[m.group(2)] = m.group(1)
    lock = {"version": ver, "generated": time.strftime("%Y-%m-%d"), "signing_key": None if no_gpg else SIGNING_KEY, "platforms": {}}
    for key, folder in FOLDERS.items():
        name = f"tor-expert-bundle-{key}-{ver}.tar.gz"
        print(f"{folder}: {name}")
        if name not in listed and key in OPTIONAL:
            print(f"    skipped: not in Tor Browser {ver}'s signed checksum list ({OPTIONAL[key]})")
            continue
        archive = CACHE / name
        sha = download([f"{BASE}/{ver}/{name}"], archive, listed.get(name))
        if name not in listed and not no_gpg:
            raise Fail(f"{name} is not in the signed checksum list, so it can't be vouched for.")
        with tarfile.open(archive, "r:gz") as tf:
            f = tf.extractfile("tor/" + exe_name(key))
            if f is None:
                raise Fail(f"{name} has no tor/{exe_name(key)}")
            exe_sha = hashlib.sha256(f.read()).hexdigest()
        lock["platforms"][key] = {"file": name, "sha256": sha, "exe_sha256": exe_sha, "size": archive.stat().st_size, "transports": [],
                                  "urls": [f"{BASE}/{ver}/{name}", f"{ARCHIVE}/{ver}/{name}"] + [f"{m.rstrip('/')}/{name}" for m in mirrors]}
        stage = CACHE / f"inspect-{folder}"
        shutil.rmtree(stage, ignore_errors=True)
        stage.mkdir()
        extract(archive, stage, exe_name(key))
        lock["platforms"][key]["transports"] = transports_in(stage)
        shutil.rmtree(stage, ignore_errors=True)
        print(f"    {archive.stat().st_size // 1024} KB, bridges: {', '.join(lock['platforms'][key]['transports']) or 'none'}")
    LOCK.write_text(json.dumps(lock, indent=2) + "\n", "utf-8")
    print(f"\nWrote {LOCK.name}. Commit it. Bundles are in {CACHE} (upload them with --mirror-url if you want your own second copy).")
    return lock


def main(argv=None):
    ap = argparse.ArgumentParser(description="Put the Tor programs for each system into tor/<folder>/.")
    ap.add_argument("--all", action="store_true", help="all five systems, not just this one")
    ap.add_argument("--only", help="one folder name (tor_win, tor_mac_arm64, ...)")
    ap.add_argument("--update", action="store_true", help="re-pin to the newest Tor release (needs GnuPG)")
    ap.add_argument("--version", help="with --update: a specific Tor Browser release")
    ap.add_argument("--mirror-url", action="append", default=[], help="with --update: https folder holding your own copy of the files")
    ap.add_argument("--no-gpg", action="store_true", help="with --update: skip the signature check (weaker)")
    ap.add_argument("--check", action="store_true", help="verify the folders on disk against the lock; no network")
    a = ap.parse_args(argv)
    try:
        if any(not m.startswith("https://") for m in a.mirror_url):
            raise Fail("--mirror-url must be an https address")
        lock = update(a.version, a.mirror_url, a.no_gpg) if a.update else read_lock()
        if a.only:
            keys = [k for k, f in FOLDERS.items() if f == a.only or k == a.only]
            if not keys:
                raise Fail(f"Unknown folder {a.only!r}. Choose from: {', '.join(FOLDERS.values())}")
        else:
            keys = list(FOLDERS) if (a.all or a.update) else [this_system()]
            if a.all or a.update:
                gone = [k for k in keys if k in OPTIONAL and k not in lock["platforms"]]
                keys = [k for k in keys if k not in gone]
                for k in gone:
                    print(f"{FOLDERS[k]}: not in the lock, skipped ({OPTIONAL[k]})")
        if a.check:
            bad = [FOLDERS[k] for k in keys if not folder_current(k, lock["platforms"].get(k, {"sha256": "", "exe_sha256": ""}))]
            print("All folders match the lock." if not bad else "Missing or different: " + ", ".join(bad))
            return 1 if bad else 0
        for k in keys:
            fetch(k, lock)
        return 0
    except Fail as e:
        print(f"\nFAILED: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())