"""
tor_bundle.py: keeps one Tor Expert Bundle per operating system and puts ONLY the right one into each build.

    python packaging/tor_bundle.py list                       what is downloaded, and which one this computer would use
    python packaging/tor_bundle.py fetch --all                download all four into packaging/tor-bundles/
    python packaging/tor_bundle.py fetch macos-arm64          download just one
    python packaging/tor_bundle.py install dist/Shield/tor    copy THIS computer's bundle to that folder (build scripts call this)

Layout on disk (the folders are the extracted Tor Expert Bundle, untouched):

    packaging/tor-bundles/
        tor-bundles.lock.json            commit this: the SHA-256 of every download, so a swapped file is caught later
        windows-x64/   tor/tor.exe  data/geoip  ...
        macos-arm64/   tor/tor      data/geoip  ...
        macos-x64/     tor/tor      data/geoip  ...
        linux-x64/     tor/tor      data/geoip  ...

At build time the matching folder is copied to <app>/tor, so the program ends up at <app>/tor/tor/tor(.exe), which is
exactly where TorRunner.find() in shield_proxy.py looks. PyInstaller cannot cross-compile, so every build runs on its own
operating system and only ever needs its own bundle. If that bundle isn't on disk yet, `install` downloads it first.

To move to a newer Tor: change TOR_BROWSER_VERSION below (current stable: https://download.torproject.org/tor/),
run `fetch --all --refresh`, and commit the changed tor-bundles.lock.json.

Standard library only.
"""
import hashlib
import json
import os
import platform
import re
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

TOR_BROWSER_VERSION = "15.0.24"        # the Tor Browser release the Expert Bundle was built for (tor 0.4.9.13 inside)

HERE = Path(__file__).resolve().parent
STORE = HERE / "tor-bundles"
LOCK = STORE / "tor-bundles.lock.json"

# key (our folder name) -> the "<os>-<cpu>" part of the file name on torproject.org
TARGETS = {
    "windows-x64": "windows-x86_64",
    "macos-arm64": "macos-aarch64",
    "macos-x64": "macos-x86_64",
    "linux-x64": "linux-x86_64",
}
MIRRORS = (
    "https://dist.torproject.org/torbrowser/{v}/",
    "https://archive.torproject.org/tor-package-archive/torbrowser/{v}/",     # older releases move here
)
MAX_DOWNLOAD = 200 * 1024 * 1024


def host_key():
    """Which bundle this computer's build needs. None if there isn't one for this system."""
    cpu = platform.machine().lower()
    arm, x64 = cpu in ("arm64", "aarch64"), cpu in ("x86_64", "amd64")
    if sys.platform == "win32":
        return "windows-x64" if x64 else None
    if sys.platform == "darwin":
        return "macos-arm64" if arm else "macos-x64" if x64 else None
    if sys.platform.startswith("linux"):
        return "linux-x64" if x64 else None
    return None


def exe_name(key):
    return "tor.exe" if key.startswith("windows") else "tor"


def tor_exe(root, key):
    return Path(root) / "tor" / exe_name(key)


# ------------------------------------------------------------------------------------------------------------
# problems with a bundle folder (empty list = good)
# ------------------------------------------------------------------------------------------------------------
def check_layout(root, key):
    root = Path(root)
    bad = []
    if not tor_exe(root, key).is_file():
        bad.append(f"{tor_exe(root, key)} is missing")
    pts = [root / "tor" / "pluggable_transports", root / "pluggable_transports"]
    pt = next((p for p in pts if (p / "pt_config.json").is_file()), None)
    if pt is None:
        bad.append("pluggable_transports/pt_config.json is missing (bridges would not work)")
    else:
        try:
            cfg = json.loads((pt / "pt_config.json").read_text("utf-8"))
        except (OSError, ValueError):
            bad.append("pt_config.json is not readable")
            cfg = {}
        lines = [str(v) for v in (cfg.get("pluggableTransports") or {}).values()]
        for word in ("obfs4", "snowflake"):
            line = next((x for x in lines if word in x), None)
            if line is None:
                bad.append(f"pt_config.json has no {word} transport")
                continue
            m = re.search(r"\bexec\s+(\S+)", line)
            prog = (m.group(1) if m else "").replace("${pt_path}", "").strip("/\\")
            if not prog or not any((pt / (prog + ext)).is_file() for ext in ("", ".exe")):
                bad.append(f"the {word} program ({prog or '?'}) is missing from {pt.name}/")
    if not any((d / "geoip").is_file() for d in (root / "data", root / "tor" / "data", root / "tor", root)):
        bad.append("geoip data file is missing")
    return bad


def make_executable(root, key):
    """Git on Windows drops the 'executable' bit, and a zip/tar can too. Put it back on every program in the bundle."""
    if key.startswith("windows"):
        return
    for p in Path(root).rglob("*"):
        if p.is_file() and not p.is_symlink():
            with open(p, "rb") as f:
                head = f.read(4)
            is_prog = head[:2] == b"#!" or head == b"\x7fELF" or head in (
                b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xfe\xed\xfa\xce", b"\xca\xfe\xba\xbe")
            if is_prog:
                p.chmod(p.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


# ------------------------------------------------------------------------------------------------------------
# download
# ------------------------------------------------------------------------------------------------------------
def _get(url, limit=MAX_DOWNLOAD):
    req = urllib.request.Request(url, headers={"User-Agent": "shield-build/1"})
    with urllib.request.urlopen(req, timeout=60) as r:
        data = r.read(limit + 1)
    if len(data) > limit:
        raise RuntimeError(f"{url} is larger than expected")
    return data


def _lock():
    try:
        d = json.loads(LOCK.read_text("utf-8"))
        return d if isinstance(d, dict) else {}
    except (OSError, ValueError):
        return {}


def _save_lock(d):
    STORE.mkdir(parents=True, exist_ok=True)
    LOCK.write_text(json.dumps(d, indent=2, sort_keys=True) + "\n", "utf-8")


def _download(key, version):
    name = f"tor-expert-bundle-{TARGETS[key]}-{version}.tar.gz"
    last = None
    for base in MIRRORS:
        base = base.format(v=version)
        try:
            data = _get(base + name)
        except (urllib.error.URLError, OSError, RuntimeError) as e:
            last = e
            continue
        published = None
        try:                         # Tor lists the SHA-256 of every file of a release next to it
            for line in _get(base + "sha256sums-signed-build.txt", 2_000_000).decode("utf-8", "replace").splitlines():
                parts = line.split()
                if len(parts) == 2 and parts[1].lstrip("*") == name:
                    published = parts[0].lower()
        except (urllib.error.URLError, OSError, RuntimeError):
            pass
        return name, data, published
    raise RuntimeError(f"Could not download {name}: {last}")


def _safe_extract(tar_path, dest):
    """Unpack a tar without letting a hostile archive write outside dest or create links that point outside it."""
    dest = Path(dest).resolve()
    with tarfile.open(tar_path, "r:gz") as t:
        for m in t.getmembers():
            target = (dest / m.name).resolve()
            if dest != target and dest not in target.parents:
                raise RuntimeError(f"unsafe path in archive: {m.name}")
            if m.issym() or m.islnk():
                link = (target.parent / m.linkname).resolve() if m.issym() else (dest / m.linkname).resolve()
                if dest != link and dest not in link.parents:
                    raise RuntimeError(f"unsafe link in archive: {m.name}")
            if not (m.isfile() or m.isdir() or m.issym() or m.islnk()):
                raise RuntimeError(f"unexpected entry in archive: {m.name}")
        try:
            t.extractall(dest, filter="data")         # Python 3.12+ (the build already requires it)
        except TypeError:
            t.extractall(dest)


def _find_root(extracted, key):
    """The folder that holds tor/<exe>. The archive normally has it at the top; be tolerant of one wrapper folder."""
    extracted = Path(extracted)
    for cand in [extracted, *[p for p in extracted.iterdir() if p.is_dir()]]:
        if tor_exe(cand, key).is_file():
            return cand
    return None


def fetch(key, version=TOR_BROWSER_VERSION, refresh=False):
    out = STORE / key
    lock = _lock()
    entry = lock.get(key, {})
    if out.is_dir() and not refresh and entry.get("version") == version and not check_layout(out, key):
        print(f"  {key}: already have Tor Browser {version} bundle")
        return out
    print(f"  {key}: downloading Tor Expert Bundle {version} ...")
    name, data, published = _download(key, version)
    digest = hashlib.sha256(data).hexdigest()
    if published and published != digest:
        raise RuntimeError(f"{name}: SHA-256 {digest} does not match the one Tor publishes ({published}). Not using it.")
    if entry.get("version") == version and entry.get("sha256") and entry["sha256"] != digest:
        raise RuntimeError(f"{name}: SHA-256 {digest} differs from the one pinned in {LOCK.name} ({entry['sha256']}). "
                           f"The download changed since you pinned it. Not using it.")
    with tempfile.TemporaryDirectory() as tmp:
        tar_path = Path(tmp) / name
        tar_path.write_bytes(data)
        ex = Path(tmp) / "x"
        ex.mkdir()
        _safe_extract(tar_path, ex)
        root = _find_root(ex, key)
        if root is None:
            raise RuntimeError(f"{name} doesn't contain tor/{exe_name(key)}. Tor may have changed the layout of the bundle.")
        problems = check_layout(root, key)
        if problems:
            raise RuntimeError(f"{name} looks wrong: " + "; ".join(problems))
        if out.exists():
            shutil.rmtree(out)
        STORE.mkdir(parents=True, exist_ok=True)
        shutil.copytree(root, out, symlinks=True)
    make_executable(out, key)
    lock[key] = {"version": version, "file": name, "sha256": digest, "verified_against_tor_sums": bool(published)}
    _save_lock(lock)
    print(f"  {key}: ok ({'matches the SHA-256 Tor publishes' if published else 'Tor sums file not reachable: pinned in the lock file instead'})")
    return out


# ------------------------------------------------------------------------------------------------------------
# install into a build
# ------------------------------------------------------------------------------------------------------------
def install(dest, key=None):
    key = key or host_key()
    if key is None:
        raise RuntimeError(f"No Tor bundle exists for this system ({sys.platform}, {platform.machine()}).")
    src = STORE / key
    if not src.is_dir() or check_layout(src, key):
        fetch(key)
    problems = check_layout(src, key)
    if problems:
        raise RuntimeError(f"{src} is not a usable Tor bundle: " + "; ".join(problems))
    dest = Path(dest).resolve()          # absolute: the version check below runs with a different working folder
    if dest.exists():
        shutil.rmtree(dest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(src, dest, symlinks=True)           # ONLY this operating system's folder goes into the build
    make_executable(dest, key)
    exe = tor_exe(dest, key)
    mb = sum(f.stat().st_size for f in dest.rglob("*") if f.is_file()) / 1048576
    print(f"  {key}: {mb:.0f} MB copied to {dest}")
    # The bundle must actually run on this computer (catches the wrong CPU, a bad download, a missing library).
    try:
        env = dict(os.environ)
        if key.startswith("linux"):          # same as Shield does when it starts Tor: its libraries are beside it
            env["LD_LIBRARY_PATH"] = str(exe.parent) + (os.pathsep + env["LD_LIBRARY_PATH"] if env.get("LD_LIBRARY_PATH") else "")
        r = subprocess.run([str(exe), "--version"], capture_output=True, text=True, timeout=30, cwd=str(exe.parent), env=env)
    except (OSError, subprocess.SubprocessError) as e:
        raise RuntimeError(f"The bundled {exe.name} would not start: {e}")
    if r.returncode != 0:
        files = ", ".join(sorted(x.name for x in exe.parent.iterdir())[:40])
        raise RuntimeError(f"The bundled {exe.name} --version failed (exit {r.returncode}): {(r.stderr or r.stdout).strip()[:300]}\n"
                           f"  files next to it: {files}")
    print("  " + (r.stdout or "").splitlines()[0] if r.stdout else "  tor started")
    return dest


def listing():
    here = host_key()
    lock = _lock()
    print(f"Tor Browser version this tool fetches: {TOR_BROWSER_VERSION}")
    print(f"This computer would use: {here or '(none: unsupported system)'}\n")
    for key in TARGETS:
        d = STORE / key
        have = d.is_dir() and not check_layout(d, key)
        v = lock.get(key, {}).get("version", "-")
        print(f"  {'*' if key == here else ' '} {key:12s} {'on disk' if have else 'not downloaded':15s} version {v}")


def main(argv):
    if not argv or argv[0] in ("-h", "--help", "help"):
        print(__doc__)
        return 0
    cmd, rest = argv[0], argv[1:]
    version = TOR_BROWSER_VERSION
    if "--version" in rest:
        i = rest.index("--version")
        version = rest[i + 1]
        del rest[i:i + 2]
    refresh = "--refresh" in rest
    rest = [a for a in rest if a != "--refresh"]
    try:
        if cmd == "list":
            listing()
        elif cmd == "fetch":
            keys = list(TARGETS) if "--all" in rest else [a for a in rest if not a.startswith("-")]
            if not keys:
                print("Say which: --all, or one of " + ", ".join(TARGETS))
                return 2
            for k in keys:
                if k not in TARGETS:
                    print(f"Unknown target {k!r}. Choose from: " + ", ".join(TARGETS))
                    return 2
                fetch(k, version, refresh)
        elif cmd == "install":
            if not rest:
                print("Usage: tor_bundle.py install <destination folder>")
                return 2
            install(rest[0])
        else:
            print(__doc__)
            return 2
    except RuntimeError as e:
        print(f"\nTOR BUNDLE: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))