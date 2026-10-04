"""
shield_update.py: update checks. No Qt in here, so it can be tested on its own.

Two separate checks, both off the moment "Check for updates" is switched off in Settings:

  1. Engine age. Shield's web engine is Chromium inside PyQt6-WebEngine, so the most important update is that
     package. One plain request to PyPI says whether a newer version exists. Nothing about you is sent.
  2. Shield itself. Reads a small manifest from a web address you control. The manifest is signed with an
     Ed25519 key; Shield only trusts a manifest whose signature verifies against the public key built into it.
     A hacked web server can therefore not push a fake update. Until UPDATE_URL and UPDATE_PUBKEY are filled in
     (below) this check is simply not shown.

"Install and restart" in Settings downloads the update for this system, checks its SHA-256 against the signed manifest
and replaces the running copy of Shield, then reopens it. How depends on the system:

  Windows  runs the Inno Setup installer silently (it upgrades the per-user install in place).
  macOS    opens the .dmg, copies Shield.app next to the installed one, and a tiny helper script swaps them once Shield quits.
  Linux    unpacks the .tar.gz next to the installed folder and the same helper swaps them.

macOS and Linux can only update in place when the user can write to where Shield is installed (/Applications for an
admin, ~/Applications, or ~/.local/share/Shield from install.sh). Otherwise the verified download is left in a folder.
Settings, history, the vault and downloaded scanner rules live in the user's data folder and are never touched.

Making the keys and signing a release (run on your own machine, keep shield-update.key secret AND backed up:
every installed copy trusts only this key, so if it is lost no further update can ever be delivered to them):

    python shield_update.py keygen                 # writes shield-update.key, prints the public key
    python shield_update.py sign manifest.json     # writes manifest.json.sig next to it

packaging/release.py does the manifest and signing for you after a build.

manifest.json looks like (the top-level url and sha256 are the Windows installer, which is what Shield 2.2.x reads;
newer builds pick their own entry from "platforms"):
    {"version": "2.3.0", "url": "https://downloads.example.org/Shield-Setup-2.3.0.exe",
     "sha256": "<64 hex characters>", "notes": "What changed, in a sentence.",
     "platforms": {"windows-x64": {"url": "...", "sha256": "..."},
                   "macos-arm64": {"url": "...", "sha256": "..."},
                   "macos-x64":   {"url": "...", "sha256": "..."},
                   "linux-x64":   {"url": "...", "sha256": "..."}}}
Host manifest.json and manifest.json.sig side by side; UPDATE_URL points at manifest.json.

Three optional fields in the signed manifest make the channel harder to attack and tell old copies of Shield when
their web engine has fallen behind:

    "expires": 1798761600            a Unix time (or "2027-01-01T00:00:00Z"). After it, the manifest is ignored.
                                     This stops someone replaying an old, validly signed manifest to hide a newer
                                     release ("freeze" attack). Put it 30 to 60 days ahead on every release and
                                     re-sign the same release before it runs out.
    "min_chromium": 140              the oldest Chromium security-patch level still considered safe. Copies whose
                                     engine is older show a warning (see Security center) until they update.
    "critical": true                 this release fixes something serious: Shield says so and asks for the update
                                     at every start instead of once a day.

Backup signing key: put the public key of a second, offline-only keypair in UPDATE_BACKUP_PUBKEYS. A manifest signed by
either key is trusted. If the main key is ever lost or leaked, release one build with the backup key promoted to
UPDATE_PUBKEY and a fresh backup, signed with the backup key, and nobody is stranded.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import platform
import plistlib
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

UPDATE_URL = "https://github.com/Daddddyn/shield/releases/download/shield/manifest.json"          # e.g. "https://downloads.example.org/shield/manifest.json"
UPDATE_PUBKEY = "tt5sBOeH5AmHJsedB02yh40HHiWr6/A96XQyS9cGdvU="       # base64 of the 32-byte public key printed by `keygen`
UPDATE_BACKUP_PUBKEYS = ("lO5r4u0NuZwCjPcKLR0gp8MpJcUXItTW5PryQDEozwE=",)      # base64 public keys of offline backup signing keys (see the notes at the top)
PYPI_URL = "https://pypi.org/pypi/PyQt6-WebEngine/json"
MAX_MANIFEST = 64 * 1024
MAX_INSTALLER = 600 * 1024 * 1024


class UpdateError(Exception):
    pass


class _HttpsOnly(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not newurl.lower().startswith("https://"):
            raise urllib.error.URLError("redirect to a non-HTTPS address refused")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _get(url, limit, version, timeout=20):
    if not url.lower().startswith("https://"):
        raise UpdateError("Updates are only fetched over HTTPS")
    req = urllib.request.Request(url, headers={"User-Agent": f"Shield-Browser/{version}", "Accept": "*/*"})
    try:
        with urllib.request.build_opener(_HttpsOnly).open(req, timeout=timeout) as r:
            data = r.read(limit + 1)
    except (urllib.error.URLError, OSError, ValueError):
        raise UpdateError("Couldn't reach the update server") from None
    if len(data) > limit:
        raise UpdateError("The download was unexpectedly large")
    return data


def vtuple(v):
    """'2.10.1' -> (2, 10, 1). Anything after the first non-numeric piece is ignored."""
    out = []
    for part in re.split(r"[.\-+]", str(v).strip().lstrip("vV")):
        m = re.match(r"\d+", part)
        if not m:
            break
        out.append(int(m.group()))
    return tuple(out) or (0,)


def newer(candidate, current):
    return vtuple(candidate) > vtuple(current)


# -- engine (PyQt6-WebEngine) ------------------------------------------------
def parse_pypi(raw):
    try:
        return str(json.loads(raw)["info"]["version"])
    except (ValueError, KeyError, TypeError):
        raise UpdateError("The package index gave an unexpected answer") from None


def check_engine(installed, version="0", fetch=None):
    """{'latest': '6.9.0', 'newer': True|False}. installed is the PyQt6-WebEngine version string in use."""
    raw = (fetch or (lambda: _get(PYPI_URL, 2 * 1024 * 1024, version)))()
    latest = parse_pypi(raw)
    return {"latest": latest, "newer": newer(latest, installed)}


# -- Shield itself ---------------------------------------------------------------
def _keys(pubkeys):
    """Accept one base64 key or several; ignore empty entries."""
    if isinstance(pubkeys, (str, bytes)):
        pubkeys = [pubkeys]
    return [k for k in (pubkeys or ()) if k]


def _parse_expiry(value):
    """Unix seconds from a number or an ISO-8601 'Z' time. 0 means 'no expiry'. Raises ValueError if unreadable."""
    if value in (None, "", 0):
        return 0.0
    if isinstance(value, bool):
        raise ValueError
    if isinstance(value, (int, float)):
        return float(value)
    import calendar
    return float(calendar.timegm(time.strptime(str(value).strip(), "%Y-%m-%dT%H:%M:%SZ")))


def verify_manifest(raw, sig_b64, pubkey_b64, now=None):
    """The parsed manifest if the signature is valid (under any trusted key) and it has not expired, else raises UpdateError."""
    sig = None
    try:
        sig = base64.b64decode(sig_b64.strip())
    except (ValueError, TypeError):
        pass
    ok = False
    for key in _keys(pubkey_b64):
        try:
            Ed25519PublicKey.from_public_bytes(base64.b64decode(key)).verify(sig or b"", raw)
            ok = True
            break
        except (InvalidSignature, ValueError, TypeError):
            continue
    if not ok:
        raise UpdateError("The update information isn't signed by the right key, so it was ignored")
    try:
        m = json.loads(raw.decode("utf-8"))
        ver, url, sha = str(m["version"]), str(m["url"]), str(m["sha256"]).lower()
        expires = _parse_expiry(m.get("expires"))
        min_chromium = int(m.get("min_chromium") or 0)
    except (ValueError, KeyError, TypeError, AttributeError):
        raise UpdateError("The update information is malformed") from None
    if expires and (now if now is not None else time.time()) > expires:
        raise UpdateError("The update information has expired, so it was ignored. Check Shield's website for the newest version")
    if not re.fullmatch(r"[0-9a-f]{64}", sha) or not url.lower().startswith("https://") or not vtuple(ver)[0]:
        raise UpdateError("The update information is malformed")
    plats = {}
    raw_p = m.get("platforms")
    for key, v in (raw_p.items() if isinstance(raw_p, dict) else []):
        try:
            pu, ps = str(v["url"]), str(v["sha256"]).lower()
        except (KeyError, TypeError):
            continue
        if re.fullmatch(r"[a-z0-9_]+-[a-z0-9_]+", str(key)) and re.fullmatch(r"[0-9a-f]{64}", ps) and pu.lower().startswith("https://"):
            plats[str(key)] = {"url": pu, "sha256": ps}
    return {"version": ver, "url": url, "sha256": sha, "notes": str(m.get("notes", ""))[:400], "platforms": plats,
            "expires": expires, "min_chromium": max(0, min(min_chromium, 10000)), "critical": m.get("critical") is True}


def trusted_keys():
    return _keys([UPDATE_PUBKEY, *UPDATE_BACKUP_PUBKEYS])


def configured():
    return bool(UPDATE_URL and UPDATE_PUBKEY)


def check_app(current, version="0", url=None, pubkey=None, fetch=None, plat=None):
    """{'version', 'url', 'sha256', 'notes', 'newer', 'platform', 'no_build'} for the signed manifest, with url and
    sha256 pointing at the installer for THIS system. Raises UpdateError."""
    url, pubkey = url or UPDATE_URL, pubkey or trusted_keys()
    if not (url and _keys(pubkey)):
        raise UpdateError("Updates aren't set up for this build")
    get = fetch or (lambda u, lim: _get(u, lim, version))
    raw = get(url, MAX_MANIFEST)
    sig = get(url + ".sig", 4096).decode("ascii", "ignore")
    m = verify_manifest(raw, sig, pubkey)
    key = plat or platform_key()
    entry = m["platforms"].get(key)
    if entry:
        m["url"], m["sha256"] = entry["url"], entry["sha256"]
    # Manifests from before multi-platform releases only describe the Windows installer.
    has_build = bool(entry) or key.startswith("windows")
    m["platform"] = key
    m["newer"] = has_build and newer(m["version"], current)
    m["no_build"] = (not has_build) and newer(m["version"], current)
    return m


def download(manifest, dest_dir, version="0", progress=None, fetch_stream=None):
    """Download the installer, check its SHA-256 against the signed manifest, and return its path."""
    dest_dir = Path(dest_dir)
    dest_dir.mkdir(parents=True, exist_ok=True)
    name = re.sub(r"[^\w.\-]", "_", manifest["url"].rsplit("/", 1)[-1])[:100] or "shield-update.bin"
    final, part = dest_dir / name, dest_dir / (name + ".part")
    h = hashlib.sha256()
    try:
        opener = fetch_stream or (lambda u: urllib.request.build_opener(_HttpsOnly).open(
            urllib.request.Request(u, headers={"User-Agent": f"Shield-Browser/{version}"}), timeout=30))
        with opener(manifest["url"]) as r, open(part, "wb") as f:
            got = 0
            while True:
                chunk = r.read(1 << 20)
                if not chunk:
                    break
                got += len(chunk)
                if got > MAX_INSTALLER:
                    raise UpdateError("The download was unexpectedly large")
                h.update(chunk)
                f.write(chunk)
                if progress:
                    progress(got)
    except (urllib.error.URLError, OSError):
        part.unlink(missing_ok=True)
        raise UpdateError("The download was interrupted") from None
    except UpdateError:
        part.unlink(missing_ok=True)
        raise
    if h.hexdigest() != manifest["sha256"]:
        part.unlink(missing_ok=True)
        raise UpdateError("The downloaded file doesn't match the signed checksum, so it was deleted")
    os.replace(part, final)
    return final


# -- this machine ----------------------------------------------------------------
APP_BUNDLE = "Shield.app"          # the folder inside the macOS disk image


def platform_key():
    """'windows-x64', 'macos-arm64', 'macos-x64', 'linux-x64', 'linux-arm64': the keys release.py writes into the manifest."""
    arch = {"amd64": "x64", "x86_64": "x64", "x64": "x64", "arm64": "arm64", "aarch64": "arm64"}.get(platform.machine().lower())
    name = {"win32": "windows", "darwin": "macos"}.get(sys.platform, "linux" if sys.platform.startswith("linux") else sys.platform)
    return f"{name}-{arch or platform.machine().lower() or 'unknown'}"


def install_target():
    """What an in-place update replaces: the program folder (Windows, Linux) or the .app (macOS).
    None when running from source, or from somewhere that can't be updated in place."""
    if not getattr(sys, "frozen", False):
        return None
    exe = Path(sys.executable).resolve()
    if sys.platform == "darwin":
        app = exe.parents[2] if len(exe.parents) > 2 else None
        if app is None or app.suffix != ".app" or exe.parent.name != "MacOS":
            return None
        if "AppTranslocation" in app.parts or app.parts[:2] == ("/", "Volumes"):
            return None            # running straight from the disk image or the Downloads folder
        return app
    return exe.parent


def can_install():
    """True when 'Install and restart' can work here: a packaged build in a place the current user can replace."""
    t = install_target()
    if t is None:
        return False
    if os.name == "nt":
        return True
    return os.access(t, os.W_OK) and os.access(t.parent, os.W_OK)


def _clean_env():
    """The environment for helper programs. A packaged Linux/macOS Shield points library paths at its own folder, and that
    folder is about to be replaced, so helpers must not inherit those."""
    env = dict(os.environ)
    for var in ("LD_LIBRARY_PATH", "DYLD_LIBRARY_PATH", "DYLD_FRAMEWORK_PATH"):
        orig = env.pop(var + "_ORIG", None)
        if orig is None:
            env.pop(var, None)
        else:
            env[var] = orig
    mei = getattr(sys, "_MEIPASS", "")
    if mei:
        for k, v in list(env.items()):
            if mei in v and k.startswith(("QT_", "QML", "QTWEBENGINE", "LD_", "DYLD_")):
                del env[k]
    return env


def _verify_file(path, expected_sha256):
    """Hash the file again, so what runs is exactly what the signed manifest described."""
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
    except OSError:
        raise UpdateError("The update file couldn't be read") from None
    if h.hexdigest() != str(expected_sha256).lower():
        Path(path).unlink(missing_ok=True)
        raise UpdateError("The update file changed after it was checked, so it was deleted")


def run_installer(path, expected_sha256):
    """Start the update for this system and return at once; the caller then closes Shield so the files can be replaced.
    Windows runs the installer. macOS and Linux stage the new copy beside the old one and start a helper that swaps them
    after Shield quits. The file is hashed again first, so what runs is exactly what the signed manifest described."""
    path = Path(path)
    if os.name == "nt":
        suffix = ".exe"
    elif sys.platform == "darwin":
        suffix = ".dmg"
    elif sys.platform.startswith("linux"):
        suffix = ".tar.gz"
    else:
        raise UpdateError("Automatic install isn't available on this system")
    if not path.name.lower().endswith(suffix) or not path.is_file():
        raise UpdateError("The update file is missing")
    _verify_file(path, expected_sha256)
    if os.name == "nt":
        return _run_windows(path)
    target = install_target()
    if target is None or not can_install():
        raise UpdateError("Shield can't replace itself where it is installed. The update was downloaded and checked")
    (_install_macos if sys.platform == "darwin" else _install_linux)(path, target)


def _run_windows(path):
    flags = 0x00000008 | 0x00000200 | 0x08000000      # DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP | CREATE_NO_WINDOW
    try:
        subprocess.Popen([str(path), "/SILENT", "/SUPPRESSMSGBOXES", "/NORESTART", "/CLOSEAPPLICATIONS", "/RELAUNCH=1"],
                         creationflags=flags, close_fds=True, cwd=str(path.parent))
    except OSError:
        raise UpdateError("Windows wouldn't start the installer") from None


# Written next to the download and started detached. Waits for Shield to quit (up to a minute), swaps the staged copy in,
# starts Shield again. If the swap fails the old copy is put back and started, so a failed update never leaves no Shield.
_SWAP_SH = r"""#!/bin/sh
pid="$1"; cur="$2"; new="$3"; launch="$4"
n=0
while kill -0 "$pid" 2>/dev/null; do
  n=$((n + 1))
  if [ "$n" -gt 300 ]; then rm -rf "$new"; exit 1; fi
  sleep 0.2
done
old="$cur.old"
rm -rf "$old"
if mv "$cur" "$old"; then
  if mv "$new" "$cur"; then rm -rf "$old"; else mv "$old" "$cur"; rm -rf "$new"; fi
else
  rm -rf "$new"
fi
if [ "$(uname)" = "Darwin" ]; then open "$cur"; else "$launch" >/dev/null 2>&1 & fi
exit 0
"""


def _start_swap(work, cur, staged, launch, pid=None):
    script = Path(work) / "shield-swap.sh"
    try:
        script.write_text(_SWAP_SH, encoding="utf-8")
        os.chmod(script, 0o700)
        subprocess.Popen(["/bin/sh", str(script), str(pid or os.getpid()), str(cur), str(staged), str(launch)],
                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         env=_clean_env(), close_fds=True, start_new_session=True)
    except OSError:
        shutil.rmtree(staged, ignore_errors=True)
        raise UpdateError("The system wouldn't start the update helper") from None


def _install_linux(archive, target, pid=None):
    """Unpack the .tar.gz (which holds a Shield/ folder) beside the installed folder, then hand over to the swap helper."""
    target = Path(target)
    staged = target.with_name(target.name + ".new")
    tmp = Path(tempfile.mkdtemp(prefix=".shield-new-", dir=target.parent))
    try:
        with tarfile.open(archive, "r:*") as t:
            t.extractall(tmp, filter="data")
        found = [d / "Shield" for d in tmp.iterdir() if (d / "Shield" / "Shield").is_file()]
        if not found:
            raise UpdateError("The update doesn't contain Shield")
        shutil.rmtree(staged, ignore_errors=True)
        os.replace(found[0], staged)
    except (tarfile.TarError, OSError):
        raise UpdateError("The update couldn't be unpacked") from None
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    if not os.access(staged / "Shield", os.X_OK):
        shutil.rmtree(staged, ignore_errors=True)
        raise UpdateError("The update isn't runnable")
    _start_swap(Path(archive).parent, target, staged, target / "Shield", pid)


def _bundle_id(app):
    try:
        return plistlib.loads((Path(app) / "Contents" / "Info.plist").read_bytes()).get("CFBundleIdentifier")
    except (OSError, ValueError, plistlib.InvalidFileException):
        return None


def _install_macos(dmg, target, pid=None):
    """Mount the .dmg, copy Shield.app beside the installed one (ditto keeps signatures and symlinks intact), unmount,
    then hand over to the swap helper."""
    target = Path(target)
    staged = target.with_name(target.name + ".new")
    work = Path(dmg).parent
    mnt = Path(tempfile.mkdtemp(prefix="mnt-", dir=work))
    env = _clean_env()
    try:
        r = subprocess.run(["hdiutil", "attach", "-nobrowse", "-readonly", "-noautoopen", "-mountpoint", str(mnt), str(dmg)],
                           capture_output=True, timeout=180, env=env)
        if r.returncode:
            raise UpdateError("macOS couldn't open the update disk image")
        src = mnt / APP_BUNDLE
        if not (src / "Contents" / "MacOS").is_dir():
            raise UpdateError("The update doesn't contain Shield.app")
        shutil.rmtree(staged, ignore_errors=True)
        r = subprocess.run(["ditto", str(src), str(staged)], capture_output=True, timeout=900, env=env)
        if r.returncode:
            shutil.rmtree(staged, ignore_errors=True)
            raise UpdateError("The update couldn't be copied")
    except (subprocess.SubprocessError, OSError):
        shutil.rmtree(staged, ignore_errors=True)
        raise UpdateError("The update couldn't be unpacked") from None
    finally:
        try:
            subprocess.run(["hdiutil", "detach", str(mnt), "-force"], capture_output=True, timeout=60, env=env)
        except (subprocess.SubprocessError, OSError):
            pass
        try:
            mnt.rmdir()
        except OSError:
            pass
    mine, theirs = _bundle_id(target), _bundle_id(staged)
    if not mine or mine != theirs:
        shutil.rmtree(staged, ignore_errors=True)
        raise UpdateError("The update is for a different app, so it was not installed")
    try:    # a copy made by Shield itself isn't quarantined, but be sure Gatekeeper doesn't treat it as a fresh download
        subprocess.run(["xattr", "-dr", "com.apple.quarantine", str(staged)], capture_output=True, timeout=120, env=env)
    except (subprocess.SubprocessError, OSError):
        pass
    _start_swap(work, target, staged, target, pid)


def cleanup(dest_dir, max_age_hours=24):
    """Remove installers and half-finished downloads left in the updates folder by earlier updates."""
    try:
        for p in Path(dest_dir).iterdir():
            if p.is_file() and p.suffix.lower() in (".exe", ".part", ".dmg", ".gz", ".sh") and time.time() - p.stat().st_mtime > max_age_hours * 3600:
                p.unlink(missing_ok=True)
    except OSError:
        pass


# -- daily schedule ----------------------------------------------------------------
def due(state_path, hours=24):
    try:
        ts = json.loads(Path(state_path).read_text("utf-8")).get("ts", 0)
    except (OSError, ValueError, AttributeError):
        ts = 0
    return time.time() - ts > hours * 3600


def mark(state_path, **extra):
    try:
        Path(state_path).write_text(json.dumps({"ts": time.time(), **extra}), encoding="utf-8")
    except OSError:
        pass


# -- release tooling ---------------------------------------------------------------
def keygen(path="shield-update.key"):
    priv = Ed25519PrivateKey.generate()
    raw = priv.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    Path(path).write_text(base64.b64encode(raw).decode(), encoding="ascii")
    if os.name != "nt":
        os.chmod(path, 0o600)
    pub = priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(pub).decode()


def sign_file(manifest_path, key_path="shield-update.key"):
    priv = Ed25519PrivateKey.from_private_bytes(base64.b64decode(Path(key_path).read_text("ascii").strip()))
    data = Path(manifest_path).read_bytes()
    sig = base64.b64encode(priv.sign(data)).decode()
    out = Path(str(manifest_path) + ".sig")
    out.write_text(sig, encoding="ascii")
    return out


if __name__ == "__main__":
    if len(sys.argv) >= 2 and sys.argv[1] == "keygen":
        print("Public key (put this in UPDATE_PUBKEY):\n" + keygen())
    elif len(sys.argv) >= 3 and sys.argv[1] == "sign":
        print("Wrote", sign_file(sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else "shield-update.key"))
    else:
        print(__doc__)
