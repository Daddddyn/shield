"""
Turns built installers into an update that existing copies of Shield will accept, on Windows, macOS and Linux.

  First time only:
      python packaging/release.py keygen
          Makes your update-signing key (in your user folder) and prints the public key.
          Paste that into UPDATE_PUBKEY in shield_update.py, set UPDATE_URL, then build.
      python packaging/release.py seal
          Optional, so you can release from ANY computer that has the project: locks the key with a passphrase into
          packaging/shield-update.key.sealed, which is safe to commit. Where the plain key file is missing, publishing asks
          for the passphrase and uses the key from memory (it is never written to disk there).

  Every release:
      1. raise VERSION in shield_core.py
      2. build each system's package:  packaging\\build.ps1 (Windows), packaging/build.sh on a Mac and on Linux
         (or run the "Build installers" GitHub workflow and download its three artifacts)
      3. put every package for this version in the release/ folder (subfolders are fine)
      4. python packaging/release.py --notes "What changed, in a sentence." --min-chromium 150
         (--days 45 is the default expiry; add --critical for an urgent security release)
      5. upload what it prints (release/upload/) to your download address

It picks up whichever packages exist for this VERSION:
      Shield-Setup-<v>.exe                 windows-x64   (required: see below)
      Shield-<v>-macos-arm64.dmg           macos-arm64
      Shield-<v>-macos-x64.dmg             macos-x64
      Shield-<v>-linux-x64.tar.gz          linux-x64
      Shield-<v>-linux-arm64.tar.gz        linux-arm64
A system with no package simply isn't offered the update; nobody is told about something they can't install.

The Windows installer is required because Shield 2.2.x on Windows reads the manifest's top-level url/sha256 fields, which
always describe it. Shield only installs an update whose manifest is signed by the key built into it, and only if the
installer's SHA-256 matches the signed manifest. A hacked web server can host the files but cannot forge an update.
"""
import argparse
import base64
import getpass
import hashlib
import json
import os
import re
import shutil
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

import shield_update  # noqa: E402  (no Qt in it)

KEY = Path(os.environ.get("SHIELD_UPDATE_KEY") or Path.home() / ".shield-release" / "shield-update.key")

# (platform key, file name for a version). The platform keys are what shield_update.platform_key() reports.
PACKAGES = [
    ("windows-x64", "Shield-Setup-{v}.exe"),
    ("macos-arm64", "Shield-{v}-macos-arm64.dmg"),
    ("macos-x64", "Shield-{v}-macos-x64.dmg"),
    ("linux-x64", "Shield-{v}-linux-x64.tar.gz"),
    ("linux-arm64", "Shield-{v}-linux-arm64.tar.gz"),
]


def current_version():
    m = re.search(r'^VERSION\s*=\s*"([^"]+)"', (ROOT / "shield_core.py").read_text("utf-8"), re.M)
    if not m:
        sys.exit("Couldn't read VERSION from shield_core.py")
    return m.group(1)


# --------------------------------------------------------------------------
# Sealed key: the signing key locked with a passphrase, so it can live in the project and be used on any computer.
# scrypt turns the passphrase into an AES-256-GCM key; the settings are authenticated too, so editing them fails.
# --------------------------------------------------------------------------
SEALED = Path(__file__).resolve().parent / "shield-update.key.sealed"
SEAL_KDF = {"n": 2 ** 17, "r": 8, "p": 1}          # about 128 MB and a second or so per guess
MIN_PASSPHRASE = 16


class SealError(Exception):
    pass


def _seal_aad(h):
    return json.dumps({k: h[k] for k in ("v", "n", "r", "p", "salt")}, sort_keys=True, separators=(",", ":")).encode()


def _seal_key_bytes(passphrase, h):
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    return Scrypt(salt=base64.b64decode(h["salt"]), length=32, n=h["n"], r=h["r"], p=h["p"]).derive(passphrase.encode("utf-8"))


def seal_key(raw, passphrase, kdf=None):
    """The signing key (32 raw bytes) locked with the passphrase, as JSON text."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    if len(passphrase) < MIN_PASSPHRASE:
        raise SealError(f"Use a passphrase of at least {MIN_PASSPHRASE} characters. Four or five random words is ideal.")
    k = kdf or SEAL_KDF
    h = {"v": 1, "n": k["n"], "r": k["r"], "p": k["p"], "salt": base64.b64encode(os.urandom(16)).decode()}
    nonce = os.urandom(12)
    ct = AESGCM(_seal_key_bytes(passphrase, h)).encrypt(nonce, raw, _seal_aad(h))
    return json.dumps({**h, "nonce": base64.b64encode(nonce).decode(), "ct": base64.b64encode(ct).decode()}, indent=2)


def open_sealed(text, passphrase):
    """The 32 raw key bytes, or SealError when the passphrase is wrong or the file was changed."""
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    try:
        h = json.loads(text)
        if h["v"] != 1 or not all(isinstance(h[k], int) for k in ("n", "r", "p")):
            raise ValueError
        if not (2 ** 14 <= h["n"] <= 2 ** 20 and h["n"] & (h["n"] - 1) == 0 and 1 <= h["r"] <= 16 and 1 <= h["p"] <= 4):
            raise ValueError
        nonce, ct = base64.b64decode(h["nonce"]), base64.b64decode(h["ct"])
        key = _seal_key_bytes(passphrase, h)
    except (ValueError, KeyError, TypeError):
        raise SealError("The sealed key file is damaged or not a sealed key.") from None
    try:
        raw = AESGCM(key).decrypt(nonce, ct, _seal_aad(h))
    except InvalidTag:
        raise SealError("Wrong passphrase (or the file was changed).") from None
    if len(raw) != 32:
        raise SealError("The sealed key file is damaged.")
    return raw


def load_private(ask=getpass.getpass):
    """The signing key: the plain key file when this computer has one, otherwise the sealed copy in the project."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    if KEY.exists():
        return Ed25519PrivateKey.from_private_bytes(base64.b64decode(KEY.read_text("ascii").strip()))
    if SEALED.exists():
        text = SEALED.read_text("utf-8")
        for attempt in range(3):
            try:
                return Ed25519PrivateKey.from_private_bytes(open_sealed(text, ask("Passphrase for the sealed update key: ")))
            except SealError as e:
                if "damaged" in str(e) or attempt == 2:
                    raise
                print(f"  {e} Try again.")
    raise SealError(f"No signing key. Expected {KEY}\nor the sealed copy {SEALED}.\n"
                    "First time: python packaging/release.py keygen    (then: python packaging/release.py seal)")


def public_of(priv):
    from cryptography.hazmat.primitives import serialization
    return base64.b64encode(priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()


def write_signature(manifest_path, priv):
    """Same file shield_update.sign_file writes (base64 Ed25519 signature of the manifest bytes), key kept in memory."""
    out = Path(str(manifest_path) + ".sig")
    out.write_text(base64.b64encode(priv.sign(Path(manifest_path).read_bytes())).decode(), encoding="ascii")
    return out


def cmd_seal(a):
    from cryptography.hazmat.primitives import serialization
    if SEALED.exists() and not a.force:
        sys.exit(f"{SEALED.name} already exists. Not overwriting it (add --force if you really mean to).")
    if not KEY.exists():
        sys.exit(f"No plain key at {KEY} to seal. Run this on the computer that has your key.")
    priv = load_private()
    if public_of(priv) != shield_update.UPDATE_PUBKEY:
        sys.exit("That key doesn't match UPDATE_PUBKEY in shield_update.py, so it is not the key Shield trusts. Not sealing it.")
    print("Choose a passphrase for the sealed copy. It is the only protection if someone gets the file, so make it long:")
    print("four or five random words is much stronger than a short password. There is no way to recover it.\n")
    p1 = getpass.getpass("New passphrase: ")
    if getpass.getpass("Again: ") != p1:
        sys.exit("The two passphrases differ. Nothing was written.")
    raw = priv.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    try:
        text = seal_key(raw, p1)
    except SealError as e:
        sys.exit(str(e))
    assert open_sealed(text, p1) == raw            # prove it opens before writing anything
    SEALED.write_text(text, encoding="utf-8")
    print(f"\nWrote {SEALED}")
    print("Commit it with the project. On another computer, `release.py` (step 3) will ask for this passphrase and sign from there.")
    print("Keep the plain key backed up as well: the passphrase protects the sealed copy, it does not replace your backup.")


def cmd_keygen():
    if KEY.exists():
        sys.exit(f"A key already exists at {KEY}.\nNot overwriting it: copies of Shield already out there trust THAT key.")
    KEY.parent.mkdir(parents=True, exist_ok=True)
    pub = shield_update.keygen(str(KEY))
    print(f"Private key written to: {KEY}")
    print("  Back it up somewhere safe and private (password manager, encrypted drive). Never commit it or upload it.")
    print("  If it is lost, no installed copy of Shield can ever be updated again.\n")
    print("Public key (paste into UPDATE_PUBKEY in shield_update.py):\n")
    print(pub)
    print("\nTo release from other computers too, after pasting the public key run:  python packaging/release.py seal")


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def find_packages(folder, version):
    """{platform key: Path} for every package of this version under folder (including subfolders)."""
    found = {}
    for key, pattern in PACKAGES:
        name = pattern.format(v=version)
        hits = [p for p in folder.rglob(name) if p.is_file() and "upload" not in p.relative_to(folder).parts[:1]]
        if len(hits) > 1 and len({sha256(p) for p in hits}) > 1:
            sys.exit(f"{name} exists in {len(hits)} places with different contents:\n  " + "\n  ".join(map(str, hits)))
        if hits:
            found[key] = hits[0]
    return found


def cmd_publish(a):
    version = current_version()
    if not shield_update.UPDATE_URL or not shield_update.UPDATE_PUBKEY:
        sys.exit("Fill in UPDATE_URL and UPDATE_PUBKEY in shield_update.py first (see packaging/README.md),\n"
                 "then rebuild: a build without them can never find updates.")
    if not shield_update.UPDATE_URL.lower().startswith("https://"):
        sys.exit("UPDATE_URL must be an https:// address")
    try:
        priv = load_private()
    except SealError as e:
        sys.exit(str(e))

    # The key must be the one this build trusts, or every installed copy would reject the update.
    pub = public_of(priv)
    if pub != shield_update.UPDATE_PUBKEY:
        sys.exit("The signing key doesn't match UPDATE_PUBKEY in shield_update.py.\n"
                 "Copies built with that public key would reject this update.")

    release = ROOT / "release"
    found = find_packages(release, version)
    if "windows-x64" not in found:
        sys.exit(f"{PACKAGES[0][1].format(v=version)} not found under {release}.\n"
                 "The Windows installer is required (Shield 2.2.x on Windows reads it from the manifest's top-level fields).\n"
                 "Run packaging\\build.ps1 first, and check VERSION in shield_core.py.")

    out = release / "upload"
    out.mkdir(parents=True, exist_ok=True)
    for old in out.iterdir():           # never leave an earlier release's files in the folder you are about to upload
        old.unlink()
    base = a.base_url or shield_update.UPDATE_URL.rsplit("/", 1)[0]
    platforms = {}
    for key, src in found.items():
        dest = out / src.name
        shutil.copy2(src, dest)
        platforms[key] = {"url": f"{base}/{src.name}", "sha256": sha256(dest)}
    win = platforms["windows-x64"]
    manifest = {"version": version, "url": win["url"], "sha256": win["sha256"], "notes": (a.notes or "")[:400],
                "platforms": platforms}
    # Signed along with everything else. "expires" stops anyone replaying an old, validly signed manifest to keep people
    # from learning about a newer release; "min_chromium" makes copies with an older web engine show a warning;
    # "critical" asks for the update at every start.
    if a.days > 0:
        manifest["expires"] = int(time.time()) + a.days * 86400
    if a.min_chromium:
        manifest["min_chromium"] = a.min_chromium
    if a.critical:
        manifest["critical"] = True
    mpath = out / "manifest.json"
    mpath.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    sig = write_signature(mpath, priv)

    # Prove the result is acceptable to the code that will read it, for every system in it.
    check = shield_update.verify_manifest(mpath.read_bytes(), sig.read_text("ascii"), shield_update.UPDATE_PUBKEY)
    assert set(check["platforms"]) == set(platforms), "a platform entry was rejected by the verifier"

    print(f"Release {version} is ready in {out}:\n")
    for key, _ in PACKAGES:
        if key in found:
            print(f"  {key:12} {found[key].name}  ({found[key].stat().st_size // 1048576} MB)")
        else:
            print(f"  {key:12} -- no package, so people on this system will not be offered {version}")
    print(f"  manifest     {mpath.name} + {sig.name}")
    if "expires" in manifest:
        print(f"\nThis manifest expires in {a.days} days. Run release.py again (same version is fine) before then, or Shield\n"
              "will ignore it and say the update information is stale.")
    else:
        print("\nWarning: no expiry set (--days 0). Set one so an old signed manifest can't be replayed.")
    print(f"\nShield looks for the manifest at:\n  {shield_update.UPDATE_URL}")
    print("\nUpload the installers FIRST and the manifest and signature last, so nobody is told about an update that isn't there yet.")
    print("With the GitHub CLI, for a release whose tag is the last part of the manifest address (here: shield):")
    print("  gh release upload shield release/upload/Shield-* --clobber")
    print("  gh release upload shield release/upload/manifest.json release/upload/manifest.json.sig --clobber")


def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("action", nargs="?", default="publish", choices=["publish", "keygen", "seal"])
    ap.add_argument("--notes", help="one sentence shown to people in Settings > Updates")
    ap.add_argument("--base-url", help="folder the installers will be hosted in (default: same folder as UPDATE_URL)")
    ap.add_argument("--days", type=int, default=45, help="how long this manifest stays valid (default 45; 0 = never expires, not advised)")
    ap.add_argument("--min-chromium", type=int, default=0,
                    help="oldest web-engine security-patch major still considered safe (see the steps: use the number the build prints, minus 1)")
    ap.add_argument("--critical", action="store_true", help="a serious security release: Shield asks for it at every start")
    ap.add_argument("--force", action="store_true", help="with seal: replace an existing sealed key file")
    a = ap.parse_args()
    if a.action == "keygen":
        cmd_keygen()
    elif a.action == "seal":
        cmd_seal(a)
    else:
        cmd_publish(a)


if __name__ == "__main__":
    main()
