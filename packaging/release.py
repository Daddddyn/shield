"""
Turns built installers into an update that existing copies of Shield will accept, on Windows, macOS and Linux.

  First time only:
      python packaging/release.py keygen
          Makes your update-signing key (kept OUTSIDE the project, in your user folder) and prints the public key.
          Paste that into UPDATE_PUBKEY in shield_update.py, set UPDATE_URL, then build.

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
    if not KEY.exists():
        sys.exit(f"No signing key at {KEY}. Run:  python packaging/release.py keygen")

    # The key on disk must be the one this build trusts, or every installed copy would reject the update.
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    priv = Ed25519PrivateKey.from_private_bytes(base64.b64decode(KEY.read_text("ascii").strip()))
    pub = base64.b64encode(priv.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)).decode()
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
    sig = shield_update.sign_file(mpath, KEY)

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
    ap.add_argument("action", nargs="?", default="publish", choices=["publish", "keygen"])
    ap.add_argument("--notes", help="one sentence shown to people in Settings > Updates")
    ap.add_argument("--base-url", help="folder the installers will be hosted in (default: same folder as UPDATE_URL)")
    ap.add_argument("--days", type=int, default=45, help="how long this manifest stays valid (default 45; 0 = never expires, not advised)")
    ap.add_argument("--min-chromium", type=int, default=0,
                    help="oldest web-engine security-patch major still considered safe (see the steps: use the number the build prints, minus 1)")
    ap.add_argument("--critical", action="store_true", help="a serious security release: Shield asks for it at every start")
    a = ap.parse_args()
    cmd_keygen() if a.action == "keygen" else cmd_publish(a)


if __name__ == "__main__":
    main()
