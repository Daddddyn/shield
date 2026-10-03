import base64
import hashlib
import io
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import shield_update as U  # noqa: E402


class Versions(unittest.TestCase):
    def test_compare(self):
        self.assertTrue(U.newer("6.10.0", "6.9.2"))
        self.assertFalse(U.newer("6.9.0", "6.9.0"))
        self.assertFalse(U.newer("6.8.1", "6.9.0"))
        self.assertTrue(U.newer("v2.3", "2.2.9"))
        self.assertEqual(U.vtuple("garbage"), (0,))
        self.assertEqual(U.vtuple("6.8.0rc1"), (6, 8, 0))

    def test_pypi(self):
        raw = json.dumps({"info": {"version": "6.9.0"}}).encode()
        self.assertEqual(U.check_engine("6.8.1", fetch=lambda: raw), {"latest": "6.9.0", "newer": True})
        self.assertFalse(U.check_engine("6.9.0", fetch=lambda: raw)["newer"])
        with self.assertRaises(U.UpdateError):
            U.check_engine("6.8.1", fetch=lambda: b"<html>")


class Signed(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        os.chdir(self.td.name)
        self.pub = U.keygen("k.key")
        self.sha = hashlib.sha256(b"installer-bytes").hexdigest()
        self.manifest = json.dumps({"version": "2.3.0", "url": "https://dl.example/Shield-2.3.0.exe", "sha256": self.sha, "notes": "Fixes."}).encode()
        Path("m.json").write_bytes(self.manifest)
        self.sig = U.sign_file("m.json", "k.key").read_text()

    def tearDown(self):
        os.chdir("/")
        self.td.cleanup()

    def fetch(self, manifest=None, sig=None):
        files = {"https://dl.example/m.json": manifest or self.manifest, "https://dl.example/m.json.sig": (sig or self.sig).encode()}
        return lambda url, lim: files[url]

    def test_valid(self):
        m = U.check_app("2.2.0", url="https://dl.example/m.json", pubkey=self.pub, fetch=self.fetch())
        self.assertTrue(m["newer"])
        self.assertEqual(m["version"], "2.3.0")
        self.assertFalse(U.check_app("2.3.0", url="https://dl.example/m.json", pubkey=self.pub, fetch=self.fetch())["newer"])

    def test_tampered_manifest_rejected(self):
        evil = self.manifest.replace(b"2.3.0", b"9.9.9")
        with self.assertRaises(U.UpdateError):
            U.check_app("2.2.0", url="https://dl.example/m.json", pubkey=self.pub, fetch=self.fetch(manifest=evil))

    def test_wrong_key_rejected(self):
        other = U.keygen("other.key")
        with self.assertRaises(U.UpdateError):
            U.check_app("2.2.0", url="https://dl.example/m.json", pubkey=other, fetch=self.fetch())

    def test_garbage_signature_rejected(self):
        with self.assertRaises(U.UpdateError):
            U.check_app("2.2.0", url="https://dl.example/m.json", pubkey=self.pub, fetch=self.fetch(sig="not-base64!!"))

    def test_malformed_manifest_rejected(self):
        bad = json.dumps({"version": "2.3.0", "url": "http://plain/x.exe", "sha256": self.sha}).encode()
        Path("b.json").write_bytes(bad)
        sig = U.sign_file("b.json", "k.key").read_text()
        with self.assertRaises(U.UpdateError):
            U.verify_manifest(bad, sig, self.pub)

    def test_not_configured(self):
        with self.assertRaises(U.UpdateError):
            U.check_app("1.0", url="", pubkey="")
        self.assertFalse(U.configured())

    def test_http_refused(self):
        with self.assertRaises(U.UpdateError):
            U._get("http://example.org/m.json", 100, "1")

    def test_download_checks_hash(self):
        man = U.check_app("2.2.0", url="https://dl.example/m.json", pubkey=self.pub, fetch=self.fetch())

        class R(io.BytesIO):
            def __enter__(self):
                return self

            def __exit__(self, *a):
                return False
        p = U.download(man, "out", fetch_stream=lambda u: R(b"installer-bytes"))
        self.assertEqual(p.read_bytes(), b"installer-bytes")
        with self.assertRaises(U.UpdateError):
            U.download(man, "out2", fetch_stream=lambda u: R(b"tampered"))
        self.assertEqual(list(Path("out2").glob("*")), [])           # nothing left behind

    def test_schedule(self):
        self.assertTrue(U.due("state.json"))
        U.mark("state.json")
        self.assertFalse(U.due("state.json"))


if __name__ == "__main__":
    unittest.main()
