"""Tests for shield_vault.py: python -m unittest discover tests"""
import json
import os
import sys
import tempfile
import time
import unittest
from pathlib import Path

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import shield_vault as V  # noqa: E402

V.KDF = {"n": 2 ** 15, "r": 8, "p": 1}      # fast settings for tests (the same code path, less memory)
MASTER = "correct horse battery staple"


class Basics(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.path = Path(self.td.name) / "vault.shv"
        self.v = V.Vault(self.path)

    def tearDown(self):
        self.td.cleanup()

    def make(self):
        self.v.create(MASTER)
        return self.v

    def test_create_unlock_roundtrip(self):
        v = self.make()
        eid = v.add("https://Example.com/login?x=1", "ann", "s3cret-Pw!x")
        self.assertTrue(v.exists())
        v.lock()
        self.assertFalse(v.unlocked)
        with self.assertRaises(V.VaultError):
            v.entries and None
            v.get(eid)
        self.assertFalse(v.unlock("wrong password here"))
        self.assertTrue(v.unlock(MASTER))
        e = v.get(eid)
        self.assertEqual((e["origin"], e["username"], e["password"]), ("https://example.com", "ann", "s3cret-Pw!x"))

    def test_file_reveals_nothing(self):
        v = self.make()
        v.add("https://secret-bank.example", "ann@mail.test", "hunter2hunter2")
        v.never_add("hidden-site.example")
        raw = self.path.read_text()
        for needle in ("secret-bank", "ann@mail", "hunter2", "hidden-site", "example"):
            self.assertNotIn(needle, raw)

    def test_tamper_detected(self):
        v = self.make()
        v.add("https://a.example", "u", "pw-pw-pw-pw")
        v.lock()
        d = json.loads(self.path.read_text())
        d["kdf"]["n"] = 2 ** 16                              # attacker edits the header
        self.path.write_text(json.dumps(d))
        v2 = V.Vault(self.path)
        self.assertFalse(v2.unlock(MASTER))
        d["kdf"]["n"] = 2 ** 15
        ct = bytearray(__import__("base64").b64decode(d["data"]["ct"]))
        ct[5] ^= 1
        d["data"]["ct"] = __import__("base64").b64encode(bytes(ct)).decode()
        self.path.write_text(json.dumps(d))
        self.assertFalse(V.Vault(self.path).unlock(MASTER))

    def test_unsafe_kdf_refused(self):
        v = self.make()
        v.lock()
        d = json.loads(self.path.read_text())
        d["kdf"]["n"] = 2 ** 30
        self.path.write_text(json.dumps(d))
        with self.assertRaises(V.VaultError):
            V.Vault(self.path).unlock(MASTER)

    def test_master_rules_and_change(self):
        with self.assertRaises(V.VaultError):
            self.v.create("short")
        v = self.make()
        v.add("https://a.example", "u", "pw-pw-pw-pw")
        self.assertFalse(v.change_master("not the master", "another long password"))
        self.assertTrue(v.change_master(MASTER, "another long password"))
        v.lock()
        self.assertFalse(v.unlock(MASTER))
        self.assertTrue(v.unlock("another long password"))
        self.assertEqual(len(v.entries), 1)

    def test_verify_master(self):
        v = self.make()
        self.assertTrue(v.verify_master(MASTER))
        self.assertFalse(v.verify_master("not it"))
        v.lock()
        with self.assertRaises(V.VaultError):
            v.verify_master(MASTER)

    def test_backoff_after_failures(self):
        v = self.make()
        v.lock()
        for _ in range(5):
            v.unlock("nope nope nope")
        self.assertGreater(v.wait_seconds(), 0)
        self.assertFalse(v.unlock(MASTER))                   # refused while waiting, even with the right password

    def test_origin_matching(self):
        v = self.make()
        v.add("https://login.example.com", "u", "pw-pw-pw-pw")
        v.add("http://insecure.example", "u", "pw-pw-pw-pw")
        v.add("http://localhost:3000/app", "dev", "pw-pw-pw-pw")
        self.assertEqual(len(v.for_origin("https://login.example.com")), 1)
        self.assertEqual(v.for_origin("https://example.com"), [])             # no subdomain guessing
        self.assertEqual(v.for_origin("https://login.example.com:8443"), [])
        self.assertEqual(v.for_origin("http://insecure.example"), [])          # never fill over plain HTTP
        self.assertEqual(len(v.for_origin("http://localhost:3000")), 1)
        self.assertEqual(v.for_origin("javascript:alert(1)"), [])

    def test_known_and_update(self):
        v = self.make()
        eid = v.add("https://a.example", "ann", "first-password-1")
        self.assertEqual(v.known("https://a.example", "ann", "first-password-1")[0], "same")
        self.assertEqual(v.known("https://a.example", "ann", "other")[0], "changed")
        self.assertEqual(v.known("https://a.example", "bob", "x")[0], "new")
        v.add("https://a.example", "ann", "second-password-2")                  # same account: updated, not duplicated
        self.assertEqual(len(v.entries), 1)
        v.update(eid, username="annie")
        self.assertEqual(v.get(eid)["username"], "annie")
        v.delete(eid)
        self.assertEqual(v.entries, [])

    def test_never_list_persists(self):
        v = self.make()
        v.never_add("Bank.example")
        v.lock()
        v.unlock(MASTER)
        self.assertIn("bank.example", v.never)

    def test_validation(self):
        v = self.make()
        with self.assertRaises(V.VaultError):
            v.add("not a url", "u", "p")
        with self.assertRaises(V.VaultError):
            v.add("https://a.example", "u", "")
        v.add("https://a.example", "u" * 5000, "p" * 5000)
        self.assertLessEqual(len(v.entries[0]["password"]), V.MAX_FIELD)

    def test_backup_kept(self):
        v = self.make()
        v.add("https://a.example", "u", "pw-pw-pw-pw")
        self.assertTrue(self.path.with_suffix(".shv.bak").exists())

    def test_autolock(self):
        v = self.make()
        v.idle_minutes = 1
        self.assertFalse(v.tick())
        v._last = time.time() - 120
        self.assertTrue(v.tick())
        self.assertFalse(v.unlocked)

    def test_rev_changes(self):
        v = self.make()
        r = v.rev
        v.add("https://a.example", "u", "pw-pw-pw-pw")
        self.assertGreater(v.rev, r)
        r = v.rev
        v.lock()
        self.assertGreater(v.rev, r)

    def test_wipe(self):
        v = self.make()
        v.wipe()
        self.assertFalse(v.exists())
        self.assertFalse(v.unlocked)


class CSV(unittest.TestCase):
    def setUp(self):
        self.td = tempfile.TemporaryDirectory()
        self.v = V.Vault(Path(self.td.name) / "v.shv")
        self.v.create(MASTER)

    def tearDown(self):
        self.td.cleanup()

    def test_import_chrome_style(self):
        text = "name,url,username,password,note\nGitHub,https://github.com/login,ann,pw1pw1pw1,\nbad,,x,y,\nBank,bank.example,bob,pw2pw2pw2,\n"
        added, skipped = self.v.import_csv(text)
        self.assertEqual((added, skipped), (2, 1))
        self.assertEqual(len(self.v.for_origin("https://bank.example")), 1)
        self.assertEqual(self.v.import_csv(text), (0, 3))      # nothing duplicated the second time

    def test_import_other_headers(self):
        text = "Login URI,Login Username,Login Password\nhttps://a.example/x,ann,pw\n"
        self.assertEqual(self.v.import_csv(text)[0], 1)

    def test_import_rejects_unknown_format(self):
        with self.assertRaises(V.VaultError):
            self.v.import_csv("foo,bar\n1,2\n")

    def test_export_roundtrip(self):
        self.v.add("https://a.example", "ann,with,commas", 'p"w pw,1')
        out = self.v.export_csv()
        td2 = tempfile.TemporaryDirectory()
        v2 = V.Vault(Path(td2.name) / "v.shv")
        v2.create(MASTER)
        self.assertEqual(v2.import_csv(out), (1, 0))
        e = v2.entries[0]
        self.assertEqual((e["username"], e["password"]), ("ann,with,commas", 'p"w pw,1'))
        td2.cleanup()


class Passwords(unittest.TestCase):
    def test_generate(self):
        for n in (8, 20, 64):
            p = V.generate(n)
            self.assertEqual(len(p), n)
            self.assertTrue(any(c.islower() for c in p) and any(c.isupper() for c in p))
            self.assertTrue(any(c.isdigit() for c in p) and any(c in V.SYMBOLS for c in p))
            self.assertFalse(set(p) & V.AMBIGUOUS)
        self.assertEqual(len({V.generate(20) for _ in range(50)}), 50)
        self.assertTrue(V.generate(16, symbols=False).isalnum())
        self.assertEqual(len(V.generate(1)), 8)

    def test_strength_ordering(self):
        weak = V.strength("password")[0]
        self.assertEqual(weak, 0)
        self.assertLessEqual(V.strength("Summer2024")[0], 1)
        self.assertLessEqual(V.strength("abcdabcdabcd")[0], 1)
        self.assertGreaterEqual(V.strength("correct horse battery staple")[0], 3)
        self.assertEqual(V.strength(V.generate(20))[0], 4)
        self.assertEqual(V.strength("")[0], 0)

    def test_audit(self):
        td = tempfile.TemporaryDirectory()
        v = V.Vault(Path(td.name) / "v.shv")
        v.create(MASTER)
        v.add("https://a.example", "u", "password1")
        v.add("https://b.example", "u", "password1")
        v.add("https://c.example", "u", V.generate(20))
        a = v.audit()
        self.assertEqual(len(a["weak"]), 2)
        self.assertEqual(len(a["reused"]), 1)
        self.assertEqual(a["total"], 3)
        td.cleanup()


if __name__ == "__main__":
    unittest.main()
