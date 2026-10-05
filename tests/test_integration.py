"""Exercises the request interceptor, navigation guard and every internal page, with PyQt6 faked (see qt_stub.py)."""
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import MagicMock
from urllib.parse import urlsplit

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
sys.path.insert(0, HERE)
os.environ["SHIELD_HOME"] = tempfile.mkdtemp(prefix="shield-test-")
os.environ["SHIELD_DOWNLOADS"] = tempfile.mkdtemp(prefix="shield-dl-")
import qt_stub  # noqa: E402,F401

import shield_core as C  # noqa: E402
import shield_filters as F  # noqa: E402
import shield_pages as P  # noqa: E402

NODE = shutil.which("node")


class FakeUrl:
    def __init__(self, url):
        self.u = urlsplit(url)
        self.raw = url
        self._scheme = self.u.scheme

    def scheme(self):
        return self._scheme

    def host(self):
        return (self.u.hostname or "")

    def port(self):
        return self.u.port or -1

    def setScheme(self, s):
        self._scheme = s

    def setPort(self, p):
        pass

    def toEncoded(self):
        return self.raw.encode()

    def toString(self):
        return self.raw


class FakeInfo:
    def __init__(self, url, first, rtype="ResourceTypeScript"):
        self.url, self.first, self.rtype = FakeUrl(url), FakeUrl(first), rtype
        self.blocked, self.redirected, self.headers = False, None, {}

    def requestUrl(self):
        return self.url

    def firstPartyUrl(self):
        return self.first

    def resourceType(self):
        return self.rtype

    def block(self, b):
        self.blocked = b

    def redirect(self, u):
        self.redirected = u

    def setHttpHeader(self, k, v):
        self.headers[k] = v


LIST = "||ads.example^\n||tracker.test^$third-party\n/pixel/*.gif\n||evil-scam.test^$all\n@@||good.test^$document\n"


def make_core():
    try:
        os.remove(C.HOME / "settings.json")          # every test starts from the defaults
    except OSError:
        pass
    cfg = C.Settings()
    ev = C.Events()
    prot = C.Protection()
    eng = F.FilterEngine()
    eng.add_text(LIST, "Ads")
    eng.add_text("||evil-scam.test^$all\n", "Scam and malware sites", harmful=True)
    prot.set(eng.finalize(), None)
    th = F.ThreatDB()
    th.add("https://phish.test/login\n", "urls", "phishing", "Live phishing pages")
    th.add("0.0.0.0 malware-host.test\n", "domains", "malware", "Live malware downloads")
    prot.set(eng, th)
    g = C.Guard(cfg, ev, prot)
    return cfg, ev, prot, g, C.Shield(cfg, ev, g)


class Interceptor(unittest.TestCase):
    def setUp(self):
        self.cfg, self.ev, self.prot, self.g, self.sh = make_core()

    def req(self, url, first="https://news.example/page", rtype="ResourceTypeScript"):
        i = FakeInfo(url, first, rtype)
        self.sh.interceptRequest(i)
        return i

    def test_filter_rules_block(self):
        self.assertTrue(self.req("https://ads.example/a.js").blocked)
        self.assertTrue(self.req("https://tracker.test/t.js").blocked)
        self.assertFalse(self.req("https://tracker.test/t.js", first="https://tracker.test/").blocked)   # first party
        self.assertTrue(self.req("https://cdn.x/pixel/a.gif", rtype="ResourceTypeImage").blocked)
        self.assertFalse(self.req("https://cdn.x/lib/app.js").blocked)
        self.assertEqual(self.ev.counts["tracker"], 3)

    def test_main_frame_is_never_blocked_by_list(self):
        self.assertFalse(self.req("https://ads.example/", first="https://ads.example/", rtype="ResourceTypeMainFrame").blocked)

    def test_builtin_trackers_still_work_without_lists(self):
        self.prot.set(None, None)
        self.assertTrue(self.req("https://www.google-analytics.com/a.js").blocked)
        self.assertFalse(self.req("https://cdn.x/lib/app.js").blocked)

    def test_site_can_turn_blocking_off(self):
        self.cfg.add_rule("news.example", "noblock")
        self.assertFalse(self.req("https://ads.example/a.js").blocked)
        self.assertFalse(self.req("https://www.google-analytics.com/a.js").blocked)

    def test_websites_may_show_ads_while_trackers_stay_blocked(self):
        self.prot.set(None, None)                                    # built-in domains only
        self.assertTrue(self.req("https://securepubads.doubleclick.net/a.js").blocked)
        self.assertTrue(self.req("https://www.google-analytics.com/a.js").blocked)
        self.cfg["block_site_ads"] = False
        self.assertFalse(self.req("https://securepubads.doubleclick.net/a.js").blocked)
        self.assertFalse(self.req("https://cdn.taboola.com/a.js").blocked)
        self.assertTrue(self.req("https://www.google-analytics.com/a.js").blocked)
        self.assertTrue(self.req("https://api.mixpanel.com/track").blocked)
        self.cfg["block_trackers"] = False                           # the master switch still wins
        self.assertFalse(self.req("https://www.google-analytics.com/a.js").blocked)

    def test_ad_networks_are_a_subset_of_the_builtin_list(self):
        self.assertTrue(C.AD_NETWORKS <= C.TRACKERS)
        self.assertFalse({"google-analytics.com", "hotjar.com", "mixpanel.com"} & C.AD_NETWORKS)

    def test_setting_off(self):
        self.cfg["block_trackers"] = False
        self.assertFalse(self.req("https://ads.example/a.js").blocked)

    def test_threat_hosts_blocked_as_subresources(self):
        self.assertTrue(self.req("https://malware-host.test/x.js").blocked)
        self.assertTrue(self.req("https://phish.test/login", rtype="ResourceTypeSubFrame").blocked)
        self.assertEqual(self.ev.counts["harmful"], 2)
        self.cfg["block_harmful"] = False
        self.assertFalse(self.req("https://malware-host.test/x.js").blocked)

    def test_https_upgrade_and_gpc(self):
        i = self.req("http://plain.example/a.js")
        self.assertIsNotNone(i.redirected)
        self.assertEqual(i.redirected.scheme(), "https")
        j = self.req("https://fine.example/a.js")
        self.assertEqual(j.headers.get(b"Sec-GPC"), b"1")

    def test_local_network_shield(self):
        self.assertTrue(self.req("http://192.168.0.1/admin", first="https://news.example/").blocked)

    def test_exception_rule(self):
        self.assertFalse(self.req("https://good.test/x.js", first="https://good.test/").blocked)


class GuardTests(unittest.TestCase):
    def setUp(self):
        self.cfg, self.ev, self.prot, self.g, self.sh = make_core()

    def test_phishing_and_malware_feed(self):
        v = self.g.verdict("phish.test", "https://phish.test/login")
        self.assertEqual(v[0], "phishing")
        self.assertIsNone(self.g.verdict("phish.test", "https://phish.test/other"))
        self.assertEqual(self.g.verdict("malware-host.test", "https://malware-host.test/a")[0], "malware")

    def test_scam_list_document_rule(self):
        v = self.g.verdict("evil-scam.test", "https://evil-scam.test/")
        self.assertEqual(v[0], "scam")

    def test_continue_anyway_remembers(self):
        self.g.allowed.add(("phishing", C.site_of("phish.test")))
        self.assertIsNone(self.g.verdict("phish.test", "https://phish.test/login"))

    def test_toggle_and_site_override(self):
        self.cfg["block_harmful"] = False
        self.assertIsNone(self.g.verdict("phish.test", "https://phish.test/login"))
        self.cfg["block_harmful"] = True
        self.cfg.add_rule("phish.test", "noblock")
        self.assertIsNone(self.g.verdict("phish.test", "https://phish.test/login"))

    def test_ad_list_rules_do_not_trigger_warnings(self):
        self.assertIsNone(self.g.verdict("ads.example", "https://ads.example/"))

    def test_old_checks_still_work(self):
        self.assertEqual(self.g.verdict("paypa1.com", "https://paypa1.com/")[0], "lookalike")
        self.cfg["navigation_guard"] = False
        self.assertIsNone(self.g.verdict("paypa1.com", "https://paypa1.com/"))
        self.assertIsNone(self.g.verdict("localhost", "http://localhost/"))


class SettingsTests(unittest.TestCase):
    def test_new_settings(self):
        try:
            os.remove(C.HOME / "settings.json")
        except OSError:
            pass
        c = C.Settings()
        self.assertTrue(c.set("fingerprint_level", "strict"))
        self.assertFalse(c.set("fingerprint_level", "extreme"))
        self.assertTrue(c["block_site_ads"] and c["block_youtube_ads"])        # both on by default
        self.assertTrue(c.set("block_site_ads", "0") and c.set("block_youtube_ads", "off"))
        self.assertTrue(c.set("startup", "restore"))
        self.assertTrue(c.set("vault_autolock", "5") and c["vault_autolock"] == 5)
        self.assertFalse(c.set("vault_autolock", "7"))
        self.assertFalse(c.set("filter_lists", "x"))
        self.assertTrue(c.set_list("ads", False))
        self.assertFalse(c.set_list("nope", True))
        self.assertTrue(c.add_rule("a.example", "noblock"))
        self.assertFalse(c.add_rule("a.example", "bogus"))
        c2 = C.Settings()                                       # persisted
        self.assertEqual((c2["startup"], c2["filter_lists"].get("ads")), ("restore", False))
        self.assertEqual((c2["block_site_ads"], c2["block_youtube_ads"]), (False, False))


def fake_app(cfg):
    app = MagicMock()
    app.resolved_theme.return_value = "dark"
    app.protection_summary.return_value = {"network": 1234, "cosmetic": 56, "threats": 78, "ready": True}
    rows = []
    for it in F.CATALOG:
        rows.append({"id": it["id"], "name": it["name"], "desc": it["desc"], "on": it["default"], "role": it["role"], "have": True,
                     "ts": 1, "size": 123456, "default": it["default"], "line": "x"})
    app.list_status.return_value = {"lists": rows, "summary": "s", "busy": False, "err": ""}
    app.engine_state.return_value = []
    app.has_vt_key.return_value = False
    app.download_list.return_value = []
    return app


def make_ctx():
    cfg, ev, prot, g, _ = make_core()
    store = MagicMock()
    store.bookmarks.return_value = []
    store.history.return_value = []
    store.favicon_uri.return_value = ""
    store.downloads.return_value = []
    ctx = P.Ctx(cfg, ev, store, g)
    ctx.app = fake_app(cfg)
    ctx.engine = {"chromium": "122.0.0.0", "flags": "--site-per-process"}
    return ctx


def scripts_of(html):
    return re.findall(r"<script[^>]*>(.*?)</script>", html, re.S)


@unittest.skipUnless(NODE, "node is not installed")
class PageJavaScript(unittest.TestCase):
    def check_js(self, name, js):
        with tempfile.NamedTemporaryFile("w", suffix=".js", delete=False) as f:
            f.write(js)
            path = f.name
        try:
            r = subprocess.run([NODE, "--check", path], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, f"{name}: {r.stderr[:600]}")
        finally:
            os.unlink(path)

    def test_every_page_renders_with_valid_script(self):
        ctx = make_ctx()
        for name, fn in P.PAGES.items():
            q = {"kind": "phishing", "url": "https://phish.test/login", "d": "List"} if name == "warning" else {}
            html = fn(ctx, q)
            self.assertIn("<!doctype html>", html, name)
            scs = scripts_of(html)
            self.assertTrue(scs, f"{name} has no script")
            for js in scs:
                self.check_js(name, js)

    def test_settings_page_has_the_elements_its_script_uses(self):
        html = P.PAGES["settings"](make_ctx(), {})
        for needle in ('id="lstupd"', 'id="lstsum"', 'id="engline"', 'id="updchk"', 'data-list="ads"', 'data-list="phishing"',
                       'data-k="fingerprint_level"', 'data-k="startup"', 'data-k="vault_autolock"', 'data-k="clean_links"',
                       'data-k="block_harmful"', 'data-k="clear_on_exit"', 'data-k="block_site_ads"', 'data-k="block_youtube_ads"',
                       "Protection lists"):
            self.assertIn(needle, html, needle)
        self.assertNotIn("EasyList", html)                           # only Shield's own brand is shown
        self.assertNotIn("uBlock", html)
        self.assertNotIn("OpenPhish", html)

    def test_security_page_mentions_new_layers(self):
        html = P.PAGES["security"](make_ctx(), {})
        for needle in ("Harmful-site warnings", "Link cleaning", "Ad and tracker blocking", "YouTube ad blocking", 'id="engline"', "Harmful sites stopped"):
            self.assertIn(needle, html, needle)

    def test_warning_page_texts(self):
        ctx = make_ctx()
        for kind, text in (("phishing", "phishing"), ("malware", "malware"), ("scam", "scam")):
            html = P.PAGES["warning"](ctx, {"kind": kind, "url": "https://bad.test/x", "d": "L"})
            self.assertIn(text, html.lower())
            self.assertIn("bad.test", html)

    def test_warning_page_escapes(self):
        html = P.PAGES["warning"](make_ctx(), {"kind": "idn", "url": "https://a.test/", "d": "<script>alert(1)</script>"})
        self.assertNotIn("<script>alert(1)</script>", html)

    def test_passwords_page_nav_and_api_strings(self):
        html = P.PAGES["passwords"](make_ctx(), {})
        self.assertIn('href="shield://passwords"', html)
        for ep in ("vault/status", "vault/list", "vault/reveal", "vault/copy", "vault/save", "vault/import", "vault/export", "vault/wipe"):
            self.assertIn(ep, html)


class ApiRouting(unittest.TestCase):
    def test_routes(self):
        ctx = make_ctx()
        app = ctx.app
        t = ctx.token
        app.vault_api.return_value = {"ok": True, "state": "none"}
        self.assertEqual(P.handle_api(ctx, "vault/status", {"t": t})["state"], "none")
        app.vault_api.assert_called_with("status", {"t": t})
        self.assertEqual(P.handle_api(ctx, "vault/status", {"t": "wrong"}), {"ok": False, "err": "bad token"})
        self.assertTrue(P.handle_api(ctx, "list/set", {"t": t, "id": "ads", "on": "0"})["ok"])
        self.assertFalse(P.handle_api(ctx, "list/set", {"t": t, "id": "zzz", "on": "0"})["ok"])
        app.lists_changed.assert_called_once()
        self.assertTrue(P.handle_api(ctx, "lists", {"t": t})["ok"])
        app.update_state.return_value = {"engine": "x", "app": "", "app_new": False}
        self.assertEqual(P.handle_api(ctx, "update/state", {"t": t})["engine"], "x")
        P.handle_api(ctx, "lists/update", {"t": t})
        app.lists_update.assert_called_with(force=True)


if __name__ == "__main__":
    unittest.main()
