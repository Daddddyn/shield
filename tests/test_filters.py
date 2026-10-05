"""Tests for shield_filters.py (no Qt needed): python -m unittest discover tests"""
import os
import sys
import tempfile
import time
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import shield_filters as F  # noqa: E402

LIST = """\
[Adblock Plus 2.0]
! comment
||ads.example.com^
||tracker.net^$third-party
||cdn.site.com/ads/
/banner/*/img^
-ad-frame.
|https://exact.example/pixel.gif|
||img.example.org^$image
@@||ads.example.com/allowed.js
||important.example^$important
@@||important.example^
||nosubdoc.example^$~subdocument
||onlyscript.example^$script,domain=a.com|~b.a.com
||weird.example^$removeparam=utm
||pop.example^$popup
/regex-rule/
@@||fine.example^$document
||fine.example^
||harmful.example^$all
example.org##.sponsored
##.generic-ad
~skip.com##.maybe-ad
news.com#@#.generic-ad
news.com##div:has-text(ad)
news.com#?#.proc
site.com##+js(abort-on-property-read, foo)
@@||clean.example^$generichide
"""


def engine(text=LIST, name="t", fmt="abp"):
    e = F.FilterEngine()
    e.add_text(text, name, fmt)
    return e.finalize()


def d(e, url, top="page.com", rtype=F.T_SCRIPT):
    from urllib.parse import urlsplit
    host = urlsplit(url).hostname
    return e.decide(url.lower(), host, top, rtype, F.site_of(host) != F.site_of(top))[0]


class Network(unittest.TestCase):
    def setUp(self):
        self.e = engine()

    def test_domain_rule_blocks_subdomains(self):
        self.assertEqual(d(self.e, "https://ads.example.com/x.js"), "block")
        self.assertEqual(d(self.e, "https://sub.ads.example.com/x.js"), "block")
        self.assertIsNone(d(self.e, "https://notads.example.com/x.js"))
        self.assertIsNone(d(self.e, "https://example.com/x.js"))

    def test_third_party_option(self):
        self.assertEqual(d(self.e, "https://tracker.net/t.js", top="page.com"), "block")
        self.assertIsNone(d(self.e, "https://tracker.net/t.js", top="tracker.net"))

    def test_host_with_path(self):
        self.assertEqual(d(self.e, "https://cdn.site.com/ads/a.js"), "block")
        self.assertIsNone(d(self.e, "https://cdn.site.com/lib/a.js"))

    def test_token_rules(self):
        self.assertEqual(d(self.e, "https://x.com/banner/300/img?a=1"), "block")
        self.assertEqual(d(self.e, "https://x.com/a-ad-frame.html"), "block")
        self.assertIsNone(d(self.e, "https://x.com/banners/300/img"))

    def test_exact_anchors(self):
        self.assertEqual(d(self.e, "https://exact.example/pixel.gif", rtype=F.T_IMAGE), "block")
        self.assertIsNone(d(self.e, "https://exact.example/pixel.gif?x"))

    def test_type_options(self):
        self.assertEqual(d(self.e, "https://img.example.org/a.png", rtype=F.T_IMAGE), "block")
        self.assertIsNone(d(self.e, "https://img.example.org/a.js", rtype=F.T_SCRIPT))
        self.assertIsNone(d(self.e, "https://nosubdoc.example/", rtype=F.T_SUBDOC))
        self.assertEqual(d(self.e, "https://nosubdoc.example/", rtype=F.T_SCRIPT), "block")

    def test_exception_beats_block(self):
        self.assertEqual(d(self.e, "https://ads.example.com/other.js"), "block")
        self.assertEqual(d(self.e, "https://ads.example.com/allowed.js"), "allow")

    def test_important_beats_exception(self):
        self.assertEqual(d(self.e, "https://important.example/x.js"), "block")

    def test_domain_option(self):
        self.assertEqual(d(self.e, "https://onlyscript.example/x.js", top="a.com"), "block")
        self.assertIsNone(d(self.e, "https://onlyscript.example/x.js", top="other.com"))
        self.assertIsNone(d(self.e, "https://onlyscript.example/x.js", top="b.a.com"))

    def test_unsupported_rules_are_skipped_not_guessed(self):
        self.assertIsNone(d(self.e, "https://weird.example/x.js"))
        self.assertIsNone(d(self.e, "https://pop.example/x.js"))
        self.assertIsNone(d(self.e, "https://x.com/regex-rule/"))

    def test_site_off(self):
        self.assertIsNone(d(self.e, "https://tracker.net/t.js", top="fine.example"))
        e = engine("||tracker.net^\n@@||fine.example^$document\n")
        self.assertIsNone(d(e, "https://tracker.net/t.js", top="www.fine.example"))
        self.assertEqual(d(e, "https://tracker.net/t.js", top="other.com"), "block")

    def test_document_rules_for_navigation(self):
        self.assertEqual(d(self.e, "https://harmful.example/", top="harmful.example", rtype=F.T_DOC), "block")
        self.assertIsNone(d(self.e, "https://ads.example.com/", top="ads.example.com", rtype=F.T_DOC))

    def test_hosts_format_blocks_third_party_only(self):
        e = engine("# hosts\n127.0.0.1 localhost\n0.0.0.0 evil-ads.example\n127.0.0.1 tracker.test\n", fmt="hosts")
        self.assertEqual(d(e, "https://evil-ads.example/a.js"), "block")
        self.assertEqual(d(e, "https://x.evil-ads.example/a.js"), "block")
        self.assertIsNone(d(e, "https://evil-ads.example/a.js", top="evil-ads.example"))
        self.assertIsNone(d(e, "https://localhost/a.js"))

    def test_badfilter(self):
        e = engine("||dropme.example^\n||dropme.example^$badfilter\n||keep.example^\n")
        self.assertIsNone(d(e, "https://dropme.example/x"))
        self.assertEqual(d(e, "https://keep.example/x"), "block")

    def test_names_reported(self):
        self.assertEqual(self.e.decide("https://ads.example.com/x.js", "ads.example.com", "page.com", F.T_SCRIPT, True)[1], "t")

    def test_stats(self):
        s = self.e.stats()
        self.assertGreater(s["network"], 8)
        self.assertGreater(s["cosmetic"], 2)


class Cosmetic(unittest.TestCase):
    def setUp(self):
        self.e = engine()

    def test_specific_and_generic(self):
        js = self.e.cosmetic_js("www.example.org")
        self.assertIn(".sponsored", js)
        self.assertIn(".generic-ad", js)

    def test_exceptions_and_exclusions(self):
        self.assertNotIn(".generic-ad", self.e.cosmetic_js("news.com"))
        self.assertNotIn(".maybe-ad", self.e.cosmetic_js("skip.com"))
        self.assertIn(".maybe-ad", self.e.cosmetic_js("other.com"))

    def test_unsupported_selectors_dropped(self):
        js = self.e.cosmetic_js("news.com")
        for bad in ("has-text", ".proc", "abort-on-property"):
            self.assertNotIn(bad, js)

    def test_generichide(self):
        self.assertEqual(self.e.cosmetic_js("clean.example"), "")  # no specific rules there, generic switched off
        e = engine("##.gen\nclean.example##.spec\n@@||clean.example^$generichide\n")
        js = e.cosmetic_js("clean.example")
        self.assertIn(".spec", js)
        self.assertNotIn(".gen", js)

    def test_output_is_safe_to_embed(self):
        e = engine("example.com##.a</script><script>alert(1)\n")
        self.assertNotIn("</script>", e.cosmetic_js("example.com"))


class Threats(unittest.TestCase):
    def test_url_and_host_feeds(self):
        t = F.ThreatDB()
        t.add("http://Bad.Example/login.php?x=1\nhttps://worse.example/a/\n# c\n", "urls", "phishing", "Phish")
        t.add("0.0.0.0 evil-domain.test\nplain-domain.test\n", "domains", "malware", "Doms")
        self.assertEqual(t.lookup("https://bad.example/login.php?x=1#frag")[0], "phishing")
        self.assertEqual(t.lookup("http://worse.example/a")[0], "phishing")
        self.assertIsNone(t.lookup("https://bad.example/other"))
        self.assertEqual(t.lookup("https://www.evil-domain.test/anything")[0], "malware")
        self.assertEqual(t.lookup("https://plain-domain.test:8443/x?y=1")[0], "malware")
        self.assertIsNone(t.lookup("https://fine.test/"))
        self.assertIsNone(t.lookup("ftp://bad.example/login.php?x=1"))


class Cleaning(unittest.TestCase):
    def test_strip(self):
        self.assertEqual(F.clean_url("https://a.com/p?id=3&utm_source=x&fbclid=abc#top"), "https://a.com/p?id=3#top")
        self.assertEqual(F.clean_url("https://a.com/p?UTM_Medium=x&gclid=1"), "https://a.com/p")
        self.assertIsNone(F.clean_url("https://a.com/p?id=3&page=2"))
        self.assertIsNone(F.clean_url("https://a.com/"))
        self.assertIsNone(F.clean_url("shield://settings?utm_source=x"))

    def test_shims(self):
        self.assertEqual(F.clean_url("https://www.google.com/url?sa=t&url=https%3A%2F%2Fexample.org%2Fa%3Fb%3D1"), "https://example.org/a?b=1")
        self.assertEqual(F.clean_url("https://l.facebook.com/l.php?u=https%3A%2F%2Fexample.org%2F&h=AT0"), "https://example.org/")
        self.assertIsNone(F.clean_url("https://l.facebook.com/l.php?u=javascript%3Aalert(1)"))
        self.assertIsNone(F.clean_url("https://www.google.com/search?q=cats"))

    def test_never_raises(self):
        for u in ("", "http://", "not a url", "https://[::1", "https://a.com/?%"):
            F.clean_url(u)


class Hosts(unittest.TestCase):
    def test_site_of(self):
        self.assertEqual(F.site_of("a.b.example.co.uk"), "example.co.uk")
        self.assertEqual(F.site_of("www.example.com"), "example.com")
        self.assertEqual(F.site_of("192.168.0.1"), "192.168.0.1")
        self.assertTrue(F.host_in("a.b.c.com", {"c.com"}))
        self.assertFalse(F.host_in("abc.com", {"c.com"}))


class Manager(unittest.TestCase):
    def test_status_and_stale(self):
        with tempfile.TemporaryDirectory() as td:
            m = F.ListManager(td, "t", {"cookies": True, "ads": False})
            ids = {s["id"]: s for s in m.status()}
            self.assertFalse(ids["ads"]["on"])
            self.assertTrue(ids["cookies"]["on"])
            self.assertIn("privacy", m.stale())
            self.assertNotIn("ads", m.stale())

    def test_validate(self):
        item = next(i for i in F.CATALOG if i["id"] == "ads")
        with self.assertRaises(F.ListError):
            F.ListManager._validate(item, "<html>nope</html>")
        with self.assertRaises(F.ListError):
            F.ListManager._validate(item, "||a.com^\n")
        F.ListManager._validate(item, "\n".join(f"||a{i}.com^" for i in range(30)))

    def test_build_from_disk(self):
        with tempfile.TemporaryDirectory() as td:
            m = F.ListManager(td, "t", {k["id"]: k["id"] in ("ads", "phishing") for k in F.CATALOG})
            (m.dir / "ads.txt").write_text("||adserver.test^\n##.ad\n")
            (m.dir / "phishing.txt").write_text("https://phish.test/login\n")
            eng, th = m.build()
            self.assertEqual(eng.decide("https://adserver.test/a.js", "adserver.test", "p.com", F.T_SCRIPT, True)[0], "block")
            self.assertEqual(th.lookup("https://phish.test/login")[0], "phishing")


    def test_build_can_leave_out_the_ad_lists(self):
        with tempfile.TemporaryDirectory() as td:
            on = ("ads", "general", "hosts", "privacy", "phishing")
            m = F.ListManager(td, "t", {k["id"]: k["id"] in on for k in F.CATALOG})
            (m.dir / "ads.txt").write_text("||adserver.test^\n##.ad\n")
            (m.dir / "general.txt").write_text("||moreads.test^\n")
            (m.dir / "hosts.txt").write_text("0.0.0.0 hostads.test\n")
            (m.dir / "privacy.txt").write_text("||tracker.test^\n")
            (m.dir / "phishing.txt").write_text("https://phish.test/login\n")
            same = lambda e, h: e.decide(f"https://{h}/a.js", h, "p.com", F.T_SCRIPT, True)[0]
            eng, th = m.build()
            self.assertEqual([same(eng, h) for h in ("adserver.test", "moreads.test", "hostads.test", "tracker.test")], ["block"] * 4)
            eng, th = m.build(skip_ids=F.AD_LIST_IDS)
            self.assertEqual([same(eng, h) for h in ("adserver.test", "moreads.test", "hostads.test", "tracker.test")],
                             [None, None, None, "block"])
            self.assertEqual(th.lookup("https://phish.test/login")[0], "phishing")      # safety lists are untouched
            self.assertEqual(eng.cosmetic_js("page.com"), "")                           # and so is nothing hidden

    def test_ad_list_ids_exist_in_the_catalog(self):
        ids = {c["id"] for c in F.CATALOG}
        self.assertTrue(F.AD_LIST_IDS <= ids)
        self.assertFalse(F.AD_LIST_IDS & {"privacy", "unbreak", "harmful", "phishing", "malware"})


class Speed(unittest.TestCase):
    def test_large_list_is_fast(self):
        import random
        random.seed(1)
        lines = []
        for i in range(60000):
            k = i % 4
            w = "".join(random.choice("abcdefghijklmnop") for _ in range(8))
            if k == 0:
                lines.append(f"||{w}.example^")
            elif k == 1:
                lines.append(f"||{w}.example/{w[:4]}/*.js^$third-party")
            elif k == 2:
                lines.append(f"/{w}/banner*.png")
            else:
                lines.append(f"&{w}=*&ad_id=")
        for i in range(300):
            lines.append("/*.gif^$image")      # a few rules with no usable word
        t0 = time.time()
        e = engine("\n".join(lines))
        build = time.time() - t0
        urls = [f"https://cdn{i}.site{i % 50}.com/assets/js/app.{i}.js?v=123&token=abcdef" for i in range(3000)]
        t0 = time.time()
        for u in urls:
            e.decide(u, u.split("/")[2], "page.com", F.T_SCRIPT, True)
        per = (time.time() - t0) / len(urls) * 1000
        print(f"\n  build {build:.2f}s for {e.stats()['network']} rules, {per:.3f} ms per request")
        self.assertLess(per, 2.0)


if __name__ == "__main__":
    unittest.main()


class HarmfulLists(unittest.TestCase):
    def test_same_rule_in_two_lists_still_counts_as_harmful(self):
        e = F.FilterEngine()
        e.add_text("||evil.test^$all\n||ads.test^\n", "Ads")
        e.add_text("||evil.test^$all\n", "Scam list", harmful=True)
        e.finalize()
        self.assertTrue(e.harmful_hit("https://evil.test/", "evil.test"))
        self.assertTrue(e.harmful_hit("https://sub.evil.test/x", "sub.evil.test"))
        self.assertFalse(e.harmful_hit("https://ads.test/", "ads.test"))          # an ad rule is not a warning
        self.assertFalse(e.harmful_hit("https://fine.test/", "fine.test"))

    def test_exception_cancels_warning(self):
        e = F.FilterEngine()
        e.add_text("||evil.test^$all\n@@||evil.test/safe^$all\n", "Scam list", harmful=True)
        e.finalize()
        self.assertTrue(e.harmful_hit("https://evil.test/bad", "evil.test"))
        self.assertFalse(e.harmful_hit("https://evil.test/safe", "evil.test"))
