"""
shield_filters.py: the blocking brain of the browser.

No Qt in here, so all of it can be tested on its own. It does four jobs:

  1. FilterEngine: reads standard ad/tracker filter lists (the Adblock syntax that EasyList and uBlock
     Origin lists use, plus hosts files) and answers one question fast: "should this request be blocked?"
     It also produces the element-hiding rules (cosmetic filters) for a page.
  2. ThreatDB: live phishing and malware feeds, matched locally. The browser never sends the address you
     visit anywhere; it downloads the feeds and looks addresses up on your own computer.
  3. ListManager: downloads and refreshes the lists (HTTPS only, conditional requests, validated, atomic).
  4. clean_url: strips tracking parameters and unwraps link-shim redirects (utm_*, fbclid, l.facebook.com...).

Rules the engine does not fully understand (procedural cosmetics, scriptlets, $removeparam, $csp, $popup,
regex rules...) are skipped instead of half-applied, so a list can never make it block more than it says.

Speed matters because matching runs on Chromium's network thread for every request. Rules are indexed:
pure-domain rules by host, everything else by the rarest word in the pattern, so a typical request touches
only a handful of rules instead of tens of thousands.
"""
from __future__ import annotations

import ipaddress
import json
import os
import re
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import parse_qsl, quote, urlsplit, urlunsplit

# --------------------------------------------------------------------------
# Host helpers (shared with shield_core)
# --------------------------------------------------------------------------
MULTI_SUFFIX = {
    "co.uk", "org.uk", "ac.uk", "gov.uk", "me.uk", "com.au", "net.au", "org.au", "edu.au", "gov.au", "co.jp", "or.jp",
    "ne.jp", "ac.jp", "go.jp", "co.nz", "org.nz", "net.nz", "ac.nz", "govt.nz", "co.za", "org.za", "com.br", "net.br",
    "org.br", "com.cn", "net.cn", "org.cn", "com.mx", "org.mx", "co.in", "net.in", "org.in", "com.tr", "org.tr",
    "com.sg", "com.hk", "com.tw", "co.kr", "or.kr", "com.ar", "com.co", "com.ua", "co.id", "com.my", "com.ph",
    "com.vn", "co.il", "com.pk", "com.ng", "co.ke", "com.eg", "com.sa", "com.pe", "com.ve", "co.th",
}


def site_of(host):
    """Registrable domain, good enough for first-party/third-party decisions (no public-suffix list needed)."""
    host = (host or "").lower().strip(".")
    try:
        ipaddress.ip_address(host.strip("[]"))
        return host
    except ValueError:
        pass
    p = host.split(".")
    if len(p) <= 2:
        return host
    return ".".join(p[-3:]) if ".".join(p[-2:]) in MULTI_SUFFIX else ".".join(p[-2:])


def host_in(host, domains):
    """True if host, or any parent domain of it, is in domains (a set or dict)."""
    parts = (host or "").lower().strip(".").split(".")
    return any(".".join(parts[i:]) in domains for i in range(len(parts)))


def _host_get(host, table):
    parts = (host or "").lower().strip(".").split(".")
    for i in range(len(parts)):
        v = table.get(".".join(parts[i:]))
        if v is not None:
            return v
    return None


# --------------------------------------------------------------------------
# Request types (Chromium resource types, folded into the names filter lists use)
# --------------------------------------------------------------------------
T_SCRIPT, T_IMAGE, T_STYLE, T_FONT, T_MEDIA, T_OBJECT = 1, 2, 4, 8, 16, 32
T_XHR, T_SUBDOC, T_PING, T_WS, T_OTHER, T_DOC = 64, 128, 256, 512, 1024, 2048
T_DEFAULT = T_SCRIPT | T_IMAGE | T_STYLE | T_FONT | T_MEDIA | T_OBJECT | T_XHR | T_SUBDOC | T_PING | T_WS | T_OTHER
T_ALL = T_DEFAULT | T_DOC

_TYPE_OPTS = {
    "script": T_SCRIPT, "image": T_IMAGE, "stylesheet": T_STYLE, "css": T_STYLE, "font": T_FONT, "media": T_MEDIA,
    "object": T_OBJECT, "object-subrequest": T_OBJECT, "xmlhttprequest": T_XHR, "xhr": T_XHR, "subdocument": T_SUBDOC,
    "frame": T_SUBDOC, "ping": T_PING, "beacon": T_PING, "websocket": T_WS, "other": T_OTHER, "document": T_DOC,
    "doc": T_DOC,
}
# Options that only change *how* a block happens; treating them as a plain block is what a browser without
# redirect surrogates does anyway.
_PLAIN_OK = {"empty", "mp4", "1p", "3p", "first-party", "third-party", "important", "badfilter", "generichide",
             "ghide", "elemhide", "ehide", "all"}

SEP = r"(?:[^a-z0-9_\-.%]|$)"
_TOKEN = re.compile(r"[a-z0-9%]{3,}")
_SKIP_TOKENS = {"http", "https", "www", "com", "net", "org", "html", "php", "js", "css", "jpg", "png", "gif"}


class Rule:
    __slots__ = ("rx_src", "_rx", "types", "third", "inc", "exc", "src", "host_anchored", "key")

    def __init__(self, rx_src, types, third, inc, exc, src, host_anchored, key):
        self.rx_src, self._rx = rx_src, None
        self.types, self.third, self.inc, self.exc, self.src = types, third, inc, exc, src
        self.host_anchored, self.key = host_anchored, key

    @property
    def rx(self):
        if self._rx is None and self.rx_src is not None:
            self._rx = re.compile(self.rx_src)
        return self._rx


def _to_regex(body, anchor_start, anchor_end):
    out = ["^"] if anchor_start else []
    if not anchor_start:
        body = body.lstrip("*")
    if not anchor_end:
        body = body.rstrip("*")
    for ch in body:
        if ch == "*":
            out.append(".*")
        elif ch == "^":
            out.append(SEP)
        else:
            out.append(re.escape(ch))
    if anchor_end:
        out.append("$")
    return "".join(out)


def _domains(spec):
    inc, exc = set(), set()
    for d in spec.lower().split("|"):
        d = d.strip()
        if not d or "*" in d or "/" in d:
            continue
        (exc if d.startswith("~") else inc).add(d.lstrip("~"))
    return frozenset(inc), frozenset(exc)


def parse_network(line, src, fmt="abp"):
    """
    One filter line to a parsed rule, or None when the line isn't a network rule or uses something we don't support.
    Returns (kind, payload): ("block"|"important"|"allow", Rule), ("hosts", host), ("site_off", host),
    ("cos_off", (host, "all"|"generic")) or ("bad", key).
    """
    if fmt == "hosts":
        parts = line.split("#")[0].split()
        if not parts:
            return None
        host = parts[1] if len(parts) > 1 else parts[0]
        host = host.lower().strip(".")
        if host in ("localhost", "localhost.localdomain", "local", "broadcasthost", "ip6-localhost", "0.0.0.0") \
                or not re.fullmatch(r"[a-z0-9][a-z0-9._-]*\.[a-z0-9-]+", host):
            return None
        return ("hosts", host)

    exception = line.startswith("@@")
    rule = line[2:] if exception else line
    opts = ""
    i = rule.rfind("$")
    if i >= 0 and not (rule.startswith("/") and rule.endswith("/")):
        opts, rule = rule[i + 1:], rule[:i]
    if not rule or (rule.startswith("/") and rule.endswith("/") and len(rule) > 2):
        return None                                   # regex rules: skipped on purpose
    if re.search(r"[\s]", rule):
        return None

    types = neg = 0
    third = None
    inc = exc = frozenset()
    important = bad = False
    cos = None
    for o in (opts.split(",") if opts else ()):
        o = o.strip().lower()
        if not o:
            continue
        name, _, val = o.partition("=")
        neg_opt = name.startswith("~")
        name = name.lstrip("~")
        if name == "domain":
            inc, exc = _domains(val)
        elif name in ("third-party", "3p"):
            third = not neg_opt
        elif name in ("first-party", "1p"):
            third = neg_opt
        elif name in _TYPE_OPTS:
            if neg_opt:
                neg |= _TYPE_OPTS[name]
            else:
                types |= _TYPE_OPTS[name]
        elif name == "all":
            types |= T_ALL
        elif name == "important":
            important = True
        elif name == "badfilter":
            bad = True
        elif name in ("generichide", "ghide"):
            cos = "generic"
        elif name in ("elemhide", "ehide"):
            cos = "all"
        elif name == "redirect" or name in _PLAIN_OK:
            pass
        else:
            return None                               # unknown or unsupported option: don't half-apply
    if types == 0:
        types = T_DEFAULT & ~neg
    else:
        types &= ~neg
    key = ("@@" if exception else "") + rule + "$" + ",".join(sorted(x for x in opts.lower().split(",") if x and x != "badfilter"))
    if bad:
        return ("bad", key)

    host_anchored = rule.startswith("||")
    anchor_start = rule.startswith("|") and not host_anchored
    anchor_end = rule.endswith("|") and len(rule) > 1
    body = rule[2:] if host_anchored else rule[1:] if anchor_start else rule
    if anchor_end:
        body = body[:-1]
    body = body.lower()
    if not body or len(body) > 300 or body.count("*") > 6:
        return None

    # Page-wide switches: @@||example.com^$document and the cosmetic exceptions.
    pure = re.fullmatch(r"([a-z0-9][a-z0-9.-]*)\^?", body) if host_anchored else None
    if exception and pure and cos:
        return ("cos_off", (pure.group(1), cos))
    if exception and pure and (types & T_DOC) and not third and not inc and not exc:
        return ("site_off", pure.group(1))

    if host_anchored:
        m = re.match(r"([a-z0-9][a-z0-9.-]*)", body)
        host = m.group(1)
        rest = body[len(host):]
        if rest == "" or rest[0] in "^/:?":
            rx = None if rest in ("", "^") else _to_regex(rest, False, anchor_end)
            r = Rule(rx, types, third, inc, exc, src, True, key)
            r.key = key
            return ("allow" if exception else "important" if important else "block", r, host)
        rx = "^[a-z][a-z0-9+.-]*://(?:[^/?#]*[.@])?" + _to_regex(body, False, anchor_end)[0:]
        r = Rule(rx, types, third, inc, exc, src, False, key)
        return ("allow" if exception else "important" if important else "block", r, None, body)
    r = Rule(_to_regex(body, anchor_start, anchor_end), types, third, inc, exc, src, False, key)
    return ("allow" if exception else "important" if important else "block", r, None, body)


# --------------------------------------------------------------------------
# Rule index
# --------------------------------------------------------------------------
class _Index:
    def __init__(self):
        self.by_host = {}        # host -> [Rule]   (||host^ and ||host/path)
        self.by_token = {}       # word -> [Rule]
        self.generic = []        # rules with no usable word
        self.count = 0

    def add_host(self, host, rule):
        self.by_host.setdefault(host, []).append(rule)
        self.count += 1

    def add_generic(self, rule):
        self.generic.append(rule)
        self.count += 1

    @staticmethod
    def _ok(r, rtype, third, top):
        if not r.types & rtype:
            return False
        if r.third is not None and r.third != third:
            return False
        if r.inc and not (top and host_in(top, r.inc)):
            return False
        if r.exc and top and host_in(top, r.exc):
            return False
        return True

    def find(self, url, host, after, tokens, rtype, third, top):
        if self.by_host:
            parts = host.split(".")
            for i in range(len(parts)):
                for r in self.by_host.get(".".join(parts[i:]), ()):
                    if self._ok(r, rtype, third, top) and (r.rx is None or r.rx.match(after)):
                        return r
        if self.by_token:
            for t in tokens:
                for r in self.by_token.get(t, ()):
                    if self._ok(r, rtype, third, top) and r.rx.search(url):
                        return r
        for r in self.generic:
            if self._ok(r, rtype, third, top) and r.rx.search(url):
                return r
        return None


_COS_MARK = re.compile(r"^[^#\s]*#@?[?$%]?#")
_COSMETIC_BAD = re.compile(r"[{};<>`\\]|:(?:-abp-|xpath|matches-css|matches-attr|matches-media|matches-path|upward|"
                           r"nth-ancestor|remove|style|watch-attr|min-text-length|others|contains|has-text|if|if-not|"
                           r"not\(:)|url\(|@import|expression\(", re.I)
GENERIC_CAP, SPECIFIC_CAP = 6000, 2500


class FilterEngine:
    def __init__(self):
        self.blk, self.imp, self.alw = _Index(), _Index(), _Index()
        self.harm = _Index()         # the same rules, but only those that came from a list marked harmful
        self.hosts = {}              # blocked hosts from hosts files (third-party requests only): host -> list index
        self.site_off = set()        # @@||site^$document: nothing is filtered on these sites
        self.cos_off_all, self.cos_off_generic = set(), set()
        self.generic, self.generic_exc = [], set()
        self.specific, self.specific_exc = {}, {}
        self.names = []              # list index -> display name
        self.harmful = set()         # names of lists whose document rules mean "warn before opening"
        self._pend = {"block": [], "important": [], "allow": []}
        self._bad = set()
        self._generic_json = None
        self.network_rules = self.cosmetic_rules = 0

    # -- loading -------------------------------------------------------------
    def add_text(self, text, name, fmt="abp", harmful=False):
        src = len(self.names)
        self.names.append(name)
        if harmful:
            self.harmful.add(name)
        seen = set()                  # per list: the same rule in two lists must stay attributed to both
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line[0] == "!" or (fmt == "hosts" and line[0] == "#"):
                continue
            if fmt == "abp":
                if line[0] == "[":
                    continue
                if _COS_MARK.search(line):
                    self._cosmetic(line)
                    continue
                if line[0] == "#":                      # a "# comment" line, not a rule
                    continue
            if line in seen:
                continue
            seen.add(line)
            try:
                res = parse_network(line, src, fmt)
            except re.error:
                res = None
            if not res:
                continue
            kind = res[0]
            if kind == "hosts":
                self.hosts.setdefault(res[1], src)
            elif kind == "site_off":
                self.site_off.add(res[1])
            elif kind == "cos_off":
                (self.cos_off_all if res[1][1] == "all" else self.cos_off_generic).add(res[1][0])
            elif kind == "bad":
                self._bad.add(res[1])
            else:
                self._pend[kind].append(res[1:])

    def _cosmetic(self, line):
        m = re.match(r"^([^#\s]*)(#@?[?$%]?#)(.*)$", line)
        if not m:
            return
        doms, op, sel = m.group(1), m.group(2), m.group(3).strip()
        if op not in ("##", "#@#") or not sel or _COSMETIC_BAD.search(sel) or sel[0] in "+^":
            return                                    # procedural, scriptlet and style-injection rules: skipped
        inc, exc = _domains(doms.replace(",", "|")) if doms else (frozenset(), frozenset())
        self.cosmetic_rules += 1
        if op == "#@#":
            if inc:
                for d in inc:
                    self.specific_exc.setdefault(d, set()).add(sel)
            else:
                self.generic_exc.add(sel)
        elif inc:
            for d in inc:
                self.specific.setdefault(d, []).append(sel)
        else:
            self.generic.append(sel)
            for d in exc:                             # ~example.com##.ad : everywhere except there
                self.specific_exc.setdefault(d, set()).add(sel)

    def finalize(self):
        """Build the indexes. Words are chosen by rarity so lookups stay short."""
        freq = {}
        staged = []
        for kind in ("block", "important", "allow"):
            for item in self._pend[kind]:
                rule, host, body = item[0], item[1], (item[2] if len(item) > 2 else None)
                if rule.key in self._bad:
                    continue
                toks = []
                if host is None and body is not None:
                    toks = self._safe_tokens(body, rule)
                    for t in toks:
                        freq[t] = freq.get(t, 0) + 1
                staged.append((kind, rule, host, toks))
        idx = {"block": self.blk, "important": self.imp, "allow": self.alw}

        def place(ix, rule, host, toks):
            if host is not None:
                ix.add_host(host, rule)
            elif toks:
                best = min(toks, key=lambda t: (freq.get(t, 0), -len(t)))
                ix.by_token.setdefault(best, []).append(rule)
                ix.count += 1
            else:
                ix.add_generic(rule)
        for kind, rule, host, toks in staged:
            place(idx[kind], rule, host, toks)
            if kind != "allow" and self.names[rule.src] in self.harmful:
                place(self.harm, rule, host, toks)
        self._pend = {"block": [], "important": [], "allow": []}
        self._bad.clear()
        self.network_rules = self.blk.count + self.imp.count + self.alw.count + len(self.hosts)
        # de-duplicate cosmetic selectors, keep order
        self.generic = list(dict.fromkeys(self.generic))
        for d, sels in self.specific.items():
            self.specific[d] = list(dict.fromkeys(sels))
        return self

    @staticmethod
    def _safe_tokens(body, rule):
        out = []
        anchor_end = rule.rx_src.endswith("$") if rule.rx_src else False
        anchor_start = rule.rx_src.startswith("^") if rule.rx_src else False
        for m in _TOKEN.finditer(body):
            s, e = m.span()
            t = m.group()
            if t in _SKIP_TOKENS:
                continue
            left_ok = (s > 0 and body[s - 1] != "*") or (s == 0 and anchor_start)
            right_ok = (e < len(body) and body[e] != "*") or (e == len(body) and anchor_end)
            if left_ok and right_ok:
                out.append(t)
        return out

    # -- queries ---------------------------------------------------------------
    def decide(self, url, host, top_host, rtype, third):
        """
        url: the full request URL, ASCII and lower-case. host: its hostname. top_host: the page's hostname.
        Returns ("block" | "allow" | None, list_name). Safe to call from any thread once finalize() has run.
        """
        if top_host and self.site_off and host_in(top_host, self.site_off):
            return None, ""
        i = url.find(host)
        after = url[i + len(host):] if i >= 0 else ""
        tokens = set(_TOKEN.findall(url))
        r = self.imp.find(url, host, after, tokens, rtype, third, top_host)
        if r:
            return "block", self.names[r.src]
        r = self.blk.find(url, host, after, tokens, rtype, third, top_host)
        src = r.src if r else None
        if r is None and third and self.hosts:
            h = _host_get(host, self.hosts)
            if h is not None:
                src = h
        if src is None:
            return None, ""
        if self.alw.find(url, host, after, tokens, rtype, third, top_host):
            return "allow", ""
        return "block", self.names[src]

    def harmful_hit(self, url, host):
        """True when a page address matches a rule from a list marked harmful (and no exception cancels it)."""
        if not self.harm.count or (self.site_off and host_in(host, self.site_off)):
            return False
        i = url.find(host)
        after = url[i + len(host):] if i >= 0 else ""
        tokens = set(_TOKEN.findall(url))
        if self.alw.find(url, host, after, tokens, T_DOC, False, host):
            return False
        return self.harm.find(url, host, after, tokens, T_DOC, False, host) is not None

    def cosmetic_js(self, host):
        """The script that hides ad containers on this page, or '' when there is nothing to hide."""
        host = (host or "").lower()
        if not host or host_in(host, self.cos_off_all) or host_in(host, self.site_off):
            return ""
        spec, exc = [], set()
        parts = host.split(".")
        for i in range(max(1, len(parts) - 1)):
            d = ".".join(parts[i:])
            spec += self.specific.get(d, ())
            exc |= self.specific_exc.get(d, set())
        generic_on = bool(self.generic) and not host_in(host, self.cos_off_generic)
        spec = [x for x in dict.fromkeys(spec) if x not in exc][:SPECIFIC_CAP]
        if not generic_on:
            gj = "[]"
        elif not exc and not self.generic_exc:
            if self._generic_json is None:
                self._generic_json = _js_json(self.generic[:GENERIC_CAP])
            gj = self._generic_json
        else:
            gj = _js_json([x for x in self.generic[:GENERIC_CAP] if x not in exc and x not in self.generic_exc])
        if gj == "[]" and not spec:
            return ""
        return COSMETIC_JS.replace("__G__", gj).replace("__S__", _js_json(spec))

    def stats(self):
        return {"network": self.network_rules, "cosmetic": self.cosmetic_rules, "lists": len(self.names)}


def _js_json(obj):
    return json.dumps(obj, separators=(",", ":")).replace("<", "\\u003c").replace("\u2028", "\\u2028").replace("\u2029", "\\u2029")


COSMETIC_JS = r"""
(()=>{try{
const G=__G__,S=__S__;
const ok=s=>{try{return CSS.supports("selector("+s+")")}catch(e){return false}};
const css=[];
const push=l=>{for(let i=0;i<l.length;i+=300){const c=l.slice(i,i+300);
 if(ok(c.join(",")))css.push(c.join(",\n")+"{display:none!important}");
 else{const g=c.filter(ok);if(g.length)css.push(g.join(",\n")+"{display:none!important}")}}};
push(S);push(G);
if(!css.length)return;
const go=()=>{const t=css.join("\n");
 try{const sh=new CSSStyleSheet();sh.replaceSync(t);document.adoptedStyleSheets=[...document.adoptedStyleSheets,sh];return}catch(e){}
 const st=document.createElement("style");st.textContent=t;(document.head||document.documentElement).appendChild(st)};
if(document.documentElement)go();
else new MutationObserver((_,o)=>{if(document.documentElement){o.disconnect();go()}}).observe(document,{childList:true});
}catch(e){}})();
"""


# --------------------------------------------------------------------------
# Threat feeds (matched locally)
# --------------------------------------------------------------------------
def norm_url(u):
    """host + path + query, lower-case host, no scheme, no fragment, no trailing slash: how feeds are compared."""
    u = (u or "").strip()
    m = re.match(r"^https?://([^/?#]*)([^#]*)", u, re.I)
    if not m:
        return None
    auth, rest = m.group(1), m.group(2)
    host = re.sub(r":(80|443)$", "", auth.rsplit("@", 1)[-1].lower()).rstrip(".")
    if rest in ("", "/"):
        rest = ""
    elif "?" not in rest:
        rest = rest.rstrip("/")
    return host + rest


class ThreatDB:
    def __init__(self):
        self.urls = {}      # normalized url -> (kind, list name)
        self.hosts = {}     # host -> (kind, list name)

    def add(self, text, fmt, kind, name):
        n = 0
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line[0] in "#!;":
                continue
            if fmt == "urls":
                k = norm_url(line.split()[0])
                if k:
                    self.urls[k] = (kind, name)
                    n += 1
            else:
                h = line.split("#")[0].split()
                h = (h[1] if len(h) > 1 else h[0]).lower().strip(".") if h else ""
                if h and re.fullmatch(r"[a-z0-9][a-z0-9._-]*\.[a-z0-9-]+", h):
                    self.hosts[h] = (kind, name)
                    n += 1
        return n

    def lookup(self, url):
        """(kind, list name) when this exact address (or its host, for host lists) is on a feed, else None."""
        k = norm_url(url)
        if not k:
            return None
        hit = self.urls.get(k)
        if hit:
            return hit
        host = k.split("/", 1)[0].split("?", 1)[0].split(":", 1)[0]
        return _host_get(host, self.hosts) if self.hosts else None

    def __len__(self):
        return len(self.urls) + len(self.hosts)


# --------------------------------------------------------------------------
# Tracking parameters and link shims
# --------------------------------------------------------------------------
TRACKING_PARAMS = {
    "fbclid", "gclid", "gclsrc", "dclid", "gbraid", "wbraid", "msclkid", "yclid", "twclid", "ttclid", "li_fat_id",
    "igshid", "igsh", "mc_eid", "mc_cid", "_hsenc", "_hsmi", "__hssc", "__hstc", "__hsfp", "hsctatracking",
    "mkt_tok", "vero_id", "vero_conv", "wickedid", "oly_enc_id", "oly_anon_id", "rb_clickid", "_openstat", "ref_src",
    "pk_campaign", "pk_kwd", "pk_source", "pk_medium", "piwik_campaign", "piwik_kwd", "fb_action_ids",
    "fb_action_types", "fb_source", "_ga", "_gl", "ef_id", "epik", "irclickid",
}
TRACKING_PREFIXES = ("utm_", "mtm_", "matomo_", "hsa_", "stm_")

# (host suffix, path, query parameter holding the real destination)
LINK_SHIMS = [
    ("google.com", "/url", ("q", "url")),
    ("l.facebook.com", "/l.php", ("u",)),
    ("lm.facebook.com", "/l.php", ("u",)),
    ("l.instagram.com", "/", ("u",)),
    ("out.reddit.com", "/", ("url",)),
    ("youtube.com", "/redirect", ("q",)),
    ("slack-redir.net", "/link", ("url",)),
    ("steamcommunity.com", "/linkfilter/", ("u", "url")),
    ("t.umblr.com", "/redirect", ("z",)),
]


def clean_url(url):
    """
    A cleaned copy of url (tracking parameters removed, link shims unwrapped), or None if nothing changed.
    Only http(s) URLs are touched. Never raises.
    """
    try:
        s = urlsplit(url)
        if s.scheme not in ("http", "https") or not s.hostname:
            return None
        host = s.hostname.lower()
        for suffix, path, params in LINK_SHIMS:
            if (host == suffix or host.endswith("." + suffix)) and (s.path == path or (path == "/" and s.path in ("", "/"))):
                q = dict(parse_qsl(s.query, keep_blank_values=False))
                for p in params:
                    dest = q.get(p, "")
                    d = urlsplit(dest)
                    if d.scheme in ("http", "https") and d.hostname:
                        return dest
        if not s.query:
            return None
        kept, changed = [], False
        for part in s.query.split("&"):
            key = part.split("=", 1)[0].lower()
            if key in TRACKING_PARAMS or key.startswith(TRACKING_PREFIXES):
                changed = True
            else:
                kept.append(part)
        if not changed:
            return None
        return urlunsplit((s.scheme, s.netloc, s.path, "&".join(kept), s.fragment))
    except Exception:
        return None


# --------------------------------------------------------------------------
# The lists themselves
# --------------------------------------------------------------------------
# Names are descriptions of what a list does, not who publishes it: the browser shows only its own brand.
CATALOG = [
    {"id": "ads", "name": "Ads", "desc": "Banner, video and pop-up ad networks, plus the page space they leave behind.",
     "url": "https://easylist.to/easylist/easylist.txt", "fmt": "abp", "role": "filter", "default": True, "hours": 72},
    {"id": "privacy", "name": "Trackers", "desc": "Analytics, beacons and cross-site tracking scripts.",
     "url": "https://easylist.to/easylist/easyprivacy.txt", "fmt": "abp", "role": "filter", "default": True, "hours": 72},
    {"id": "general", "name": "Extra protection", "desc": "Additional ad, tracker and annoyance rules, updated often.",
     "url": "https://ublockorigin.github.io/uAssets/filters/filters.txt", "fmt": "abp", "role": "filter", "default": True, "hours": 72},
    {"id": "unbreak", "name": "Compatibility fixes", "desc": "Exceptions that stop blocking from breaking logins, videos and checkouts.",
     "url": "https://ublockorigin.github.io/uAssets/filters/unbreak.txt", "fmt": "abp", "role": "filter", "default": True, "hours": 72},
    {"id": "hosts", "name": "Ad and tracker hosts", "desc": "A plain list of domains that exist only to serve ads and tracking.",
     "url": "https://pgl.yoyo.org/adservers/serverlist.php?hostformat=hosts&showintro=0&mimetype=plaintext",
     "fmt": "hosts", "role": "filter", "default": True, "hours": 120},
    {"id": "harmful", "name": "Scam and malware sites", "desc": "Known scam, fake-download and malware sites. You get a warning before they open.",
     "url": "https://ublockorigin.github.io/uAssets/filters/badware.txt", "fmt": "abp", "role": "filter", "default": True, "hours": 48},
    {"id": "cookies", "name": "Cookie banners", "desc": "Hides cookie consent pop-ups. Off by default because it can hide a button a site needs.",
     "url": "https://secure.fanboy.co.nz/fanboy-cookiemonster.txt", "fmt": "abp", "role": "filter", "default": False, "hours": 72},
    {"id": "annoyances", "name": "Pop-ups and overlays", "desc": "Newsletter nags, chat bubbles and other overlays. Off by default.",
     "url": "https://secure.fanboy.co.nz/fanboy-annoyance.txt", "fmt": "abp", "role": "filter", "default": False, "hours": 72},
    {"id": "phishing", "name": "Live phishing pages", "desc": "Addresses of phishing pages reported in the last hours. Matched on this computer.",
     "url": "https://openphish.com/feed.txt", "fmt": "urls", "role": "threat", "kind": "phishing", "default": True, "hours": 6},
    {"id": "malware", "name": "Live malware downloads", "desc": "Addresses currently serving malware. Matched on this computer.",
     "url": "https://urlhaus.abuse.ch/downloads/text_online/", "fmt": "urls", "role": "threat", "kind": "malware", "default": True, "hours": 6},
    {"id": "phish-domains", "name": "Phishing domains (large)", "desc": "A much bigger list of phishing domains. Uses more memory, so it is off by default.",
     "url": "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt",
     "fmt": "domains", "role": "threat", "kind": "phishing", "default": False, "hours": 24},
]
MAX_LIST_BYTES = 80 * 1024 * 1024


class ListError(Exception):
    pass


class _HttpsOnly(urllib.request.HTTPRedirectHandler):
    """Follow redirects, but never to anything that isn't HTTPS."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if not newurl.lower().startswith("https://"):
            raise urllib.error.URLError("redirect to a non-HTTPS address refused")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class ListManager:
    def __init__(self, home, version="1", enabled=None):
        self.dir = Path(home) / "lists"
        self.dir.mkdir(parents=True, exist_ok=True)
        self.version = version
        self.overrides = enabled if enabled is not None else {}   # id -> bool, shared with Settings
        self.lock = threading.Lock()

    # -- state -------------------------------------------------------------
    def is_on(self, item):
        return bool(self.overrides.get(item["id"], item["default"]))

    def _meta_path(self, item):
        return self.dir / f"{item['id']}.json"

    def _data_path(self, item):
        return self.dir / f"{item['id']}.txt"

    def meta(self, item):
        try:
            return json.loads(self._meta_path(item).read_text("utf-8"))
        except (OSError, ValueError):
            return {}

    def status(self):
        out = []
        for it in CATALOG:
            m = self.meta(it)
            have = self._data_path(it).exists()
            out.append({"id": it["id"], "name": it["name"], "desc": it["desc"], "on": self.is_on(it), "role": it["role"],
                        "have": have, "ts": m.get("ts", 0), "size": m.get("size", 0), "default": it["default"]})
        return out

    def stale(self, force_hours=None):
        """Enabled lists that are missing or older than their refresh interval."""
        now, out = time.time(), []
        for it in CATALOG:
            if not self.is_on(it):
                continue
            ts = self.meta(it).get("ts", 0)
            limit = (force_hours if force_hours is not None else it["hours"]) * 3600
            if not self._data_path(it).exists() or now - ts > limit:
                out.append(it["id"])
        return out

    # -- download ----------------------------------------------------------
    def update(self, ids=None, progress=None, force=False):
        """Download the given lists (default: every enabled one). One failed list never blocks the others."""
        todo = [it for it in CATALOG if (ids is None and self.is_on(it)) or (ids is not None and it["id"] in ids)]
        errors, changed = [], 0
        for it in todo:
            if progress:
                progress(f"Updating {it['name']}")
            try:
                changed += 1 if self._fetch(it, force) else 0
            except ListError as e:
                errors.append(f"{it['name']}: {e}")
        return changed, errors

    def _fetch(self, item, force):
        meta = self.meta(item)
        headers = {"User-Agent": f"Shield-Browser/{self.version}", "Accept": "text/plain, */*"}
        if not force and self._data_path(item).exists():
            if meta.get("etag"):
                headers["If-None-Match"] = meta["etag"]
            if meta.get("modified"):
                headers["If-Modified-Since"] = meta["modified"]
        req = urllib.request.Request(item["url"], headers=headers)
        opener = urllib.request.build_opener(_HttpsOnly)
        try:
            with opener.open(req, timeout=40) as r:
                raw = r.read(MAX_LIST_BYTES + 1)
                etag, modified = r.headers.get("ETag", ""), r.headers.get("Last-Modified", "")
        except urllib.error.HTTPError as e:
            if e.code == 304:
                meta["ts"] = time.time()
                self._write_meta(item, meta)
                return False
            raise ListError(f"the server answered {e.code}") from None
        except (urllib.error.URLError, OSError, ValueError):
            raise ListError("couldn't connect") from None
        if len(raw) > MAX_LIST_BYTES:
            raise ListError("the list is unexpectedly large")
        text = raw.decode("utf-8", "replace")
        self._validate(item, text)
        tmp = self._data_path(item).with_suffix(".part")
        tmp.write_text(text, encoding="utf-8")
        os.replace(tmp, self._data_path(item))
        self._write_meta(item, {"ts": time.time(), "etag": etag, "modified": modified, "size": len(raw)})
        return True

    def _write_meta(self, item, meta):
        try:
            self._meta_path(item).write_text(json.dumps(meta), encoding="utf-8")
        except OSError:
            pass

    @staticmethod
    def _validate(item, text):
        head = text[:4000].lstrip()
        if not head or head.lower().startswith(("<!doctype", "<html", "<?xml", "{")):
            raise ListError("the download wasn't a list")
        lines = [l for l in text.splitlines() if l.strip() and not l.lstrip().startswith(("!", "#", "["))]
        if len(lines) < (1 if item["role"] == "threat" else 15):
            raise ListError("the list looks empty")
        if item["fmt"] == "urls" and not any(l.lower().startswith("http") for l in lines[:50]):
            raise ListError("the list is in an unexpected format")

    # -- build ---------------------------------------------------------------
    def build(self):
        """Parse every enabled list from disk. Returns (FilterEngine, ThreatDB)."""
        eng, threats = FilterEngine(), ThreatDB()
        for it in CATALOG:
            if not self.is_on(it):
                continue
            try:
                text = self._data_path(it).read_text("utf-8", "replace")
            except OSError:
                continue
            if it["role"] == "threat":
                threats.add(text, it["fmt"], it["kind"], it["name"])
            else:
                eng.add_text(text, it["name"], it["fmt"], harmful=it["id"] == "harmful")
        return eng.finalize(), threats
