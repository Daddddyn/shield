"""
shield_core.py: settings, local storage and the security engine.

Nothing in this file talks to the network. Everything is stored locally in
~/.shieldbrowser (override with the SHIELD_HOME environment variable).
File scanning lives in shield_scan.py, the blocking rules and threat feeds in shield_filters.py,
the password vault in shield_vault.py.
"""
import copy
import ipaddress
import json
import os
import re
import sqlite3
import threading
import time
from collections import Counter, deque
from pathlib import Path
from urllib.parse import urlparse

from PyQt6.QtWebEngineCore import QWebEngineUrlRequestInfo, QWebEngineUrlRequestInterceptor

from shield_filters import (  # noqa: F401  (site_of and host_in are re-exported for the rest of the app)
    CATALOG, T_DOC, T_FONT, T_IMAGE, T_MEDIA, T_OBJECT, T_OTHER, T_PING, T_SCRIPT, T_STYLE, T_SUBDOC, T_WS, T_XHR,
    host_in, site_of,
)
from shield_scan import (  # noqa: F401  (re-exported for the rest of the app)
    BENIGN_LOOKING, BIDI_CHARS, DOUBLE_EXT, EXEC_EXT, EXEC_MIMES, RISKY_EXT,
)

VERSION = "2.3.0"
HOME = Path(os.environ.get("SHIELD_HOME") or Path.home() / ".shieldbrowser")
HOME.mkdir(parents=True, exist_ok=True)
DOWNLOADS = Path(os.environ.get("SHIELD_DOWNLOADS") or Path.home() / "Downloads")
QUARANTINE = DOWNLOADS / "ShieldQuarantine"

SEARCH_ENGINES = {
    "duckduckgo": ("DuckDuckGo", "https://duckduckgo.com/?q={}"),
    "brave": ("Brave Search", "https://search.brave.com/search?q={}"),
    "startpage": ("Startpage", "https://www.startpage.com/do/search?q={}"),
    "mojeek": ("Mojeek", "https://www.mojeek.com/search?q={}"),
    "ecosia": ("Ecosia", "https://www.ecosia.org/search?q={}"),
    "google": ("Google", "https://www.google.com/search?q={}"),
}

DEFAULTS = {
    "theme": "dark",
    "homepage": "shield://newtab",
    "search_engine": "duckduckgo",
    "https_only": True,
    "block_trackers": True,
    "block_third_party_cookies": True,
    "block_local_network": True,
    "fingerprint_protection": True,
    "send_gpc": True,
    "navigation_guard": True,
    "permissions": "deny",
    "risky_downloads": "ask",
    "vt_confirm_upload": True,
    "scan_yara": True,
    "scan_clamav": True,
    "scan_defender": True,
    "vt_auto_lookup": False,
    "history_days": 30,
    "persistent_sessions": False,
    "site_rules": {},
    "custom_blocklist": [],
    # protection lists (shield_filters.py)
    "filter_lists": {},               # list id -> on/off, only where the user changed the default
    "cosmetic_filtering": True,       # hide the empty boxes ads leave behind
    "block_harmful": True,            # warn before known phishing, malware and scam sites
    "clean_links": True,              # strip tracking parameters and unwrap redirect links
    "auto_update_lists": True,        # refresh the lists in the background (no personal data is sent)
    "fingerprint_level": "standard",
    # startup and exit
    "startup": "home",
    "clear_on_exit": False,
    # password vault (shield_vault.py)
    "vault_autolock": 15,
    "vault_offer_save": True,
    "vault_autofill": True,
    # updates
    "check_updates": True,
    # hardened mode: JavaScript runs without the JIT compiler (needs a restart). Slower pages, far fewer exploitable bugs.
    "hardened_mode": False,
}
CHOICES = {
    "theme": {"dark", "light", "system"},
    "search_engine": set(SEARCH_ENGINES),
    "permissions": {"deny", "ask"},
    "risky_downloads": {"ask", "block"},
    "history_days": {0, 7, 30, 90},
    "fingerprint_level": {"standard", "strict"},
    "startup": {"home", "restore"},
    "vault_autolock": {0, 5, 15, 60},
}
RULES = {"nojs", "http", "noblock"}


class Settings(dict):
    def __init__(self):
        super().__init__(copy.deepcopy(DEFAULTS))     # a copy, so nested dicts and lists aren't shared with DEFAULTS
        self.path = HOME / "settings.json"
        try:
            data = json.loads(self.path.read_text(encoding="utf-8"))
            for k, v in data.items():
                if k in DEFAULTS and type(v) is type(DEFAULTS[k]):
                    self[k] = v
        except Exception:
            pass

    def save(self):
        try:
            self.path.write_text(json.dumps(self, indent=2), encoding="utf-8")
        except OSError:
            pass

    def set(self, key, raw):
        if key not in DEFAULTS or key in ("site_rules", "custom_blocklist", "filter_lists"):
            return False
        default = DEFAULTS[key]
        try:
            if isinstance(default, bool):
                val = str(raw).lower() in ("1", "true", "on")
            elif isinstance(default, int):
                val = int(raw)
            else:
                val = str(raw).strip()
        except ValueError:
            return False
        if key in CHOICES and val not in CHOICES[key]:
            return False
        if key == "homepage" and not re.match(r"^(https?://|shield://)[^\s]+$", val):
            return False
        self[key] = val
        self.save()
        return True

    def add_rule(self, host, rule):
        host = host.strip().lower()
        if rule not in RULES or not re.match(r"^[a-z0-9.-]+$", host):
            return False
        rules = self["site_rules"].setdefault(host, [])
        if rule not in rules:
            rules.append(rule)
        self.save()
        return True

    def del_rule(self, host, rule):
        rules = self["site_rules"].get(host, [])
        if rule in rules:
            rules.remove(rule)
        if not rules:
            self["site_rules"].pop(host, None)
        self.save()

    def set_list(self, list_id, on):
        if list_id not in {c["id"] for c in CATALOG}:
            return False
        self["filter_lists"][list_id] = bool(on)
        self.save()
        return True

    def set_blocklist(self, text):
        doms = []
        for line in text.splitlines():
            d = line.strip().lower().lstrip(".")
            if d and re.match(r"^[a-z0-9.-]+$", d) and d not in doms:
                doms.append(d)
        self["custom_blocklist"] = doms
        self.save()


# --------------------------------------------------------------------------
# Host helpers (site_of and host_in live in shield_filters.py)
# --------------------------------------------------------------------------
def is_local_host(host):
    h = (host or "").lower().strip("[]")
    if not h:
        return False
    if h == "localhost" or h.endswith(".localhost") or h.endswith(".local"):
        return True
    try:
        ip = ipaddress.ip_address(h)
        return ip.is_loopback or not ip.is_global
    except ValueError:
        return False


TRACKERS = {
    "doubleclick.net", "googlesyndication.com", "googleadservices.com",
    "google-analytics.com", "googletagmanager.com", "googletagservices.com",
    "connect.facebook.net", "facebook.net", "scorecardresearch.com", "adnxs.com",
    "taboola.com", "outbrain.com", "criteo.com", "criteo.net", "hotjar.com",
    "quantserve.com", "amazon-adsystem.com", "adsrvr.org", "rubiconproject.com",
    "pubmatic.com", "openx.net", "casalemedia.com", "moatads.com", "krxd.net",
    "bluekai.com", "demdex.net", "everesttech.net", "mathtag.com", "segment.io",
    "mixpanel.com", "fullstory.com", "mouseflow.com", "clarity.ms", "ads-twitter.com",
    "analytics.tiktok.com", "ads.linkedin.com", "snap.licdn.com", "bat.bing.com",
}


def load_blocklists(into):
    """Load every *.txt in ~/.shieldbrowser/blocklists (hosts-file or one domain per line)."""
    d = HOME / "blocklists"
    d.mkdir(exist_ok=True)
    for f in sorted(d.glob("*.txt")):
        try:
            for line in f.read_text(encoding="utf-8", errors="ignore").splitlines():
                parts = line.split("#")[0].strip().lower().split()
                if not parts:
                    continue
                dom = (parts[1] if len(parts) > 1 else parts[0]).lstrip("|").rstrip("^")
                if "/" in dom or "*" in dom or dom in ("localhost", "0.0.0.0") or ":" in dom:
                    continue
                into.add(dom)
        except OSError:
            pass


# --------------------------------------------------------------------------
# Event log (in memory only, wiped on exit)
# --------------------------------------------------------------------------
BLOCK_KINDS = {"tracker", "cookie", "local_net", "harmful"}


class Events:
    def __init__(self):
        self.lock = threading.Lock()
        self.log = deque(maxlen=400)
        self.counts = Counter()
        self.domains = Counter()
        self.by_site = Counter()

    def add(self, kind, detail, site=None, log=True):
        with self.lock:
            self.counts[kind] += 1
            if site and kind in BLOCK_KINDS:
                self.by_site[site] += 1
            if kind in ("tracker", "cookie"):
                self.domains[detail] += 1
            if log:
                self.log.append({"t": time.strftime("%H:%M:%S"), "kind": kind, "detail": detail})

    def site_count(self, site):
        with self.lock:
            return self.by_site.get(site, 0)

    def snapshot(self):
        with self.lock:
            return {
                "counts": dict(self.counts),
                "domains": self.domains.most_common(12),
                "log": list(self.log)[::-1][:120],
            }


# --------------------------------------------------------------------------
# Navigation guard + session state shared with the request interceptor
# --------------------------------------------------------------------------
TOP_SITES = [
    "google.com", "youtube.com", "facebook.com", "amazon.com", "apple.com", "microsoft.com",
    "paypal.com", "netflix.com", "instagram.com", "linkedin.com", "github.com", "wikipedia.org",
    "reddit.com", "whatsapp.com", "dropbox.com", "icloud.com", "outlook.com", "office.com",
    "chase.com", "bankofamerica.com", "wellsfargo.com", "coinbase.com", "binance.com",
    "steampowered.com", "discord.com", "spotify.com", "ebay.com", "yahoo.com", "adobe.com",
    "twitter.com", "roblox.com", "protonmail.com", "gmail.com", "walmart.com",
]


def levenshtein(a, b):
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]


def lookalike_of(site):
    if site in TOP_SITES:
        return None
    for d in TOP_SITES:
        if len(d.split(".")[0]) >= 6 and abs(len(d) - len(site)) <= 1 and levenshtein(site, d) == 1:
            return d
    return None


class Protection:
    """The live blocking engine and threat feeds. Swapped in whole when lists are (re)built, so the request
    thread never sees a half-built engine."""

    def __init__(self):
        self.engine = None      # shield_filters.FilterEngine
        self.threats = None     # shield_filters.ThreatDB
        self.version = 0

    def set(self, engine, threats):
        self.engine, self.threats = engine, threats
        self.version += 1


def _encoded(url):
    return bytes(url.toEncoded()).decode("ascii", "ignore").lower()


class Guard:
    def __init__(self, settings, events, prot=None):
        self.s = settings
        self.ev = events
        self.prot = prot or Protection()
        self.allowed = set()   # (kind, site) the user chose to continue to this session
        self.http_ok = set()   # hosts allowed over plain HTTP this session
        self.upgrades = {}     # host -> time we last upgraded it to HTTPS
        self.main_blocks = {}  # blocked top-level address -> (kind, detail, time): set on the network thread, read by the page

    def rules_for(self, host):
        parts = (host or "").lower().split(".")
        out = set()
        for i in range(len(parts)):
            out.update(self.s["site_rules"].get(".".join(parts[i:]), []))
        return out

    def http_allowed(self, host):
        return host_in(host, self.http_ok) or "http" in self.rules_for(host)

    def harmful(self, host, url):
        """(kind, list name) when this page is on a live phishing/malware feed or on the scam list, else None."""
        p = self.prot
        if p.threats is not None and len(p.threats):
            hit = p.threats.lookup(url)
            if hit:
                return hit
        eng = p.engine
        if eng is not None and eng.harmful_hit(url.lower(), host):
            return ("scam", "Scam and malware sites")
        return None

    def note_main_block(self, url, verdict):
        """Remember that a top-level request (often a redirect hop) was stopped, so the page can show the warning."""
        now = time.time()
        if len(self.main_blocks) > 64:
            for k in [k for k, v in list(self.main_blocks.items()) if now - v[2] > 30]:
                self.main_blocks.pop(k, None)
        self.main_blocks[url] = (verdict[0], verdict[1], now)

    def take_main_block(self, urls, hosts=()):
        """The (kind, detail, blocked address) for a navigation that just failed because the interceptor stopped it.
        urls: addresses the page believes it was loading. hosts: their host names (the stopped address is often the
        last hop of a redirect chain, which the page may not know by its exact text)."""
        now = time.time()
        for u in urls:
            hit = self.main_blocks.get(u)
            if hit and now - hit[2] < 30:
                self.main_blocks.pop(u, None)
                return hit[0], hit[1], u
        recent = [(u, h) for u, h in list(self.main_blocks.items()) if now - h[2] < 10]
        wanted = {h.lower() for h in hosts if h}
        pick = [(u, h) for u, h in recent if (urlparse(u).hostname or "").lower() in wanted]
        if not pick and len(recent) == 1:       # only one candidate: no way to confuse it with another tab
            pick = recent
        if pick:
            u, h = pick[0]
            self.main_blocks.pop(u, None)
            return h[0], h[1], u
        return None

    def verdict(self, host, url=""):
        """Return (kind, detail) if a top-level navigation to host deserves a warning."""
        if not host or is_local_host(host):
            return None
        site = site_of(host)
        if self.s["block_harmful"] and url and "noblock" not in self.rules_for(host):
            hit = self.harmful(host, url)
            if hit and (hit[0], site) not in self.allowed:
                return hit
        if not self.s["navigation_guard"]:
            return None
        if any(lbl.startswith("xn--") for lbl in host.split(".")) and ("idn", site) not in self.allowed:
            try:
                shown = host.encode("ascii").decode("idna")
            except Exception:
                shown = host
            return ("idn", shown)
        if host_in(host, set(self.s["custom_blocklist"])) and ("blocked", site) not in self.allowed:
            return ("blocked", host)
        d = lookalike_of(site)
        if d and ("lookalike", site) not in self.allowed:
            return ("lookalike", d)
        return None


# --------------------------------------------------------------------------
# Request interceptor (runs on Chromium's IO thread: keep it fast, no UI calls)
# --------------------------------------------------------------------------
RT = QWebEngineUrlRequestInfo.ResourceType


_RT_NAMES = {"ResourceTypeSubFrame": T_SUBDOC, "ResourceTypeStylesheet": T_STYLE, "ResourceTypeScript": T_SCRIPT,
             "ResourceTypeImage": T_IMAGE, "ResourceTypeFontResource": T_FONT, "ResourceTypeMedia": T_MEDIA,
             "ResourceTypeObject": T_OBJECT, "ResourceTypePluginResource": T_OBJECT, "ResourceTypeXhr": T_XHR,
             "ResourceTypePing": T_PING, "ResourceTypeCspReport": T_PING, "ResourceTypeFavicon": T_IMAGE}
_RT_MAP = {getattr(RT, k): v for k, v in _RT_NAMES.items() if hasattr(RT, k)}


class Shield(QWebEngineUrlRequestInterceptor):
    def __init__(self, settings, events, guard, parent=None):
        super().__init__(parent)
        self.s, self.ev, self.g = settings, events, guard
        self.prot = guard.prot

    def interceptRequest(self, info):
        try:
            self._go(info)
        except Exception:
            self.ev.add("error", "request check failed", log=False)

    def _go(self, info):
        s = self.s
        url = info.requestUrl()
        scheme = url.scheme()
        if scheme not in ("http", "https", "ws", "wss"):
            return
        host = url.host().lower()
        first_url = info.firstPartyUrl()
        first = first_url.host().lower()
        rtype = info.resourceType()
        main = rtype == RT.ResourceTypeMainFrame
        site = site_of(first or host)

        # 1. HTTPS-only: upgrade, unless the user allowed HTTP for this host.
        if scheme in ("http", "ws") and s["https_only"] and not is_local_host(host) \
                and not self.g.http_allowed(host):
            url.setScheme("https" if scheme == "http" else "wss")
            if url.port() in (80, 8080):
                url.setPort(-1)
            self.g.upgrades[host] = time.time()
            self.ev.add("https_upgrade", host, site, log=False)
            info.redirect(url)
            return

        # 2. Local-network shield: public sites may not probe localhost / LAN.
        if s["block_local_network"] and not main and first and is_local_host(host) \
                and first_url.scheme() != "shield" and not is_local_host(first):
            info.block(True)
            self.ev.add("local_net", f"{first} tried to reach {host}", site)
            return

        # 2b. Every top-level request, including each hop of a redirect chain, gets the same warning check as a typed
        #     address. acceptNavigationRequest only sees the first address, so without this a harmless-looking link
        #     could redirect into a phishing page unchecked. The page shows the warning once the load fails.
        if main and scheme in ("http", "https"):
            try:
                enc_main = _encoded(url)
                v = self.g.verdict(host, enc_main)
            except Exception:
                v = None
                self.ev.add("error", "navigation check failed", log=False)
            if v:
                self.g.note_main_block(url.toString(), v)
                info.block(True)
                self.ev.add("navigation", f"stopped a redirect into {v[0]} site {host}")
                if v[0] in ("phishing", "malware", "scam"):
                    self.ev.add("harmful", host, site_of(host), log=False)
                return

        # 3. Ads, trackers and known-bad hosts (never on a site the user turned blocking off for).
        if not main and first and ("noblock" not in self.g.rules_for(first)):
            third = site_of(host) != site
            if s["block_trackers"] and third and host_in(host, TRACKERS):
                info.block(True)
                self.ev.add("tracker", host, site_of(first), log=False)
                return
            eng, threats = self.prot.engine, self.prot.threats
            enc = None
            if s["block_trackers"] and eng is not None:
                enc = _encoded(url)
                rt = T_WS if scheme in ("ws", "wss") else _RT_MAP.get(rtype, T_OTHER)
                verdict, _name = eng.decide(enc, host, first, rt, third)
                if verdict == "block":
                    info.block(True)
                    self.ev.add("tracker", host, site_of(first), log=False)
                    return
            if s["block_harmful"] and threats is not None and len(threats):
                if threats.lookup(enc or _encoded(url)):
                    info.block(True)
                    self.ev.add("harmful", host, site_of(first))
                    return

        # 4. Privacy signals.
        if s["send_gpc"]:
            info.setHttpHeader(b"Sec-GPC", b"1")
            info.setHttpHeader(b"DNT", b"1")


def make_cookie_filter(settings, events):
    def allow(req):
        try:
            if settings["block_third_party_cookies"] and req.thirdParty:
                events.add("cookie", req.origin.host() or "unknown", site_of(req.firstPartyUrl.host()), log=False)
                return False
        except Exception:
            pass
        return True
    return allow


# --------------------------------------------------------------------------
# Download gate: a quick look before the download, the real scan afterwards (shield_scan.py)
# --------------------------------------------------------------------------
def clean_name(name):
    name = os.path.basename(name or "")
    name = "".join(c for c in name if ord(c) >= 32 and c not in '<>:"/\\|?*')
    name = name.strip(" .")[:150]
    return name or "download"


def unique_path(folder, name):
    folder = Path(folder)
    target = folder / name
    stem, suffix, i = target.stem, target.suffix, 1
    while target.exists():
        target = folder / f"{stem} ({i}){suffix}"
        i += 1
    return target


def assess_download(name, url, mime):
    """
    Pre-download red flags as (level, message); level is 'danger', 'warn' or 'info'.

    Being a program is NOT a red flag. Chrome, Firefox and Steam are all programs. This only reports tricks
    that are visible from the name, the server and the connection; whether the file itself is safe is decided
    after it arrives, by signature checks and scanners (shield_scan.py).
    """
    out = []
    n = name.lower()
    ext = os.path.splitext(n)[1]
    if any(c in name for c in BIDI_CHARS):
        out.append(("danger", "The file name contains hidden direction-control characters, a classic disguise trick."))
    if DOUBLE_EXT.search(n):
        out.append(("danger", "Double extension: this looks like a document but is actually a program."))
    if mime in EXEC_MIMES and ext not in EXEC_EXT:
        out.append(("danger" if ext in BENIGN_LOOKING else "warn",
                    "The server says this is a program, but the file name says otherwise."))
    if ext in RISKY_EXT:
        out.append(("warn", "This type of file is rarely downloaded on purpose and is often used by malware."))
    scheme = url.split(":", 1)[0].lower()
    host = url.split("/")[2].split(":")[0] if url.count("/") >= 2 else ""
    if scheme == "http" and not is_local_host(host):
        out.append(("warn", "Downloaded over an insecure connection, so it could have been altered on the way."))
    elif scheme in ("data", "blob"):
        out.append(("info", "This file was generated by the page itself, not served from a remote file."))
    return out


def _one_line(text):
    return "".join(c for c in str(text or "") if c.isprintable() and c not in "\r\n")[:2000]


def mark_of_the_web(path, url=""):
    """Tag a file as downloaded from the internet (Windows alternate data stream). Windows itself, SmartScreen and
    Office then treat it with suspicion. Returns True when the tag is in place (or does not apply on this system)."""
    if os.name != "nt":
        return True
    try:
        with open(str(path) + ":Zone.Identifier", "w", encoding="ascii", errors="replace", newline="") as f:
            u = _one_line(url)
            f.write(f"[ZoneTransfer]\r\nZoneId=3\r\nReferrerUrl={u}\r\nHostUrl={u}\r\n")
        return True
    except OSError:
        return False


def lock_down(path, url=""):
    """Make a quarantined file non-executable and tag it as downloaded from the internet."""
    try:
        if os.name == "nt":
            mark_of_the_web(path, url)
        else:
            os.chmod(path, 0o400)
    except OSError:
        pass


# --------------------------------------------------------------------------
# API key for VirusTotal. Kept in its own file (never in settings.json, never sent to internal pages).
# On Windows it is encrypted with DPAPI, so only your Windows account can read it. Elsewhere it is plain
# text readable only by you (file permissions).
# --------------------------------------------------------------------------
_VT_KEY_FILE = HOME / "virustotal.key"
_DPAPI_TAG = "dpapi:"
_DPAPI_ENTROPY = b"shield-browser/virustotal-key"


def _dpapi(data, protect):
    """Windows Data Protection API through ctypes. Returns bytes, or None on any failure or off Windows."""
    if os.name != "nt":
        return None
    try:
        import ctypes
        from ctypes import wintypes

        class Blob(ctypes.Structure):
            _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

        def blob(b):
            buf = ctypes.create_string_buffer(b, len(b))
            return Blob(len(b), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char))), buf

        crypt32, kernel32 = ctypes.windll.crypt32, ctypes.windll.kernel32
        kernel32.LocalFree.argtypes = [ctypes.c_void_p]
        din, keep1 = blob(data)
        ent, keep2 = blob(_DPAPI_ENTROPY)
        out = Blob()
        fn = crypt32.CryptProtectData if protect else crypt32.CryptUnprotectData
        fn.restype = wintypes.BOOL
        ok = fn(ctypes.byref(din), None, ctypes.byref(ent), None, None, 0, ctypes.byref(out))
        if not ok:
            return None
        try:
            return ctypes.string_at(out.pbData, out.cbData)
        finally:
            kernel32.LocalFree(ctypes.cast(out.pbData, ctypes.c_void_p))
    except Exception:
        return None


def _write_vt(key):
    import base64
    enc = _dpapi(key.encode("utf-8"), True)
    _VT_KEY_FILE.write_text(_DPAPI_TAG + base64.b64encode(enc).decode("ascii") if enc else key, encoding="utf-8")
    if os.name != "nt":
        os.chmod(_VT_KEY_FILE, 0o600)


def get_vt_key():
    import base64
    try:
        raw = _VT_KEY_FILE.read_text(encoding="utf-8").strip()
    except OSError:
        return ""
    if raw.startswith(_DPAPI_TAG):
        try:
            dec = _dpapi(base64.b64decode(raw[len(_DPAPI_TAG):]), False)
        except ValueError:
            dec = None
        key = dec.decode("utf-8", "ignore") if dec else ""
        return key if re.fullmatch(r"[A-Za-z0-9]{32,128}", key) else ""
    if re.fullmatch(r"[A-Za-z0-9]{32,128}", raw):
        if os.name == "nt":                      # an older install left it as plain text: protect it now
            try:
                _write_vt(raw)
            except OSError:
                pass
        return raw
    return ""


def set_vt_key(key):
    key = (key or "").strip()
    if key == "":
        try:
            _VT_KEY_FILE.unlink()
        except OSError:
            pass
        return True
    if not re.fullmatch(r"[A-Za-z0-9]{32,128}", key):
        return False
    try:
        _write_vt(key)
        return True
    except OSError:
        return False


# --------------------------------------------------------------------------
# Local storage (bookmarks, history, download records)
# --------------------------------------------------------------------------
class Store:
    def __init__(self):
        self.db = sqlite3.connect(HOME / "shield.db")
        self.db.row_factory = sqlite3.Row
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS bookmarks(url TEXT PRIMARY KEY, title TEXT, added REAL);
            CREATE TABLE IF NOT EXISTS history(id INTEGER PRIMARY KEY, url TEXT, title TEXT, ts REAL);
            CREATE TABLE IF NOT EXISTS downloads(id INTEGER PRIMARY KEY, name TEXT, url TEXT, sha256 TEXT,
                state TEXT, path TEXT, ts REAL, flags TEXT DEFAULT '[]', size INTEGER DEFAULT 0);
            CREATE TABLE IF NOT EXISTS favicons(host TEXT PRIMARY KEY, png BLOB, ts REAL);
        """)
        # Older databases lack the scan columns; add them in place so nobody loses their history.
        have = {r[1] for r in self.db.execute("PRAGMA table_info(downloads)")}
        for col, ddl in (("scan", "TEXT DEFAULT ''"), ("vt", "TEXT DEFAULT ''"), ("verdict", "TEXT DEFAULT ''"),
                         ("mime", "TEXT DEFAULT ''")):
            if col not in have:
                self.db.execute(f"ALTER TABLE downloads ADD COLUMN {col} {ddl}")
        self.db.commit()
        self._icons = {}

    def q(self, sql, args=()):
        cur = self.db.execute(sql, args)
        self.db.commit()
        return cur

    # bookmarks
    def bookmarks(self, limit=500):
        return [dict(r) for r in self.q("SELECT url,title FROM bookmarks ORDER BY added DESC LIMIT ?", (limit,))]

    def is_bookmarked(self, url):
        return bool(self.q("SELECT 1 FROM bookmarks WHERE url=?", (url,)).fetchone())

    def toggle_bookmark(self, url, title):
        if self.is_bookmarked(url):
            self.q("DELETE FROM bookmarks WHERE url=?", (url,))
            return False
        self.q("INSERT INTO bookmarks VALUES(?,?,?)", (url, title or url, time.time()))
        return True

    def del_bookmark(self, url):
        self.q("DELETE FROM bookmarks WHERE url=?", (url,))

    # history
    def add_history(self, url, title):
        last = self.q("SELECT url FROM history ORDER BY id DESC LIMIT 1").fetchone()
        if last and last["url"] == url:
            return
        self.q("INSERT INTO history(url,title,ts) VALUES(?,?,?)", (url, title or url, time.time()))

    def history(self, search="", limit=300):
        like = f"%{search}%"
        rows = self.q("SELECT id,url,title,ts FROM history WHERE url LIKE ? OR title LIKE ? "
                      "ORDER BY id DESC LIMIT ?", (like, like, limit))
        return [dict(r) for r in rows]

    def del_history(self, hid):
        self.q("DELETE FROM history WHERE id=?", (hid,))

    def clear_history(self):
        self.q("DELETE FROM history")

    def prune_history(self, days):
        cutoff = time.time() - days * 86400 if days else time.time() + 1
        self.q("DELETE FROM history WHERE ts < ?", (cutoff,))

    # downloads
    def new_download(self, name, url, flags, mime=""):
        cur = self.q("INSERT INTO downloads(name,url,state,ts,flags,mime) VALUES(?,?,?,?,?,?)",
                     (name, url, "downloading", time.time(), json.dumps(flags), mime))
        return cur.lastrowid

    def update_download(self, did, **kw):
        cols = ", ".join(f"{k}=?" for k in kw)
        self.q(f"UPDATE downloads SET {cols} WHERE id=?", (*kw.values(), did))

    def download(self, did):
        r = self.q("SELECT * FROM downloads WHERE id=?", (did,)).fetchone()
        return dict(r) if r else None

    def downloads(self, limit=100):
        return [dict(r) for r in self.q("SELECT * FROM downloads ORDER BY id DESC LIMIT ?", (limit,))]

    def forget_download(self, did):
        self.q("DELETE FROM downloads WHERE id=? AND state IN ('released','deleted','failed','missing','blocked')", (did,))

    def pending_count(self):
        return self.q("SELECT COUNT(*) FROM downloads WHERE state IN ('quarantined','scanning')").fetchone()[0]

    def clear_downloads(self):
        self.q("DELETE FROM downloads WHERE state IN ('released','deleted','failed','missing','blocked')")

    # favicons (kept so the new tab page, history and bookmarks can show real site icons)
    def save_favicon(self, host, png):
        host = (host or "").lower()
        if not host or not png:
            return
        self.q("INSERT OR REPLACE INTO favicons(host,png,ts) VALUES(?,?,?)", (host, png, time.time()))
        self._icons.pop(host, None)

    def favicon_uri(self, host):
        import base64
        host = (host or "").lower()
        if host in self._icons:
            return self._icons[host]
        r = self.q("SELECT png FROM favicons WHERE host=?", (host,)).fetchone()
        uri = "data:image/png;base64," + base64.b64encode(r[0]).decode() if r and r[0] else None
        self._icons[host] = uri
        return uri

    def clear_favicons(self):
        self.q("DELETE FROM favicons")
        self._icons.clear()
