#!/usr/bin/env python3
"""
Shield V2: a zero-bloat, security-first browser on the Chromium engine.

    pip install -r requirements.txt
    python shield.py
"""
import hashlib
import json
import os
import re
import secrets
import shutil
import sys
import threading
import time
from pathlib import Path
from urllib.parse import quote_plus, urlparse

# --------------------------------------------------------------------------
# Chromium switches. These must be set before Qt starts, and they are the browser's own, not the environment's:
# anything that could weaken the sandbox, site isolation or certificate checks is refused even if some other
# program (or malware that planted an environment variable) asks for it.
# --------------------------------------------------------------------------
STARTUP_WARNINGS = []     # shown in the Security center


def _early_setting(name, default=False):
    """Read one value from settings.json before Qt (and the rest of Shield) is loaded."""
    try:
        home = Path(os.environ.get("SHIELD_HOME") or Path.home() / ".shieldbrowser")
        return json.loads((home / "settings.json").read_text("utf-8")).get(name, default)
    except Exception:
        return default


HARDENED = _early_setting("hardened_mode") is True
# Chromium honours only the LAST copy of a repeated switch, so each of these is one combined switch.
_ENABLE = ["StrictOriginIsolation"]                       # every origin in its own process, not just every site
_DISABLE = ["BrowsingTopics"]                             # no ad-interest profiling API
_FLAGS = [
    "--site-per-process",                                   # every site in its own process
    "--enable-features=" + ",".join(_ENABLE),
    "--disable-features=" + ",".join(_DISABLE),
    "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",  # no WebRTC IP leaks
    "--disable-background-networking", "--disable-sync", "--no-pings",
    "--disable-breakpad", "--disable-domain-reliability", "--no-default-browser-check",
    "--autoplay-policy=document-user-activation-required",  # no video or audio starts by itself
    "--enable-strict-powerful-feature-restrictions",        # camera, location and similar only on secure pages
]
# The private connection (shield_proxy.py). Chromium only reads its proxy at launch, so it is always pointed at a small switch
# inside Shield (127.0.0.1, random port). While the toolbar toggle is off the switch connects straight to the site; when it is on,
# everything goes through the Tor that ships with Shield, with a kill switch so nothing leaks while Tor is still connecting.
PROXY = None
try:
    from shield_proxy import PrivacyProxy
    PROXY = PrivacyProxy()
    _FLAGS.append(f"--proxy-server=socks5://127.0.0.1:{PROXY.start()}")
except Exception as _e:         # without it the browser still works, just without the toggle
    PROXY = None
    STARTUP_WARNINGS.append(f"The private connection is unavailable: {_e}")
if HARDENED:
    _FLAGS.append("--js-flags=--jitless")                  # no JIT: most browser exploits need it (this also turns off WebAssembly)

# Switches that are harmless and sometimes needed to work around graphics or display problems. Nothing else is
# accepted from the environment.
_SAFE_ENV_FLAG = re.compile(r"^--(disable-gpu|disable-gpu-compositing|disable-software-rasterizer|use-angle=[a-z0-9]+|"
                            r"force-device-scale-factor=[0-9.]+|lang=[A-Za-z-]+)$")


def _sanitize_environment():
    for var in ("QTWEBENGINE_REMOTE_DEBUGGING", "QTWEBENGINE_DISABLE_SANDBOX"):
        if os.environ.pop(var, None) is not None:
            STARTUP_WARNINGS.append(f"Ignored the {var} setting from the environment: it would weaken the browser.")
    inherited = os.environ.get("QTWEBENGINE_CHROMIUM_FLAGS", "").split()
    kept = [f for f in inherited if _SAFE_ENV_FLAG.match(f)]
    dropped = [f for f in inherited if f not in kept]
    if dropped:
        STARTUP_WARNINGS.append(f"Ignored {len(dropped)} browser switch(es) from the environment that could weaken security.")
    if os.environ.get("SHIELD_INSECURE_NO_SANDBOX") == "1":      # only for CI containers that run as root
        os.environ["QTWEBENGINE_DISABLE_SANDBOX"] = "1"
        STARTUP_WARNINGS.append("The Chromium sandbox is OFF (SHIELD_INSECURE_NO_SANDBOX). Do not browse like this.")
    os.environ["QTWEBENGINE_CHROMIUM_FLAGS"] = " ".join(_FLAGS + kept).strip()


_sanitize_environment()

from PyQt6.QtCore import (
    QAbstractNativeEventFilter, QBuffer, QByteArray, QEvent, QIODevice, QMimeData, QObject, QPoint, QPointF, QSize, Qt, QTimer,
    QUrl, QUrlQuery, pyqtSignal,
)
from PyQt6.QtGui import QAction, QColor, QCursor, QDesktopServices, QGuiApplication, QIcon, QKeySequence, QPainter, QPalette, QPixmap
from PyQt6.QtNetwork import QLocalServer, QLocalSocket
from PyQt6.QtPrintSupport import QPrintDialog, QPrinter
from PyQt6.QtWebChannel import QWebChannel
from PyQt6.QtWebEngineCore import (
    QWebEngineDownloadRequest, QWebEnginePage, QWebEngineProfile, QWebEngineScript,
    QWebEngineSettings, QWebEngineUrlScheme,
)
from PyQt6.QtWebEngineWidgets import QWebEngineView
from PyQt6.QtWidgets import (
    QApplication, QCompleter, QFileDialog, QMainWindow, QMenu, QVBoxLayout, QHBoxLayout, QWidget,
)

try:
    from PyQt6.QtWebEngineCore import QWebEngineContextMenuRequest
except ImportError:          # older Qt: the page menu then simply offers fewer items
    QWebEngineContextMenuRequest = None
from PyQt6.QtCore import QStringListModel

import shield_fx
import shield_sound
import shield_update
import shield_vault
from shield_autofill import VaultBridge, qwebchannel_js
from shield_core import (
    DOWNLOADS, HOME, QUARANTINE, SEARCH_ENGINES, TRACKERS, VERSION, Events, Guard, Protection, Settings, Shield, Store,
    assess_download, clean_name, get_vt_key, is_local_host, load_blocklists, lock_down, make_cookie_filter,
    mark_of_the_web, site_of, unique_path,
)
from shield_filters import AD_LIST_IDS, ListManager, clean_url
from shield_fx import DropReveal, fx_on
from shield_pages import Ctx, SchemeHandler, _list_line, _summary_line
from shield_scripts import VAULT_JS, YT_JS, fill_call, fp_script, is_youtube_host
from shield_scan import ScanEngine, VirusTotal, VTError, label_for_name, sha256_file
from shield_sound import ScrollFeel, ScrollWatcher, SoundEngine, play as play_sound, sound_folders
from shield_ui import (
    Chrome, FindBar, IconButton, Omnibox, Pill, Sheet, T, TabCard, TabSearch, TabStrip, ViewHost, pix, soften_menu, stylesheet, usable_grab,
)


def register_scheme():
    scheme = QWebEngineUrlScheme(b"shield")
    scheme.setSyntax(QWebEngineUrlScheme.Syntax.Host)
    flags = QWebEngineUrlScheme.Flag.SecureScheme | QWebEngineUrlScheme.Flag.FetchApiAllowed | QWebEngineUrlScheme.Flag.CorsEnabled
    scheme.setFlags(flags)
    QWebEngineUrlScheme.registerScheme(scheme)


FROZEN = bool(getattr(sys, "frozen", False))              # True inside the packaged Shield.exe
CAN_INSTALL = shield_update.can_install()                  # a packaged build in a place it can replace itself (all three systems)
ALLOWED_SCHEMES = {"http", "https", "shield", "about", "blob", "view-source"}
APP_WORLD = QWebEngineScript.ScriptWorldId.ApplicationWorld
APP_WORLD_ID = int(getattr(APP_WORLD, "value", 1))
HARMFUL = ("phishing", "malware", "scam")
PERM_LABELS = {
    "MediaAudioCapture": "your microphone", "MediaVideoCapture": "your camera",
    "MediaAudioVideoCapture": "your camera and microphone", "Geolocation": "your location",
    "DesktopVideoCapture": "your screen", "DesktopAudioVideoCapture": "your screen and audio",
    "ClipboardReadWrite": "your clipboard", "Notifications": "notifications",
}


def sandbox_status():
    """'on' or 'off' for the Chromium sandbox, as far as can be told from outside the engine."""
    if os.environ.get("QTWEBENGINE_DISABLE_SANDBOX") == "1" or "--no-sandbox" in os.environ.get("QTWEBENGINE_CHROMIUM_FLAGS", ""):
        return "off"
    if os.name == "posix" and hasattr(os, "geteuid") and os.geteuid() == 0:
        return "off"
    return "on"


class _SessionLock(QAbstractNativeEventFilter):
    """Windows only: lock the password vault the moment the PC is locked or goes to sleep, not after the idle timer."""
    WM_WTSSESSION_CHANGE, WM_POWERBROADCAST = 0x02B1, 0x0218
    WTS_SESSION_LOCK, PBT_APMSUSPEND = 0x7, 0x4

    def __init__(self, on_lock):
        super().__init__()
        self.on_lock = on_lock

    def nativeEventFilter(self, event_type, message):
        try:
            if bytes(event_type) in (b"windows_generic_MSG", b"windows_dispatcher_MSG"):
                from ctypes import wintypes
                msg = wintypes.MSG.from_address(int(message))
                if (msg.message == self.WM_WTSSESSION_CHANGE and msg.wParam == self.WTS_SESSION_LOCK) \
                        or (msg.message == self.WM_POWERBROADCAST and msg.wParam == self.PBT_APMSUSPEND):
                    self.on_lock()
        except Exception:
            pass
        return False, 0


def watch_session_lock(win):
    """Ask Windows to tell this window when the session is locked; the vault locks when it is. One filter serves every window."""
    if os.name != "nt":
        return None
    try:
        import ctypes
        from ctypes import wintypes
        fn = ctypes.windll.wtsapi32.WTSRegisterSessionNotification
        fn.argtypes = [wintypes.HWND, wintypes.DWORD]
        fn.restype = wintypes.BOOL
        fn(int(win.winId()), 0)             # 0 = this session only
        app = QApplication.instance()
        if getattr(app, "_session_lock", None) is None:
            app._session_lock = _SessionLock(win.core.lock_vault_now)
            app.installNativeEventFilter(app._session_lock)
        return app._session_lock
    except Exception:
        return None


class SafePage(QWebEnginePage):
    def __init__(self, browser, parent):
        super().__init__(browser.profile, parent)
        self.b = browser            # the window showing this page; a tab moved to another window gets a new one
        self._last_popup = 0.0
        self.starts = 0            # navigations begun on this page
        self.login = {}            # what the password-form script last reported
        self.pending = None        # a login that was just submitted and may be worth saving
        self.fullScreenRequested.connect(lambda req: self.b.on_fullscreen(req, self))
        self.certificateError.connect(self._cert_error)
        self.loadFinished.connect(self._after_load)
        self.loadStarted.connect(self._on_start)
        # The engine paints its base colour before a page's first frame. Left alone that is white, which is the flash
        # between pages. Keep it matched to the theme (see sync_bg) and follow theme changes.
        self._busy = False
        self.urlChanged.connect(self.sync_bg)
        self.loadFinished.connect(self._bg_done)
        T.changed.connect(self.sync_bg)
        self.sync_bg()
        self.windowCloseRequested.connect(lambda: self.b.close_page(self))
        self.recentlyAudibleChanged.connect(lambda _a: self.b.on_audio(self))
        self.pdfPrintingFinished.connect(lambda path, ok: self.b.toast("Saved the page as a PDF" if ok else "Couldn't save the PDF"))
        if hasattr(self, "permissionRequested"):
            self.permissionRequested.connect(self._perm_new)
        else:
            self.featurePermissionRequested.connect(self._perm_old)
        # Channel to the password-form script. It exists only in the isolated world, so web pages can't reach it.
        self._channel = QWebChannel(self)
        self._channel.registerObject("shieldVault", VaultBridge(self))
        self.setWebChannel(self._channel, APP_WORLD_ID)

    def _on_start(self):
        self.starts += 1
        self.login = {}
        self._busy = True
        self.sync_bg()

    def _bg_done(self, *_):
        self._busy = False
        self.sync_bg()

    def sync_bg(self, *_):
        """Colour shown under a page until it has painted. Internal and blank pages, and any page that is still loading
        in dark mode, sit on the theme's own background, so a navigation never flashes white. Once a website has
        finished loading it gets plain white, because a site that sets no background of its own expects white behind
        its black text."""
        try:
            dark = self.b.is_dark()
            if self.url().scheme() in ("shield", "about", "") or (dark and self._busy):
                col = QColor("#111113") if dark else QColor("#f5f5f7")      # same as --bg in shield_pages.py
            else:
                col = QColor("#ffffff")
            if self.backgroundColor() != col:
                self.setBackgroundColor(col)
        except Exception:
            pass

    def vault_seen(self, d):
        self.login = {"pw": bool(d.get("pw")), "newpw": bool(d.get("newpw")), "user": bool(d.get("user")), "cross": bool(d.get("cross"))}
        self.b.vault_seen(self)

    def vault_captured(self, d):
        self.b.vault_captured(self, d)

    def set_cosmetic(self, host):
        """Install the page-cleanup script for the site about to load (it runs before the page builds)."""
        sc = self.scripts()
        for name in ("shield-cos", "shield-yt"):
            for old in sc.find(name):
                sc.remove(old)
        b = self.b
        if "noblock" in b.guard.rules_for(host):
            return
        if b.cfg["block_youtube_ads"] and is_youtube_host(host):
            y = QWebEngineScript()
            y.setName("shield-yt")
            y.setSourceCode(YT_JS)
            y.setInjectionPoint(QWebEngineScript.InjectionPoint.DocumentCreation)
            y.setWorldId(QWebEngineScript.ScriptWorldId.MainWorld)     # it has to change what the player sees
            y.setRunsOnSubFrames(False)
            sc.insert(y)
        if not (b.cfg["cosmetic_filtering"] and b.cfg["block_trackers"]):
            return
        eng = b.prot.engine
        js = eng.cosmetic_js(host) if eng is not None else ""
        if not js:
            return
        s = QWebEngineScript()
        s.setName("shield-cos")
        s.setSourceCode(js)
        s.setInjectionPoint(QWebEngineScript.InjectionPoint.DocumentCreation)
        s.setWorldId(APP_WORLD)
        s.setRunsOnSubFrames(False)
        sc.insert(s)

    # --- permissions ------------------------------------------------------
    def _perm_new(self, perm):
        o = perm.origin()
        origin = f"{o.scheme()}://{o.host()}" + (f":{o.port()}" if o.port() > 0 else "")
        self.b.decide_permission(o.host(), perm.permissionType().name, perm.grant, perm.deny, origin)

    def _perm_old(self, origin, feature):
        P = QWebEnginePage.PermissionPolicy
        self.b.decide_permission(
            origin.host(), feature.name,
            lambda: self.setFeaturePermission(origin, feature, P.PermissionGrantedByUser),
            lambda: self.setFeaturePermission(origin, feature, P.PermissionDeniedByUser),
            f"{origin.scheme()}://{origin.host()}" + (f":{origin.port()}" if origin.port() > 0 else ""))

    def _cert_error(self, err):
        self.b.events.add("tls", f"rejected certificate for {err.url().host()}: {err.description()}")
        err.rejectCertificate()

    # --- navigation guard -------------------------------------------------
    def acceptNavigationRequest(self, url, nav_type, is_main_frame):
        if not is_main_frame:
            return True
        N = QWebEnginePage.NavigationType
        scheme = url.scheme()
        if scheme not in ALLOWED_SCHEMES and not (scheme == "data" and nav_type == N.NavigationTypeTyped):
            self.b.events.add("navigation", f"blocked {scheme}: navigation")
            return False
        if scheme == "shield":
            # Web pages may never navigate to internal pages; only the user (typed), a shield:// page, or the tab's own
            # back/forward/reload. A fresh popup has an empty address, which must NOT count as trusted: a website
            # could open a popup and point it at shield://.
            ok = nav_type in (N.NavigationTypeTyped, N.NavigationTypeBackForward, N.NavigationTypeReload) \
                or self.url().scheme() == "shield"
            if not ok:
                self.b.events.add("navigation", "blocked a website from opening a shield:// page")
            elif nav_type == N.NavigationTypeLinkClicked and self.url().scheme() == "shield":
                # moving between internal pages: tell the next page to settle in quietly instead of replaying its intro
                try:
                    self.b.ctx.soft_to = (url.host(), time.monotonic())
                except Exception:
                    pass
            return ok
        if scheme in ("http", "https"):
            host = url.host().lower()
            enc = bytes(url.toEncoded()).decode("ascii", "ignore")
            if self.b.cfg["clean_links"] and nav_type == N.NavigationTypeLinkClicked:
                cleaned = clean_url(enc)
                if cleaned and cleaned != enc:
                    self.b.events.add("link", f"cleaned a link to {host}", log=False)
                    QTimer.singleShot(0, lambda u=cleaned: self.setUrl(QUrl(u)))
                    return False
            v = self.b.guard.verdict(host, enc)
            if v:
                self.b.events.add("navigation", f"warned about {v[0]} site {host}")
                if v[0] in HARMFUL:
                    self.b.events.add("harmful", host, site_of(host), log=False)
                self.show_warning(v[0], url, v[1])
                return False
            js_ok = "nojs" not in self.b.guard.rules_for(host)
            self.settings().setAttribute(QWebEngineSettings.WebAttribute.JavascriptEnabled, js_ok)
            self.set_cosmetic(host)
        return True

    def show_warning(self, kind, url, detail=""):
        u = QUrl("shield://warning/")
        q = QUrlQuery()
        q.addQueryItem("kind", kind)
        q.addQueryItem("url", url.toString())
        q.addQueryItem("d", detail)
        u.setQuery(q)
        QTimer.singleShot(0, lambda: self.setUrl(u))

    def _after_load(self, ok):
        if ok:
            return
        hit = self.b.guard.take_main_block([self.url().toString(), self.requestedUrl().toString()],
                                           [self.url().host(), self.requestedUrl().host()])
        if hit:                       # a redirect led somewhere flagged: same warning page as a typed address
            kind, detail, addr = hit
            self.show_warning(kind, QUrl(addr), detail)
            return
        req = self.requestedUrl()
        host = req.host().lower()
        g = self.b.guard
        if req.scheme() in ("http", "https") and time.time() - g.upgrades.get(host, 0) < 30 \
                and self.b.cfg["https_only"] and not g.http_allowed(host):
            http = QUrl(req)
            http.setScheme("http")
            self.show_warning("nohttps", http)

    def createWindow(self, _type):
        now = time.time()
        if now - self._last_popup < 1.5:
            self.b.events.add("popup", "limited a rapid popup")
            return None
        self._last_popup = now
        return self.b.new_tab(None).page()


class Tab(QWebEngineView):
    def __init__(self, browser):
        super().__init__()
        self.setPage(SafePage(browser, self))
        self.loading = False
        feel = getattr(browser.core, "scroll_feel", None)
        if feel is not None:
            ScrollWatcher(self, feel)         # lets the scroll sound follow how far the page really moves

    def contextMenuEvent(self, e):
        try:
            self.page().b.page_menu(self, e.globalPos())
        except RuntimeError:
            pass



def ext_kind(name):
    """Best guess at what a file is from its name alone (used until the real scan has looked at it)."""
    label = label_for_name(name)
    return {"Windows program": "program", "Windows library": "program", "Linux program": "program", "Script": "script",
            "Archive": "archive", "Image": "media", "Audio or video": "media", "Office document": "document",
            "Office file with macros": "macro", "PDF document": "document", "Disk image": "diskimage"}.get(
        label, "installer" if "installer" in label.lower() or "package" in label.lower() else "file")


def _j(text, default=None):
    try:
        return json.loads(text) if text else default
    except ValueError:
        return default


def short(text, n=44):
    return text if len(text) <= n else text[:n // 2 - 1] + "\u2026" + text[-(n // 2 - 1):]


VT_MESSAGES = {
    "auth": "VirusTotal didn't accept your API key. Check it in Settings.",
    "network": "Couldn't reach VirusTotal. Check your connection and try again.",
    "rate": "VirusTotal's free limit was reached. Try again in a minute.",
    "toolarge": "This file is too large for VirusTotal (650 MB limit).",
    "timeout": "VirusTotal is taking too long. Try again in a few minutes.",
}


def instance_name():
    """One local socket name per data folder, so two profiles can run side by side."""
    return "shield-browser-" + hashlib.sha1(str(HOME).encode("utf-8")).hexdigest()[:12]


class Bridge(QObject):
    """Carries results from worker threads back to the UI thread (queued automatically by Qt)."""
    scan_done = pyqtSignal(int, object)
    vt_done = pyqtSignal(int, object)
    say = pyqtSignal(str)            # a message to show as a toast
    show_folder = pyqtSignal(str)    # a folder to open
    quit_now = pyqtSignal()          # close Shield (an update installer has just been started)


class Root(QWidget):
    resized = pyqtSignal()

    def resizeEvent(self, e):
        super().resizeEvent(e)
        self.resized.emit()


class Core(QObject):
    """Everything the windows share: settings, the web engine profile, the password vault, downloads, scanning,
    protection lists and updates. There is exactly one, and it outlives every window."""

    def __init__(self):
        super().__init__()
        self.windows = []          # the open Browser windows, oldest first
        self._last = None          # the window that was active most recently
        self._quitting = False
        self._down = False
        self.cfg = Settings()
        self.sounds = SoundEngine(sound_folders(Path(__file__).resolve().parent))     # the sounds packed into the app; silent if there are none
        shield_sound.install(self.sounds)
        self.scroll_feel = ScrollFeel(self.sounds)
        self._apply_feel()
        self.events = Events()
        self.store = Store()
        self.prot = Protection()
        self.guard = Guard(self.cfg, self.events, self.prot)
        self.ctx = Ctx(self.cfg, self.events, self.store, self.guard)
        self.ctx.app = self
        load_blocklists(TRACKERS)
        self.store.prune_history(self.cfg["history_days"])
        self.secret = secrets.token_hex(16)       # seeds this session's per-site fingerprint noise
        self.active_dl = {}
        self.session_perms = {}
        self.closed_tabs = []
        self._session_sig = ""
        self._tick_n = 0
        # protection lists, password vault, updates
        self.lists = ListManager(HOME, VERSION, self.cfg["filter_lists"])
        self.list_job = {"busy": False, "msg": "", "err": ""}
        self._lists_lock = threading.Lock()
        self.vault = shield_vault.Vault(HOME / "vault.shv", self.cfg["vault_autolock"])
        self._qwc_js = qwebchannel_js()
        self._upd = self._load_update_state()
        # scanning
        self.scanner = ScanEngine(HOME)
        self.bridge = Bridge()
        self.bridge.scan_done.connect(self._on_scan_done)
        self.bridge.vt_done.connect(self._on_vt_done)
        self.bridge.say.connect(self.toast)
        self.bridge.show_folder.connect(lambda p: QDesktopServices.openUrl(QUrl.fromLocalFile(p)))
        self.bridge.quit_now.connect(self.quit_all)
        self.scan_live, self.vt_live, self.vt_cancel_ev, self.eng_jobs = {}, {}, {}, {}
        self._eng_cache, self._eng_ts = None, 0.0
        self.apply_theme()
        self._build_profile()
        self.timer = QTimer(self)
        self.timer.timeout.connect(self._tick)
        self.timer.start(700)
        threading.Thread(target=self._refresh_engines, daemon=True).start()
        threading.Thread(target=self._lists_startup, daemon=True).start()
        threading.Thread(target=self._update_startup, daemon=True).start()
        self._lists_timer = QTimer(self)
        self._lists_timer.timeout.connect(self._lists_maybe_update)
        self._lists_timer.start(30 * 60 * 1000)
        QTimer.singleShot(0, self._recover_downloads)
        self._start_server()
        self.notes = list(STARTUP_WARNINGS) + (["The Chromium sandbox is off."] if sandbox_status() == "off" and not STARTUP_WARNINGS else [])
        try:
            QGuiApplication.styleHints().colorSchemeChanged.connect(lambda *_: self.cfg["theme"] == "system" and self.apply_theme())
        except Exception:
            pass

    # ------------------------------------------------------------------ windows
    def active(self):
        """The window the person is using (or last used)."""
        w = QApplication.activeWindow()
        if w is not None and any(w is x for x in self.windows):
            return w
        if self._last is not None and any(self._last is x for x in self.windows):
            return self._last
        return self.windows[-1] if self.windows else None

    def _each(self, fn):
        for w in list(self.windows):
            try:
                fn(w)
            except RuntimeError:
                pass

    def toast(self, text):
        w = self.active()
        if w is not None:
            w.toast(text)

    def ask(self, on_done, **kw):
        w = self.active()
        if w is not None:
            w.ask(on_done, **kw)

    def _vault_ui(self):
        self._each(lambda w: w._vault_ui())

    def focus_active(self):
        w = self.active()
        if w is not None and w.cur() is not None:
            w.cur().setFocus()

    @staticmethod
    def _fit(w):
        """Nudge a window back onto a screen if it would hang off the edge."""
        g = w.frameGeometry()
        scr = QGuiApplication.screenAt(g.center()) or QGuiApplication.primaryScreen()
        if scr is None:
            return
        a = scr.availableGeometry()
        x = min(max(g.x(), a.left()), max(a.left(), a.right() - g.width() + 1))
        y = min(max(g.y(), a.top()), max(a.top(), a.bottom() - g.height() + 1))
        if (x, y) != (g.x(), g.y()):
            w.move(x, y)

    def new_window(self, urls=(), restore=None, empty=False, at=None, size=None):
        """Open another browser window. `at` is where its frame goes; otherwise it cascades from the active window."""
        src = self.active()
        w = Browser(self, urls=urls, restore=restore, empty=empty)
        self.windows.append(w)
        roomy = src is not None and not src.isMaximized() and not src.isFullScreen()
        geo = restore.get("geo") if restore else None
        if size is not None:
            w.resize(size)
        elif geo and geo[2] >= 400 and geo[3] >= 300:
            w.setGeometry(geo[0], geo[1], geo[2], geo[3])
        elif roomy:
            w.resize(src.size())
        if at is not None:
            w.move(at)
        elif geo and geo[2] >= 400 and geo[3] >= 300:
            pass
        elif roomy:
            w.move(src.pos() + QPoint(34, 34))
        if restore and restore.get("max"):
            w.showMaximized()
        else:
            w.show()
        self._fit(w)
        watch_session_lock(w)
        self._last = w
        return w

    def tear_off(self, view, src, gp, grab):
        """A tab was dropped on the desktop: it becomes its own window, with the tab under the pointer where it was held."""
        state = src.release_view(view)
        g, f = src.geometry(), src.frameGeometry()
        frame = QPoint(g.x() - f.x(), g.y() - f.y())                                  # the title bar and border around the page area
        client = QPoint(int(gp.x() - TabStrip.PAD_L - grab.x()), int(gp.y() - 5 - grab.y()))
        size = src.normalGeometry().size() if src.isMaximized() else src.size()
        w = self.new_window(empty=True, size=size, at=client - frame)
        w.adopt_view(view, state)
        self._fit(w)
        w.bring_to_front()
        if src.strip.count() == 0:
            QTimer.singleShot(0, src.close)

    def move_tab(self, view, src, dst, slot=None):
        """Move a tab, page and all, from one window to another."""
        if src is dst:
            return
        state = src.release_view(view)
        dst.adopt_view(view, state, slot)
        dst.bring_to_front()
        if src.strip.count() == 0:
            QTimer.singleShot(0, src.close)

    def open_urls(self, urls):
        w = self.active() or self.new_window()
        for u in urls:
            w.new_tab(QUrl(u))
        w.bring_to_front()

    def start(self, urls=()):
        """Open the first window(s): last session if that is what the person chose, plus any addresses from the command line."""
        saved = self._read_session() if self.cfg["startup"] == "restore" else []
        made = [self.new_window(restore=s) for s in saved]
        if urls:
            if made:
                for u in urls:
                    made[-1].new_tab(QUrl(u))
            else:
                made.append(self.new_window(urls=urls))
        elif not made:
            made.append(self.new_window())
        self._last = made[-1]
        if self.notes:
            QTimer.singleShot(1500, lambda: self.toast(self.notes[0]))

    # ------------------------------------------------------------------ session
    def _read_session(self):
        try:
            data = json.loads((HOME / "session.json").read_text("utf-8"))
        except (OSError, ValueError):
            return []
        wins = data.get("windows") if isinstance(data, dict) else None
        if not isinstance(wins, list):
            wins = [data] if isinstance(data, dict) else []      # the older single-window format
        out = []
        for w in wins[:8]:
            if not isinstance(w, dict):
                continue
            tabs = [t for t in w.get("tabs", []) if isinstance(t, dict) and re.match(r"^https?://", str(t.get("url", "")))][:60]
            if not tabs:
                continue
            try:
                cur = min(max(int(w.get("current", 0)), 0), len(tabs) - 1)
            except (TypeError, ValueError):
                cur = 0
            geo = w.get("geo")
            if not (isinstance(geo, list) and len(geo) == 4 and all(type(x) is int for x in geo)):
                geo = None
            out.append({"tabs": tabs, "current": cur, "geo": geo, "max": bool(w.get("max"))})
        return out

    def save_session(self, force=False):
        if self.cfg["startup"] != "restore":
            return
        wins = [d for d in (w.session_state() for w in self.windows) if d]
        data = json.dumps({"windows": wins})
        if data == self._session_sig and not force:
            return
        self._session_sig = data
        try:
            (HOME / "session.json").write_text(data, encoding="utf-8")
        except OSError:
            pass

    def _tick(self):
        if self.vault.tick():
            self.toast("Vault locked after a while without use")
        self._tick_n += 1
        if self._tick_n % 8 == 0:
            self.save_session()

    # ------------------------------------------------- one Shield, many windows
    def _on_instance(self):
        sock = self.server.nextPendingConnection()
        if sock is None:
            return
        sock.waitForReadyRead(300)
        raw = bytes(sock.readAll())[:65536]
        sock.disconnectFromServer()
        try:
            urls = [u for u in json.loads(raw.decode("utf-8")) if isinstance(u, str) and re.match(r"^https?://\S+$", u)][:20]
        except ValueError:
            urls = []
        if urls:
            self.open_urls(urls)                 # a link from another app: a new tab in the window in use
        else:
            self.new_window().bring_to_front()   # starting Shield again opens another window

    # ------------------------------------------------------------------ closing
    def window_closing(self, win):
        if not any(win is x for x in self.windows):
            return
        if not self._quitting and len(self.windows) == 1:
            self.save_session(force=True)        # the last window still counts: this is what comes back next time
        self.windows = [x for x in self.windows if x is not win]
        if not self._quitting and self.windows:
            self.save_session(force=True)
        if not self.windows:
            self.shutdown()

    def quit_all(self):
        if self._quitting:
            return
        self._quitting = True
        self.save_session(force=True)
        for w in list(self.windows):
            w.close()
        self.shutdown()
        QApplication.quit()

    def on_about_to_quit(self):
        if self.windows and not self._quitting:
            self.save_session(force=True)
        self.shutdown()

    def shutdown(self):
        if self._down:
            return
        self._down = True
        self.timer.stop()
        self.vault.lock()
        if self.cfg["clear_on_exit"] and self.cfg["persistent_sessions"]:
            self.profile.cookieStore().deleteAllCookies()
            self.profile.clearHttpCache()
        for ev in self.vt_cancel_ev.values():
            ev.set()

    # ------------------------------------------------------------------ settings and data
    def _apply_feel(self):
        c = self.cfg
        shield_fx.set_enabled(c["fluid_motion"])
        self.sounds.configure(c["sound_effects"], c["sound_volume"] / 100.0, c["scroll_sound"])

    def _smooth_scroll(self):
        """Animated scrolling in the web engine (off by default in Qt): wheel, keys and trackpad glide instead of jumping."""
        A = QWebEngineSettings.WebAttribute
        if hasattr(A, "ScrollAnimatorEnabled"):
            self.profile.settings().setAttribute(A.ScrollAnimatorEnabled, bool(self.cfg["fluid_motion"]))

    def on_setting(self, key):
        if key in ("fluid_motion", "sound_effects", "sound_volume", "scroll_sound"):
            self._apply_feel()
            self._smooth_scroll()
            if key in ("sound_effects", "sound_volume"):
                self.sounds.play("click")            # a preview, so the new volume can be judged
        elif key == "theme":
            self.apply_theme()
        elif key in ("fingerprint_protection", "fingerprint_level", "vault_autofill", "vault_offer_save"):
            self.rebuild_scripts()
            self._each(lambda w: w.refresh_vault_button())
        elif key == "history_days":
            self.store.prune_history(self.cfg["history_days"])
        elif key == "vault_autolock":
            self.vault.idle_minutes = self.cfg["vault_autolock"]
        elif key == "startup" and self.cfg["startup"] == "home":
            try:
                (HOME / "session.json").unlink()
            except OSError:
                pass
        elif key == "auto_update_lists":
            self._lists_maybe_update()
        elif key == "block_site_ads":
            self.lists_changed()                  # rebuild with or without the ad lists
        elif key == "check_updates" and self.cfg["check_updates"]:
            threading.Thread(target=self._run_update_check, daemon=True).start()

    def clear_data(self, what):
        if what in ("history", "all"):
            self.store.clear_history()
            self.store.clear_favicons()
            self._each(lambda w: w.refresh_completer())
        if what in ("cookies", "all"):
            self.profile.cookieStore().deleteAllCookies()
        if what in ("cache", "all"):
            self.profile.clearHttpCache()
        if what in ("downloads", "all"):
            self.store.clear_downloads()

    def _build_profile(self):
        if self.cfg["clear_on_exit"]:
            for d in ("profile", "cache"):           # wiped before the engine opens them: reliable even after a crash
                shutil.rmtree(HOME / d, ignore_errors=True)
        if self.cfg["persistent_sessions"]:
            p = QWebEngineProfile("shield", self)
            p.setPersistentStoragePath(str(HOME / "profile"))
            p.setCachePath(str(HOME / "cache"))
            p.setPersistentCookiesPolicy(QWebEngineProfile.PersistentCookiesPolicy.AllowPersistentCookies)
        else:
            p = QWebEngineProfile(self)  # off-the-record: nothing is written to disk
        self.profile = p
        self.shield = Shield(self.cfg, self.events, self.guard, self)
        p.setUrlRequestInterceptor(self.shield)
        self.scheme = SchemeHandler(self.ctx, self)
        p.installUrlSchemeHandler(b"shield", self.scheme)
        p.downloadRequested.connect(self.on_download)
        self._cookie_filter = make_cookie_filter(self.cfg, self.events)
        p.cookieStore().setCookieFilter(self._cookie_filter)
        p.setSpellCheckEnabled(False)
        # Grants are remembered only by Shield, for this session. Without this Qt could store a "yes" on disk and
        # stop asking, which would bypass the deny-by-default permission broker.
        if hasattr(p, "setPersistentPermissionsPolicy"):
            try:
                p.setPersistentPermissionsPolicy(QWebEngineProfile.PersistentPermissionsPolicy.AskEveryTime)
            except Exception:
                pass

        A = QWebEngineSettings.WebAttribute
        wanted = {
            "PluginsEnabled": False, "WebRTCPublicInterfacesOnly": True,
            "JavascriptCanAccessClipboard": False, "ScreenCaptureEnabled": False,
            "AllowRunningInsecureContent": False, "LocalContentCanAccessRemoteUrls": False,
            "LocalContentCanAccessFileUrls": False, "AllowGeolocationOnInsecureOrigins": False,
            "HyperlinkAuditingEnabled": False, "DnsPrefetchEnabled": False,
            "AllowWindowActivationFromJavaScript": False, "TouchIconsEnabled": False,
            "FullScreenSupportEnabled": True, "AutoLoadIconsForPage": True,
            "NavigateOnDropEnabled": False,        # dropping a link or file on a page must not navigate it
        }
        for name, val in wanted.items():
            if hasattr(A, name):
                p.settings().setAttribute(getattr(A, name), val)

        self._smooth_scroll()
        self._default_ua = p.httpUserAgent()
        m = re.search(r"Chrome/([\d.]+)", self._default_ua)
        self.ctx.engine = {"chromium": m.group(1) if m else "unknown", "flags": " ".join(_FLAGS),
                           "hardened": HARDENED, "warnings": list(STARTUP_WARNINGS),
                           "sandbox": sandbox_status()}
        self.rebuild_scripts()

    def rebuild_scripts(self):
        sc = self.profile.scripts()
        for name in ("shield-fp", "shield-vault"):
            for old in sc.find(name):
                sc.remove(old)
        fp = self.cfg["fingerprint_protection"]
        if fp:
            s = QWebEngineScript()
            s.setName("shield-fp")
            s.setSourceCode(fp_script(self.secret, self.cfg["fingerprint_level"]))
            s.setInjectionPoint(QWebEngineScript.InjectionPoint.DocumentCreation)
            s.setWorldId(QWebEngineScript.ScriptWorldId.MainWorld)
            s.setRunsOnSubFrames(True)
            sc.insert(s)
        if (self.cfg["vault_autofill"] or self.cfg["vault_offer_save"]) and self._qwc_js:
            v = QWebEngineScript()
            v.setName("shield-vault")
            v.setSourceCode(self._qwc_js + "\n" + VAULT_JS)
            v.setInjectionPoint(QWebEngineScript.InjectionPoint.DocumentReady)
            v.setWorldId(APP_WORLD)
            v.setRunsOnSubFrames(False)
            sc.insert(v)
        # Drop the QtWebEngine token from the UA so we look like ordinary Chromium.
        self.profile.setHttpUserAgent(re.sub(r"\s*QtWebEngine/[\d.]+", "", self._default_ua) if fp else self._default_ua)
        self.profile.setHttpAcceptLanguage("en-US,en;q=0.9" if fp else "")

    def apply_theme(self):
        app = QApplication.instance()
        app.setStyle("Fusion")
        t = self.cfg["theme"]
        try:
            S = Qt.ColorScheme
            app.styleHints().setColorScheme({"dark": S.Dark, "light": S.Light}.get(t, S.Unknown))
        except Exception:
            pass
        dark = self.is_dark()
        shots = []
        if fx_on() and dark != T.dark:           # remember how each window looked, so the new colours can spread over it
            for w in list(self.windows):
                try:
                    if w.isVisible() and not w.isMinimized():
                        shots.append((w, w.root.grab()))
                except RuntimeError:
                    pass
        T.set_dark(dark)
        p = QPalette()
        R = QPalette.ColorRole
        for role, name in [(R.Window, "bar"), (R.WindowText, "text"), (R.Base, "card"), (R.AlternateBase, "field"),
                           (R.Text, "text"), (R.Button, "field"), (R.ButtonText, "text"), (R.Highlight, "acc"),
                           (R.ToolTipBase, "card"), (R.ToolTipText, "text"), (R.PlaceholderText, "faint")]:
            p.setColor(role, T.c(name))
        p.setColor(R.HighlightedText, QColor("#ffffff"))
        app.setPalette(p)
        app.setStyleSheet(stylesheet())
        for w, pm in shots:
            try:
                w.theme_drop(pm)
            except RuntimeError:
                pass
        if shots:
            play_sound("theme")

    def is_dark(self):
        t = self.cfg["theme"]
        if t == "system":
            try:
                return QGuiApplication.styleHints().colorScheme() != Qt.ColorScheme.Light
            except Exception:
                return True
        return t == "dark"

    def resolved_theme(self):
        return "dark" if self.is_dark() else "light"

    def on_download(self, dl):
        name = clean_name(dl.downloadFileName())
        url = dl.url().toString()
        mime = dl.mimeType()
        issues = assess_download(name, url, mime)
        danger = any(lvl == "danger" for lvl, _ in issues)
        if danger and self.cfg["risky_downloads"] == "block":
            dl.cancel()
            self.events.add("download", f"auto-blocked disguised download {name}")
            self.toast(f"Blocked a disguised download: {short(name, 30)}")
            return
        host = dl.url().host() or "this page"
        rows = [(("danger" if lvl == "danger" else "warn" if lvl == "warn" else "info"), msg) for lvl, msg in issues]
        if danger:
            icon, tone, buttons = "shield-alert", "bad", [("Block", "pri", "block"), ("Download to quarantine", "danger-text", "allow")]
        elif issues:
            icon, tone, buttons = "alert", "warn", [("Download to quarantine", "pri", "allow"), ("Cancel", "plain", "block")]
        else:
            icon, tone, buttons = "download", "acc", [("Download", "pri", "allow"), ("Cancel", "plain", "block")]
        body = f"From {short(host, 40)}. " + ("Shield will check who made it and scan it before you can open it."
                                              if not danger else "This one looks like a trick, so blocking it is the safe choice.")

        def done(v):
            if v == "allow":
                self._start_download(dl, name, url, mime, issues)
            else:
                try:
                    dl.cancel()
                except RuntimeError:
                    pass
                self.events.add("download", f"you blocked {name}")
        self.ask(done, icon=icon, tone=tone, title=short(name, 40), body=body, rows=rows, buttons=buttons, cancel="block")

    def _start_download(self, dl, name, url, mime, issues):
        try:
            QUARANTINE.mkdir(parents=True, exist_ok=True)
            target = unique_path(QUARANTINE, name)
            dl.setDownloadDirectory(str(QUARANTINE))
            dl.setDownloadFileName(target.name)
            did = self.store.new_download(target.name, url, [list(i) for i in issues], mime)
            self.active_dl[did] = dl
            dl.stateChanged.connect(lambda st, d=dl, i=did, p=target: self._dl_state(st, i, p, name, url, mime))
            dl.accept()
            self.events.add("download", f"allowed {name} into quarantine")
            self.toast(f"Downloading {short(name, 34)}")
        except RuntimeError:
            pass

    def _dl_state(self, state, did, path, name, url, mime):
        S = QWebEngineDownloadRequest.DownloadState
        if state == S.DownloadCompleted:
            self._each(lambda w: (w.dl_btn.pulse(), w.dl_btn.bounce()))
            play_sound("download")
            self.active_dl.pop(did, None)
            lock_down(path, url)
            self.store.update_download(did, state="scanning", path=str(path))
            self._scan_async(did, path, name, url, mime)
        elif state in (S.DownloadCancelled, S.DownloadInterrupted):
            self.store.update_download(did, state="failed")
            self.active_dl.pop(did, None)

    def download_progress(self, did):
        dl = self.active_dl.get(did)
        try:
            return (dl.receivedBytes(), dl.totalBytes()) if dl else (0, 0)
        except RuntimeError:
            return (0, 0)

    def _recover_downloads(self):
        """If Shield was closed mid-download or mid-scan, don't leave those rows stuck forever."""
        for r in self.store.downloads(200):
            if r["state"] == "downloading":
                self.store.update_download(r["id"], state="failed")
            elif r["state"] == "scanning":
                if r["path"] and Path(r["path"]).exists():
                    self._scan_async(r["id"], Path(r["path"]), r["name"], r["url"], r["mime"] or "")
                else:
                    self.store.update_download(r["id"], state="failed")

    def _scan_async(self, did, path, name, url, mime):
        enabled = {k for k in ("yara", "clamav", "defender") if self.cfg.get(f"scan_{k}", True)}
        self.scan_live[did] = {"stage": "hash", "label": "Fingerprinting the file"}

        def say(stage, label):
            self.scan_live[did] = {"stage": stage, "label": label}

        def work():
            sha = size = None
            try:
                sha, size = sha256_file(path)
                res = self.scanner.scan(str(path), name, url, mime, progress=say, enabled=enabled)
                out = {"sha": sha, "size": size, "scan": res}
            except Exception as e:  # a broken scanner must never leave the file stuck
                out = {"gone": True} if not Path(path).exists() else \
                    {"error": f"{type(e).__name__}: {str(e)[:160]}", "sha": sha, "size": size}   # keep the fingerprint for release
            self.bridge.scan_done.emit(did, out)
        threading.Thread(target=work, daemon=True).start()

    def _on_scan_done(self, did, out):
        self.scan_live.pop(did, None)
        row = self.store.download(did)
        if not row or row["state"] != "scanning":
            return
        if out.get("gone"):
            scan = {"verdict": "malicious", "headline": "Removed by your antivirus",
                    "summary": "Another security program deleted this file as soon as it arrived. That usually means it was malware.",
                    "findings": [], "engines": [], "kind": ext_kind(row["name"]), "version": 1}
            self.store.update_download(did, state="blocked", scan=json.dumps(scan), verdict="malicious")
            self.events.add("download", f"{row['name']} was removed by your antivirus")
            self.toast(f"{short(row['name'], 28)} was removed by your antivirus")
            return
        if "error" in out:
            scan = {"verdict": "unverified", "headline": "Couldn't scan this file", "summary": out["error"],
                    "findings": [], "engines": [], "kind": ext_kind(row["name"]), "version": 1}
            size = Path(row["path"]).stat().st_size if row["path"] and Path(row["path"]).exists() else 0
            self.store.update_download(did, state="quarantined", size=out.get("size") or size, scan=json.dumps(scan),
                                       verdict="unverified", sha256=out.get("sha") or "")
        else:
            scan = out["scan"]
            self.store.update_download(did, state="quarantined", sha256=out["sha"], size=out["size"],
                                       scan=json.dumps(scan), verdict=scan["verdict"])
        self.events.add("download", f"scanned {row['name']}: {scan['verdict']}")
        self.toast(f"{short(row['name'], 28)}: {scan['headline']}")
        if "error" not in out and self.cfg["vt_auto_lookup"] and get_vt_key():
            self.vt_start(did, False)

    def has_vt_key(self):
        return bool(get_vt_key())

    def vt_start(self, did, upload):
        key = get_vt_key()
        if not key:
            return {"ok": False, "err": "nokey"}
        row = self.store.download(did)
        if not row or row["state"] not in ("quarantined", "released") or not row["path"] or not row["sha256"]:
            return {"ok": False, "err": "This file isn't ready to check yet."}
        if did in self.vt_live:
            return {"ok": False, "err": "Already checking this file."}
        path = row["path"]
        if not Path(path).exists():
            return {"ok": False, "err": "The file is no longer where Shield left it."}
        allow = bool(upload) or not self.cfg["vt_confirm_upload"]
        cancel = threading.Event()
        self.vt_cancel_ev[did] = cancel
        self.vt_live[did] = {"stage": "lookup", "label": "Looking the file up on VirusTotal"}
        name, sha = row["name"], row["sha256"]

        def say(stage, label):
            self.vt_live[did] = {"stage": stage, "label": label}

        def work():
            try:
                res = VirusTotal(key).scan(path, name, sha, allow, say, cancel, skip_lookup=bool(upload))
            except VTError as e:
                res = None if e.kind == "cancelled" else {"state": "error", "kind": e.kind, "error": VT_MESSAGES.get(e.kind, str(e))}
            except Exception as e:
                res = {"state": "error", "kind": "error", "error": f"Something went wrong ({type(e).__name__})."}
            self.bridge.vt_done.emit(did, res)
        threading.Thread(target=work, daemon=True).start()
        return {"ok": True}

    def vt_cancel(self, did):
        ev = self.vt_cancel_ev.get(did)
        if ev:
            ev.set()

    def _on_vt_done(self, did, res):
        self.vt_live.pop(did, None)
        self.vt_cancel_ev.pop(did, None)
        if res is None:
            return
        self.store.update_download(did, vt=json.dumps(res))
        row = self.store.download(did)
        name = short(row["name"], 26) if row else "File"
        if res.get("state") == "done":
            bad = res["malicious"] + res["suspicious"]
            self.toast(f"VirusTotal: {bad} of {res['total']} engines flagged {name}" if bad else f"VirusTotal: {name} came back clean")
        elif res.get("state") == "needs_upload":
            self.toast("VirusTotal hasn't seen this file. Open Downloads to scan it.")

    def _refresh_engines(self):
        try:
            self._eng_cache = self.scanner.engines_status()
        except Exception:
            self._eng_cache = []
        self._eng_ts = time.time()

    def engine_state(self):
        if self._eng_cache is None or time.time() - self._eng_ts > 30:
            self._refresh_engines()
        out = []
        for e in self._eng_cache:
            j = self.eng_jobs.get(e["key"], {})
            out.append({**e, "busy": j.get("busy", False), "msg": j.get("msg", ""), "err": j.get("err", "")})
        return out

    def engine_update(self, key):
        eng = {"yara": self.scanner.yara, "clamav": self.scanner.clam}.get(key)
        if not eng:
            return {"ok": False, "err": "Nothing to update"}
        if self.eng_jobs.get(key, {}).get("busy"):
            return {"ok": False, "err": "Already updating"}
        self.eng_jobs[key] = {"busy": True, "msg": "Starting", "err": ""}

        def work():
            err = ""
            try:
                eng.update(progress=lambda m: self.eng_jobs[key].__setitem__("msg", m))
            except Exception as e:
                err = str(e)[:200] or "The update failed"
            self._refresh_engines()
            self.eng_jobs[key] = {"busy": False, "msg": "", "err": err}
        threading.Thread(target=work, daemon=True).start()
        return {"ok": True}

    def _start_server(self):
        self.server = QLocalServer(self)
        name = instance_name()
        QLocalServer.removeServer(name)
        self.server.setSocketOptions(QLocalServer.SocketOption.UserAccessOption)
        if self.server.listen(name):
            self.server.newConnection.connect(self._on_instance)

    def lock_vault_now(self):
        if self.vault.unlocked:
            self.vault.lock()
            self._vault_ui()
            self.toast("Vault locked")

    def copy_secret(self, text):
        """Copy to the clipboard, keep it out of Windows clipboard history, and clear it after 30 seconds."""
        mime = QMimeData()
        mime.setText(text)
        mime.setData("ExcludeClipboardContentFromMonitorProcessing", QByteArray(b"1"))
        mime.setData("CanIncludeInClipboardHistory", QByteArray(b"\x00\x00\x00\x00"))
        mime.setData("CanUploadToCloudClipboard", QByteArray(b"\x00\x00\x00\x00"))
        cb = QApplication.clipboard()
        cb.setMimeData(mime)

        def wipe():
            if cb.text() == text:
                cb.clear()
        QTimer.singleShot(30000, wipe)

    def vault_api(self, action, q):
        v = self.vault
        pw = q.get("pw", "")
        try:
            if action == "status":
                state = "none" if not v.exists() else "unlocked" if v.unlocked else "locked"
                return {"ok": True, "state": state, "rev": v.rev, "wait": v.wait_seconds()}
            if action == "strength":
                return {"ok": True, "score": shield_vault.strength(pw)[0]}
            if action == "generate":
                flag = lambda k: q.get(k, "1") != "0"  # noqa: E731
                n = int(q.get("length", "20") or 20)
                return {"ok": True, "pw": shield_vault.generate(n, flag("lower"), flag("upper"), flag("digits"), flag("symbols"), flag("clear"))}
            if action == "create":
                v.create(pw)
                self._vault_ui()
                return {"ok": True}
            if action == "unlock":
                if v.wait_seconds():
                    return {"ok": False, "err": f"Too many tries. Wait {v.wait_seconds()} seconds."}
                ok = v.unlock(pw)
                self._vault_ui()
                return {"ok": ok, "err": "" if ok else (f"That isn't the master password. Wait {v.wait_seconds()} seconds." if v.wait_seconds() else "That isn't the master password.")}
            if action == "lock":
                v.lock()
                self._vault_ui()
                return {"ok": True}
            if action == "list":
                a = v.audit()
                weak = set(a["weak"])
                reused = {i for g in a["reused"] for i in g}
                ents = []
                for e in v.entries:
                    host = shield_vault.host_of(e["origin"])
                    ents.append({"id": e["id"], "origin": e["origin"], "host": host, "username": e["username"], "title": e["title"],
                                 "weak": e["id"] in weak, "reused": e["id"] in reused, "icon": self.store.favicon_uri(host) or ""})
                return {"ok": True, "entries": ents, "never": sorted(v.never)}
            if action == "audit":
                a = v.audit()
                return {"ok": True, "weak": a["weak"], "old": a["old"], "reused": len(a["reused"]),
                        "reusedIds": [i for g in a["reused"] for i in g]}
            if action == "reveal":
                e = v.get(q.get("id", ""))
                return {"ok": True, "pw": e["password"]} if e else {"ok": False, "err": "That login no longer exists"}
            if action == "copy":
                e = v.get(q.get("id", ""))
                if not e:
                    return {"ok": False, "err": "That login no longer exists"}
                self.copy_secret(e["password"] if q.get("what") == "pass" else e["username"])
                return {"ok": True}
            if action == "copytext":
                self.copy_secret(q.get("text", "")[:256])
                return {"ok": True}
            if action == "save":
                eid = q.get("id", "")
                if eid:
                    url = q.get("url", "")
                    v.update(eid, url=url if url.startswith(("http://", "https://")) else "https://" + url, username=q.get("user", ""), password=pw)
                else:
                    url = q.get("url", "").strip()
                    v.add(url if "://" in url else "https://" + url, q.get("user", ""), pw)
                return {"ok": True}
            if action == "delete":
                v.delete(q.get("id", ""))
                return {"ok": True}
            if action == "never/del":
                v.never_remove(q.get("host", ""))
                return {"ok": True}
            if action == "change":
                if not v.change_master(q.get("old", ""), pw):
                    return {"ok": False, "err": "The current master password isn't right."}
                return {"ok": True}
            if action == "import":
                path, _ = QFileDialog.getOpenFileName(self, "Choose the password file to import", str(DOWNLOADS), "CSV files (*.csv);;All files (*)")
                if not path:
                    return {"ok": False, "cancelled": True}
                if os.path.getsize(path) > 8 * 1024 * 1024:
                    return {"ok": False, "err": "That file is too large to be a password list"}
                added, skipped = v.import_csv(Path(path).read_text("utf-8", "replace"))
                return {"ok": True, "added": added, "skipped": skipped}
            if action == "export":
                if not v.verify_master(pw):
                    return {"ok": False, "err": "That isn't the master password."}
                path, _ = QFileDialog.getSaveFileName(self, "Save your passwords as a CSV file", str(DOWNLOADS / "shield-passwords.csv"), "CSV files (*.csv)")
                if not path:
                    return {"ok": True, "cancelled": True}
                with open(path, "w", encoding="utf-8", newline="") as f:
                    f.write(v.export_csv())
                return {"ok": True}
            if action == "wipe":
                if not v.verify_master(pw):
                    return {"ok": False, "err": "That isn't the master password."}
                v.wipe()
                self._vault_ui()
                return {"ok": True}
        except shield_vault.VaultError as e:
            return {"ok": False, "err": str(e)}
        except (OSError, ValueError) as e:
            return {"ok": False, "err": str(e)[:160] or "That didn't work"}
        return {"ok": False, "err": "unknown"}

    def _build_protection(self):
        engine, threats = self.lists.build(skip_ids=() if self.cfg["block_site_ads"] else AD_LIST_IDS)
        self.prot.set(engine, threats)

    def _lists_startup(self):
        with self._lists_lock:
            try:
                self._build_protection()
            except Exception as e:
                self.list_job["err"] = f"Couldn't read the lists: {str(e)[:120]}"
        self._lists_maybe_update()

    def _lists_maybe_update(self):
        if self.cfg["auto_update_lists"] and not self.list_job["busy"] and self.lists.stale():
            self.lists_update()

    def lists_changed(self):
        """A list was switched on or off: rebuild from what is on disk (new lists download on the next update)."""
        def work():
            with self._lists_lock:
                try:
                    self._build_protection()
                except Exception:
                    pass
        threading.Thread(target=work, daemon=True).start()

    def lists_update(self, force=False):
        if self.list_job["busy"]:
            return {"ok": True}
        self.list_job.update(busy=True, msg="Starting", err="")

        def work():
            with self._lists_lock:
                err = ""
                try:
                    _changed, errors = self.lists.update(progress=lambda m: self.list_job.__setitem__("msg", m))
                    err = errors[0] if errors else ""
                    self.list_job["msg"] = "Applying"
                    self._build_protection()
                except Exception as e:
                    err = str(e)[:160] or "The update failed"
                self.list_job.update(busy=False, msg="", err=err)
        threading.Thread(target=work, daemon=True).start()
        return {"ok": True}

    def protection_summary(self):
        eng, th = self.prot.engine, self.prot.threats
        st = eng.stats() if eng is not None else {"network": 0, "cosmetic": 0}
        return {"network": st["network"], "cosmetic": st["cosmetic"], "threats": len(th) if th is not None else 0,
                "ready": eng is not None}

    def list_status(self):
        rows = []
        for it in self.lists.status():
            rows.append({**it, "line": _list_line(it)})
        summ = _summary_line(self.protection_summary())
        if self.list_job["busy"]:
            summ = self.list_job["msg"] or "Working"
        return {"lists": rows, "summary": summ, "busy": self.list_job["busy"], "err": self.list_job["err"]}

    @staticmethod
    def _engine_versions():
        base = "unknown"
        try:
            from PyQt6 import QtWebEngineCore as wc
            base = wc.qWebEngineChromiumVersion()
        except Exception:
            pass
        try:
            from importlib.metadata import version
            inst = version("PyQt6-WebEngine")
        except Exception:
            inst = "0"
        return base, inst

    @staticmethod
    def _engine_major():
        """Chromium major version of the engine's newest security patches (0 if Qt can't say). The base version
        Qt reports is older than this and would make the engine look less patched than it is."""
        try:
            from PyQt6 import QtWebEngineCore as wc
            fn = getattr(wc, "qWebEngineChromiumSecurityPatchVersion", None) or wc.qWebEngineChromiumVersion
            return int(str(fn()).split(".")[0])
        except Exception:
            return 0

    def _engine_stale(self, state):
        floor, have = int(state.get("min_chromium") or 0), self._engine_major()
        return bool(floor and have and have < floor)

    def _state_path(self):
        return HOME / "update-state.json"

    def _load_update_state(self):
        try:
            d = json.loads(self._state_path().read_text("utf-8"))
            if not isinstance(d, dict):
                return {}
            a = d.get("app")
            if isinstance(a, dict) and a.get("newer") and not shield_update.newer(a.get("version", "0"), VERSION):
                a["newer"] = False          # the update this file remembers is the one now running
            return d
        except (OSError, ValueError):
            return {}

    def _update_startup(self):
        shield_update.cleanup(HOME / "updates")
        a = self._upd.get("app") or {}
        urgent = bool(a.get("critical") and a.get("newer"))     # a security release is waiting: ask at every start
        if self.cfg["check_updates"] and (urgent or shield_update.due(self._state_path())):
            self._run_update_check()

    def _run_update_check(self):
        res = dict(self._upd)
        base, inst = self._engine_versions()
        if not FROZEN:      # a packaged build ships its own engine, so only a Shield update can change it
            try:
                res.update(shield_update.check_engine(inst, VERSION))
                res.pop("engine_err", None)
            except shield_update.UpdateError as e:
                res["engine_err"] = str(e)
        if shield_update.configured():
            try:
                m = shield_update.check_app(VERSION, VERSION)
                res["app"] = m
                res["min_chromium"] = m.get("min_chromium", 0)
                res["ok_ts"] = time.time()               # last time the signed update information was read successfully
                res.pop("app_err", None)
            except shield_update.UpdateError as e:
                res["app_err"] = str(e)
        res["ts"] = time.time()
        self._upd = res
        shield_update.mark(self._state_path(), **{k: v for k, v in res.items() if k != "ts"})
        app = res.get("app") or {}
        if self._engine_stale(res):
            self.bridge.say.emit("This copy of Shield's web engine is out of date. Install the newest Shield now: Settings > Updates.")
        elif app.get("newer") and app.get("critical"):
            self.bridge.say.emit(f"Shield {app['version']} fixes a serious security problem. Please install it now: Settings > Updates.")
        elif res.get("newer"):
            self.bridge.say.emit("A newer web engine is available. See Settings > Updates.")
        elif app.get("newer"):
            self.bridge.say.emit(f"Shield {app['version']} is available. See Settings > Updates.")

    def update_state(self):
        base, inst = self._engine_versions()
        u = self._upd
        line = f"Chromium {base} base, PyQt6-WebEngine {inst}"
        if FROZEN:
            line = f"Chromium {base}. The web engine is part of Shield and is updated with each Shield release."
        elif u.get("engine_err"):
            line += f". {u['engine_err']}."
        elif "newer" in u:
            line += (f". Version {u.get('latest', '?')} is available: run  pip install -U PyQt6 PyQt6-WebEngine  and restart."
                     if u["newer"] else ". Up to date.")
        elif not self.cfg["check_updates"]:
            line += ". Update checks are off."
        if self._engine_stale(u):
            line += f". This web engine is older than the {u['min_chromium']} that Shield now requires. Install the newest Shield."
        out = {"engine": line, "app": "", "app_new": False, "can_install": CAN_INSTALL,
               "engine_stale": self._engine_stale(u)}
        if shield_update.configured():
            a = u.get("app")
            if u.get("app_err"):
                out["app"] = u["app_err"]
            elif a and a.get("no_build"):
                out["app"] = f"Version {a['version']} is out, but there isn't a build for this system yet."
            elif a:
                out["app_new"] = bool(a.get("newer"))
                out["app"] = (f"Version {a['version']} is available. {a['notes']}" if a.get("newer") else f"You have the newest version ({VERSION}).")
                if a.get("newer") and a.get("critical"):
                    out["app"] = "Important security update. " + out["app"]
            ok_ts = u.get("ok_ts")
            if self.cfg["check_updates"] and ok_ts and time.time() - ok_ts > 14 * 86400 and not u.get("app_err"):
                out["app"] = (out["app"] + " ").lstrip() + f"Shield hasn't been able to read update information for {int((time.time() - ok_ts) // 86400)} days."
        return out

    def update_check(self):
        if self.list_job.get("checking"):
            return {"ok": False, "err": "Already checking"}
        self.list_job["checking"] = True
        try:
            self._run_update_check()
        finally:
            self.list_job["checking"] = False
        return {"ok": True, **self.update_state()}

    def update_download(self):
        a = self._upd.get("app")
        if not (a and a.get("newer")):
            return {"ok": False, "err": "There is nothing to download"}
        dest = HOME / "updates"

        def work():
            try:
                path = shield_update.download(a, dest, VERSION)
                if CAN_INSTALL:
                    self.bridge.say.emit("Update downloaded and verified. Installing, Shield will reopen in a moment")
                    shield_update.run_installer(path, a["sha256"])
                    self.bridge.quit_now.emit()
                else:
                    self.bridge.say.emit("The update is saved and checked. Opening its folder")
                    self.bridge.show_folder.emit(str(dest))
            except shield_update.UpdateError as e:
                self.bridge.say.emit(str(e))
        threading.Thread(target=work, daemon=True).start()
        if CAN_INSTALL:
            return {"ok": True, "msg": "Downloading. Shield will restart by itself when it is ready."}
        return {"ok": True, "msg": "Downloading. Shield will tell you when it is saved."}

    def download_list(self):
        out = []
        for r in self.store.downloads(100):
            did = r["id"]
            scan, vt = _j(r["scan"]), _j(r["vt"])
            d = {"id": did, "name": r["name"], "url": (r["url"] or "")[:300], "host": urlparse(r["url"] or "").hostname or "",
                 "size": r["size"] or 0, "ts": r["ts"], "state": r["state"], "sha256": r["sha256"] or "",
                 "flags": _j(r["flags"], []), "verdict": r["verdict"] or "", "scan": scan, "vt": vt,
                 "kind": (scan or {}).get("kind") or ext_kind(r["name"])}
            if r["state"] == "downloading":
                rec, tot = self.download_progress(did)
                d["progress"] = {"received": rec, "total": tot}
            if did in self.scan_live:
                d["live"] = self.scan_live[did]
            if did in self.vt_live:
                d["vtlive"] = self.vt_live[did]
            out.append(d)
        return out

    def release_download(self, did, confirm):
        row = self.store.download(did)
        if not row or row["state"] != "quarantined":
            return False, "Not in quarantine" if not row or row["state"] != "scanning" else "Still scanning"
        # Only a file that was scanned and came back clearly fine leaves quarantine on one click. Anything flagged,
        # unsigned-and-unknown, partly scanned or downloaded over a warning needs an explicit second confirmation.
        flags = _j(row["flags"], [])
        needs_confirm = row["verdict"] not in ("trusted", "clean", "checked") or any(f[0] in ("danger", "warn") for f in flags)
        if needs_confirm and not confirm:
            return False, "confirm"
        expected = (row["sha256"] or "").lower()
        if not expected:
            return False, "This file has no stored fingerprint, so Shield can't prove it is unchanged. Delete it and download it again."
        src = Path(row["path"])
        if not src.exists():
            self.store.update_download(did, state="missing")
            return False, "File is missing"
        DOWNLOADS.mkdir(parents=True, exist_ok=True)
        dst = unique_path(DOWNLOADS, src.name)
        try:
            os.chmod(src, 0o644)
        except OSError:
            pass
        shutil.move(str(src), str(dst))
        # Prove that what now sits in Downloads is exactly the file that was scanned. Hashing the file after the move
        # (not before) leaves no gap in which something could swap it.
        try:
            got = sha256_file(dst)[0].lower()
        except OSError:
            got = ""
        if got != expected:
            try:
                os.chmod(dst, 0o600)
                os.remove(dst)
            except OSError:
                pass
            self.store.update_download(did, state="blocked", verdict="malicious")
            self.events.add("download", f"{dst.name} changed after it was scanned: deleted")
            return False, "This file changed after Shield checked it, so it was deleted. Download it again."
        mark_of_the_web(dst, row["url"])      # keep the 'from the internet' tag, even if the file crossed drives
        self.store.update_download(did, state="released", path=str(dst))
        self.events.add("download", f"released {dst.name}")
        return True, ""

    def delete_download(self, did):
        row = self.store.download(did)
        self.vt_cancel(did)
        if row and row["path"]:
            try:
                os.chmod(row["path"], 0o600)
                os.remove(row["path"])
            except OSError:
                pass
        self.store.update_download(did, state="deleted")

    def forget_download(self, did):
        self.store.forget_download(did)

    def open_download_folder(self, did):
        row = self.store.download(did)
        if row and row["path"]:
            QDesktopServices.openUrl(QUrl.fromLocalFile(str(Path(row["path"]).parent)))


class Browser(QMainWindow):
    """One browser window. What it shares with the other windows lives in Core and is reached through self.core."""

    def __init__(self, core, urls=(), restore=None, empty=False):
        super().__init__()
        self.core = core
        self.setWindowTitle("Shield")
        self.resize(1320, 840)
        self.split_pair = None         # (left, right) while two tabs are shown side by side
        self._devtools = []
        self._printer = None
        self._sheet, self._sheet_q = None, []
        self._tick_n = 0
        self._live = False                      # becomes True once the window is up: tabs restored at start stay quiet
        self._shield_site, self._shield_n = None, 0
        self._build_ui()
        self._open_tabs(urls, restore, empty)
        self.timer = QTimer(self)
        self.timer.timeout.connect(self._tick)
        self.timer.start(700)
        self._live = True
        QApplication.instance().focusChanged.connect(self._focus_moved)

    def __getattr__(self, name):
        # Anything that is not about this window (settings, vault, store, profile ...) is looked up on the shared Core.
        if name == "core" or name.startswith("__"):
            raise AttributeError(name)
        return getattr(self.core, name)

    def _open_tabs(self, urls, restore, empty):
        opened = False
        if restore:
            saved, cur = restore["tabs"], restore["current"]
            for i, t in enumerate(saved):
                v = self.new_tab(QUrl(t["url"]), background=i != cur)
                if t.get("pinned"):
                    self.strip.set_pinned(v, True)
            opened = bool(saved)
        for u in urls:
            self.new_tab(QUrl(u))
            opened = True
        if not opened and not empty:
            self.new_tab(QUrl(self.cfg["homepage"]))

    # ------------------------------------------------------------------ window
    def new_window(self):
        self.core.new_window()

    def bring_to_front(self):
        if self.isMinimized():
            self.showNormal()
        self.raise_()
        self.activateWindow()

    def changeEvent(self, e):
        if e.type() == QEvent.Type.ActivationChange and self.isActiveWindow():
            self.core._last = self
        super().changeEvent(e)

    def refresh_vault_button(self):
        self.vault_btn.setVisible(self.cfg["vault_autofill"] or self.vault.exists())

    def session_state(self):
        views = [v for v in self.strip.views() if v.url().scheme() in ("http", "https")]
        if not views:
            return None
        cur = self.cur()
        idx = [i for i, v in enumerate(views) if v is cur]
        g = self.normalGeometry() if (self.isMaximized() or self.isFullScreen()) else self.geometry()
        return {"tabs": [{"url": v.url().toString(), "pinned": self.strip.is_pinned(v)} for v in views],
                "current": idx[0] if idx else 0, "geo": [g.x(), g.y(), g.width(), g.height()], "max": self.isMaximized()}

    # ------------------------------------------------- tabs that move between windows
    def release_view(self, view):
        """Take a tab out of this window without closing it, so that another window can adopt it."""
        views = self.strip.views()
        i = views.index(view)
        was_current = view is self.cur()
        mate = self.strip.mate_of(view)
        if self.split_pair and any(view is x for x in self.split_pair):
            self._end_split(show=mate)
        state = self.strip.state_of(view)
        self._unwire(view)
        self.strip.remove_tab(view, ghost=False)
        self.stack.removeWidget(view)
        rest = self.strip.views()
        if was_current and rest:
            self._select(mate if mate is not None and any(mate is x for x in rest) else rest[min(i, len(rest) - 1)])
        return state

    def adopt_view(self, view, state, slot=None):
        """Take over a tab (and its live page) from another window."""
        self.stack.addWidget(view)
        view.page().b = self
        self.strip.insert_tab(view, state, slot)
        self._wire(view)
        self._select(view)

    def _tab_dropped(self, view, target_strip, slot):
        dst = target_strip.window()
        if isinstance(dst, Browser) and dst is not self:
            self.core.move_tab(view, self, dst, slot)

    def move_to_new_window(self, view):
        if self.strip.count() < 2:
            return
        o = self.mapToGlobal(QPoint(0, 0))
        self.core.tear_off(view, self, QPoint(o.x() + 34 + TabStrip.PAD_L + 40, o.y() + 34 + 19), QPointF(40, 14))

    # ------------------------------------------------------------------ split view
    def split_clicked(self):
        if self.split_pair:
            self.split_menu()
        else:
            self.enter_split()

    def split_toggle(self):
        if self.split_pair:
            self._end_split()
        else:
            self.enter_split()

    def enter_split(self, other=None):
        """Show the current tab next to another: the one given, or a fresh tab ready for an address."""
        cur = self.cur()
        if cur is None or self.split_pair or (other is not None and other is cur):
            return
        fresh = other is None
        if fresh:
            other = self.new_tab(QUrl(self.cfg["homepage"]), background=True)
        self.strip.set_pair(cur, other)
        self.split_pair = (cur, other)
        self._select(other if fresh else cur)
        self._refresh_split_ui()
        if fresh:
            QTimer.singleShot(0, self.focus_urlbar)

    def _end_split(self, show=None):
        """Put the two tabs back to being separate. Both stay open; `show` (default: the focused one) stays on screen."""
        if not self.split_pair:
            return
        keep = show if show is not None else self.cur()
        self.split_pair = None
        self.strip.clear_pair()
        if keep is not None:
            self.stack.show_single(keep, animate=True)
            self.strip.set_current(keep)
            self._sync()
        self._refresh_split_ui()

    def swap_split(self):
        if not self.split_pair:
            return
        a, b = self.split_pair
        self.split_pair = (b, a)
        self.strip.set_pair(b, a)
        self.stack.swap()

    # ------------------------------------------------------------------ private connection
    def toggle_proxy(self):
        if PROXY is None:
            return
        PROXY.toggle()
        self._proxy_sync()

    def proxy_menu(self, pos):
        if PROXY is None:
            return
        st = PROXY.state()["name"]
        m = soften_menu(QMenu(self))
        a = m.addAction("Turn off" if PROXY.want else "Turn on")
        a.triggered.connect(self.toggle_proxy)
        n = m.addAction("New identity (fresh route)")
        n.setEnabled(st == "on")
        n.triggered.connect(lambda: (PROXY.new_identity(), self.toast("New route: sites you open next can't be linked to the ones before")))
        m.addSeparator()
        boot = m.addAction("On when Shield opens")
        boot.setCheckable(True)
        boot.setChecked(bool(self.cfg["proxy_on_start"]))
        boot.triggered.connect(lambda on: self.cfg.set("proxy_on_start", "1" if on else "0"))
        m.exec(self.proxy_btn.mapToGlobal(pos))

    def _proxy_sync(self):
        """Keep the globe button and its messages in step with the connection. Runs a couple of times a second."""
        if PROXY is None:
            return
        s = PROXY.state()
        name, pct, msg = s["name"], s["pct"], s["message"].strip()
        if msg and msg[-1] not in ".!?":
            msg += "."
        label = PROXY.LABEL.get(s.get("transport", ""), "")
        via = f" via {label}" if label else ""
        self.proxy_btn.set_tone({"on": "acc", "connecting": "warn", "failed": "bad"}.get(name))
        self.proxy_btn.setToolTip({
            "off": "Private connection: off. Click to hide the sites you visit from your network and internet provider.",
            "connecting": f"{msg} {pct}%. Pages wait until it is ready, so nothing goes out unprotected.",
            "on": f"Private connection: on{via}. Your network sees Tor, not the sites you visit. Click to turn off, right-click for more.",
            "failed": f"{msg} Pages stay paused so nothing goes out unprotected. Click to turn it off.",
            "unavailable": msg,
        }[name])
        tr = s.get("transport", "")
        if name == "connecting" and tr not in ("", "direct") and tr != self._proxy_tr:
            self._proxy_tr = tr         # the normal route didn't work, so Shield moved on by itself
            self.toast(f"This network may be blocking Tor. Trying {label}.")
        if name in ("off", "unavailable"):
            self._proxy_tr = ""
        if name != self._proxy_name:
            prev, self._proxy_name = self._proxy_name, name
            note = {"on": f"Private connection on{via}. Your network can no longer see which sites you visit.",
                    "connecting": "Connecting privately. Pages wait until it is ready.",
                    "failed": msg + " Pages are paused. Click the globe to turn it off.",
                    "unavailable": msg}.get(name)
            if name == "off" and prev in ("on", "connecting", "failed"):
                note = "Private connection off. Browsing is direct again."
            if self.isActiveWindow():
                if name == "on":
                    self.proxy_btn.pulse(3)
                    play_sound("connect")
                elif name == "connecting":
                    self.proxy_btn.pulse(1)
                    play_sound("toggle")
                elif name == "failed":
                    self.proxy_btn.shake()
                    play_sound("error")
                elif name == "off" and prev in ("on", "connecting", "failed"):
                    play_sound("toggle")
            if note:
                self.toast(note)

    def _refresh_split_ui(self):
        on = self.split_pair is not None
        self.split_btn.set_tone("acc" if on else None)
        self.split_btn.setToolTip("Split view options" if on else "Split view (Ctrl+\\)")

    def split_menu(self):
        pair = self.split_pair
        if not pair:
            return
        m = soften_menu(QMenu(self))
        m.addAction("Swap sides").triggered.connect(lambda: self.swap_split())
        m.addAction("Reset divider").triggered.connect(lambda: self.stack.set_ratio(0.5, animate=True))
        m.addSeparator()
        m.addAction("Close left pane").triggered.connect(lambda: self.close_view(pair[0]))
        m.addAction("Close right pane").triggered.connect(lambda: self.close_view(pair[1]))
        m.addAction("Move right pane to new window").triggered.connect(lambda: self.move_to_new_window(pair[1]))
        m.addSeparator()
        m.addAction("Exit split view\t" + "Ctrl+\\").triggered.connect(lambda: self._end_split())
        b = self.split_btn
        pos = b.mapToGlobal(b.rect().bottomRight())
        pos.setX(pos.x() - m.sizeHint().width())
        pos.setY(pos.y() + 4)
        m.exec(pos)

    def _focus_moved(self, _old, new):
        try:
            self.stack.note_focus(new)
        except RuntimeError:
            pass

    def _open_in_split(self, url):
        if self.split_pair:
            cur = self.cur()
            left, right = self.split_pair
            (right if cur is left else left).setUrl(url)
        else:
            self.enter_split(self.new_tab(url, background=True))

    # ------------------------------------------------------------------ hover card, tab search
    @staticmethod
    def _host_text(u):
        s = u.scheme()
        if s in ("http", "https"):
            return u.host()
        if s == "shield":
            return "Shield"
        return u.toString()[:80] if s else ""

    def _hover_tab(self, view, rect):
        if view is None or rect is None:
            self.tabcard.dismiss()
            return
        st = self.strip.state_of(view)
        chips = []
        if st.get("audio") == 1:
            chips.append(("Playing audio", "acc"))
        elif st.get("audio") == 2:
            chips.append(("Muted", None))
        if st.get("pinned"):
            chips.append(("Pinned", None))
        if self.split_pair and any(view is x for x in self.split_pair):
            chips.append(("Split view", "acc"))
        if getattr(view, "loading", False):
            chips.append(("Loading", None))
        pt = self.strip.mapTo(self.root, QPoint(int(rect.center().x()), int(rect.bottom())))
        self.tabcard.point_at(st.get("title") or view.title(), self._host_text(view.url()), chips, pt.x(), pt.y() + 6, self.root.width())

    def show_tab_search(self):
        self.tabcard.dismiss()
        cur = self.cur()
        rows = []
        for v in self.strip.views():
            st = self.strip.state_of(v)
            rows.append({"kind": "tab", "view": v, "title": st.get("title") or v.title(), "host": self._host_text(v.url()),
                         "icon": st.get("icon"), "current": v is cur})
        for u in reversed(self.closed_tabs[-8:]):
            rows.append({"kind": "closed", "url": u, "title": (u.host() + u.path()).rstrip("/") or u.toString(), "host": u.host(), "icon": None})
        self.tabsearch.present(rows)

    def _search_chosen(self, row):
        if row["kind"] == "tab":
            if any(row["view"] is x for x in self.strip.views()):
                self._select(row["view"])
        else:
            if row["url"] in self.closed_tabs:
                self.closed_tabs.remove(row["url"])
            self.new_tab(row["url"])

    # ------------------------------------------------------------------ page context menu
    def page_menu(self, view, gpos):
        if view is not self.cur():
            self._select(view)
        req = None
        try:
            req = view.lastContextMenuRequest()
        except Exception:
            pass
        A = QWebEnginePage.WebAction
        link = req.linkUrl() if req else QUrl()
        media = req.mediaUrl() if req else QUrl()
        sel = (req.selectedText() if req else "").strip()
        editable = bool(req and req.isContentEditable())
        is_img = False
        if req and QWebEngineContextMenuRequest is not None and media.isValid():
            is_img = req.mediaType() == QWebEngineContextMenuRequest.MediaType.MediaTypeImage
        web_link = link.isValid() and link.scheme() in ("http", "https")      # a page can't use this menu to reach shield:// pages
        m = soften_menu(QMenu(self))

        def act(label, fn, enabled=True):
            a = m.addAction(label)
            a.setEnabled(enabled)
            a.triggered.connect(lambda _=False: fn())
            return a

        def do(web_action):
            return lambda: view.triggerPageAction(web_action)

        if web_link:
            act("Open link in new tab", lambda: self.new_tab(link))
            act("Open link in new window", lambda: self.core.new_window(urls=[link.toString()]))
            act("Open link in split view", lambda: self._open_in_split(link))
            m.addSeparator()
            act("Copy link address", do(A.CopyLinkToClipboard))
            act("Save link as\u2026", do(A.DownloadLinkToDisk))
            m.addSeparator()
        if is_img:
            if media.scheme() in ("http", "https"):
                act("Open image in new tab", lambda: self.new_tab(media))
            act("Copy image", do(A.CopyImageToClipboard))
            act("Copy image address", do(A.CopyImageUrlToClipboard), media.scheme() in ("http", "https"))
            act("Save image as\u2026", do(A.DownloadImageToDisk))
            m.addSeparator()
        if editable:
            act("Cut", do(A.Cut), bool(sel))
            act("Copy", do(A.Copy), bool(sel))
            act("Paste", do(A.Paste))
            act("Select all", do(A.SelectAll))
            m.addSeparator()
        elif sel:
            act("Copy", do(A.Copy))
            act("Search the web for \u201c" + short(sel.replace("\n", " "), 26) + "\u201d", lambda: self.new_tab(self.to_url(sel[:500])))
            m.addSeparator()
        elif not (web_link or is_img):
            h = view.history()
            act("Back", view.back, h.canGoBack())
            act("Forward", view.forward, h.canGoForward())
            act("Reload", view.reload)
            m.addSeparator()
            act("Select all", do(A.SelectAll))
            act("Save as PDF\u2026", self.save_pdf)
            act("Print\u2026", self.print_page)
            m.addSeparator()
        web_page = view.url().scheme() in ("http", "https")
        act("View page source", self.view_source, web_page)
        act("Inspect", self.open_devtools, web_page)
        m.exec(gpos)

    # ------------------------------------------------------------------ closing
    def closeEvent(self, e):
        self.timer.stop()
        try:
            QApplication.instance().focusChanged.disconnect(self._focus_moved)
        except (TypeError, RuntimeError):
            pass
        self.tabcard.dismiss()
        self.core.window_closing(self)
        for dv in self._devtools:
            try:
                dv.close()
            except RuntimeError:
                pass
        for v in list(self.strip.views()):
            self.stack.removeWidget(v)
            self._dispose(v)
        super().closeEvent(e)

    # ------------------------------------------------------------------ the window's own UI
    def _build_ui(self):
        self.root = Root()
        self.setCentralWidget(self.root)
        col = QVBoxLayout(self.root)
        col.setContentsMargins(0, 0, 0, 0)
        col.setSpacing(0)

        self.chrome = Chrome()
        cv = QVBoxLayout(self.chrome)
        cv.setContentsMargins(0, 0, 0, 0)
        cv.setSpacing(0)
        self.strip = TabStrip()
        self.strip.currentChanged.connect(self._select)
        self.strip.closeRequested.connect(self.close_view)
        self.strip.newRequested.connect(lambda: self.new_tab(QUrl(self.cfg["homepage"])))
        self.strip.contextRequested.connect(self._tab_menu)
        self.strip.audioToggleRequested.connect(self.toggle_mute)
        self.strip.searchRequested.connect(self.show_tab_search)
        self.strip.hoverChanged.connect(self._hover_tab)
        self.strip.pairBroken.connect(lambda _v: self._end_split())
        self.strip.tabDropped.connect(self._tab_dropped)
        self.strip.tabTornOff.connect(lambda v, gp, grab: self.core.tear_off(v, self, gp, grab))
        cv.addWidget(self.strip)

        bar = QWidget()
        bar.setFixedHeight(48)
        bl = QHBoxLayout(bar)
        bl.setContentsMargins(10, 0, 10, 8)
        bl.setSpacing(2)
        self.back_btn = IconButton("back", "Back (Alt+Left)")
        self.fwd_btn = IconButton("forward", "Forward (Alt+Right)")
        self.reload_btn = IconButton("reload", "Reload (F5)")
        self.home_btn = IconButton("home", "Home")
        self.back_btn.clicked.connect(lambda: self.cur().back())
        self.fwd_btn.clicked.connect(lambda: self.cur().forward())
        self.reload_btn.clicked.connect(self.reload_or_stop)
        self.home_btn.clicked.connect(lambda: self.cur().setUrl(QUrl(self.cfg["homepage"])))
        for b in (self.back_btn, self.fwd_btn, self.reload_btn, self.home_btn):
            bl.addWidget(b)
        bl.addSpacing(6)

        self.omni = Omnibox()
        self.urlbar = self.omni.edit
        self.urlbar.returnPressed.connect(self.navigate)
        self.omni.lock.clicked.connect(self.site_menu)
        self.omni.star.clicked.connect(self.toggle_bookmark)
        self.omni.zoom.clicked.connect(lambda: self.zoom(0))
        self.completer_model = QStringListModel(self)
        self.completer = QCompleter(self.completer_model, self)
        self.completer.setCaseSensitivity(Qt.CaseSensitivity.CaseInsensitive)
        self.completer.setFilterMode(Qt.MatchFlag.MatchContains)
        self.completer.activated.connect(lambda t: (self.urlbar.setText(t), self.navigate()))
        self.urlbar.setCompleter(self.completer)
        bl.addWidget(self.omni, 1)
        bl.addSpacing(6)

        self.shield_btn = IconButton("shield-check", "Blocked on this page. Click for the Security center.")
        self.shield_btn.clicked.connect(lambda: self.open_internal("security"))
        self.vault_btn = IconButton("key", "Passwords")
        self.vault_btn.clicked.connect(self.key_menu)
        self.dl_btn = IconButton("download", "Downloads (Ctrl+J)")
        self.dl_btn.clicked.connect(lambda: self.open_internal("downloads"))
        self.menu_btn = IconButton("more", "Menu")
        self.menu_btn.clicked.connect(self.show_menu)
        self.split_btn = IconButton("split", "Split view (Ctrl+\\)")
        self.split_btn.clicked.connect(self.split_clicked)
        self.proxy_btn = IconButton("globe", "Private connection: off")
        self.proxy_btn.clicked.connect(self.toggle_proxy)
        self.proxy_btn.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.proxy_btn.customContextMenuRequested.connect(self.proxy_menu)
        self.proxy_btn.setVisible(PROXY is not None)
        self._proxy_name, self._proxy_tr = "off", ""
        for b in (self.vault_btn, self.shield_btn, self.dl_btn, self.proxy_btn, self.split_btn, self.menu_btn):
            bl.addWidget(b)
        self.vault_btn.setVisible(self.cfg["vault_autofill"] or self.vault.exists())
        cv.addWidget(bar)
        col.addWidget(self.chrome)

        self.stack = ViewHost()
        self.stack.activated.connect(self._select)
        col.addWidget(self.stack, 1)

        self.toast_pill = Pill(self.root, hold_ms=2800)
        self.link_pill = Pill(self.root, hold_ms=0, elide_frac=.62)
        self.link_pill._anchor = "bottom-left"
        self.findbar = FindBar(self.root)
        self.findbar.queryChanged.connect(self._find_query)
        self.findbar.step.connect(self._find_step)
        self.findbar.closed.connect(lambda: self.cur() and self.cur().findText(""))
        self.tabcard = TabCard(self.root)
        self.drop_fx = DropReveal(self.root)      # the drop that turns the whole window dark or light
        self.tabsearch = TabSearch(self.root)
        self.tabsearch.chosen.connect(self._search_chosen)
        self.root.resized.connect(self._place_overlays)

        self._build_menu()
        extra = [
            ("Ctrl+L", self.focus_urlbar), ("F6", self.focus_urlbar),
            ("Ctrl+W", lambda: self.close_view(self.cur())),
            ("F5", lambda: self.cur().reload()), ("Ctrl+R", lambda: self.cur().reload()),
            ("Ctrl+Shift+R", lambda: self.cur().triggerPageAction(QWebEnginePage.WebAction.ReloadAndBypassCache)),
            ("Alt+Left", lambda: self.cur().back()), ("Alt+Right", lambda: self.cur().forward()),
            ("Ctrl+D", self.toggle_bookmark),
            ("Ctrl+Tab", lambda: self.strip.cycle(+1)), ("Ctrl+Shift+Tab", lambda: self.strip.cycle(-1)),
            ("Esc", self.hide_find), ("Ctrl++", lambda: self.zoom(+0.1)),
            ("F12", self.open_devtools),
        ] + [(f"Ctrl+{i}", lambda i=i: self.select_nth(i)) for i in range(1, 10)]
        for key, fn in extra:
            a = QAction(self)
            a.setShortcut(QKeySequence(key))
            a.triggered.connect(fn)
            self.addAction(a)
        self.refresh_completer()

    def _build_menu(self):
        self.menu = soften_menu(QMenu(self))
        entries = [
            ("New tab", "Ctrl+T", lambda: self.new_tab(QUrl(self.cfg["homepage"]))),
            ("New window", "Ctrl+N", self.new_window),
            ("Reopen closed tab", "Ctrl+Shift+T", self.reopen_tab),
            ("Search tabs\u2026", "Ctrl+Shift+A", self.show_tab_search),
            ("Split view", "Ctrl+\\", self.split_toggle),
            None,
            ("Passwords", None, lambda: self.open_internal("passwords")),
            ("Bookmarks", "Ctrl+Shift+O", lambda: self.open_internal("bookmarks")),
            ("History", "Ctrl+H", lambda: self.open_internal("history")),
            ("Downloads", "Ctrl+J", lambda: self.open_internal("downloads")),
            None,
            ("Find in page", "Ctrl+F", self.show_find),
            ("Print\u2026", "Ctrl+P", self.print_page),
            ("Save page as PDF\u2026", None, self.save_pdf),
            ("View page source", "Ctrl+U", self.view_source),
            ("Developer tools", "F12", None),
            ("Zoom in", "Ctrl+=", lambda: self.zoom(+0.1)),
            ("Zoom out", "Ctrl+-", lambda: self.zoom(-0.1)),
            ("Actual size", "Ctrl+0", lambda: self.zoom(0)),
            ("Full screen", "F11", self.toggle_fullscreen),
            None,
            ("Security center", None, lambda: self.open_internal("security")),
            ("Clear browsing data\u2026", "Ctrl+Shift+Del", lambda: self.open_internal("settings#clear")),
            ("Settings", "Ctrl+,", lambda: self.open_internal("settings")),
            None,
            ("Close window", "Ctrl+Shift+W", self.close),
            ("Quit Shield", "Ctrl+Q", self.core.quit_all),
        ]
        for item in entries:
            if item is None:
                self.menu.addSeparator()
                continue
            label, key, fn = item
            a = self.menu.addAction(label + (f"\t{key}" if key else ""))
            if fn is None:                     # shortcut already registered elsewhere (F12)
                a.triggered.connect(self.open_devtools)
                continue
            a.triggered.connect(fn)
            if key:
                sc = QAction(self)
                sc.setShortcut(QKeySequence(key))
                sc.triggered.connect(fn)
                self.addAction(sc)

    def show_menu(self):
        b = self.menu_btn
        pos = b.mapToGlobal(b.rect().bottomRight())
        pos.setX(pos.x() - self.menu.sizeHint().width())
        pos.setY(pos.y() + 4)
        self.menu.exec(pos)

    def _place_overlays(self):
        self.findbar.top = (self.chrome.height() if self.chrome.isVisible() else 0) + 10
        for w in (self.toast_pill, self.link_pill, self.findbar):
            w.reposition()
        if self._sheet:
            self._sheet.setGeometry(self.root.rect())
        if self.tabsearch.isVisible():
            self.tabsearch.setGeometry(self.root.rect())

    def focus_urlbar(self):
        self.omni.focus_edit()

    def toast(self, text):
        self.toast_pill.show_text(text)

    def cur(self):
        return self.stack.currentWidget()

    def new_tab(self, url=None, background=False):
        view = Tab(self)
        self.stack.addWidget(view)
        self.strip.add_tab(view, "New tab")
        self._wire(view)
        if not background:
            self._select(view)
            if self._live:
                play_sound("tab_new")
        if url:
            view.setUrl(url)
        return view

    def _wire(self, view):
        """Connect a page's signals to this window. They are remembered so a tab can be handed to another window."""
        page = view.page()
        links = [
            (view.titleChanged, lambda t, v=view: self._title(v, t)),
            (view.iconChanged, lambda ic, v=view: self._icon(v, ic)),
            (view.urlChanged, lambda u, v=view: self._sync() if v is self.cur() else None),
            (view.loadStarted, lambda v=view: self._loading(v, True)),
            (view.loadProgress, lambda p, v=view: self.chrome.progress.progress(p) if v is self.cur() else None),
            (view.loadFinished, lambda ok, v=view: self._load_done(v, ok)),
            (page.linkHovered, lambda u, v=view: self._hover_link(u) if v is self.cur() else None),
            (page.findTextFinished,
             lambda r, v=view: self.findbar.set_count(r.activeMatch(), r.numberOfMatches()) if v is self.cur() else None),
        ]
        for sig, slot in links:
            sig.connect(slot)
        view._links = links

    def _unwire(self, view):
        for sig, slot in getattr(view, "_links", []):
            try:
                sig.disconnect(slot)
            except (TypeError, RuntimeError):
                pass
        view._links = []

    def _drop_origin(self, view):
        """Where the page falls out of: straight below the tab it belongs to (a tab still growing counts as where it will end up)."""
        t = self.strip._find(view)
        if t is None or not self._live:
            return None
        cx = (t.tx + t.tw / 2.0) if t.w < t.tw * 0.6 else (t.x + t.w / 2.0)
        g = self.strip.mapToGlobal(QPoint(int(round(cx)), 0))
        return QPointF(float(self.stack.mapFromGlobal(g).x()), 0.0)

    def theme_drop(self, pm):
        """Dark and light change as a drop that spreads from the pointer (or the middle of the toolbar if it is elsewhere)."""
        pos = self.root.mapFromGlobal(QCursor.pos())
        if not self.root.rect().contains(pos):
            pos = QPoint(self.root.width() // 2, self.chrome.height() // 2)
        self.drop_fx.play(pm if usable_grab(pm) else None, QPointF(pos), T.c("acc"), T.c("window"), T.dark)

    def _select(self, view):
        if view is None:
            return
        origin = self._drop_origin(view)
        self.strip.set_current(view)
        pair = self.split_pair
        if pair and any(view is x for x in pair):
            self.stack.show_split(pair[0], pair[1], view)
        else:
            self.stack.show_single(view, origin=origin)
        self.chrome.progress.hide()
        self._sync()
        if self.findbar.isVisible():
            self.cur().findText(self.findbar.edit.text())
        view.setFocus()

    def close_view(self, view):
        if view is None:
            return
        if view.url().scheme() in ("http", "https"):
            self.closed_tabs.append(view.url())
        if self.strip.count() <= 1:
            self.close()
            return
        if self._live:
            play_sound("tab_close")
        views = self.strip.views()
        i = views.index(view)
        was_current = view is self.cur()
        mate = self.strip.mate_of(view)
        if self.split_pair and any(view is x for x in self.split_pair):
            self._end_split(show=mate)           # the other half stays, and grows to fill the window
        self.strip.remove_tab(view)
        self.stack.removeWidget(view)
        self._dispose(view)
        if was_current:
            rest = self.strip.views()
            self._select(mate if mate is not None else rest[min(i, len(rest) - 1)])

    def close_page(self, page):
        for v in self.strip.views():
            if v.page() is page:
                self.close_view(v)
                return

    def _tab_menu(self, view, pos):
        m = soften_menu(QMenu(self))
        m.addAction("Reload").triggered.connect(view.reload)
        m.addAction("Duplicate").triggered.connect(lambda: self.new_tab(view.url()))
        pinned = self.strip.is_pinned(view)
        m.addAction("Unpin tab" if pinned else "Pin tab").triggered.connect(lambda: self.strip.set_pinned(view, not pinned))
        if self.strip.audio_of(view) or view.page().isAudioMuted():
            muted = view.page().isAudioMuted()
            m.addAction("Unmute tab" if muted else "Mute tab").triggered.connect(lambda: self.toggle_mute(view))
        m.addSeparator()
        cur, pair = self.cur(), self.split_pair
        if pair and any(view is x for x in pair):
            m.addAction("Exit split view").triggered.connect(lambda: self._end_split())
        elif not pair and view is cur:
            m.addAction("Open in split view").triggered.connect(lambda: self.enter_split())
        elif not pair and cur is not None:
            m.addAction("Show side by side with current tab").triggered.connect(lambda: self.enter_split(view))
        others = [w for w in self.core.windows if w is not self]
        if others:
            sub = soften_menu(QMenu("Move to window", m))
            for w in others:
                label = short((w.windowTitle() or "Shield").replace(" \u2013 Shield", ""), 34) or "Shield"
                sub.addAction(label).triggered.connect(lambda _=False, w=w: self.core.move_tab(view, self, w))
            m.addMenu(sub)
        if self.strip.count() > 1:
            m.addAction("Move to new window").triggered.connect(lambda: self.move_to_new_window(view))
        m.addSeparator()
        m.addAction("Close tab").triggered.connect(lambda: self.close_view(view))
        views = self.strip.views()
        right = [v for v in views[views.index(view) + 1:] if not self.strip.is_pinned(v)]
        ar = m.addAction("Close tabs to the right")
        ar.setEnabled(bool(right))
        ar.triggered.connect(lambda: [self.close_view(v) for v in right])
        other = m.addAction("Close other tabs")
        keep = [v for v in views if v is not view and not self.strip.is_pinned(v)]
        other.setEnabled(bool(keep))
        other.triggered.connect(lambda: [self.close_view(v) for v in keep])
        m.exec(pos)

    def select_nth(self, n):
        views = self.strip.views()
        if views:
            self._select(views[-1] if n >= 9 else views[min(n - 1, len(views) - 1)])

    def on_audio(self, page):
        for v in self.strip.views():
            if v.page() is page:
                self.strip.set_audio(v, 2 if page.isAudioMuted() else 1 if page.recentlyAudible() else 0)
                return

    def toggle_mute(self, view):
        try:
            p = view.page()
            p.setAudioMuted(not p.isAudioMuted())
            self.on_audio(p)
        except RuntimeError:
            pass

    @staticmethod
    def _dispose(view):
        page = view.page()
        view.setPage(None)
        page.deleteLater()
        view.deleteLater()

    def reopen_tab(self):
        if self.closed_tabs:
            self.new_tab(self.closed_tabs.pop())

    def open_internal(self, name):
        self.new_tab(QUrl("shield://" + name))

    def _title(self, view, title):
        self.strip.set_title(view, title)
        if view is self.cur():
            self.setWindowTitle(f"{title} \u2013 Shield" if title else "Shield")

    def _icon(self, view, icon):
        self.strip.set_icon(view, icon)
        u = view.url()
        host = u.host().lower()
        if u.scheme() in ("http", "https") and host and not icon.isNull() \
                and (self.cfg["history_days"] or self.store.is_bookmarked(u.toString())):
            ba = QByteArray()
            buf = QBuffer(ba)
            buf.open(QIODevice.OpenModeFlag.WriteOnly)
            icon.pixmap(QSize(32, 32)).save(buf, "PNG")
            self.store.save_favicon(host, bytes(ba))

    def _loading(self, view, on):
        view.loading = on
        self.strip.set_loading(view, on)
        if view is self.cur():
            self.reload_btn.set_icon("close" if on else "reload")
            if on:
                self.chrome.progress.start()

    def _load_done(self, view, ok):
        self._loading(view, False)
        if view is self.cur():
            self.chrome.progress.finish()
        u = view.url()
        if ok and u.scheme() in ("http", "https") and self.cfg["history_days"]:
            self.store.add_history(u.toString(), view.title())
            self.refresh_completer()
        if view is self.cur():
            self._sync()

    def reload_or_stop(self):
        v = self.cur()
        v.stop() if v.loading else v.reload()

    def _sync(self):
        v = self.cur()
        if not v:
            return
        u = v.url()
        s = u.scheme()
        text = re.sub(r"^(shield://[^/?#]+)/(?=$|#)", r"\1", u.toString()) if s == "shield" else u.toString()
        shown = "" if text in ("shield://newtab", "about:blank") else text
        self.omni.set_url(shown)
        look = {"https": ("lock", None, "Connection is secure"), "http": ("lock-open", "warn", "Connection is not secure"),
                "shield": ("shield-check", "acc", "Shield page")}.get(s, ("globe", None, "Site controls"))
        self.omni.lock.set_icon(look[0])
        self.omni.lock.set_tone(look[1])
        self.omni.lock.setToolTip(look[2] + ". Click for site controls.")
        self.reload_btn.set_icon("close" if v.loading else "reload")
        on = s in ("http", "https") and self.store.is_bookmarked(u.toString())
        self.omni.star.set_icon("star-fill" if on else "star")
        self.omni.star.set_tone("acc" if on else None)
        h = v.history()
        self.back_btn.setEnabled(h.canGoBack())
        self.fwd_btn.setEnabled(h.canGoForward())
        self.omni.zoom.set_zoom(v.zoomFactor())
        t = v.title()
        self.setWindowTitle(f"{t} \u2013 Shield" if t else "Shield")

    def _tick(self):
        self._proxy_sync()
        v = self.cur()
        if v:
            site = site_of(v.url().host())
            n = self.events.site_count(site)
            if site == self._shield_site and n > self._shield_n and self.isActiveWindow():
                self.shield_btn.glint()               # the shield just caught something on this page
            self._shield_site, self._shield_n = site, n
            self.shield_btn.set_badge(f"{n}" if n else "", "ok")
            self.shield_btn.set_tone("ok" if n else None)
            self.omni.zoom.set_zoom(v.zoomFactor())
        n = self.store.pending_count()
        self.dl_btn.set_badge(str(n) if n else "", "acc")
        self.back_btn.setEnabled(bool(v) and v.history().canGoBack())
        self.fwd_btn.setEnabled(bool(v) and v.history().canGoForward())
        self._tick_n += 1
        if self._tick_n % 3 == 0:
            self._vault_badge()

    def _hover_link(self, url):
        if url:
            self.link_pill.show_text(url, hold=False)
        else:
            self.link_pill.hide_now()

    def to_url(self, text):
        t = text.strip()
        if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", t):
            return QUrl(t)
        if t.startswith("about:"):
            return QUrl(t)
        host = t.split("/")[0].split(":")[0]
        if " " not in t and re.match(r"^[\w.-]+(:\d+)?(/.*)?$", t) and ("." in host or host == "localhost"):
            return QUrl(("http://" if is_local_host(host) else "https://") + t)
        tmpl = SEARCH_ENGINES[self.cfg["search_engine"]][1]
        return QUrl(tmpl.format(quote_plus(t)))

    def navigate(self):
        if self.urlbar.text().strip():
            self.cur().setUrl(self.to_url(self.urlbar.text()))
            self.cur().setFocus()

    def refresh_completer(self):
        items = [b["url"] for b in self.store.bookmarks(100)]
        items += [h["url"] for h in self.store.history("", 200)]
        self.completer_model.setStringList(list(dict.fromkeys(items)))

    def toggle_bookmark(self):
        u = self.cur().url()
        if u.scheme() in ("http", "https"):
            on = self.store.toggle_bookmark(u.toString(), self.cur().title())
            self.toast("Bookmark added" if on else "Bookmark removed")
            if on:
                self.omni.star.burst()
                play_sound("star")
            self.refresh_completer()
            self._sync()

    def site_menu(self):
        u = self.cur().url()
        host = u.host().lower()
        m = soften_menu(QMenu(self))
        if u.scheme() not in ("http", "https") or not host:
            m.addAction("Internal Shield page").setEnabled(False)
        else:
            m.addAction(host).setEnabled(False)
            m.addAction("Secure connection (HTTPS)" if u.scheme() == "https" else "Not secure (HTTP)").setEnabled(False)
            n = self.events.site_count(site_of(host))
            m.addAction(f"{n:,} blocked on this site this session" if n else "Nothing blocked on this site yet").setEnabled(False)
            m.addSeparator()
            for rule, label in (("nojs", "Block JavaScript on this site"), ("http", "Allow plain HTTP on this site"),
                                ("noblock", "Turn off ad and tracker blocking here")):
                a = m.addAction(label)
                a.setCheckable(True)
                a.setChecked(rule in self.cfg["site_rules"].get(host, []))
                a.toggled.connect(lambda on, r=rule: self.set_rule(host, r, on))
        b = self.omni.lock
        m.exec(b.mapToGlobal(b.rect().bottomLeft()))

    def set_rule(self, host, rule, on):
        self.cfg.add_rule(host, rule) if on else self.cfg.del_rule(host, rule)
        self.cur().reload()

    def show_find(self):
        self._place_overlays()
        self.findbar.present()

    def hide_find(self):
        if self.findbar.isVisible():
            self.findbar.dismiss()

    def _find_query(self, text):
        if self.cur():
            self.cur().findText(text)
            if not text:
                self.findbar.set_count(0, 0)

    def _find_step(self, forward):
        flag = QWebEnginePage.FindFlag(0) if forward else QWebEnginePage.FindFlag.FindBackward
        self.cur().findText(self.findbar.edit.text(), flag)

    def zoom(self, delta):
        v = self.cur()
        v.setZoomFactor(1.0 if delta == 0 else max(0.3, min(4.0, v.zoomFactor() + delta)))
        self.omni.zoom.set_zoom(v.zoomFactor())

    def toggle_fullscreen(self):
        self.showNormal() if self.isFullScreen() else self.showFullScreen()

    def on_fullscreen(self, req, page=None):
        req.accept()
        on = req.toggleOn()
        self.chrome.setVisible(not on)
        self.showFullScreen() if on else self.showNormal()
        if self.split_pair:
            asker = next((x for x in self.strip.views() if page is not None and x.page() is page), None)
            if on and asker is not None:
                self.stack.show_single(asker)      # the page that asked fills the window; the split returns afterwards
            elif not on:
                self._select(self.cur())

    def ask(self, on_done, **kw):
        """Show a modal card without blocking the event loop. Cards queue up if several arrive at once."""
        self._sheet_q.append((kw, on_done))
        self._next_sheet()

    def _next_sheet(self):
        if self._sheet or not self._sheet_q:
            return
        kw, cb = self._sheet_q.pop(0)
        s = Sheet(self.root, **kw)
        self._sheet = s

        def gone(*_):
            self._sheet = None
            QTimer.singleShot(0, self._next_sheet)
        s.done.connect(cb)
        s.destroyed.connect(gone)
        s.present()

    def decide_permission(self, host, name, grant, deny, origin=None):
        label = PERM_LABELS.get(name, name)
        key = (origin or host, name)       # per origin (scheme, host and port), so http://x and https://x never share a grant
        if key in self.session_perms:
            (grant if self.session_perms[key] else deny)()
            return
        if self.cfg["permissions"] == "deny" or name == "Notifications":
            deny()
            self.events.add("permission", f"denied {label} for {host}")
            return

        def done(v):
            ok = v == "allow"
            self.session_perms[key] = ok
            try:
                (grant if ok else deny)()
            except RuntimeError:
                pass
            self.events.add("permission", f"{'allowed' if ok else 'denied'} {label} for {host}")
        self.ask(done, icon="shield", tone="acc", title=f"Allow {short(host, 36)} to use {label}?",
                 body="If you allow it, this lasts until you close Shield.",
                 buttons=[("Allow for this session", "pri", "allow"), ("Don't allow", "plain", "deny")], cancel="deny")

    def print_page(self):
        v = self.cur()
        if v.url().scheme() not in ("http", "https"):
            self.toast("Only web pages can be printed")
            return
        self._printer = QPrinter(QPrinter.PrinterMode.HighResolution)
        if not QPrintDialog(self._printer, self).exec():
            self._printer = None
            return

        def done(ok):
            self._printer = None
            self.toast("Sent to the printer" if ok else "Couldn't print this page")
        v.page().print(self._printer, done)

    def save_pdf(self):
        v = self.cur()
        if v.url().scheme() not in ("http", "https"):
            self.toast("Only web pages can be saved as PDF")
            return
        name = clean_name(v.title() or v.url().host() or "page")[:80] + ".pdf"
        path, _ = QFileDialog.getSaveFileName(self, "Save page as PDF", str(DOWNLOADS / name), "PDF (*.pdf)")
        if path:
            v.page().printToPdf(path)

    def view_source(self):
        v = self.cur()
        if v.url().scheme() in ("http", "https"):
            self.new_tab(QUrl("view-source:" + v.url().toString()))

    def open_devtools(self):
        v = self.cur()
        if not v or v.url().scheme() not in ("http", "https"):
            self.toast("Developer tools open on web pages")
            return
        for dv in self._devtools[:]:
            try:
                if dv.property("target") is v.page() and dv.isVisible():
                    dv.raise_()
                    dv.activateWindow()
                    return
            except RuntimeError:
                self._devtools.remove(dv)
        dv = QWebEngineView()
        dev_page = QWebEnginePage(self.profile, dv)
        dv.setPage(dev_page)
        dv.setProperty("target", v.page())
        v.page().setDevToolsPage(dev_page)
        dv.setWindowTitle("Developer tools \u2013 Shield")
        dv.resize(1060, 720)
        dv.show()
        self._devtools.append(dv)

    def _vault_ui(self):
        """Refresh everything that depends on the vault's state."""
        self.vault_btn.setVisible(self.cfg["vault_autofill"] or self.vault.exists())
        self._vault_badge()

    def _vault_badge(self):
        v, view = self.vault, self.cur()
        if not view:
            return
        page = view.page()
        origin = shield_vault.norm_origin(view.url().toString())
        n = 0
        if v.unlocked and origin and page.login.get("pw"):
            n = len(v.for_origin(origin))
        self.vault_btn.set_badge(str(n) if n else "", "acc")
        self.vault_btn.set_tone("acc" if n else None)
        tip = ("Passwords: set up the vault" if not v.exists() else "Passwords: the vault is locked. Click to unlock."
               if not v.unlocked else f"{n} saved login{'s' if n != 1 else ''} for this site" if n else "Passwords")
        self.vault_btn.setToolTip(tip)

    def unlock_prompt(self, after=None, error=""):
        v = self.vault

        def done(res):
            act, text = res if isinstance(res, tuple) else (res, "")
            if act != "unlock":
                return
            sheet = self._sheet          # the card stays open while the answer is checked, then answers like Face ID

            def answer(result, message=""):
                try:
                    if sheet is not None:
                        sheet.resolve(result, message)
                except RuntimeError:
                    pass
            if v.wait_seconds():
                answer(None)
                self.toast(f"Too many tries. Wait {v.wait_seconds()} seconds.")
                return
            try:
                ok = v.unlock(text)
            except shield_vault.VaultError as e:
                answer(None)
                self.toast(str(e))
                return
            except Exception:
                answer(None)
                raise
            if ok:
                self._vault_ui()
                self.vault_btn.glint()
                answer(True)
                if after:
                    after()
            else:
                answer(False, "That isn't the master password. Try again.")
        self.ask(done, icon="lock", tone="acc", title="Unlock your vault", body=error or "Enter your master password.",
                 buttons=[("Unlock", "pri", "unlock"), ("Cancel", "plain", "cancel")], cancel="cancel",
                 field={"placeholder": "Master password", "password": True}, hold=("unlock",))

    def key_menu(self):
        v, view = self.vault, self.cur()
        m = soften_menu(QMenu(self))
        origin = shield_vault.norm_origin(view.url().toString()) if view else ""
        if not v.exists():
            m.addAction("Set up the password vault\u2026").triggered.connect(lambda: self.open_internal("passwords"))
        elif not v.unlocked:
            m.addAction("Unlock the vault\u2026").triggered.connect(lambda: self.unlock_prompt())
            m.addAction("Open passwords").triggered.connect(lambda: self.open_internal("passwords"))
        else:
            hits = v.for_origin(origin) if origin else []
            if hits:
                m.addAction(f"Fill a login for {shield_vault.host_of(origin)}").setEnabled(False)
                for e in hits:
                    m.addAction(e["username"] or "No username").triggered.connect(lambda _=False, i=e["id"]: self.vault_fill(i))
            elif origin and not shield_vault.can_fill(origin):
                m.addAction("Logins only fill on secure (HTTPS) pages").setEnabled(False)
            elif origin:
                m.addAction("No saved logins for this site").setEnabled(False)
            m.addSeparator()
            m.addAction("Generate a password and copy it").triggered.connect(self.gen_and_copy)
            m.addAction("Open passwords").triggered.connect(lambda: self.open_internal("passwords"))
            m.addAction("Lock the vault now").triggered.connect(lambda: (v.lock(), self._vault_ui(), self.toast("Vault locked")))
        b = self.vault_btn
        pos = b.mapToGlobal(b.rect().bottomRight())
        pos.setX(pos.x() - m.sizeHint().width())
        pos.setY(pos.y() + 4)
        m.exec(pos)

    def gen_and_copy(self):
        self.copy_secret(shield_vault.generate(20))
        self.toast("A new password is on your clipboard. It leaves in 30 seconds.")

    def vault_fill(self, eid):
        v, view = self.vault, self.cur()
        try:
            e = v.get(eid)
        except shield_vault.VaultError:
            return
        if not e or not view:
            return
        if shield_vault.norm_origin(view.url().toString()) != e["origin"]:
            self.toast("That login belongs to a different site")
            return

        def result(r):
            msg = {"ok": "Filled", "noform": "There's no login form on this page",
                   "cross": "This form would send your password to another site, so Shield didn't fill it",
                   "hidden": "The password box on this page isn't visible, so Shield didn't fill it"}.get(r, "Couldn't fill this form")
            if r == "ok":
                try:
                    v.mark_used(eid)
                except shield_vault.VaultError:
                    pass
            self.toast(msg)
        view.page().runJavaScript(fill_call(e["username"], e["password"]), APP_WORLD_ID, result)

    def vault_seen(self, page):
        p = page.pending
        if p and page.starts > p["starts"]:           # a new document loaded after the login was sent
            page.pending = None
            if not page.login.get("pw"):
                self._offer_save(p["origin"], p["user"], p["pw"])
        cur = self.cur()
        if cur is not None and page is cur.page():
            self._vault_badge()

    def vault_captured(self, page, d):
        v = self.vault
        if not (self.cfg["vault_offer_save"] and v.exists()):
            return
        origin = shield_vault.norm_origin(page.url().toString())
        user, pw, kind = d.get("user", ""), d.get("pw", ""), d.get("kind")
        if not origin or not shield_vault.can_fill(origin) or d.get("cross") or kind not in ("login", "new", "change") \
                or not isinstance(user, str) or not isinstance(pw, str) or not pw:
            return
        if v.unlocked and shield_vault.host_of(origin) in v.never:
            return
        token = secrets.token_hex(4)
        page.pending = {"origin": origin, "user": user[:256], "pw": pw[:256], "starts": page.starts, "token": token}
        QTimer.singleShot(4000, lambda: self._pending_timeout(page, token))

    def _pending_timeout(self, page, token):
        try:
            p = page.pending
            if not p or p["token"] != token:
                return
            page.pending = None

            def check(has_form):
                if not has_form:                       # the form is gone: the sign-in worked
                    self._offer_save(p["origin"], p["user"], p["pw"])
            page.runJavaScript("(()=>!!document.querySelector('input[type=password]'))()", APP_WORLD_ID, check)
        except RuntimeError:
            pass

    def _offer_save(self, origin, user, pw, error=""):
        v = self.vault
        host = shield_vault.host_of(origin)
        who = f" for {short(user, 30)}" if user else ""
        if v.unlocked:
            state, _eid = v.known(origin, user, pw)
            if state == "same" or host in v.never:
                return

            def done(a):
                try:
                    if a == "save":
                        v.add(origin, user, pw)
                        self.toast("Saved to your vault")
                    elif a == "never":
                        v.never_add(host)
                        self.toast(f"Shield won't offer to save {short(host, 30)} again")
                except shield_vault.VaultError as e:
                    self.toast(str(e))
                self._vault_ui()
            update = state == "changed"
            self.ask(done, icon="key", tone="acc", title="Update the saved password?" if update else "Save this password?",
                     body=(f"The password{who} on {host} has changed." if update else f"Shield will keep this login{who} for {host} in your vault."),
                     buttons=[("Update" if update else "Save", "pri", "save"), ("Not now", "plain", "skip"), ("Never for this site", "danger-text", "never")],
                     cancel="skip")
        else:
            def done(res):
                act, text = res if isinstance(res, tuple) else (res, "")
                if act != "save":
                    return
                if v.wait_seconds():
                    self.toast(f"Too many tries. Wait {v.wait_seconds()} seconds.")
                    return
                try:
                    ok = v.unlock(text)
                    if ok and host not in v.never and v.known(origin, user, pw)[0] != "same":
                        v.add(origin, user, pw)
                        self.toast("Saved to your vault")
                except shield_vault.VaultError as e:
                    self.toast(str(e))
                    return
                if ok:
                    self._vault_ui()
                else:
                    self._offer_save(origin, user, pw, "That isn't the master password. Try again.")
            self.ask(done, icon="key", tone="acc", title="Save this password?",
                     body=error or f"Unlock your vault to save this login{who} for {host}.",
                     buttons=[("Unlock and save", "pri", "save"), ("Not now", "plain", "skip")], cancel="skip",
                     field={"placeholder": "Master password", "password": True})


def app_icon():
    from PyQt6.QtCore import QRectF, QPointF
    from PyQt6.QtGui import QLinearGradient, QBrush
    size = 256
    pm = QPixmap(size, size)
    pm.fill(Qt.GlobalColor.transparent)
    p = QPainter(pm)
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    g = QLinearGradient(QPointF(0, 0), QPointF(size, size))
    g.setColorAt(0, QColor("#58a8ff"))
    g.setColorAt(1, QColor("#0a6cff"))
    p.setBrush(QBrush(g))
    p.setPen(Qt.PenStyle.NoPen)
    p.drawRoundedRect(QRectF(8, 8, size - 16, size - 16), 58, 58)
    p.drawPixmap(QPointF(62, 62), pix("shield-check", QColor("#ffffff"), 132, 1.0))
    p.end()
    return QIcon(pm)


def _log_exception(kind, value, tb):
    import traceback
    try:
        with open(HOME / "shield.log", "a", encoding="utf-8") as f:
            f.write(time.strftime("%Y-%m-%d %H:%M:%S ") + "".join(traceback.format_exception(kind, value, tb)) + "\n")
    except OSError:
        pass
    if sys.stderr:     # a windowed build has no console, so there is nothing to print to
        sys.__excepthook__(kind, value, tb)


def _windows_identity():
    """Give the process its own taskbar identity so the pinned icon, the Start menu entry and the window all agree."""
    if os.name != "nt":
        return
    try:
        import ctypes
        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("Shield.Browser")
    except Exception:
        pass


def selftest(out_path):
    """Checks that a packaged build has everything it needs, including a working web engine. Used by build.ps1.
    Writes a small JSON report (a windowed build has no console) and returns the exit code."""
    import shield_scan
    report = {"version": VERSION, "frozen": FROZEN, "checks": {}}
    ok_all = [True]

    def check(name, fn):
        try:
            detail = fn()
            report["checks"][name] = {"ok": True, "detail": str(detail)[:200]}
        except Exception as e:
            report["checks"][name] = {"ok": False, "detail": f"{type(e).__name__}: {e}"[:300]}
            ok_all[0] = False

    def need(cond, msg):
        if not cond:
            raise RuntimeError(msg)

    def yara_ok():
        need(shield_scan.yara_x is not None, "yara_x did not load")
        c = shield_scan.yara_x.Compiler()
        c.add_source("rule t { strings: $a = \"abc\" condition: $a }")
        r = shield_scan.yara_x.Scanner(c.build()).scan(b"xxabcxx")
        need(len(r.matching_rules) == 1, "yara rule did not match")
        return "ok"

    def pe_ok():
        need(shield_scan.pefile is not None, "pefile did not load")
        return "ok"

    def sign_ok():
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
        k = Ed25519PrivateKey.generate()
        k.public_key().verify(k.sign(b"x"), b"x")
        return "ok"

    def channel_ok():
        js = qwebchannel_js()
        need(len(js) > 1000, "qwebchannel.js is missing")
        return f"{len(js)} bytes"

    def vault_ok():
        """The password vault's cryptography (Argon2id + AES-GCM) works in this packed build: create, lock, reopen, rekey."""
        import tempfile
        with tempfile.TemporaryDirectory() as d:
            v = shield_vault.Vault(str(Path(d) / "t.shv"))
            v.create("selftest-master-pw")
            v.add("https://example.com", "u", "p")
            v.lock()
            need(not v.unlock("wrong-master-pass"), "a wrong password opened the vault")
            need(v.unlock("selftest-master-pw"), "the right password did not open the vault")
            need(v.change_master("selftest-master-pw", "selftest-master-pw-2"), "changing the master password failed")
            v.lock()
            need(v.unlock("selftest-master-pw-2") and len(v.entries) == 1, "the vault did not reopen after rekeying")
        return "ok"

    def engine_ok():
        """Reports the web engine's security-patch level, which is what the signed min_chromium floor is compared with."""
        major = Core._engine_major()
        need(major > 0, "Qt could not report the engine's patch level")
        return f"Chromium security-patch major {major}"

    app = QApplication(sys.argv)
    check("yara", yara_ok)
    check("pefile", pe_ok)
    check("update signatures", sign_ok)
    check("webchannel script", channel_ok)
    check("vault cryptography", vault_ok)
    check("engine patch level", engine_ok)
    check("icons", lambda: need(not pix("shield-check", QColor("#ffffff"), 24, 1.0).isNull(), "icon rendering failed") or "ok")

    # the web engine itself: start it, load a page, run script in it
    result = {}
    prof = QWebEngineProfile(app)                 # off the record, nothing is written
    page = QWebEnginePage(prof, app)

    def finish(ok, detail):
        if "done" in result:
            return
        result["done"] = True
        report["checks"]["web engine"] = {"ok": ok, "detail": detail}
        if not ok:
            ok_all[0] = False
        app.quit()

    def loaded(ok):
        if not ok:
            return finish(False, "the test page did not load")
        page.runJavaScript("document.title + ':' + (6*7)", lambda v: finish(v == "shield:42", f"script returned {v!r}"))

    page.loadFinished.connect(loaded)
    page.setHtml("<title>shield</title><p>ok</p>", QUrl("https://selftest.invalid/"))
    QTimer.singleShot(40000, lambda: finish(False, "timed out waiting for the web engine"))
    app.exec()
    page.deleteLater()
    report["ok"] = ok_all[0]
    try:
        Path(out_path).write_text(json.dumps(report, indent=2), encoding="utf-8")
    except OSError:
        return 2
    return 0 if ok_all[0] else 1


def start_urls(argv):
    """Web addresses from the command line. Shield is also what other apps launch when you click a link."""
    return [a for a in argv if re.match(r"^https?://\S+$", a)][:20]


def forward_to_running(urls):
    """If Shield is already open, hand it the addresses and return True so this second copy can quit."""
    sock = QLocalSocket()
    sock.connectToServer(instance_name())
    if not sock.waitForConnected(400):
        return False
    sock.write(json.dumps(urls).encode("utf-8"))
    sock.flush()
    sock.waitForBytesWritten(800)
    sock.disconnectFromServer()
    return True


class _OpenEvents(QObject):
    """macOS hands 'open this link' to the running app as an event, not as a command-line argument."""

    def __init__(self, core):
        super().__init__(core)
        self.core = core

    def eventFilter(self, obj, ev):
        if ev.type() == QEvent.Type.FileOpen:
            u = ev.url().toString() if ev.url().isValid() else ""
            if re.match(r"^https?://\S+$", u):
                self.core.open_urls([u])
            return True
        return False


def main():
    args = sys.argv[1:]
    if "--version" in args:
        if sys.stdout:
            print(f"Shield {VERSION}")
        return
    if os.name == "posix" and hasattr(os, "geteuid") and os.geteuid() == 0 and os.environ.get("SHIELD_INSECURE_NO_SANDBOX") != "1":
        if sys.stderr:
            print("Shield won't run as the root user: the Chromium sandbox can't be used that way. Run it as a normal user.", file=sys.stderr)
        sys.exit(2)
    sys.excepthook = _log_exception   # without this, PyQt6 aborts the whole process on any unhandled error in a slot
    _windows_identity()
    register_scheme()
    if "--selftest" in args:
        i = args.index("--selftest")
        sys.exit(selftest(args[i + 1] if i + 1 < len(args) else str(HOME / "selftest.json")))
    app = QApplication(sys.argv)
    app.setApplicationName("Shield")
    app.setDesktopFileName("shield")
    urls = start_urls(sys.argv[1:])
    if forward_to_running(urls):
        return
    f = app.font()
    try:
        f.setFamilies(["SF Pro Text", "Segoe UI Variable Text", "Segoe UI", "Inter", "Helvetica Neue", "Noto Sans", "Ubuntu"])
    except Exception:
        pass
    f.setPointSizeF(9.5)
    app.setFont(f)
    app.setWindowIcon(app_icon())
    core = Core()
    app._core = core                                   # the one thing every window shares lives as long as the app
    app.aboutToQuit.connect(core.on_about_to_quit)
    if sys.platform == "darwin":
        app._open_events = _OpenEvents(core)
        app.installEventFilter(app._open_events)
    if PROXY is not None:
        PROXY.settings = lambda: (core.cfg["proxy_bridge_mode"], core.cfg["proxy_bridges"])
        app.aboutToQuit.connect(PROXY.shutdown)          # Tor never outlives the browser
        if core.cfg["proxy_on_start"] and PROXY.available():
            PROXY.enable()
    core.start(urls)
    QTimer.singleShot(0, core.focus_active)
    sys.exit(app.exec())


if __name__ == "__main__":
    main()
