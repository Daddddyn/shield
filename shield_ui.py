"""
shield_ui.py: the native widgets that make up the browser chrome.

Design rules used everywhere in here:
  * one icon set (shield_icons.py), drawn from SVG so it stays sharp at any scale
  * one palette per theme (Theme), nothing hard-coded in the widgets
  * motion is never linear: values glide toward their target with exponential easing, so any animation
    can be interrupted halfway (hover out while hovering in, close a tab while another is opening)
    and still look right
"""
import math
import re
import time

from PyQt6.QtCore import QEvent, QObject, QPointF, QRectF, QSize, Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QColor, QFont, QFontMetricsF, QPainter, QPen, QPixmap
from PyQt6.QtSvg import QSvgRenderer
from PyQt6.QtWidgets import (
    QAbstractButton, QApplication, QFrame, QGraphicsOpacityEffect, QHBoxLayout, QLabel, QLineEdit,
    QStackedWidget, QToolTip, QVBoxLayout, QWidget,
)

from shield_core import site_of
from shield_icons import svg_doc


# --------------------------------------------------------------------------
# Theme
# --------------------------------------------------------------------------
def _c(s):
    s = s.lstrip("#")
    if len(s) == 8:  # CSS order: rrggbbaa
        return QColor(int(s[0:2], 16), int(s[2:4], 16), int(s[4:6], 16), int(s[6:8], 16))
    return QColor("#" + s)


DARK = dict(window="#161618", bar="#1f1f22", field="#2c2c30", field_h="#343439", hover="#ffffff14", press="#ffffff24",
            tab="#38383d", text="#f5f5f7", mut="#a1a1a8", faint="#6c6c73", line="#ffffff1c", acc="#0a84ff",
            ok="#32d74b", warn="#ffb340", bad="#ff5a50", card="#262629", shadow="#000000")
LIGHT = dict(window="#e6e6ea", bar="#f4f4f6", field="#e7e7eb", field_h="#dfdfe4", hover="#00000012", press="#00000020",
             tab="#ffffff", text="#1d1d1f", mut="#6e6e73", faint="#a1a1a6", acc="#007aff",
             ok="#1e8a39", warn="#a85a00", bad="#d1281d", card="#ffffff", shadow="#000000", line="#0000001a")


class Theme(QObject):
    changed = pyqtSignal()

    def __init__(self):
        super().__init__()
        self.dark = True
        self._cache = {}

    def set_dark(self, dark):
        if dark != self.dark or not self._cache:
            self.dark = dark
            self._cache = {k: _c(v) for k, v in (DARK if dark else LIGHT).items()}
            self.changed.emit()

    def c(self, name, alpha=None):
        col = QColor(self._cache[name])
        if alpha is not None:
            col.setAlphaF(max(0.0, min(1.0, alpha)))
        return col

    def mix(self, a, b, t):
        ca, cb = self._cache[a], self._cache[b]
        return QColor(int(ca.red() + (cb.red() - ca.red()) * t), int(ca.green() + (cb.green() - ca.green()) * t),
                      int(ca.blue() + (cb.blue() - ca.blue()) * t), int(ca.alpha() + (cb.alpha() - ca.alpha()) * t))


T = Theme()
T.set_dark(True)


def approach(cur, target, rate, dt):
    """Move toward target exponentially. Frame-rate independent and safe to retarget at any moment."""
    return cur + (target - cur) * (1.0 - math.exp(-rate * dt))


def lerp(a, b, t):
    return a + (b - a) * t


class Glide:
    """A single float that eases toward a target on a timer, then stops the timer when it settles."""

    def __init__(self, owner, apply, rate=16.0, value=0.0):
        self.v, self.t, self.rate, self.apply = value, value, rate, apply
        self._tm = QTimer(owner)
        self._tm.setInterval(8)
        self._tm.timeout.connect(self._step)
        self._last = 0.0

    def to(self, target, instant=False):
        self.t = target
        if instant:
            self.v = target
            self.apply(self.v)
            self._tm.stop()
            return
        if not self._tm.isActive():
            self._last = time.perf_counter()
            self._tm.start()

    def _step(self):
        now = time.perf_counter()
        dt = min(0.05, now - self._last)
        self._last = now
        self.v = approach(self.v, self.t, self.rate, dt)
        if abs(self.v - self.t) < 0.002:
            self.v = self.t
            self._tm.stop()
        self.apply(self.v)


# --------------------------------------------------------------------------
# Icons
# --------------------------------------------------------------------------
_icons = {}


def pix(name, color, size, dpr=2.0):
    """An SVG icon tinted to any colour (alpha included), cached."""
    key = (name, color.rgba(), size, round(dpr, 2))
    pm = _icons.get(key)
    if pm is None:
        px = max(1, int(size * dpr))
        pm = QPixmap(px, px)
        pm.fill(Qt.GlobalColor.transparent)
        pm.setDevicePixelRatio(dpr)
        r = QSvgRenderer(svg_doc(name, "#000000").encode())
        p = QPainter(pm)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        r.render(p, QRectF(0, 0, size, size))
        p.setCompositionMode(QPainter.CompositionMode.CompositionMode_SourceIn)
        p.fillRect(pm.rect(), color)
        p.end()
        if len(_icons) > 400:
            _icons.clear()
        _icons[key] = pm
    return pm


def draw_icon(p, name, rect, color, opacity=1.0):
    dpr = p.device().devicePixelRatioF() if hasattr(p.device(), "devicePixelRatioF") else 2.0
    pm = pix(name, color, int(round(rect.width())), max(1.0, dpr))
    if opacity < 1.0:
        p.save()
        p.setOpacity(p.opacity() * opacity)
    p.drawPixmap(QPointF(rect.x(), rect.y()), pm)
    if opacity < 1.0:
        p.restore()


def soft_shadow(p, rect, radius, spread=26.0, strength=0.2, dy=10.0, scale=1.0):
    """A smooth drop shadow: many near-invisible layers instead of a few visible steps."""
    n = 18
    col = T.c("shadow")
    p.setPen(Qt.PenStyle.NoPen)
    for i in range(n, 0, -1):
        grow = spread * i / n
        col.setAlphaF(max(0.0, strength * scale / n))
        p.setBrush(col)
        p.drawRoundedRect(rect.adjusted(-grow, -grow + dy, grow, grow + dy), radius + grow, radius + grow)


def ui_font(pt=9.5, weight=None):
    f = QFont(QApplication.font())
    f.setPointSizeF(pt)
    if weight is not None:
        f.setWeight(weight)
    return f


# --------------------------------------------------------------------------
# Icon button
# --------------------------------------------------------------------------
class IconButton(QAbstractButton):
    def __init__(self, name, tip="", size=34, icon=18, parent=None):
        super().__init__(parent)
        self._name, self._prev, self._icon = name, None, icon
        self._hv, self._pr, self._xf = 0.0, 0.0, 1.0
        self._tone, self._badge, self._badge_tone = None, "", "acc"
        self._kbd = False
        self.setFixedSize(size, size)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFocusPolicy(Qt.FocusPolicy.TabFocus)
        self.setToolTip(tip)
        self._g_hv = Glide(self, self._set_hv, 18)
        self._g_pr = Glide(self, self._set_pr, 30)
        self._g_xf = Glide(self, self._set_xf, 22, 1.0)
        self.pressed.connect(lambda: self._g_pr.to(1.0))
        self.released.connect(lambda: self._g_pr.to(0.0))
        T.changed.connect(self.update)

    def _set_hv(self, v):
        self._hv = v
        self.update()

    def _set_pr(self, v):
        self._pr = v
        self.update()

    def _set_xf(self, v):
        self._xf = v
        if v >= 1.0:
            self._prev = None
        self.update()

    def enterEvent(self, e):
        self._g_hv.to(1.0)
        super().enterEvent(e)

    def leaveEvent(self, e):
        self._g_hv.to(0.0)
        super().leaveEvent(e)

    def set_icon(self, name, animate=True):
        if name == self._name:
            return
        self._prev, self._name = self._name, name
        self._xf = 0.0
        self._g_xf.v = 0.0
        self._g_xf.to(1.0, instant=not animate)

    def set_tone(self, tone):
        self._tone = tone
        self.update()

    def set_badge(self, text, tone="acc"):
        if text != self._badge or tone != self._badge_tone:
            self._badge, self._badge_tone = text, tone
            self.update()

    def changeEvent(self, e):
        if e.type() == QEvent.Type.EnabledChange:
            self.update()
        super().changeEvent(e)

    def focusInEvent(self, e):
        self._kbd = e.reason() in (Qt.FocusReason.TabFocusReason, Qt.FocusReason.BacktabFocusReason)
        super().focusInEvent(e)

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        r = QRectF(self.rect())
        on = self.isEnabled()
        bg = T.mix("hover", "press", self._pr)
        bg.setAlphaF(bg.alphaF() * (self._hv if on else 0.0))
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(bg)
        p.drawRoundedRect(r.adjusted(1, 1, -1, -1), 9, 9)
        if self.hasFocus() and self._kbd:
            p.setBrush(Qt.BrushStyle.NoBrush)
            p.setPen(QPen(T.c("acc", .7), 1.6))
            p.drawRoundedRect(r.adjusted(2, 2, -2, -2), 8, 8)
        base = T.c(self._tone) if self._tone else T.mix("mut", "text", self._hv)
        if not on:
            base = T.c("faint", .55)
        s = self._icon * (1.0 - 0.1 * self._pr)
        box = QRectF(r.center().x() - s / 2, r.center().y() - s / 2, s, s)
        if self._prev is not None:
            draw_icon(p, self._prev, box, base, 1.0 - self._xf)
            rot = box.translated(0, (1 - self._xf) * 2.5)
            draw_icon(p, self._name, rot, base, self._xf)
        else:
            draw_icon(p, self._name, box, base)
        if self._badge:
            f = ui_font(7.2, QFont.Weight.Bold)
            fm = QFontMetricsF(f)
            w = max(15.0, fm.horizontalAdvance(self._badge) + 9)
            br = QRectF(r.right() - w - 1, r.top() + 1, w, 14.5)
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(T.c("bar"))
            p.drawRoundedRect(br.adjusted(-1.5, -1.5, 1.5, 1.5), 8.5, 8.5)
            p.setBrush(T.c(self._badge_tone))
            p.drawRoundedRect(br, 7.25, 7.25)
            p.setFont(f)
            p.setPen(QColor("#ffffff"))
            p.drawText(br, Qt.AlignmentFlag.AlignCenter, self._badge)


# --------------------------------------------------------------------------
# Omnibox
# --------------------------------------------------------------------------
class Edit(QLineEdit):
    focused = pyqtSignal(bool)

    def __init__(self):
        super().__init__()
        self._select_next = False

    def focusInEvent(self, e):
        super().focusInEvent(e)
        self.focused.emit(True)
        if e.reason() == Qt.FocusReason.MouseFocusReason:
            self._select_next = True
        QTimer.singleShot(0, self.selectAll)

    def focusOutEvent(self, e):
        super().focusOutEvent(e)
        self.focused.emit(False)

    def mouseReleaseEvent(self, e):
        super().mouseReleaseEvent(e)
        self._select_next = False

    def keyPressEvent(self, e):
        if e.key() == Qt.Key.Key_Escape:
            self.focused.emit(False)
            self.clearFocus()
            return
        super().keyPressEvent(e)


_URL_RE = re.compile(r"^(?P<scheme>[a-zA-Z][a-zA-Z0-9+.-]*://)?(?P<host>[^/:?#]*)(?P<rest>.*)$")


def split_url(text):
    """[(text, kind)] where kind is dim | strong | warn. The real domain is emphasised, everything else recedes."""
    m = _URL_RE.match(text)
    if not m:
        return [(text, "dim")]
    scheme, host, rest = m.group("scheme") or "", m.group("host") or "", m.group("rest") or ""
    out = []
    if scheme and scheme.lower() not in ("https://",):
        out.append((scheme, "warn" if scheme.lower() == "http://" else "dim"))
    if scheme.lower() == "shield://":
        out.append((host, "strong"))
    else:
        reg = site_of(host)
        if reg and host.endswith(reg) and len(host) > len(reg):
            out.append((host[:-len(reg)], "dim"))
            out.append((reg, "strong"))
        else:
            out.append((host, "strong"))
    if rest:
        out.append((rest, "dim"))
    return out


class UrlLabel(QWidget):
    clicked = pyqtSignal()

    def __init__(self):
        super().__init__()
        self._text = ""
        self.setCursor(Qt.CursorShape.IBeamCursor)
        T.changed.connect(self.update)

    def set_text(self, t):
        self._text = t
        self.update()

    def mousePressEvent(self, e):
        self.clicked.emit()

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.TextAntialiasing)
        f = ui_font(10)
        bold = ui_font(10, QFont.Weight.DemiBold)
        x, w = 4.0, float(self.width() - 8)
        segs = split_url(self._text)
        cy = self.height() / 2.0
        for i, (txt, kind) in enumerate(segs):
            font = bold if kind == "strong" else f
            fm = QFontMetricsF(font)
            avail = w - (x - 4)
            if avail <= 4:
                break
            shown = fm.elidedText(txt, Qt.TextElideMode.ElideRight, avail) if fm.horizontalAdvance(txt) > avail else txt
            p.setFont(font)
            p.setPen({"strong": T.c("text"), "warn": T.c("warn"), "dim": T.c("mut")}[kind])
            p.drawText(QPointF(x, cy + (fm.ascent() - fm.descent()) / 2.0), shown)
            x += fm.horizontalAdvance(shown)


class Omnibox(QFrame):
    def __init__(self):
        super().__init__()
        self.setFixedHeight(34)
        self.setAttribute(Qt.WidgetAttribute.WA_Hover)
        self._hv, self._fc = 0.0, 0.0
        self.lock = IconButton("lock", "Site controls", 28, 15)
        self.star = IconButton("star", "Bookmark this page (Ctrl+D)", 28, 16)
        self.edit = Edit()
        self.edit.setFrame(False)
        self.edit.setPlaceholderText("Search or enter address")
        self.edit.setClearButtonEnabled(False)
        self.label = UrlLabel()
        self.stack = QStackedWidget()
        self.stack.addWidget(self.label)
        self.stack.addWidget(self.edit)
        lay = QHBoxLayout(self)
        lay.setContentsMargins(5, 0, 5, 0)
        lay.setSpacing(3)
        lay.addWidget(self.lock)
        lay.addWidget(self.stack, 1)
        lay.addWidget(self.star)
        self._g_hv = Glide(self, self._sh, 14)
        self._g_fc = Glide(self, self._sf, 16)
        self.edit.focused.connect(self._on_focus)
        self.label.clicked.connect(self.focus_edit)
        self.edit.textChanged.connect(lambda *_: None)
        self._current = ""
        self._apply_style()
        T.changed.connect(self._apply_style)
        T.changed.connect(self.update)

    def _apply_style(self):
        self.edit.setStyleSheet(
            f"QLineEdit{{background:transparent;border:0;padding:0 2px;color:{T.c('text').name()};"
            f"selection-background-color:{T.c('acc').name()};selection-color:#ffffff}}")

    def _sh(self, v):
        self._hv = v
        self.update()

    def _sf(self, v):
        self._fc = v
        self.update()

    def enterEvent(self, e):
        self._g_hv.to(1.0)
        super().enterEvent(e)

    def leaveEvent(self, e):
        self._g_hv.to(0.0)
        super().leaveEvent(e)

    def focus_edit(self):
        self.stack.setCurrentWidget(self.edit)
        self.edit.setFocus(Qt.FocusReason.MouseFocusReason)
        self.edit.selectAll()

    def _on_focus(self, on):
        self._g_fc.to(1.0 if on else 0.0)
        if not on:
            self.edit.setText(self._current)
            self._show_label()

    def _show_label(self):
        if self._current:
            self.label.set_text(self._current)
            self.stack.setCurrentWidget(self.label)
        else:
            self.stack.setCurrentWidget(self.edit)

    def set_url(self, text):
        """What the page's address is. Ignored while the user is typing."""
        self._current = text
        if not self.edit.hasFocus():
            self.edit.setText(text)
            self._show_label()

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        r = QRectF(self.rect()).adjusted(.5, .5, -.5, -.5)
        bg = T.mix("field", "field_h", self._hv * (1 - self._fc))
        if self._fc > 0:
            bg = T.mix("field", "card" if T.dark else "tab", self._fc * .55)
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(bg)
        p.drawRoundedRect(r, 17, 17)
        if self._fc > 0.01:
            p.setBrush(Qt.BrushStyle.NoBrush)
            p.setPen(QPen(T.c("acc", self._fc * .85), 2))
            p.drawRoundedRect(r.adjusted(1, 1, -1, -1), 16, 16)


# --------------------------------------------------------------------------
# Progress line
# --------------------------------------------------------------------------
class ProgressLine(QWidget):
    def __init__(self, parent):
        super().__init__(parent)
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        self._val, self._alpha, self._target = 0.0, 0.0, 0.0
        self._g_val = Glide(self, self._sv, 5.5)
        self._g_a = Glide(self, self._sa, 9.0)
        self.hide()

    def _sv(self, v):
        self._val = v
        self.update()

    def _sa(self, v):
        self._alpha = v
        if v <= 0.02 and self._target >= 1.0:
            self._val, self._g_val.v, self._g_val.t = 0.0, 0.0, 0.0
            self._alpha = 0.0
            self.hide()
        self.update()

    def start(self):
        self._target = 0.0
        self.show()
        self._g_val.v = 0.0
        self._g_val.to(0.0, instant=True)
        self._g_val.rate = 5.5
        self._g_a.to(1.0)
        self._g_val.to(0.12)

    def progress(self, pct):
        # Real progress only ever moves us forward; we always stay a little behind it so motion never stalls or jumps.
        if not self.isVisible():
            self.start()
        self._g_val.to(max(self._g_val.t, 0.12 + 0.82 * pct / 100.0))

    def finish(self):
        if not self.isVisible():
            return
        self._target = 1.0
        self._g_val.rate = 12.0
        self._g_val.to(1.0)
        QTimer.singleShot(260, lambda: self._g_a.to(0.0))

    def paintEvent(self, _):
        if self._val <= 0:
            return
        p = QPainter(self)
        w = self.width() * min(1.0, self._val)
        a = T.c("acc", self._alpha)
        p.fillRect(QRectF(0, 0, w, self.height()), a)


# --------------------------------------------------------------------------
# Tab strip
# --------------------------------------------------------------------------
class _Tab:
    __slots__ = ("view", "title", "icon", "loading", "x", "w", "tx", "tw", "hv", "cx", "pinned", "audio")

    def __init__(self, view, title):
        self.view, self.title, self.icon, self.loading = view, title, None, False
        self.pinned, self.audio = False, 0      # audio: 0 silent, 1 playing, 2 muted
        self.x = self.w = self.tx = self.tw = 0.0
        self.hv = 0.0
        self.cx = 0.0  # close-button hover


class TabStrip(QWidget):
    currentChanged = pyqtSignal(object)
    closeRequested = pyqtSignal(object)
    newRequested = pyqtSignal()
    contextRequested = pyqtSignal(object, object)
    audioToggleRequested = pyqtSignal(object)

    H, PAD_L, PAD_R, GAP, MIN_W, MAX_W, PIN_W = 42, 10, 10, 2, 44, 228, 42

    def __init__(self):
        super().__init__()
        self.setFixedHeight(self.H)
        self.setMouseTracking(True)
        self.items, self.ghosts, self.cur = [], [], None
        self._hover, self._drag, self._drag_dx, self._press = None, None, 0.0, None
        self._tm = QTimer(self)
        self._tm.setInterval(8)
        self._tm.timeout.connect(self._tick)
        self._last = 0.0
        self.plus = IconButton("plus", "New tab (Ctrl+T)", 30, 17, self)
        self.plus.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.plus.clicked.connect(self.newRequested)
        T.changed.connect(self.update)

    # -- model ----------------------------------------------------------
    def views(self):
        return [t.view for t in self.items]

    def count(self):
        return len(self.items)

    def _find(self, view):
        return next((t for t in self.items if t.view is view), None)

    def index_of(self, view):
        return next((i for i, t in enumerate(self.items) if t.view is view), -1)

    def add_tab(self, view, title="New tab"):
        t = _Tab(view, title)
        self.items.append(t)
        self._layout()
        t.x, t.w = t.tx, 0.0
        self._kick()

    def remove_tab(self, view):
        t = self._find(view)
        if not t:
            return
        self.ghosts.append({"x": t.x, "w": t.w, "a": 1.0, "title": t.title, "icon": t.icon, "active": t is self.current_item()})
        self.items.remove(t)
        if self.cur is t.view:
            self.cur = None
        self._layout()
        self._kick()

    def current_item(self):
        return self._find(self.cur)

    def set_current(self, view):
        if view is not self.cur:
            self.cur = view
            self.update()

    def set_title(self, view, title):
        t = self._find(view)
        if t:
            t.title = title or "New tab"
            self.update()

    def set_icon(self, view, qicon):
        t = self._find(view)
        if t:
            t.icon = qicon.pixmap(QSize(32, 32)) if qicon and not qicon.isNull() else None
            self.update()

    def set_loading(self, view, on):
        t = self._find(view)
        if t and t.loading != on:
            t.loading = on
            self._kick()

    def cycle(self, step):
        if len(self.items) < 2:
            return
        i = (self.index_of(self.cur) + step) % len(self.items)
        self._select(self.items[i])

    def pinned_count(self):
        return sum(1 for t in self.items if t.pinned)

    def is_pinned(self, view):
        t = self._find(view)
        return bool(t and t.pinned)

    def set_pinned(self, view, on):
        t = self._find(view)
        if not t or t.pinned == on:
            return
        t.pinned = on
        self.items.sort(key=lambda it: not it.pinned)   # stable: pinned tabs gather on the left, order kept
        self._layout()
        self._kick()

    def set_audio(self, view, state):
        t = self._find(view)
        if t and t.audio != state:
            t.audio = state
            self.update()

    def audio_of(self, view):
        t = self._find(view)
        return t.audio if t else 0

    # -- layout / animation --------------------------------------------
    def _layout(self, immediate=False):
        n = len(self.items)
        if not n:
            return
        pins = self.pinned_count()
        free = n - pins
        avail = self.width() - self.PAD_L - self.PAD_R - 40 - pins * (self.PIN_W + self.GAP)
        w = max(self.MIN_W, min(self.MAX_W, (avail - max(0, free - 1) * self.GAP) / free)) if free else 0
        x = float(self.PAD_L)
        for t in self.items:
            tw = self.PIN_W if t.pinned else w
            if t is self._drag:
                x += tw + self.GAP
                t.tw = tw
                continue
            t.tx, t.tw = x, tw
            if immediate:
                t.x, t.w = t.tx, t.tw
            x += tw + self.GAP
        self._place_plus()

    def _place_plus(self):
        if self.items:
            last = max(self.items, key=lambda t: t.x + t.w)
            x = last.x + last.w + 6
        else:
            x = self.PAD_L
        self.plus.move(int(min(x, self.width() - self.PAD_R - 30)), (self.H - 30) // 2)

    def resizeEvent(self, e):
        self._layout(immediate=True)
        super().resizeEvent(e)

    def _kick(self):
        if not self._tm.isActive():
            self._last = time.perf_counter()
            self._tm.start()

    def _tick(self):
        now = time.perf_counter()
        dt = min(0.05, now - self._last)
        self._last = now
        busy = False
        for t in self.items:
            if t is not self._drag:
                t.x, t.w = approach(t.x, t.tx, 20, dt), approach(t.w, t.tw, 20, dt)
                if abs(t.x - t.tx) < .25 and abs(t.w - t.tw) < .25:
                    t.x, t.w = t.tx, t.tw
                else:
                    busy = True
            t.hv = approach(t.hv, 1.0 if t is self._hover else 0.0, 18, dt)
            if abs(t.hv - (1.0 if t is self._hover else 0.0)) > .01:
                busy = True
            if t.loading:
                busy = True
        for g in self.ghosts[:]:
            g["a"] = approach(g["a"], 0.0, 17, dt)
            g["w"] = approach(g["w"], g["w"] * .7, 6, dt)
            if g["a"] < .03:
                self.ghosts.remove(g)
            else:
                busy = True
        self._place_plus()
        self.update()
        if not busy:
            self._tm.stop()

    # -- painting ------------------------------------------------------
    def _close_rect(self, t):
        return QRectF(t.x + t.w - 28, (self.H - 20) / 2, 20, 20)

    def _audio_rect(self, t):
        if t.audio and not t.pinned and t.w >= 110:
            return QRectF(t.x + t.w - 50, (self.H - 20) / 2, 20, 20)
        return None

    def _paint_tab(self, p, x, w, title, icon, loading, active, hv, cx, alpha=1.0, show_close=True, pinned=False, audio=0):
        if w < 6:
            return
        p.setOpacity(alpha)
        r = QRectF(x, 5, w, self.H - 10)
        if active:
            p.setPen(QPen(T.c("line"), 1))
            p.setBrush(T.c("tab"))
            p.drawRoundedRect(r.adjusted(.5, .5, -.5, -.5), 9, 9)
        elif hv > .01:
            col = T.c("hover")
            col.setAlphaF(col.alphaF() * hv)
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(col)
            p.drawRoundedRect(r, 9, 9)
        p.setPen(Qt.PenStyle.NoPen)
        close_vis = show_close and not pinned and w >= 80 and (active or hv > .05)
        compact = w < 70 or pinned
        audio_slot = bool(audio) and not pinned and w >= 110
        ix = r.center().x() - 8 if (compact and not close_vis) else r.left() + 11
        iy = r.center().y() - 8
        if loading:
            p.setPen(QPen(T.c("acc"), 2, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
            ang = int((time.perf_counter() * 420) % 360)
            p.drawArc(QRectF(ix + 2, iy + 2, 12, 12), -ang * 16, 270 * 16)
        elif icon is not None:
            p.drawPixmap(QRectF(ix, iy, 16, 16), icon, QRectF(icon.rect()))
        else:
            draw_icon(p, "globe", QRectF(ix, iy, 16, 16), T.c("faint"))
        if audio and not audio_slot:      # no room for a button: a small badge on the corner of the icon
            draw_icon(p, "volume-off" if audio == 2 else "volume", QRectF(ix + 8, iy + 8, 10, 10), T.c("faint") if audio == 2 else T.c("acc"))
        if not compact:
            tx = r.left() + 34
            right = r.right() - (54 if audio_slot else 30 if close_vis else 10)
            if right - tx > 12:
                f = ui_font(9.2, QFont.Weight.Medium if active else QFont.Weight.Normal)
                fm = QFontMetricsF(f)
                txt = fm.elidedText(title, Qt.TextElideMode.ElideRight, right - tx)
                p.setFont(f)
                p.setPen(T.c("text") if active else T.mix("mut", "text", hv))
                p.drawText(QPointF(tx, r.center().y() + (fm.ascent() - fm.descent()) / 2.0), txt)
        if audio_slot:
            a = QRectF(r.right() - 50, r.center().y() - 10, 20, 20)
            draw_icon(p, "volume-off" if audio == 2 else "volume", a.adjusted(2, 2, -2, -2), T.c("faint") if audio == 2 else T.c("acc"))
        if close_vis:
            c = QRectF(r.right() - 28, r.center().y() - 10, 20, 20)
            if cx > .01:
                col = T.c("press")
                col.setAlphaF(col.alphaF() * cx)
                p.setPen(Qt.PenStyle.NoPen)
                p.setBrush(col)
                p.drawEllipse(c)
            draw_icon(p, "close", c.adjusted(4, 4, -4, -4), T.mix("mut", "text", max(cx, .35 if active else 0)))
        p.setOpacity(1.0)

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.setRenderHint(QPainter.RenderHint.TextAntialiasing)
        for g in self.ghosts:
            self._paint_tab(p, g["x"], g["w"], g["title"], g["icon"], False, g["active"], 0, 0, g["a"], False)
        for t in self.items:
            if t is not self._drag:
                self._paint_tab(p, t.x, t.w, t.title, t.icon, t.loading, t.view is self.cur, t.hv, t.cx, 1.0, True, t.pinned, t.audio)
        if self._drag:
            t = self._drag
            self._paint_tab(p, t.x, t.w, t.title, t.icon, t.loading, True, 1.0, t.cx, 1.0, True, t.pinned, t.audio)

    # -- mouse ----------------------------------------------------------
    def _at(self, pos):
        for t in self.items:
            if t.x <= pos.x() <= t.x + t.w:
                return t
        return None

    def _select(self, t):
        if t.view is not self.cur:
            self.cur = t.view
            self.update()
            self.currentChanged.emit(t.view)

    def mousePressEvent(self, e):
        t = self._at(e.position())
        self._press = None
        if not t:
            return
        if e.button() == Qt.MouseButton.LeftButton:
            on_close = (not t.pinned) and t.w >= 80 and (t.view is self.cur or t.hv > .05) and self._close_rect(t).contains(e.position())
            ar = self._audio_rect(t)
            on_audio = bool(ar and ar.contains(e.position()))
            self._press = (t, e.position(), "audio" if on_audio else on_close)
            if not on_close and not on_audio:
                self._select(t)
        elif e.button() == Qt.MouseButton.MiddleButton:
            self._press = (t, e.position(), "middle")

    def mouseMoveEvent(self, e):
        pos = e.position()
        t = self._at(pos)
        if t is not self._hover:
            self._hover = t
            self._kick()
        for it in self.items:
            want = 1.0 if (t is it and self._close_rect(it).contains(pos)) else 0.0
            if abs(it.cx - want) > .01:
                it.cx = approach(it.cx, want, 40, .016)
                self._kick()
        if self._press and e.buttons() & Qt.MouseButton.LeftButton and self._press[2] is False:
            it, start, _ = self._press
            if self._drag is None and abs(pos.x() - start.x()) > 6:
                self._drag, self._drag_dx = it, start.x() - it.x
            if self._drag:
                d = self._drag
                d.x = max(self.PAD_L, min(pos.x() - self._drag_dx, self.width() - self.PAD_R - d.w - 36))
                mid = d.x + d.w / 2
                slot = sum(1 for o in self.items if o is not d and o.tx + o.tw / 2 < mid)
                pins = self.pinned_count()
                slot = min(slot, pins - 1) if d.pinned else max(slot, pins)      # pinned tabs stay on the left
                slot = max(0, min(len(self.items) - 1, slot))
                if self.items.index(d) != slot:
                    self.items.remove(d)
                    self.items.insert(slot, d)
                self._layout()
                self._kick()
                self.update()
        self.setCursor(Qt.CursorShape.ArrowCursor)

    def leaveEvent(self, e):
        self._hover = None
        for it in self.items:
            it.cx = 0.0
        self._kick()
        super().leaveEvent(e)

    def mouseReleaseEvent(self, e):
        if self._drag:
            self._drag = None
            self._layout()
            self._kick()
        elif self._press:
            t, _, mode = self._press
            if mode == "middle" and self._at(e.position()) is t and e.button() == Qt.MouseButton.MiddleButton:
                self.closeRequested.emit(t.view)
            elif mode is True and self._at(e.position()) is t and self._close_rect(t).contains(e.position()):
                self.closeRequested.emit(t.view)
            elif mode == "audio":
                ar = self._audio_rect(t)
                if ar and ar.contains(e.position()):
                    self.audioToggleRequested.emit(t.view)
        self._press = None

    def mouseDoubleClickEvent(self, e):
        if self._at(e.position()) is None:
            self.newRequested.emit()

    def contextMenuEvent(self, e):
        t = self._at(QPointF(e.pos()))
        if t:
            self.contextRequested.emit(t.view, e.globalPos())

    def event(self, e):
        if e.type() == QEvent.Type.ToolTip:
            t = self._at(QPointF(e.pos()))
            if t and t.title:
                QToolTip.showText(e.globalPos(), t.title, self)
            else:
                QToolTip.hideText()
            return True
        return super().event(e)


# --------------------------------------------------------------------------
# Chrome container (paints the toolbar background, owns the progress line)
# --------------------------------------------------------------------------
class Chrome(QWidget):
    def __init__(self):
        super().__init__()
        self.progress = ProgressLine(self)
        T.changed.connect(self.update)

    def resizeEvent(self, e):
        self.progress.setGeometry(0, self.height() - 2, self.width(), 2)
        super().resizeEvent(e)

    def paintEvent(self, _):
        p = QPainter(self)
        p.fillRect(self.rect(), T.c("bar"))
        p.fillRect(0, self.height() - 1, self.width(), 1, T.c("line"))


# --------------------------------------------------------------------------
# Overlays: toast, hover link, find bar
# --------------------------------------------------------------------------
class Pill(QWidget):
    """A floating rounded label that eases in and out. Used for toasts and the hovered-link readout."""
    M = 16  # transparent margin so the shadow can fade out instead of being clipped

    def __init__(self, parent, hold_ms=2600, elide_frac=1.0):
        super().__init__(parent)
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        self._text, self._shown, self._a, self._off = "", "", 0.0, 12.0
        self._hold, self._elide = hold_ms, elide_frac
        self._g = Glide(self, self._set, 14)
        self._timer = QTimer(self)
        self._timer.setSingleShot(True)
        self._timer.timeout.connect(self.hide_now)
        self._anchor = "bottom-center"
        self.hide()

    def _set(self, v):
        self._a = v
        self._off = (1 - v) * 12
        if v <= 0.01 and self._g.t == 0.0:
            self.hide()
        self.update()

    def show_text(self, text, hold=True):
        self._text = text
        fm = QFontMetricsF(ui_font(9.5, QFont.Weight.Medium))
        maxw = max(120, int(self.parentWidget().width() * self._elide) - 40)
        self._shown = fm.elidedText(text, Qt.TextElideMode.ElideMiddle, maxw)
        self.resize(int(fm.horizontalAdvance(self._shown)) + 34 + 2 * self.M, 34 + 2 * self.M)
        self.reposition()
        self.show()
        self.raise_()
        self._g.to(1.0)
        self._timer.stop()
        if hold:
            self._timer.start(self._hold)

    def hide_now(self):
        self._g.to(0.0)

    def reposition(self):
        pw, ph = self.parentWidget().width(), self.parentWidget().height()
        m = self.M
        if self._anchor == "bottom-left":
            self.move(14 - m, ph - self.height() - 14 + m)
        else:
            self.move((pw - self.width()) // 2, ph - self.height() - 26 + m)

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.setOpacity(self._a)
        m = self.M
        r = QRectF(m, m + self._off, self.width() - 2 * m, self.height() - 2 * m)
        soft_shadow(p, r, 17, spread=m - 2, strength=.24 if T.dark else .15, dy=4)
        p.setPen(QPen(T.c("line"), 1))
        p.setBrush(T.c("card"))
        p.drawRoundedRect(r, 17, 17)
        p.setFont(ui_font(9.5, QFont.Weight.Medium))
        p.setPen(T.c("text"))
        p.drawText(r, Qt.AlignmentFlag.AlignCenter, self._shown)


class FindBar(QFrame):
    queryChanged = pyqtSignal(str)
    step = pyqtSignal(bool)   # True = forward
    closed = pyqtSignal()

    def __init__(self, parent):
        super().__init__(parent)
        self.M = 18
        self.setFixedSize(372 + 2 * self.M, 42 + 2 * self.M)
        self._a, self._off, self._base_y, self.top = 0.0, -10.0, 12, 10
        self._g = Glide(self, self._set, 15)
        self.edit = Edit()
        self.edit.setFrame(False)
        self.edit.setPlaceholderText("Find in page")
        self.count = QLabel("")
        self.count.setMinimumWidth(52)
        self.count.setAlignment(Qt.AlignmentFlag.AlignRight | Qt.AlignmentFlag.AlignVCenter)
        self.prev = IconButton("chevron-up", "Previous (Shift+Enter)", 28, 16)
        self.next = IconButton("chevron-down", "Next (Enter)", 28, 16)
        self.shut = IconButton("close", "Close (Esc)", 28, 15)
        lay = QHBoxLayout(self)
        lay.setContentsMargins(34 + self.M, self.M, 7 + self.M, self.M)
        lay.setSpacing(2)
        lay.addWidget(self.edit, 1)
        lay.addWidget(self.count)
        lay.addWidget(self.prev)
        lay.addWidget(self.next)
        lay.addWidget(self.shut)
        self.edit.textChanged.connect(self.queryChanged)
        self.edit.returnPressed.connect(lambda: self.step.emit(not (QApplication.keyboardModifiers() & Qt.KeyboardModifier.ShiftModifier)))
        self.prev.clicked.connect(lambda: self.step.emit(False))
        self.next.clicked.connect(lambda: self.step.emit(True))
        self.shut.clicked.connect(self.dismiss)
        self.edit.focused.connect(lambda *_: None)
        self._style()
        T.changed.connect(self._style)
        self.hide()

    def _style(self):
        self.edit.setStyleSheet(f"QLineEdit{{background:transparent;border:0;color:{T.c('text').name()};"
                                f"selection-background-color:{T.c('acc').name()};selection-color:#fff}}")
        self.count.setStyleSheet(f"color:{T.c('mut').name()};font-size:12px;background:transparent")
        self.update()

    def _set(self, v):
        self._a, self._off = v, (1 - v) * -10
        if v <= .01 and self._g.t == 0:
            self.hide()
        self.update()
        self.move(self.x(), self._base_y + int(self._off))

    def present(self):
        self.reposition()
        self.show()
        self.raise_()
        self._g.to(1.0)
        self.edit.setFocus()
        self.edit.selectAll()

    def dismiss(self):
        self._g.to(0.0)
        self.closed.emit()

    def reposition(self):
        self._base_y = self.top - self.M
        self.move(self.parentWidget().width() - self.width() - 16 + self.M, self._base_y + int(self._off))

    def set_count(self, active, total):
        self.count.setText("" if not self.edit.text() else (f"{active} of {total}" if total else "No results"))

    def keyPressEvent(self, e):
        if e.key() == Qt.Key.Key_Escape:
            self.dismiss()
        else:
            super().keyPressEvent(e)

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.setOpacity(self._a)
        m = self.M
        r = QRectF(m, m, self.width() - 2 * m, self.height() - 2 * m)
        soft_shadow(p, r, 14, spread=m - 2, strength=.26 if T.dark else .16, dy=5)
        p.setPen(QPen(T.c("line"), 1))
        p.setBrush(T.c("card"))
        p.drawRoundedRect(r, 14, 14)
        draw_icon(p, "search", QRectF(m + 14, self.height() / 2 - 8, 16, 16), T.c("mut"))


# --------------------------------------------------------------------------
# Sheet: modal confirmation card that slides up over a dimmed window
# --------------------------------------------------------------------------
class PushButton(QAbstractButton):
    def __init__(self, text, kind="plain"):
        super().__init__()
        self.setText(text)
        self.kind = kind
        self._hv = self._pr = 0.0
        self.setFixedHeight(42)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self._g_hv = Glide(self, self._sh, 18)
        self._g_pr = Glide(self, self._sp, 30)
        self.pressed.connect(lambda: self._g_pr.to(1.0))
        self.released.connect(lambda: self._g_pr.to(0.0))

    def _sh(self, v):
        self._hv = v
        self.update()

    def _sp(self, v):
        self._pr = v
        self.update()

    def enterEvent(self, e):
        self._g_hv.to(1.0)
        super().enterEvent(e)

    def leaveEvent(self, e):
        self._g_hv.to(0.0)
        super().leaveEvent(e)

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        s = 1.0 - 0.03 * self._pr
        r = QRectF(self.rect()).adjusted(.5, .5, -.5, -.5)
        c = r.center()
        p.translate(c)
        p.scale(s, s)
        p.translate(-c)
        k = self.kind
        if k == "pri":
            bg, fg = T.mix("acc", "text", .0 + .12 * self._hv), QColor("#ffffff")
        elif k == "dng":
            bg, fg = T.mix("bad", "text", .12 * self._hv), QColor("#ffffff")
        elif k == "danger-text":
            bg, fg = T.mix("field", "field_h", self._hv), T.c("bad")
        else:
            bg, fg = T.mix("field", "field_h", self._hv), T.c("text")
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(bg)
        p.drawRoundedRect(r, 11, 11)
        p.setFont(ui_font(10, QFont.Weight.Medium))
        p.setPen(fg)
        p.drawText(r, Qt.AlignmentFlag.AlignCenter, self.text())


class Badge(QWidget):
    def __init__(self, icon, tone):
        super().__init__()
        self.icon, self.tone, self._s = icon, tone, 0.6
        self.setFixedSize(60, 60)
        self._g = Glide(self, self._set, 11, 0.6)

    def _set(self, v):
        self._s = v
        self.update()

    def pop(self):
        self._g.to(1.0)

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        c = QPointF(self.width() / 2, self.height() / 2)
        s = self._s
        p.translate(c)
        p.scale(s, s)
        p.translate(-c)
        col = T.c(self.tone)
        p.setPen(Qt.PenStyle.NoPen)
        fill = QColor(col)
        fill.setAlphaF(.17)
        p.setBrush(fill)
        p.drawEllipse(QRectF(2, 2, 56, 56))
        draw_icon(p, self.icon, QRectF(16, 16, 28, 28), col)


class Sheet(QWidget):
    done = pyqtSignal(object)

    def __init__(self, root, icon="info", tone="acc", title="", body="", rows=(), buttons=(), cancel=None, field=None):
        super().__init__(root)
        self._cancel, self._first = cancel, (buttons[0][2] if buttons else None)
        self.edit = None
        self._a = 0.0
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self.card = QFrame(self)
        self.card.setFixedWidth(404)
        self.card.setStyleSheet("QFrame{background:transparent}")
        lay = QVBoxLayout(self.card)
        lay.setContentsMargins(26, 28, 26, 22)
        lay.setSpacing(0)
        self.badge = Badge(icon, tone)
        lay.addWidget(self.badge, 0, Qt.AlignmentFlag.AlignHCenter)
        lay.addSpacing(14)
        t = QLabel(title)
        t.setWordWrap(True)
        t.setAlignment(Qt.AlignmentFlag.AlignCenter)
        t.setTextFormat(Qt.TextFormat.PlainText)
        t.setStyleSheet(f"color:{T.c('text').name()};font-size:17px;font-weight:650;background:transparent")
        lay.addWidget(t)
        if body:
            lay.addSpacing(6)
            b = QLabel(body)
            b.setWordWrap(True)
            b.setAlignment(Qt.AlignmentFlag.AlignCenter)
            b.setTextFormat(Qt.TextFormat.PlainText)
            b.setStyleSheet(f"color:{T.c('mut').name()};font-size:13px;background:transparent")
            lay.addWidget(b)
        if rows:
            lay.addSpacing(14)
            box = QFrame()
            box.setStyleSheet(f"QFrame{{background:{T.c('field').name()};border-radius:12px}}")
            bl = QVBoxLayout(box)
            bl.setContentsMargins(12, 10, 12, 10)
            bl.setSpacing(8)
            for level, text in rows:
                row = QWidget()
                row.setStyleSheet("background:transparent")
                h = QHBoxLayout(row)
                h.setContentsMargins(0, 0, 0, 0)
                h.setSpacing(9)
                ico = QLabel()
                tone2 = {"danger": "bad", "warn": "warn", "info": "mut"}.get(level, "mut")
                ico.setPixmap(pix({"danger": "shield-alert", "warn": "alert"}.get(level, "info"), T.c(tone2), 16, self.devicePixelRatioF()))
                ico.setFixedSize(16, 16)
                ico.setAlignment(Qt.AlignmentFlag.AlignTop)
                lab = QLabel(text)
                lab.setWordWrap(True)
                lab.setTextFormat(Qt.TextFormat.PlainText)
                lab.setStyleSheet(f"color:{T.c('text').name()};font-size:12.5px;background:transparent")
                h.addWidget(ico, 0, Qt.AlignmentFlag.AlignTop)
                h.addWidget(lab, 1)
                bl.addWidget(row)
            lay.addWidget(box)
        if field:
            lay.addSpacing(14)
            self.edit = QLineEdit()
            self.edit.setPlaceholderText(field.get("placeholder", ""))
            if field.get("password"):
                self.edit.setEchoMode(QLineEdit.EchoMode.Password)
            self.edit.setFixedHeight(42)
            self.edit.setStyleSheet(
                f"QLineEdit{{background:{T.c('field').name()};color:{T.c('text').name()};border:1px solid transparent;"
                f"border-radius:11px;padding:0 13px;font-size:13.5px;selection-background-color:{T.c('acc').name()}}}"
                f"QLineEdit:focus{{border:1px solid {T.c('acc').name()}}}")
            self.edit.returnPressed.connect(lambda: self._go(self._first))
            lay.addWidget(self.edit)
        lay.addSpacing(22)
        for i, (label, kind, value) in enumerate(buttons):
            btn = PushButton(label, kind)
            btn.clicked.connect(lambda _=False, v=value: self._go(v))
            lay.addWidget(btn)
            if i < len(buttons) - 1:
                lay.addSpacing(8)
        self.card.adjustSize()
        self.fx = QGraphicsOpacityEffect(self.card)
        self.fx.setOpacity(0.0)
        self.card.setGraphicsEffect(self.fx)
        self._g = Glide(self, self._set, 13)
        self._closing = False
        self.hide()

    def _layout_card(self):
        self.card.adjustSize()
        self._base_y = (self.height() - self.card.height()) // 2
        self.card.move((self.width() - self.card.width()) // 2, self._base_y + int((1 - self._a) * 26))

    def resizeEvent(self, e):
        self._layout_card()
        super().resizeEvent(e)

    def _set(self, v):
        self._a = v
        self.fx.setOpacity(min(1.0, v * 1.25))
        self.card.move(self.card.x(), self._base_y + int((1 - v) * 26))
        if v <= .004 and self._closing:
            self.hide()
            self.deleteLater()
        self.update()

    def _go(self, value):
        """A button was pressed. With a text field the answer is (button value, typed text)."""
        self.finish((value, self.edit.text()) if self.edit is not None else value)

    def present(self):
        self.setGeometry(self.parentWidget().rect())
        self._layout_card()
        self.show()
        self.raise_()
        if self.edit is not None:
            QTimer.singleShot(60, self.edit.setFocus)
        else:
            self.setFocus()
        self._g.to(1.0)
        QTimer.singleShot(90, self.badge.pop)

    def finish(self, value):
        if self._closing:
            return
        self._closing = True
        self._g.rate = 20
        self._g.to(0.0)
        self.done.emit(value)

    def event(self, e):
        if e.type() == QEvent.Type.ShortcutOverride and e.key() in (Qt.Key.Key_Escape, Qt.Key.Key_Return, Qt.Key.Key_Enter):
            e.accept()
            return True
        return super().event(e)

    def keyPressEvent(self, e):
        if e.key() == Qt.Key.Key_Escape:
            self._go(self._cancel)
        elif e.key() in (Qt.Key.Key_Return, Qt.Key.Key_Enter) and self._first is not None:
            self._go(self._first)
        else:
            e.accept()

    def mousePressEvent(self, e):
        e.accept()

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.fillRect(self.rect(), T.c("shadow", .46 * self._a))
        r = QRectF(self.card.geometry())
        soft_shadow(p, r, 22, spread=34, strength=.30 if T.dark else .22, dy=14, scale=self._a)
        p.setOpacity(min(1.0, self._a * 1.25))
        p.setPen(QPen(T.c("line"), 1))
        p.setBrush(T.c("card"))
        p.drawRoundedRect(r, 22, 22)


# --------------------------------------------------------------------------
# Global stylesheet (menus, tooltips, the address suggestions popup)
# --------------------------------------------------------------------------
def stylesheet():
    c = lambda n: T.c(n).name(QColor.NameFormat.HexArgb) if T.c(n).alpha() < 255 else T.c(n).name()
    rgba = lambda n: f"rgba({T.c(n).red()},{T.c(n).green()},{T.c(n).blue()},{T.c(n).alpha()})"
    return f"""
QToolTip{{background:{c('card')};color:{c('text')};border:1px solid {rgba('line')};border-radius:8px;padding:5px 9px;font-size:12px}}
QMenu{{background:{c('card')};border:1px solid {rgba('line')};border-radius:12px;padding:6px;color:{c('text')}}}
QMenu::item{{padding:7px 28px 7px 14px;border-radius:7px;margin:1px 0}}
QMenu::item:selected{{background:{c('acc')};color:#ffffff}}
QMenu::item:disabled{{color:{c('faint')}}}
QMenu::separator{{height:1px;background:{rgba('line')};margin:6px 8px}}
QMenu::indicator{{width:14px;height:14px;margin-left:6px}}
QAbstractItemView{{background:{c('card')};color:{c('text')};border:1px solid {rgba('line')};border-radius:12px;padding:5px;outline:0;
selection-background-color:{c('acc')};selection-color:#ffffff}}
QAbstractItemView::item{{padding:7px 10px;border-radius:7px}}
QScrollBar:vertical{{background:transparent;width:10px;margin:4px 2px}}
QScrollBar::handle:vertical{{background:{rgba('hover')};border-radius:3px;min-height:30px}}
QScrollBar::add-line:vertical,QScrollBar::sub-line:vertical{{height:0}}
"""


def soften_menu(menu):
    """Rounded, shadow-free popup menus (needs a compositing window system; harmless without)."""
    menu.setWindowFlag(Qt.WindowType.FramelessWindowHint, True)
    menu.setWindowFlag(Qt.WindowType.NoDropShadowWindowHint, True)
    menu.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground, True)
    return menu
