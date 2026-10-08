"""
shield_ui.py: the native widgets that make up the browser chrome.

Design rules used everywhere in here:
  * one icon set (shield_icons.py), drawn from SVG so it stays sharp at any scale
  * one palette per theme (Theme), nothing hard-coded in the widgets
  * motion is never linear: everything moves on springs (shield_motion.py) that keep their velocity, so any
    animation can be interrupted halfway (hover out while hovering in, close a split while it opens) and the
    motion carries on smoothly. One shared frame clock steps all of them in lockstep.
"""
import math
import re
import time

from PyQt6.QtCore import QEvent, QObject, QPoint, QPointF, QRect, QRectF, QSize, Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QBrush, QColor, QFont, QFontMetricsF, QLinearGradient, QPainter, QPainterPath, QPen, QPixmap, QRadialGradient
from PyQt6.QtSvg import QSvgRenderer
from PyQt6.QtWidgets import (
    QAbstractButton, QApplication, QFrame, QGraphicsOpacityEffect, QHBoxLayout, QLabel, QLineEdit,
    QStackedWidget, QToolTip, QVBoxLayout, QWidget,
)

from shield_core import site_of
from shield_icons import svg_doc
from shield_fx import DropReveal, Ripples, ease_in_out, ease_out, fx_on, shake_offset
from shield_motion import Spring, Ticker, FrameClock, clamp01, iround, smoothstep, snap_rect, spring_step, window
from shield_sound import play as play_sound


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
    """A single float that springs toward a target on the shared frame clock. Same interface as always (to(),
    .v, .t, .rate), but retargeting mid-flight keeps the velocity, so nothing ever snaps or restarts."""

    def __init__(self, owner, apply, rate=16.0, value=0.0, eps=0.002, bounce=0.0):
        self.s = Spring(value, rate, 1.0 - bounce, eps)
        self.apply = apply
        self._run = self._step

    @property
    def v(self):
        return self.s.x

    @v.setter
    def v(self, val):
        self.s.x, self.s.v = float(val), 0.0

    @property
    def t(self):
        return self.s.t

    @t.setter
    def t(self, val):
        self.s.t = float(val)

    @property
    def rate(self):
        return self.s.omega

    @rate.setter
    def rate(self, val):
        self.s.omega = val * 1.5

    def to(self, target, instant=False):
        self.s.t = float(target)
        if instant:
            self.s.jump(target)
            FrameClock.get().remove(self._run)
            self.apply(self.s.x)
            return
        FrameClock.get().add(self._run)

    def _step(self, dt):
        alive = self.s.step(dt)
        self.apply(self.s.x)
        return alive


# --------------------------------------------------------------------------
# Icons
# --------------------------------------------------------------------------
_icons = {}
_masks = {}


def _mask(name, size, dpr):
    """The icon's shape alone (black with alpha), parsed from SVG exactly once per size."""
    key = (name, size, round(dpr, 2))
    pm = _masks.get(key)
    if pm is None:
        px = max(1, int(size * dpr))
        pm = QPixmap(px, px)
        pm.fill(Qt.GlobalColor.transparent)
        pm.setDevicePixelRatio(dpr)
        r = QSvgRenderer(svg_doc(name, "#000000").encode())
        p = QPainter(pm)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        r.render(p, QRectF(0, 0, size, size))
        p.end()
        if len(_masks) > 400:
            _masks.clear()
        _masks[key] = pm
    return pm


def pix(name, color, size, dpr=2.0):
    """An SVG icon tinted to any colour (alpha included), cached.

    Hover and press blend colours continuously, so an exact-colour cache missed on every frame and re-parsed the SVG
    each time (a visible hitch on every hover). Now the shape is parsed once and colours are snapped to 6 bits per
    channel (invisible to the eye, and a whole hover transition only ever needs about 20 distinct tints)."""
    q = color.rgba() & 0xFCFCFCFC
    key = (name, q, size, round(dpr, 2))
    pm = _icons.get(key)
    if pm is None:
        col = QColor.fromRgba(q | ((q >> 6) & 0x03030303))       # top bits repeated: white stays white, black stays black
        pm = QPixmap(_mask(name, size, dpr))
        p = QPainter(pm)
        p.setCompositionMode(QPainter.CompositionMode.CompositionMode_SourceIn)
        p.fillRect(QRectF(0, 0, size, size), col)
        p.end()
        if len(_icons) > 600:
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


_shadows = {}


def soft_shadow(p, rect, radius, spread=26.0, strength=0.2, dy=10.0, scale=1.0):
    """A smooth drop shadow: many near-invisible layers instead of a few visible steps.

    Those 18 anti-aliased layers used to be repainted on every frame of every overlay animation. They are now drawn
    once per size into a pixmap and blitted, and `scale` (the fade) is just the painter's opacity."""
    if scale <= 0.003:
        return
    dev = p.device()
    dpr = max(1.0, dev.devicePixelRatioF() if hasattr(dev, "devicePixelRatioF") else 1.0)
    w, h = round(rect.width() * 2) / 2.0, round(rect.height() * 2) / 2.0
    key = (w, h, radius, spread, round(strength, 3), dy, T.dark, round(dpr, 2))
    mg = int(math.ceil(spread + abs(dy))) + 2
    pm = _shadows.get(key)
    if pm is None:
        pm = QPixmap(int((math.ceil(w) + 2 * mg) * dpr), int((math.ceil(h) + 2 * mg) * dpr))
        pm.setDevicePixelRatio(dpr)
        pm.fill(Qt.GlobalColor.transparent)
        q = QPainter(pm)
        q.setRenderHint(QPainter.RenderHint.Antialiasing)
        q.setPen(Qt.PenStyle.NoPen)
        n = 18
        col = T.c("shadow")
        col.setAlphaF(max(0.0, min(1.0, strength / n)))
        q.setBrush(col)
        base = QRectF(mg, mg, w, h)
        for i in range(n, 0, -1):
            grow = spread * i / n
            q.drawRoundedRect(base.adjusted(-grow, -grow + dy, grow, grow + dy), radius + grow, radius + grow)
        q.end()
        if len(_shadows) > 40:
            _shadows.clear()
        _shadows[key] = pm
    p.save()
    p.setOpacity(p.opacity() * min(1.0, scale))
    p.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform, True)
    p.drawPixmap(QPointF(rect.x() - mg, rect.y() - mg), pm)
    p.restore()


def quality(p):
    """Painter settings for anything that moves: sub-pixel text and image positions, so edges glide between pixels
    instead of stepping from one to the next."""
    p.setRenderHint(QPainter.RenderHint.Antialiasing)
    p.setRenderHint(QPainter.RenderHint.TextAntialiasing)
    p.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform)
    sub = getattr(QPainter.RenderHint, "VerticalSubpixelPositioning", None)
    if sub is not None:
        p.setRenderHint(sub)


def ui_font(pt=9.5, weight=None):
    f = QFont(QApplication.font())
    f.setPointSizeF(pt)
    f.setHintingPreference(QFont.HintingPreference.PreferNoHinting)     # hinted glyphs snap to whole pixels and shimmer in motion
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
        # the extra life: a ripple where it is pressed, and four things the program can ask for (pulse, burst, glint, shake)
        self.silent = False                       # True: pressing makes no click sound (the caller plays a better one)
        self._rip = Ripples(self)
        self._rings, self._burst, self._glint, self._shake = [], None, None, None
        self._pop = Spring(0.0, 17.0, 0.36, 0.003)       # the icon's little jump: kicked, then it springs back with a wobble
        self._fx_run = self._fx_step

    # -- extra life ---------------------------------------------------------------
    def mousePressEvent(self, e):
        if e.button() == Qt.MouseButton.LeftButton and self.isEnabled():
            if not self.silent:
                play_sound("click")
            if fx_on():
                self._rip.add(e.position().x(), e.position().y())
        super().mousePressEvent(e)

    def pulse(self, rings=2):
        """Rings spread out from the icon like a drop landing in water. For something that just turned on or arrived."""
        if fx_on():
            self._rings += [-0.17 * i for i in range(rings)]      # a negative age means "not started yet"
            FrameClock.get().add(self._fx_run)

    def burst(self):
        """The icon jumps and throws off sparks. For a small celebration (a bookmark saved)."""
        if fx_on():
            self._burst = 0.0
            self._pop.x, self._pop.v = 0.0, 15.0
            FrameClock.get().add(self._fx_run)

    def glint(self):
        """A band of light sweeps across the icon once."""
        if fx_on():
            self._glint = 0.0
            FrameClock.get().add(self._fx_run)

    def shake(self):
        """The icon shakes side to side: no."""
        if fx_on():
            self._shake = 0.0
            FrameClock.get().add(self._fx_run)

    def bounce(self):
        """The icon drops a little and bounces: it arrived."""
        if fx_on():
            self._pop.x, self._pop.v = -0.30, 0.0
            FrameClock.get().add(self._fx_run)

    def _fx_step(self, dt):
        busy = self._pop.step(dt)
        self._rings = [a + dt for a in self._rings if a + dt < 0.72]
        if self._rings:
            busy = True
        if self._burst is not None:
            self._burst += dt
            if self._burst > 0.6:
                self._burst = None
            else:
                busy = True
        if self._glint is not None:
            self._glint += dt
            if self._glint > 0.7:
                self._glint = None
            else:
                busy = True
        if self._shake is not None:
            self._shake += dt
            if self._shake > 0.6:
                self._shake = None
            else:
                busy = True
        self.update()
        return busy

    def _paint_glint(self, p, box):
        dpr = p.device().devicePixelRatioF() if hasattr(p.device(), "devicePixelRatioF") else 2.0
        size = int(round(box.width()))
        tint = QColor(255, 255, 255) if T.dark else QColor(T.c("acc"))
        lit = QPixmap(pix(self._name, tint, size, max(1.0, dpr)))      # a copy: the cached one stays untouched
        c = -0.3 + 1.6 * ease_in_out(self._glint / 0.62)
        w, side = 0.3, float(size)
        g = QLinearGradient(QPointF(side * (c - w), side * (c - w)), QPointF(side * (c + w), side * (c + w)))
        g.setColorAt(0.0, QColor(255, 255, 255, 0))
        g.setColorAt(0.5, QColor(255, 255, 255, 240))
        g.setColorAt(1.0, QColor(255, 255, 255, 0))
        q = QPainter(lit)
        q.setCompositionMode(QPainter.CompositionMode.CompositionMode_DestinationIn)
        q.fillRect(QRectF(0, 0, side, side), QBrush(g))
        q.end()
        p.drawPixmap(QPointF(box.x(), box.y()), lit)

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
        if self._rip.items:
            self._rip.paint(p, r.adjusted(1, 1, -1, -1), 9, T.c(self._tone) if self._tone else T.c("text"), r.width() * 0.62)
        s = self._icon * (1.0 - 0.1 * self._pr) * (1.0 + 0.32 * self._pop.x)
        dx = shake_offset(self._shake, 3.4, 8.0, 7.0) if self._shake is not None else 0.0
        box = QRectF(r.center().x() - s / 2 + dx, r.center().y() - s / 2, s, s)
        if self._prev is not None:
            draw_icon(p, self._prev, box, base, 1.0 - self._xf)
            rot = box.translated(0, (1 - self._xf) * 2.5)
            draw_icon(p, self._name, rot, base, self._xf)
        else:
            draw_icon(p, self._name, box, base)
        if self._glint is not None:
            self._paint_glint(p, box)
        if self._rings or self._burst is not None:
            fxc = T.c(self._tone) if self._tone else T.c("acc")
            c0 = r.center()
            p.setBrush(Qt.BrushStyle.NoBrush)
            for a in self._rings:
                if a < 0:
                    continue
                u = clamp01(a / 0.72)
                col = QColor(fxc)
                col.setAlphaF(0.6 * (1.0 - u) ** 1.3)
                p.setPen(QPen(col, 1.9 * (1.0 - u) + 0.5))
                rad = self._icon * 0.45 + (r.width() / 2.0 - 1.0 - self._icon * 0.45) * ease_out(u)
                p.drawEllipse(c0, rad, rad)
            if self._burst is not None:
                u = clamp01(self._burst / 0.55)
                p.setPen(Qt.PenStyle.NoPen)
                for k in range(8):
                    ang = k * math.pi / 4 + 0.2
                    dist = self._icon * (0.38 + 0.36 * ease_out(u))
                    rad = (2.1 if k % 2 == 0 else 1.4) * (1.0 - u) ** 0.8 + 0.15
                    col = QColor(fxc)
                    col.setAlphaF(max(0.0, 1.0 - u * u))
                    p.setBrush(col)
                    p.drawEllipse(QPointF(c0.x() + math.cos(ang) * dist, c0.y() + math.sin(ang) * dist), rad, rad)
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


# --------------------------------------------------------------------------
# Zoom chip (lives inside the address bar)
# --------------------------------------------------------------------------
class ZoomChip(QAbstractButton):
    """A small '125%' chip that grows into the address bar while a page is zoomed. Clicking it resets the zoom."""
    FULL = 46

    def __init__(self):
        super().__init__()
        self._a, self._hv, self._text = 0.0, 0.0, ""
        self.setFixedSize(1, 24)
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.setToolTip("Reset zoom (Ctrl+0)")
        self._g = Glide(self, self._set, 17)
        self._g_hv = Glide(self, self._sh, 18)
        T.changed.connect(self.update)
        self.hide()

    def _set(self, v):
        self._a = v
        self.setFixedWidth(max(1, int(round(self.FULL * v))))
        if v <= 0.01 and self._g.t == 0.0:
            self.hide()
        self.update()

    def _sh(self, v):
        self._hv = v
        self.update()

    def enterEvent(self, e):
        self._g_hv.to(1.0)
        super().enterEvent(e)

    def leaveEvent(self, e):
        self._g_hv.to(0.0)
        super().leaveEvent(e)

    def set_zoom(self, factor):
        pct = int(round(factor * 100))
        if pct != 100:
            self._text = f"{pct}%"
            if not self.isVisible():
                self.show()
            self._g.to(1.0)
            self.update()
        elif self._g.t != 0.0 or self.isVisible():
            self._g.to(0.0)

    def paintEvent(self, _):
        if self._a <= 0.01:
            return
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.setOpacity(min(1.0, self._a))
        r = QRectF(self.rect()).adjusted(.5, .5, -.5, -.5)
        bg = T.mix("hover", "press", .35 + .65 * self._hv)
        p.setPen(Qt.PenStyle.NoPen)
        p.setBrush(bg)
        p.drawRoundedRect(r, 12, 12)
        p.setFont(ui_font(8.4, QFont.Weight.DemiBold))
        p.setPen(T.mix("mut", "text", self._hv))
        p.drawText(r, Qt.AlignmentFlag.AlignCenter, self._text)


class Omnibox(QFrame):
    def __init__(self):
        super().__init__()
        self.setFixedHeight(34)
        self.setAttribute(Qt.WidgetAttribute.WA_Hover)
        self._hv, self._fc = 0.0, 0.0
        self.lock = IconButton("lock", "Site controls", 28, 15)
        self.star = IconButton("star", "Bookmark this page (Ctrl+D)", 28, 16)
        self.zoom = ZoomChip()
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
        lay.addWidget(self.zoom)
        lay.addWidget(self.star)
        self._g_hv = Glide(self, self._sh, 14)
        self._g_fc = Glide(self, self._sf, 16)
        self._sw, self._sw_run = 1.0, self._sw_step           # the sweep of light: 0..1, and 1 means finished
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

    def _sw_step(self, dt):
        self._sw = min(1.0, self._sw + dt / 0.85)
        self.update()
        return self._sw < 1.0

    def _paint_sweep(self, p, q):
        """Two points of light leave the left end of the field, run along the top and the bottom with a fading tail, and meet
        at the right end. Positions are measured along the outline itself, so the light moves at an even speed."""
        R = q.height() / 2.0
        cy, x0, x1 = q.center().y(), q.left(), q.right()
        flat = max(0.0, q.width() - 2.0 * R)
        quarter = math.pi * R / 2.0
        total = 2.0 * quarter + flat

        def at(s, side):
            if s <= quarter:
                th = math.pi - s / R
                return QPointF(x0 + R + R * math.cos(th), cy + side * R * math.sin(th))
            if s <= quarter + flat:
                return QPointF(x0 + R + (s - quarter), cy + side * R)
            th = math.pi / 2.0 - (s - quarter - flat) / R
            return QPointF(x1 - R + R * math.cos(th), cy + side * R * math.sin(th))

        tail = min(total * 0.6, 260.0)
        head = ease_in_out(self._sw) * (total + tail)
        lo, hi = max(0.0, head - tail), min(total, head)
        if hi - lo < 1.0:
            return
        fade = 1.0 - smoothstep((self._sw - 0.7) / 0.3)
        col = QColor(T.c("acc")).lighter(185 if T.dark else 120)
        n = 36
        for width, weight in ((8.0, 0.20), (3.0, 1.0)):          # a soft glow underneath, a bright core on top
            for side in (-1.0, 1.0):
                for i in range(n):
                    a = lo + (hi - lo) * i / n
                    b = lo + (hi - lo) * (i + 1) / n
                    col.setAlphaF(max(0.0, min(1.0, ((i + 1) / n) ** 1.7 * fade * weight)))
                    p.setPen(QPen(col, width, Qt.PenStyle.SolidLine, Qt.PenCapStyle.FlatCap))
                    p.drawLine(at(a, side), at(b, side))

    def _on_focus(self, on):
        self._g_fc.to(1.0 if on else 0.0)
        if on and fx_on():
            self._sw = 0.0
            FrameClock.get().add(self._sw_run)
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
            ring = self._fc * .85 * (0.28 + 0.72 * smoothstep(self._sw * 1.1))      # while the light runs, the ring fills in behind it
            p.setPen(QPen(T.c("acc", ring), 2))
            p.drawRoundedRect(r.adjusted(1, 1, -1, -1), 16, 16)
        if self._sw < 1.0:
            self._paint_sweep(p, r.adjusted(1, 1, -1, -1))


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
        self._fade = None           # the pending "now fade out" step after a load finishes
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
        if self._fade is not None:      # a new load began before the last one finished fading: it must not be cut short
            self._fade.cancel()
            self._fade = None
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
        if self._fade is not None:
            self._fade.cancel()
        self._fade = FrameClock.get().after(0.26, lambda: self._g_a.to(0.0))     # let the bar reach the end, THEN fade

    def paintEvent(self, _):
        if self._val <= 0:
            return
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        h = float(self.height())
        w = self.width() * min(1.0, self._val)
        a = T.c("acc", self._alpha)
        p.fillRect(QRectF(0, h - 2, w, 2), a)
        if fx_on() and w > 6 and self._alpha > 0.02:
            # the bar brightens toward its tip, and the tip blooms into the toolbar above it like a comet
            trail = min(w, 170.0)
            head = QColor(T.c("acc")).lighter(145)
            head.setAlphaF(min(1.0, self._alpha))
            tail = T.c("acc", 0.0)
            g = QLinearGradient(w - trail, 0, w, 0)
            g.setColorAt(0.0, tail)
            g.setColorAt(1.0, head)
            p.fillRect(QRectF(w - trail, h - 2, trail, 2), QBrush(g))
            p.save()
            p.translate(w, h - 1.0)
            p.scale(1.0, 0.3)
            bloom = QRadialGradient(QPointF(0, 0), 34.0)
            glow = QColor(T.c("acc"))
            glow.setAlphaF(0.5 * min(1.0, self._alpha))
            bloom.setColorAt(0.0, glow)
            glow.setAlphaF(0.0)
            bloom.setColorAt(1.0, glow)
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(QBrush(bloom))
            p.drawEllipse(QPointF(0, 0), 34.0, 34.0)
            p.restore()


# --------------------------------------------------------------------------
# Tab strip
# --------------------------------------------------------------------------
class _Tab:
    __slots__ = ("view", "title", "icon", "loading", "x", "w", "tx", "tw", "hv", "cx", "pinned", "audio", "mate", "pa", "vx", "vw",
                 "vh", "vc", "vp", "cxt", "pk", "vpk", "rip")

    def __init__(self, view, title):
        self.view, self.title, self.icon, self.loading = view, title, None, False
        self.pinned, self.audio = False, 0      # audio: 0 silent, 1 playing, 2 muted
        self.x = self.w = self.tx = self.tw = 0.0
        self.vx = self.vw = 0.0   # velocities, so tabs keep their momentum when the layout changes mid-slide
        self.hv = 0.0
        self.cx = 0.0  # close-button hover
        self.cxt = 0.0   # where the close-button hover is heading
        self.vh = self.vc = self.vp = 0.0      # velocities of hv, cx, pa
        self.mate = None   # the other tab of a split view (a _Tab), if this one is paired
        self.pa = 0.0      # how strongly the pair's capsule shows, eased
        self.pk = self.vpk = 0.0     # the tab's squish when it is chosen: pressed in, then it springs back out with a wobble
        self.rip = None              # water ripples from where it was pressed (made when first needed)


class DragGhost(QWidget):
    """The floating tab that follows the pointer once a tab has been pulled out of its strip.

    It is a separate, click-through window so it can leave the browser window and cross onto other windows. It eases
    toward the pointer instead of being glued to it, and fades out on drop so the new window seems to take its place."""
    M = 22

    def __init__(self, strip, item, width):
        super().__init__(None, Qt.WindowType.Tool | Qt.WindowType.FramelessWindowHint | Qt.WindowType.WindowStaysOnTopHint
                         | Qt.WindowType.WindowTransparentForInput | Qt.WindowType.NoDropShadowWindowHint)
        self.setAttribute(Qt.WidgetAttribute.WA_TranslucentBackground)
        self.setAttribute(Qt.WidgetAttribute.WA_ShowWithoutActivating)
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        self.setAttribute(Qt.WidgetAttribute.WA_QuitOnClose, False)     # a drag ghost must never keep Shield running
        self._strip = strip
        self._title, self._icon, self._pinned, self._audio = item.title, item.icon, item.pinned, item.audio
        self._w = float(width)
        self.resize(int(self._w) + 2 * self.M, TabStrip.H + 2 * self.M)
        self._px = self._py = None
        self._tx = self._ty = 0.0
        self._sc, self._tsc = 0.94, 1.04
        self._al, self._tal = 0.0, 1.0
        self._vsc = self._val = 0.0
        self._dead = False
        self._vx = self._vy = 0.0
        self._tm = Ticker(self._step)

    def follow(self, gx, gy, scale=1.04):
        """Aim the ghost's top-left corner (global pixels) and scale; it glides there."""
        if self._dead:
            return
        self._tx, self._ty, self._tsc = float(gx), float(gy), scale
        if self._px is None:
            self._px, self._py = self._tx, self._ty
            self.move(int(self._px), int(self._py))
            self.show()
        self._tm.start()

    def dissolve(self):
        """Fade away and delete itself."""
        if self._dead:
            return
        self._dead, self._tal = True, 0.0
        if self._px is None:
            self.deleteLater()
            return
        self._tm.start()

    def _step(self, dt):
        if self._px is not None:
            self._px, self._vx = spring_step(self._px, self._vx, self._tx, 55.0, 1.0, dt)
            self._py, self._vy = spring_step(self._py, self._vy, self._ty, 55.0, 1.0, dt)
            self.move(iround(self._px), iround(self._py))
        self._sc, self._vsc = spring_step(self._sc, self._vsc, self._tsc, 33.0, 1.0, dt)
        self._al, self._val = spring_step(self._al, self._val, self._tal, 33.0 if not self._dead else 24.0, 1.0, dt)
        self.update()
        if self._dead and self._al < .02:
            self.hide()
            self.deleteLater()
            return False
        return True

    def paintEvent(self, _):
        p = QPainter(self)
        quality(p)
        p.setOpacity(max(0.0, min(1.0, self._al)))
        m = self.M
        c = QPointF(self.width() / 2.0, self.height() / 2.0)
        p.translate(c)
        p.scale(self._sc, self._sc)
        p.translate(-c)
        r = QRectF(m, m + 5, self._w, TabStrip.H - 10)
        soft_shadow(p, r, 9, spread=m - 6, strength=.40 if T.dark else .24, dy=7)
        p.translate(0, m)
        self._strip._paint_tab(p, m, self._w, self._title, self._icon, False, True, 1.0, 0.0, 1.0, False, self._pinned, self._audio)


class TabStrip(QWidget):
    currentChanged = pyqtSignal(object)
    closeRequested = pyqtSignal(object)
    newRequested = pyqtSignal()
    contextRequested = pyqtSignal(object, object)
    audioToggleRequested = pyqtSignal(object)
    searchRequested = pyqtSignal()
    hoverChanged = pyqtSignal(object, object)         # (view or None, the tab's QRectF in strip coordinates)
    pairBroken = pyqtSignal(object)                   # a tab of a split view was picked up: the split dissolves first
    tabDropped = pyqtSignal(object, object, int)      # (view, the other window's TabStrip, slot): moved to that window
    tabTornOff = pyqtSignal(object, object, object)   # (view, global QPoint, grab offset QPointF): dropped on the desktop

    H, PAD_L, PAD_R, GAP, MIN_W, MAX_W, PIN_W = 42, 10, 10, 2, 44, 228, 42
    TAIL = 76       # room kept free on the right for the new-tab and tab-search buttons
    DETACH = 28     # how far (px) the pointer has to leave the strip before a tab lifts off

    def __init__(self):
        super().__init__()
        self.setFixedHeight(self.H)
        self.setMouseTracking(True)
        self.items, self.ghosts, self.cur = [], [], None
        self._hover, self._drag, self._drag_dx, self._drag_dy, self._press = None, None, 0.0, 0.0, None
        self._lifted, self._over, self._ghost = False, None, None     # dragged tab out of the strip / the other strip under it / its ghost
        self._gap, self._gw, self._gwa = None, 0.0, 0.0                # drop preview from another window: (slot, pinned), its width, eased
        self._tm = Ticker(self._tick)
        self.plus = IconButton("plus", "New tab (Ctrl+T)", 30, 17, self)
        self.plus.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.plus.silent = True                 # opening a tab has its own sound
        self.plus.clicked.connect(self.newRequested)
        self.search = IconButton("chevron-down", "Search tabs (Ctrl+Shift+A)", 30, 16, self)
        self.search.setFocusPolicy(Qt.FocusPolicy.NoFocus)
        self.search.clicked.connect(self.searchRequested)
        T.changed.connect(self.update)

    # -- model ----------------------------------------------------------
    def views(self):
        return [t.view for t in self.items]

    def count(self):
        return len(self.items)

    def live(self):
        """The tabs that currently take up room (a tab that has been lifted out for a drag does not)."""
        return [t for t in self.items if not (t is self._drag and self._lifted)]

    def _find(self, view):
        return next((t for t in self.items if t.view is view), None)

    def index_of(self, view):
        return next((i for i, t in enumerate(self.items) if t.view is view), -1)

    def tab_rect(self, t):
        return QRectF(t.x, 5, t.w, self.H - 10)

    def add_tab(self, view, title="New tab"):
        t = _Tab(view, title)
        self.items.append(t)
        self._layout()
        t.x, t.w = t.tx, 0.0
        self._kick()

    def insert_tab(self, view, state, slot=None):
        """Add a tab that came from another window, keeping what it looked like there."""
        t = _Tab(view, state.get("title") or "New tab")
        t.icon, t.pinned = state.get("icon"), bool(state.get("pinned"))
        t.audio, t.loading = int(state.get("audio", 0)), bool(state.get("loading"))
        pins = self.pinned_count()
        slot = len(self.items) if slot is None else slot
        slot = min(slot, pins) if t.pinned else max(slot, pins)
        slot = max(0, min(len(self.items), slot))
        self.items.insert(slot, t)
        self._gap = None
        self._layout()
        t.x, t.w = t.tx, 0.0
        self._kick()

    def state_of(self, view):
        t = self._find(view)
        if not t:
            return {}
        return {"title": t.title, "icon": t.icon, "pinned": t.pinned, "audio": t.audio, "loading": t.loading}

    def remove_tab(self, view, ghost=True):
        t = self._find(view)
        if not t:
            return
        if ghost:
            self.ghosts.append({"x": t.x, "w": t.w, "a": 1.0, "title": t.title, "icon": t.icon, "active": t is self.current_item()})
        if t.mate is not None:
            t.mate.mate = None
            t.mate = None
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
            self._kick()
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

    # -- split view pairs -------------------------------------------------
    def place_after(self, view, anchor):
        """Slide a tab so it sits right after another one (pinned tabs stay on the left)."""
        t, a = self._find(view), self._find(anchor)
        if not t or not a or t is a:
            return
        self.items.remove(t)
        i = self.items.index(a) + 1
        pins = self.pinned_count()
        i = min(i, pins) if t.pinned else max(i, pins)
        self.items.insert(i, t)
        self._layout()
        self._kick()

    def set_pair(self, a, b):
        ta, tb = self._find(a), self._find(b)
        if not ta or not tb or ta is tb:
            return
        self.clear_pair()
        ta.mate, tb.mate = tb, ta
        self.place_after(b, a)
        self._kick()

    def clear_pair(self):
        for t in self.items:
            t.mate = None
            t.pa = 0.0
        self.update()

    def mate_of(self, view):
        t = self._find(view)
        return t.mate.view if t and t.mate is not None else None

    # -- layout / animation --------------------------------------------
    def _layout(self, immediate=False):
        live = self.live()
        gap = self._gap
        n_pin = sum(1 for t in live if t.pinned) + (1 if gap and gap[1] else 0)
        n_free = len(live) - sum(1 for t in live if t.pinned) + (1 if gap and not gap[1] else 0)
        avail = self.width() - self.PAD_L - self.PAD_R - self.TAIL - n_pin * (self.PIN_W + self.GAP)
        w = max(self.MIN_W, min(self.MAX_W, (avail - max(0, n_free - 1) * self.GAP) / n_free)) if n_free else 0
        self._gw = float(self.PIN_W if gap and gap[1] else w)
        x = float(self.PAD_L)
        slot = 0
        for t in self.items:
            tw = self.PIN_W if t.pinned else w
            if t is self._drag and self._lifted:
                t.tw = tw
                continue
            if gap and slot == gap[0]:
                x += self._gw + self.GAP
            slot += 1
            if t is self._drag:
                x += tw + self.GAP
                t.tw = tw
                continue
            t.tx, t.tw = x, tw
            if immediate:
                t.x, t.w, t.vx, t.vw = t.tx, t.tw, 0.0, 0.0
            x += tw + self.GAP
        self._place_plus()

    def _place_plus(self):
        live = self.live()
        x = (max(t.x + t.w for t in live) + 6) if live else float(self.PAD_L)
        x += self._gwa
        self.plus.move(iround(min(x, self.width() - self.PAD_R - 64)), (self.H - 30) // 2)

    def resizeEvent(self, e):
        self._layout(immediate=True)
        self.search.move(self.width() - self.PAD_R - 30, (self.H - 30) // 2)
        super().resizeEvent(e)

    def _kick(self):
        self._tm.start()

    def _tick(self, dt):
        busy = False
        cur_item = self._find(self.cur)
        for t in self.items:
            if t is not self._drag:
                t.x, t.vx = spring_step(t.x, t.vx, t.tx, 26.0, 1.0, dt)
                t.w, t.vw = spring_step(t.w, t.vw, t.tw, 26.0, 1.0, dt)
                if abs(t.x - t.tx) < .15 and abs(t.w - t.tw) < .15 and abs(t.vx) < 4 and abs(t.vw) < 4:
                    t.x, t.w, t.vx, t.vw = t.tx, t.tw, 0.0, 0.0
                else:
                    busy = True
            else:
                t.vx = t.vw = 0.0
            hv_t = 1.0 if t is self._hover else 0.0
            t.hv, t.vh = spring_step(t.hv, t.vh, hv_t, 27.0, 1.0, dt)
            if abs(t.hv - hv_t) < .004 and abs(t.vh) < .05:
                t.hv, t.vh = hv_t, 0.0
            else:
                busy = True
            t.cx, t.vc = spring_step(t.cx, t.vc, t.cxt, 60.0, 1.0, dt)      # was only ever advanced by mouse moves
            if abs(t.cx - t.cxt) < .004 and abs(t.vc) < .05:
                t.cx, t.vc = t.cxt, 0.0
            else:
                busy = True
            if t.pk or t.vpk:
                t.pk, t.vpk = spring_step(t.pk, t.vpk, 0.0, 24.0, 0.42, dt)
                if abs(t.pk) < .003 and abs(t.vpk) < .06:
                    t.pk = t.vpk = 0.0
                else:
                    busy = True
            want = 0.0 if t.mate is None else (1.0 if (t is cur_item or t.mate is cur_item) else .55)
            t.pa, t.vp = spring_step(t.pa, t.vp, want, 21.0, 1.0, dt)
            if abs(t.pa - want) < .004 and abs(t.vp) < .05:
                t.pa, t.vp = want, 0.0
            else:
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
        end_gap = bool(self._gap) and self._gap[0] >= len(self.live())
        gt = (self._gw + self.GAP) if end_gap else 0.0
        self._gwa = approach(self._gwa, gt, 18, dt)
        if abs(self._gwa - gt) > .25:
            busy = True
        else:
            self._gwa = gt
        self._place_plus()
        self.update()
        return busy

    # -- painting ------------------------------------------------------
    def _close_rect(self, t):
        return QRectF(t.x + t.w - 28, (self.H - 20) / 2, 20, 20)

    def _audio_rect(self, t):
        if t.audio and not t.pinned and t.w >= 110:
            return QRectF(t.x + t.w - 50, (self.H - 20) / 2, 20, 20)
        return None

    def _paint_tab(self, p, x, w, title, icon, loading, active, hv, cx, alpha=1.0, show_close=True, pinned=False, audio=0, ca=1.0):
        if w < 6:
            return
        base_op = p.opacity()
        p.setOpacity(base_op * alpha)
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
        if ca < 1.0:
            p.setOpacity(base_op * alpha * ca)      # the surface is there from the start; its contents arrive as it opens
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
        p.setOpacity(base_op)

    def _paint_capsule(self, p, a, b):
        """The soft shape behind two tabs that are shown side by side."""
        l, r = (a, b) if a.x <= b.x else (b, a)
        al = max(0.0, min(1.0, l.pa))
        rect = QRectF(l.x - 1, 5, (r.x + r.w) - l.x + 2, self.H - 10)
        fill = T.c("field")
        fill.setAlphaF(fill.alphaF() * al)
        ln = T.c("line")
        ln.setAlphaF(ln.alphaF() * al)
        p.setPen(QPen(ln, 1))
        p.setBrush(fill)
        p.drawRoundedRect(rect.adjusted(.5, .5, -.5, -.5), 10, 10)
        mx = (l.x + l.w + r.x) / 2.0
        p.drawLine(QPointF(mx, 15), QPointF(mx, self.H - 15))

    def paintEvent(self, _):
        p = QPainter(self)
        quality(p)
        for g in self.ghosts:
            self._paint_tab(p, g["x"], g["w"], g["title"], g["icon"], False, g["active"], 0, 0, g["a"], False)
        done = set()
        for t in self.items:
            m = t.mate
            if m is None or id(t) in done or t is self._drag or m is self._drag or t.pa <= .01:
                continue
            if abs(self.items.index(t) - self.items.index(m)) != 1:      # pinned tabs can keep a pair apart: no capsule then
                continue
            done.add(id(t))
            done.add(id(m))
            self._paint_capsule(p, t, m)
        for t in self.items:
            if t is not self._drag:
                grow = window(t.w / t.tw, 0.12, 0.6) if 0 < t.tw and t.w < t.tw else 1.0
                squish = t.pk != 0.0 and t.w > 20
                if squish:
                    p.save()
                    c = QPointF(t.x + t.w / 2.0, self.H / 2.0)
                    p.translate(c)
                    k = 1.0 + 0.05 * t.pk
                    p.scale(k, 1.0 + 0.09 * t.pk)
                    p.translate(-c)
                self._paint_tab(p, t.x, t.w, t.title, t.icon, t.loading, t.view is self.cur, t.hv, t.cx, 1.0, True, t.pinned, t.audio, ca=grow)
                if t.rip is not None and t.rip.items:
                    t.rip.paint(p, QRectF(t.x, 5, t.w, self.H - 10), 9, T.c("text"), max(60.0, t.w * 0.75))
                if squish:
                    p.restore()
        if self._drag and not self._lifted:
            t = self._drag
            self._paint_tab(p, t.x, t.w, t.title, t.icon, t.loading, True, 1.0, t.cx, 1.0, True, t.pinned, t.audio)

    # -- mouse ----------------------------------------------------------
    def _at(self, pos):
        for t in self.items:
            if t is self._drag and self._lifted:
                continue
            if t.x <= pos.x() <= t.x + t.w:
                return t
        return None

    def _select(self, t):
        if t.view is not self.cur:
            self.cur = t.view
            if fx_on():
                t.pk, t.vpk = -1.0, 0.0
            play_sound("tab_select")
            self._kick()
            self.update()
            self.currentChanged.emit(t.view)

    def mousePressEvent(self, e):
        t = self._at(e.position())
        self._press = None
        self.hoverChanged.emit(None, None)
        if not t:
            return
        if e.button() == Qt.MouseButton.LeftButton:
            on_close = (not t.pinned) and t.w >= 80 and (t.view is self.cur or t.hv > .05) and self._close_rect(t).contains(e.position())
            ar = self._audio_rect(t)
            on_audio = bool(ar and ar.contains(e.position()))
            self._press = (t, e.position(), "audio" if on_audio else on_close)
            if not on_close and not on_audio:
                if fx_on():
                    if t.rip is None:
                        t.rip = Ripples(self)
                    t.rip.add(e.position().x(), e.position().y())
                self._select(t)
        elif e.button() == Qt.MouseButton.MiddleButton:
            self._press = (t, e.position(), "middle")

    def _strip_under(self, gp):
        """The tab strip of another browser window under a global point, if any."""
        pt = gp.toPoint()
        for w in QApplication.topLevelWidgets():
            s = getattr(w, "strip", None)
            if not isinstance(s, TabStrip) or s is self or not w.isVisible() or w.isMinimized():
                continue
            lp = s.mapFromGlobal(pt)
            if -8 <= lp.x() <= s.width() + 8 and -8 <= lp.y() <= s.H + 8:
                return s
        return None

    def _drag_move(self, e):
        pos, gp = e.position(), e.globalPosition()
        it, start, _ = self._press
        if self._drag is None:
            if abs(pos.x() - start.x()) <= 6 and abs(pos.y() - start.y()) <= 6:
                return
            if it.mate is not None:
                self.pairBroken.emit(it.view)          # pulling a tab out of a split view frees it from the split
            self._drag, self._drag_dx, self._drag_dy = it, start.x() - it.x, max(0.0, start.y() - 5)
            self.hoverChanged.emit(None, None)
        d = self._drag
        inside = -self.DETACH <= pos.y() <= self.H + self.DETACH and -60 <= pos.x() <= self.width() + 60
        target = None if inside else self._strip_under(gp)
        can_leave = target is not None or len(self.items) > 1      # the only tab of a window can join another window, never form a new one
        if inside or not can_leave:
            if self._lifted:
                self._lifted = False
                if self._ghost is not None:
                    self._ghost.dissolve()
                    self._ghost = None
                self._set_over(None, gp, d)
            d.x = max(self.PAD_L, min(pos.x() - self._drag_dx, self.width() - self.PAD_R - d.w - 70))
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
            return
        # the tab has left the strip: a ghost carries it and the slot closes behind it
        if not self._lifted:
            self._lifted = True
            self._layout()
            self._kick()
        gw = d.w if d.pinned else max(d.w, 150.0)
        if self._ghost is None:
            self._ghost = DragGhost(self, d, gw)
        self._set_over(target, gp, d)
        gx = gp.x() - min(self._drag_dx, gw - 12) - DragGhost.M
        if target is not None:
            gy = target.mapToGlobal(QPoint(0, 5)).y() - DragGhost.M       # settles into the other strip's row
            self._ghost.follow(gx, gy, 1.0)
        else:
            self._ghost.follow(gx, gp.y() - self._drag_dy - 5 - DragGhost.M, 1.05)
        self.update()

    def _set_over(self, target, gp, d):
        if target is not self._over and self._over is not None:
            try:
                self._over.clear_drop()
            except RuntimeError:
                pass
        self._over = target
        if target is not None:
            target.preview_drop(gp, d.pinned)

    def _end_drag(self):
        self._drag = None
        self._lifted = False
        if self._over is not None:
            try:
                self._over.clear_drop()
            except RuntimeError:
                pass
            self._over = None
        if self._ghost is not None:
            self._ghost.dissolve()
            self._ghost = None
        self._layout()
        self._kick()

    # drop preview, used by the strip that is being dragged over
    def preview_drop(self, gp, pinned):
        x = self.mapFromGlobal(gp.toPoint()).x()
        shift = (self._gw + self.GAP) if self._gap else 0.0
        before = self._gap[0] if self._gap else len(self.items) + 1
        slot = 0
        for i, o in enumerate(self.items):
            ctr = o.tx + o.tw / 2.0 - (shift if i >= before else 0.0)
            if ctr < x:
                slot += 1
        pins = self.pinned_count()
        slot = min(slot, pins) if pinned else max(slot, pins)
        slot = max(0, min(len(self.items), slot))
        g = (slot, bool(pinned))
        if g != self._gap:
            self._gap = g
            self._layout()
            self._kick()

    def clear_drop(self):
        if self._gap is not None:
            self._gap = None
            self._layout()
            self._kick()

    def drop_slot(self):
        return self._gap[0] if self._gap else len(self.items)

    def mouseMoveEvent(self, e):
        pos = e.position()
        if self._drag is not None or (self._press and self._press[2] is False and e.buttons() & Qt.MouseButton.LeftButton):
            self._drag_move(e)
            return
        t = self._at(pos)
        if t is not self._hover:
            self._hover = t
            self._kick()
            self.hoverChanged.emit(t.view if t else None, self.tab_rect(t) if t else None)
        for it in self.items:
            want = 1.0 if (t is it and self._close_rect(it).contains(pos)) else 0.0
            if it.cxt != want:
                it.cxt = want
                self._kick()
        self.setCursor(Qt.CursorShape.ArrowCursor)

    def leaveEvent(self, e):
        self._hover = None
        for it in self.items:
            it.cxt = 0.0
        self._kick()
        self.hoverChanged.emit(None, None)
        super().leaveEvent(e)

    def mouseReleaseEvent(self, e):
        if self._drag:
            d, gp = self._drag, e.globalPosition()
            lifted, over = self._lifted, self._over
            slot = over.drop_slot() if over is not None else 0
            grab = QPointF(self._drag_dx, self._drag_dy)
            self._end_drag()
            if lifted and over is not None:
                self.tabDropped.emit(d.view, over, slot)
            elif lifted and len(self.items) > 1:
                self.tabTornOff.emit(d.view, gp.toPoint(), grab)
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
            self.hoverChanged.emit(None, None)
            self.contextRequested.emit(t.view, e.globalPos())

    def event(self, e):
        if e.type() == QEvent.Type.ToolTip:       # the hover card replaces the plain tooltip
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
        self.progress.setGeometry(0, self.height() - 9, self.width(), 9)     # the bar is its bottom 2 px; the rest is room for its glow
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
        self.fx = QGraphicsOpacityEffect(self)          # the card AND its field and buttons fade together
        self.fx.setOpacity(0.0)
        self.setGraphicsEffect(self.fx)
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
        self.fx.setOpacity(window(v, 0.0, 0.8))
        if v <= .01 and self._g.t == 0:
            self.hide()
        self.update()
        self.move(self.x(), self._base_y + iround(self._off))

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
        self.move(self.parentWidget().width() - self.width() - 16 + self.M, self._base_y + iround(self._off))

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
        m = self.M
        r = QRectF(m, m, self.width() - 2 * m, self.height() - 2 * m)
        soft_shadow(p, r, 14, spread=m - 2, strength=.26 if T.dark else .16, dy=5)
        p.setPen(QPen(T.c("line"), 1))
        p.setBrush(T.c("card"))
        p.drawRoundedRect(r, 14, 14)
        draw_icon(p, "search", QRectF(m + 14, self.height() / 2 - 8, 16, 16), T.c("mut"))


# --------------------------------------------------------------------------
# View host: one page, or two side by side
# --------------------------------------------------------------------------
class _Clip(QWidget):
    """A plain frame that holds one page. Animating the frame only CROPS the page; it never makes the web engine
    re-layout, which is what made split animations stutter before."""


class _Snap(QWidget):
    """A picture of a page as it looked a moment ago, laid over the live page inside the same frame. While a pane changes
    width it is stretched to the pane and dissolves into the live page, which was laid out once at its final size. That is
    how macOS and iOS hide a re-layout: the eye follows one continuous motion and there is no moment where content jumps."""

    def __init__(self, parent):
        super().__init__(parent)
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        self.pm, self.a = None, 0.0
        self.void = QRect()         # the part of the frame the live page does not reach yet; it stays covered until it closes
        self.hide()

    def paintEvent(self, _):
        if self.pm is None or (self.a <= 0.003 and self.void.isEmpty()):
            return
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform)
        p.setOpacity(max(0.0, min(1.0, self.a)))
        p.drawPixmap(self.rect(), self.pm)
        if not self.void.isEmpty():
            p.setClipRect(self.void)
            p.setOpacity(1.0)
            p.drawPixmap(self.rect(), self.pm)


def _usable(pm):
    """A grab of the web engine can come back empty (no frame drawn yet, GPU read-back off). Only trust one with content."""
    if pm is None or pm.isNull() or pm.width() < 8 or pm.height() < 8:
        return False
    img = pm.toImage()
    w, h = img.width(), img.height()
    seen = set()
    for fy in (.1, .3, .5, .7, .9):
        for fx in (.1, .3, .5, .7, .9):
            c = img.pixelColor(int(w * fx), int(h * fy))
            if c.alpha() >= 250:
                seen.add(c.rgb())
    return bool(seen) and seen != {0xff000000}


usable_grab = _usable


class _Pane:
    __slots__ = ("view", "clip", "snap", "s", "size", "anchor", "leaving", "live", "w0")

    def __init__(self, view, clip):
        self.view, self.clip = view, clip
        self.snap = _Snap(clip)
        # x, y, width, height of the frame, each on its own spring (same stiffness, so they stay in step)
        self.s = [Spring(0.0, 10.0, 1.0, 0.12) for _ in range(4)]
        for s in self.s:
            s.omega = ViewHost.OMEGA
        self.size = QSize(0, 0)     # the size the page is laid out at. It is set ONCE, to the final size, when a motion starts
                                    # (a pane that is leaving keeps the size it had, so it slides away whole)
        self.anchor = "l"           # which edge of the frame the page is pinned to
        self.leaving, self.live = False, False
        self.w0 = 0.0               # the frame's width when the current motion began (the dissolve is measured against it)

    def rect(self):
        return QRectF(self.s[0].x, self.s[1].x, self.s[2].x, self.s[3].x)


class ViewHost(QWidget):
    """Holds the page views of a window. Shows one page, or two side by side with a draggable divider.

    How the split motion works, and why it never jumps:

      * The web engine is expensive to resize, so every page is laid out ONCE, at the size it will end at, the moment a
        motion starts. During the motion only its frame moves, which crops or reveals it.
      * The frames of the two panes are welded to one divider, so nothing ever overlaps. A pane that arrives or leaves rides
        the divider (its page slides in or out whole). A pane that stays keeps its page planted on its far edge, where it
        will end up, so there is never an empty strip at the window's edge and no content has to travel afterwards.
      * A pane that changes width keeps a snapshot of how it looked, stretched to its frame, dissolving into the live page
        as the divider travels. The old layout compresses into the new one, and when the frame lands there is nothing left
        to snap. If the engine can't be captured, the page simply takes its final layout at the start.
      * Each frame is a critically damped spring that keeps its velocity, so interrupting a motion halfway (closing a split
        while it opens, dragging, swapping) never jumps; a fresh snapshot is taken from whatever is on screen at that moment.

    Pane edges are rounded per edge so the two pages and the divider never drift a pixel apart. Dragging the divider by
    hand stays live."""
    activated = pyqtSignal(object)      # the user clicked into the other pane
    GUT, TOP, LIMIT = 10, 3, 0.2
    OMEGA = 15.0                         # spring stiffness for pane motion: lands in about 0.4 s with no overshoot
    DISSOLVE = (0.04, 0.88)              # the part of the motion over which the old look hands over to the live page

    def __init__(self):
        super().__init__()
        self.setMouseTracking(True)
        self._views, self._active, self._pair = [], None, None
        self._ratio = 0.5
        self._p = {}                     # view -> _Pane
        self._hv, self._drag = 0.0, False
        self._g_hv = Glide(self, self._sh, 16)
        self._tm = Ticker(self._tick)
        self._drop = DropReveal(self)       # the water drop that carries one page over another (see shield_fx.py)
        T.changed.connect(self.update)

    # -- the small part of QStackedWidget the window uses ---------------------
    def addWidget(self, view):
        clip = _Clip(self)
        view.setParent(clip)
        view.hide()
        clip.hide()
        self._views.append(view)
        self._p[view] = _Pane(view, clip)

    def removeWidget(self, view):
        if view in self._views:
            self._views.remove(view)
        p = self._p.pop(view, None)
        if self._pair and view in self._pair:
            self._pair = None
        if self._active is view:
            self._active = None
        view.hide()
        if p is not None:
            view.setParent(self)         # leave the frame before it goes, exactly as a plain child would be left
            view.hide()
            p.clip.hide()
            p.clip.deleteLater()

    def currentWidget(self):
        return self._active

    def is_split(self):
        return self._pair is not None

    def pair(self):
        return self._pair

    # -- layout ---------------------------------------------------------------
    def _split_rects(self):
        W, H = float(self.width()), float(self.height())
        l, r = self._pair
        wl = (W - self.GUT) * self._ratio
        return {l: QRectF(0, self.TOP, wl, H - self.TOP), r: QRectF(wl + self.GUT, self.TOP, W - wl - self.GUT, H - self.TOP)}

    def _cur(self, view):
        p = self._p.get(view)
        return p.rect() if p is not None else None

    @staticmethod
    def _jump(p, r):
        for s, val in zip(p.s, (r.x(), r.y(), r.width(), r.height())):
            s.jump(val)

    @staticmethod
    def _aim(p, r):
        for s, val in zip(p.s, (r.x(), r.y(), r.width(), r.height())):
            s.t = val

    def _place(self, p):
        """Put a pane's frame, page and snapshot where its springs say, on whole pixels."""
        c = snap_rect(p.s[0].x, p.s[1].x, p.s[2].x, p.s[3].x)
        if p.clip.geometry() != c:
            p.clip.setGeometry(c)
        fw, fh = (p.size.width(), p.size.height()) if p.size.width() > 0 else (c.width(), c.height())
        r = QRect(0 if p.anchor == "l" else c.width() - fw, 0, fw, fh)
        if p.view.geometry() != r:
            p.view.setGeometry(r)
        if p.snap.pm is not None:
            sr = QRect(0, 0, c.width(), c.height())
            if p.snap.geometry() != sr:
                p.snap.setGeometry(sr)
            gap = c.width() - fw
            vr = QRect() if gap <= 0 else (QRect(fw, 0, gap, c.height()) if p.anchor == "l" else QRect(0, 0, gap, c.height()))
            if vr != p.snap.void:
                p.snap.void = vr
                p.snap.update()

    def _drop_snap(self, p):
        if p.snap.pm is not None or p.snap.isVisible():
            p.snap.pm, p.snap.a, p.snap.void = None, 0.0, QRect()
            p.snap.hide()

    def _progress(self, p):
        """How far a pane has travelled toward its final width, 0..1."""
        goal = p.s[2].t
        span = abs(p.w0 - goal)
        if span < 1.0:
            return 1.0
        return max(0.0, min(1.0, 1.0 - abs(p.s[2].x - goal) / span))

    def _dissolve(self, p):
        if p.snap.pm is None:
            return
        a = 1.0 - window(self._progress(p), *self.DISSOLVE)
        if a <= 0.004 and p.snap.void.isEmpty():
            self._drop_snap(p)
        else:
            p.snap.a = max(0.0, a)
            p.snap.update()

    def _hide(self, view):
        p = self._p.get(view)
        if p is not None:
            p.live = p.leaving = False
            self._drop_snap(p)
            view.hide()
            p.clip.hide()

    def _show(self, p):
        if not p.clip.isVisibleTo(self):
            p.clip.show()
        if not p.view.isVisibleTo(p.clip):
            p.view.show()
        if p.snap.pm is not None:
            p.snap.show()
            p.snap.raise_()

    def _snap(self, goal):
        """Put every pane exactly where it belongs, right now."""
        self._tm.stop()
        for v in self._views:
            if v not in goal:
                self._hide(v)
        for v, g in goal.items():
            p = self._p[v]
            self._jump(p, g)
            self._drop_snap(p)
            p.anchor, p.leaving, p.live = "l", False, False
            p.w0 = g.width()
            p.size = snap_rect(g.x(), g.y(), g.width(), g.height()).size()
            self._place(p)
            self._show(p)
        self.update()

    def _animate(self, goals, anchors=None, leaving=(), starts=None):
        """Glide every pane to its goal, all welded to the same divider.

        starts: where a pane that is just arriving begins. leaving: panes that shrink away and are hidden when they land
        (they keep their page size, so nothing re-lays-out while they go). anchors: the edge of its frame a page is pinned to for arriving and leaving panes."""
        anchors, starts = anchors or {}, starts or {}
        for v in self._views:
            if v not in goals:
                self._hide(v)
        # 1. a picture of every pane that will change width, taken BEFORE anything moves or re-lays-out
        W = float(self.width())
        shots = {}
        for v, g in goals.items():
            p = self._p[v]
            if v in starts or v in leaving or not (p.clip.isVisibleTo(self) and self.isVisible()):
                continue
            cur = p.rect()
            if abs(cur.width() - g.width()) > 1.5 and cur.width() > 8 and cur.height() > 8:
                pm = p.clip.grab()
                if _usable(pm):
                    shots[v] = pm
        # 2. aim every frame, lay each page out once at its final size
        for v, g in goals.items():
            p = self._p[v]
            seen = p.clip.isVisibleTo(self) and self.isVisible()
            if v in starts:
                self._jump(p, starts[v])
            elif not seen:
                self._jump(p, g)
            p.w0 = p.s[2].x
            self._aim(p, g)
            ride = anchors.get(v) or ("r" if g.x() + g.width() / 2.0 <= W / 2.0 else "l")
            changes = abs(p.w0 - g.width()) > 1.5
            if changes and v not in starts and v not in leaving:
                ride = "l" if ride == "r" else "r"      # a pane that stays keeps its page planted on its far edge, so the
                                                       # content is already in its final place and any gap is at the divider
            p.anchor, p.leaving, p.live = ride, v in leaving, True
            if not p.leaving:
                p.size = snap_rect(g.x(), g.y(), g.width(), g.height()).size()
            if v in shots:
                p.snap.pm, p.snap.a = shots[v], 1.0
            else:
                self._drop_snap(p)
            self._place(p)
            self._show(p)
        self._tm.start()
        self.update()

    def _capture(self):
        """A picture of what the host shows right now, or None if the web engine could not be captured."""
        pm = self.grab()
        return pm if _usable(pm) else None

    def show_single(self, view, animate=False, origin=None):
        """Show one page. If it was one half of a split and animate is set, the other half slides away.

        origin: where the drop lands, as an x position along the top edge in this widget's coordinates. When given, the new
        page falls out of that spot like a drop of water and spreads over the old one (the live new page is already
        underneath; only a picture of the old one is being cut away, so nothing is laid out twice)."""
        prev = self._pair
        shot = False
        if (origin is not None and fx_on() and prev is None and self.isVisible() and self.width() > 80 and self.height() > 80
                and self._active is not None and self._active is not view and self._active in self._p
                and self._p[self._active].clip.isVisibleTo(self)):
            shot = self._capture()          # taken BEFORE anything changes
        self._pair = None
        self._active = view
        W, H = float(self.width()), float(self.height())
        full = QRectF(0, 0, W, H)
        if animate and prev and view in prev and view in self._p and self._p[view].clip.isVisibleTo(self) and self.isVisible():
            other = prev[1] if view is prev[0] else prev[0]
            if other in self._p and self._p[other].clip.isVisibleTo(self):
                left_gone = other is prev[0]
                self._animate({view: full, other: QRectF(0 if left_gone else W, 0, 0, H)},
                              anchors={other: "r" if left_gone else "l", view: "l" if left_gone else "r"}, leaving={other})
                return
        self._snap({view: full})
        if shot is not False:
            self._drop.play(shot, QPointF(float(origin.x()), 0.0), T.c("acc"), T.c("window"), T.dark)

    def show_split(self, left, right, active, animate=True):
        """Show two pages side by side. The one that was alone before grows to make room for the other."""
        was = self._active if self._pair is None else None
        same = self._pair == (left, right)
        self._pair = (left, right)
        self._active = active
        goals = self._split_rects()
        if same:
            self._animate(goals)
            return
        if animate and self.isVisible() and was in (left, right) and was in self._p and self._p[was].clip.isVisibleTo(self):
            other = right if was is left else left
            W, H = float(self.width()), float(self.height())
            from_right = other is right
            self._animate(goals, anchors={other: "l" if from_right else "r", was: "r" if from_right else "l"},
                          starts={other: QRectF(W if from_right else 0, 0, 0, H)})
            return
        self._snap(goals)

    def set_active(self, view):
        if view is not self._active:
            self._active = view
            self.update()

    def swap(self):
        """Exchange the two panes; each one glides to the other's place."""
        if not self._pair:
            return
        self._pair = (self._pair[1], self._pair[0])
        self._animate(self._split_rects())
        act = self._p.get(self._active)
        if act is not None:
            act.clip.raise_()      # the two pages have to pass through each other: the one you are working in passes in front

    def set_ratio(self, ratio, animate=False):
        self._ratio = max(self.LIMIT, min(1.0 - self.LIMIT, ratio))
        if not self._pair:
            return
        goals = self._split_rects()
        if animate:
            self._animate(goals)
        else:
            self._snap(goals)           # dragging by hand: the pages follow the pointer exactly
        self.update()

    def ratio(self):
        return self._ratio

    def resizeEvent(self, e):
        super().resizeEvent(e)
        self._drop.cancel()
        if self._pair:
            self._snap(self._split_rects())
        elif self._active is not None:
            self._snap({self._active: QRectF(0, 0, self.width(), self.height())})

    def _tick(self, dt):
        busy = False
        for v, p in list(self._p.items()):
            if not p.live:
                continue
            moving = [s.step(dt) for s in p.s]      # every spring steps, even after one lands
            self._place(p)
            self._dissolve(p)
            if any(moving):
                busy = True
                continue
            p.live = False
            self._drop_snap(p)
            if p.leaving:
                self._hide(v)
            else:
                self._place(p)
        self.update()
        return busy

    # -- divider ----------------------------------------------------------------
    def _gutter(self):
        if not self._pair or any(self._p[v].leaving for v in self._p):
            return None
        a, b = self._cur(self._pair[0]), self._cur(self._pair[1])
        if a is None or b is None or b.left() - a.right() < 2:
            return None
        return QRectF(a.right(), 0, b.left() - a.right(), self.height())

    def _sh(self, v):
        self._hv = v
        self.update()

    def mouseMoveEvent(self, e):
        if self._drag:
            self.set_ratio((e.position().x() - self.GUT / 2.0) / max(1.0, self.width() - self.GUT))
            return
        g = self._gutter()
        hot = bool(g and g.adjusted(-4, 0, 4, 0).contains(e.position()))
        self._g_hv.to(1.0 if hot else 0.0)
        self.setCursor(Qt.CursorShape.SplitHCursor if hot else Qt.CursorShape.ArrowCursor)

    def mousePressEvent(self, e):
        g = self._gutter()
        if e.button() == Qt.MouseButton.LeftButton and g and g.adjusted(-4, 0, 4, 0).contains(e.position()):
            self._drag = True
            self._g_hv.to(1.0)
        else:
            super().mousePressEvent(e)

    def mouseReleaseEvent(self, e):
        self._drag = False
        super().mouseReleaseEvent(e)

    def mouseDoubleClickEvent(self, e):
        g = self._gutter()
        if g and g.adjusted(-4, 0, 4, 0).contains(e.position()):
            self.set_ratio(0.5, animate=True)
        else:
            super().mouseDoubleClickEvent(e)

    def leaveEvent(self, e):
        if not self._drag:
            self._g_hv.to(0.0)
        super().leaveEvent(e)

    def note_focus(self, widget):
        """Called with whatever widget just received keyboard focus: clicking into the other pane makes it the active one."""
        if self._pair is None or widget is None:
            return
        for v in self._pair:
            if v is not self._active and (widget is v or v.isAncestorOf(widget)):
                self.activated.emit(v)
                return

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.fillRect(self.rect(), T.c("window"))
        if not self._pair:
            return
        act = self._cur(self._active)
        if act is not None and act.top() > 0.05:
            amt = min(1.0, act.top() / self.TOP)
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(T.c("acc", amt))
            p.drawRoundedRect(QRectF(act.left() + 10, 0.4, max(0.0, act.width() - 20), 2.2), 1.1, 1.1)
        g = self._gutter()
        if g is not None:
            a = (.22 + .6 * self._hv) * min(1.0, g.width() / float(self.GUT))
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(T.c("mut", a))
            p.drawRoundedRect(QRectF(g.center().x() - 2, g.center().y() - 22, 4, 44), 2, 2)


# --------------------------------------------------------------------------
# Tab hover card
# --------------------------------------------------------------------------
def _two_lines(text, fm, width):
    """Split text into at most two lines that fit the width, eliding the second."""
    if fm.horizontalAdvance(text) <= width:
        return [text]
    cut = len(text)
    while cut > 1 and fm.horizontalAdvance(text[:cut]) > width:
        cut -= 1
    sp = text.rfind(" ", 0, cut + 1)
    if sp > cut * 0.5:
        cut = sp
    first, rest = text[:cut].rstrip(), text[cut:].lstrip()
    return [first, fm.elidedText(rest, Qt.TextElideMode.ElideRight, width)] if rest else [first]


class TabCard(QWidget):
    """The card that rises under a tab when the pointer rests on it: full title, address and what the tab is doing.
    Moving to the next tab slides the card over instead of closing and reopening it."""
    M, W = 18, 296

    def __init__(self, parent):
        super().__init__(parent)
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        self._title, self._host, self._chips = [], "", []
        self._a, self._x, self._y = 0.0, 0.0, 0.0
        self._tx, self._ty = 0.0, 0.0
        self._pending = None
        self._hh, self._prev, self._cf = 0.0, None, 1.0     # card height (eased), the content it is leaving, crossfade 0..1
        self._g = Glide(self, self._set, 16)
        self._gx = Glide(self, self._setx, 20, eps=0.05)
        self._gh = Glide(self, self._seth, 20, eps=0.05)
        self._gc = Glide(self, self._setc, 24, 1.0)
        self._delay = QTimer(self)
        self._delay.setSingleShot(True)
        self._delay.timeout.connect(self._reveal)
        T.changed.connect(self.update)
        self.hide()

    def _set(self, v):
        self._a = v
        if v <= 0.01 and self._g.t == 0.0:
            self.hide()
        self._place()
        self.update()

    def _setx(self, v):
        self._x = v
        self._place()

    def _seth(self, v):
        self._hh = v
        self.update()

    def _setc(self, v):
        self._cf = v
        if v >= 0.999:
            self._prev = None
        self.update()

    def _place(self):
        self.move(iround(self._x) - self.M, iround(self._ty + (1.0 - self._a) * 7) - self.M)

    def point_at(self, title, host, chips, center_x, top_y, parent_w):
        """Ask for the card to show for a tab. It appears after a short rest, or at once if a card is already up."""
        x = max(10.0, min(center_x - self.W / 2.0, parent_w - self.W - 10.0))
        self._pending = (title, host, chips, x, float(top_y))
        if self._a > 0.05 and self.isVisible():
            self._delay.stop()
            self._reveal()
        else:
            self._delay.start(430)

    def dismiss(self):
        self._delay.stop()
        self._pending = None
        self._g.to(0.0)

    def _reveal(self):
        if not self._pending:
            return
        title, host, chips, x, y = self._pending
        first = not (self._a > 0.05 and self.isVisible())
        if not first and self._hh > 0:
            # moving to another tab: the old words fade out as the new ones fade in, and the card grows or shrinks to fit
            self._prev = (self._title, self._host, self._chips)
            self._gc.v = self._cf = 0.0
            self._gc.to(1.0)
        fm = QFontMetricsF(ui_font(10, QFont.Weight.DemiBold))
        self._title = _two_lines(title or "New tab", fm, self.W - 32)
        self._host, self._chips = host, list(chips)[:3]
        h = 16 + 19 * len(self._title) + 4 + 16 + (30 if self._chips else 0) + 14
        full = 16 + 19 * 2 + 4 + 16 + 30 + 14                  # the tallest it can ever be: the widget is that size, always
        if self.height() != full + 2 * self.M:
            self.resize(self.W + 2 * self.M, full + 2 * self.M)
        self._ty = y
        if first:
            self._x = x
            self._gx.v = self._gx.t = x
            self._prev, self._cf = None, 1.0
            self._hh = self._gh.v = self._gh.t = float(h)
        self._gh.to(float(h), instant=first)
        self._gx.to(x, instant=first)
        self._place()
        self.show()
        self.raise_()
        self._g.to(1.0)
        self.update()

    def paintEvent(self, _):
        p = QPainter(self)
        quality(p)
        p.setOpacity(window(self._a, 0.0, 0.85))
        m = self.M
        r = QRectF(m, m, self.W, max(0.0, self._hh))
        soft_shadow(p, r, 14, spread=m - 2, strength=.30 if T.dark else .18, dy=6)
        p.setPen(QPen(T.c("line"), 1))
        p.setBrush(T.c("card"))
        p.drawRoundedRect(r, 14, 14)
        p.save()
        p.setClipRect(r.adjusted(0, 1, 0, -1))
        base = p.opacity()
        if self._prev is not None:
            p.setOpacity(base * (1.0 - window(self._cf, 0.0, 0.7)))
            self._paint_content(p, r, *self._prev)
        p.setOpacity(base * (window(self._cf, 0.25, 1.0) if self._prev is not None else 1.0))
        self._paint_content(p, r, self._title, self._host, self._chips)
        p.restore()

    def _paint_content(self, p, r, lines, host, chips):
        y = r.top() + 14
        f = ui_font(10, QFont.Weight.DemiBold)
        fm = QFontMetricsF(f)
        p.setFont(f)
        p.setPen(T.c("text"))
        for line in lines:
            p.drawText(QPointF(r.left() + 16, y + fm.ascent()), line)
            y += 19
        y += 4
        hf = ui_font(9)
        hm = QFontMetricsF(hf)
        p.setFont(hf)
        p.setPen(T.c("mut"))
        p.drawText(QPointF(r.left() + 16, y + hm.ascent()), hm.elidedText(host, Qt.TextElideMode.ElideMiddle, self.W - 32))
        y += 16
        if chips:
            x = r.left() + 16
            y += 10
            cf = ui_font(8.2, QFont.Weight.Medium)
            cm = QFontMetricsF(cf)
            for text, tone in chips:
                w = cm.horizontalAdvance(text) + 18
                box = QRectF(x, y, w, 20)
                col = T.c(tone) if tone else T.c("mut")
                bg = QColor(col)
                bg.setAlphaF(.16)
                p.setPen(Qt.PenStyle.NoPen)
                p.setBrush(bg)
                p.drawRoundedRect(box, 10, 10)
                p.setFont(cf)
                p.setPen(col)
                p.drawText(box, Qt.AlignmentFlag.AlignCenter, text)
                x += w + 6


# --------------------------------------------------------------------------
# Tab search
# --------------------------------------------------------------------------
class _SearchEdit(Edit):
    nav = pyqtSignal(int)
    accept = pyqtSignal()
    escape = pyqtSignal()

    def keyPressEvent(self, e):
        k = e.key()
        if k == Qt.Key.Key_Down:
            self.nav.emit(1)
        elif k == Qt.Key.Key_Up:
            self.nav.emit(-1)
        elif k in (Qt.Key.Key_Return, Qt.Key.Key_Enter):
            self.accept.emit()
        elif k == Qt.Key.Key_Escape:
            self.escape.emit()
        else:
            QLineEdit.keyPressEvent(self, e)


class TabSearch(QWidget):
    """Find any open tab (or reopen a recently closed one) by typing part of its title or address."""
    chosen = pyqtSignal(object)
    CARD_W, ROW, HEAD, TOPBAR, MAXH = 560, 42, 28, 58, 400

    def __init__(self, root):
        super().__init__(root)
        self._rows, self._items, self._sel = [], [], -1
        self._a, self._closing = 0.0, False
        self._scroll_t = 0.0
        self._sy, self._ss = 0.0, 0.0
        self.setMouseTracking(True)
        self.setFocusPolicy(Qt.FocusPolicy.StrongFocus)
        self.edit = _SearchEdit()
        self.edit.setParent(self)
        self.edit.setFrame(False)
        self.edit.setPlaceholderText("Search tabs")
        self.edit.textChanged.connect(self._refilter)
        self.edit.nav.connect(self._step)
        self.edit.accept.connect(self._accept)
        self.edit.escape.connect(self.finish)
        self.fx_edit = QGraphicsOpacityEffect(self.edit)     # the field arrives a beat after the card
        self.fx_edit.setOpacity(0.0)
        self.edit.setGraphicsEffect(self.fx_edit)
        self._g = Glide(self, self._set, 15)
        self._g_sel = Glide(self, self._sel_y, 22, eps=0.05)
        self._g_scroll = Glide(self, self._sc_set, 18, eps=0.05)
        self._style()
        T.changed.connect(self._style)
        self.hide()

    def _style(self):
        self.edit.setStyleSheet(f"QLineEdit{{background:transparent;border:0;color:{T.c('text').name()};font-size:15px;"
                                f"selection-background-color:{T.c('acc').name()};selection-color:#fff}}")
        self.update()

    # -- data -------------------------------------------------------------------
    def present(self, rows):
        """rows: dicts with kind ('tab' or 'closed'), title, host, icon (QPixmap or None), and view or url."""
        self._rows = rows
        self._closing = False
        self.edit.blockSignals(True)
        self.edit.clear()
        self.edit.blockSignals(False)
        self.setGeometry(self.parentWidget().rect())
        self._refilter("", first=True)
        self.show()
        self.raise_()
        self._g.to(1.0)
        self.edit.setFocus()

    def _refilter(self, text="", first=False):
        q = (text if isinstance(text, str) else self.edit.text()).strip().lower()
        picked = [r for r in self._rows if not q or q in (r["title"] or "").lower() or q in (r["host"] or "").lower()]
        items, last = [], None
        for r in picked:
            if r["kind"] != last:
                items.append(("head", "Open tabs" if r["kind"] == "tab" else "Recently closed"))
                last = r["kind"]
            items.append(("row", r))
        self._items = items
        sel = [i for i, it in enumerate(items) if it[0] == "row"]
        cur = next((i for i, it in enumerate(items) if it[0] == "row" and it[1].get("current")), None)
        self._sel = (cur if (first and cur is not None) else sel[0]) if sel else -1
        self._scroll_t = 0.0
        self._g_scroll.to(0.0, instant=True)
        self._ensure_visible(instant=True)
        self._snap_sel()
        self.update()

    def _y_of(self, index):
        y = 0
        for i, (kind, _d) in enumerate(self._items):
            h = self.HEAD if kind == "head" else self.ROW
            if i == index:
                return y, h
            y += h
        return y, 0

    def _total(self):
        return sum(self.HEAD if k == "head" else self.ROW for k, _ in self._items)

    def _list_h(self):
        return max(self.ROW, min(self.MAXH, self._total()))

    def _card(self):
        w = min(self.CARD_W, self.width() - 40)
        h = self.TOPBAR + (self._list_h() + 10 if self._items else 52)
        # whole pixels, so the card, its field and its rows share one grid and nothing shimmers against anything else
        return QRectF(float(iround((self.width() - w) / 2.0)), float(64 + iround((1 - self._a) * -10)), float(iround(w)), float(h))

    def _snap_sel(self):
        y, _h = self._y_of(self._sel) if self._sel >= 0 else (0, 0)
        self._g_sel.to(y, instant=True)
        self._sy = y

    def _ensure_visible(self, instant=False):
        if self._sel < 0:
            return
        y, h = self._y_of(self._sel)
        top, view = self._scroll_t, self._list_h()
        if y < top:
            top = max(0.0, y - (self.HEAD if y >= self.HEAD else 0))
        elif y + h > top + view:
            top = y + h - view
        top = max(0.0, min(max(0.0, self._total() - view), top))
        self._scroll_t = top
        self._g_scroll.to(top, instant=instant)

    def _sel_y(self, v):
        self._sy = v
        self.update()

    def _sc_set(self, v):
        self._ss = v
        self.update()

    def _set(self, v):
        self._a = v
        self.edit.setGeometry(self._edit_rect())
        self.fx_edit.setOpacity(window(v, 0.22, 0.9))
        if v <= .004 and self._closing:
            self.hide()
        self.update()

    def _edit_rect(self):
        c = self._card()
        return QRect(iround(c.left() + 52), iround(c.top() + 8), iround(c.width() - 52 - 20), 42)

    def resizeEvent(self, e):
        super().resizeEvent(e)
        self.edit.setGeometry(self._edit_rect())

    # -- interaction -------------------------------------------------------------
    def _rows_idx(self):
        return [i for i, it in enumerate(self._items) if it[0] == "row"]

    def _step(self, d):
        idx = self._rows_idx()
        if not idx:
            return
        pos = idx.index(self._sel) if self._sel in idx else -1
        self._sel = idx[(pos + d) % len(idx)]
        y, _h = self._y_of(self._sel)
        self._g_sel.to(y)
        self._ensure_visible()

    def _accept(self):
        if 0 <= self._sel < len(self._items) and self._items[self._sel][0] == "row":
            self.finish(self._items[self._sel][1])
        else:
            self.finish()

    def finish(self, row=None):
        if self._closing:
            return
        self._closing = True
        self._g.rate = 22
        self._g.to(0.0)
        if isinstance(row, dict):
            self.chosen.emit(row)

    def _row_at(self, pos):
        c = self._card()
        top = c.top() + self.TOPBAR
        if not (c.left() <= pos.x() <= c.right() and top <= pos.y() <= top + self._list_h()):
            return -1
        y = pos.y() - top + self._ss
        acc = 0
        for i, (kind, _d) in enumerate(self._items):
            h = self.HEAD if kind == "head" else self.ROW
            if acc <= y < acc + h:
                return i if kind == "row" else -1
            acc += h
        return -1

    def mouseMoveEvent(self, e):
        i = self._row_at(e.position())
        if i >= 0 and i != self._sel:
            self._sel = i
            self._g_sel.to(self._y_of(i)[0])

    def mousePressEvent(self, e):
        i = self._row_at(e.position())
        if i >= 0:
            self.finish(self._items[i][1])
        elif not self._card().contains(e.position()):
            self.finish()
        e.accept()

    def wheelEvent(self, e):
        d = e.angleDelta().y()
        if d and self._total() > self._list_h():
            top = max(0.0, min(self._total() - self._list_h(), self._scroll_t - d * 0.6))
            self._scroll_t = top
            self._g_scroll.to(top)
        e.accept()

    def event(self, e):
        if e.type() == QEvent.Type.ShortcutOverride and e.key() == Qt.Key.Key_Escape:
            e.accept()
            return True
        return super().event(e)

    # -- painting ------------------------------------------------------------------
    def paintEvent(self, _):
        p = QPainter(self)
        quality(p)
        p.fillRect(self.rect(), T.c("shadow", .30 * self._a))
        c = self._card()
        soft_shadow(p, c, 20, spread=34, strength=.34 if T.dark else .22, dy=14, scale=window(self._a, 0.0, 0.7))
        p.setOpacity(window(self._a, 0.0, 0.7))
        p.setPen(QPen(T.c("line"), 1))
        p.setBrush(T.c("card"))
        p.drawRoundedRect(c, 20, 20)
        p.setOpacity(window(self._a, 0.22, 0.9))                 # content follows the card
        draw_icon(p, "search", QRectF(c.left() + 20, c.top() + 21, 18, 18), T.c("mut"))
        top = c.top() + self.TOPBAR
        p.setPen(QPen(T.c("line"), 1))
        p.drawLine(QPointF(c.left() + 14, top - 2), QPointF(c.right() - 14, top - 2))
        if not self._items:
            p.setFont(ui_font(10.5))
            p.setPen(T.c("mut"))
            p.drawText(QRectF(c.left(), top, c.width(), 48), Qt.AlignmentFlag.AlignCenter, "No matching tabs")
            return
        p.save()
        p.setClipRect(QRectF(c.left() + 8, top, c.width() - 16, self._list_h()))
        base = top - self._ss
        if self._sel >= 0:
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(T.c("acc"))
            p.drawRoundedRect(QRectF(c.left() + 8, base + self._sy + 1, c.width() - 16, self.ROW - 2), 10, 10)
        y = base
        near = abs(self._sy - self._y_of(self._sel)[0]) if self._sel >= 0 else 99
        for i, (kind, data) in enumerate(self._items):
            if kind == "head":
                p.setFont(ui_font(8.2, QFont.Weight.DemiBold))
                p.setPen(T.c("faint"))
                p.drawText(QRectF(c.left() + 22, y, c.width() - 44, self.HEAD), Qt.AlignmentFlag.AlignVCenter | Qt.AlignmentFlag.AlignLeft, data.upper())
                y += self.HEAD
                continue
            on = i == self._sel and near < self.ROW * .6
            fg = QColor("#ffffff") if on else T.c("text")
            sub = QColor(255, 255, 255, 190) if on else T.c("mut")
            ix, iy = c.left() + 22, y + (self.ROW - 16) / 2.0
            ic = data.get("icon")
            if ic is not None:
                p.drawPixmap(QRectF(ix, iy, 16, 16), ic, QRectF(ic.rect()))
            else:
                draw_icon(p, "clock" if data["kind"] == "closed" else "globe", QRectF(ix, iy, 16, 16), sub)
            host = data.get("host") or ""
            hf, tf = ui_font(9), ui_font(10.2, QFont.Weight.Medium)
            hm, tm = QFontMetricsF(hf), QFontMetricsF(tf)
            right = c.right() - 24
            hw = min(hm.horizontalAdvance(host), 170.0)
            p.setFont(hf)
            p.setPen(sub)
            p.drawText(QPointF(right - hw, y + self.ROW / 2.0 + (hm.ascent() - hm.descent()) / 2.0), hm.elidedText(host, Qt.TextElideMode.ElideMiddle, hw))
            tx = ix + 28
            p.setFont(tf)
            p.setPen(fg)
            p.drawText(QPointF(tx, y + self.ROW / 2.0 + (tm.ascent() - tm.descent()) / 2.0),
                       tm.elidedText(data.get("title") or host or "New tab", Qt.TextElideMode.ElideRight, max(40.0, right - hw - 14 - tx)))
            y += self.ROW
        p.restore()


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
        self._rip = Ripples(self)

    def mousePressEvent(self, e):
        if e.button() == Qt.MouseButton.LeftButton and self.isEnabled():
            play_sound("click")
            if fx_on():
                self._rip.add(e.position().x(), e.position().y())
        super().mousePressEvent(e)

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
        if self._rip.items:
            self._rip.paint(p, r, 11, QColor("#ffffff") if k in ("pri", "dng") else T.c("text"), r.width() * 0.8)
        p.setFont(ui_font(10, QFont.Weight.Medium))
        p.setPen(fg)
        p.drawText(r, Qt.AlignmentFlag.AlignCenter, self.text())


class Badge(QWidget):
    """The round icon at the top of a card. It pops in, and it can play out an answer the way Face ID does: on success the
    padlock springs open, a ring draws itself around the badge, the lock turns into a check mark that is drawn stroke by
    stroke, and a pulse spreads outward. On a refusal the lock rattles and flushes red."""

    def __init__(self, icon, tone):
        super().__init__()
        self.icon, self.tone, self._s = icon, tone, 0.6
        self.setFixedSize(60, 60)
        self._g = Glide(self, self._set, 11, 0.6, bounce=0.3)      # a touch of overshoot: it pops, then settles
        self.verdict, self._vt = None, 0.0                           # None, "ok" or "bad", and seconds since it began
        self.on_change = None                                        # the card repaints its pulse when this fires
        self._vrun = self._vstep

    def _set(self, v):
        self._s = v
        self.update()

    def pop(self):
        self._g.to(1.0)

    def verify(self, ok):
        if not fx_on():
            return
        self.verdict, self._vt = ("ok" if ok else "bad"), 0.0
        FrameClock.get().add(self._vrun)

    def _vstep(self, dt):
        self._vt += dt
        self.update()
        if self.on_change:
            self.on_change()
        if self.verdict == "bad" and self._vt > 1.0:
            self.verdict = None
            self.update()
            return False
        return self.verdict == "ok" and self._vt < 1.3 or self.verdict == "bad"

    def rings(self):
        """(radius, opacity) of the pulses leaving the badge, measured from its centre. The card paints them."""
        if self.verdict != "ok":
            return []
        out = []
        for delay in (0.22, 0.38):
            u = (self._vt - delay) / 0.75
            if 0.0 < u < 1.0:
                out.append((30.0 + 54.0 * ease_out(u), 0.55 * (1.0 - u) ** 1.5))
        return out

    @staticmethod
    def _lock(p, col, opened, alpha):
        """The padlock, drawn by hand so its shackle can lift. Same shape as the 'lock' icon, on the same 24 unit grid."""
        p.save()
        p.setOpacity(p.opacity() * alpha)
        k = 28.0 / 24.0
        p.translate(16.0, 16.0)
        p.scale(k, k)
        p.setBrush(Qt.BrushStyle.NoBrush)
        p.setPen(QPen(col, 1.6, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin))
        p.drawRoundedRect(QRectF(5.5, 10.8, 13.0, 9.4), 2.4, 2.4)
        lift = 1.9 * opened
        path = QPainterPath()
        path.moveTo(8.5, 10.8)
        path.lineTo(8.5, 8.2 - lift)
        path.arcTo(QRectF(8.5, 4.7 - lift, 7.0, 7.0), 180.0, -180.0)
        path.lineTo(15.5, 10.8 - 3.5 * opened)
        p.drawPath(path)
        p.restore()

    def paintEvent(self, _):
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        c = QPointF(self.width() / 2, self.height() / 2)
        s = self._s
        p.translate(c)
        p.scale(s, s)
        p.translate(-c)
        col = T.c(self.tone)
        t = self._vt
        if self.verdict == "ok":
            col = T.mix(self.tone, "ok", ease_out(t / 0.35))
            ok = T.c("ok")
            bump = 1.0 + 0.07 * math.sin(math.pi * clamp01((t - 0.55) / 0.45))
            p.translate(c)
            p.scale(bump, bump)
            p.translate(-c)
            fill = QColor(col)
            fill.setAlphaF(0.17 + 0.07 * ease_out(t / 0.5))
            p.setPen(Qt.PenStyle.NoPen)
            p.setBrush(fill)
            p.drawEllipse(QRectF(2, 2, 56, 56))
            # 1. the padlock springs open, then dissolves
            fade = 1.0 - ease_in_out((t - 0.34) / 0.26)
            if fade > 0.01:
                p.save()
                sc = 1.0 - 0.22 * (1.0 - fade)
                p.translate(c)
                p.scale(sc, sc)
                p.translate(-c)
                self._lock(p, col, ease_out(t / 0.26), fade)
                p.restore()
            # 2. a ring draws itself around the badge
            prog = ease_in_out((t - 0.12) / 0.5)
            if prog > 0.0:
                p.setBrush(Qt.BrushStyle.NoBrush)
                p.setPen(QPen(ok, 3.0, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap))
                p.drawArc(QRectF(3.5, 3.5, 53, 53), 90 * 16, -int(prog * 360 * 16))
            # 3. the check mark is drawn stroke by stroke
            cp = ease_out((t - 0.40) / 0.38)
            if cp > 0.0:
                k = 28.0 / 24.0
                pts = [QPointF(16 + x * k, 16 + y * k) for x, y in ((5.5, 12.5), (9.8, 16.8), (18.5, 7.8))]
                l1, l2 = math.hypot(4.3, 4.3), math.hypot(8.7, 9.0)
                run = cp * (l1 + l2)
                path = QPainterPath(pts[0])
                if run <= l1:
                    f = run / l1
                    path.lineTo(pts[0] + (pts[1] - pts[0]) * f)
                else:
                    path.lineTo(pts[1])
                    f = (run - l1) / l2
                    path.lineTo(pts[1] + (pts[2] - pts[1]) * f)
                p.setBrush(Qt.BrushStyle.NoBrush)
                p.setPen(QPen(ok, 3.2, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin))
                p.drawPath(path)
            return
        if self.verdict == "bad":
            flush = ease_out(t / 0.12) * (1.0 - smoothstep((t - 0.45) / 0.45))
            col = T.mix(self.tone, "bad", flush)
            p.setPen(Qt.PenStyle.NoPen)
            fill = QColor(col)
            fill.setAlphaF(0.17 + 0.08 * flush)
            p.setBrush(fill)
            p.drawEllipse(QRectF(2, 2, 56, 56))
            p.save()
            p.translate(c)
            p.rotate(shake_offset(t, 1.0, 9.0, 5.0) * 11.0)         # the padlock rattles
            p.translate(-c)
            draw_icon(p, self.icon, QRectF(16, 16, 28, 28), col)
            p.restore()
            return
        p.setPen(Qt.PenStyle.NoPen)
        fill = QColor(col)
        fill.setAlphaF(.17)
        p.setBrush(fill)
        p.drawEllipse(QRectF(2, 2, 56, 56))
        draw_icon(p, self.icon, QRectF(16, 16, 28, 28), col)


class Sheet(QWidget):
    done = pyqtSignal(object)

    def __init__(self, root, icon="info", tone="acc", title="", body="", rows=(), buttons=(), cancel=None, field=None, hold=()):
        """hold: button values that do NOT close the card. The card waits for resolve(): True plays the Face ID style success,
        False shakes it and keeps it open for another try, None just closes it."""
        super().__init__(root)
        self._cancel, self._first = cancel, (buttons[0][2] if buttons else None)
        self._hold, self._pending, self._shk, self._shx, self._body = set(hold), False, None, 0.0, None
        self._shk_run = self._shk_step
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
        self.badge.on_change = self.update
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
            self._body = b
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
        self.card.move((self.width() - self.card.width()) // 2 + iround(self._shx), self._base_y + iround((1 - self._a) * 26))

    def resizeEvent(self, e):
        self._layout_card()
        super().resizeEvent(e)

    def _set(self, v):
        self._a = v
        self.fx.setOpacity(window(v, 0.14, 0.85))                # contents arrive just after the card surface
        self.card.move(self.card.x(), self._base_y + iround((1 - v) * 26))
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
        play_sound("sheet")
        if self.edit is not None:
            QTimer.singleShot(60, self.edit.setFocus)
        else:
            self.setFocus()
        self._g.to(1.0)
        FrameClock.get().after(0.09, self.badge.pop)

    def finish(self, value):
        if self._closing or self._pending:
            return
        key = value[0] if isinstance(value, tuple) else value
        if key in self._hold:
            self._pending = True          # stays open: whoever asked decides how it ends (resolve)
            self.done.emit(value)
            return
        self._begin_close()
        self.done.emit(value)

    def _begin_close(self):
        if self._closing:
            return
        self._closing = True
        self._g.rate = 20
        self._g.to(0.0)

    def resolve(self, result, message=""):
        """Answer a held card. True: success (the padlock opens, a ring and a check draw, a pulse spreads), then it closes.
        False: it shakes and shows `message`, ready for another try. None: it simply closes."""
        if self._closing:
            return
        if result is None:
            self._pending = False
            self._begin_close()
        elif result:
            self.badge.verify(True)
            play_sound("unlock")
            self._pending = True          # ignore input while the celebration plays
            FrameClock.get().after(1.0 if fx_on() else 0.0, self._begin_close)
        else:
            self._pending = False
            self.badge.verify(False)
            play_sound("error")
            if fx_on():
                self._shk = 0.0
                FrameClock.get().add(self._shk_run)
            if self._body is not None and message:
                self._body.setText(message)
                self._body.setStyleSheet(f"color:{T.c('bad').name()};font-size:13px;background:transparent")
            if self.edit is not None:
                self.edit.clear()
                self.edit.setFocus()

    def _shk_step(self, dt):
        self._shk += dt
        done = self._shk > 0.7
        self._shx = 0.0 if done else shake_offset(self._shk, 14.0, 7.5, 6.0)
        self._layout_card()
        self.update()
        if done:
            self._shk = None
        return not done

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
        soft_shadow(p, r, 22, spread=34, strength=.30 if T.dark else .22, dy=14, scale=window(self._a, 0.0, 0.7))
        p.setOpacity(window(self._a, 0.0, 0.7))
        p.setPen(QPen(T.c("line"), 1))
        p.setBrush(T.c("card"))
        p.drawRoundedRect(r, 22, 22)
        pulses = self.badge.rings()
        if pulses:
            c = QPointF(self.badge.mapTo(self, self.badge.rect().center()))
            p.setBrush(Qt.BrushStyle.NoBrush)
            for rad, a in pulses:
                col = T.c("ok")
                col.setAlphaF(a)
                p.setPen(QPen(col, 2.2))
                p.drawEllipse(c, rad, rad)


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
