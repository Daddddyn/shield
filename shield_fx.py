"""
shield_fx.py: the "liquid" look of Shield's motion. One visual idea is used everywhere: a DROP.

  * Open or switch to a tab and the page falls out of that tab like a drop of water: a small circle that spreads until it
    has covered the old page. Its edge wobbles like a liquid surface, throws a soft shadow onto what it covers, and
    carries a thin ripple that trails behind it. (DropReveal)
  * The same drop turns the whole window from dark to light, starting where you clicked.
  * Press a button and a ripple spreads from your finger. A toggle sends out a ring. A bookmark bursts. (shield_ui.py)

Everything here runs on the shared FrameClock from shield_motion.py (one clock for the whole browser, locked to the
screen's refresh), and everything checks fx_on() first, so turning "Fluid motion" off in Settings, or turning off
animations in Windows, gives a calm browser with none of it.

How the reveal stays smooth: it is NOT re-laying out the page. The new page is already shown, complete, underneath. On top
of it sits a picture of the OLD page with a growing hole in it. Painting a picture with a hole is one cheap blit per frame
(about 3 ms for a full window at 200% scaling), and the hole's edge is anti-aliased, so it never steps or shimmers.
"""
import math
import os

from PyQt6.QtCore import QPointF, QRectF, Qt, pyqtSignal
from PyQt6.QtGui import QColor, QPainter, QPainterPath, QPen
from PyQt6.QtWidgets import QWidget

from shield_motion import FrameClock, Spring, clamp01, lerp, smoothstep

# --------------------------------------------------------------------------
# On / off
# --------------------------------------------------------------------------
_state = {"on": True}


def _os_animations():
    """False when Windows is set to 'Show animations: off' (Settings > Accessibility > Visual effects)."""
    if os.name != "nt":
        return True
    try:
        import ctypes
        flag = ctypes.c_int(1)
        # SPI_GETCLIENTAREAANIMATION = 0x1042
        if ctypes.windll.user32.SystemParametersInfoW(0x1042, 0, ctypes.byref(flag), 0):
            return bool(flag.value)
    except Exception:
        pass
    return True


def set_enabled(on):
    """Called by Shield when the 'Fluid motion' setting changes."""
    _state["on"] = bool(on)


def fx_on():
    """Should the extra effects (not the basic UI motion) play right now?"""
    return _state["on"] and _os_animations() and os.environ.get("SHIELD_NO_FX") != "1"


# --------------------------------------------------------------------------
# Small shared helpers
# --------------------------------------------------------------------------
def ease_out(t):
    """Fast start, soft landing. For effects measured in time rather than driven by a spring."""
    t = clamp01(t)
    return 1.0 - (1.0 - t) ** 3


def ease_in_out(t):
    t = clamp01(t)
    return 4 * t * t * t if t < 0.5 else 1.0 - (-2 * t + 2) ** 3 / 2


def shake_offset(t, amp=10.0, freq=7.0, decay=6.0):
    """A damped side-to-side shake, the way a wrong passcode answers on an iPhone. t is seconds since it began."""
    if t < 0:
        return 0.0
    return amp * math.exp(-decay * t) * math.sin(2.0 * math.pi * freq * t)


class Ripples:
    """Water ripples that spread from where a control was pressed. The owner calls add() on press and paint() from its
    paintEvent; this class steps itself on the shared clock and asks the owner to repaint."""
    LIFE = 0.62

    def __init__(self, owner):
        self.owner = owner
        self.items = []             # [x, y, age in seconds, strength]
        self._run = self._step

    def add(self, x, y, strength=1.0):
        self.items.append([float(x), float(y), 0.0, strength])
        if len(self.items) > 4:
            self.items.pop(0)
        FrameClock.get().add(self._run)

    def clear(self):
        self.items.clear()

    def _step(self, dt):
        for it in self.items:
            it[2] += dt
        self.items = [it for it in self.items if it[2] < self.LIFE]
        try:
            self.owner.update()
        except RuntimeError:
            self.items.clear()
        return bool(self.items)

    def paint(self, p, clip_rect, radius, color, reach):
        """clip_rect/radius: the shape the ripple is confined to. reach: how far (px) it travels. color: QColor."""
        if not self.items:
            return
        p.save()
        path = QPainterPath()
        path.addRoundedRect(QRectF(clip_rect), radius, radius)
        p.setClipPath(path)
        p.setPen(Qt.PenStyle.NoPen)
        for x, y, age, k in self.items:
            u = clamp01(age / self.LIFE)
            r = lerp(3.0, reach, ease_out(u))
            col = QColor(color)
            col.setAlphaF(max(0.0, 0.26 * k * (1.0 - u) ** 1.6))
            p.setBrush(col)
            p.drawEllipse(QPointF(x, y), r, r)
            # a thin brighter rim gives the ripple a surface, like the edge of a wave
            rim = QColor(color)
            rim.setAlphaF(max(0.0, 0.34 * k * (1.0 - u) ** 2.2))
            p.setBrush(Qt.BrushStyle.NoBrush)
            p.setPen(QPen(rim, 1.2))
            p.drawEllipse(QPointF(x, y), r, r)
            p.setPen(Qt.PenStyle.NoPen)
        p.restore()


# --------------------------------------------------------------------------
# The drop
# --------------------------------------------------------------------------
class DropReveal(QWidget):
    """A picture of how things looked a moment ago, laid over the live widgets, with a circular hole that grows from a point.
    Inside the hole you see the live (new) look; outside it, the old one. Child of whatever it covers; click-through."""
    finished = pyqtSignal()

    OMEGA, KICK = 9.5, 2.2        # spring: a quick kick out of the tab, then it eases to a stop
    FULL = 0.93                   # the hole covers everything when the spring is 93% done (the last 7% would only crawl into a corner)
    WOBBLE = 0.05                 # how lively the liquid edge is (fraction of the radius)
    POINTS = 200

    def __init__(self, parent):
        super().__init__(parent)
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        self.setAttribute(Qt.WidgetAttribute.WA_NoSystemBackground)
        self._pm = None
        self._o = QPointF()
        self._R = 1.0
        self._s = Spring(0.0, 1.0, 1.0, 0.0005)
        self._time = 0.0
        self._k = 1.0
        self._accent, self._bg, self._dark = QColor("#0a84ff"), QColor("#161618"), True
        self._run = self._step
        self.hide()

    # -- control ---------------------------------------------------------------
    def playing(self):
        return self.isVisible()

    def play(self, pm, origin, accent, bg, dark=True, strength=1.0):
        """pm: the old look (QPixmap) or None for a flat colour. origin: where the drop lands, in this widget's coordinates."""
        host = self.parentWidget()
        if host is None or host.width() < 40 or host.height() < 40:
            return
        self.setGeometry(host.rect())
        self._pm = pm if (pm is not None and not pm.isNull()) else None
        self._o = QPointF(origin)
        w, h = float(self.width()), float(self.height())
        far = max(math.hypot(self._o.x() - cx, self._o.y() - cy) for cx in (0.0, w) for cy in (0.0, h))
        self._R = far * 1.012 + 3.0
        self._accent, self._bg, self._dark = QColor(accent), QColor(bg), bool(dark)
        self._k = strength
        self._s = Spring(0.0, 1.0, 1.0, 0.0005)
        self._s.t = 1.0
        self._s.omega = self.OMEGA
        self._s.v = self.KICK
        self._time = 0.0
        self.show()
        self.raise_()
        self.update()
        FrameClock.get().add(self._run)

    def cancel(self):
        FrameClock.get().remove(self._run)
        if self.isVisible():
            self._pm = None
            self.hide()

    def resizeEvent(self, e):
        super().resizeEvent(e)
        if self.isVisible():
            self.cancel()          # the picture no longer matches the window: just let the live page show

    # -- motion ----------------------------------------------------------------
    def _step(self, dt):
        self._s.step(dt)
        self._time += dt
        if self._s.x >= self.FULL or self._time > 1.6:
            self._pm = None
            self.hide()
            self.finished.emit()
            return False
        self.update()
        return True

    def _progress(self):
        return clamp01(self._s.x / self.FULL)

    def _radius(self):
        return self._R * self._progress()

    def _blob(self, r, progress):
        """The outline of the hole: a circle whose edge ripples like a liquid surface and settles round as it grows."""
        path = QPainterPath()
        amp = self.WOBBLE * ((1.0 - progress) ** 1.4) * smoothstep(progress / 0.07) * self._k
        if amp < 0.0008:
            path.addEllipse(self._o, r, r)
            return path
        t = self._time
        n = self.POINTS
        ox, oy = self._o.x(), self._o.y()
        for i in range(n):
            a = 2.0 * math.pi * i / n
            k = 1.0 + amp * (0.62 * math.sin(3.0 * a + 9.0 * t) + 0.38 * math.sin(5.0 * a - 13.0 * t + 1.3))
            x, y = ox + r * k * math.cos(a), oy + r * k * math.sin(a)
            if i == 0:
                path.moveTo(x, y)
            else:
                path.lineTo(x, y)
        path.closeSubpath()
        return path

    # -- painting ---------------------------------------------------------------
    def paintEvent(self, _):
        s = self._progress()
        r = self._radius()
        p = QPainter(self)
        p.setRenderHint(QPainter.RenderHint.Antialiasing)
        p.setRenderHint(QPainter.RenderHint.SmoothPixmapTransform)
        full = QRectF(self.rect())
        if r < 0.6:
            self._paint_old(p, full, 0.0)
            return
        blob = self._blob(r, s)
        outside = QPainterPath()
        outside.addRect(full)
        outside.addPath(blob)                       # odd-even fill: rectangle minus the hole
        # 1. the old look, with the hole cut out of it
        p.save()
        p.setClipPath(outside)
        self._paint_old(p, full, s)
        # 2. the new surface lifts away from the old one: a soft shadow just outside the edge
        shade = QColor(0, 0, 0)
        for width, a in ((64.0, 0.045), (40.0, 0.06), (22.0, 0.08), (9.0, 0.10)):
            shade.setAlphaF(a * (1.0 if self._dark else 0.7) * (1.0 - 0.5 * s))
            p.setPen(QPen(shade, width, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin))
            p.setBrush(Qt.BrushStyle.NoBrush)
            p.drawPath(blob)
        p.restore()
        # 3. the rim: a glow in the accent colour, a bright thread of light on top
        fade = (1.0 - s) ** 0.9
        glow = QColor(self._accent)
        glow.setAlphaF(0.20 * fade)
        p.setBrush(Qt.BrushStyle.NoBrush)
        p.setPen(QPen(glow, 12.0, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin))
        p.drawPath(blob)
        line = QColor(self._accent).lighter(135)
        line.setAlphaF(0.85 * fade)
        p.setPen(QPen(line, 2.2, Qt.PenStyle.SolidLine, Qt.PenCapStyle.RoundCap, Qt.PenJoinStyle.RoundJoin))
        p.drawPath(blob)
        # 4. a ripple trailing inside the hole, like the second ring of a water drop
        rr = r - 26.0 - 46.0 * s
        if rr > 8.0:
            ring = QColor(255, 255, 255)
            ring.setAlphaF(0.20 * (1.0 - s) ** 1.2)
            p.setPen(QPen(ring, 1.6))
            p.drawEllipse(self._o, rr, rr)

    def _paint_old(self, p, full, s):
        if self._pm is not None:
            p.drawPixmap(full, self._pm, QRectF(self._pm.rect()))
        else:
            p.fillRect(full, self._bg)
        # the old page darkens a little as it is covered, which sells the depth
        dim = 0.22 * 4.0 * s * (1.0 - s)
        if dim > 0.004:
            p.fillRect(full, QColor(0, 0, 0, int(255 * dim * (1.0 if self._dark else 0.55))))
