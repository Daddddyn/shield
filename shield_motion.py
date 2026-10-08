"""
shield_motion.py: the motion engine behind every animation in Shield.

These are the same ideas Apple's fluid interfaces are built on:

  * Springs, not fixed-time curves. A spring has position AND velocity, so when something changes its mind halfway
    (hover out while hovering in, close a split while it is still opening) the motion carries on smoothly instead of
    restarting or snapping. It also starts gently and lands softly, which is what reads as "premium".
  * One clock for everything, locked to the display. Every animation is stepped by the same clock with the same time
    delta, so they all move in lockstep and the window repaints once per frame, not once per animation.
  * The clock IS the screen's vertical blank. On Windows a tiny background thread sleeps on the compositor's vblank
    (DwmFlush) and wakes the UI exactly when a frame is due. A timer can only guess the refresh rate (16 ms ticks on a
    16.67 ms display beat against each other and drop a frame every second or so, which is what "choppy" looks like).
    Time deltas come from the vblank timestamp itself, so a frame that arrives late is caught up exactly, never
    stretched. Where vblank can't be waited on, a precise timer with a smoothed delta takes over.
  * Whole pixels only at the last step. Positions are kept as floats, and rounded by EDGE (left and right
    separately) when a widget is placed, so two neighbours never drift a pixel apart.
  * Sequencing lives on the same clock (FrameClock.after), so "then this, a beat later" is counted in frames of the
    same timeline instead of by a separate timer that can land between two frames.

No widgets in this file; it only needs QtCore/QtGui.
"""
import math
import os
import threading
import time

from PyQt6.QtCore import QObject, QRect, Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QGuiApplication

# Glide "rate" numbers used throughout shield_ui.py were written for exponential easing. This maps them onto spring
# stiffness so every existing animation keeps its speed but gains a soft start and velocity continuity.
OMEGA_PER_RATE = 1.5

MAX_DT = 1.0 / 20.0     # a long stall must not teleport anything


def spring_step(x, v, target, omega, zeta, dt):
    """Advance a damped spring by dt seconds. Closed form, so it is exact and stable at any frame time.

    omega: natural frequency (rad/s, higher = snappier). zeta: 1.0 is critically damped (no overshoot, the smoothest
    possible arrival); below 1.0 it settles with a small, springy overshoot.
    """
    if dt <= 0.0 or omega <= 0.0:
        return x, v
    d = x - target
    if zeta >= 0.999:
        e = math.exp(-omega * dt)
        j = v + omega * d
        return target + (d + j * dt) * e, (v - j * omega * dt) * e
    wd = omega * math.sqrt(1.0 - zeta * zeta)
    e = math.exp(-zeta * omega * dt)
    c, s = math.cos(wd * dt), math.sin(wd * dt)
    b = (v + zeta * omega * d) / wd
    return target + e * (d * c + b * s), e * (v * c - ((zeta * omega * v + omega * omega * d) / wd) * s)


class Spring:
    """One animated number. Set .t (the target) at any time; call step(dt) each frame; it keeps its velocity."""
    __slots__ = ("x", "v", "t", "omega", "zeta", "eps")

    def __init__(self, value=0.0, rate=16.0, zeta=1.0, eps=0.002):
        self.x = self.t = float(value)
        self.v = 0.0
        self.omega = rate * OMEGA_PER_RATE
        self.zeta = zeta
        self.eps = eps       # how close (in the value's own units) counts as arrived

    def jump(self, value):
        self.x = self.t = float(value)
        self.v = 0.0

    def step(self, dt):
        """Move one frame. Returns True while still moving, False once it has landed exactly on the target."""
        self.x, self.v = spring_step(self.x, self.v, self.t, self.omega, self.zeta, dt)
        if abs(self.x - self.t) < self.eps and abs(self.v) < self.eps * self.omega:
            self.x, self.v = self.t, 0.0
            return False
        return True


def iround(v):
    """Round half up (Python's round() rounds halves to even, which makes edges flicker between frames)."""
    return int(math.floor(v + 0.5))


def clamp01(v):
    return 0.0 if v < 0.0 else 1.0 if v > 1.0 else v


def lerp(a, b, t):
    return a + (b - a) * t


def smoothstep(t):
    """0 to 1 with zero slope at both ends. For deriving a secondary value (a stagger, a fade) from a spring."""
    t = clamp01(t)
    return t * t * (3.0 - 2.0 * t)


def window(v, start, end):
    """Where v sits between start and end, 0..1 and eased. Lets ONE spring drive several parts of a transition in
    order: the card fades over 0..0.6 of the motion, its content over 0.35..1.0, and they can never fall out of step."""
    if end <= start:
        return 1.0 if v >= end else 0.0
    return smoothstep((v - start) / (end - start))


def snap_rect(x, y, w, h):
    """A QRect from float geometry, rounded by edges so neighbouring rectangles never gain or lose a pixel."""
    l, t = iround(x), iround(y)
    r, b = iround(x + w), iround(y + h)
    return QRect(l, t, max(0, r - l), max(0, b - t))


class _Delay:
    """A callback that fires after some seconds of CLOCK time (frames), not wall time. cancel() before it fires."""
    __slots__ = ("left", "fn", "dead")

    def __init__(self, seconds, fn):
        self.left, self.fn, self.dead = seconds, fn, False

    def cancel(self):
        self.dead = True

    def __call__(self, dt):
        if self.dead:
            return False
        self.left -= dt
        if self.left > 0.0:
            return True
        self.dead = True
        self.fn()
        return False


class FrameClock(QObject):
    """The single clock that drives every animation. Subscribers are callables fn(dt) -> bool (True = keep going)."""
    _one = None
    _vblank = pyqtSignal()            # emitted by the vblank thread, delivered on the UI thread

    @classmethod
    def get(cls):
        if cls._one is None:
            cls._one = cls()
        return cls._one

    def __init__(self):
        super().__init__()
        self._subs = []
        self._last = None             # timestamp of the previous frame (None = the clock was idle)
        self._smooth = 1.0 / 60.0     # timer mode only: filtered frame time
        self._hires = False
        self._tm = QTimer(self)
        self._tm.setTimerType(Qt.TimerType.PreciseTimer)
        self._tm.timeout.connect(self._on_timer)
        # vblank mode (Windows)
        self._flush = None
        self._want = threading.Event()
        self._stamp = 0.0
        self._inflight = False
        self._broken = False
        self._thread = None
        self._vblank.connect(self._on_vblank, Qt.ConnectionType.QueuedConnection)
        if os.name == "nt" and os.environ.get("SHIELD_NO_VBLANK") != "1":
            try:
                import ctypes
                fn = ctypes.windll.dwmapi.DwmFlush
                fn.restype = ctypes.c_long
                fn.argtypes = []
                self._flush = fn
            except Exception:
                self._flush = None

    # -- display ----------------------------------------------------------------
    @staticmethod
    def _hz():
        screen = QGuiApplication.primaryScreen()
        hz = screen.refreshRate() if screen is not None else 60.0
        return hz if 24.0 <= hz <= 500.0 else 60.0

    def _period(self):
        return 1.0 / self._hz()

    # -- subscribers --------------------------------------------------------------
    def active(self, fn):
        return fn in self._subs

    def add(self, fn):
        if fn not in self._subs:
            self._subs.append(fn)
        self._wake()

    def remove(self, fn):
        if fn in self._subs:
            self._subs.remove(fn)

    def after(self, seconds, fn):
        """Run fn after `seconds` on this clock. Returns a handle with cancel()."""
        d = _Delay(max(0.0, seconds), fn)
        self.add(d)
        return d

    # -- running ---------------------------------------------------------------------
    def _vblank_ok(self):
        return self._flush is not None and not self._broken

    def _wake(self):
        if self._vblank_ok():
            if self._thread is None:
                self._thread = threading.Thread(target=self._vblank_loop, name="shield-vblank", daemon=True)
                self._thread.start()
            if not self._want.is_set():
                self._last = None
                self._inflight = False
                self._want.set()
            return
        if not self._tm.isActive():
            self._last = None
            self._smooth = self._period()
            self._tm.setInterval(max(2, int(round(1000.0 * self._period()))))
            self._set_hires(True)
            self._tm.start()

    def _idle(self):
        self._want.clear()
        if self._tm.isActive():
            self._tm.stop()
        self._set_hires(False)
        self._last = None

    def _vblank_loop(self):
        """Background thread: sleeps until the display's next vertical blank and tells the UI thread. It does no UI
        work and holds no Python lock while it waits (ctypes releases the GIL during the call)."""
        from time import perf_counter
        flush = self._flush
        last, fast = perf_counter(), 0
        while True:
            self._want.wait()
            try:
                bad = flush() != 0
            except Exception:
                bad = True
            now = perf_counter()
            # If the compositor stops pacing us (monitor asleep, remote session), calls return at once. Give up on
            # vblank and let the timer take over rather than spin.
            fast = fast + 1 if now - last < 0.002 else 0
            last = now
            if bad or fast >= 8:
                self._broken = True
                self._vblank.emit()
                return
            self._stamp = now
            if not self._inflight:
                self._inflight = True
                self._vblank.emit()

    def _on_vblank(self):
        try:
            if self._broken and self._want.is_set():
                self._want.clear()
                self._wake()                      # carries on with the timer
                return
            if not self._want.is_set():
                return
            t = self._stamp
            dt = self._period() if self._last is None else t - self._last
            self._last = t
            self._advance(min(max(dt, 0.001), MAX_DT))
        finally:
            self._inflight = False

    def _on_timer(self):
        now = time.perf_counter()
        period = self._period()
        if self._last is None:
            raw = period
        else:
            raw = now - self._last
        self._last = now
        if raw > 2.5 * period:
            dt = raw                              # a real stall: catch up honestly
        else:
            self._smooth += (raw - self._smooth) * 0.2      # timer jitter is noise: filter it so motion stays even
            dt = self._smooth
        self._advance(min(max(dt, 0.001), MAX_DT))

    def _advance(self, dt):
        for fn in list(self._subs):
            if fn not in self._subs:
                continue
            try:
                alive = fn(dt)
            except RuntimeError as e:
                if "deleted" not in str(e):
                    raise
                alive = False      # the widget that owned this animation is gone
            if not alive:
                self.remove(fn)
        if not self._subs:
            self._idle()

    def _set_hires(self, on):
        """Windows, timer mode only: 1 ms timer resolution while animating, released the moment everything is still."""
        if os.name != "nt" or on == self._hires:
            return
        try:
            import ctypes
            winmm = ctypes.windll.winmm
            (winmm.timeBeginPeriod if on else winmm.timeEndPeriod)(1)
            self._hires = on
        except Exception:
            pass


class Ticker:
    """A start/stop handle for one animation callback on the shared clock: fn(dt) -> bool (True = still moving)."""
    __slots__ = ("fn",)

    def __init__(self, fn):
        self.fn = fn

    def start(self):
        FrameClock.get().add(self.fn)

    def stop(self):
        FrameClock.get().remove(self.fn)

    def isActive(self):
        return FrameClock.get().active(self.fn)
