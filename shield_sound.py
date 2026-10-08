"""
shield_sound.py: the sounds of Shield. Put your own audio files in the `sounds` folder and they play; nothing else to wire.

    sounds/click.wav            any button, and the fallback for the tab sounds below
    sounds/tab_select.wav       switching to a tab                  (falls back to click)
    sounds/tab_new.wav          opening a tab                       (falls back to tab_select, then click)
    sounds/tab_close.wav        closing a tab                       (falls back to click)
    sounds/toggle.wav           switches, the private connection    (falls back to click)
    sounds/star.wav             bookmarking a page                  (falls back to click)
    sounds/theme.wav            dark <-> light                      (falls back to toggle, then click)
    sounds/sheet.wav            a dialog opening                    (silent if missing)
    sounds/unlock.wav           the vault unlocking                 (falls back to success)
    sounds/error.wav            a wrong password                    (silent if missing)
    sounds/success.wav          something finished well             (silent if missing)
    sounds/download.wav         a download landing                  (falls back to success)
    sounds/connect.wav          private connection established      (falls back to success)
    sounds/scroll.wav           ONE short tick, played every few lines you scroll
    sounds/scroll_loop.wav      OR a continuous bed that swells with scroll speed (use either, or both)

  * Variations: name_1.wav, name_2.wav, ... are picked at random (never the same one twice in a row). A click that is a
    little different each time is what keeps a sound from getting tiresome.
  * Format: .wav plays instantly (QSoundEffect). .mp3, .ogg, .flac, .m4a and .opus work too but start a few tens of
    milliseconds late, so use .wav for anything you click. Short is better: 30 to 150 ms for clicks and ticks.
  * The sounds are PART OF THE APP, not a setting: there is no per-user folder and nothing a user can swap in. At build time
    `python tools/pack_sounds.py` packs the files in `sounds/` into shield_sounds_data.py, which is imported like any other
    module (so PyInstaller bundles it with no extra options). While developing, with no packed module, the plain `sounds`
    folder beside shield.py is used instead.
  * Settings > Fluid motion and sound has the master switch, the volume and a separate switch for the scroll sound.

Scrolling is tied to REAL movement, not to the mouse wheel: the tick plays as the page actually moves, so it stays in step
with smooth scrolling, trackpad momentum, keyboard and scrollbar dragging, stays quiet at the top and bottom of a page, and
a page that scrolls itself never makes noise.

No sound is played while Shield is in the background. If QtMultimedia is missing, everything here quietly does nothing.
"""
import atexit
import base64
import math
import random
import re
import shutil
import tempfile
import time
import zlib
from pathlib import Path

from PyQt6.QtCore import QObject, Qt, QUrl
from PyQt6.QtGui import QGuiApplication

try:
    from PyQt6.QtMultimedia import QAudioOutput, QMediaPlayer, QSoundEffect
    HAVE_AUDIO = True
except Exception:                      # a build without multimedia: the browser must still work
    HAVE_AUDIO = False

from shield_motion import FrameClock

# What each event may fall back to, in order. An event nobody provided a file for is silent.
EVENTS = {
    "click": ("click",),
    "tab_select": ("tab_select", "click"),
    "tab_new": ("tab_new", "tab_select", "click"),
    "tab_close": ("tab_close", "click"),
    "toggle": ("toggle", "click"),
    "star": ("star", "click"),
    "theme": ("theme", "toggle", "click"),
    "sheet": ("sheet",),
    "unlock": ("unlock", "success"),
    "error": ("error",),
    "success": ("success",),
    "download": ("download", "success"),
    "connect": ("connect", "success"),
    "scroll": ("scroll",),
}
_POOL = {"click": 4, "scroll": 5, "tab_select": 3}      # how many copies of a sound may overlap (default 2)
_GAP = {"click": 0.030, "scroll": 0.030}                # the least time between two plays of one sound (seconds)
_EXTS = {".wav", ".mp3", ".ogg", ".flac", ".m4a", ".aac", ".opus"}
_NAME = re.compile(r"^(.*?)(?:[_-]?\d+)?$")


def _unpack_embedded():
    """The sounds packed into the app (shield_sounds_data.py), written to a private temporary folder that lives for this run
    only and is deleted at exit. Returns that folder, or None when the app was built without packed sounds."""
    try:
        import shield_sounds_data as packed
        files = packed.FILES
    except Exception:
        return None
    try:
        tmp = Path(tempfile.mkdtemp(prefix="shield-snd-"))
        for name, blob in files.items():
            (tmp / Path(name).name).write_bytes(zlib.decompress(base64.b64decode(blob)))
        atexit.register(shutil.rmtree, str(tmp), True)
        return tmp
    except Exception:
        return None


def sound_folders(app_dir):
    """Where the sounds come from. The packed copy inside the app wins; the plain folder beside shield.py is only a
    development fallback for when nothing has been packed. There is deliberately no user-writable location."""
    tmp = _unpack_embedded()
    if tmp is not None:
        return [tmp]
    return [Path(app_dir) / "sounds"]


class _Sample:
    """One audio file with a few players, so the same sound can overlap itself (fast clicking, fast scrolling)."""

    def __init__(self, path, pool, parent):
        self.path, self.voices, self.next = path, [], 0
        self.effect = path.suffix.lower() == ".wav"
        url = QUrl.fromLocalFile(str(path))
        for _ in range(pool):
            try:
                if self.effect:
                    v = QSoundEffect(parent)
                    v.setSource(url)
                else:
                    v = QMediaPlayer(parent)
                    v._out = QAudioOutput(parent)
                    v.setAudioOutput(v._out)
                    v.setSource(url)
                self.voices.append(v)
            except Exception:
                break

    def _busy(self, v):
        try:
            if self.effect:
                return v.isPlaying()
            return v.playbackState() == QMediaPlayer.PlaybackState.PlayingState
        except Exception:
            return True

    def play(self, volume):
        n = len(self.voices)
        if not n:
            return
        pick = None
        for i in range(n):
            v = self.voices[(self.next + i) % n]
            if not self._busy(v):
                pick = v
                break
        if pick is None:                    # every copy is still sounding: cut in on the oldest
            pick = self.voices[self.next % n]
        self.next = (self.next + 1) % n
        try:
            if self.effect:
                pick.setVolume(volume)
                pick.play()
            else:
                pick._out.setVolume(volume)
                pick.setPosition(0)
                pick.play()
        except Exception:
            pass


class _Loop:
    """A sound that repeats while it is wanted. Its volume is set from outside (the scroll bed follows scroll speed)."""

    def __init__(self, path, parent):
        self.v, self.on, self.effect = None, False, path.suffix.lower() == ".wav"
        url = QUrl.fromLocalFile(str(path))
        try:
            if self.effect:
                self.v = QSoundEffect(parent)
                self.v.setSource(url)
                try:
                    self.v.setLoopCount(QSoundEffect.Loop.Infinite.value)
                except Exception:
                    self.v.setLoopCount(-2)
                self.v.setVolume(0.0)
            else:
                self.v = QMediaPlayer(parent)
                self.v._out = QAudioOutput(parent)
                self.v.setAudioOutput(self.v._out)
                self.v.setSource(url)
                self.v.setLoops(QMediaPlayer.Loops.Infinite)
                self.v._out.setVolume(0.0)
        except Exception:
            self.v = None

    def volume(self, vol):
        if self.v is None:
            return
        try:
            (self.v.setVolume if self.effect else self.v._out.setVolume)(vol)
        except Exception:
            pass

    def start(self):
        if self.v is not None and not self.on:
            self.on = True
            try:
                self.v.play()
            except Exception:
                pass

    def stop(self):
        if self.v is not None and self.on:
            self.on = False
            try:
                self.v.stop()
            except Exception:
                pass


class SoundEngine(QObject):
    def __init__(self, folders):
        super().__init__()
        self.folders = [Path(f) for f in folders]
        self.enabled, self.volume, self.scroll_on = True, 0.65, True
        self._lib = {}          # name -> [_Sample, ...] (the variations)
        self._last = {}         # name -> index of the variation played last
        self._stamp = {}        # name -> when it last played
        self.loop = None        # the scroll bed, if the person provided one
        self.reload()

    # -- loading -------------------------------------------------------------------
    def reload(self):
        """Find the files again. A name found in an earlier folder is not taken from a later one."""
        self._lib.clear()
        self.loop = None
        if not HAVE_AUDIO:
            return
        claimed = {}
        for folder in self.folders:
            try:
                files = sorted(f for f in folder.iterdir() if f.is_file() and f.suffix.lower() in _EXTS)
            except OSError:
                continue
            found = {}
            for f in files:
                name = _NAME.match(f.stem.lower()).group(1).strip("_-")
                if name and name not in claimed:
                    found.setdefault(name, []).append(f)
            for name, paths in found.items():
                claimed[name] = paths
        for name, paths in claimed.items():
            if name == "scroll_loop":
                loop = _Loop(paths[0], self)
                self.loop = loop if loop.v is not None else None
                continue
            samples = [_Sample(p, _POOL.get(name, 2), self) for p in paths]
            samples = [s for s in samples if s.voices]
            if samples:
                self._lib[name] = samples

    def configure(self, enabled=None, volume=None, scroll=None):
        if enabled is not None:
            self.enabled = bool(enabled)
        if volume is not None:
            self.volume = max(0.0, min(1.0, float(volume)))
        if scroll is not None:
            self.scroll_on = bool(scroll)
        if not (self.enabled and self.scroll_on) and self.loop is not None:
            self.loop.stop()

    # -- playing ------------------------------------------------------------------
    def _resolve(self, event):
        for name in EVENTS.get(event, (event,)):
            if name in self._lib:
                return name
        return None

    def has(self, event):
        return self._resolve(event) is not None

    def play(self, event, gain=1.0):
        """Play an event's sound. Returns True if one was started."""
        if not (HAVE_AUDIO and self.enabled):
            return False
        if QGuiApplication.applicationState() != Qt.ApplicationState.ApplicationActive:
            return False
        name = self._resolve(event)
        if name is None:
            return False
        now = time.perf_counter()
        if now - self._stamp.get(name, 0.0) < _GAP.get(name, 0.045):
            return False
        self._stamp[name] = now
        variants = self._lib[name]
        i = 0
        if len(variants) > 1:
            choices = [k for k in range(len(variants)) if k != self._last.get(name)]
            i = random.choice(choices)
        self._last[name] = i
        variants[i].play(max(0.0, min(1.0, self.volume * gain)))
        return True


class ScrollFeel(QObject):
    """Turns scrolling into sound. Fed by the page itself (how far it REALLY moved), but only while a person is driving.

    note_input() is called when the wheel, a scroll key or the mouse (button held) is used; for the next half second any
    movement of the page counts as theirs. moved() is called with every change of the page's scroll position."""
    STEP = 72.0          # pixels of travel per tick
    INTENT = 0.5         # seconds a person's input keeps vouching for movement (covers smooth scrolling and trackpad glide)
    FAST = 2600.0        # px/s that counts as "fast": ticks reach full volume
    BED = 2200.0         # px/s at which the continuous bed reaches full volume

    def __init__(self, engine):
        super().__init__()
        self.e = engine
        self._until = 0.0
        self._acc = 0.0
        self._speed = 0.0
        self._t_last = 0.0
        self._bed, self._bed_goal, self._bed_run, self._last_move = 0.0, 0.0, False, 0.0
        self._tick = self._bed_tick

    def note_input(self):
        self._until = time.perf_counter() + self.INTENT

    def moved(self, dx, dy):
        e = self.e
        if not (e.enabled and e.scroll_on):
            return
        now = time.perf_counter()
        if now > self._until:
            self._acc, self._speed, self._t_last = 0.0, 0.0, 0.0      # the page moved by itself: not ours to announce
            return
        dist = abs(dx) + abs(dy)
        if dist < 0.5:
            return
        dt = (now - self._t_last) if self._t_last and now - self._t_last < 0.25 else 0.016
        self._t_last = now
        self._speed += (dist / max(dt, 0.004) - self._speed) * 0.35
        if e.has("scroll"):
            self._acc += dist
            n = 0
            while self._acc >= self.STEP and n < 2:
                e.play("scroll", 0.35 + 0.65 * min(1.0, self._speed / self.FAST))
                self._acc -= self.STEP
                n += 1
            if self._acc >= self.STEP:
                self._acc = 0.0
        if e.loop is not None:
            self._bed_goal = min(1.0, self._speed / self.BED)
            self._last_move = now
            if not self._bed_run:
                self._bed_run = True
                FrameClock.get().add(self._tick)

    def _bed_tick(self, dt):
        e = self.e
        if time.perf_counter() - self._last_move > 0.14:
            self._bed_goal = 0.0
        self._bed += (self._bed_goal - self._bed) * (1.0 - math.exp(-16.0 * dt))
        if e.loop is None or not (e.enabled and e.scroll_on):
            self._bed, self._bed_run = 0.0, False
            return False
        if self._bed > 0.03:
            e.loop.start()
            e.loop.volume(min(1.0, self._bed * e.volume))
            return True
        if self._bed_goal <= 0.0:
            e.loop.stop()
            self._bed, self._bed_run = 0.0, False
            return False
        return True


class ScrollWatcher(QObject):
    """Sits on one web view. Notices a person scrolling (wheel, keys, dragging) and the page's real scroll movement."""
    def __init__(self, view, feel):
        super().__init__(view)
        from PyQt6.QtCore import QEvent
        self._ev = QEvent.Type
        self.view, self.feel = view, feel
        self._proxy = None
        self._pos = None
        self._keys = {Qt.Key.Key_Space, Qt.Key.Key_PageUp, Qt.Key.Key_PageDown, Qt.Key.Key_Home, Qt.Key.Key_End,
                      Qt.Key.Key_Up, Qt.Key.Key_Down, Qt.Key.Key_Left, Qt.Key.Key_Right}
        view.installEventFilter(self)
        self.hook()
        view.page().scrollPositionChanged.connect(self._moved)

    def hook(self):
        """The widget that really receives input can be replaced when the page changes process: follow it."""
        try:
            fp = self.view.focusProxy()
        except RuntimeError:
            return
        if fp is not None and fp is not self._proxy:
            self._proxy = fp
            fp.installEventFilter(self)

    def _moved(self, pos):
        try:
            if not self.view.isVisible():
                self._pos = None
                return
        except RuntimeError:
            return
        if self._pos is not None:
            self.feel.moved(pos.x() - self._pos.x(), pos.y() - self._pos.y())
        self._pos = pos

    def eventFilter(self, obj, e):
        t = e.type()
        E = self._ev
        if t == E.Wheel:
            self.feel.note_input()
        elif t == E.KeyPress:
            if e.key() in self._keys:
                self.feel.note_input()
        elif t == E.MouseMove:
            if e.buttons() & Qt.MouseButton.LeftButton:       # dragging the scroll bar, or a selection that scrolls the page
                self.feel.note_input()
        elif t in (E.ChildAdded, E.ChildPolished):
            self.hook()
        return False


# --------------------------------------------------------------------------
# The one shared engine. Widgets call play("click") without needing a reference to anything.
# --------------------------------------------------------------------------
_engine = None


def install(engine):
    global _engine
    _engine = engine


def play(event, gain=1.0):
    e = _engine
    if e is not None:
        try:
            return e.play(event, gain)
        except Exception:
            return False
    return False
