"""
shield_sound.py: optional interface sounds, chosen by the person.

Nothing ships with Shield. Drop your own files into the sounds folder (inside Shield's data folder, or next to the
program) and turn "Sound effects" on in Settings:

    click.wav   a left click anywhere in the browser
    scroll.wav  played in small ticks while a page is scrolled (its own switch in Settings)
    open.wav    a tab opening out of the tab bar

.wav plays with the lowest delay and is the best choice for clicks. .mp3, .ogg, .m4a and .flac also work. A name
with no file is simply silent. Nothing is played, and no event filter is installed, while the setting is off.

The sounds are played by Qt's own audio classes: no extra package and nothing leaves the computer.
"""
import time

from PyQt6.QtCore import QEvent, QObject, QUrl, Qt
from PyQt6.QtGui import QMouseEvent, QWheelEvent
from PyQt6.QtWidgets import QApplication

try:
    from PyQt6.QtMultimedia import QAudioOutput, QMediaPlayer, QSoundEffect
except Exception:                       # Qt built without multimedia: the setting stays, the sounds stay silent
    QAudioOutput = QMediaPlayer = QSoundEffect = None

EXTS = (".wav", ".mp3", ".ogg", ".m4a", ".flac")
NAMES = ("click", "scroll", "open")
SCROLL_STEP = 80.0         # pixels of scrolling between two ticks
SCROLL_GAP = 0.045         # never closer together than this (seconds)
CLICK_GAP = 0.03


class _Voice:
    """One sound with a few copies, so quick repeats overlap instead of cutting each other off."""

    def __init__(self, path, copies=3):
        self.i = 0
        self.items = []
        url = QUrl.fromLocalFile(str(path))
        self.wav = path.suffix.lower() == ".wav" and QSoundEffect is not None
        for _ in range(copies):
            if self.wav:
                s = QSoundEffect()
                s.setSource(url)
                self.items.append(s)
            elif QMediaPlayer is not None:
                out = QAudioOutput()
                pl = QMediaPlayer()
                pl.setAudioOutput(out)
                pl.setSource(url)
                self.items.append((pl, out))

    def play(self, volume):
        if not self.items:
            return
        it = self.items[self.i]
        self.i = (self.i + 1) % len(self.items)
        if self.wav:
            it.setVolume(volume)
            it.play()
        else:
            pl, out = it
            out.setVolume(volume)
            pl.stop()
            pl.setPosition(0)
            pl.play()


class Sounds(QObject):
    def __init__(self, cfg, folders):
        super().__init__()
        self.cfg, self.folders = cfg, list(folders)
        self.v = {}
        self._on = False
        self._t_click = self._t_scroll = 0.0
        self._acc = 0.0
        self.reload()

    def reload(self):
        """Look for the files again (so new ones are picked up without restarting)."""
        self.v = {}
        for name in NAMES:
            found = next((d / (name + e) for d in self.folders for e in EXTS if (d / (name + e)).is_file()), None)
            if found is not None:
                try:
                    self.v[name] = _Voice(found)
                except Exception:
                    pass

    def apply(self):
        """Install or remove the event filter to match the setting. Off means the app pays nothing for this."""
        app = QApplication.instance()
        if app is None:
            return
        want = bool(self.cfg["sound_effects"])
        if want and not self._on:
            self.reload()
            app.installEventFilter(self)
            self._on = True
        elif not want and self._on:
            app.removeEventFilter(self)
            self._on = False

    def play(self, name, gain=1.0):
        if not self._on:
            return
        v = self.v.get(name)
        if v is not None:
            v.play(max(0.0, min(1.0, self.cfg["sound_volume"] / 100.0 * gain)))

    def eventFilter(self, obj, ev):
        t = ev.type()
        if t == QEvent.Type.MouseButtonPress:
            if isinstance(ev, QMouseEvent) and ev.button() == Qt.MouseButton.LeftButton:
                now = time.monotonic()
                if now - self._t_click > CLICK_GAP:
                    self._t_click = now
                    self.play("click")
        elif t == QEvent.Type.Wheel and self.cfg["sound_scroll"] and isinstance(ev, QWheelEvent):
            pd, ad = ev.pixelDelta(), ev.angleDelta()
            px = abs(pd.y()) or abs(ad.y()) * 100.0 / 120.0      # a wheel notch is about 100 px of page
            if px:
                now = time.monotonic()
                if now - self._t_scroll > 0.25:
                    self._acc = SCROLL_STEP                    # a fresh scroll ticks right away
                self._acc += px
                if self._acc >= SCROLL_STEP and now - self._t_scroll >= SCROLL_GAP:
                    speed = min(1.0, px / 120.0)               # a fast flick is a little louder than a slow drag
                    self._acc = 0.0
                    self._t_scroll = now
                    self.play("scroll", 0.55 + 0.45 * speed)
        return False
