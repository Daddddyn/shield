"""
shield_autofill.py: the thin Qt layer between login forms on a page and the vault.

The page-side script (shield_scripts.VAULT_JS) runs in an isolated world. This bridge is the only thing it can
talk to, and it is registered only for that world, so the website's own scripts cannot reach it. Everything the
script sends is treated as untrusted text: the browser works out the site from the page address itself and
ignores what the script claims.
"""
import json

from PyQt6.QtCore import QFile, QIODevice, QObject, pyqtSlot
from PyQt6.QtWebChannel import QWebChannel  # noqa: F401  (importing it loads Qt's bundled qwebchannel.js)

MAX_MESSAGE = 4096


def qwebchannel_js():
    """Qt's own client library for the channel, read from the resources compiled into Qt. '' if unavailable."""
    f = QFile(":/qtwebchannel/qwebchannel.js")
    if not f.open(QIODevice.OpenModeFlag.ReadOnly):
        return ""
    try:
        return bytes(f.readAll()).decode("utf-8", "replace")
    finally:
        f.close()


class VaultBridge(QObject):
    def __init__(self, page):
        super().__init__(page)
        self.page = page

    @staticmethod
    def _load(text):
        if not isinstance(text, str) or len(text) > MAX_MESSAGE:
            return None
        try:
            d = json.loads(text)
        except ValueError:
            return None
        return d if isinstance(d, dict) else None

    @pyqtSlot(str)
    def seen(self, text):
        d = self._load(text)
        if d is not None:
            self.page.vault_seen(d)

    @pyqtSlot(str)
    def captured(self, text):
        d = self._load(text)
        if d is not None:
            self.page.vault_captured(d)
