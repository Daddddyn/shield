"""
Draws Shield's icon with the same code the browser uses at runtime and writes, into packaging/:
  shield.ico   Windows (16 to 256 px, PNG-compressed, so it stays sharp on every scale)
  shield.icns  macOS   (16 to 1024 px)
  shield.png   Linux   (512 px, used by install.sh for the launcher entry)
Run it again if you change the icon. build.ps1 / build.sh run it for you when a file is missing.

    python packaging/make_icon.py
"""
import os
import struct
import sys
from pathlib import Path

os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))

from PyQt6.QtCore import QBuffer, QIODevice, Qt
from PyQt6.QtWidgets import QApplication

import shield   # noqa: E402  (needs the path above)

SIZES = [16, 20, 24, 32, 40, 48, 64, 128, 256]


def png_bytes(image):
    buf = QBuffer()
    buf.open(QIODevice.OpenModeFlag.WriteOnly)
    image.save(buf, "PNG")
    return bytes(buf.data())


ICNS_TYPES = {16: b"icp4", 32: b"icp5", 64: b"icp6", 128: b"ic07", 256: b"ic08", 512: b"ic09", 1024: b"ic10"}


def icns_bytes(frames):
    """frames: [(size, png_bytes)]. An .icns file is 'icns', its total length, then one (type, length, PNG) record per size."""
    body = b"".join(ICNS_TYPES[s] + struct.pack(">I", 8 + len(d)) + d for s, d in frames)
    return b"icns" + struct.pack(">I", 8 + len(body)) + body


def main():
    app = QApplication(sys.argv)
    only = sys.argv[1:]            # optionally name what to write: ico icns png (default: all)
    want = lambda k: not only or k in only
    big = shield.app_icon().pixmap(1024, 1024).toImage()
    if big.width() < 1024:
        big = big.scaled(1024, 1024, Qt.AspectRatioMode.IgnoreAspectRatio, Qt.TransformationMode.SmoothTransformation)
    scale = lambda s: big.scaled(s, s, Qt.AspectRatioMode.IgnoreAspectRatio, Qt.TransformationMode.SmoothTransformation)
    if want("icns"):
        out = HERE / "shield.icns"
        out.write_bytes(icns_bytes([(s, png_bytes(scale(s))) for s in ICNS_TYPES]))
        print(f"Wrote {out} ({out.stat().st_size // 1024} KB)")
    if want("png"):
        out = HERE / "shield.png"
        out.write_bytes(png_bytes(scale(512)))
        print(f"Wrote {out} ({out.stat().st_size // 1024} KB)")
    if not want("ico"):
        del app
        return
    master = shield.app_icon().pixmap(256, 256).toImage()
    frames = []
    for s in SIZES:
        img = master if s == 256 else master.scaled(s, s, Qt.AspectRatioMode.IgnoreAspectRatio, Qt.TransformationMode.SmoothTransformation)
        frames.append((s, png_bytes(img)))
    head = struct.pack("<HHH", 0, 1, len(frames))
    offset = 6 + 16 * len(frames)
    entries, blobs = b"", b""
    for s, data in frames:
        entries += struct.pack("<BBBBHHII", 0 if s >= 256 else s, 0 if s >= 256 else s, 0, 0, 1, 32, len(data), offset)
        blobs += data
        offset += len(data)
    out = HERE / "shield.ico"
    out.write_bytes(head + entries + blobs)
    print(f"Wrote {out} ({out.stat().st_size // 1024} KB, {len(frames)} sizes)")
    del app


if __name__ == "__main__":
    main()
