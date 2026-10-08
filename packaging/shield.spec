# -*- mode: python ; coding: utf-8 -*-
"""
PyInstaller recipe for Shield on Windows, macOS and Linux. Run it through build.ps1 (Windows) or build.sh (macOS, Linux);
they call:  pyinstaller packaging/shield.spec

Why it is built this way:
  * onedir, not onefile. A onefile build unpacks itself into a temp folder on EVERY launch, which is the single
    biggest cause of slow starts. A folder build starts straight away and the installer puts it in place once.
  * windowed. No console window, ever.
  * UPX off. It makes starts slower and makes antivirus programs suspicious.

Output: dist/Shield/ (Windows, Linux)  or  dist/Shield.app (macOS).
"""
import re
import sys
from pathlib import Path

IS_WIN = sys.platform == "win32"
IS_MAC = sys.platform == "darwin"

ROOT = Path(SPECPATH).parent                      # SPECPATH is the packaging folder
VERSION = re.search(r'^VERSION\s*=\s*"([^"]+)"', (ROOT / "shield_core.py").read_text("utf-8"), re.M).group(1)
nums = (re.findall(r"\d+", VERSION) + ["0", "0", "0", "0"])[:4]
V4 = ", ".join(nums)
V4_DOT = ".".join(nums)
PUBLISHER = "Atools"                              # shown in the file's Properties > Details tab (Windows). Put your name here.
BUNDLE_ID = "org.shieldbrowser.shield"            # macOS. NEVER change it once people have installed: the updater refuses a
                                                  # download whose bundle id differs from the installed app's.

version_file = None
if IS_WIN:
    version_file = Path(SPECPATH) / "version_info.txt"
    version_file.write_text(f"""VSVersionInfo(
  ffi=FixedFileInfo(filevers=({V4}), prodvers=({V4}), mask=0x3f, flags=0x0, OS=0x40004, fileType=0x1, subtype=0x0, date=(0, 0)),
  kids=[
    StringFileInfo([StringTable('040904B0', [
      StringStruct('CompanyName', '{PUBLISHER}'),
      StringStruct('FileDescription', 'Shield'),
      StringStruct('FileVersion', '{V4_DOT}'),
      StringStruct('InternalName', 'Shield'),
      StringStruct('OriginalFilename', 'Shield.exe'),
      StringStruct('ProductName', 'Shield'),
      StringStruct('ProductVersion', '{V4_DOT}')])]),
    VarFileInfo([VarStruct('Translation', [1033, 1200])])
  ]
)
""", encoding="utf-8")

ICON_FILE = {"win32": "shield.ico", "darwin": "shield.icns"}.get(sys.platform)
ICON = Path(SPECPATH) / ICON_FILE if ICON_FILE else None
ICON = ICON if ICON and ICON.exists() else None

# Tor. Each installer carries ONLY its own system's folder (tor/tor_win, tor/tor_mac_arm64, tor/tor_mac_x64, tor/tor_lin_x64,
# tor/tor_lin_arm64), made by packaging/get_tor.py. They are packed as data, so they sit beside the program inside the install,
# where shield_proxy.py looks (tor_folder() there must give the same name).
import platform
_cpu = "arm64" if platform.machine().lower() in ("arm64", "aarch64") else "x64"
TOR_FOLDER = "tor_win" if IS_WIN else (f"tor_mac_{_cpu}" if IS_MAC else f"tor_lin_{_cpu}")
TOR_SRC = ROOT / "tor" / TOR_FOLDER
if not (TOR_SRC / "tor").is_dir():
    raise SystemExit(f"{TOR_SRC} is missing. Run:  python packaging/get_tor.py   (build.ps1 / build.sh do it for you)")

# Qt parts Shield never uses. Leaving them out makes the install smaller and the antivirus scan faster.
# (QtQml / QtQuick / QtOpenGL / QtNetwork / QtPositioning / QtWebChannel stay: the web engine itself needs them.)
UNUSED = [
    "PyQt6.QtBluetooth", "PyQt6.QtNfc", "PyQt6.QtSensors", "PyQt6.QtSerialPort", "PyQt6.QtSql", "PyQt6.QtTest",
    "PyQt6.QtDesigner", "PyQt6.QtHelp", "PyQt6.Qt3DCore", "PyQt6.Qt3DRender", "PyQt6.Qt3DInput", "PyQt6.Qt3DLogic",
    "PyQt6.Qt3DAnimation", "PyQt6.Qt3DExtras", "PyQt6.QtCharts", "PyQt6.QtDataVisualization", "PyQt6.QtGraphs",
    "PyQt6.QtMultimediaWidgets", "PyQt6.QtRemoteObjects", "PyQt6.QtTextToSpeech",
    "PyQt6.QtNetworkAuth", "PyQt6.QtStateMachine", "PyQt6.QtSpatialAudio", "PyQt6.QtQuick3D", "PyQt6.QtScxml",
    "PyQt6.QtVirtualKeyboard", "PyQt6.QtHttpServer", "PyQt6.QtLocation", "PyQt6.QtSvgWidgets", "PyQt6.QtPdfWidgets",
    "tkinter", "unittest", "pydoc", "doctest", "test", "setuptools", "pkg_resources", "distutils", "lib2to3",
]

a = Analysis(
    [str(ROOT / "shield.py")],
    pathex=[str(ROOT)],
    binaries=[],
    datas=[(str(TOR_SRC), f"tor/{TOR_FOLDER}")],
    # Both are imported inside try/except in shield_scan.py. Naming them here guarantees they are packed.
    hiddenimports=["yara_x", "pefile", "PyQt6.QtSvg", "PyQt6.QtWebChannel", "PyQt6.QtPrintSupport", "PyQt6.QtMultimedia", "shield_sound"],
    hookspath=[],
    runtime_hooks=[],
    excludes=UNUSED,
    noarchive=False,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="Shield",
    console=False,                 # no cmd window
    icon=str(ICON) if (ICON and IS_WIN) else None,
    version=str(version_file) if version_file else None,
    upx=False,
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    name="Shield",
)

if IS_MAC:
    # Signing is done afterwards by build.sh (it needs the entitlements and the hardened runtime), not here.
    app = BUNDLE(
        coll,
        name="Shield.app",
        icon=str(ICON) if ICON else None,
        bundle_identifier=BUNDLE_ID,
        version=VERSION,
        info_plist={
            "CFBundleName": "Shield",
            "CFBundleDisplayName": "Shield",
            "CFBundleShortVersionString": VERSION,
            "CFBundleVersion": VERSION,
            "LSMinimumSystemVersion": "12.0",
            "NSHighResolutionCapable": True,
            "LSApplicationCategoryType": "public.app-category.productivity",
            # Lets Shield appear under System Settings > Desktop & Dock > Default web browser, and receive clicked links.
            "CFBundleURLTypes": [{"CFBundleURLName": "Web site URL", "CFBundleURLSchemes": ["http", "https"]}],
            "CFBundleDocumentTypes": [{"CFBundleTypeName": "HTML document", "CFBundleTypeRole": "Viewer",
                                       "LSItemContentTypes": ["public.html"], "LSHandlerRank": "Alternate"}],
            # macOS ends the app the moment a page asks for these unless the reason is declared.
            "NSCameraUsageDescription": "A website you allowed is asking to use your camera.",
            "NSMicrophoneUsageDescription": "A website you allowed is asking to use your microphone.",
            "NSLocationWhenInUseUsageDescription": "A website you allowed is asking for your location.",
        },
    )
