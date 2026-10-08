"""
check_fx.py: finds out why Shield's animations (the Tor ring, the address-bar light, ripples, the tab drop) are not
playing on THIS computer. Put it next to shield.py and run it from that folder:

    python check_fx.py

It changes nothing. It prints one line per thing that can switch the animations off, then a verdict.
"""
import hashlib
import json
import os
import re
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen" if os.name != "nt" else "windows")

problems = []


def line(ok, label, detail=""):
    print(f"  [{'ok' if ok else '!!'}] {label}" + (f": {detail}" if detail else ""))
    if not ok:
        problems.append(label)


def read(name):
    p = HERE / name
    return p.read_text("utf-8", "replace") if p.is_file() else ""


print(f"Folder: {HERE}\n")

# ---- 1. Is this the version that HAS the animations? --------------------------------------------------
print("1. Which files are these?")
core, ui, fx = read("shield_core.py"), read("shield_ui.py"), read("shield_fx.py")
m = re.search(r'^VERSION\s*=\s*"([^"]+)"', core, re.M)
print(f"     Shield version in shield_core.py: {m.group(1) if m else 'not found'}")
line(bool(fx), "shield_fx.py exists")
line("Ripples" in ui and "pulse" in ui, "shield_ui.py has the ripple and Tor-ring (pulse) code")
line("_paint_sweep" in ui, "shield_ui.py has the address-bar light sweep (_paint_sweep)")
for n in ("shield.py", "shield_ui.py", "shield_fx.py", "shield_motion.py", "shield_core.py"):
    t = HERE / n
    if t.is_file():
        print(f"     {n:18s} sha256 {hashlib.sha256(t.read_bytes()).hexdigest()[:16]}   (compare these between your computers)")

# ---- 2. The switches ------------------------------------------------------------------------------------
print("\n2. What can turn the animations off")
line(os.environ.get("SHIELD_NO_FX") != "1", "environment variable SHIELD_NO_FX is not set to 1", f"it is {os.environ.get('SHIELD_NO_FX')!r}")
line(os.environ.get("SHIELD_NO_VBLANK") != "1", "environment variable SHIELD_NO_VBLANK is not set to 1 (only affects smoothness)")

home = Path(os.environ.get("SHIELD_HOME") or Path.home() / ".shieldbrowser")
fluid = True
try:
    fluid = bool(json.loads((home / "settings.json").read_text("utf-8")).get("fluid_motion", True))
    line(fluid, f'Settings > "Fluid motion" is on  ({home / "settings.json"})', f"fluid_motion is {fluid}")
except OSError:
    line(True, f"no settings file yet in {home} (default is on)")
except ValueError:
    line(False, f"{home / 'settings.json'} is unreadable")

if os.name == "nt":
    import ctypes
    flag = ctypes.c_int(1)
    got = ctypes.windll.user32.SystemParametersInfoW(0x1042, 0, ctypes.byref(flag), 0)
    line(bool(flag.value) or not got, "Windows animations are on (Settings > Accessibility > Visual effects > Animation effects)",
         f"Windows reports animations {'ON' if flag.value else 'OFF'}")
    remote = bool(ctypes.windll.user32.GetSystemMetrics(0x1000))        # SM_REMOTESESSION
    line(not remote, "this is not a Remote Desktop session (Windows turns animations off inside those)", "it IS a remote session" if remote else "")
else:
    print("  (the Windows animation switch does not apply on this system)")

try:
    import shield_fx
    shield_fx.set_enabled(fluid)
    on = shield_fx.fx_on()
    print(f"\n  => Shield's own test, fx_on(), says: {'ON' if on else 'OFF'}")
    if not on:
        problems.append("fx_on() is off")
except Exception as ex:
    line(False, "could not import shield_fx.py", str(ex))

# ---- 3. Frame pacing (not an on/off switch, but explains choppy motion) --------------------------------
print("\n3. Frame clock")
try:
    from PyQt6.QtWidgets import QApplication
    app = QApplication(sys.argv)
    scr = app.primaryScreen()
    print(f"     screen refresh rate reported by Qt: {scr.refreshRate():.1f} Hz")
    if os.name == "nt":
        import ctypes
        flush = ctypes.windll.dwmapi.DwmFlush
        ts = []
        for _ in range(12):
            t0 = time.perf_counter()
            r = flush()
            ts.append((time.perf_counter() - t0) * 1000.0)
        paced = sum(ts[2:]) / len(ts[2:])
        line(r == 0 and paced > 2.0, "the display's vertical blank can be waited on (DwmFlush)",
             f"average wait {paced:.1f} ms; Shield falls back to a timer if this is not paced")
except Exception as ex:
    print(f"     (skipped: {ex})")

print()
if not problems:
    print("RESULT: nothing here is switching the animations off. If they still don't play, send me this whole printout.")
else:
    print("RESULT: found " + str(len(problems)) + " thing(s) to look at, marked [!!] above.")
