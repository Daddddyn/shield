"""
Register Shield with Windows so it appears under Settings > Apps > Default apps and can open links and .html files.

    python tools/register_windows.py             # register for the current Windows user (no admin needed)
    python tools/register_windows.py --remove    # undo it
    python tools/register_windows.py --exe "C:\\Program Files\\Shield\\Shield.exe"    # for a packaged build

Windows does not let a program make itself the default browser. This adds Shield to the list and then opens the
Default apps page, where you pick it. Everything is written under HKEY_CURRENT_USER only.
"""
import os
import sys

APP = "Shield"
CAP = r"Software\Clients\StartMenuInternet\Shield\Capabilities"


def plan(command):
    """The registry entries to create, as (key path, value name, value). Pure data, so it can be tested anywhere."""
    html, url = "ShieldHTML", "ShieldURL"
    e = [
        (rf"Software\Classes\{html}", "", "Shield HTML Document"),
        (rf"Software\Classes\{html}\shell\open\command", "", f'{command} "%1"'),
        (rf"Software\Classes\{url}", "", "Shield URL"),
        (rf"Software\Classes\{url}", "URL Protocol", ""),
        (rf"Software\Classes\{url}\shell\open\command", "", f'{command} "%1"'),
        (r"Software\Clients\StartMenuInternet\Shield", "", APP),
        (r"Software\Clients\StartMenuInternet\Shield\shell\open\command", "", command),
        (CAP, "ApplicationName", APP),
        (CAP, "ApplicationDescription", "A zero-bloat, security-first browser"),
        (CAP + r"\URLAssociations", "http", url),
        (CAP + r"\URLAssociations", "https", url),
        (CAP + r"\FileAssociations", ".htm", html),
        (CAP + r"\FileAssociations", ".html", html),
        (r"Software\RegisteredApplications", APP, CAP),
    ]
    return e


def default_command(exe=None):
    if exe:
        return f'"{exe}"'
    py = sys.executable
    pyw = py[:-10] + "pythonw.exe" if py.lower().endswith("python.exe") else py
    script = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "shield.py"))
    return f'"{pyw}" "{script}"'


def register(command):
    import winreg
    for path, name, value in plan(command):
        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_WRITE) as k:
            winreg.SetValueEx(k, name, 0, winreg.REG_SZ, value)


def remove():
    import winreg

    def kill(path):
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_READ | winreg.KEY_WRITE) as k:
                while True:
                    try:
                        sub = winreg.EnumKey(k, 0)
                    except OSError:
                        break
                    kill(path + "\\" + sub)
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, path)
        except OSError:
            pass
    for path in (r"Software\Classes\ShieldHTML", r"Software\Classes\ShieldURL", r"Software\Clients\StartMenuInternet\Shield"):
        kill(path)
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Software\RegisteredApplications", 0, winreg.KEY_WRITE) as k:
            winreg.DeleteValue(k, APP)
    except OSError:
        pass


def main(argv):
    if os.name != "nt":
        print("This tool is for Windows.")
        return 1
    if "--remove" in argv:
        remove()
        print("Shield was removed from the list of browsers.")
        return 0
    exe = argv[argv.index("--exe") + 1] if "--exe" in argv and argv.index("--exe") + 1 < len(argv) else None
    register(default_command(exe))
    print("Registered. Opening Default apps: choose Shield for HTTP and HTTPS.")
    os.startfile("ms-settings:defaultapps")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
