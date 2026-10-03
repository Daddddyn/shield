"""Static checks over every source file: syntax, and names that are used but never defined anywhere."""
import ast
import builtins
import os
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FILES = ["shield.py", "shield_core.py", "shield_pages.py", "shield_ui.py", "shield_icons.py", "shield_scan.py",
         "shield_filters.py", "shield_vault.py", "shield_scripts.py", "shield_update.py", "shield_autofill.py"]


def defined_names(tree):
    names = set(dir(builtins)) | {"__file__", "__name__"}
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            names.add(n.name)
            if not isinstance(n, ast.ClassDef):
                a = n.args
                for x in a.args + a.kwonlyargs + a.posonlyargs:
                    names.add(x.arg)
                for x in (a.vararg, a.kwarg):
                    if x:
                        names.add(x.arg)
        elif isinstance(n, ast.Lambda):
            a = n.args
            for x in a.args + a.kwonlyargs + a.posonlyargs:
                names.add(x.arg)
            for x in (a.vararg, a.kwarg):
                if x:
                    names.add(x.arg)
        elif isinstance(n, (ast.Import, ast.ImportFrom)):
            for al in n.names:
                names.add((al.asname or al.name).split(".")[0])
        elif isinstance(n, ast.Name) and isinstance(n.ctx, (ast.Store, ast.Del)):
            names.add(n.id)
        elif isinstance(n, ast.ExceptHandler) and n.name:
            names.add(n.name)
        elif isinstance(n, ast.arg):
            names.add(n.arg)
        elif isinstance(n, (ast.Global, ast.Nonlocal)):
            names.update(n.names)
    return names


class Static(unittest.TestCase):
    def test_every_file_parses_and_has_no_unknown_names(self):
        for f in FILES:
            with open(os.path.join(ROOT, f), encoding="utf-8") as fh:
                tree = ast.parse(fh.read(), f)
            known = defined_names(tree)
            bad = sorted({f"{n.id}:{n.lineno}" for n in ast.walk(tree)
                          if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load) and n.id not in known})
            self.assertEqual(bad, [], f"{f}: names used but never defined")

    def test_self_attributes_used_in_browser_exist(self):
        """Every self.x the Browser reads must be assigned somewhere in the class (catches typos like self.vualt)."""
        with open(os.path.join(ROOT, "shield.py"), encoding="utf-8") as fh:
            tree = ast.parse(fh.read())
        for cls in [n for n in tree.body if isinstance(n, ast.ClassDef) and n.name in ("Browser", "SafePage")]:
            assigned = {n.name for n in cls.body if isinstance(n, ast.FunctionDef)}
            for n in ast.walk(cls):
                if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name) and n.value.id == "self" and isinstance(n.ctx, ast.Store):
                    assigned.add(n.attr)
            inherited = set(dir(__import__("tests.qt_stub", fromlist=["x"]).Dummy))
            missing = sorted({n.attr for n in ast.walk(cls) if isinstance(n, ast.Attribute) and isinstance(n.value, ast.Name)
                              and n.value.id == "self" and isinstance(n.ctx, ast.Load) and n.attr not in assigned
                              and n.attr not in inherited})
            # Qt's own methods are allowed; anything else is a typo
            qt = {"setCentralWidget", "setWindowTitle", "resize", "close", "show", "raise_", "activateWindow", "isMinimized",
                  "showNormal", "addAction", "setPage", "url", "window", "isFullScreen", "showFullScreen", "setWindowState",
                  "windowState", "palette", "setPalette", "setStyleSheet", "isVisible", "width", "height", "title", "history",
                  "settings", "profile", "scripts", "setUrl", "requestedUrl", "fullScreenRequested", "certificateError",
                  "loadFinished", "loadStarted", "windowCloseRequested", "recentlyAudibleChanged", "pdfPrintingFinished",
                  "permissionRequested", "featurePermissionRequested", "setFeaturePermission", "setWebChannel", "icon",
                  "recentlyAudible", "isAudioMuted", "setAudioMuted", "runJavaScript", "print", "printToPdf", "setDevToolsPage"}
            self.assertEqual([m for m in missing if m not in qt], [], f"{cls.name}: attributes read but never set")


if __name__ == "__main__":
    unittest.main()
