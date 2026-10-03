"""
A stand-in for PyQt6 so the parts of Shield that are logic (interceptor, guard, page generation) can be tested on a
machine without Qt. Importing this module installs the fakes. It does not try to be Qt, only to be permissive.
"""
import sys
import types


class _Signal:
    def __init__(self, *a, **k):
        self.slots = []

    def __get__(self, obj, owner=None):
        if obj is None:
            return self
        bound = obj.__dict__.setdefault("_sig_" + str(id(self)), _BoundSignal())
        return bound


class _BoundSignal:
    def __init__(self):
        self.slots = []

    def connect(self, f):
        self.slots.append(f)

    def emit(self, *a):
        for f in list(self.slots):
            f(*a)

    def disconnect(self, *a):
        self.slots.clear()


class Dummy:
    def __init__(self, *a, **k):
        pass

    def __getattr__(self, name):
        if name.startswith("__"):
            raise AttributeError(name)
        return Dummy()

    def __call__(self, *a, **k):
        return Dummy()

    def __iter__(self):
        return iter(())

    def __bool__(self):
        return True


class _Enum:
    """Any attribute is a distinct, stable value (stands in for Qt's nested enums)."""

    def __getattr__(self, name):
        if name.startswith("__"):
            raise AttributeError(name)
        return name


def _make_class(name):
    ns = {"__init__": lambda self, *a, **k: None}
    cls = type(name, (Dummy,), ns)
    cls.ResourceType = _Enum()
    for e in ("NavigationType", "WebAction", "WebAttribute", "InjectionPoint", "ScriptWorldId", "PersistentCookiesPolicy",
              "DownloadState", "Syntax", "Flag", "SocketOption", "PrinterMode", "Error", "PermissionPolicy"):
        setattr(cls, e, _Enum())
    return cls


class _Module(types.ModuleType):
    def __getattr__(self, name):
        if name.startswith("__"):
            raise AttributeError(name)
        if name == "pyqtSignal":
            return _Signal
        if name == "pyqtSlot":
            return lambda *a, **k: (lambda f: f)
        cls = _make_class(name)
        setattr(self, name, cls)
        return cls


def install():
    if "PyQt6" in sys.modules and not isinstance(sys.modules["PyQt6"], _Module):
        return
    root = _Module("PyQt6")
    root.__path__ = []
    sys.modules["PyQt6"] = root
    for sub in ("QtCore", "QtGui", "QtWidgets", "QtWebEngineCore", "QtWebEngineWidgets", "QtNetwork", "QtPrintSupport",
                "QtWebChannel", "QtSvg"):
        m = _Module("PyQt6." + sub)
        sys.modules["PyQt6." + sub] = m
        setattr(root, sub, m)


install()
