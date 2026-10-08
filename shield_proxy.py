"""
shield_proxy.py: the private connection. One switch in the toolbar that moves all browsing through Tor, with nothing
for the person to install or sign up for.

Why there is a small proxy inside Shield at all
-----------------------------------------------
Chromium only reads its proxy settings when it starts, so a toggle that works instantly can't change Chromium's
settings. Instead Chromium is always pointed at the SwitchProxy below (a SOCKS5 server on 127.0.0.1, random port), and the
SwitchProxy decides what happens to each connection:

    off      connect straight to the site, exactly as the browser would have
    on       send it through Tor (a copy of tor ships inside the Shield folder; see TorRunner.find)

Because Shield owns every connection, flipping the switch can do what a Chromium setting can't:

  * Kill switch. The moment "on" is requested the switch stops going direct. If Tor isn't ready yet, or dies, connections
    are REFUSED rather than quietly made without protection.
  * Existing connections are dropped on every change, so nothing opened before you switched keeps going the old way.
  * No DNS leak. Names are never resolved on this computer in "on" mode; the name itself is handed to Tor.
  * Local addresses (192.168.x.x, localhost...) are refused in "on" mode, so a page can't use Tor to probe your network
    or leak that it asked.
  * "New identity" starts fresh Tor circuits for everything that follows (Tor separates streams by the SOCKS login we
    present, and the login changes).

Networks that block Tor
-----------------------
Work, school and some national networks block Tor's public entry points. Shield then moves on by itself, in this order,
and remembers what worked for 12 hours:

    1. normal Tor          fastest
    2. obfs4 bridge        makes Tor traffic look like random noise
    3. Snowflake           routes through volunteers' browsers, behind a content-delivery network that is hard to block
    4. your own bridges    (optional) pasted in Settings, from bridges.torproject.org

The bridge addresses and the programs that speak obfs4 and Snowflake are read from the Tor Expert Bundle's own
pluggable_transports/pt_config.json, so they always match the copy of Tor that ships with Shield; nothing is baked in here.
Everything that ends up in Tor's config file is validated first (one line, a strict character set, a known transport), so a
bad bridge line, or a hand-edited settings file, can't smuggle in other Tor options. The kill switch stays on through every
step: while Shield is working through these, nothing is sent unprotected.

What this is not: it hides which sites you visit from your network and your ISP, and hides your address from the sites.
It does not make you anonymous the way Tor Browser does (your browser is still recognisable), and it is slower than a
direct connection. Standard library only, so it can be tested on its own.
"""
import asyncio
import ipaddress
import json
import os
import platform
import re
import secrets
import socket
import struct
import subprocess
import sys
import threading
import time
from pathlib import Path

HANDSHAKE_TIMEOUT = 15.0
CONNECT_TIMEOUT = 25.0
HALF_CLOSE_GRACE = 120.0
MAX_CONNECTIONS = 1500
BUF = 65536
START_TIMEOUT = 300.0           # everything Shield will try, in total, before it gives up
REMEMBER_FOR = 12 * 3600        # how long a method that worked is tried first next time

# SOCKS5 reply codes (RFC 1928)
R_OK, R_FAIL, R_NOT_ALLOWED, R_NET_UNREACH, R_HOST_UNREACH, R_REFUSED, R_TTL, R_BAD_CMD = 0, 1, 2, 3, 4, 5, 6, 7


class _Refuse(Exception):
    def __init__(self, code):
        super().__init__(code)
        self.code = code


class _Session:
    """One client connection and the remote side it was joined to, so it can be cut off from outside."""
    __slots__ = ("writers", "mode", "dead")

    def __init__(self, writer):
        self.writers, self.mode, self.dead = [writer], None, False

    def add(self, writer):
        self.writers.append(writer)
        if self.dead:
            self.close()

    def close(self):
        self.dead = True
        for w in self.writers:
            try:
                w.close()
            except Exception:
                pass


def _is_local(host):
    """True for anything that is not on the public internet. Names are judged by their form only (never resolved)."""
    h = host.lower().rstrip(".")
    if h == "localhost" or h.endswith(".localhost"):
        return True
    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        return False
    return not ip.is_global


class SwitchProxy:
    """A SOCKS5 server on 127.0.0.1 that either connects directly or chains to Tor. CONNECT only, no UDP, no listening."""

    def __init__(self, port=0):
        self.mode = "direct"                  # "direct" or "tunnel"
        self.upstream = None                  # (host, port) of Tor's SOCKS port once it is usable
        self.identity = secrets.token_hex(8)  # the SOCKS login we present to Tor; changing it means new circuits
        self.port = 0
        self.hosts = {}                       # optional name -> address overrides for direct connections (used by tests)
        self.log = []                         # the last destinations asked for, as (host, port, how); used by tests
        self.stats = {"direct": 0, "tunnel": 0, "refused": 0}
        self._want_port = port
        self._loop = None
        self._server = None
        self._sessions = set()
        self._ready = threading.Event()

    # -- running -------------------------------------------------------------
    def start(self):
        threading.Thread(target=self._run, name="shield-switch", daemon=True).start()
        self._ready.wait(10)
        if not self.port:
            raise RuntimeError("the local proxy could not start")
        return self.port

    def _run(self):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        self._loop = loop

        async def boot():
            try:
                self._server = await asyncio.start_server(self._client, "127.0.0.1", self._want_port, backlog=256)
                self.port = self._server.sockets[0].getsockname()[1]
            finally:
                self._ready.set()
        try:
            loop.run_until_complete(boot())
            loop.run_forever()
        except Exception:
            self._ready.set()
        finally:
            try:        # let every relay finish cancelling before the loop goes away
                pending = [t for t in asyncio.all_tasks(loop) if not t.done()]
                for t in pending:
                    t.cancel()
                if pending:
                    loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
                loop.close()
            except Exception:
                pass

    def shutdown(self):
        loop = self._loop
        if loop is None:
            return
        self.drop_all()
        try:
            loop.call_soon_threadsafe(self._server.close)
            loop.call_soon_threadsafe(lambda: loop.call_later(0.2, loop.stop))
        except Exception:
            pass

    # -- control (safe to call from any thread) --------------------------------
    def configure(self, mode, upstream=None):
        changed = mode != self.mode
        self.mode, self.upstream = mode, upstream
        if changed:
            self.drop_all()

    def new_identity(self):
        self.identity = secrets.token_hex(8)
        self.drop_all(only="tunnel")

    def drop_all(self, only=None):
        loop = self._loop
        if loop is None:
            return

        def cut():
            for s in list(self._sessions):
                if only is None or s.mode == only:
                    s.close()
        try:
            loop.call_soon_threadsafe(cut)
        except RuntimeError:
            pass

    # -- one client --------------------------------------------------------------
    async def _client(self, r, w):
        if len(self._sessions) >= MAX_CONNECTIONS:
            w.close()
            return
        s = _Session(w)
        self._sessions.add(s)
        try:
            await self._serve(r, w, s)
        except _Refuse as e:
            self.stats["refused"] += 1
            await self._reply(w, e.code)
        except (OSError, asyncio.IncompleteReadError, asyncio.TimeoutError, ValueError):
            pass
        finally:
            self._sessions.discard(s)
            s.close()

    @staticmethod
    async def _reply(w, code):
        try:
            w.write(bytes([5, code, 0, 1, 0, 0, 0, 0, 0, 0]))
            await w.drain()
        except Exception:
            pass

    async def _serve(self, r, w, s):
        t = HANDSHAKE_TIMEOUT
        head = await asyncio.wait_for(r.readexactly(2), t)
        if head[0] != 5:
            return
        methods = await asyncio.wait_for(r.readexactly(head[1]), t)
        if 0 in methods:
            w.write(b"\x05\x00")
        elif 2 in methods:                     # user/password login: accepted as is (this only listens on 127.0.0.1)
            w.write(b"\x05\x02")
            await w.drain()
            await asyncio.wait_for(r.readexactly(1), t)
            ulen = (await asyncio.wait_for(r.readexactly(1), t))[0]
            await asyncio.wait_for(r.readexactly(ulen), t)
            plen = (await asyncio.wait_for(r.readexactly(1), t))[0]
            await asyncio.wait_for(r.readexactly(plen), t)
            w.write(b"\x01\x00")
        else:
            w.write(b"\x05\xff")
            await w.drain()
            return
        await w.drain()

        ver, cmd, _rsv, atyp = await asyncio.wait_for(r.readexactly(4), t)
        if ver != 5:
            return
        if atyp == 1:
            host = socket.inet_ntoa(await asyncio.wait_for(r.readexactly(4), t))
        elif atyp == 3:
            n = (await asyncio.wait_for(r.readexactly(1), t))[0]
            host = (await asyncio.wait_for(r.readexactly(n), t)).decode("ascii", "replace")
        elif atyp == 4:
            host = socket.inet_ntop(socket.AF_INET6, await asyncio.wait_for(r.readexactly(16), t))
        else:
            raise _Refuse(8)
        port = struct.unpack(">H", await asyncio.wait_for(r.readexactly(2), t))[0]
        if cmd != 1:
            raise _Refuse(R_BAD_CMD)
        if port == 0 or not host:
            raise _Refuse(R_FAIL)

        mode, upstream = self.mode, self.upstream
        s.mode = mode
        if mode == "tunnel":
            if upstream is None:
                raise _Refuse(R_REFUSED)       # the kill switch: Tor isn't ready, so nothing goes out
            if _is_local(host):
                raise _Refuse(R_NOT_ALLOWED)
            rr, rw = await self._open_tunnel(upstream, atyp, host, port)
            self.stats["tunnel"] += 1
        else:
            rr, rw = await self._open_direct(host, port)
            self.stats["direct"] += 1
        self.log.append((host, port, mode))
        del self.log[:-50]
        s.add(rw)
        if s.dead:
            return
        w.write(bytes([5, 0, 0, 1, 0, 0, 0, 0, 0, 0]))
        await w.drain()
        await self._relay(r, w, rr, rw)

    async def _open_direct(self, host, port):
        host = self.hosts.get(host, host)
        try:
            return await asyncio.wait_for(asyncio.open_connection(host, port, happy_eyeballs_delay=0.25), CONNECT_TIMEOUT)
        except asyncio.TimeoutError:
            raise _Refuse(R_TTL)
        except socket.gaierror:
            raise _Refuse(R_HOST_UNREACH)
        except ConnectionRefusedError:
            raise _Refuse(R_REFUSED)
        except OSError:
            raise _Refuse(R_NET_UNREACH)

    async def _open_tunnel(self, upstream, atyp, host, port):
        """Connect to a site THROUGH Tor's SOCKS port. The name goes to Tor as a name; it is never looked up here."""
        t = HANDSHAKE_TIMEOUT
        try:
            rr, rw = await asyncio.wait_for(asyncio.open_connection(*upstream), t)
        except (OSError, asyncio.TimeoutError):
            raise _Refuse(R_REFUSED)
        try:
            user = b"shield"
            pw = self.identity.encode("ascii")
            rw.write(b"\x05\x01\x02")
            if (await asyncio.wait_for(rr.readexactly(2), t)) != b"\x05\x02":
                raise _Refuse(R_FAIL)
            rw.write(b"\x01" + bytes([len(user)]) + user + bytes([len(pw)]) + pw)
            if (await asyncio.wait_for(rr.readexactly(2), t))[1] != 0:
                raise _Refuse(R_FAIL)
            if atyp == 3:
                addr = b"\x03" + bytes([len(host)]) + host.encode("ascii")
            elif atyp == 4:
                addr = b"\x04" + socket.inet_pton(socket.AF_INET6, host)
            else:
                addr = b"\x01" + socket.inet_aton(host)
            rw.write(b"\x05\x01\x00" + addr + struct.pack(">H", port))
            await rw.drain()
            ver, rep, _r, a = await asyncio.wait_for(rr.readexactly(4), CONNECT_TIMEOUT)
            n = {1: 4, 4: 16}.get(a)
            if n is None:
                n = (await asyncio.wait_for(rr.readexactly(1), t))[0]
            await asyncio.wait_for(rr.readexactly(n + 2), t)
            if rep != 0:
                raise _Refuse(rep)
            return rr, rw
        except BaseException:
            rw.close()
            raise

    async def _relay(self, r, w, rr, rw):
        async def pump(src, dst):
            while True:
                data = await src.read(BUF)
                if not data:
                    break
                dst.write(data)
                await dst.drain()
            try:
                if dst.can_write_eof():
                    dst.write_eof()
            except Exception:
                pass
        a = asyncio.ensure_future(pump(r, rw))
        b = asyncio.ensure_future(pump(rr, w))
        try:
            done, pending = await asyncio.wait({a, b}, return_when=asyncio.FIRST_COMPLETED)
            if any(d.exception() for d in done):
                return
            if pending:     # one side finished cleanly; the other gets a while to say what it still has to say
                await asyncio.wait(pending, timeout=HALF_CLOSE_GRACE)
        except (OSError, ConnectionError):
            pass
        finally:
            for t in (a, b):
                if not t.done():
                    try:
                        t.cancel()
                    except RuntimeError:        # the loop is already shutting down
                        pass
            for t in (a, b):
                if t.done() and not t.cancelled():
                    t.exception()       # retrieved, so a dropped connection is never reported as an unhandled error


# --------------------------------------------------------------------------
# Bridges: validation and the bundle's own configuration
# --------------------------------------------------------------------------
TRANSPORTS = ("obfs4", "snowflake", "webtunnel", "meek_lite")      # what a bridge line may name
_ADDR = re.compile(r"^(?:(\d{1,3}(?:\.\d{1,3}){3})|\[([0-9A-Fa-f:]+)\]):(\d{1,5})$")
_FPR = re.compile(r"^[0-9A-Fa-f]{40}$")
_TOKEN = re.compile(r"^[A-Za-z0-9+/=_.:,\[\]%@~?&;#-]{1,700}$")
_PT_ARGS = re.compile(r"^[A-Za-z0-9 _.=/,-]*$")


def clean_bridge(line):
    """One bridge line in its canonical form, or None. A bridge line is written into Tor's config file, so it must be a single
    plain line: an optional known transport name, an address, an optional fingerprint, and key=value options, nothing else."""
    if not isinstance(line, str):
        return None
    s = line.strip()
    if s[:7].lower() == "bridge ":
        s = s[7:].strip()
    if not s or len(s) > 1500 or any(ord(c) < 32 or ord(c) == 127 for c in s):
        return None
    toks = s.split()
    transport = None
    if toks[0].lower() in TRANSPORTS:
        transport, toks = toks[0].lower(), toks[1:]
    if not toks:
        return None
    m = _ADDR.match(toks[0])
    if not m:
        return None
    try:
        if m.group(1):
            ipaddress.IPv4Address(m.group(1))
        else:
            ipaddress.IPv6Address(m.group(2))
    except ValueError:
        return None
    if not 1 <= int(m.group(3)) <= 65535:
        return None
    rest = toks[1:]
    if rest and "=" not in rest[0] and not _FPR.match(rest[0]):
        return None
    for t in rest:
        if not _TOKEN.match(t):
            return None
    return " ".join(([transport] if transport else []) + toks[:1] + rest)


def parse_bridges(text, limit=12):
    """(good lines, number of lines that were not usable) from text a person pasted."""
    good, bad = [], 0
    for raw in str(text or "").replace("\r", "\n").split("\n"):
        if not raw.strip():
            continue
        b = clean_bridge(raw)
        if b is None:
            bad += 1
        elif b not in good and len(good) < limit:
            good.append(b)
    return good, bad


def _bridge_transport(line):
    first = line.split(" ", 1)[0]
    return first if first in TRANSPORTS else None


class _PT:
    """What the bundle says about its pluggable transports: which program speaks which transport, and its bridge lists."""

    def __init__(self, exe):
        self.exedir = exe.parent
        self.plugins, self.bridges, self.dir = {}, {}, None
        for d in (self.exedir / "pluggable_transports", self.exedir / "PluggableTransports",
                  self.exedir.parent / "pluggable_transports", self.exedir.parent / "PluggableTransports"):
            if (d / "pt_config.json").is_file():
                self.dir = d
                break
        if self.dir is None:
            return
        try:
            cfg = json.loads((self.dir / "pt_config.json").read_text("utf-8"))
        except (OSError, ValueError):
            return
        if not isinstance(cfg, dict):
            return
        for raw in (cfg.get("pluggableTransports") or {}).values():
            line = self._plugin(raw)
            if line:
                for name in line.split()[1].split(","):
                    self.plugins.setdefault(name, line)
        for group, val in (cfg.get("bridges") or {}).items():
            items = val.get("bridges") if isinstance(val, dict) else val
            lines = [b for b in (clean_bridge(x) for x in (items or []) if isinstance(x, str)) if b]
            if lines:
                self.bridges[str(group)] = lines[:12]

    def _plugin(self, raw):
        """A ClientTransportPlugin line made safe: the program must be a file inside the bundle's own transports folder."""
        if not isinstance(raw, str):
            return None
        m = re.fullmatch(r"\s*ClientTransportPlugin\s+([a-z0-9_,]+)\s+exec\s+(\S+)(?:\s+(.*?))?\s*", raw)
        if not m:
            return None
        names, prog, args = m.group(1), m.group(2), m.group(3) or ""
        if not _PT_ARGS.match(args):
            return None
        prog = prog.replace("${pt_path}", str(self.dir) + os.sep)
        cand = Path(prog)
        if not cand.is_file() and os.name == "nt" and not prog.lower().endswith(".exe"):
            cand = Path(prog + ".exe")
        try:
            real = cand.resolve()
            real.relative_to(self.dir.resolve())
        except (OSError, ValueError):
            return None
        if not real.is_file():
            return None
        # Relative to Tor's working folder (the Shield folder), so a path with spaces never has to be quoted for Tor.
        try:
            shown = os.path.relpath(real, self.exedir.resolve())
        except ValueError:
            return None
        if " " in shown or ".." in Path(shown).parts:
            return None
        return f"ClientTransportPlugin {names} exec {shown}" + (f" {args}" if args else "")


# --------------------------------------------------------------------------
# Tor
# --------------------------------------------------------------------------
def _free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _kill_with_us(proc):
    """Windows: put Tor in a job that dies with Shield, so it can never be left running if Shield crashes."""
    if os.name != "nt":
        return None
    try:
        import ctypes
        from ctypes import wintypes
        k = ctypes.windll.kernel32

        class BASIC(ctypes.Structure):
            _fields_ = [("PerProcessUserTimeLimit", ctypes.c_int64), ("PerJobUserTimeLimit", ctypes.c_int64),
                        ("LimitFlags", wintypes.DWORD), ("MinimumWorkingSetSize", ctypes.c_size_t),
                        ("MaximumWorkingSetSize", ctypes.c_size_t), ("ActiveProcessLimit", wintypes.DWORD),
                        ("Affinity", ctypes.c_size_t), ("PriorityClass", wintypes.DWORD), ("SchedulingClass", wintypes.DWORD)]

        class IO(ctypes.Structure):
            _fields_ = [(n, ctypes.c_uint64) for n in ("a", "b", "c", "d", "e", "f")]

        class EXT(ctypes.Structure):
            _fields_ = [("Basic", BASIC), ("Io", IO), ("ProcessMemoryLimit", ctypes.c_size_t),
                        ("JobMemoryLimit", ctypes.c_size_t), ("PeakProcessMemoryUsed", ctypes.c_size_t),
                        ("PeakJobMemoryUsed", ctypes.c_size_t)]
        job = k.CreateJobObjectW(None, None)
        info = EXT()
        info.Basic.LimitFlags = 0x2000          # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        k.SetInformationJobObject(wintypes.HANDLE(job), 9, ctypes.byref(info), ctypes.sizeof(info))
        k.AssignProcessToJobObject(wintypes.HANDLE(job), wintypes.HANDLE(int(proc._handle)))
        return job
    except Exception:
        return None


def tor_folder():
    """Which folder of the bundled Tor programs belongs to THIS system. Each installer carries only its own; the others are never packed."""
    m = platform.machine().lower()
    arch = "arm64" if m in ("arm64", "aarch64") else "x64"
    if sys.platform == "win32":
        return "tor_win"
    return f"tor_mac_{arch}" if sys.platform == "darwin" else f"tor_lin_{arch}"


_BOOT = re.compile(r"Bootstrapped (\d+)%")


class TorRunner:
    """Runs the copy of tor that ships with Shield, as a plain client, and reports how far it has got."""

    def __init__(self, bases=None, home=None, on_ready=None, on_change=None):
        here = Path(__file__).resolve().parent
        frozen = Path(sys.executable).resolve().parent if getattr(sys, "frozen", False) else None
        packed = Path(sys._MEIPASS) if getattr(sys, "_MEIPASS", None) else None      # where PyInstaller puts the data files it packs
        self.bases = [Path(b) for b in (bases or [])] or [p for p in (packed, frozen, here) if p]
        self.home = Path(home) if home else Path(os.environ.get("SHIELD_HOME") or Path.home() / ".shieldbrowser")
        self.state, self.pct, self.message, self.socks_port = "idle", 0, "", 0
        self._on_ready, self._on_change = on_ready, on_change
        self._lock = threading.Lock()
        self._gen = 0
        self._proc = None
        self._thread = None
        self._job = None
        self._extra = []

    def find(self):
        """The bundled tor program, or None. Only the Shield folder is searched; nothing from the environment or PATH."""
        name = "tor.exe" if os.name == "nt" else "tor"
        for b in self.bases:
            for rel in (("tor", tor_folder(), "tor", name), ("tor", tor_folder(), name), ("tor", name), ("tor", "tor", name), ("tor", "Tor", name)):
                p = b.joinpath(*rel)
                if p.is_file():
                    return p
        return None

    def available(self):
        return self.find() is not None

    def selftest(self):
        """Run the bundled programs on this system and say whether they work: [(name, ok, detail)]. Needs no network.

        1. tor itself starts (right CPU, its libraries are found, the system lets it run).
        2. Tor accepts the configuration Shield writes for it: direct, and with each bridge type (paths, plugin lines, bridge lines).
        3. each bridge program starts and speaks Tor's transport protocol, exactly as Tor will launch it."""
        import tempfile
        exe = self.find()
        if exe is None:
            return [("tor", False, "not found")]
        kw = {"creationflags": getattr(subprocess, "CREATE_NO_WINDOW", 0)} if os.name == "nt" else {}
        out = []
        try:
            r = subprocess.run([str(exe), "--version"], cwd=str(exe.parent), capture_output=True, text=True, timeout=30, **kw)
            m = re.search(r"Tor version ([0-9][0-9.]*)", r.stdout)
            out.append(("tor", r.returncode == 0 and bool(m), f"version {m.group(1)}" if m else (r.stderr or r.stdout or "did not start").strip()[:120]))
        except (OSError, subprocess.SubprocessError) as e:
            return [("tor", False, f"could not start: {e}"[:140])]
        if not out[0][1]:
            return out
        info = self.transports()
        with tempfile.TemporaryDirectory() as tmp:
            probe = TorRunner(bases=self.bases, home=tmp)
            methods = [("direct", [])] + [(n, sorted({v["plugin"]}) + ["UseBridges 1"] + [f"Bridge {b}" for b in v["bridges"]]) for n, v in sorted(info.items())]
            for name, extra in methods:
                probe._extra = extra
                try:
                    rc = probe._torrc(exe, _free_port())
                    r = subprocess.run([str(exe), "--verify-config", "-f", str(rc)], cwd=str(exe.parent), capture_output=True, text=True, timeout=30, **kw)
                    ok = r.returncode == 0
                    why = "configuration accepted" if ok else ((r.stdout + r.stderr).strip().splitlines() or ["rejected"])[-1][:140]
                except (OSError, subprocess.SubprocessError) as e:
                    ok, why = False, str(e)[:140]
                out.append((f"{name} config", ok, why))
            for line in sorted({v["plugin"] for v in info.values()}):
                out.append(self._probe_plugin(exe, line, tmp, kw))
        return out

    @staticmethod
    def _probe_plugin(exe, line, tmp, kw):
        """Start one bridge program the way Tor does and wait for it to announce its transport."""
        import queue
        parts = line.split()
        names, prog, args = parts[1], parts[3], parts[4:]
        env = dict(os.environ, TOR_PT_MANAGED_TRANSPORT_VER="1", TOR_PT_STATE_LOCATION=tmp, TOR_PT_CLIENT_TRANSPORTS=names,
                   TOR_PT_EXIT_ON_STDIN_CLOSE="1")
        label = Path(prog).stem
        try:
            proc = subprocess.Popen([str(exe.parent / prog), *args], cwd=str(exe.parent), env=env, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                    stderr=subprocess.STDOUT, text=True, **kw)
        except OSError as e:
            return (label, False, f"could not start: {e}"[:140])
        q = queue.Queue()
        threading.Thread(target=lambda: [q.put(x.strip()) for x in proc.stdout], daemon=True).start()
        seen, end, ok = [], time.monotonic() + 15, False
        try:
            while time.monotonic() < end:
                try:
                    ln = q.get(timeout=0.3)
                except queue.Empty:
                    if proc.poll() is not None:
                        break
                    continue
                seen.append(ln)
                if ln.startswith("CMETHOD ") or "ENV-ERROR" in ln or "VERSION-ERROR" in ln:
                    ok = ln.startswith("CMETHOD ")
                    break
        finally:
            try:
                proc.stdin.close()
                proc.wait(3)
            except Exception:
                proc.kill()
        return (label, ok, f"starts and offers {names}" if ok else ("; ".join(seen)[:140] or "gave no answer"))

    def pt(self):
        exe = self.find()
        return _PT(exe) if exe is not None else None

    def transports(self):
        """The bridge methods this copy of Shield can actually use: {'obfs4': {...}, 'snowflake': {...}}. A method is listed
        only if the bundle has a bridge list for it AND the program that speaks it."""
        pt = self.pt()
        out = {}
        if pt is None:
            return out
        for name in ("obfs4", "snowflake"):
            group = pt.bridges.get(name)
            if not group:
                continue
            keep = [b for b in group if _bridge_transport(b) in (None, name) and (_bridge_transport(b) is None or _bridge_transport(b) in pt.plugins)]
            if keep and name in pt.plugins:
                out[name] = {"plugin": pt.plugins[name], "bridges": keep}
        return out

    def plugin_for(self, transport):
        pt = self.pt()
        return pt.plugins.get(transport) if pt else None

    def _set(self, state=None, pct=None, message=None):
        if state is not None:
            self.state = state
        if pct is not None:
            self.pct = pct
        if message is not None:
            self.message = message
        if self._on_change:
            try:
                self._on_change()
            except Exception:
                pass

    def start(self, extra=None):
        """extra: already-validated torrc lines (bridge settings) to add for this run."""
        with self._lock:
            if self.state in ("starting", "ready"):
                return
            self._extra = list(extra or [])
            self._gen += 1
            gen, prev = self._gen, self._thread
            self.socks_port = 0
            self._set("starting", 0, "Starting")
            self._thread = threading.Thread(target=self._run, args=(gen, prev), name="shield-tor", daemon=True)
            self._thread.start()

    def stop(self):
        with self._lock:
            self._gen += 1
            self.socks_port = 0
            self.state, self.pct, self.message = "idle", 0, ""
            p = self._proc
        if p is not None:
            try:
                p.terminate()
            except Exception:
                pass

    def join(self, timeout=5.0):
        t = self._thread
        if t is not None:
            t.join(timeout)

    def _torrc(self, exe, port):
        data = self.home / "tor" / "data"
        data.mkdir(parents=True, exist_ok=True)
        lines = [f'DataDirectory "{data.as_posix()}"', f"SocksPort 127.0.0.1:{port} IsolateSOCKSAuth", "SafeSocks 1",
                 "ClientOnly 1", "AvoidDiskWrites 1", "Log notice stdout"]
        for opt, fn in (("GeoIPFile", "geoip"), ("GeoIPv6File", "geoip6")):
            for d in (exe.parent, exe.parent / "data", exe.parent.parent / "data", exe.parent.parent):
                if (d / fn).is_file():
                    lines.append(f'{opt} "{(d / fn).as_posix()}"')
                    break
        lines += [x for x in self._extra if "\n" not in x and "\r" not in x]
        path = self.home / "tor" / "torrc"
        path.write_text("\n".join(lines) + "\n", "utf-8")
        return path

    def _run(self, gen, prev):
        if prev is not None:
            prev.join(10)                    # never two copies on one data folder
        proc = None
        try:
            exe = self.find()
            if gen != self._gen:
                return
            if exe is None:
                self._set("missing", 0, "The private connection component is not installed.")
                return
            port = _free_port()
            torrc = self._torrc(exe, port)
            kw = {}
            if os.name == "nt":
                kw["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
            proc = subprocess.Popen([str(exe), "-f", str(torrc)], cwd=str(exe.parent), stdin=subprocess.DEVNULL,
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, encoding="utf-8",
                                    errors="replace", bufsize=1, **kw)
            self._job = _kill_with_us(proc)
            with self._lock:
                if gen != self._gen:
                    proc.terminate()
                    return
                self._proc = proc
            last_err = ""
            for line in proc.stdout:
                if gen != self._gen:
                    break
                m = _BOOT.search(line)
                if m:
                    pct = int(m.group(1))
                    if pct >= 100:
                        self.socks_port = port
                        self._set("ready", 100, "Connected")
                        if self._on_ready and gen == self._gen:
                            self._on_ready(port)
                    else:
                        self._set(pct=pct, message=line.split(":", 1)[-1].strip()[:120])
                elif "[err]" in line or ("[warn]" in line and "Problem bootstrapping" in line):
                    last_err = line.split("]", 1)[-1].strip()[:160]
            if gen == self._gen:
                self._set("failed", None, last_err or "Tor stopped unexpectedly.")
        except Exception as e:
            if gen == self._gen:
                self._set("failed", None, f"Could not start Tor: {e}"[:160])
        finally:
            if proc is not None:
                try:
                    if proc.poll() is None:
                        proc.terminate()
                        try:
                            proc.wait(5)
                        except subprocess.TimeoutExpired:
                            proc.kill()
                except Exception:
                    pass
                with self._lock:
                    if self._proc is proc:
                        self._proc = None


# --------------------------------------------------------------------------
# The switch the person sees
# --------------------------------------------------------------------------
def bundle_status(bases=None):
    """What this copy of Shield includes, for the settings page."""
    r = TorRunner(bases=bases)
    if not r.available():
        return {"tor": False, "obfs4": False, "snowflake": False}
    t = r.transports()
    return {"tor": True, "obfs4": "obfs4" in t, "snowflake": "snowflake" in t}


class PrivacyProxy:
    """off / connecting / on / failed / unavailable, and the one call that changes it."""

    # How long a method may go without making progress before the next one is tried. Direct Tor on a network that blocks it
    # stalls at the very start; bridges legitimately take longer, and Snowflake has to find a volunteer first.
    STALL = {"direct": 30.0, "custom": 60.0, "obfs4": 60.0, "snowflake": 120.0}
    LABEL = {"direct": "", "custom": "your bridge", "obfs4": "an obfs4 bridge", "snowflake": "Snowflake"}

    def __init__(self, bases=None, home=None):
        self.switch = SwitchProxy()
        self.tor = TorRunner(bases=bases, home=home, on_ready=self._tor_ready)
        self.settings = lambda: ("auto", "")        # -> (bridge mode, pasted bridge lines); the browser replaces this
        self.want = False
        self.phase = "idle"                         # idle | trying | ready | failed
        self.transport = ""
        self.fail = ""
        self._gen = 0

    def start(self):
        """Start the local switch. Returns its port, which Chromium must be told about before it starts."""
        return self.switch.start()

    @property
    def port(self):
        return self.switch.port

    def _tor_ready(self, socks_port):
        """Tor has a circuit. The switch starts tunnelling and the state says 'on' in the same instant, so what the button
        shows is never behind what the connection is doing."""
        if self.want:
            self.switch.configure("tunnel", ("127.0.0.1", socks_port))
            self.phase = "ready"
            if self.transport:
                self._remember(self.transport)

    def available(self):
        return self.tor.available()

    def selftest(self):
        return self.tor.selftest()

    # -- which methods, in which order ---------------------------------------------
    def _file(self):
        return self.tor.home / "tor" / "last_transport"

    def _recent(self):
        try:
            name, when = self._file().read_text("utf-8").split()
            if name in self.STALL and time.time() - float(when) < REMEMBER_FOR:
                return name
        except (OSError, ValueError):
            pass
        return None

    def _remember(self, name):
        try:
            self._file().parent.mkdir(parents=True, exist_ok=True)
            self._file().write_text(f"{name} {int(time.time())}", "utf-8")
        except OSError:
            pass

    def _custom(self):
        """The person's own bridges that this copy of Shield can use (the program for their transport must exist)."""
        lines, _bad = parse_bridges(self.settings()[1])
        pt = self.tor.pt()
        return [b for b in lines if _bridge_transport(b) is None or (pt is not None and _bridge_transport(b) in pt.plugins)]

    def plan(self):
        """(ordered list of methods to try, message if there is nothing to try)."""
        mode = self.settings()[0]
        have = self.tor.transports()
        custom = self._custom()
        if mode == "off":
            return ["direct"], ""
        if mode in ("obfs4", "snowflake"):
            if mode in have:
                return [mode], ""
            return [], f"{'obfs4' if mode == 'obfs4' else 'Snowflake'} bridges are not included in this copy of Shield."
        if mode == "custom":
            if custom:
                return ["custom"], ""
            return [], "No usable bridges were found in the list you saved in Settings."
        seq = ["direct"] + (["custom"] if custom else []) + [t for t in ("obfs4", "snowflake") if t in have]
        last = self._recent()
        if last in seq and last != "direct":
            seq.remove(last)
            seq.insert(0, last)
        return seq, ""

    def _extra(self, method):
        if method == "direct":
            return []
        if method == "custom":
            bridges = self._custom()
            plugins = {self.tor.plugin_for(_bridge_transport(b)) for b in bridges if _bridge_transport(b)}
        else:
            info = self.tor.transports()[method]
            bridges, plugins = info["bridges"], {info["plugin"]}
        return sorted(p for p in plugins if p) + ["UseBridges 1"] + [f"Bridge {b}" for b in bridges]

    # -- the switch ------------------------------------------------------------------
    def enable(self):
        if self.want:
            return
        if not self.tor.available():
            self.tor._set("missing", 0, "The private connection component is not installed with this copy of Shield.")
            return
        self.want = True
        self._gen += 1
        self.phase, self.transport, self.fail = "trying", "", ""
        self.switch.configure("tunnel", None)        # from this moment nothing goes out unprotected
        threading.Thread(target=self._attempts, args=(self._gen,), name="shield-tor-plan", daemon=True).start()

    def disable(self):
        self.want = False
        self._gen += 1
        self.phase = "idle"
        self.switch.configure("direct")
        self.tor.stop()

    def toggle(self):
        (self.disable if self.want else self.enable)()
        return self.want

    def _fail(self, gen, message):
        if gen == self._gen:
            self.phase, self.fail = "failed", message
            self.tor.stop()

    def _attempts(self, gen):
        """Try each method in turn until Tor has built a circuit. Runs on its own thread; the kill switch is already on."""
        try:
            order, why = self.plan()
            if not order:
                self._fail(gen, why)
                return
            deadline = time.monotonic() + START_TIMEOUT
            error = ""
            for method in order:
                if gen != self._gen:
                    return
                self.transport = method
                self.tor.start(self._extra(method))
                last_move, seen = time.monotonic(), -1
                while True:
                    time.sleep(0.2)
                    if gen != self._gen:
                        return
                    now, ts = time.monotonic(), self.tor.state
                    if ts == "ready":
                        self.phase = "ready"
                        self._remember(method)
                        return
                    if ts == "missing":
                        self._fail(gen, self.tor.message)
                        return
                    if ts == "failed":
                        error = self.tor.message
                        break
                    if self.tor.pct != seen:
                        seen, last_move = self.tor.pct, now
                    if now - last_move > self.STALL[method] or now > deadline:
                        break
                self.tor.stop()                      # this one didn't work: clean up, then the next
                self.tor.join(10)
                if now > deadline:
                    break
            if any(m != "direct" for m in order):
                self._fail(gen, "Tor could not connect, even through bridges. This network may be blocking it. "
                                "You can add a bridge of your own in Settings, under Private connection.")
            elif error:
                self._fail(gen, error)               # a real error from Tor itself is more useful than a guess
            else:
                self._fail(gen, "Tor could not connect. This network may be blocking it. This copy of Shield has no bridges "
                                "to try; you can add your own in Settings, under Private connection.")
        except Exception as e:
            self._fail(gen, f"Could not start the private connection: {e}"[:160])

    def new_identity(self):
        if self.want and self.state()["name"] == "on":
            self.switch.new_identity()

    def state(self):
        """{'name': off|connecting|on|failed|unavailable, 'pct': 0..100, 'message': text, 'transport': direct|obfs4|...}"""
        t = self.tor
        base = {"transport": self.transport}
        if not self.want:
            if t.state == "missing":
                return {**base, "name": "unavailable", "pct": 0, "message": t.message}
            return {**base, "name": "off", "pct": 0, "message": ""}
        if self.phase == "failed":
            return {**base, "name": "failed", "pct": t.pct, "message": self.fail}
        if self.phase == "ready":
            if t.state == "ready" and self.switch.upstream is not None:
                return {**base, "name": "on", "pct": 100, "message": "Connected"}
            return {**base, "name": "failed", "pct": t.pct, "message": t.message or "Tor stopped unexpectedly."}
        via = self.LABEL.get(self.transport, "")
        msg = (t.message or "Connecting") + (f" (trying {via})" if via else "")
        return {**base, "name": "connecting", "pct": t.pct, "message": msg}

    def shutdown(self):
        self.want = False
        self._gen += 1
        try:
            self.switch.configure("direct")
            self.tor.stop()
            self.tor.join(3)
            self.switch.shutdown()
        except Exception:
            pass
