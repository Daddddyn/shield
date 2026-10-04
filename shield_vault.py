"""
shield_vault.py: the password vault. No Qt in here, so it can be tested on its own.

Design
------
  * One file on this computer (vault.shv). Nothing is synced or uploaded.
  * A random 256-bit data key encrypts the entries (AES-256-GCM). The data key is itself encrypted with a key
    derived from your master password using Argon2id (a deliberately slow, memory-hard function, so guessing is
    expensive: 128 MiB and three passes per attempt). Vaults from older versions used scrypt; they still open, and
    are upgraded the first time they are unlocked.
  * Changing the master password (and every upgrade) creates a brand-new data key and re-encrypts the entries, then
    deletes the backup copy. An old copy of the file that leaks together with the old password therefore cannot open
    anything saved afterwards. Deleting an entry also deletes the backup that still held it.
  * The file header is authenticated, so changing the KDF settings or swapping parts of a file is detected.
  * The master password is never stored. Forget it and the vault cannot be opened: there is no recovery.
  * Everything, including the list of sites you told it never to save, lives inside the encrypted part, so the
    file reveals nothing about where you have accounts.
  * Writes are atomic (write, flush, replace) and the previous version is kept as vault.shv.bak.
  * The vault locks itself after a period of inactivity and on demand.

Honest limits: Python cannot wipe secrets from memory, so while the vault is unlocked, malware running as you
could read them. The vault protects the file at rest and the passwords from web pages, not from a compromised PC.
"""
from __future__ import annotations

import base64
import csv
import hashlib
import io
import json
import os
import re
import secrets
import string
import threading
import time
import unicodedata
from pathlib import Path
from urllib.parse import urlsplit

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

FORMAT = 2
# Current settings: Argon2id, 128 MiB, 3 passes, 4 lanes (about half a second on a normal PC).
KDF = {"alg": "argon2id", "m": 128 * 1024, "t": 3, "p": 4}
# Bounds for what an opened file may ask for. Too low means a weak file (it is upgraded on unlock); too high means
# a hostile file trying to exhaust memory or time.
MIN_M, MAX_M = 64 * 1024, 1024 * 1024          # KiB
MIN_T, MAX_T = 2, 12
MIN_P, MAX_P = 1, 16
# Format 1 (Shield 2.x): scrypt. Read-only; never written any more.
LEGACY_SCRYPT = {"n": 2 ** 16, "r": 8, "p": 2}
LEGACY_MIN_N = 2 ** 15
MIN_MASTER = 12
MAX_FIELD = 1024
MAX_ENTRIES = 20000
_WRAP_AAD = {1: b"shield-vault/wrap/v1", 2: b"shield-vault/wrap/v2"}
_DATA_AAD = {1: b"shield-vault/data/v1", 2: b"shield-vault/data/v2"}


class VaultError(Exception):
    pass


def _b64(b):
    return base64.b64encode(b).decode("ascii")


def _unb64(s):
    return base64.b64decode(s.encode("ascii"))


def _normalize_master(pw):
    return unicodedata.normalize("NFKC", pw).encode("utf-8")


def _derive_scrypt(master, salt, n, r, p):
    return hashlib.scrypt(_normalize_master(master), salt=salt, n=n, r=r, p=p, maxmem=256 * 1024 * 1024, dklen=32)


def _derive_argon(master, salt, m, t, p):
    return Argon2id(salt=salt, length=32, iterations=t, lanes=p, memory_cost=m).derive(_normalize_master(master))


def norm_origin(url):
    """scheme://host[:port] for web addresses, or '' for anything a login should never be tied to."""
    try:
        s = urlsplit((url or "").strip())
        host = (s.hostname or "").lower().rstrip(".")
        if s.scheme not in ("http", "https") or not host:
            return ""
        port = s.port
    except ValueError:
        return ""
    default = 443 if s.scheme == "https" else 80
    return f"{s.scheme}://{host}" + (f":{port}" if port and port != default else "")


def host_of(origin):
    return urlsplit(origin).hostname or ""


def can_fill(origin):
    """Credentials are only ever filled on HTTPS pages, or plain HTTP on this very computer (dev servers)."""
    s = urlsplit(origin)
    if s.scheme == "https":
        return True
    h = (s.hostname or "")
    return s.scheme == "http" and (h == "localhost" or h.endswith(".localhost") or h in ("127.0.0.1", "::1"))


_fill_safe = can_fill


# --------------------------------------------------------------------------
# Passwords: generator and strength
# --------------------------------------------------------------------------
AMBIGUOUS = set("Il1O0o")
SYMBOLS = "!@#$%^&*()-_=+[]{};:,.?"


def generate(length=20, lower=True, upper=True, digits=True, symbols=True, avoid_ambiguous=True):
    """A random password from the operating system's secure generator, with at least one character of each kind."""
    length = max(8, min(128, int(length)))
    pools = []
    for on, chars in ((lower, string.ascii_lowercase), (upper, string.ascii_uppercase), (digits, string.digits), (symbols, SYMBOLS)):
        if on:
            pools.append([c for c in chars if not (avoid_ambiguous and c in AMBIGUOUS)])
    if not pools:
        pools = [[c for c in string.ascii_lowercase + string.digits if not (avoid_ambiguous and c in AMBIGUOUS)]]
    out = [secrets.choice(p) for p in pools]
    allc = [c for p in pools for c in p]
    out += [secrets.choice(allc) for _ in range(length - len(out))]
    secrets.SystemRandom().shuffle(out)
    return "".join(out)


_COMMON = set("""password 123456 12345678 123456789 qwerty abc123 111111 password1 iloveyou admin welcome monkey dragon
letmein login master football baseball sunshine princess qwertyuiop 654321 superman 1qaz2wsx trustno1 passw0rd
michael shadow 123123 1234567 1234567890 000000 qazwsx zaq12wsx charlie jordan hello freedom whatever starwars
computer secret summer flower hunter ranger buster soccer harley batman killer pepper cheese cookie internet
""".split())
_SEQS = ["abcdefghijklmnopqrstuvwxyz", "qwertyuiopasdfghjklzxcvbnm", "0123456789", "9876543210"]


def strength(pw):
    """(score 0-4, label, estimated bits). An estimate: it punishes the patterns people actually use."""
    if not pw:
        return 0, "Empty", 0.0
    low = pw.lower()
    pool = 0
    for chars in (string.ascii_lowercase, string.ascii_uppercase, string.digits, SYMBOLS):
        if any(c in chars for c in pw):
            pool += len(chars)
    if any(ord(c) > 127 for c in pw):
        pool += 60
    bits = len(pw) * (pool.bit_length() if pool else 1) * 0.98
    uniq = len(set(pw))
    bits -= max(0, len(pw) - uniq) * 1.5
    if low in _COMMON or re.sub(r"[\d\W_]+$", "", low) in _COMMON:
        bits = min(bits, 12)
    if any(low[i:i + 4] in s for s in _SEQS for i in range(max(0, len(low) - 3))):
        bits -= 8
    if re.fullmatch(r"(.{1,4})\1+", pw):
        bits = min(bits, 14)
    if re.fullmatch(r"[a-zA-Z]+\d{1,4}[!@#$%^&*.?]?", pw):
        bits -= 10
    if re.search(r"(19|20)\d\d", pw):
        bits -= 6
    bits = max(0.0, bits)
    score = 0 if bits < 28 else 1 if bits < 40 else 2 if bits < 56 else 3 if bits < 72 else 4
    return score, ("Very weak", "Weak", "Fair", "Strong", "Excellent")[score], round(bits, 1)


# --------------------------------------------------------------------------
# The vault
# --------------------------------------------------------------------------
class Vault:
    def __init__(self, path, idle_minutes=15):
        self.path = Path(path)
        self.idle_minutes = idle_minutes
        self._key = None                # the data key, only while unlocked
        self._head = None
        self.entries = []
        self.never = set()
        self.rev = 0                    # bumps on every change, lock and unlock (the UI polls it)
        self._last = time.time()
        self._fails, self._block_until = 0, 0.0
        self._lock = threading.RLock()

    # -- state ---------------------------------------------------------------
    def exists(self):
        return self.path.is_file()

    @property
    def unlocked(self):
        return self._key is not None

    def touch(self):
        self._last = time.time()

    def tick(self):
        """Call regularly: locks the vault after the idle period. Returns True if it just locked."""
        if self.unlocked and self.idle_minutes and time.time() - self._last > self.idle_minutes * 60:
            self.lock()
            return True
        return False

    def lock(self):
        with self._lock:
            was = self.unlocked
            self._key, self._head = None, None
            self.entries, self.never = [], set()
            if was:
                self.rev += 1

    # -- creating / opening --------------------------------------------------
    def create(self, master):
        if self.exists():
            raise VaultError("A vault already exists")
        self._check_master(master)
        with self._lock:
            self._key = secrets.token_bytes(32)
            self.entries, self.never = [], set()
            self._head = self._new_head(master)
            self._save()
            self.rev += 1
            self.touch()

    @staticmethod
    def _check_master(master):
        if len(master or "") < MIN_MASTER:
            raise VaultError(f"The master password needs at least {MIN_MASTER} characters")

    # -- key wrapping --------------------------------------------------------
    @staticmethod
    def _kdf_aad(kdf, salt, version=FORMAT):
        """The key-derivation settings, bound into the wrapped key so they cannot be swapped without detection."""
        if version == 1:
            body = {"n": kdf["n"], "r": kdf["r"], "p": kdf["p"], "s": _b64(salt)}
        else:
            body = {"alg": kdf["alg"], "m": kdf["m"], "t": kdf["t"], "p": kdf["p"], "s": _b64(salt)}
        return json.dumps(body, sort_keys=True).encode()

    def _new_head(self, master):
        """Wrap self._key under a fresh salt with the current (Argon2id) settings."""
        salt = secrets.token_bytes(16)
        kek = _derive_argon(master, salt, KDF["m"], KDF["t"], KDF["p"])
        nonce = secrets.token_bytes(12)
        wrapped = AESGCM(kek).encrypt(nonce, self._key, _WRAP_AAD[FORMAT] + self._kdf_aad(KDF, salt))
        return {"v": FORMAT, "kdf": {**KDF, "salt": _b64(salt)}, "wrap": {"nonce": _b64(nonce), "ct": _b64(wrapped)}}

    @staticmethod
    def _parse_kdf(head):
        """(version, kdf settings, salt, is_current). Raises VaultError for a file asking for unsafe settings."""
        v = head.get("v")
        if v not in (1, 2):
            raise VaultError("This vault was made by a newer version of Shield")
        k = head["kdf"]
        salt = _unb64(k["salt"])
        if len(salt) < 16:
            raise VaultError("The vault file has unsafe settings and was not opened")
        if v == 1:
            n, r, p = int(k["n"]), int(k["r"]), int(k["p"])
            if not (LEGACY_MIN_N <= n <= 2 ** 20 and n & (n - 1) == 0 and 1 <= r <= 16 and 1 <= p <= 8):
                raise VaultError("The vault file has unsafe settings and was not opened")
            return 1, {"n": n, "r": r, "p": p}, salt, False
        if k.get("alg") != "argon2id":
            raise VaultError("The vault file has unsafe settings and was not opened")
        m, t, p = int(k["m"]), int(k["t"]), int(k["p"])
        if not (MIN_M <= m <= MAX_M and MIN_T <= t <= MAX_T and MIN_P <= p <= MAX_P):
            raise VaultError("The vault file has unsafe settings and was not opened")
        current = m >= KDF["m"] and t >= KDF["t"] and p >= KDF["p"]
        return 2, {"alg": "argon2id", "m": m, "t": t, "p": p}, salt, current

    def _unwrap(self, head, master):
        """The data key if master is right, None if it is wrong. Raises VaultError for unreadable or unsafe files."""
        try:
            ver, k, salt, _cur = self._parse_kdf(head)
            if ver == 1:
                kek = _derive_scrypt(master, salt, k["n"], k["r"], k["p"])
            else:
                kek = _derive_argon(master, salt, k["m"], k["t"], k["p"])
            return AESGCM(kek).decrypt(_unb64(head["wrap"]["nonce"]), _unb64(head["wrap"]["ct"]),
                                       _WRAP_AAD[ver] + self._kdf_aad(k, salt, ver))
        except InvalidTag:
            return None
        except VaultError:
            raise
        except (ValueError, KeyError, TypeError):
            raise VaultError("The vault file is damaged. A backup may exist next to it (vault.shv.bak).") from None

    def wait_seconds(self):
        return max(0, int(self._block_until - time.time() + 0.999))

    def unlock(self, master):
        """True on success. After repeated wrong passwords, attempts are slowed down (wait_seconds())."""
        with self._lock:
            if self.unlocked:
                return True
            if self.wait_seconds():
                return False
            try:
                head = json.loads(self.path.read_text("utf-8"))
                if not isinstance(head, dict):
                    raise ValueError
            except (OSError, ValueError):
                raise VaultError("The vault file is damaged. A backup may exist next to it (vault.shv.bak).") from None
            key = self._unwrap(head, master)
            if key is None:
                self._note_failure()
                return False
            try:
                ver = head["v"]
                blob = AESGCM(key).decrypt(_unb64(head["data"]["nonce"]), _unb64(head["data"]["ct"]),
                                           _DATA_AAD[ver] + self._head_aad(head))
                data = json.loads(blob.decode("utf-8"))
            except (InvalidTag, ValueError, KeyError, TypeError):
                raise VaultError("The vault file is damaged. A backup may exist next to it (vault.shv.bak).") from None
            self._fails, self._block_until = 0, 0.0
            self._key, self._head = key, {k: v for k, v in head.items() if k != "data"}
            self.entries = [e for e in data.get("entries", []) if isinstance(e, dict)]
            self.never = set(data.get("never", []))
            self.rev += 1
            self.touch()
            _ver, _k, _salt, current = self._parse_kdf(head)
            if ver != FORMAT or not current:
                # An older or weaker vault: move it to the current format with a brand-new data key.
                try:
                    self._rekey(master)
                except (OSError, VaultError):
                    pass            # it still opens fine; the upgrade is tried again next time
            return True

    def _note_failure(self):
        self._fails += 1
        self._block_until = time.time() + (min(30, 2 ** (self._fails - 3)) if self._fails > 3 else 0)

    @staticmethod
    def _head_aad(head):
        return json.dumps({"v": head["v"], "kdf": head["kdf"], "wrap": head["wrap"]}, sort_keys=True).encode()

    def verify_master(self, master):
        """True if master is the vault's master password. Used to confirm risky actions while unlocked."""
        with self._lock:
            self._need()
            try:
                head = json.loads(self.path.read_text("utf-8"))
                if not isinstance(head, dict):
                    raise ValueError
            except (OSError, ValueError):
                raise VaultError("The vault file couldn't be read") from None
            return self._unwrap(head, master) is not None

    def _rekey(self, master):
        """New random data key, new salt, current KDF settings; entries re-encrypted; the old backup is deleted.
        If anything fails, the in-memory state goes back to what it was and the file is left as it was."""
        old_key, old_head = self._key, self._head
        try:
            self._key = secrets.token_bytes(32)
            self._head = self._new_head(master)
            self._save(drop_backup=True)
        except Exception:
            self._key, self._head = old_key, old_head
            raise

    def change_master(self, old, new):
        with self._lock:
            self._need()
            self._check_master(new)
            if not self.verify_master(old):
                self._note_failure()
                return False
            self._rekey(new)
            self.rev += 1
            return True

    # -- saving ----------------------------------------------------------------
    def _save(self, drop_backup=False):
        payload = json.dumps({"entries": self.entries, "never": sorted(self.never)}, separators=(",", ":")).encode("utf-8")
        nonce = secrets.token_bytes(12)
        head = dict(self._head)
        head["data"] = {"nonce": _b64(nonce),
                        "ct": _b64(AESGCM(self._key).encrypt(nonce, payload, _DATA_AAD[head["v"]] + self._head_aad(head)))}
        self._head = {k: v for k, v in head.items() if k != "data"}
        text = json.dumps(head, separators=(",", ":"))
        tmp = self.path.with_suffix(".part")
        with open(tmp, "w", encoding="utf-8") as f:
            f.write(text)
            f.flush()
            os.fsync(f.fileno())
        if os.name != "nt":
            try:
                os.chmod(tmp, 0o600)
            except OSError:
                pass
        bak = self.path.with_suffix(".shv.bak")
        if self.path.exists():
            try:
                os.replace(self.path, bak)
            except OSError:
                pass
        os.replace(tmp, self.path)
        if os.name != "nt":
            try:
                os.chmod(self.path, 0o600)
            except OSError:
                pass
        if drop_backup:
            # Only after the new file is proven readable with the new key; until then the backup is the safety net.
            if self._readback_ok(len(self.entries)):
                try:
                    bak.unlink()
                except OSError:
                    pass

    def _readback_ok(self, count):
        try:
            head = json.loads(self.path.read_text("utf-8"))
            blob = AESGCM(self._key).decrypt(_unb64(head["data"]["nonce"]), _unb64(head["data"]["ct"]),
                                             _DATA_AAD[head["v"]] + self._head_aad(head))
            return len(json.loads(blob.decode("utf-8")).get("entries", [])) == count
        except Exception:
            return False

    def _need(self):
        if not self.unlocked:
            raise VaultError("The vault is locked")
        self.touch()

    # -- entries -----------------------------------------------------------------
    @staticmethod
    def _clean(v):
        return (v or "")[:MAX_FIELD]

    def add(self, url, username, password, title=""):
        with self._lock:
            self._need()
            origin = norm_origin(url)
            if not origin:
                raise VaultError("That isn't a web address")
            if not password:
                raise VaultError("The password is empty")
            if len(self.entries) >= MAX_ENTRIES:
                raise VaultError("The vault is full")
            username = self._clean(username)
            dup = self._find(origin, username)
            now = time.time()
            if dup:
                dup.update(password=self._clean(password), modified=now)
                eid = dup["id"]
            else:
                eid = secrets.token_hex(6)
                self.entries.append({"id": eid, "origin": origin, "username": username, "password": self._clean(password),
                                     "title": self._clean(title) or host_of(origin), "created": now, "modified": now, "used": 0})
            self._save()
            self.rev += 1
            return eid

    def _find(self, origin, username):
        return next((e for e in self.entries if e["origin"] == origin and e["username"] == username), None)

    def get(self, eid):
        self._need()
        return next((e for e in self.entries if e["id"] == eid), None)

    def update(self, eid, url=None, username=None, password=None, title=None):
        with self._lock:
            e = self.get(eid)
            if not e:
                raise VaultError("That entry no longer exists")
            if url is not None:
                origin = norm_origin(url)
                if not origin:
                    raise VaultError("That isn't a web address")
                e["origin"] = origin
            if username is not None:
                e["username"] = self._clean(username)
            if password is not None:
                if not password:
                    raise VaultError("The password is empty")
                e["password"] = self._clean(password)
            if title is not None:
                e["title"] = self._clean(title) or host_of(e["origin"])
            e["modified"] = time.time()
            self._save()
            self.rev += 1

    def delete(self, eid):
        with self._lock:
            self._need()
            n = len(self.entries)
            self.entries = [e for e in self.entries if e["id"] != eid]
            if len(self.entries) != n:
                self._save(drop_backup=True)      # the backup would still hold the deleted password
                self.rev += 1

    def mark_used(self, eid):
        with self._lock:
            e = self.get(eid)
            if e:
                e["used"] = time.time()
                self._save()

    def for_origin(self, origin):
        """Logins for exactly this origin (same scheme, host and port), most recently used first."""
        self._need()
        if not origin or not can_fill(origin):
            return []
        hits = [e for e in self.entries if e["origin"] == origin]
        return sorted(hits, key=lambda e: (e["used"], e["modified"]), reverse=True)

    def known(self, origin, username, password):
        """'same' if this exact login is saved, 'changed' if the account is saved with another password, else 'new'."""
        e = self._find(origin, username)
        if not e:
            return "new", None
        return ("same" if e["password"] == password else "changed"), e["id"]

    # -- never-save list ---------------------------------------------------------
    def never_add(self, host):
        with self._lock:
            self._need()
            self.never.add((host or "").lower())
            self._save()
            self.rev += 1

    def never_remove(self, host):
        with self._lock:
            self._need()
            self.never.discard((host or "").lower())
            self._save()
            self.rev += 1

    # -- check-up ------------------------------------------------------------------
    def audit(self):
        self._need()
        weak, by_pw, old = [], {}, []
        cutoff = time.time() - 365 * 86400 * 2
        for e in self.entries:
            if strength(e["password"])[0] <= 1:
                weak.append(e["id"])
            by_pw.setdefault(e["password"], []).append(e["id"])
            if e["modified"] < cutoff:
                old.append(e["id"])
        reused = [ids for ids in by_pw.values() if len(ids) > 1]
        return {"weak": weak, "reused": reused, "old": old, "total": len(self.entries)}

    # -- import / export ---------------------------------------------------------------
    def export_csv(self):
        self._need()
        buf = io.StringIO()
        w = csv.writer(buf)
        w.writerow(["name", "url", "username", "password"])
        for e in self.entries:
            w.writerow([e["title"], e["origin"], e["username"], e["password"]])
        return buf.getvalue()

    def import_csv(self, text):
        """Accepts the CSV files other browsers and password managers export. Returns (added, skipped)."""
        self._need()
        if len(text) > 8 * 1024 * 1024:
            raise VaultError("That file is too large to be a password list")
        rows = list(csv.reader(io.StringIO(text.lstrip("\ufeff"))))
        if not rows:
            return 0, 0
        head = [h.strip().lower() for h in rows[0]]

        def col(*names):
            for n in names:
                if n in head:
                    return head.index(n)
            return -1
        iu = col("url", "login_uri", "origin", "website", "web site", "login uri", "hostname", "site")
        iw = col("username", "login_username", "login username", "login", "user", "email", "user name", "login name")
        ip = col("password", "login_password", "login password", "pass")
        it = col("name", "title")
        if iu < 0 or ip < 0:
            raise VaultError("Couldn't find the address and password columns in that file")
        added = skipped = 0
        with self._lock:
            for r in rows[1:MAX_ENTRIES + 1]:
                try:
                    origin = norm_origin(r[iu] if "://" in r[iu] else "https://" + r[iu].strip())
                    pw = r[ip]
                except IndexError:
                    skipped += 1
                    continue
                if not origin or not pw:
                    skipped += 1
                    continue
                user = r[iw] if iw >= 0 and iw < len(r) else ""
                if self._find(origin, self._clean(user)):
                    skipped += 1
                    continue
                if len(self.entries) >= MAX_ENTRIES:
                    skipped += 1
                    continue
                now = time.time()
                self.entries.append({"id": secrets.token_hex(6), "origin": origin, "username": self._clean(user),
                                     "password": self._clean(pw),
                                     "title": self._clean(r[it] if it >= 0 and it < len(r) else "") or host_of(origin),
                                     "created": now, "modified": now, "used": 0})
                added += 1
            if added:
                self._save()
                self.rev += 1
        return added, skipped

    def wipe(self):
        """Delete the vault file and its backup (used for 'start over')."""
        with self._lock:
            self.lock()
            for p in (self.path, self.path.with_suffix(".shv.bak"), self.path.with_suffix(".part")):
                try:
                    p.unlink()
                except OSError:
                    pass
            self.rev += 1
