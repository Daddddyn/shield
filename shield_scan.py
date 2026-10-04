"""
shield_scan.py: what the download gate uses to decide whether a file is safe.

No Qt in here, so it can be tested on its own. Nothing in this file touches the
network unless the user asks (rule updates, VirusTotal).

How a verdict is reached
------------------------
A file being a program is NOT a finding. Nearly every useful download (Chrome,
Firefox, Steam) is an .exe, so "it's executable" says nothing about danger.
What matters is evidence:

  1. Who made it?   Signature check by the operating system (Authenticode on
                    Windows, codesign on macOS). A valid signature means the
                    publisher is known and the file is unchanged since signing.
  2. Is it lying?   Contents vs. file name: a program called photo.pdf, a
                    ".pdf.exe" double extension, macros inside a ".docx".
  3. Do scanners recognise it?
                    YARA-X with community rules (pip, all platforms),
                    ClamAV (if installed), Microsoft Defender (Windows, if on).
  4. Optionally, VirusTotal (hash lookup, upload only on request).
"""
from __future__ import annotations

import concurrent.futures
import hashlib
import io
import json
import math
import os
import re
import secrets
import shutil
import subprocess
import sys
import tarfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path

try:  # optional: structural checks on Windows programs
    import pefile
except Exception:  # pragma: no cover
    pefile = None
try:  # optional: community detection rules, wheels exist for Windows, macOS and Linux
    import yara_x
except Exception:  # pragma: no cover
    yara_x = None

VERSION = "1.0"

# --------------------------------------------------------------------------
# File type knowledge
# --------------------------------------------------------------------------
NATIVE_EXT = {".exe", ".dll", ".scr", ".com", ".cpl", ".sys", ".ocx"}
INSTALLER_EXT = {".msi", ".msix", ".msixbundle", ".appx", ".appxbundle", ".msp", ".pkg", ".mpkg",
                 ".dmg", ".deb", ".rpm", ".appimage", ".apk", ".run"}
SCRIPT_EXT = {".bat", ".cmd", ".ps1", ".psm1", ".vbs", ".vbe", ".js", ".jse", ".wsf", ".wsh", ".hta",
              ".sh", ".command", ".reg", ".lnk", ".jar", ".chm", ".inf", ".url"}
DISKIMG_EXT = {".iso", ".img", ".vhd", ".vhdx"}
EXEC_EXT = NATIVE_EXT | INSTALLER_EXT | SCRIPT_EXT | DISKIMG_EXT
# Types that almost nobody means to download from a website, and that malware loves.
RISKY_EXT = {".scr", ".vbs", ".vbe", ".jse", ".wsf", ".wsh", ".hta", ".lnk", ".reg", ".chm", ".cpl", ".inf", ".url"}
MACRO_EXT = {".docm", ".xlsm", ".pptm", ".xlam", ".dotm", ".xltm", ".ppam", ".potm", ".sldm"}
OOXML_EXT = {".docx", ".xlsx", ".pptx", ".dotx", ".xltx", ".potx"}
OLE_EXT = {".doc", ".xls", ".ppt", ".dot", ".xla", ".pps", ".pot"}
ARCHIVE_EXT = {".zip", ".rar", ".7z", ".tar", ".gz", ".cab", ".tgz", ".xz", ".bz2", ".zst"}
BENIGN_LOOKING = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt", ".rtf", ".csv", ".jpg",
                  ".jpeg", ".png", ".gif", ".webp", ".bmp", ".svg", ".mp3", ".mp4", ".mov", ".wav", ".zip",
                  ".odt", ".ods", ".md", ".html", ".htm"}
EXEC_MIMES = {
    "application/x-msdownload", "application/x-dosexec", "application/x-msdos-program",
    "application/vnd.microsoft.portable-executable", "application/x-executable", "application/x-sh",
    "application/x-bat", "application/java-archive", "application/x-apple-diskimage",
    "application/vnd.android.package-archive", "application/x-msi", "application/hta",
    "application/x-ms-installer",
}
DOUBLE_EXT = re.compile(
    r"\.(pdf|docx?|xlsx?|pptx?|txt|rtf|jpe?g|png|gif|mp3|mp4|zip|csv)\s*\."
    r"(exe|scr|bat|cmd|com|js|vbs|ps1|lnk|jar|msi|hta)$"
)
BIDI_CHARS = "\u202e\u202d\u200e\u200f\u2066\u2067"

LABELS = {
    ".msi": "Windows installer", ".msix": "Windows app package", ".msixbundle": "Windows app package",
    ".appx": "Windows app package", ".appxbundle": "Windows app package", ".msp": "Windows patch",
    ".pkg": "macOS installer", ".mpkg": "macOS installer", ".dmg": "macOS disk image",
    ".deb": "Debian package", ".rpm": "RPM package", ".appimage": "AppImage", ".apk": "Android app",
    ".run": "Linux installer", ".dll": "Windows library", ".sys": "Windows driver", ".ocx": "Windows control",
    ".scr": "Screensaver program", ".lnk": "Shortcut", ".reg": "Registry file", ".jar": "Java program",
    ".chm": "Compiled help file", ".iso": "Disk image", ".img": "Disk image", ".vhd": "Virtual disk",
    ".vhdx": "Virtual disk", ".pdf": "PDF document", ".url": "Internet shortcut",
}

# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------


def F(engine, level, title, detail="", weak=False):
    """A finding. level: good | info | warn | bad. weak=True means 'a heuristic, not proof'."""
    d = {"engine": engine, "level": level, "title": title, "detail": detail}
    if weak:
        d["weak"] = True
    return d


def sha256_file(path, progress=None):
    h, size = hashlib.sha256(), 0
    total = os.path.getsize(path) or 1
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
            size += len(chunk)
            if progress:
                progress(size / total)
    return h.hexdigest(), size


def _run(cmd, timeout=60, env=None):
    kw = {}
    if os.name == "nt":
        kw["creationflags"] = 0x08000000  # CREATE_NO_WINDOW
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env,
                          encoding="utf-8", errors="replace", **kw)


def _read(path, n):
    try:
        with open(path, "rb") as f:
            return f.read(n)
    except OSError:
        return b""


def registrable_label(host):
    """'dl.google.com' -> 'google'; 'foo.co.uk' -> 'foo'."""
    p = (host or "").lower().strip(".").split(".")
    if len(p) >= 3 and p[-2] in {"co", "com", "org", "net", "ac", "gov", "edu"} and len(p[-1]) == 2:
        return p[-3]
    return p[-2] if len(p) >= 2 else (p[0] if p else "")


_LEGAL = {"llc", "inc", "ltd", "limited", "corp", "corporation", "co", "gmbh", "ag", "sa", "bv", "oy", "ab",
          "plc", "pty", "srl", "sarl", "kk", "company", "the", "software", "technologies", "technology",
          "foundation", "international", "systems", "labs", "group", "holdings", "and", "of"}


def publisher_matches_host(publisher, host):
    """True when the signer's name and the download site obviously belong together (Google LLC / dl.google.com)."""
    label = registrable_label(host)
    if not publisher or not label:
        return False
    words = [w for w in re.split(r"[^a-z0-9]+", publisher.lower()) if w and w not in _LEGAL]
    if not words:
        return False
    joined = "".join(words)
    return any(len(w) >= 3 and label == w for w in words) or (len(joined) >= 4 and label == joined)


def common_name(subject):
    """Pull the readable name out of a certificate subject like 'CN=Google LLC, O=Google LLC, C=US'."""
    if not subject:
        return ""
    m = re.search(r'(?:^|,\s*)CN\s*=\s*("([^"]+)"|[^,]+)', subject)
    if m:
        return (m.group(2) or m.group(1)).strip()
    m = re.search(r'(?:^|,\s*)O\s*=\s*("([^"]+)"|[^,]+)', subject)
    return ((m.group(2) or m.group(1)).strip() if m else subject.strip())


# --------------------------------------------------------------------------
# Identifying what a file really is
# --------------------------------------------------------------------------
def label_for_name(name):
    """What to call a file before it has been downloaded (extension only)."""
    ext = os.path.splitext(name.lower())[1]
    if ext in LABELS:
        return LABELS[ext]
    if ext in NATIVE_EXT:
        return "Windows program"
    if ext in SCRIPT_EXT:
        return "Script"
    if ext in MACRO_EXT:
        return "Office file with macros"
    if ext in OOXML_EXT or ext in OLE_EXT:
        return "Office document"
    if ext in ARCHIVE_EXT:
        return "Archive"
    if ext in {".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".svg", ".heic"}:
        return "Image"
    if ext in {".mp3", ".wav", ".flac", ".m4a", ".mp4", ".mov", ".mkv", ".webm", ".avi"}:
        return "Audio or video"
    return "File"


def sniff(path):
    """Identify content by magic bytes. Returns pe | elf | macho | script | ole | zip | pdf | rar | 7z | gzip | None."""
    head = _read(path, 4096)
    if head[:2] == b"MZ":
        off = int.from_bytes(head[0x3C:0x40], "little") if len(head) >= 0x40 else 0
        if off and off + 4 <= len(head) and head[off:off + 4] == b"PE\0\0":
            return "pe"
        if off and off > len(head):
            try:
                with open(path, "rb") as f:
                    f.seek(off)
                    if f.read(4) == b"PE\0\0":
                        return "pe"
            except OSError:
                pass
        return "dos"
    if head[:4] == b"\x7fELF":
        return "elf"
    if head[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe"):
        return "macho"
    if head[:4] == b"\xca\xfe\xba\xbe":
        return "macho" if int.from_bytes(head[4:8], "big") < 45 else "javaclass"
    if head[:2] == b"#!":
        return "script"
    if head[:8] == b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1":
        return "ole"
    if head[:4] in (b"PK\x03\x04", b"PK\x05\x06"):
        return "zip"
    if head[:4] == b"%PDF":
        return "pdf"
    if head[:4] == b"Rar!":
        return "rar"
    if head[:6] == b"7z\xbc\xaf\x27\x1c":
        return "7z"
    if head[:2] == b"\x1f\x8b":
        return "gzip"
    return None


def classify(path, name):
    """What is this file, and can it run code? Returns {kind, label, runs_code, sniffed}."""
    ext = os.path.splitext(name.lower())[1]
    s = sniff(path)
    label, runs, kind = LABELS.get(ext, "File"), False, "file"
    if s in ("pe", "dos"):
        kind, runs = "program", True
        label = LABELS[ext] if ext in (NATIVE_EXT | INSTALLER_EXT) and ext in LABELS else "Windows program"
        if pefile and s == "pe" and ext not in LABELS:
            try:
                pe = pefile.PE(str(path), fast_load=True)
                label = "Windows library" if pe.is_dll() else "Windows program"
                pe.close()
            except Exception:
                pass
    elif s == "elf":
        kind, runs, label = "program", True, "Linux program"
    elif s == "macho":
        kind, runs, label = "program", True, "macOS program"
    elif s == "javaclass":
        kind, runs, label = "program", True, "Java class"
    elif s == "script" or ext in SCRIPT_EXT:
        kind, runs = "script", True
        if label == "File":
            label = "Script"
    elif ext in NATIVE_EXT:
        kind, runs, label = "program", True, LABELS.get(ext, "Windows program")
    elif ext in INSTALLER_EXT:
        kind, runs = "installer", True
    elif ext in DISKIMG_EXT:
        kind, runs = "diskimage", True
    elif ext in MACRO_EXT:
        kind, label = "macro", "Office file with macros"
    elif ext in OOXML_EXT or ext in OLE_EXT:
        kind, label = "document", "Office document"
    elif ext in ARCHIVE_EXT or s in ("zip", "rar", "7z", "gzip"):
        kind, label = "archive", "Archive"
    elif ext == ".pdf" or s == "pdf":
        kind, label = "document", "PDF document"
    elif ext in {".jpg", ".jpeg", ".png", ".gif", ".webp", ".bmp", ".svg", ".heic"}:
        kind, label = "media", "Image"
    elif ext in {".mp3", ".wav", ".flac", ".m4a", ".mp4", ".mov", ".mkv", ".webm", ".avi"}:
        kind, label = "media", "Audio or video"
    elif ext in {".txt", ".md", ".csv", ".json", ".xml", ".log"}:
        kind, label = "text", "Text file"
    return {"kind": kind, "label": label, "runs_code": runs, "sniffed": s, "ext": ext}


# --------------------------------------------------------------------------
# Signature verification (who made this?)
# --------------------------------------------------------------------------
_PS = (
    "$ErrorActionPreference='Stop';[Console]::OutputEncoding=[System.Text.Encoding]::UTF8;"
    "try{$s=Get-AuthenticodeSignature -LiteralPath $env:SHIELD_SCAN_FILE;"
    "$o=[ordered]@{status=[string]$s.Status;message=[string]$s.StatusMessage;subject=$null;issuer=$null;notAfter=$null;timestamped=$false};"
    "if($s.SignerCertificate){$o.subject=$s.SignerCertificate.Subject;$o.issuer=$s.SignerCertificate.Issuer;$o.notAfter=$s.SignerCertificate.NotAfter.ToString('o')};"
    "if($s.TimeStamperCertificate){$o.timestamped=$true};$o|ConvertTo-Json -Compress}"
    "catch{@{status='Error';message=$_.Exception.Message}|ConvertTo-Json -Compress}"
)


def parse_authenticode(raw):
    """Turn Get-AuthenticodeSignature's JSON into our signature dict (kept separate so it can be tested anywhere)."""
    data = json.loads(raw)
    st = (data.get("status") or "").lower()
    publisher = common_name(data.get("subject") or "")
    sig = {"method": "Windows Authenticode", "publisher": publisher, "message": data.get("message") or "",
           "issuer": common_name(data.get("issuer") or "")}
    if st == "valid":
        sig["status"] = "valid"
    elif st == "notsigned":
        sig["status"] = "unsigned"
    elif st == "hashmismatch":
        sig["status"] = "tampered"
    elif st == "nottrusted":
        sig["status"] = "untrusted"
    elif st in ("notsupportedfileformat", "incompatible"):
        sig["status"] = "unsupported"
    else:
        sig["status"] = "unknown"
    return sig


def _sig_windows(path):
    env = dict(os.environ, SHIELD_SCAN_FILE=str(path))
    for exe in ("powershell.exe", "pwsh.exe"):
        if not shutil.which(exe):
            continue
        try:
            r = _run([exe, "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", _PS],
                     timeout=45, env=env)
            lines = [ln for ln in r.stdout.splitlines() if ln.strip().startswith("{")]
            if lines:
                return parse_authenticode(lines[-1])
        except Exception:
            continue
    return {"status": "unknown", "method": "Windows Authenticode", "publisher": "",
            "message": "PowerShell was not available to verify the signature."}


def _sig_macos(path):
    if not Path("/usr/bin/codesign").exists():
        return {"status": "unknown", "method": "macOS codesign", "publisher": "", "message": ""}
    ext = os.path.splitext(str(path).lower())[1]
    if ext in (".pkg", ".mpkg") and Path("/usr/sbin/pkgutil").exists():
        r = _run(["/usr/sbin/pkgutil", "--check-signature", str(path)], timeout=40)
        text = r.stdout + r.stderr
        if "no signature" in text.lower():
            return {"status": "unsigned", "method": "macOS pkgutil", "publisher": "", "message": ""}
        m = re.search(r"^\s*1\.\s*(?:Developer ID Installer:\s*)?(.+?)(?:\s*\([A-Z0-9]{10}\))?\s*$", text, re.M)
        ok = r.returncode == 0 and "signed" in text.lower()
        return {"status": "valid" if ok else "untrusted", "method": "macOS pkgutil",
                "publisher": m.group(1).strip() if m else "", "message": ""}
    r = _run(["/usr/bin/codesign", "--verify", "--strict", "--verbose=1", str(path)], timeout=60)
    text = (r.stdout + r.stderr).lower()
    if r.returncode == 0:
        info = _run(["/usr/bin/codesign", "-dv", "--verbose=2", str(path)], timeout=40)
        m = re.search(r"Authority=(?:Developer ID Application:\s*)?(.+?)(?:\s*\([A-Z0-9]{10}\))?\s*$",
                      info.stdout + info.stderr, re.M)
        return {"status": "valid", "method": "macOS codesign", "publisher": m.group(1).strip() if m else "", "message": ""}
    if "not signed at all" in text:
        return {"status": "unsigned", "method": "macOS codesign", "publisher": "", "message": ""}
    return {"status": "tampered" if "modified" in text or "invalid" in text else "untrusted",
            "method": "macOS codesign", "publisher": "", "message": (r.stderr or "")[:200]}


def check_signature(path, kind, sniffed):
    """Ask the operating system whether this file carries a valid publisher signature."""
    try:
        if sys.platform == "win32" and (sniffed in ("pe", "dos") or kind in ("installer",)):
            return _sig_windows(path)
        if sys.platform == "darwin" and (sniffed == "macho" or kind == "installer"):
            return _sig_macos(path)
    except Exception as e:
        return {"status": "unknown", "method": "", "publisher": "", "message": str(e)[:200]}
    if sniffed == "pe" and pefile:
        try:
            pe = pefile.PE(str(path), fast_load=True)
            size = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]].Size
            pe.close()
            if size:
                return {"status": "unverified", "method": "", "publisher": "",
                        "message": "This file carries a signature, but this operating system cannot verify it."}
            return {"status": "unsigned", "method": "", "publisher": "", "message": ""}
        except Exception:
            pass
    return {"status": "unsupported", "method": "", "publisher": "", "message": ""}


# --------------------------------------------------------------------------
# Built-in static checks (always on, pure Python)
# --------------------------------------------------------------------------
def _entropy(data):
    if not data:
        return 0.0
    counts = [0] * 256
    for b in data:
        counts[b] += 1
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in counts if c)


def _pe_checks(path, signed_hint):
    out = []
    if not pefile:
        return out
    try:
        if os.path.getsize(path) > 300 * 1024 * 1024:
            return out
        pe = pefile.PE(str(path), fast_load=True)
    except Exception:
        return [F("Shield", "warn", "The program file is malformed",
                  "The header doesn't follow the Windows program format. Damaged downloads look like this, and so do "
                  "programs built to confuse scanners.", weak=True)]
    try:
        names = [s.Name.rstrip(b"\0").decode("latin-1", "replace") for s in pe.sections]
        packers = {".upx": "UPX", "upx0": "UPX", ".aspack": "ASPack", ".themida": "Themida", ".vmp0": "VMProtect",
                   ".petite": "Petite", ".mpress": "MPRESS"}
        for n in names:
            p = packers.get(n.lower())
            if p:
                out.append(F("Shield", "info", f"Packed with {p}",
                             "Packing compresses a program. Legitimate software does it, and so does malware.", weak=True))
                break
        sec_size = pe.OPTIONAL_HEADER.DATA_DIRECTORY[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"]].Size
        hot = [s for s in pe.sections if (s.Characteristics & 0x20000000) and s.SizeOfRawData > 8192
               and _entropy(s.get_data()[:1 << 20]) > 7.3]
        if hot and not sec_size and not signed_hint:
            pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"]])
            n_imports = sum(len(e.imports) for e in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []))
            if n_imports < 12:
                out.append(F("Shield", "warn", "Looks packed or encrypted",
                             "The code is high-entropy and imports almost nothing, and the program is unsigned. "
                             "That pattern is typical of packed malware, though some legitimate tools do it too.", weak=True))
    except Exception:
        pass
    finally:
        try:
            pe.close()
        except Exception:
            pass
    return out


def _archive_checks(path, ext, sniffed):
    out = []
    try:
        if sniffed == "zip" or ext == ".zip":
            with zipfile.ZipFile(path) as z:
                infos = z.infolist()[:20000]
                names = [i.filename for i in infos]
                if any(i.flag_bits & 0x1 for i in infos):
                    out.append(F("Shield", "warn", "Password-protected archive",
                                 "Scanners can't look inside it. Malware is often shipped this way, and so are many "
                                 "ordinary files, so check where it came from.", weak=True))
                comp = sum(i.compress_size for i in infos) or 1
                unc = sum(i.file_size for i in infos)
                if unc > 4 * 1024 ** 3 or (unc / comp > 1000 and unc > 100 * 1024 ** 2):
                    out.append(F("Shield", "warn", "Unusually large when unpacked",
                                 f"About {unc / 1024 ** 3:.1f} GB once unpacked from {comp / 1024 ** 2:.1f} MB. "
                                 "Archives like this can be built to overwhelm a computer.", weak=True))
                dbl = [n for n in names if DOUBLE_EXT.search(os.path.basename(n).lower())]
                if dbl:
                    out.append(F("Shield", "bad", "Contains a disguised program", f"{os.path.basename(dbl[0])} looks like a document but is a program."))
                progs = [n for n in names if os.path.splitext(n.lower())[1] in (NATIVE_EXT | SCRIPT_EXT) and not n.endswith("/")]
                if progs:
                    out.append(F("Shield", "info", f"Contains {len(progs)} program file{'s' if len(progs) != 1 else ''}",
                                 ", ".join(os.path.basename(p) for p in progs[:4]) + ("…" if len(progs) > 4 else "")))
        elif ext in (".tar", ".tgz", ".gz", ".xz", ".bz2") and tarfile.is_tarfile(path):
            with tarfile.open(path) as t:
                names = [m.name for i, m in zip(range(20000), t)]
            dbl = [n for n in names if DOUBLE_EXT.search(os.path.basename(n).lower())]
            if dbl:
                out.append(F("Shield", "bad", "Contains a disguised program", f"{os.path.basename(dbl[0])} looks like a document but is a program."))
    except (zipfile.BadZipFile, tarfile.TarError, OSError, RuntimeError):
        out.append(F("Shield", "warn", "The archive is damaged",
                     "It couldn't be opened. The download may be incomplete.", weak=True))
    return out


def _macro_checks(path, ext, sniffed):
    out = []
    if ext in MACRO_EXT:
        out.append(F("Shield", "warn", "Contains macros", "Macros can run programs when you open the file. Only enable them if you trust the sender.", weak=True))
    elif ext in OOXML_EXT and sniffed == "zip":
        try:
            with zipfile.ZipFile(path) as z:
                if any(n.lower().endswith("vbaproject.bin") for n in z.namelist()):
                    out.append(F("Shield", "bad", "Hidden macros", f"The name says {ext} (no macros), but the file contains a macro project. That mismatch is a known trick."))
        except Exception:
            pass
    elif ext in OLE_EXT and sniffed == "ole":
        blob = _read(path, 8 * 1024 * 1024)
        if "_VBA_PROJECT".encode("utf-16-le") in blob:
            out.append(F("Shield", "warn", "Contains macros", "Macros can run programs when you open the file. Only enable them if you trust the sender.", weak=True))
    return out


def inspect_file(path, name):
    """Built-in checks that need no outside tools. Returns (classification, findings)."""
    cls = classify(path, name)
    ext, s, f = cls["ext"], cls["sniffed"], []
    if any(c in name for c in BIDI_CHARS):
        f.append(F("Shield", "bad", "Hidden characters in the file name", "Direction-control characters are used to make a program's extension look harmless."))
    if DOUBLE_EXT.search(name.lower()):
        f.append(F("Shield", "bad", "Disguised as a document", "A double extension makes a program look like a document."))
    if s in ("pe", "dos", "elf", "macho", "javaclass") and ext not in (NATIVE_EXT | INSTALLER_EXT | SCRIPT_EXT):
        if ext in BENIGN_LOOKING:
            f.append(F("Shield", "bad", f"A program pretending to be a {ext} file",
                       f"The contents are a {cls['label']}, but the name says {ext}. Disguising programs this way is a classic malware move."))
        elif ext not in ("", ".bin", ".run", ".out", ".so", ".dylib", ".appimage", ".tmp", ".part"):
            f.append(F("Shield", "warn", f"Unexpected file name for a {cls['label']}",
                       f"The name ends in {ext}, which isn't normally used for programs.", weak=True))
    if ext in RISKY_EXT:
        f.append(F("Shield", "warn", f"{cls['label']} files are rarely downloaded on purpose",
                   "This type is mostly used by installers run by IT teams, and by malware.", weak=True))
    if s == "pe":
        f += _pe_checks(path, False)
    f += _archive_checks(path, ext, s)
    f += _macro_checks(path, ext, s)
    return cls, f


# --------------------------------------------------------------------------
# Scan engines
# --------------------------------------------------------------------------
class YaraEngine:
    """Community YARA rules via YARA-X (VirusTotal's rewrite of YARA). Works on Python 3.14, every OS, pip only."""
    key, name = "yara", "YARA rules"
    FORGE = "https://github.com/YARAHQ/yara-forge/releases/latest/download/yara-forge-rules-core.zip"

    def __init__(self, home):
        self.dir = Path(home) / "yara"
        self.dir.mkdir(parents=True, exist_ok=True)
        self._rules, self._sig, self._count, self._err = None, None, 0, ""

    def _files(self):
        return sorted(p for p in self.dir.iterdir() if p.suffix.lower() in (".yar", ".yara"))

    def status(self):
        if not yara_x:
            return {"key": self.key, "name": self.name, "available": False,
                    "detail": "Not installed. Run: pip install yara-x"}
        files = self._files()
        if not files:
            return {"key": self.key, "name": self.name, "available": False, "detail": "No rules yet. Download the community rules."}
        total = 0
        for p in files:
            try:
                total += len(re.findall(r"^\s*(?:(?:private|global)\s+)*rule\s+\w+", p.read_text("utf-8", "ignore"), re.M))
            except OSError:
                pass
        stamp = ""
        try:
            meta = json.loads((self.dir / ".updated.json").read_text())
            stamp = time.strftime("%b %d, %Y", time.localtime(meta["ts"]))
        except Exception:
            pass
        return {"key": self.key, "name": self.name, "available": True,
                "detail": f"{total:,} rules" + (f", updated {stamp}" if stamp else ""), "count": total, "updated": stamp}

    def _load(self):
        files = self._files()
        sig = tuple((p.name, p.stat().st_mtime_ns) for p in files)
        if self._rules is not None and sig == self._sig:
            return self._rules
        if not files:
            raise RuntimeError("no rules")
        sources = [(p.name, p.read_text("utf-8", "ignore")) for p in files]

        def add(c, n, src):
            try:
                c.add_source(src, origin=n)
            except TypeError:           # older yara-x releases have no origin argument
                c.add_source(src)
        try:
            c = yara_x.Compiler()
            for n, src in sources:
                add(c, n, src)
            rules = c.build()
        except Exception:
            # One broken file shouldn't switch the whole engine off: keep only files that compile alone.
            good = []
            for n, src in sources:
                try:
                    t = yara_x.Compiler()
                    add(t, n, src)
                    t.build()
                    good.append((n, src))
                except Exception:
                    continue
            if not good:
                raise
            c = yara_x.Compiler()
            for n, src in good:
                add(c, n, src)
            rules = c.build()
        self._rules, self._sig = rules, sig
        return rules

    def scan(self, path):
        if not yara_x:
            raise RuntimeError("yara-x is not installed")
        sc = yara_x.Scanner(self._load())
        if hasattr(sc, "set_timeout"):
            sc.set_timeout(60)
        out = []
        for m in sc.scan_file(str(path)).matching_rules:
            meta = dict(m.metadata)
            try:
                score = int(meta.get("score", 0))
            except (TypeError, ValueError):
                score = 0
            nice = re.sub(r"^[A-Z0-9]+_(?=[A-Z])", "", m.identifier).replace("_", " ")
            level = "bad" if score >= 75 else "warn" if score >= 50 else "info"
            out.append(F("YARA", level, nice, str(meta.get("description", "")), weak=True))
        out.sort(key=lambda f: {"bad": 0, "warn": 1, "info": 2}[f["level"]])
        return out[:6]

    def update(self, progress=None):
        """Download the YARA-Forge 'core' ruleset (user-initiated; one HTTPS request to GitHub)."""
        if not yara_x:
            raise RuntimeError("yara-x is not installed (pip install yara-x)")
        if progress:
            progress("Downloading rules")
        LIMIT = 80 * 1024 * 1024
        req = urllib.request.Request(self.FORGE, headers={"User-Agent": f"Shield-Browser/{VERSION}"})
        with urllib.request.build_opener(_TrustedRedirects).open(req, timeout=60) as r:
            data = r.read(LIMIT + 1)
        if len(data) > LIMIT:
            raise RuntimeError("The rules download was larger than expected, so it was ignored")
        z = zipfile.ZipFile(io.BytesIO(data))
        info = next((i for i in z.infolist() if i.filename.endswith(".yar")), None)
        if not info:
            raise RuntimeError("The download didn't contain a rules file")
        if info.file_size > 200 * 1024 * 1024:          # a zip bomb claims a small file and unpacks to a huge one
            raise RuntimeError("The rules file was unreasonably large, so it was ignored")
        with z.open(info) as f:
            raw = f.read(info.file_size + 1)
        if len(raw) > info.file_size:
            raise RuntimeError("The rules file didn't match its declared size, so it was ignored")
        text = raw.decode("utf-8", "replace")
        if progress:
            progress("Checking rules")
        c = yara_x.Compiler()
        c.add_source(text)
        c.build()  # raises if the rules don't compile; we only ever replace a working file with a working file
        # A tampered or broken release that is nearly empty would silently switch most detection off.
        count = len(re.findall(r"(?m)^\s*(?:(?:private|global)\s+)*rule\s+\w+", text))
        old = self.dir / "yara-forge-core.yar"
        if old.exists():
            prev = len(re.findall(r"(?m)^\s*(?:(?:private|global)\s+)*rule\s+\w+", old.read_text("utf-8", "ignore")))
            if prev >= 100 and count < prev // 2:
                raise RuntimeError(f"The new rules ({count}) are far fewer than the current ones ({prev}), so they were not installed")
        if count < 50:
            raise RuntimeError("The rules file contained almost no rules, so it was ignored")
        tmp = self.dir / "yara-forge-core.yar.part"
        tmp.write_text(text, encoding="utf-8")
        os.replace(tmp, self.dir / "yara-forge-core.yar")
        (self.dir / ".updated.json").write_text(json.dumps({"ts": time.time(), "source": self.FORGE}))
        self._rules = None
        return self.status()


class ClamEngine:
    """ClamAV via its command line scanner. Free, open source, Windows / macOS / Linux."""
    key, name = "clamav", "ClamAV"

    def __init__(self, home):
        self.home = Path(home)
        self.base = self.home / "clamav"
        self._exe = {}

    def _find(self, tool):
        if tool in self._exe:
            return self._exe[tool]
        exe = tool + (".exe" if os.name == "nt" else "")
        cands = [self.base / exe, self.base / "bin" / exe]
        found = shutil.which(exe)
        if found:
            cands.append(Path(found))
        pf = [os.environ.get("ProgramFiles"), os.environ.get("ProgramFiles(x86)"), os.environ.get("LOCALAPPDATA")]
        cands += [Path(p) / "ClamAV" / exe for p in pf if p]
        cands += [Path(p) / exe for p in ("/opt/homebrew/bin", "/usr/local/bin", "/usr/bin", "/opt/local/bin")]
        hit = next((str(c) for c in cands if c.is_file()), None)
        self._exe[tool] = hit
        return hit

    def _dbdir(self):
        d = self.base / "db"
        return d if d.is_dir() and any(d.glob("*.c[vl]d")) else None

    def status(self):
        exe = self._find("clamscan")
        if not exe:
            return {"key": self.key, "name": self.name, "available": False, "installed": False,
                    "detail": "Not installed. Optional: adds a large signature database."}
        cmd = [exe, "--version"] + ([f"--database={self._dbdir()}"] if self._dbdir() else [])
        try:
            v = _run(cmd, timeout=30).stdout.strip()
        except Exception as e:
            return {"key": self.key, "name": self.name, "available": False, "installed": True, "detail": f"Found, but it won't start: {e}"}
        m = re.match(r"ClamAV\s+([\d.]+\S*?)(?:/(\d+)/)?", v)
        if m and m.group(2):
            return {"key": self.key, "name": self.name, "available": True, "installed": True,
                    "detail": f"Version {m.group(1)}, signatures {m.group(2)}"}
        return {"key": self.key, "name": self.name, "available": False, "installed": True,
                "detail": "Installed, but has no signatures yet. Update signatures to enable it."}

    def scan(self, path):
        exe = self._find("clamscan")
        if not exe:
            raise RuntimeError("ClamAV is not installed")
        cmd = [exe, "--no-summary", "--infected", "--stdout", "--max-filesize=400M", "--max-scansize=1000M"]
        if self._dbdir():
            cmd.append(f"--database={self._dbdir()}")
        r = _run(cmd + [str(path)], timeout=600)
        if r.returncode == 0:
            return []
        if r.returncode == 1:
            out = []
            for line in r.stdout.splitlines():
                m = re.match(r"^.*?:\s*(.+?)\s+FOUND\s*$", line)
                if m:
                    out.append(F("ClamAV", "bad", m.group(1), "ClamAV matched a known malware signature."))
            return out or [F("ClamAV", "bad", "Malware signature matched", "")]
        raise RuntimeError((r.stderr or r.stdout).strip().splitlines()[-1][:160] if (r.stderr or r.stdout).strip() else "ClamAV failed")

    def update(self, progress=None):
        fresh = self._find("freshclam")
        if not fresh:
            raise RuntimeError("freshclam was not found. Install ClamAV first.")
        db = self.base / "db"
        db.mkdir(parents=True, exist_ok=True)
        conf = self.base / "freshclam.conf"
        conf.write_text(f"DatabaseDirectory {db}\nDatabaseMirror database.clamav.net\n", encoding="utf-8")
        if progress:
            progress("Downloading signatures")
        r = _run([fresh, f"--config-file={conf}", f"--datadir={db}"], timeout=1800)
        if r.returncode != 0:
            tail = (r.stderr or r.stdout).strip().splitlines()
            raise RuntimeError(tail[-1][:200] if tail else "freshclam failed")
        self._exe.pop("clamscan", None)
        return self.status()


class DefenderEngine:
    """Microsoft Defender through its own command line tool. Windows only, and only if it is switched on."""
    key, name = "defender", "Microsoft Defender"

    def _exe(self):
        if os.name != "nt":
            return None
        plat = Path(os.environ.get("ProgramData", r"C:\ProgramData")) / "Microsoft" / "Windows Defender" / "Platform"
        try:
            vers = sorted((p for p in plat.iterdir() if (p / "MpCmdRun.exe").is_file()), key=lambda p: p.name, reverse=True)
            if vers:
                return str(vers[0] / "MpCmdRun.exe")
        except OSError:
            pass
        old = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Windows Defender" / "MpCmdRun.exe"
        return str(old) if old.is_file() else None

    def status(self):
        if os.name != "nt":
            return {"key": self.key, "name": self.name, "available": False, "detail": "Windows only."}
        ok = bool(self._exe())
        return {"key": self.key, "name": self.name, "available": ok,
                "detail": "Ready" if ok else "Not found on this PC."}

    def scan(self, path):
        exe = self._exe()
        if not exe:
            raise RuntimeError("Defender is not available")
        r = _run([exe, "-Scan", "-ScanType", "3", "-File", str(path), "-DisableRemediation"], timeout=300)
        if r.returncode == 0:
            return []
        if r.returncode == 2:
            names = re.findall(r"^\s*Threat\s*:\s*(.+?)\s*$", r.stdout, re.M) or ["Threat detected"]
            return [F("Defender", "bad", n, "Microsoft Defender flagged this file.") for n in names[:4]]
        raise RuntimeError("Defender couldn't scan (another antivirus may be managing protection)")


# --------------------------------------------------------------------------
# Putting it together
# --------------------------------------------------------------------------
class ScanEngine:
    def __init__(self, home):
        self.yara, self.clam, self.defender = YaraEngine(home), ClamEngine(home), DefenderEngine()

    def engines_status(self):
        return [self.yara.status(), self.clam.status(), self.defender.status()]

    def scan(self, path, name, url="", mime="", progress=None, enabled=None):
        say = progress or (lambda stage, label: None)
        t0 = time.time()
        say("inspect", "Inspecting the file")
        cls, findings = inspect_file(path, name)

        say("signature", "Checking the publisher's signature")
        sig = {"status": "unsupported", "publisher": "", "method": "", "message": ""}
        if cls["runs_code"]:
            sig = check_signature(path, cls["kind"], cls["sniffed"])
        host = urllib.parse.urlparse(url).hostname or ""
        sig["matches_site"] = sig.get("status") == "valid" and publisher_matches_host(sig.get("publisher", ""), host)

        engines, ran_detector = [], False
        jobs = {"yara": self.yara, "clamav": self.clam, "defender": self.defender}
        runnable = {}
        for k, e in jobs.items():
            st = e.status()
            if enabled is not None and k not in enabled:
                engines.append({"key": k, "name": e.name, "state": "skipped", "detail": "Turned off in Settings"})
            elif st["available"]:
                runnable[k] = e
            else:
                engines.append({"key": k, "name": e.name, "state": "skipped", "detail": st["detail"]})
        if runnable:
            say("engines", "Scanning with " + ", ".join(jobs[k].name for k in runnable))
            with concurrent.futures.ThreadPoolExecutor(max_workers=len(runnable)) as ex:
                futs = {ex.submit(e.scan, path): k for k, e in runnable.items()}
                done = 0
                for fut in concurrent.futures.as_completed(futs):
                    k = futs[fut]
                    done += 1
                    if len(runnable) > 1:
                        say("engines", f"Scanning ({done} of {len(runnable)} scanners finished)")
                    try:
                        res = fut.result()
                        ran_detector = True
                        bad = [r for r in res if r["level"] == "bad"]
                        engines.append({"key": k, "name": jobs[k].name, "state": "found" if bad else "clean",
                                        "detail": bad[0]["title"] if bad else "Nothing found"})
                        findings += res
                    except Exception as err:
                        engines.append({"key": k, "name": jobs[k].name, "state": "error", "detail": str(err)[:180]})

        # A valid signature means a known publisher and an untouched file. Heuristics don't outrank that;
        # only real antivirus detections do (stolen certificates exist, but false positives on signed software are far more common).
        s = sig.get("status")
        if s == "valid":
            for f in findings:
                if f.get("weak") and f["level"] in ("warn", "bad"):
                    f["level"] = "info"
            who = sig.get("publisher") or "a verified publisher"
            where = " and it was downloaded from their own site" if sig.get("matches_site") else ""
            findings.insert(0, F("Signature", "good", f"Signed by {who}",
                                 f"The signature is valid and the file hasn't changed since it was signed{where}."))
        elif s == "tampered":
            findings.insert(0, F("Signature", "bad", "The signature doesn't match the file",
                                 "The file was changed after it was signed. It was either tampered with or damaged in transit."))
        elif s == "untrusted":
            who = f" by {sig['publisher']}" if sig.get("publisher") else ""
            findings.insert(0, F("Signature", "warn", f"Signed{who}, but the certificate isn't trusted",
                                 sig.get("message") or "The certificate may be self-signed, expired or revoked.", weak=True))
        elif s == "unsigned" and cls["runs_code"] and cls["kind"] in ("program", "installer"):
            findings.insert(0, F("Signature", "info", "Not signed",
                                 "There's no publisher signature, so there's no way to confirm who made it. Common for small open-source tools."))

        findings.sort(key=lambda f: {"bad": 0, "warn": 1, "good": 2, "info": 3}[f["level"]])
        av_hit = any(f["level"] == "bad" and f["engine"] in ("ClamAV", "Defender") for f in findings) or \
            any(f["level"] == "bad" and f["engine"] == "YARA" for f in findings)
        struct_bad = any(f["level"] == "bad" for f in findings)
        warns = [f for f in findings if f["level"] == "warn"]
        if av_hit:
            verdict = "malicious"
        elif struct_bad:
            verdict = "danger"
        elif warns:
            verdict = "caution"
        elif s == "valid":
            verdict = "trusted"
        elif cls["runs_code"]:
            verdict = "unverified"   # a program nobody vouches for, even if no scanner objected
        elif ran_detector:
            verdict = "clean"
        else:
            verdict = "checked"

        names = [e["name"] for e in engines if e["state"] in ("clean", "found")]
        head, text = _words(verdict, cls, sig, findings, names)
        say("done", "Finished")
        return {"verdict": verdict, "headline": head, "summary": text, "kind": cls["kind"], "kind_label": cls["label"],
                "signature": sig, "findings": findings, "engines": engines, "took": round(time.time() - t0, 1),
                "scanned_at": time.time(), "version": VERSION}


def _words(verdict, cls, sig, findings, scanners):
    kind = cls["label"].lower()
    ran = ", ".join(scanners[:-1]) + (" and " if len(scanners) > 1 else "") + scanners[-1] if scanners else ""
    top = next((f for f in findings if f["level"] in ("bad", "warn")), None)
    if verdict == "malicious":
        hit = next(f for f in findings if f["level"] == "bad" and f["engine"] in ("ClamAV", "Defender", "YARA"))
        return "Threat detected", f"{hit['engine']} flagged this file as {hit['title']}. Delete it."
    if verdict == "danger":
        return "Don't open this file", f"{top['title']}. {top['detail']}" if top else ""
    if verdict == "caution":
        if top:
            return "Check before you open it", f"{top['title']}. {top['detail']}".strip()
        return "Check before you open it", f"This {kind} needs a closer look before you run it."
    if verdict == "trusted":
        who = sig.get("publisher") or "a verified publisher"
        extra = f" {ran} found nothing." if ran else ""
        return f"Signed by {who}", "The signature is valid and the file is unchanged." + extra
    if verdict == "unverified":
        if sig.get("status") == "unverified":
            why = "It carries a signature, but this operating system can't verify it."
        else:
            why = "It isn't signed, so Shield can't confirm who made it."
        done = f" {ran} found nothing." if ran else " Only Shield's built-in checks ran, because no scanner is set up."
        return "Not verified", f"{why}{done} Look it up on VirusTotal before you run it."
    if verdict == "clean":
        return "No threats found", f"Checked with {ran}."
    return "No problems found", "Shield's built-in checks passed. Turn on a scanner in Settings for deeper checks."


# --------------------------------------------------------------------------
# VirusTotal (public API v3)
# --------------------------------------------------------------------------
class VTError(Exception):
    def __init__(self, message, kind="error", retry_after=0):
        super().__init__(message)
        self.kind, self.retry_after = kind, retry_after


class _TrustedRedirects(urllib.request.HTTPRedirectHandler):
    """Follow redirects only over HTTPS and only to GitHub's own download hosts (a release download is always
    redirected to one of them). Anything else is refused, so a hijacked link cannot send the rules update elsewhere."""
    HOSTS = ("github.com", "objects.githubusercontent.com", "release-assets.githubusercontent.com",
             "github-releases.githubusercontent.com")

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        u = urllib.parse.urlparse(newurl)
        if u.scheme != "https" or (u.hostname or "").lower() not in self.HOSTS:
            raise urllib.error.URLError("refused a redirect to an untrusted address")
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class _SameHostOnly(urllib.request.HTTPRedirectHandler):
    """Never follow redirects: the API key must not travel anywhere we didn't choose."""

    def redirect_request(self, *a, **k):
        return None


class _Multipart:
    """Streams a file as multipart/form-data without loading it all into memory."""

    def __init__(self, field, filename, path):
        self.boundary = "----shield" + secrets.token_hex(12)
        safe = re.sub(r'[^\w.\- ]', "_", filename) or "file"
        head = (f'--{self.boundary}\r\nContent-Disposition: form-data; name="{field}"; filename="{safe}"\r\n'
                f"Content-Type: application/octet-stream\r\n\r\n").encode()
        tail = f"\r\n--{self.boundary}--\r\n".encode()
        self.length = len(head) + os.path.getsize(path) + len(tail)
        self._parts = [io.BytesIO(head), open(path, "rb"), io.BytesIO(tail)]

    def read(self, n=-1):
        while self._parts:
            chunk = self._parts[0].read(n if n and n > 0 else -1)
            if chunk:
                return chunk
            p = self._parts.pop(0)
            if hasattr(p, "close"):
                p.close()
        return b""

    def close(self):
        for p in self._parts:
            p.close()


class VirusTotal:
    BASE = "https://www.virustotal.com/api/v3"
    GUI = "https://www.virustotal.com/gui/file/"
    DIRECT_LIMIT = 32 * 1024 * 1024
    MAX_UPLOAD = 650 * 1024 * 1024

    def __init__(self, key, base=None):
        self.key = key
        self.base = (base or self.BASE).rstrip("/")
        self.opener = urllib.request.build_opener(_SameHostOnly)

    # -- plumbing ----------------------------------------------------------
    def _call(self, method, url, data=None, headers=None, timeout=60):
        host = urllib.parse.urlparse(url).hostname or ""
        h = {"User-Agent": f"Shield-Browser/{VERSION}", "Accept": "application/json"}
        if host.endswith("virustotal.com") or host in ("127.0.0.1", "localhost"):
            h["x-apikey"] = self.key
        h.update(headers or {})
        req = urllib.request.Request(url, data=data, headers=h, method=method)
        try:
            with self.opener.open(req, timeout=timeout) as r:
                body = r.read()
                return json.loads(body) if body else {}
        except urllib.error.HTTPError as e:
            body = e.read()[:2000]
            try:
                msg = json.loads(body).get("error", {}).get("message", "")
            except Exception:
                msg = ""
            if e.code == 404:
                raise VTError("not found", "notfound")
            if e.code in (401, 403):
                raise VTError("VirusTotal rejected the API key" + (f" ({msg})" if msg else ""), "auth")
            if e.code == 429:
                ra = int(e.headers.get("Retry-After", "0") or 0)
                raise VTError("VirusTotal's rate limit was hit", "rate", ra)
            if e.code == 413:
                raise VTError("The file is too large for VirusTotal", "toolarge")
            raise VTError(msg or f"VirusTotal returned an error ({e.code})", "server")
        except (urllib.error.URLError, TimeoutError, OSError) as e:
            raise VTError("Couldn't reach VirusTotal. Check your connection.", "network") from e

    def _retry(self, fn, tries=4, cancel=None, on_wait=None):
        """The free API allows 4 requests a minute, so a 429 means 'wait', not 'fail'."""
        for i in range(tries):
            try:
                return fn()
            except VTError as e:
                if e.kind != "rate" or i == tries - 1:
                    raise
                wait = max(e.retry_after, 20)
                if on_wait:
                    on_wait(wait)
                for _ in range(int(wait * 2)):
                    if cancel and cancel.is_set():
                        raise VTError("Cancelled", "cancelled")
                    time.sleep(0.5)

    # -- API ---------------------------------------------------------------
    def lookup(self, sha256, **kw):
        """Existing report for this hash, or None if VirusTotal has never seen the file. Sends only the hash."""
        try:
            return self._retry(lambda: self._call("GET", f"{self.base}/files/{sha256}"), **kw).get("data", {})
        except VTError as e:
            if e.kind == "notfound":
                return None
            raise

    def upload(self, path, name, **kw):
        size = os.path.getsize(path)
        if size > self.MAX_UPLOAD:
            raise VTError("The file is over VirusTotal's 650 MB limit", "toolarge")

        def go():
            url = f"{self.base}/files"
            if size > self.DIRECT_LIMIT:
                url = self._call("GET", f"{self.base}/files/upload_url").get("data") or url
            body = _Multipart("file", name, path)
            try:
                return self._call("POST", url, data=body, timeout=900,
                                  headers={"Content-Type": f"multipart/form-data; boundary={body.boundary}",
                                           "Content-Length": str(body.length)})
            finally:
                body.close()
        return self._retry(go, **kw).get("data", {}).get("id")

    def analyse(self, sha256, **kw):
        """Ask for a fresh scan of a file VirusTotal already has (no upload needed)."""
        return self._retry(lambda: self._call("POST", f"{self.base}/files/{sha256}/analyse", data=b""), **kw).get("data", {}).get("id")

    def analysis(self, analysis_id, **kw):
        return self._retry(lambda: self._call("GET", f"{self.base}/analyses/{analysis_id}"), **kw).get("data", {})

    # -- results -----------------------------------------------------------
    @staticmethod
    def summarize(attrs, sha256):
        stats = attrs.get("last_analysis_stats") or attrs.get("stats") or {}
        results = attrs.get("last_analysis_results") or attrs.get("results") or {}
        mal, sus = int(stats.get("malicious", 0)), int(stats.get("suspicious", 0))
        total = mal + sus + int(stats.get("harmless", 0)) + int(stats.get("undetected", 0))
        flagged = [{"engine": v.get("engine_name") or k, "category": v.get("category"), "result": v.get("result") or ""}
                   for k, v in results.items() if v.get("category") in ("malicious", "suspicious")]
        flagged.sort(key=lambda r: (r["category"] != "malicious", r["engine"].lower()))
        return {"malicious": mal, "suspicious": sus, "total": total, "flagged": flagged[:30],
                "date": attrs.get("last_analysis_date") or attrs.get("date"), "link": VirusTotal.GUI + sha256,
                "name": (attrs.get("meaningful_name") or "")}

    def scan(self, path, name, sha256, allow_upload, progress, cancel=None, skip_lookup=False):
        """Hash lookup first. Uploads only if allowed. Returns a dict with state 'done' or 'needs_upload'.

        skip_lookup is for when the person has just been told VirusTotal doesn't know the file and chose to upload it:
        the free API allows four requests a minute, so repeating the lookup would waste one.
        """
        say = progress

        def wait_note(sec):
            say("waiting", f"VirusTotal asked us to slow down. Retrying in {sec}s")

        kw = {"cancel": cancel, "on_wait": wait_note}
        rep = None
        if not (skip_lookup and allow_upload):
            say("lookup", "Looking the file up on VirusTotal")
            rep = self.lookup(sha256, **kw)
        if rep and (rep.get("attributes") or {}).get("last_analysis_stats") and VirusTotal.summarize(rep["attributes"], sha256)["total"] > 0:
            s = VirusTotal.summarize(rep["attributes"], sha256)
            s.update(state="done", source="existing")
            return s
        if rep is not None:
            say("queued", "Asking VirusTotal to scan the file")
            aid = self.analyse(sha256, **kw)
        else:
            if not allow_upload:
                return {"state": "needs_upload", "size": os.path.getsize(path), "link": VirusTotal.GUI + sha256}
            say("uploading", "Uploading to VirusTotal")
            aid = self.upload(path, name, **kw)
        if not aid:
            raise VTError("VirusTotal didn't accept the file", "server")
        say("queued", "Waiting for the scan to start")
        started = time.time()
        interval = 20  # four requests a minute is the free limit; lookup + upload already used two
        while time.time() - started < 15 * 60:
            for _ in range(interval * 2):
                if cancel and cancel.is_set():
                    raise VTError("Cancelled", "cancelled")
                time.sleep(0.5)
            a = self.analysis(aid, **kw)
            attrs = a.get("attributes", {})
            st = attrs.get("status")
            if st == "completed":
                s = VirusTotal.summarize(attrs, sha256)
                s.update(state="done", source="fresh")
                s["date"] = s["date"] or int(time.time())
                return s
            say("scanning", "VirusTotal is scanning" if st == "in-progress" else "Waiting in VirusTotal's queue")
        raise VTError("VirusTotal is taking too long. Try again in a few minutes.", "timeout")
