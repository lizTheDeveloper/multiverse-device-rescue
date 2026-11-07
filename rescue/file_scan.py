"""Which files a malware scan looks at, and the small helpers every scanner shares.

The scanners (malware_file_scan with Apple's own YARA rules, clamav_scanner,
the quarantine action) look at the places malware usually lands, not the whole
disk: the Downloads folder, temporary and shared folders, each app's main
program, what background jobs start, and browser add-on folders.

Everything here only reads. Every walk is bounded: symbolic links are never
followed, each place has a cap on how many entries are looked at, and files
above a size cap are counted and skipped, never read.
"""

from __future__ import annotations

import hashlib
import json
import os
import plistlib
import re
import stat
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path

from rescue.runtime import content_file

# https://www.virustotal.com/gui/file/<sha256>: a lookup of the fingerprint
# only. Opening it uploads nothing.
VIRUSTOTAL_FILE_URL = "https://www.virustotal.com/gui/file/{sha256}"
SHA256_RE = re.compile(r"^[0-9a-f]{64}\Z")

# How deep a walk goes under each place, and how many entries it may look at.
MAX_DEPTH = 4
MAX_ENTRIES_PER_PLACE = 20000
# Scripts are plain text, so the "is it a program?" test can't use the first
# bytes: a script is a file with one of these endings, or marked runnable, up
# to this size (Apple's script rules all look at files under 1 MB).
SCRIPT_MAX_BYTES = 1024 * 1024
SCRIPT_SUFFIXES = frozenset({
    ".sh", ".bash", ".zsh", ".command", ".tool", ".py", ".pl", ".rb", ".js", ".jxa",
    ".scpt", ".applescript", ".scptd", ".ps1", ".vbs", ".bat", ".cmd", ".jse", ".wsf",
})
# The first bytes of a program: Mach-O (32/64-bit, both byte orders, and
# universal "fat" files), ELF, Windows PE, compiled AppleScript/JXA, and "#!".
_PROGRAM_MAGIC = (
    b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf", b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe",
    b"\xca\xfe\xba\xbe", b"\xbe\xba\xfe\xca", b"\xca\xfe\xba\xbf", b"\xbf\xba\xfe\xca",
    b"\x7fELF", b"MZ", b"FasdUAS", b"JsOsaDAS", b"#!",
)
_HEAD_BYTES = 8
# Endings that are never programs: not even their first bytes are read.
_NOT_PROGRAM_SUFFIXES = frozenset({
    ".png", ".jpg", ".jpeg", ".gif", ".webp", ".svg", ".ico", ".icns", ".heic", ".bmp", ".tiff",
    ".mp3", ".mp4", ".m4a", ".m4v", ".mov", ".wav", ".avi", ".mkv", ".webm", ".flac",
    ".pdf", ".txt", ".md", ".rtf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pages",
    ".numbers", ".key", ".csv", ".json", ".html", ".htm", ".css", ".woff", ".woff2", ".ttf",
    ".otf", ".map", ".xml", ".yaml", ".yml", ".log", ".lock", ".strings", ".nib", ".car",
})
# Where a script ending alone isn't enough: a browser add-on is mostly
# JavaScript that the browser runs, not the system, so only real programs
# (by their first bytes) are kept there.
_MAGIC_ONLY_PLACES = frozenset({"browser_add_ons"})
_WEB_CODE_SUFFIXES = frozenset({".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".wasm", ".riv"})
# Riskiest first: when a budget runs out, it runs out on apps from /Applications,
# which Gatekeeper and notarization already vetted when they were installed.
RISK_ORDER = ("background_jobs", "temporary", "shared", "downloads", "browser_add_ons", "apps")

# macOS: what System Integrity Protection guards, and Apple's own read-only
# system. Nothing here is ever quarantined, and a scan doesn't spend its
# budget on it.
_MAC_SYSTEM_PREFIXES = (
    "/System/", "/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/usr/lib/", "/usr/libexec/",
    "/usr/share/", "/usr/standalone/", "/Library/Apple/", "/private/var/db/", "/etc/", "/private/etc/",
)
_LINUX_SYSTEM_PREFIXES = (
    "/bin/", "/sbin/", "/usr/bin/", "/usr/sbin/", "/usr/lib/", "/usr/lib64/", "/usr/libexec/",
    "/lib/", "/lib64/", "/boot/", "/proc/", "/sys/", "/dev/", "/etc/",
)
_WINDOWS_SYSTEM_PREFIXES = ("c:\\windows\\",)
# chflags: SF_RESTRICTED is the flag System Integrity Protection sets on what it
# guards; the immutable flags mean "nobody may move this".
SF_RESTRICTED = 0x00080000
_IMMUTABLE = getattr(stat, "SF_IMMUTABLE", 0x00020000) | getattr(stat, "UF_IMMUTABLE", 0x00000002)


@dataclass(frozen=True)
class Target:
    path: str
    size: int
    # Which place it was found in: "downloads", "apps", "background_jobs",
    # "temporary", "shared", "browser_add_ons".
    place: str
    # The file listed (0 = not recorded). Reading it later checks it's still
    # this very file, so a name swapped in the meantime is never read or blamed.
    ino: int = 0
    dev: int = 0
    mtime_ns: int = 0


@dataclass
class TargetSet:
    targets: list[Target] = field(default_factory=list)
    # Files skipped for being larger than the per-file cap.
    too_large: int = 0
    # Places that exist but couldn't be read (macOS asks permission for some).
    unreadable_places: list[str] = field(default_factory=list)
    # Places whose walk stopped at MAX_ENTRIES_PER_PLACE.
    capped_places: list[str] = field(default_factory=list)
    # Files that weren't programs or scripts (only counted when programs_only).
    not_programs: int = 0
    # Names with a control character (a line break, say) are never listed:
    # they could pass for a different file in a list of names.
    odd_names: int = 0
    # The listing itself ran out of time: some places weren't looked at.
    listing_stopped: bool = False
    seconds: float = 0.0

    @property
    def total_bytes(self) -> int:
        return sum(t.size for t in self.targets)


def _platform() -> str:
    return sys.platform if sys.platform in ("darwin", "win32") else "linux"


def virustotal_url(sha256: str) -> str | None:
    """VirusTotal's page for one fingerprint, or None if it isn't a sha256."""
    if not isinstance(sha256, str) or not SHA256_RE.match(sha256):
        return None
    return VIRUSTOTAL_FILE_URL.format(sha256=sha256)


def sha256_file(path: str | os.PathLike, chunk: int = 1024 * 1024) -> str:
    """The file's sha256, read in pieces so a large file never sits in memory."""
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        while True:
            block = fh.read(chunk)
            if not block:
                break
            digest.update(block)
    return digest.hexdigest()


def has_control_character(text: str) -> bool:
    return any(ord(c) < 32 or ord(c) == 127 for c in str(text))


_READ_FLAGS = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0) | getattr(os, "O_BINARY", 0)


def _open_target(target: Target, max_bytes: int | None = None) -> int | None:
    """A descriptor for the very file that was listed, or None.

    Opened without following a link; it must still be a regular file with the
    inode, size and modification time it had when listed, and no larger than
    `max_bytes`.
    """
    try:
        fd = os.open(target.path, _READ_FLAGS)
    except OSError:
        return None
    try:
        st = os.fstat(fd)
        # Linux hands a freed inode number straight to the next new file, so a
        # swapped-in file can have the old one: size and change time too.
        same = not target.ino or ((st.st_ino, st.st_dev, st.st_size, st.st_mtime_ns)
                                  == (target.ino, target.dev, target.size, target.mtime_ns))
        if stat.S_ISREG(st.st_mode) and same and (max_bytes is None or st.st_size <= max_bytes):
            return fd
    except OSError:
        pass
    os.close(fd)
    return None


def read_target(target: Target, max_bytes: int) -> bytes | None:
    """The listed file's contents, read from the same descriptor that was checked; None if it changed."""
    fd = _open_target(target, max_bytes)
    if fd is None:
        return None
    try:
        chunks, total = [], 0
        while total <= max_bytes:
            block = os.read(fd, 1024 * 1024)
            if not block:
                break
            chunks.append(block)
            total += len(block)
        return b"".join(chunks) if total <= max_bytes else None
    except OSError:
        return None
    finally:
        os.close(fd)


def sha256_target(target: Target) -> str | None:
    """sha256 of the very file that was listed, or None if it's gone or was swapped."""
    fd = _open_target(target)
    if fd is None:
        return None
    try:
        digest = hashlib.sha256()
        while True:
            block = os.read(fd, 1024 * 1024)
            if not block:
                break
            digest.update(block)
        return digest.hexdigest()
    except OSError:
        return None
    finally:
        os.close(fd)


def is_system_path(path: str, platform: str | None = None, resolve: bool = True) -> bool:
    """True for the operating system's own files (SIP on a Mac): never moved, not worth a scan.

    `resolve=False` skips following links, for paths a walk found without following any.
    """
    platform = platform or _platform()
    if platform == "win32":
        return str(path).lower().startswith(_WINDOWS_SYSTEM_PREFIXES)
    prefixes = _MAC_SYSTEM_PREFIXES if platform == "darwin" else _LINUX_SYSTEM_PREFIXES
    candidates = {str(path), os.path.realpath(path)} if resolve else {str(path)}
    return any(c.startswith(prefixes) for c in candidates)


def is_protected(path: str, platform: str | None = None) -> bool:
    """True when the system guards this file: a system path, or a SIP/immutable flag on it."""
    if is_system_path(path, platform):
        return True
    try:
        flags = getattr(os.lstat(path), "st_flags", 0)
    except OSError:
        return False
    return bool(flags & (SF_RESTRICTED | _IMMUTABLE))


def looks_like_program(path: str, size: int, mode: int, magic_only: bool = False) -> bool:
    """A program or a script, by its first bytes, its ending, or its runnable bit."""
    suffix = os.path.splitext(path)[1].lower()
    if suffix in _NOT_PROGRAM_SUFFIXES or (magic_only and suffix in _WEB_CODE_SUFFIXES):
        return False
    if not magic_only and size <= SCRIPT_MAX_BYTES and (suffix in SCRIPT_SUFFIXES or mode & 0o111):
        return True
    try:
        with open(path, "rb") as fh:
            head = fh.read(_HEAD_BYTES)
    except OSError:
        return False
    return head.startswith(_PROGRAM_MAGIC)


def places(platform: str, home: Path) -> list[tuple[str, Path, int]]:
    """(place, folder, depth) for every folder a scan walks, in order."""
    if platform == "darwin":
        support = home / "Library" / "Application Support"
        found = [
            ("downloads", home / "Downloads", MAX_DEPTH),
            ("temporary", Path("/private/tmp"), MAX_DEPTH),
            ("temporary", Path("/private/var/tmp"), MAX_DEPTH),
            ("shared", Path("/Users/Shared"), MAX_DEPTH),
        ]
        for browser in ("Google/Chrome", "BraveSoftware/Brave-Browser", "Microsoft Edge", "Chromium",
                        "Vivaldi", "Arc/User Data"):
            found += [("browser_add_ons", p / "Extensions", MAX_DEPTH + 2) for p in _profiles(support / browser)]
        found += [("browser_add_ons", p / "extensions", 2) for p in _profiles(support / "Firefox" / "Profiles")]
        return found
    if platform == "win32":
        local = Path(os.environ.get("LOCALAPPDATA") or home / "AppData" / "Local")
        roaming = Path(os.environ.get("APPDATA") or home / "AppData" / "Roaming")
        public = Path(os.environ.get("PUBLIC") or "C:\\Users\\Public")
        temp = Path(os.environ.get("TEMP") or local / "Temp")
        found = [
            ("downloads", home / "Downloads", MAX_DEPTH),
            ("temporary", temp, MAX_DEPTH),
            ("shared", public, MAX_DEPTH),
            ("background_jobs", roaming / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup", 1),
        ]
        for browser in ("Google/Chrome/User Data", "Microsoft/Edge/User Data", "BraveSoftware/Brave-Browser/User Data"):
            found += [("browser_add_ons", p / "Extensions", MAX_DEPTH + 2) for p in _profiles(local / browser)]
        found += [("browser_add_ons", p / "extensions", 2) for p in _profiles(roaming / "Mozilla" / "Firefox" / "Profiles")]
        return found
    config = Path(os.environ.get("XDG_CONFIG_HOME") or home / ".config")
    found = [
        ("downloads", home / "Downloads", MAX_DEPTH),
        ("temporary", Path("/tmp"), MAX_DEPTH),
        ("temporary", Path("/var/tmp"), MAX_DEPTH),
        ("temporary", Path("/dev/shm"), MAX_DEPTH),
        ("background_jobs", home / ".local" / "bin", 1),
    ]
    for browser in ("google-chrome", "chromium", "BraveSoftware/Brave-Browser", "microsoft-edge"):
        found += [("browser_add_ons", p / "Extensions", MAX_DEPTH + 2) for p in _profiles(config / browser)]
    found += [("browser_add_ons", p / "extensions", 2) for p in _profiles(home / ".mozilla" / "firefox")]
    return found


def _profiles(folder: Path) -> list[Path]:
    """The browser's profile folders ("Default", "Profile 1", "abcd.default-release")."""
    try:
        return sorted(p for p in folder.iterdir() if p.is_dir() and not p.is_symlink())
    except OSError:
        return []


def app_programs(home: Path) -> list[str]:
    """The main program of every app in /Applications and ~/Applications (one folder down too)."""
    out: list[str] = []
    for root in (Path("/Applications"), home / "Applications"):
        try:
            entries = sorted(root.iterdir())
        except OSError:
            continue
        for entry in entries:
            if entry.suffix == ".app":
                out += _bundle_program(entry)
            elif entry.is_dir() and not entry.is_symlink():
                try:
                    out += [p for sub in sorted(entry.iterdir()) if sub.suffix == ".app" for p in _bundle_program(sub)]
                except OSError:
                    continue
    return out


def _bundle_program(app: Path) -> list[str]:
    if app.is_symlink():
        return []
    try:
        with open(app / "Contents" / "Info.plist", "rb") as fh:
            info = plistlib.load(fh)
    except Exception:
        return []
    name = info.get("CFBundleExecutable") if isinstance(info, dict) else None
    if not isinstance(name, str) or not name or "/" in name:
        return []
    return [str(app / "Contents" / "MacOS" / name)]


def job_programs(home: Path) -> list[str]:
    """What each LaunchAgent/LaunchDaemon starts: its Program and every full path among its arguments."""
    out: list[str] = []
    for folder in (home / "Library" / "LaunchAgents", Path("/Library/LaunchAgents"), Path("/Library/LaunchDaemons")):
        try:
            plists = sorted(folder.glob("*.plist"))
        except OSError:
            continue
        for plist in plists[:500]:
            try:
                with open(plist, "rb") as fh:
                    data = plistlib.load(fh)
            except Exception:
                continue
            if not isinstance(data, dict):
                continue
            args = data.get("ProgramArguments")
            candidates = [data.get("Program")] + (list(args) if isinstance(args, list) else [])
            out += [c for c in candidates if isinstance(c, str) and c.startswith("/")]
    return out


def collect_targets(
    platform: str,
    home: Path,
    *,
    max_file_bytes: int,
    max_files: int,
    programs_only: bool,
    time_budget: float | None = None,
    clock=time.monotonic,
) -> TargetSet:
    """Every file in the places malware lives, within the caps, riskiest place first. Reads only.

    With `time_budget`, listing stops when it runs out (`listing_stopped`).
    """
    result = TargetSet()
    start = clock()
    seen: set[str] = set()
    by_place: dict[str, list[Target]] = {}
    count = [0]

    def add(path: str, place: str, named: bool = False) -> bool:
        """False once max_files is reached. `named`: the path came from a settings
        file (an app's or a job's), not from a walk, so it may go through links."""
        if count[0] >= max_files:
            return False
        if has_control_character(path):
            result.odd_names += 1
            return True
        if time_budget is not None and clock() - start >= time_budget:
            result.listing_stopped = True
            return False
        try:
            st = os.lstat(path) if not named else os.stat(path)
        except OSError:
            return True
        if not stat.S_ISREG(st.st_mode):
            return True
        if named:
            path = os.path.realpath(path)
        if is_system_path(path, platform, resolve=False):
            return True
        if st.st_size > max_file_bytes:
            result.too_large += 1
            return True
        if st.st_size == 0:
            return True
        if programs_only and not looks_like_program(path, st.st_size, st.st_mode, place in _MAGIC_ONLY_PLACES):
            result.not_programs += 1
            return True
        key = os.path.normcase(path)
        if key in seen:
            return True
        seen.add(key)
        by_place.setdefault(place, []).append(Target(path=path, size=st.st_size, place=place,
                                                       ino=st.st_ino, dev=st.st_dev, mtime_ns=st.st_mtime_ns))
        count[0] += 1
        return True

    def collect() -> None:
        if platform == "darwin":
            for path in job_programs(home):
                if not add(path, "background_jobs", named=True):
                    return
        for place, folder, depth in places(platform, home):
            if not _walk(folder, depth, lambda p, pl=place: add(p, pl), result, place):
                return
        if platform == "darwin":
            for path in app_programs(home):
                if not add(path, "apps", named=True):
                    return

    collect()
    result.seconds = round(clock() - start, 2)
    for place in RISK_ORDER:
        result.targets += by_place.pop(place, [])
    for rest in by_place.values():
        result.targets += rest
    return result


def _walk(folder: Path, depth: int, add, result: TargetSet, place: str) -> bool:
    """Walk one place without following links. False once the file cap is reached."""
    try:
        if folder.is_symlink() or not folder.is_dir():
            # /tmp on a Mac is a link to /private/tmp; the real folder is listed itself.
            return True
    except OSError:
        return True
    looked = 0
    stack = [(str(folder), 0)]
    first = True
    while stack:
        current, level = stack.pop()
        try:
            with os.scandir(current) as entries:
                listed = sorted(entries, key=lambda e: e.name)
        except OSError:
            if first:
                result.unreadable_places.append(str(folder))
            first = False
            continue
        first = False
        for entry in listed:
            looked += 1
            if has_control_character(entry.name):
                result.odd_names += 1
                continue
            if looked > MAX_ENTRIES_PER_PLACE:
                result.capped_places.append(str(folder))
                return True
            try:
                if entry.is_symlink():
                    continue
                if entry.is_dir(follow_symlinks=False):
                    if level < depth:
                        stack.append((entry.path, level + 1))
                    continue
            except OSError:
                continue
            if not add(entry.path):
                return False
    return True


# --- does a match look like monitoring software? ------------------------------

STALKERWARE_LIST = "modules/security/stalkerware_scan/data/known_stalkerware.json"
# Words in a scanner's verdict that mean "watches a person": Defender's
# MonitoringTool category, spyware, keyloggers, stalkerware.
_MONITORING_WORDS = re.compile(r"monitoringtool|stalk|keylog|spyware|(?<![a-z])spy(?![a-z])", re.I)
_known_products: list[tuple[re.Pattern, str]] | None = None


def _monitoring_products() -> list[tuple[re.Pattern, str]]:
    """(matcher, product name) for every product the stalkerware check knows."""
    global _known_products
    if _known_products is None:
        try:
            data = json.loads(content_file(STALKERWARE_LIST).read_text(encoding="utf-8"))
            entries = data.get("entries", []) if isinstance(data, dict) else []
        except (OSError, ValueError):
            entries = []
        # The same boundary rule as stalkerware_scan: "bark" never matches "barkeeper".
        _known_products = [
            (re.compile(rf"(?<![a-z0-9]){re.escape(e['pattern'].lower())}(?![a-z0-9])"), str(e.get("name") or e["pattern"]))
            for e in entries
            if isinstance(e, dict) and isinstance(e.get("pattern"), str) and e["pattern"]
        ]
    return _known_products


def monitoring_name(*texts: str) -> str | None:
    """The monitoring product or kind a match points at (its rule, verdict or file name), else None.

    A yes here only adds the safety note before removal: someone who set it up
    to watch this person may notice it's gone. A wrong yes costs one paragraph.
    """
    haystack = " ".join(t for t in texts if isinstance(t, str)).lower()
    if not haystack:
        return None
    for matcher, name in _monitoring_products():
        if matcher.search(haystack):
            return name
    found = _MONITORING_WORDS.search(haystack)
    return "monitoring software" if found else None
