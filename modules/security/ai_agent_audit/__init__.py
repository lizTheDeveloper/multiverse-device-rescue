"""ai_agent_audit: what AI tools on this computer can reach, using HackMyAgent.

HackMyAgent (OpenA2A, Apache-2.0) has a ``detect`` command that lists the AI
assistants on a machine (Claude Code, Cursor, Copilot, Claude Desktop, LM
Studio...), the MCP servers ("add-ons") each one is wired to, and AI settings
files that hold a credential. This module runs only that command:

    node <install>/node_modules/hackmyagent/dist/cli.js detect <home> --json --depth 0

with its usage reporting off (``OPENA2A_TELEMETRY=off``) and its own settings
folder pointed at a temp dir (``OPENA2A_HOME``) that is deleted afterwards, so
it writes nothing into the person's home folder.

HackMyAgent is not bundled. On first use it is fetched with ``npm ci`` from the
pinned lockfile in ``vendor/hackmyagent/`` (every package and its integrity
hash, no install scripts) into the user cache folder, then reused. Node.js is
never installed for the person: no Node.js means "couldn't check".
``rescue scan --no-downloads`` (or ``RESCUE_NO_DOWNLOADS=1``) turns the fetch
off; a copy already fetched still runs.

HackMyAgent's governance findings (SOUL.md, identity) and its remediation
lines (which name OpenA2A products) are not passed on. Credential values are
never read or repeated: HackMyAgent masks them, and only the variable *name*
is kept, when it looks like a name.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

from rescue.command import run
from rescue.models import (
    CheckResult,
    Finding,
    FixResult,
    Mode,
    Platform,
    RiskLevel,
    Severity,
    SystemProfile,
)
from rescue.module_base import ModuleBase
from rescue.runtime import bundled_root

HMA_VERSION = "0.33.2"
REGISTRY = "https://registry.npmjs.org/"
MIN_NODE_MAJOR = 18
FETCH_TIMEOUT = 180
DETECT_TIMEOUT = 60
VERSION_TIMEOUT = 15
# A fetch leftover this old belongs to a scan that was killed mid-download.
STALE_SECONDS = 3600

# sha256 of every file npm ci puts in the install folder, committed next to
# the lockfile and checked before every run.
MANIFEST_NAME = "tree.sha256"
# The only variables from Reclaim City's own environment that node and npm see
# (plus LC_* and the ones this module sets).
_ENV_ALLOWED = frozenset({
    "PATH", "HOME", "USERPROFILE", "SystemRoot", "SYSTEMROOT", "windir", "TEMP", "TMP",
    "TMPDIR", "LANG", "APPDATA", "LOCALAPPDATA", "HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY",
    "https_proxy", "http_proxy", "no_proxy",
    # Windows: how programs are found and where Program Files is; none loads code.
    "PATHEXT", "COMSPEC", "ProgramFiles", "ProgramFiles(x86)", "ProgramData", "SystemDrive",
})
_ENV_ALLOWED_UPPER = frozenset(name.upper() for name in _ENV_ALLOWED)
# The one link allowed in the install folder: the AI-runtime stub.
STUB_LINK = "node_modules/onnxruntime-node"
# Written by npm itself (its record of what it installed); nothing runs it.
NOT_HASHED = frozenset({"node_modules/.package-lock.json"})

# Stand-ins filled in at run time (shown as "…" in docs/commands.md).
_NPM_CACHE = object()
_NPM_RC = object()
_NPM_GLOBAL_RC = object()
_HOME = object()

# The three commands this module can run. argv[0] is replaced by the full
# path of the node/npm that was found, argv[1] of DETECT_ARGS by the cli.js
# inside the fetched copy. --userconfig/--globalconfig point at empty files
# so the person's .npmrc (and any npm login token in it) isn't used.
NODE_VERSION_ARGS = ["node", "--version"]
NPM_CI_ARGS = [
    "npm", "ci", "--ignore-scripts", "--no-bin-links", "--no-audit", "--no-fund",
    "--registry=https://registry.npmjs.org/", "--cache", _NPM_CACHE,
    "--userconfig", _NPM_RC, "--globalconfig", _NPM_GLOBAL_RC,
]
DETECT_ARGS = [
    "node", "node_modules/hackmyagent/dist/cli.js", "detect", _HOME, "--json", "--depth", "0",
    "--no-contribute",
]


_GET_NODE = (
    "If you'd like this check, install Node.js (the version marked LTS) from "
    "https://nodejs.org and run the checkup again. If you don't use AI coding "
    "tools, you can skip this."
)

# Why the check couldn't run, in plain words. Keys are data.reason.
_COULD_NOT_CHECK = {
    "node_missing": (
        "This check uses a free tool called HackMyAgent, which runs on Node.js, "
        "and we couldn't find Node.js on this computer. That isn't a problem in "
        "itself. " + _GET_NODE
    ),
    "node_failed": (
        "This check uses a free tool called HackMyAgent, which runs on Node.js. "
        "Node.js is on this computer, but it didn't start when we tried it, so "
        "the check couldn't run. Reinstalling Node.js from https://nodejs.org "
        "usually fixes this."
    ),
    "elevated": (
        "This check runs a downloaded tool (HackMyAgent) on Node.js. Reclaim City "
        "is running with administrator rights right now, and running a downloaded "
        "tool with those rights isn't safe, so we skipped it. Run the checkup the "
        "normal way, without sudo or \u201cRun as administrator\u201d, to include it."
    ),
    "hackmyagent_settings": (
        "HackMyAgent, the free tool this check uses, already has its own settings "
        "on this computer (~/.hackmyagent/config.json), so it has been used here "
        "before. Running it could change those settings, so we left it alone. To "
        "check your AI tools by hand, run your own copy of HackMyAgent the way you "
        "usually do, for example: hackmyagent detect ~ --depth 0 --no-contribute"
    ),
    "tampered": (
        "The saved copy of the AI-tools checker had changed since it was "
        "downloaded, so it wasn't run. We deleted it; the next checkup that's "
        "allowed to download fetches a fresh copy. If you see this again after "
        "that, mention it to "
        "whoever helps you with your computer."
    ),
    "download_mismatch": (
        "Reclaim City downloaded HackMyAgent, but the files didn't match the copy "
        "it expects, so it didn't use or keep them. Run the checkup again later; "
        "if it keeps happening, this copy of Reclaim City may need an update."
    ),
    "manifest_missing": (
        "This copy of Reclaim City is missing a file it needs for this check (the "
        "list of HackMyAgent's files), so the check didn't run. Reinstalling or "
        "updating Reclaim City should fix it."
    ),
    "stub_link_failed": (
        "Reclaim City couldn't finish setting up its working copy of HackMyAgent "
        "on this computer (one folder link couldn't be made), so the check didn't "
        "run. This is a problem on our side, not a sign that anything was changed."
    ),
    "copy_failed": (
        "Reclaim City couldn't make a working copy of HackMyAgent to run (the disk "
        "may be full), so the check didn't run. Run the checkup again after "
        "freeing some space."
    ),
    "node_too_old": (
        "This check uses a free tool called HackMyAgent, which needs Node.js "
        f"version {MIN_NODE_MAJOR} or newer. The Node.js on this computer is older. "
        + _GET_NODE
    ),
    "npm_missing": (
        "This check uses a free tool called HackMyAgent. Node.js is here, but its "
        "package tool (npm) isn't, so we couldn't download HackMyAgent. "
        "Reinstalling Node.js from https://nodejs.org puts npm back."
    ),
    "downloads_off": (
        "This check uses a free tool called HackMyAgent, which Reclaim City "
        "downloads the first time it's needed. Downloads are turned off for this "
        "scan, so it didn't run. Run the scan without --no-downloads to include it."
    ),
    "fetch_failed": (
        "This check uses a free tool called HackMyAgent, which Reclaim City "
        "downloads from the npm registry the first time it's needed. The download "
        "didn't finish, so the check didn't run. This usually means the internet "
        "connection dropped or the registry was busy. Run the checkup again later. "
        "On a work or school network that inspects secure connections, the "
        "download may never work; that network's IT team can help."
    ),
    "timed_out": (
        "HackMyAgent took too long to look at your AI tools, so we stopped it. "
        "Run the checkup again to try once more."
    ),
    "not_measured": (
        "HackMyAgent ran but said it couldn't look at your AI tools' settings on "
        "this computer."
    ),
    "integrity_failed": (
        "HackMyAgent stopped because its own self-check failed: its files don't "
        "match what was published. We didn't use its results. Run the checkup "
        "again. If this keeps happening, delete the folder named below; the next "
        "checkup downloads a fresh copy."
    ),
    "tool_failed": (
        "HackMyAgent stopped with an error before it finished, so we couldn't "
        "look at your AI tools' settings."
    ),
    "bad_output": (
        "HackMyAgent finished, but its answer wasn't in a form we could read, so "
        "we didn't use it."
    ),
}

# What an MCP server with each capability lets the AI tool do.
_CAPABILITY_WORDS = {
    "database": "read and change a database",
    "filesystem": "read and change files on this computer",
    "shell": "run commands on this computer",
    "exec": "run commands on this computer",
    "command": "run commands on this computer",
    "browser": "control a web browser",
    "network": "reach websites and online services",
}

# A variable name, never a value: letters, digits and underscores, and none
# of the prefixes real keys start with.
_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,63}$")
_SECRET_PREFIXES = ("ghp_", "gho_", "ghs_", "ghu_", "github_pat_", "xox", "AKIA", "ASIA",
                    "sk_live", "sk_test", "rk_live", "glpat")
# HackMyAgent's own "config" finding detail: `.claude/settings.json:3 — "NAME" = …`
_DETAIL_RE = re.compile(r"^(?P<file>[^:\n]+):(?P<line>\d+)\s+\S+\s+\"(?P<token>[^\"]*)\"")


def _safe_name(token: Any) -> str | None:
    if not isinstance(token, str) or not _NAME_RE.match(token):
        return None
    if token.startswith(_SECRET_PREFIXES):
        return None
    # A long unbroken run of letters and digits looks like a key, not a name.
    if any(len(part) >= 20 for part in token.split("_")):
        return None
    return token


_FILE_ATTRIBUTE_REPARSE_POINT = 0x400


def _is_link(path: Path) -> bool:
    """A symlink, or (on Windows) a junction or any other reparse point.

    os.path.isjunction only exists from Python 3.12, so the reparse-point
    attribute from lstat is checked too.
    """
    if path.is_symlink():
        return True
    is_junction = getattr(os.path, "isjunction", None)
    if is_junction is not None and is_junction(path):
        return True
    try:
        attributes = getattr(os.lstat(path), "st_file_attributes", 0) or 0
    except (OSError, ValueError):
        return False
    return bool(attributes & _FILE_ATTRIBUTE_REPARSE_POINT)


def _remove_tree(path: Path) -> None:
    """Delete a folder (or a link in its place) without following links."""
    try:
        if _is_link(path):
            try:
                os.unlink(path)
            except OSError:
                os.rmdir(path)
        elif path.exists():
            shutil.rmtree(path, ignore_errors=True)
    except OSError:
        pass


def _create_junction(target: str, link: str) -> None:
    import _winapi  # Windows only

    _winapi.CreateJunction(target, link)


def _lookup(name: str, dirs: list[str], platform: Platform) -> Path | None:
    """The first ``name`` in ``dirs``. Relative folders (and so the current one) are skipped."""
    exts = [".exe", ".cmd"] if platform == Platform.WIN32 and name == "npm" else (
        [".exe"] if platform == Platform.WIN32 else [""])
    for directory in dirs:
        if not directory or not os.path.isabs(directory):
            continue
        for ext in exts:
            candidate = Path(directory) / f"{name}{ext}"
            if candidate.is_file() and os.access(candidate, os.X_OK):
                return candidate
    return None


# Every working folder is made beside the saved copy, in the person's own cache
# folder, never in a shared temp folder: node looks for node_modules in each
# parent folder of the code it runs, and another account could plant one in /tmp.
_SCRATCH_PREFIXES = (".hackmyagent-", ".run-", ".npm-cache-", ".settings-")


def _scratch(parent: Path, prefix: str) -> Path:
    parent.mkdir(parents=True, exist_ok=True)
    return Path(tempfile.mkdtemp(prefix=prefix, dir=parent))


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b""):
            digest.update(chunk)
    return digest.hexdigest()


def tree_hashes(root: Path) -> tuple[dict[str, str], list[str], list[str]]:
    """Every file under ``root`` with its sha256, plus links and other odd entries.

    Links are listed, never followed. Paths are relative, with forward slashes.
    """
    files: dict[str, str] = {}
    links: list[str] = []
    odd: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        here = Path(dirpath)
        for name in list(dirnames):
            if _is_link(here / name):
                links.append((here / name).relative_to(root).as_posix())
                dirnames.remove(name)
        for name in filenames:
            path = here / name
            rel = path.relative_to(root).as_posix()
            if _is_link(path):
                links.append(rel)
            elif not stat.S_ISREG(path.lstat().st_mode):
                odd.append(rel)
            elif rel not in NOT_HASHED:
                files[rel] = _sha256(path)
    return files, sorted(links), sorted(odd)


def render_manifest(files: dict[str, str]) -> str:
    lines = [
        f"# HackMyAgent {HMA_VERSION}: sha256 of every file npm ci puts in the install folder.",
        "# Written by scripts/generate_hackmyagent_manifest.py. Do not edit by hand.",
    ]
    lines += [f"{digest}  {path}" for path, digest in sorted(files.items())]
    return "\n".join(lines) + "\n"


def read_manifest(path: Path) -> dict[str, str]:
    files: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        digest, _, rel = line.partition("  ")
        files[rel] = digest
    return files


def tree_problems(install: Path, expected: dict[str, str]) -> list[str]:
    """What differs between the install folder and the manifest. Empty means it matches."""
    if _is_link(install):
        return ["the install folder is a link"]
    if not install.is_dir():
        return ["the install folder is missing"]
    files, links, odd = tree_hashes(install)
    problems = [f"unexpected link: {link}" for link in links if link != STUB_LINK]
    if STUB_LINK in links:
        try:
            same = (install / STUB_LINK).resolve() == (install / "stub").resolve()
        except (OSError, RuntimeError):  # RuntimeError: a link loop, before Python 3.13
            same = False
        if not same:
            problems.append(f"{STUB_LINK} points somewhere else")
    problems += [f"unexpected entry: {entry}" for entry in odd]
    for rel, digest in files.items():
        if rel not in expected:
            problems.append(f"extra file: {rel}")
        elif expected[rel] != digest:
            problems.append(f"changed: {rel}")
    problems += [f"missing: {rel}" for rel in expected if rel not in files]
    return problems


class _DestinationError(Exception):
    """Writing the run copy failed (disk full and the like), as opposed to a bad source."""


def _open_no_follow_posix(name: str, dir_fd: int, directory: bool) -> int:
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    # O_NONBLOCK: opening a planted FIFO must not hang; fstat then rejects it.
    flags |= os.O_DIRECTORY if directory else os.O_NONBLOCK
    fd = os.open(name, flags, dir_fd=dir_fd)
    mode = os.fstat(fd).st_mode
    if not (stat.S_ISDIR(mode) if directory else stat.S_ISREG(mode)):
        os.close(fd)
        raise OSError(f"not a {'folder' if directory else 'file'}: {name}")
    return fd


def _open_checked_windows(path: Path, directory: bool) -> int | None:
    """Windows has neither O_NOFOLLOW nor dir_fd: lstat each step and compare after opening."""
    before = os.lstat(path)
    if _is_link(path) or not (stat.S_ISDIR(before.st_mode) if directory else stat.S_ISREG(before.st_mode)):
        raise OSError(f"not a plain {'folder' if directory else 'file'}: {path}")
    if directory:
        return None
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_BINARY", 0))
    after = os.fstat(fd)
    if (after.st_dev, after.st_ino) != (before.st_dev, before.st_ino) or not stat.S_ISREG(after.st_mode):
        os.close(fd)
        raise OSError(f"changed while opening: {path}")
    return fd


def _create_no_follow(parts: list[str], out_chain: list[tuple[str, int]], root_fd: int) -> int:
    """Create ``parts`` inside the run copy without following any link planted there.

    Folders are made 0700 and opened O_NOFOLLOW|O_DIRECTORY relative to the
    one before; the file is created O_EXCL|O_NOFOLLOW, 0600. ``out_chain``
    keeps the open folders along the current path.
    """
    keep = 0
    while keep < len(out_chain) and keep < len(parts) - 1 and out_chain[keep][0] == parts[keep]:
        keep += 1
    for _, open_fd in out_chain[keep:]:
        os.close(open_fd)
    del out_chain[keep:]
    cloexec = getattr(os, "O_CLOEXEC", 0)
    for part in parts[len(out_chain):-1]:
        parent_fd = out_chain[-1][1] if out_chain else root_fd
        try:
            os.mkdir(part, 0o700, dir_fd=parent_fd)
        except FileExistsError:
            pass
        out_chain.append((part, os.open(part, os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY | cloexec,
                                        dir_fd=parent_fd)))
    parent_fd = out_chain[-1][1] if out_chain else root_fd
    return os.open(parts[-1], os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | cloexec,
                   0o600, dir_fd=parent_fd)


def copy_from_manifest(install: Path, dest: Path, expected: dict[str, str], platform: Platform) -> bool:
    """Copy exactly the files the manifest names from ``install`` into ``dest``, hashing as it goes.

    No path component of the saved copy, or of the run copy being written, is
    ever followed if it is a link: on POSIX each step is opened with O_NOFOLLOW
    relative to the folder before it, so nothing outside the saved copy can be
    read and nothing outside ``dest`` can be written. Returns False when a file is
    missing, isn't a plain file, or doesn't match its hash. Raises
    _DestinationError when writing the copy fails.
    """
    windows = platform == Platform.WIN32 or not hasattr(os, "O_NOFOLLOW")
    chain: list[tuple[str, int]] = []  # open folders along the current path (POSIX)
    out_chain: list[tuple[str, int]] = []  # the same, in the run copy
    root_fd = None
    out_root_fd = None
    try:
        if not windows:
            root_fd = os.open(install, os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY
                              | getattr(os, "O_CLOEXEC", 0))
            try:
                out_root_fd = os.open(dest, os.O_RDONLY | os.O_NOFOLLOW | os.O_DIRECTORY
                                      | getattr(os, "O_CLOEXEC", 0))
            except OSError as exc:
                raise _DestinationError(str(exc)) from exc
        else:
            _open_checked_windows(install, directory=True)
        for rel in sorted(expected):
            parts = rel.split("/")
            if any(part in ("", ".", "..") for part in parts):
                return False
            if windows:
                current = install
                for part in parts[:-1]:
                    current = current / part
                    _open_checked_windows(current, directory=True)
                fd = _open_checked_windows(current / parts[-1], directory=False)
            else:
                keep = 0
                while keep < len(chain) and keep < len(parts) - 1 and chain[keep][0] == parts[keep]:
                    keep += 1
                for _, open_fd in chain[keep:]:
                    os.close(open_fd)
                del chain[keep:]
                for part in parts[len(chain):-1]:
                    parent_fd = chain[-1][1] if chain else root_fd
                    chain.append((part, _open_no_follow_posix(part, parent_fd, directory=True)))
                fd = _open_no_follow_posix(parts[-1], chain[-1][1] if chain else root_fd,
                                           directory=False)
            assert fd is not None
            digest = hashlib.sha256()
            try:
                try:
                    if windows:
                        target = dest.joinpath(*parts)
                        target.parent.mkdir(parents=True, exist_ok=True)
                        out = open(target, "xb")
                    else:
                        out = os.fdopen(_create_no_follow(parts, out_chain, out_root_fd), "wb")
                except OSError as exc:
                    raise _DestinationError(str(exc)) from exc
                with out:
                    while True:
                        chunk = os.read(fd, 1 << 20)
                        if not chunk:
                            break
                        digest.update(chunk)
                        try:
                            out.write(chunk)
                        except OSError as exc:
                            raise _DestinationError(str(exc)) from exc
            finally:
                os.close(fd)
            if digest.hexdigest() != expected[rel]:
                return False
        return True
    except OSError:
        return False
    finally:
        for _, open_fd in chain + out_chain:
            os.close(open_fd)
        for open_fd in (root_fd, out_root_fd):
            if open_fd is not None:
                os.close(open_fd)


def _matches(root: Path, expected: dict[str, str]) -> bool:
    """True when ``root`` matches the manifest. A file that can't be read counts as a mismatch."""
    try:
        return not tree_problems(root, expected)
    except OSError:
        return False


def _version_tuple(name: str) -> tuple[int, ...]:
    return tuple(int(n) for n in re.findall(r"\d+", name)[:3]) or (0,)


def user_cache_dir(platform: Platform | None = None) -> Path:
    """The per-user cache folder: ~/Library/Caches, $XDG_CACHE_HOME or ~/.cache, %LOCALAPPDATA%."""
    override = os.environ.get("RESCUE_CACHE_DIR")
    if override:
        return Path(override)
    platform = platform or Platform(sys.platform if sys.platform in ("darwin", "win32") else "linux")
    home = Path.home()
    if platform == Platform.DARWIN:
        return home / "Library" / "Caches"
    if platform == Platform.WIN32:
        local = os.environ.get("LOCALAPPDATA")
        return Path(local) if local else home / "AppData" / "Local"
    xdg = os.environ.get("XDG_CACHE_HOME")
    return Path(xdg) if xdg else home / ".cache"


class _ChangedDuringRun(Exception):
    """HackMyAgent's files changed while it ran: something else may have run in its place."""


class _CouldNotCheck(Exception):
    def __init__(self, reason: str, **data: Any):
        super().__init__(reason)
        self.reason = reason
        self.data = data


class Module(ModuleBase):
    name = "ai_agent_audit"
    category = "security"
    platforms = [Platform.DARWIN, Platform.LINUX, Platform.WIN32]
    risk_level = RiskLevel.SAFE
    priority = 60
    depends_on = []
    estimated_duration = "about a second; the first run also downloads about 51 MB"
    # The first run fetches (up to 180 s) and then runs detect (up to 60 s).
    check_timeout = VERSION_TIMEOUT + FETCH_TIMEOUT + DETECT_TIMEOUT + 15

    emits_codes = [
        "security.ai_agent_audit.credentials_in_ai_config",
        "security.ai_agent_audit.risky_mcp_server",
        "security.ai_agent_audit.ai_inventory",
        "security.ai_agent_audit.could_not_check",
        "security.ai_agent_audit.changed_during_run",
    ]

    # Seams for tests: the home folder to look at, the fixed places Node.js is
    # often installed (None = the real defaults), and the vendor files.
    home: Path | None = None
    system_node_dirs: list[Path] | None = None
    vendor_dir: Path | None = None
    elevated: bool | None = None  # None = ask the operating system
    _left_in_home: str | None = None

    # --- check ------------------------------------------------------------------

    def check(self, profile: SystemProfile) -> CheckResult:
        self._left_in_home = None
        try:
            doc = self._detect(profile.platform)
        except _CouldNotCheck as exc:
            findings = [self._could_not_check(exc)]
        except _ChangedDuringRun:
            findings = [self._changed_during_run_finding(profile.platform)]
        else:
            findings = self._findings(doc, self._install_dir(profile.platform), profile.platform)
        if self._left_in_home and findings:
            target = next((f for f in findings
                           if f.code == "security.ai_agent_audit.ai_inventory"), findings[0])
            target.data["left_in_home"] = self._left_in_home
            target.description += (
                f"\n\nHackMyAgent's start-up self-check added a line to {self._left_in_home}. "
                "Something else changed that file during the check, so we left it as it is."
            )
        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        # Every finding is about settings the person changes in their own AI
        # tools; nothing here is changed for them.
        return FixResult(module_name=self.name, actions=[])

    # --- running HackMyAgent --------------------------------------------------------

    def _home(self) -> Path:
        return Path(self.home) if self.home is not None else Path.home()

    def _install_dir(self, platform: Platform) -> Path:
        return user_cache_dir(platform) / "ReclaimCity" / f"hackmyagent-{HMA_VERSION}"

    def _vendor_dir(self) -> Path:
        return Path(self.vendor_dir) if self.vendor_dir else bundled_root() / "vendor" / "hackmyagent"

    def _is_elevated(self, platform: Platform) -> bool:
        if self.elevated is not None:
            return bool(self.elevated)
        if platform == Platform.WIN32:
            try:
                import ctypes

                return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
            except Exception:
                return False
        geteuid = getattr(os, "geteuid", None)
        return bool(geteuid is not None and geteuid() == 0)

    def _expected_tree(self) -> dict[str, str]:
        try:
            return read_manifest(self._vendor_dir() / MANIFEST_NAME)
        except OSError as exc:
            raise _CouldNotCheck("manifest_missing", detail=f"no {MANIFEST_NAME}: {exc}"[:200]) from exc

    def _detect(self, platform: Platform) -> dict:
        # A downloaded tool never runs with administrator rights: the copy and
        # node itself live in folders any program running as the person can change.
        if self._is_elevated(platform):
            raise _CouldNotCheck("elevated")
        # HackMyAgent moves (and rewrites) its own older settings when it starts.
        if (self._home() / ".hackmyagent" / "config.json").exists():
            raise _CouldNotCheck("hackmyagent_settings")

        install = self._install_dir(platform)
        expected = self._expected_tree()
        if install.parent.is_dir():
            self._clean_stale(install.parent)
        downloads_off = os.environ.get("RESCUE_NO_DOWNLOADS") == "1"
        usable = self._installed(install)
        if not usable and downloads_off:
            raise _CouldNotCheck("downloads_off")

        node = self._find_node(platform)
        if node is None:
            raise _CouldNotCheck("node_missing")
        version = run([str(node), *NODE_VERSION_ARGS[1:]], timeout=VERSION_TIMEOUT,
                      env=self._env(node))
        if not version.ok:
            raise _CouldNotCheck("node_failed")
        if _version_tuple(version.stdout.strip())[0] < MIN_NODE_MAJOR:
            raise _CouldNotCheck("node_too_old", node_version=version.stdout.strip()[:20])

        if not usable:
            self._fetch(node, install, platform, expected)
        # HackMyAgent runs from a fresh private copy that is checked right
        # before and again right after the run; a saved copy that changed is
        # deleted and fetched once more.
        run_dir = self._verified_copy(install, expected, platform)
        if run_dir is None:
            _remove_tree(install)
            if not usable or downloads_off:
                raise _CouldNotCheck("tampered")
            self._fetch(node, install, platform, expected)
            run_dir = self._verified_copy(install, expected, platform)
            if run_dir is None:
                _remove_tree(install)
                raise _CouldNotCheck("tampered")
        doc: dict | None = None
        failure: _CouldNotCheck | None = None
        changed_during_run = False
        try:
            try:
                doc = self._run_detect(node, run_dir, install)
            except _CouldNotCheck as exc:
                failure = exc
            finally:
                changed_during_run = not _matches(run_dir, expected)
        finally:
            _remove_tree(run_dir.parent)
            if changed_during_run:
                # Foreign code may have run: the results are not used, and the
                # saved copy goes too, so the next checkup downloads a fresh one.
                _remove_tree(install)
        if changed_during_run:
            raise _ChangedDuringRun()
        if failure is not None:
            raise failure
        assert doc is not None
        return doc

    def _verified_copy(self, install: Path, expected: dict[str, str], platform: Platform) -> Path | None:
        """Copy exactly the manifest's files from the saved copy into a new private folder.

        Every file is read without following links and hashed while it is
        copied. Returns the copy's folder, or None when the saved copy doesn't
        match the manifest.
        """
        if not self._installed(install) or _is_link(install):
            return None
        try:
            holder = _scratch(install.parent, ".run-")
        except OSError as exc:
            raise _CouldNotCheck("copy_failed", detail=str(exc)[:200]) from exc
        copy = holder / "hackmyagent"
        try:
            copy.mkdir()
            ok = copy_from_manifest(install, copy, expected, platform)
        except (OSError, _DestinationError) as exc:
            _remove_tree(holder)
            raise _CouldNotCheck("copy_failed", detail=str(exc)[:200]) from exc
        if not ok:
            _remove_tree(holder)
            return None
        try:
            (copy / "node_modules").mkdir(exist_ok=True)
            self._make_stub_link(copy, platform)
        except (OSError, _CouldNotCheck) as exc:
            _remove_tree(holder)
            if isinstance(exc, _CouldNotCheck):
                raise
            raise _CouldNotCheck("stub_link_failed", detail=str(exc)[:200]) from exc
        return copy

    @staticmethod
    def _installed(install: Path) -> bool:
        if _is_link(install):
            return True  # reported (and removed) by tree_problems
        pkg = install / "node_modules" / "hackmyagent"
        try:
            meta = json.loads((pkg / "package.json").read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return False
        return meta.get("version") == HMA_VERSION and (pkg / "dist" / "cli.js").is_file()

    def _env(self, node: Path, **extra: str) -> dict[str, str]:
        """The child's environment, from an allow-list: nothing like NODE_OPTIONS or npm_config_*
        can reach node or npm and change what code runs."""
        # Windows keeps environment names upper-case (WINDIR, not windir).
        env = {key: value for key, value in os.environ.items()
               if key in _ENV_ALLOWED or key.startswith("LC_")
               or (os.name == "nt" and key.upper() in _ENV_ALLOWED_UPPER)}
        env["PATH"] = os.pathsep.join([str(node.parent), env.get("PATH", "")]).rstrip(os.pathsep)
        env.update(extra)
        return env

    def _npm_command(
        self, node: Path, platform: Platform, npm_cache: Path, npmrc: Path, global_rc: Path
    ) -> tuple[list[str], dict[str, str]]:
        """The npm ci argv and extra env. On Windows, npm-cli.js through node: no npm.cmd, no cmd.exe."""
        if platform == Platform.WIN32:
            npm_cli = node.parent / "node_modules" / "npm" / "bin" / "npm-cli.js"
            if not npm_cli.is_file():
                raise _CouldNotCheck("npm_missing")
            flags = [a for a in NPM_CI_ARGS[1:] if isinstance(a, str)
                     and a not in ("--cache", "--userconfig", "--globalconfig")]
            env = {"npm_config_cache": str(npm_cache), "npm_config_userconfig": str(npmrc),
                   "npm_config_globalconfig": str(global_rc)}
            return [str(node), str(npm_cli), *flags], env
        path_dirs = [str(node.parent), *os.environ.get("PATH", "").split(os.pathsep)]
        npm = _lookup("npm", path_dirs, platform)
        if npm is None:
            raise _CouldNotCheck("npm_missing")
        fill = {id(_NPM_CACHE): str(npm_cache), id(_NPM_RC): str(npmrc),
                id(_NPM_GLOBAL_RC): str(global_rc)}
        argv = [str(npm) if a == "npm" else fill.get(id(a), a) for a in NPM_CI_ARGS]
        return [str(a) for a in argv], {}

    @staticmethod
    def _clean_stale(parent: Path) -> None:
        """Leftovers of a fetch that was killed before it could clean up."""
        cutoff = time.time() - STALE_SECONDS
        candidates = [p for prefix in _SCRATCH_PREFIXES for p in parent.glob(prefix + "*")]
        for path in candidates:
            try:
                if path.lstat().st_mtime < cutoff:
                    _remove_tree(path)
            except OSError:
                pass

    def _fetch(self, node: Path, install: Path, platform: Platform, expected: dict[str, str]) -> None:
        """npm ci the pinned lockfile in a temp dir beside ``install``, verify it, then rename it in."""
        vendor = self._vendor_dir()
        parent = install.parent
        try:
            parent.mkdir(parents=True, exist_ok=True)
            work = _scratch(parent, ".hackmyagent-")
        except OSError as exc:
            raise _CouldNotCheck("fetch_failed", detail=str(exc)[:200]) from exc
        try:
            npm_cache = _scratch(parent, ".npm-cache-")
        except OSError as exc:
            _remove_tree(work)
            raise _CouldNotCheck("fetch_failed", detail=str(exc)[:200]) from exc
        npmrc = npm_cache / "empty-user-npmrc"
        global_rc = npm_cache / "empty-global-npmrc"
        try:
            npmrc.write_text("", encoding="utf-8")
            global_rc.write_text("", encoding="utf-8")
            argv, extra = self._npm_command(node, platform, npm_cache / "cache", npmrc, global_rc)
            try:
                for name in ("package.json", "package-lock.json"):
                    shutil.copy2(vendor / name, work / name)
                shutil.copytree(vendor / "stub", work / "stub")
            except OSError as exc:
                raise _CouldNotCheck("fetch_failed", detail=f"vendor files missing: {exc}"[:200]) from exc
            result = run(
                argv, timeout=FETCH_TIMEOUT, cwd=str(work),
                env=self._env(node, npm_config_update_notifier="false", **extra),
            )
            if not result.ok:
                detail = "timed out" if result.timed_out else (result.stderr or result.error or "")
                raise _CouldNotCheck("fetch_failed", detail=detail.strip()[-300:])
            if not self._installed(work):
                raise _CouldNotCheck("fetch_failed", detail="the download wasn't the pinned version")
            try:
                problems = tree_problems(work, expected)
            except OSError as exc:
                problems = [f"unreadable: {exc}"]
            if problems:
                raise _CouldNotCheck("download_mismatch", detail="; ".join(problems[:5])[:300])
            try:
                if self._installed(install) and _matches(install, expected):
                    return  # another scan put a good copy in place meanwhile; keep it
                if install.exists() or _is_link(install):
                    _remove_tree(install)
                os.replace(work, install)
            except OSError as exc:
                raise _CouldNotCheck("fetch_failed", detail=str(exc)[:200]) from exc
        finally:
            _remove_tree(work)
            _remove_tree(npm_cache)

    @staticmethod
    def _make_stub_link(root: Path, platform: Platform) -> None:
        """node_modules/onnxruntime-node -> stub: a junction on Windows, a relative symlink elsewhere."""
        link = root / STUB_LINK
        try:
            if platform == Platform.WIN32:
                _create_junction(str(root / "stub"), str(link))
            else:
                os.symlink(os.path.join("..", "stub"), link)
        except OSError as exc:
            raise _CouldNotCheck("stub_link_failed", detail=str(exc)[:200]) from exc

    def _run_detect(self, node: Path, run_dir: Path, install: Path) -> dict:
        cli = run_dir / "node_modules" / "hackmyagent" / "dist" / "cli.js"
        try:
            settings = _scratch(install.parent, ".settings-")
        except OSError as exc:
            raise _CouldNotCheck("copy_failed", detail=str(exc)[:200]) from exc
        # Its start-up self-check appends to ~/.nanomind/integrity-events.jsonl
        # (a path taken from the home folder, which detect needs as it is);
        # that write is undone afterwards.
        log_state = self._nanomind_before()
        try:
            argv = [str(node) if a == "node" else str(cli) if i == 1 else
                    str(self._home()) if a is _HOME else a
                    for i, a in enumerate(DETECT_ARGS)]
            # Its settings, its telemetry file (and the machine ID it derives
            # for it) and its temp-folder sweep all land in a folder deleted below.
            sandbox = str(settings)
            result = run(
                argv, timeout=DETECT_TIMEOUT, cwd=sandbox,
                env=self._env(node, OPENA2A_TELEMETRY="off", OPENA2A_HOME=sandbox,
                              XDG_CONFIG_HOME=sandbox, TMPDIR=sandbox, TMP=sandbox, TEMP=sandbox),
            )
        finally:
            _remove_tree(settings)
            self._left_in_home = self._nanomind_after(log_state)
        if result.timed_out:
            raise _CouldNotCheck("timed_out")
        if result.returncode == 2:
            raise _CouldNotCheck("not_measured")
        if result.returncode == 3:
            raise _CouldNotCheck("integrity_failed", install_dir=self._tilde(str(install)))
        if result.returncode not in (0, 1):
            raise _CouldNotCheck("tool_failed", exit_code=result.returncode)
        if result.truncated:
            raise _CouldNotCheck("bad_output")
        try:
            doc = json.loads(result.stdout)
        except ValueError:
            raise _CouldNotCheck("bad_output") from None
        if not isinstance(doc, dict):
            raise _CouldNotCheck("bad_output")
        for key in ("agents", "mcpServers"):
            if not isinstance(doc.get(key), list):
                raise _CouldNotCheck("bad_output")
        for key in ("aiConfigs", "findings"):
            if doc.get(key) is not None and not isinstance(doc.get(key), list):
                raise _CouldNotCheck("bad_output")
        coverage = doc.get("coverage")
        if isinstance(coverage, dict) and coverage.get("measured") is False:
            raise _CouldNotCheck("not_measured")
        return doc

    _NANOMIND_LOG = ".nanomind/integrity-events.jsonl"

    def _nanomind_before(self) -> dict:
        folder = self._home() / ".nanomind"
        log = folder / "integrity-events.jsonl"
        state: dict[str, Any] = {"folder_existed": folder.exists() or _is_link(folder),
                                 "start": time.time(), "file": None, "odd": False}
        try:
            st = os.lstat(log)
        except OSError:
            return state
        if stat.S_ISREG(st.st_mode) and not _is_link(log):
            state["file"] = (st.st_dev, st.st_ino, st.st_size)
        else:
            state["odd"] = True
        return state

    @staticmethod
    def _our_events(data: bytes, start: float, end: float) -> bool:
        """True when every line is a HackMyAgent integrity event stamped inside this run."""
        from datetime import datetime

        lines = [line for line in data.decode("utf-8", errors="replace").splitlines() if line.strip()]
        if not lines:
            return False
        for line in lines:
            try:
                event = json.loads(line)
                when = datetime.fromisoformat(str(event["timestamp"]).replace("Z", "+00:00"))
            except (ValueError, KeyError, TypeError):
                return False
            if not isinstance(event.get("eventType"), str):
                return False
            if not (start - 2 <= when.timestamp() <= end + 2):
                return False
        return True

    def _nanomind_after(self, state: dict) -> str | None:
        """Undo HackMyAgent's self-check log line(s), only when they are surely ours.

        Returns the home-relative path when something was left in place, else None.
        """
        folder = self._home() / ".nanomind"
        log = folder / "integrity-events.jsonl"
        left = "~/" + self._NANOMIND_LOG
        end = time.time()
        if state["odd"] or _is_link(folder):
            return left
        try:
            st = os.lstat(log)
        except OSError:
            st = None
        if st is None:
            if state["file"] is not None:
                return left  # it was there before and is gone now: not ours to explain
            self._remove_our_folder(folder, state)
            return None
        if not stat.S_ISREG(st.st_mode) or _is_link(log):
            return left
        flags = os.O_RDWR | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
        try:
            fd = os.open(log, flags)
        except OSError:
            return left
        try:
            opened = os.fstat(fd)
            if not stat.S_ISREG(opened.st_mode) or (opened.st_dev, opened.st_ino) != (st.st_dev, st.st_ino):
                return left
            before = state["file"]
            if before is not None:
                dev, ino, old_size = before
                if (opened.st_dev, opened.st_ino) != (dev, ino):
                    return left
                if opened.st_size == old_size:
                    return None
                if opened.st_size < old_size or opened.st_size - old_size > 1 << 20:
                    return left
                os.lseek(fd, old_size, os.SEEK_SET)
                tail = os.read(fd, opened.st_size - old_size)
                if not self._our_events(tail, state["start"], end):
                    return left
                os.ftruncate(fd, old_size)
                return None
            if opened.st_size > 1 << 20:
                return left
            if not self._our_events(os.read(fd, opened.st_size), state["start"], end):
                return left
            now = os.lstat(log)
            if (now.st_dev, now.st_ino) != (opened.st_dev, opened.st_ino):
                return left
            os.unlink(log)
        except OSError:
            return left
        finally:
            os.close(fd)
        self._remove_our_folder(folder, state)
        return None

    @staticmethod
    def _remove_our_folder(folder: Path, state: dict) -> None:
        if state["folder_existed"] or _is_link(folder):
            return
        try:
            folder.rmdir()  # only when empty
        except OSError:
            pass

    def _node_search_dirs(self, platform: Platform) -> list[Path]:
        """Places Node.js is often installed that a desktop app's PATH misses."""
        home = self._home()
        if platform == Platform.WIN32:
            fixed = [Path(os.environ[v]) / "nodejs"
                     for v in ("ProgramFiles", "ProgramFiles(x86)") if os.environ.get(v)]
        else:
            fixed = [Path("/opt/homebrew/bin"), Path("/usr/local/bin")]
        if self.system_node_dirs is not None:
            fixed = list(self.system_node_dirs)
        dirs = fixed + [home / ".local" / "bin", home / ".volta" / "bin"]
        nvm = home / ".nvm" / "versions" / "node"
        try:
            versions = sorted((p for p in nvm.iterdir() if p.is_dir()),
                              key=lambda p: _version_tuple(p.name), reverse=True)
        except OSError:
            versions = []
        if versions:
            dirs.append(versions[0] / "bin")
        return dirs

    def _find_node(self, platform: Platform) -> Path | None:
        """node from PATH, then the usual places; absolute folders only, never the current one."""
        dirs = [*os.environ.get("PATH", "").split(os.pathsep),
                *(str(d) for d in self._node_search_dirs(platform))]
        return _lookup("node", dirs, platform)

    # --- turning the result into findings --------------------------------------------

    def _tilde(self, path: str) -> str:
        home = str(self._home())
        if path == home:
            return "~"
        if path.startswith(home + os.sep) or path.startswith(home + "/"):
            return "~" + path[len(home):]
        return path

    def _home_path(self, file: str) -> str:
        """HackMyAgent's paths are relative to the home folder it was given."""
        if file.startswith("~") or not file:
            return file
        if os.path.isabs(file):
            return self._tilde(file)
        return "~/" + file

    @staticmethod
    def _tool_of(source: str) -> str:
        """'Cursor (global)' -> 'Cursor'."""
        return re.sub(r"\s*\(.*\)\s*$", "", source or "").strip()

    def _findings(self, doc: dict, install: Path, platform: Platform) -> list[Finding]:
        agents = [a for a in doc.get("agents") or [] if isinstance(a, dict)]
        servers = [s for s in doc.get("mcpServers") or [] if isinstance(s, dict)]
        configs = [c for c in doc.get("aiConfigs") or [] if isinstance(c, dict)]
        reported = [f for f in doc.get("findings") or [] if isinstance(f, dict)]

        findings = self._credential_findings(configs, reported)
        config_files = {a.get("name"): a.get("source") for a in agents
                        if str(a.get("source", "")).startswith("~")}
        for server in servers:
            if str(server.get("risk", "")).lower() in ("high", "critical"):
                findings.append(self._mcp_finding(server, config_files))
        if agents or servers:
            findings.append(self._inventory(agents, servers, install, platform))
        return findings

    def _credential_findings(self, configs: list[dict], reported: list[dict]) -> list[Finding]:
        hits = []
        for c in configs:
            if str(c.get("risk", "")).lower() != "critical":
                continue
            evidence = c.get("evidence") if isinstance(c.get("evidence"), dict) else {}
            hits.append({"file": str(c.get("file", "")), "line": evidence.get("line"),
                         "token": evidence.get("token"), "tool": c.get("tool")})
        if not hits:
            # Only HackMyAgent's own "config" finding says so: read where from its detail.
            for f in reported:
                text = f"{f.get('title', '')} {f.get('detail', '')}".lower()
                if f.get("category") != "config" or "credential" not in text:
                    continue
                for line in str(f.get("detail", "")).splitlines() or [""]:
                    m = _DETAIL_RE.match(line.strip())
                    hits.append({"file": m["file"] if m else "", "line": m["line"] if m else None,
                                 "token": m["token"] if m else None, "tool": None})
        out = []
        seen = set()
        for hit in hits:
            key = (hit["file"], hit["line"], hit["token"])
            if key in seen:
                continue
            seen.add(key)
            out.append(self._credential_finding(hit))
        return out

    def _credential_finding(self, hit: dict) -> Finding:
        file = self._home_path(hit["file"])
        try:
            line = int(hit["line"]) if hit["line"] is not None else None
        except (TypeError, ValueError):
            line = None
        variable = _safe_name(hit["token"])
        tool = hit["tool"] or "An AI tool"
        owner = f"{tool}'s" if hit["tool"] else "An AI tool's"
        where = f"{file}, line {line}" if file and line else (file or "a settings file")
        named = f", saved under the name {variable}" if variable else ""
        data: dict[str, Any] = {"file": file, "tool": hit["tool"]}
        if line is not None:
            data["line"] = line
        if variable:
            data["variable"] = variable
        return Finding(
            title=f"A secret key is saved in {owner} settings file",
            description=(
                f"{owner} settings file ({where}) holds what looks like a secret key"
                f"{named}. We didn't read the key itself. A key saved in a plain "
                "settings file can be read by any program running as you, and it "
                "travels with the file when that folder is backed up, synced or "
                "shared. This is common and isn't a sign that anyone has used it.\n\n"
                "What to do: If you know what this key is for, sign in to the "
                "service that issued it, make a new key, delete the old one there, "
                f"and put the new one where {tool if hit['tool'] else 'the tool'}'s "
                "own instructions suggest instead of in this file. If you don't "
                "recognise it, ask whoever set the tool up before changing anything."
            ),
            severity=Severity.WARNING,
            category=self.category,
            code="security.ai_agent_audit.credentials_in_ai_config",
            data=data,
        )

    def _mcp_finding(self, server: dict, config_files: dict) -> Finding:
        name = str(server.get("name", "an add-on"))
        source = str(server.get("source", ""))
        tool = self._tool_of(source) or "An AI tool"
        raw_caps = server.get("capabilities")
        caps = [c for c in raw_caps if isinstance(c, str)] if isinstance(raw_caps, list) else []
        doing = [_CAPABILITY_WORDS[c] for c in caps if c in _CAPABILITY_WORDS]
        doing = list(dict.fromkeys(doing))
        can = " and ".join(doing) if doing else "do more than most add-ons"
        config_file = config_files.get(tool)
        data: dict[str, Any] = {
            "name": name, "tool": source, "capabilities": caps,
            "transport": server.get("transport"), "risk": server.get("risk"),
        }
        if config_file:
            data["config_file"] = config_file
        settings = f" ({config_file})" if config_file else ""
        return Finding(
            title=f"{tool} has an add-on that can {can}: {name}",
            description=(
                f"{tool} is set up with an add-on called “{name}” (an MCP "
                f"server) that lets its AI assistant {can}. If you set this up on "
                "purpose, it may be fine. The risk is that an AI assistant can be "
                "tricked by something it reads, such as a web page or a document, "
                "into using that power in ways you didn't ask for.\n\n"
                "What to do: If you don't use this add-on, remove it from "
                f"{tool}'s add-on (MCP) settings{settings}. If you do use it, give "
                "it the least it needs: an account that can only read, or a single "
                "folder instead of the whole computer."
            ),
            severity=Severity.WARNING,
            category=self.category,
            code="security.ai_agent_audit.risky_mcp_server",
            data=data,
        )

    def _inventory(
        self, agents: list[dict], servers: list[dict], install: Path, platform: Platform
    ) -> Finding:
        tools = [{"name": str(a.get("name", "")), "state": a.get("state"),
                  "kind": a.get("category")} for a in agents]
        by_tool: dict[str, list[str]] = {}
        for s in servers:
            by_tool.setdefault(str(s.get("source", "unknown")), []).append(str(s.get("name", "")))
        names = ", ".join(
            f"{t['name']} (running)" if t["state"] == "running" else t["name"] for t in tools
        ) or "none we recognise"
        lines = [f"  {source}: {', '.join(found)}" for source, found in by_tool.items()]
        add_ons = (
            f"\n\nThey are connected to {len(servers)} add-on(s) (MCP servers), "
            "which let them reach things outside the chat:\n" + "\n".join(lines)
            if servers else ""
        )
        # Run by hand the same way this check runs it: nothing shared, usage
        # reporting off, its settings in throwaway folders (where the shell allows).
        if platform == Platform.WIN32:
            command = ('$env:OPENA2A_TELEMETRY="off"; node node_modules/hackmyagent/dist/cli.js '
                       "detect C:\\path\\to\\project --depth 0 --no-contribute")
            leftovers = (" On Windows this way it keeps its own small settings files in "
                         "~\\.opena2a and ~\\.config\\opena2a.")
        else:
            command = ('OPENA2A_TELEMETRY=off OPENA2A_HOME="$(mktemp -d)" '
                       'XDG_CONFIG_HOME="$(mktemp -d)" node node_modules/hackmyagent/dist/cli.js '
                       "detect /path/to/project --depth 0 --no-contribute")
            leftovers = ""
        return Finding(
            title=f"AI tools on this computer: {len(tools)}",
            description=(
                f"These AI tools are installed or running here: {names}.{add_ons}\n\n"
                "Nothing here is wrong by itself; it's a list so you can spot "
                "anything you don't remember installing. An AI tool or add-on you "
                "don't recognise is worth asking about.\n\n"
                "This looked at the settings for your whole account, not inside "
                "each project folder. To look inside one project folder too, open "
                f"a terminal and run:\n  cd {self._tilde(str(install))}\n  {command}\n"
                "(with your project folder's path in place of the example path). "
                "Run by hand, it also adds a line to ~/.nanomind/integrity-events.jsonl "
                f"each time.{leftovers}"
            ),
            severity=Severity.INFO,
            category=self.category,
            code="security.ai_agent_audit.ai_inventory",
            data={"tools": tools, "mcp_servers_by_tool": by_tool,
                  "mcp_server_count": len(servers), "project_command": command},
        )

    def _changed_during_run_finding(self, platform: Platform) -> Finding:
        return Finding(
            title="The AI-tools checker's files changed while it was running",
            description=(
                "While HackMyAgent (the free tool this check uses) was running, some "
                "of its files changed. That shouldn't happen. It may mean another "
                "program on this computer swapped in its own code, which would then "
                "have run with Reclaim City's permissions. We threw its results away "
                "and deleted the saved copy; a fresh one is downloaded on the next "
                "checkup that's allowed to download.\n\n"
                "What to do: Run a full checkup and look at what is set to start "
                "automatically on this computer (background tasks and login items), "
                "and at anything you don't recognise. If you're not sure what you're "
                "looking at, ask someone you trust who helps you with computers, and "
                "show them this message."
            ),
            severity=Severity.WARNING,
            category=self.category,
            code="security.ai_agent_audit.changed_during_run",
            data={"reason": "changed_during_run",
                  "install_dir": self._tilde(str(self._install_dir(platform)))},
        )

    def _could_not_check(self, exc: _CouldNotCheck) -> Finding:
        text = _COULD_NOT_CHECK[exc.reason]
        if exc.reason == "integrity_failed" and exc.data.get("install_dir"):
            text += f"\n\nThe folder: {exc.data['install_dir']}"
        return Finding(
            title="Couldn't check what your AI tools can reach",
            description=(
                f"{text}\n\nThis means we didn't look at your AI tools' settings; "
                "it doesn't mean they're fine or that something is wrong."
            ),
            severity=Severity.INFO,
            category=self.category,
            code="security.ai_agent_audit.could_not_check",
            data={"reason": exc.reason, **exc.data},
        )
