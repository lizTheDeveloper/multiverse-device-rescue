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
        "it expects, so it didn't use or keep them. Run the checkup again later."
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
        "connection dropped or the registry was busy. Run the checkup again later."
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


def _is_link(path: Path) -> bool:
    """A symlink, or (on Windows) a junction."""
    if path.is_symlink():
        return True
    is_junction = getattr(os.path, "isjunction", None)
    return bool(is_junction is not None and is_junction(path))


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
        except OSError:
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
    ]

    # Seams for tests: the home folder to look at, the fixed places Node.js is
    # often installed (None = the real defaults), and the vendor files.
    home: Path | None = None
    system_node_dirs: list[Path] | None = None
    vendor_dir: Path | None = None
    elevated: bool | None = None  # None = ask the operating system

    # --- check ------------------------------------------------------------------

    def check(self, profile: SystemProfile) -> CheckResult:
        try:
            doc = self._detect(profile.platform)
        except _CouldNotCheck as exc:
            return CheckResult(module_name=self.name, findings=[self._could_not_check(exc)])
        return CheckResult(
            module_name=self.name,
            findings=self._findings(doc, self._install_dir(profile.platform), profile.platform),
        )

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
            raise _CouldNotCheck("download_mismatch", detail=f"no {MANIFEST_NAME}: {exc}"[:200]) from exc

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
        downloads_off = os.environ.get("RESCUE_NO_DOWNLOADS") == "1"
        usable = self._installed(install)
        if not usable and downloads_off:
            raise _CouldNotCheck("downloads_off")

        node = self._find_node(platform)
        if node is None:
            raise _CouldNotCheck("node_missing")
        version = run([str(node), *NODE_VERSION_ARGS[1:]], timeout=VERSION_TIMEOUT)
        if not version.ok:
            raise _CouldNotCheck("node_failed")
        if _version_tuple(version.stdout.strip())[0] < MIN_NODE_MAJOR:
            raise _CouldNotCheck("node_too_old", node_version=version.stdout.strip()[:20])

        if not usable:
            self._fetch(node, install, platform, expected)
        # Checked right before it runs, every time, so what runs is what was
        # downloaded. A saved copy that changed is deleted and fetched once more.
        if tree_problems(install, expected):
            _remove_tree(install)
            if not usable or downloads_off:
                raise _CouldNotCheck("tampered")
            self._fetch(node, install, platform, expected)
            if tree_problems(install, expected):
                _remove_tree(install)
                raise _CouldNotCheck("tampered")
        return self._run_detect(node, install)

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
        env = dict(os.environ)
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
        candidates = list(parent.glob(".hackmyagent-*"))
        candidates += list(Path(tempfile.gettempdir()).glob("rc-npm-cache-*"))
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
            self._clean_stale(parent)
            work = Path(tempfile.mkdtemp(prefix=".hackmyagent-", dir=parent))
        except OSError as exc:
            raise _CouldNotCheck("fetch_failed", detail=str(exc)[:200]) from exc
        npm_cache = Path(tempfile.mkdtemp(prefix="rc-npm-cache-"))
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
            problems = tree_problems(work, expected)
            if problems:
                raise _CouldNotCheck("download_mismatch", detail="; ".join(problems[:5])[:300])
            try:
                if self._installed(install) and not tree_problems(install, expected):
                    return  # another scan put a good copy in place meanwhile; keep it
                if install.exists() or _is_link(install):
                    _remove_tree(install)
                os.replace(work, install)
            except OSError as exc:
                raise _CouldNotCheck("fetch_failed", detail=str(exc)[:200]) from exc
            self._relink_stub(install, platform)
        finally:
            _remove_tree(work)
            _remove_tree(npm_cache)

    @staticmethod
    def _relink_stub(install: Path, platform: Platform) -> None:
        """Windows makes the stub link a junction to an absolute path: point it at the renamed copy."""
        if platform != Platform.WIN32:
            return  # a relative symlink (../stub) survives the rename
        link = install / STUB_LINK
        try:
            if _is_link(link):
                try:
                    os.unlink(link)
                except OSError:
                    os.rmdir(link)
            _create_junction(str(install / "stub"), str(link))
        except OSError:
            pass  # detect never loads it; tree_problems reports a link that points elsewhere

    def _run_detect(self, node: Path, install: Path) -> dict:
        cli = install / "node_modules" / "hackmyagent" / "dist" / "cli.js"
        settings = Path(tempfile.mkdtemp(prefix="rc-opena2a-"))
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
                "(with your project folder's path in place of the example path)."
                f"{leftovers}"
            ),
            severity=Severity.INFO,
            category=self.category,
            code="security.ai_agent_audit.ai_inventory",
            data={"tools": tools, "mcp_servers_by_tool": by_tool,
                  "mcp_server_count": len(servers), "project_command": command},
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
