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

import json
import os
import re
import shutil
import sys
import tempfile
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

# Stand-ins filled in at run time (shown as "…" in docs/commands.md).
_NPM_CACHE = object()
_HOME = object()

# The three commands this module can run. argv[0] is replaced by the full
# path of the node/npm that was found, argv[1] of DETECT_ARGS by the cli.js
# inside the fetched copy.
NODE_VERSION_ARGS = ["node", "--version"]
NPM_CI_ARGS = [
    "npm", "ci", "--ignore-scripts", "--no-audit", "--no-fund",
    "--registry=https://registry.npmjs.org/", "--cache", _NPM_CACHE,
]
DETECT_ARGS = [
    "node", "node_modules/hackmyagent/dist/cli.js", "detect", _HOME, "--json", "--depth", "0",
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
        "again; Reclaim City will download a fresh copy if this keeps happening "
        "after you delete the folder named in this finding's details."
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

    def _detect(self, platform: Platform) -> dict:
        install = self._install_dir(platform)
        installed = self._installed(install)
        if not installed and os.environ.get("RESCUE_NO_DOWNLOADS") == "1":
            raise _CouldNotCheck("downloads_off")

        node = self._find_node(platform)
        if node is None:
            raise _CouldNotCheck("node_missing")
        version = run([str(node), *NODE_VERSION_ARGS[1:]], timeout=VERSION_TIMEOUT)
        if not version.ok or _version_tuple(version.stdout.strip())[0] < MIN_NODE_MAJOR:
            raise _CouldNotCheck("node_too_old", node_version=version.stdout.strip()[:20])

        if not installed:
            self._fetch(node, install)

        return self._run_detect(node, install)

    @staticmethod
    def _installed(install: Path) -> bool:
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

    def _fetch(self, node: Path, install: Path) -> None:
        """npm ci the pinned lockfile in a temp dir beside ``install``, then rename it in."""
        npm = shutil.which("npm", path=str(node.parent)) or shutil.which("npm")
        if npm is None:
            raise _CouldNotCheck("npm_missing")
        vendor = self._vendor_dir()
        parent = install.parent
        try:
            parent.mkdir(parents=True, exist_ok=True)
            work = Path(tempfile.mkdtemp(prefix=".hackmyagent-", dir=parent))
        except OSError as exc:
            raise _CouldNotCheck("fetch_failed", detail=str(exc)[:200]) from exc
        npm_cache = Path(tempfile.mkdtemp(prefix="rc-npm-cache-"))
        try:
            try:
                for name in ("package.json", "package-lock.json"):
                    shutil.copy2(vendor / name, work / name)
                shutil.copytree(vendor / "stub", work / "stub")
            except OSError as exc:
                raise _CouldNotCheck("fetch_failed", detail=f"vendor files missing: {exc}"[:200]) from exc
            argv = [npm if a == "npm" else str(npm_cache) if a is _NPM_CACHE else a
                    for a in NPM_CI_ARGS]
            result = run(
                argv, timeout=FETCH_TIMEOUT, cwd=str(work),
                env=self._env(node, npm_config_update_notifier="false"),
            )
            if not result.ok:
                detail = "timed out" if result.timed_out else (result.stderr or result.error or "")
                raise _CouldNotCheck("fetch_failed", detail=detail.strip()[-300:])
            if not self._installed(work):
                raise _CouldNotCheck("fetch_failed", detail="the download wasn't the pinned version")
            try:
                if install.exists():
                    shutil.rmtree(install)
                os.replace(work, install)
            except OSError as exc:
                # Another scan may have put a good copy in place meanwhile.
                if not self._installed(install):
                    raise _CouldNotCheck("fetch_failed", detail=str(exc)[:200]) from exc
        finally:
            shutil.rmtree(work, ignore_errors=True)
            shutil.rmtree(npm_cache, ignore_errors=True)

    def _run_detect(self, node: Path, install: Path) -> dict:
        cli = install / "node_modules" / "hackmyagent" / "dist" / "cli.js"
        settings = Path(tempfile.mkdtemp(prefix="rc-opena2a-"))
        try:
            argv = [str(node) if a == "node" else str(cli) if i == 1 else
                    str(self._home()) if a is _HOME else a
                    for i, a in enumerate(DETECT_ARGS)]
            result = run(
                argv, timeout=DETECT_TIMEOUT, cwd=str(settings),
                env=self._env(node, OPENA2A_TELEMETRY="off", OPENA2A_HOME=str(settings)),
            )
        finally:
            shutil.rmtree(settings, ignore_errors=True)
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
        found = shutil.which("node")
        if found:
            return Path(found)
        for directory in self._node_search_dirs(platform):
            found = shutil.which("node", path=str(directory))
            if found:
                return Path(found)
        return None

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
        caps = [str(c) for c in server.get("capabilities") or [] if isinstance(c, str)]
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
        telemetry_off = (
            '$env:OPENA2A_TELEMETRY="off"; ' if platform == Platform.WIN32
            else "OPENA2A_TELEMETRY=off "
        )
        command = f"{telemetry_off}node node_modules/hackmyagent/dist/cli.js detect /path/to/project"
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
                "(with your project folder's path in place of /path/to/project)."
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
