import json
import shutil
import subprocess
import time
from pathlib import Path

from rescue.models import (
    Action,
    ActionKind,
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

# Warm the shared IOC database cache at import time (not lazily inside
# check()). The loader caches its parsed result keyed by data_dir, so this
# eager load ensures real IOC data is cached before check()/fix() run —
# which matters because check() may execute under test mocks (or other
# unusual filesystem conditions) that would otherwise interfere with the
# loader's own internal file-existence checks.
_iocs_cache = None
try:
    from modules.security.ai_worm_iocs.loader import load_iocs as _load_iocs

    _iocs_cache = _load_iocs()
except Exception:
    _iocs_cache = None


_MCP_CONFIG_PATHS = [
    "~/.claude/settings.json",
    "~/.claude.json",
    "~/.cursor/mcp.json",
    "~/.continue/config.json",
]

# Relative (repo-rooted) paths that appear in the shared IOC database as
# known hook/dropper artifacts.
_REPO_HOOK_IOC_FILES = [
    ".claude/setup.mjs",
    ".cursor/rules/setup.mdc",
    ".github/setup.js",
]

# Files that are not IOC-backed on their own, but whose presence combined
# with a suspicious auto-run configuration is a known technique for silent
# code execution. Flagged at medium confidence only.
_REPO_HOOK_HEURISTIC_FILES = [
    ".vscode/tasks.json",
]

_COMMON_PROJECT_DIRS = [
    "~/src",
    "~/Projects",
    "~/projects",
    "~/code",
    "~/dev",
    "~/Developer",
    "~/repos",
    "~/git",
    "~/workspace",
]

_MAX_SCAN_DIRS = 100
_SSH_KEY_RECENT_WINDOW_SECONDS = 7 * 24 * 3600


class Module(ModuleBase):
    name = "ai_worm_git_ssh"
    category = "security"
    platforms = [Platform.DARWIN, Platform.LINUX, Platform.WIN32]
    risk_level = RiskLevel.MODERATE
    priority = 56
    depends_on = []
    estimated_duration = "10s"

    emits_codes = [
        "security.ai_worm_git_ssh.git_hookspath_hijack",
        "security.ai_worm_git_ssh.git_templatedir_hijack",
        "security.ai_worm_git_ssh.npmrc_git_override",
        "security.ai_worm_git_ssh.rogue_mcp_server",
        "security.ai_worm_git_ssh.repo_hook_file",
        "security.ai_worm_git_ssh.ssh_authorized_keys_recent",
    ]

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []
        findings.extend(self._check_git_global_config())

        for entry in self._check_npmrc_override():
            findings.append(
                Finding(
                    title="npm config overrides git binary with node",
                    description=(
                        f".npmrc at {entry['path']} contains 'git=node', which "
                        "replaces the git binary invoked by npm — a known "
                        "Shai-Hulud technique used to bypass --ignore-scripts "
                        "protections."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
                    code="security.ai_worm_git_ssh.npmrc_git_override",
                    data={
                        "check": "npmrc_git_override",
                        "confidence": "high",
                        "path": entry["path"],
                        "line": entry["line"],
                    },
                )
            )

        for entry in self._check_mcp_configs():
            findings.append(
                Finding(
                    title=f"Rogue MCP server detected: {entry['server_name']}",
                    description=(
                        f"MCP server '{entry['server_name']}' configured in "
                        f"{entry['config_path']} matches a known malicious "
                        f"server IOC (threat: {entry['threat']})."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
                    code="security.ai_worm_git_ssh.rogue_mcp_server",
                    data={
                        "check": "rogue_mcp_server",
                        "confidence": "high",
                        "config_path": entry["config_path"],
                        "server_name": entry["server_name"],
                        "threat": entry["threat"],
                    },
                )
            )

        findings.extend(self._check_repo_hooks())
        findings.extend(self._check_ssh_authorized_keys())
        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            confidence = finding.data.get("confidence", "low")
            check = finding.data.get("check")

            if confidence == "high" and check == "git_hookspath_hijack":
                actions.append(self._fix_unset_git_config("core.hooksPath"))
            elif confidence == "high" and check == "git_templatedir_hijack":
                actions.append(self._fix_unset_git_config("init.templateDir"))
            elif confidence == "high" and check == "npmrc_git_override":
                actions.append(self._fix_npmrc_override(finding))
            elif confidence == "high" and check == "rogue_mcp_server":
                actions.append(self._fix_rogue_mcp_server(finding))
            elif confidence == "high" and check == "repo_hook_file":
                actions.append(self._fix_repo_hook_file(finding))
            else:
                actions.append(
                    Action(
                        title=f"Investigate: {finding.title}",
                        description=(
                            f"Manual investigation recommended. "
                            f"Confidence: {confidence}. {finding.description}"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    # -- detection: git global config -----------------------------------

    def _run_git_config(self, key: str) -> str | None:
        try:
            result = subprocess.run(
                ["git", "config", "--global", key],
                capture_output=True,
                text=True,
                timeout=5,
            )
        except (subprocess.TimeoutExpired, OSError):
            return None
        if result.returncode != 0:
            return None
        value = (result.stdout or "").strip()
        return value or None

    _LEGITIMATE_HOOK_MANAGERS = {
        "husky", "lefthook", "overcommit", "pre-commit", "git-hooks",
        ".git-hooks", ".githooks", "core.hooksPath",
    }

    def _looks_legitimate_hooks_path(self, path_str: str) -> bool:
        p = Path(path_str)
        name_lower = p.name.lower()
        for manager in self._LEGITIMATE_HOOK_MANAGERS:
            if manager in name_lower or manager in str(p).lower():
                return True
        home = str(Path.home())
        if path_str.startswith(home) and not self._path_matches_ioc(path_str):
            return True
        return False

    def _path_matches_ioc(self, path_str: str) -> bool:
        iocs = self._get_iocs()
        if iocs is None:
            return False
        for p_ioc in iocs.paths:
            if p_ioc.path in path_str or path_str in p_ioc.path:
                return True
        return False

    def _check_git_global_config(self) -> list[Finding]:
        findings = []

        hooks_path = self._run_git_config("core.hooksPath")
        if hooks_path:
            if self._looks_legitimate_hooks_path(hooks_path):
                confidence = "low"
                severity = Severity.INFO
                title = "Git core.hooksPath set (likely legitimate)"
            else:
                confidence = "high"
                severity = Severity.CRITICAL
                title = "Git core.hooksPath hijacked"
            findings.append(
                Finding(
                    title=title,
                    description=(
                        f"Global git config core.hooksPath is set to: "
                        f"{hooks_path}. Custom hooks paths can be used "
                        "to run code on every git operation."
                    ),
                    severity=severity,
                    category=self.category,
                    code="security.ai_worm_git_ssh.git_hookspath_hijack",
                    data={
                        "check": "git_hookspath_hijack",
                        "confidence": confidence,
                        "value": hooks_path,
                    },
                )
            )

        template_dir = self._run_git_config("init.templateDir")
        if template_dir:
            if self._looks_legitimate_hooks_path(template_dir):
                confidence = "low"
                severity = Severity.INFO
                title = "Git init.templateDir set (likely legitimate)"
            else:
                confidence = "high"
                severity = Severity.CRITICAL
                title = "Git init.templateDir hijacked"
            findings.append(
                Finding(
                    title=title,
                    description=(
                        f"Global git config init.templateDir is set to: "
                        f"{template_dir}. Custom templates (including hooks) "
                        "are copied into every newly created or cloned repository."
                    ),
                    severity=severity,
                    category=self.category,
                    code="security.ai_worm_git_ssh.git_templatedir_hijack",
                    data={
                        "check": "git_templatedir_hijack",
                        "confidence": confidence,
                        "value": template_dir,
                    },
                )
            )

        return findings

    # -- detection: npmrc override ---------------------------------------

    def _check_npmrc_override(self) -> list[dict[str, str]]:
        results = []
        candidates = [Path.home() / ".npmrc"]
        try:
            cwd = Path.cwd()
            candidates.append(cwd / ".npmrc")
            candidates.extend(parent / ".npmrc" for parent in cwd.parents)
        except OSError:
            pass

        seen: set[str] = set()
        for path in candidates:
            key = str(path)
            if key in seen:
                continue
            seen.add(key)
            try:
                if not path.is_file():
                    continue
                content = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            for line in content.splitlines():
                if line.strip() == "git=node":
                    results.append({"path": str(path), "line": line.strip()})

        return results

    # -- detection: MCP server configs -----------------------------------

    def _check_mcp_configs(self) -> list[dict[str, str]]:
        results = []
        iocs = _iocs_cache
        if iocs is None or not iocs.mcp_servers:
            return results

        known = {server.name: server for server in iocs.mcp_servers}

        for cfg in _MCP_CONFIG_PATHS:
            path = Path(cfg).expanduser()
            try:
                if not path.is_file():
                    continue
                data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
            except (OSError, ValueError):
                continue

            if not isinstance(data, dict):
                continue
            mcp_servers = data.get("mcpServers")
            if not isinstance(mcp_servers, dict):
                continue

            for server_name in mcp_servers:
                ioc = known.get(server_name)
                if ioc is not None:
                    results.append(
                        {
                            "config_path": str(path),
                            "server_name": server_name,
                            "threat": ioc.threat,
                        }
                    )

        return results

    # -- detection: repo hook files ---------------------------------------

    def _candidate_repo_dirs(self) -> list[Path]:
        dirs: list[Path] = []
        try:
            dirs.append(Path.cwd())
        except OSError:
            pass

        for base in _COMMON_PROJECT_DIRS:
            if len(dirs) >= _MAX_SCAN_DIRS:
                break
            base_path = Path(base).expanduser()
            try:
                if not base_path.is_dir():
                    continue
            except OSError:
                continue
            dirs.append(base_path)
            try:
                for child in sorted(base_path.iterdir())[:20]:
                    if len(dirs) >= _MAX_SCAN_DIRS:
                        break
                    if child.is_dir() and not child.name.startswith("."):
                        dirs.append(child)
            except OSError:
                continue

        return dirs

    def _check_repo_hooks(self) -> list[Finding]:
        findings = []
        iocs = _iocs_cache
        ioc_by_path = {}
        if iocs is not None:
            for entry in iocs.paths:
                if entry.path in _REPO_HOOK_IOC_FILES:
                    ioc_by_path[entry.path] = entry

        seen: set[str] = set()
        for repo_dir in self._candidate_repo_dirs():
            for rel_path in _REPO_HOOK_IOC_FILES:
                candidate = repo_dir / rel_path
                key = str(candidate)
                if key in seen:
                    continue
                try:
                    if not candidate.is_file():
                        continue
                except OSError:
                    continue
                seen.add(key)
                ioc = ioc_by_path.get(rel_path)
                threat = ioc.threat if ioc else "unknown"
                # High confidence only when the IOC database confirms this
                # exact path; if the database failed to load or doesn't
                # (yet) list this filename, fall back to a medium-confidence
                # heuristic match rather than treating it as certain.
                confidence = "high" if ioc else "medium"
                findings.append(
                    Finding(
                        title=f"Suspicious repo hook file: {rel_path}",
                        description=(
                            f"Found {candidate}, matching a known malicious "
                            f"hook/dropper IOC pattern (threat: {threat})."
                            if ioc
                            else (
                                f"Found {candidate}, a filename pattern "
                                "associated with AI worm hook injection "
                                "(not IOC-confirmed — review manually)."
                            )
                        ),
                        severity=Severity.CRITICAL if ioc else Severity.WARNING,
                        category=self.category,
                        code="security.ai_worm_git_ssh.repo_hook_file",
                        data={
                            "check": "repo_hook_file",
                            "confidence": confidence,
                            "path": str(candidate),
                            "threat": threat,
                        },
                    )
                )

            for rel_path in _REPO_HOOK_HEURISTIC_FILES:
                candidate = repo_dir / rel_path
                key = str(candidate)
                if key in seen:
                    continue
                try:
                    if not candidate.is_file():
                        continue
                    content = candidate.read_text(encoding="utf-8", errors="ignore")
                except OSError:
                    continue
                if "folderOpen" not in content:
                    continue
                seen.add(key)
                findings.append(
                    Finding(
                        title=f"Auto-run task configuration detected: {rel_path}",
                        description=(
                            f"{candidate} configures a task to run "
                            "automatically on folder open (runOn: "
                            "folderOpen), a technique that can be abused "
                            "for silent code execution. Not IOC-confirmed — "
                            "review manually."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        code="security.ai_worm_git_ssh.repo_hook_file",
                        data={
                            "check": "repo_hook_file",
                            "confidence": "medium",
                            "path": str(candidate),
                            "threat": "heuristic_autorun_task",
                        },
                    )
                )

        return findings

    # -- detection: SSH authorized_keys -----------------------------------

    def _check_ssh_authorized_keys(self) -> list[Finding]:
        findings = []
        path = Path.home() / ".ssh" / "authorized_keys"
        try:
            if not path.is_file():
                return findings
            file_stat = path.stat()
            content = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return findings

        key_lines = [
            line
            for line in content.splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
        if not key_lines:
            return findings

        age_seconds = time.time() - file_stat.st_mtime
        if age_seconds <= _SSH_KEY_RECENT_WINDOW_SECONDS:
            findings.append(
                Finding(
                    title="SSH authorized_keys recently modified",
                    description=(
                        f"{path} was modified within the last 7 days and "
                        f"contains {len(key_lines)} key(s). Recent, "
                        "unexpected additions to authorized_keys can "
                        "indicate unauthorized remote-access persistence — "
                        "verify every key is recognized."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.ai_worm_git_ssh.ssh_authorized_keys_recent",
                    data={
                        "check": "ssh_authorized_keys_recent",
                        "confidence": "low",
                        "path": str(path),
                        "key_count": len(key_lines),
                        "modified_days_ago": round(age_seconds / 86400, 2),
                    },
                )
            )

        return findings

    # -- fix actions --------------------------------------------------------

    def _fix_unset_git_config(self, key: str) -> Action:
        try:
            result = subprocess.run(
                ["git", "config", "--global", "--unset", key],
                capture_output=True,
                text=True,
                timeout=5,
            )
            success = result.returncode == 0
            return Action(
                title=f"Reset git {key}",
                description=(
                    f"Ran `git config --global --unset {key}` to remove "
                    "the hijacked setting."
                ),
                risk_level=RiskLevel.MODERATE,
                kind=ActionKind.MUTATION,
                executed=True,
                success=success,
                error=None if success else (getattr(result, "stderr", None) or "unset failed"),
            )
        except (subprocess.TimeoutExpired, OSError) as e:
            return Action(
                title=f"Reset git {key}",
                description=f"Failed to run git config --global --unset {key}",
                risk_level=RiskLevel.MODERATE,
                kind=ActionKind.MUTATION,
                executed=True,
                success=False,
                error=str(e),
            )

    def _fix_npmrc_override(self, finding: Finding) -> Action:
        path_str = finding.data.get("path")
        if not path_str:
            return Action(
                title="Remove npmrc git=node override",
                description="No path recorded for this finding",
                risk_level=RiskLevel.MODERATE,
                executed=True,
                success=False,
                error="missing path",
            )
        path = Path(path_str)
        try:
            if not path.is_file():
                return Action(
                    title=f"Remove npmrc override: {path}",
                    description=f"File already removed: {path}",
                    risk_level=RiskLevel.SAFE,
                    executed=True,
                    success=True,
                )
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
            new_lines = [line for line in lines if line.strip() != "git=node"]
            if len(new_lines) != len(lines):
                new_content = "\n".join(new_lines)
                if new_content:
                    new_content += "\n"
                path.write_text(new_content, encoding="utf-8")
            return Action(
                title=f"Remove npmrc override: {path}",
                description=f"Removed 'git=node' line(s) from {path}",
                risk_level=RiskLevel.MODERATE,
                kind=ActionKind.MUTATION,
                executed=True,
                success=True,
            )
        except OSError as e:
            return Action(
                title=f"Remove npmrc override: {path}",
                description=f"Failed to edit {path}",
                risk_level=RiskLevel.MODERATE,
                kind=ActionKind.MUTATION,
                executed=True,
                success=False,
                error=str(e),
            )

    def _fix_rogue_mcp_server(self, finding: Finding) -> Action:
        config_path = finding.data.get("config_path")
        server_name = finding.data.get("server_name")
        if not config_path or not server_name:
            return Action(
                title="Remove rogue MCP server",
                description="Missing config_path/server_name on finding",
                risk_level=RiskLevel.MODERATE,
                executed=True,
                success=False,
                error="missing data",
            )
        path = Path(config_path).expanduser()
        try:
            if not path.is_file():
                return Action(
                    title=f"Remove rogue MCP server: {server_name}",
                    description=f"Config file already removed: {path}",
                    risk_level=RiskLevel.SAFE,
                    executed=True,
                    success=True,
                )
            data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
            removed = False
            if isinstance(data, dict) and isinstance(data.get("mcpServers"), dict):
                if server_name in data["mcpServers"]:
                    del data["mcpServers"][server_name]
                    removed = True
            if removed:
                path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
            return Action(
                title=f"Remove rogue MCP server: {server_name}",
                description=(
                    f"Removed '{server_name}' from {path}"
                    if removed
                    else f"'{server_name}' not found in {path} (already removed?)"
                ),
                risk_level=RiskLevel.MODERATE,
                kind=ActionKind.MUTATION,
                executed=True,
                success=True,
            )
        except (OSError, ValueError) as e:
            return Action(
                title=f"Remove rogue MCP server: {server_name}",
                description=f"Failed to edit {path}",
                risk_level=RiskLevel.MODERATE,
                kind=ActionKind.MUTATION,
                executed=True,
                success=False,
                error=str(e),
            )

    def _fix_repo_hook_file(self, finding: Finding) -> Action:
        path_str = finding.data.get("path")
        if not path_str:
            return Action(
                title="Quarantine repo hook file",
                description="No path recorded for this finding",
                risk_level=RiskLevel.MODERATE,
                executed=True,
                success=False,
                error="missing path",
            )
        src = Path(path_str)
        quarantine_dir = Path.home() / ".rescue_quarantine"
        try:
            if not src.exists():
                return Action(
                    title=f"Quarantine: {src.name}",
                    description=f"File already removed: {src}",
                    risk_level=RiskLevel.SAFE,
                    executed=True,
                    success=True,
                )
            quarantine_dir.mkdir(parents=True, exist_ok=True)
            dest = quarantine_dir / f"{src.parent.name}_{src.name}"
            shutil.move(str(src), str(dest))
            return Action(
                title=f"Quarantine: {src.name}",
                description=f"Moved {src} to {dest}",
                risk_level=RiskLevel.MODERATE,
                kind=ActionKind.MUTATION,
                executed=True,
                success=True,
            )
        except OSError as e:
            return Action(
                title=f"Quarantine: {src.name}",
                description=f"Failed to quarantine {src}",
                risk_level=RiskLevel.MODERATE,
                kind=ActionKind.MUTATION,
                executed=True,
                success=False,
                error=str(e),
            )
