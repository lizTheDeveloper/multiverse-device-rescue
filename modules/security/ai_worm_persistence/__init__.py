import csv
import io
import json
import os
import re
import subprocess
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
def _load_iocs():
    try:
        from modules.security.ai_worm_iocs.loader import load_iocs

        return load_iocs()
    except Exception:
        return None


_iocs_cache = _load_iocs()


# Known malicious macOS LaunchAgent labels used by the Miasma worm. The
# gh-token-monitor agent is a dead-man switch: it runs `rm -rf ~/` if its
# stolen GitHub PAT starts returning 4xx (i.e. gets revoked), so it must be
# disabled with extreme care and always BEFORE other persistence removal.
_KNOWN_MALICIOUS_LAUNCHAGENT_LABELS = {
    "com.user.gh-token-monitor": {"threat": "miasma", "is_deadman_switch": True},
    "com.user.update-monitor": {"threat": "miasma", "is_deadman_switch": False},
}

# Equivalent rogue systemd --user unit names on Linux.
_KNOWN_MALICIOUS_SYSTEMD_UNITS = {
    "gh-token-monitor.service": {"threat": "miasma", "is_deadman_switch": True},
    "update-monitor.service": {"threat": "miasma", "is_deadman_switch": False},
}

# Heuristic markers for persistence artifacts that aren't (yet) in the IOC
# database: references to the `bun` runtime (Miasma's payload interpreter)
# or well-known AI API endpoints being called from a background agent.
_HEURISTIC_PERSISTENCE_PATTERNS = [
    re.compile(r"\bbun\b"),
    re.compile(r"api\.anthropic\.com"),
    re.compile(r"api\.openai\.com"),
    re.compile(r"generativelanguage\.googleapis\.com"),
]

_SHELL_PROFILE_FILES = [
    "~/.bashrc",
    "~/.zshrc",
    "~/.bash_profile",
    "~/.profile",
    "~/.zprofile",
]

_SHELL_INJECTION_PATTERNS = [
    re.compile(r"curl\s+[^\n|]*\|\s*(sudo\s+)?(bash|sh|zsh|python3?|node)\b"),
    re.compile(r"wget\s+[^\n|]*\|\s*(sudo\s+)?(bash|sh|zsh|python3?|node)\b"),
    re.compile(r"wget\s+-O\s*-\s+[^\n|]*\|\s*(bash|sh|zsh)\b"),
    re.compile(r"eval\s*[\"'(]?\s*\$\(\s*(curl|wget)\b"),
    re.compile(r"eval\s+.*base64\s+(-d|--decode)\b"),
    re.compile(r"eval\s*\(\s*atob\s*\("),
    re.compile(r"source\s+/tmp/\S+"),
    re.compile(r"source\s+~/\.[\w./-]*/[\w.-]+\.sh"),
]

_WIN_SUSPICIOUS_MARKERS = [
    "%temp%",
    "\\temp\\",
    "%appdata%",
    "\\appdata\\local\\temp",
    "\\appdata\\roaming",
]


class Module(ModuleBase):
    name = "ai_worm_persistence"
    category = "security"
    platforms = [Platform.DARWIN, Platform.LINUX, Platform.WIN32]
    risk_level = RiskLevel.DESTRUCTIVE
    priority = 57
    depends_on = []
    estimated_duration = "10s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings: list[Finding] = []

        if profile.platform == Platform.DARWIN:
            for raw in self._check_launchagents_darwin():
                findings.append(self._finding_from_launchagent(raw))

        if profile.platform == Platform.LINUX:
            for raw in self._check_systemd_linux():
                findings.append(self._finding_from_systemd(raw))

        if profile.platform == Platform.WIN32:
            for raw in self._check_scheduled_tasks_win():
                findings.append(self._finding_from_scheduled_task(raw))

        for raw in self._check_shell_profiles():
            findings.append(self._finding_from_shell_profile(raw))

        for raw in self._check_sessionstart_hooks():
            findings.append(self._finding_from_sessionstart_hook(raw))

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions: list[Action] = []

        # CRITICAL: dead-man switch persistence must be disabled before any
        # other remediation. Removing e.g. a normal LaunchAgent first could
        # be interpreted by a still-running dead-man switch watcher as
        # tampering, or simply race with it — always neutralize the
        # dead-man switch first.
        ordered = sorted(
            findings.findings,
            key=lambda f: 0 if f.data.get("is_deadman_switch") else 1,
        )

        for finding in ordered:
            confidence = finding.data.get("confidence", "low")
            check = finding.data.get("check")

            if confidence != "high":
                actions.append(self._investigate_action(finding))
                continue

            if check == "malicious_launchagent":
                actions.append(self._fix_launchagent(finding))
            elif check == "malicious_systemd_unit":
                actions.append(self._fix_systemd_unit(finding))
            elif check == "scheduled_task_persistence":
                actions.append(self._fix_scheduled_task(finding))
            elif check == "shell_profile_injection":
                actions.append(self._fix_shell_profile(finding))
            elif check == "sessionstart_hook":
                actions.append(self._fix_sessionstart_hook(finding))
            else:
                actions.append(self._investigate_action(finding))

        return FixResult(module_name=self.name, actions=actions)

    # -- detection: macOS LaunchAgents ------------------------------------

    def _check_launchagents_darwin(self) -> list[dict]:
        results: list[dict] = []
        la_dir = Path.home() / "Library" / "LaunchAgents"
        try:
            if not la_dir.exists():
                return results
            plists = list(la_dir.glob("*.plist"))
        except OSError:
            return results

        for plist in plists:
            try:
                if not plist.is_file():
                    continue
                content = plist.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue

            label_match = re.search(
                r"<key>Label</key>\s*<string>([^<]+)</string>", content
            )
            label = label_match.group(1) if label_match else plist.stem

            known = _KNOWN_MALICIOUS_LAUNCHAGENT_LABELS.get(label)
            if known:
                results.append(
                    {
                        "plist": str(plist),
                        "label": label,
                        "threat": known["threat"],
                        "is_deadman_switch": known["is_deadman_switch"],
                        "confidence": "high",
                    }
                )
                continue

            for pat in _HEURISTIC_PERSISTENCE_PATTERNS:
                if pat.search(content):
                    results.append(
                        {
                            "plist": str(plist),
                            "label": label,
                            "threat": "unknown",
                            "is_deadman_switch": False,
                            "confidence": "medium",
                        }
                    )
                    break

        return results

    def _finding_from_launchagent(self, raw: dict) -> Finding:
        confidence = raw.get("confidence", "high")
        severity = Severity.CRITICAL if confidence == "high" else Severity.WARNING
        plist = raw.get("plist")
        label = raw.get("label") or (Path(plist).stem if plist else "unknown")
        threat = raw.get("threat", "unknown")
        is_deadman = bool(raw.get("is_deadman_switch", False))

        title = f"Malicious LaunchAgent detected: {label}"
        description = (
            f"LaunchAgent '{label}' at {plist} matches a known {threat} "
            "persistence mechanism."
        )
        if is_deadman:
            title = f"Dead-man switch LaunchAgent detected: {label}"
            description += (
                " WARNING: this is a dead-man switch — it is designed to "
                "trigger destructive action (e.g. rm -rf ~/) if its "
                "monitored credential is revoked or it is tampered with. "
                "Disable it before removing any other persistence."
            )

        return Finding(
            title=title,
            description=description,
            severity=severity,
            category=self.category,
            data={
                "check": "malicious_launchagent",
                "confidence": confidence,
                "plist": plist,
                "label": label,
                "threat": threat,
                "is_deadman_switch": is_deadman,
            },
        )

    # -- detection: Linux systemd --user units ----------------------------

    def _check_systemd_linux(self) -> list[dict]:
        results: list[dict] = []
        unit_dir = Path.home() / ".config" / "systemd" / "user"
        try:
            if not unit_dir.exists():
                return results
            units = list(unit_dir.glob("*.service"))
        except OSError:
            return results

        known_paths = {}
        if _iocs_cache is not None:
            for entry in _iocs_cache.paths:
                if "linux" in entry.platforms and entry.type in (
                    "persistence",
                    "deadman_switch",
                ):
                    known_paths[entry.path] = entry

        for unit in units:
            try:
                if not unit.is_file():
                    continue
                content = unit.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue

            unit_name = unit.name
            known = _KNOWN_MALICIOUS_SYSTEMD_UNITS.get(unit_name)
            if known:
                results.append(
                    {
                        "unit": str(unit),
                        "unit_name": unit.stem,
                        "threat": known["threat"],
                        "is_deadman_switch": known["is_deadman_switch"],
                        "confidence": "high",
                    }
                )
                continue

            matched_ioc = None
            for path_str, ioc in known_paths.items():
                marker = Path(path_str).name
                if marker and marker in content:
                    matched_ioc = ioc
                    break

            if matched_ioc:
                results.append(
                    {
                        "unit": str(unit),
                        "unit_name": unit.stem,
                        "threat": matched_ioc.threat,
                        "is_deadman_switch": matched_ioc.type == "deadman_switch",
                        "confidence": "high",
                    }
                )
                continue

            for pat in _HEURISTIC_PERSISTENCE_PATTERNS:
                if pat.search(content):
                    results.append(
                        {
                            "unit": str(unit),
                            "unit_name": unit.stem,
                            "threat": "unknown",
                            "is_deadman_switch": False,
                            "confidence": "medium",
                        }
                    )
                    break

        return results

    def _finding_from_systemd(self, raw: dict) -> Finding:
        confidence = raw.get("confidence", "medium")
        severity = Severity.CRITICAL if confidence == "high" else Severity.WARNING
        unit = raw.get("unit")
        unit_name = raw.get("unit_name") or (Path(unit).stem if unit else "unknown")
        threat = raw.get("threat", "unknown")
        is_deadman = bool(raw.get("is_deadman_switch", False))

        title = f"Malicious systemd unit detected: {unit_name}"
        description = (
            f"systemd --user unit '{unit_name}' at {unit} matches a known "
            f"{threat} persistence mechanism."
        )
        if is_deadman:
            title = f"Dead-man switch systemd unit detected: {unit_name}"
            description += (
                " WARNING: this is a dead-man switch — disable it before "
                "removing any other persistence."
            )

        return Finding(
            title=title,
            description=description,
            severity=severity,
            category=self.category,
            data={
                "check": "malicious_systemd_unit",
                "confidence": confidence,
                "unit": unit,
                "unit_name": unit_name,
                "threat": threat,
                "is_deadman_switch": is_deadman,
            },
        )

    # -- detection: Windows scheduled tasks --------------------------------

    def _check_scheduled_tasks_win(self) -> list[dict]:
        results: list[dict] = []
        try:
            proc = subprocess.run(
                ["schtasks", "/Query", "/FO", "CSV", "/V"],
                capture_output=True,
                text=True,
                timeout=15,
            )
        except (subprocess.TimeoutExpired, OSError):
            return results

        output = getattr(proc, "stdout", "") or ""
        if not output.strip():
            return results

        try:
            reader = csv.DictReader(io.StringIO(output))
            rows = list(reader)
        except csv.Error:
            return results

        for row in rows:
            task_to_run = (row.get("Task To Run") or "").strip()
            task_name = (row.get("TaskName") or "").strip()
            if not task_to_run:
                continue
            lowered = task_to_run.lower()
            if any(marker in lowered for marker in _WIN_SUSPICIOUS_MARKERS):
                results.append(
                    {
                        "task_name": task_name,
                        "command": task_to_run,
                        "threat": "unknown",
                        "is_deadman_switch": False,
                        "confidence": "medium",
                    }
                )

        return results

    def _finding_from_scheduled_task(self, raw: dict) -> Finding:
        confidence = raw.get("confidence", "medium")
        severity = Severity.CRITICAL if confidence == "high" else Severity.WARNING
        task_name = raw.get("task_name") or "unknown"

        return Finding(
            title=f"Suspicious scheduled task: {task_name}",
            description=(
                f"Scheduled task '{task_name}' runs "
                f"'{raw.get('command')}' from a temp/appdata location — a "
                "common persistence technique."
            ),
            severity=severity,
            category=self.category,
            data={
                "check": "scheduled_task_persistence",
                "confidence": confidence,
                "task_name": task_name,
                "command": raw.get("command"),
                "threat": raw.get("threat", "unknown"),
                "is_deadman_switch": bool(raw.get("is_deadman_switch", False)),
            },
        )

    # -- detection: shell profile injection --------------------------------

    def _check_shell_profiles(self) -> list[dict]:
        results: list[dict] = []
        for rel in _SHELL_PROFILE_FILES:
            path = Path(rel).expanduser()
            try:
                if not path.is_file():
                    continue
                content = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue

            for line_number, line in enumerate(content.splitlines(), start=1):
                for pat in _SHELL_INJECTION_PATTERNS:
                    if pat.search(line):
                        results.append(
                            {
                                "file": str(path),
                                "line": line.strip(),
                                "line_number": line_number,
                                "confidence": "medium",
                            }
                        )
                        break

        return results

    def _finding_from_shell_profile(self, raw: dict) -> Finding:
        confidence = raw.get("confidence", "medium")
        if confidence == "high":
            severity = Severity.CRITICAL
        elif confidence == "medium":
            severity = Severity.WARNING
        else:
            severity = Severity.INFO

        file_ = raw.get("file")
        line = raw.get("line")
        line_number = raw.get("line_number")

        return Finding(
            title=f"Suspicious shell profile injection in {file_}",
            description=(
                f"Line {line_number} of {file_} contains a pattern "
                f"associated with worm persistence: {line}"
            ),
            severity=severity,
            category=self.category,
            data={
                "check": "shell_profile_injection",
                "confidence": confidence,
                "file": file_,
                "line": line,
                "line_number": line_number,
            },
        )

    # -- detection: Claude Code SessionStart hooks -------------------------

    def _check_sessionstart_hooks(self) -> list[dict]:
        results: list[dict] = []
        settings_path = Path.home() / ".claude" / "settings.json"
        try:
            if not settings_path.is_file():
                return results
            data = json.loads(
                settings_path.read_text(encoding="utf-8", errors="ignore")
            )
        except (OSError, ValueError):
            return results

        if not isinstance(data, dict):
            return results
        hooks = data.get("hooks")
        if not isinstance(hooks, dict):
            return results
        session_start = hooks.get("SessionStart")
        if not session_start:
            return results

        known_markers = []
        if _iocs_cache is not None:
            for entry in _iocs_cache.paths:
                if entry.type in ("hook", "payload", "dropper"):
                    known_markers.append(entry.path)

        for command in self._extract_hook_commands(session_start):
            matched = any(marker in command for marker in known_markers)
            results.append(
                {
                    "path": str(settings_path),
                    "command": command,
                    "threat": "sandworm_mode" if matched else "unknown",
                    "is_deadman_switch": False,
                    "confidence": "high" if matched else "low",
                }
            )

        return results

    def _extract_hook_commands(self, session_start) -> list[str]:
        commands: list[str] = []
        if isinstance(session_start, list):
            for entry in session_start:
                if not isinstance(entry, dict):
                    continue
                inner_hooks = entry.get("hooks")
                if isinstance(inner_hooks, list):
                    for h in inner_hooks:
                        if isinstance(h, dict) and "command" in h:
                            commands.append(str(h["command"]))
                elif "command" in entry:
                    commands.append(str(entry["command"]))
        elif isinstance(session_start, dict):
            for h in session_start.values():
                if isinstance(h, dict) and "command" in h:
                    commands.append(str(h["command"]))
        return commands

    def _finding_from_sessionstart_hook(self, raw: dict) -> Finding:
        confidence = raw.get("confidence", "low")
        if confidence == "high":
            severity = Severity.CRITICAL
        elif confidence == "medium":
            severity = Severity.WARNING
        else:
            severity = Severity.INFO

        title = (
            "Known malicious SessionStart hook detected"
            if confidence == "high"
            else "SessionStart hook present (review manually)"
        )

        return Finding(
            title=title,
            description=(
                f"SessionStart hook command in {raw.get('path')}: "
                f"{raw.get('command')}"
            ),
            severity=severity,
            category=self.category,
            data={
                "check": "sessionstart_hook",
                "confidence": confidence,
                "path": raw.get("path"),
                "command": raw.get("command"),
                "threat": raw.get("threat", "unknown"),
                "is_deadman_switch": bool(raw.get("is_deadman_switch", False)),
            },
        )

    # -- fix actions --------------------------------------------------------

    def _fix_launchagent(self, finding: Finding) -> Action:
        plist_str = finding.data.get("plist")
        is_deadman = bool(finding.data.get("is_deadman_switch", False))
        label = finding.data.get("label") or (
            Path(plist_str).stem if plist_str else "unknown"
        )

        title = (
            f"Disable dead-man switch LaunchAgent: {label}"
            if is_deadman
            else f"Disable LaunchAgent: {label}"
        )
        description = (
            f"Ran `launchctl unload` on {plist_str} and removed the plist "
            f"to disable {label} persistence."
        )
        if is_deadman:
            description = (
                "WARNING: this is a dead-man switch that may execute "
                "destructive code if disabled incorrectly. Unloaded and "
                "removed it before any other persistence remediation. "
            ) + description

        try:
            subprocess.run(
                ["launchctl", "unload", plist_str],
                capture_output=True,
                text=True,
                timeout=10,
            )
        except (subprocess.TimeoutExpired, OSError) as e:
            return Action(
                title=title,
                description=f"Failed to unload {plist_str}",
                risk_level=RiskLevel.DESTRUCTIVE,
                kind=ActionKind.MUTATION,
                executed=True,
                success=False,
                error=str(e),
            )

        try:
            if plist_str:
                try:
                    os.remove(plist_str)
                except FileNotFoundError:
                    pass
            return Action(
                title=title,
                description=description,
                risk_level=RiskLevel.DESTRUCTIVE,
                kind=ActionKind.MUTATION,
                executed=True,
                success=True,
            )
        except OSError as e:
            return Action(
                title=title,
                description=f"Failed to remove {plist_str}",
                risk_level=RiskLevel.DESTRUCTIVE,
                kind=ActionKind.MUTATION,
                executed=True,
                success=False,
                error=str(e),
            )

    def _fix_systemd_unit(self, finding: Finding) -> Action:
        unit_path = finding.data.get("unit")
        is_deadman = bool(finding.data.get("is_deadman_switch", False))
        unit_name = finding.data.get("unit_name") or (
            Path(unit_path).stem if unit_path else "unknown"
        )
        unit_file_name = f"{unit_name}.service"

        title = (
            f"Disable dead-man switch systemd unit: {unit_name}"
            if is_deadman
            else f"Disable systemd unit: {unit_name}"
        )
        description = (
            f"Stopped and disabled the {unit_file_name} systemd --user unit "
            f"and removed {unit_path}."
        )
        if is_deadman:
            description = (
                "WARNING: this is a dead-man switch that may execute "
                "destructive code if disabled incorrectly. Stopped and "
                "removed it before any other persistence remediation. "
            ) + description

        try:
            subprocess.run(
                ["systemctl", "--user", "stop", unit_file_name],
                capture_output=True,
                text=True,
                timeout=10,
            )
            subprocess.run(
                ["systemctl", "--user", "disable", unit_file_name],
                capture_output=True,
                text=True,
                timeout=10,
            )
        except (subprocess.TimeoutExpired, OSError) as e:
            return Action(
                title=title,
                description=f"Failed to stop/disable {unit_file_name}",
                risk_level=RiskLevel.DESTRUCTIVE,
                kind=ActionKind.MUTATION,
                executed=True,
                success=False,
                error=str(e),
            )

        try:
            if unit_path:
                try:
                    os.remove(unit_path)
                except FileNotFoundError:
                    pass
            return Action(
                title=title,
                description=description,
                risk_level=RiskLevel.DESTRUCTIVE,
                kind=ActionKind.MUTATION,
                executed=True,
                success=True,
            )
        except OSError as e:
            return Action(
                title=title,
                description=f"Failed to remove {unit_path}",
                risk_level=RiskLevel.DESTRUCTIVE,
                kind=ActionKind.MUTATION,
                executed=True,
                success=False,
                error=str(e),
            )

    def _fix_scheduled_task(self, finding: Finding) -> Action:
        task_name = finding.data.get("task_name")
        title = f"Delete scheduled task: {task_name}"
        try:
            result = subprocess.run(
                ["schtasks", "/Delete", "/TN", task_name, "/F"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            success = result.returncode == 0
            error = None if success else (getattr(result, "stderr", None) or "delete failed")
        except (subprocess.TimeoutExpired, OSError) as e:
            success, error = False, str(e)

        return Action(
            title=title,
            description=(
                f"Deleted scheduled task '{task_name}' that ran a script "
                "from a suspicious temp/appdata location."
            ),
            risk_level=RiskLevel.DESTRUCTIVE,
            kind=ActionKind.MUTATION,
            executed=True,
            success=success,
            error=error,
        )

    def _fix_shell_profile(self, finding: Finding) -> Action:
        file_str = finding.data.get("file")
        line_number = finding.data.get("line_number")
        line_content = finding.data.get("line") or ""
        title = f"Remove injected line from {Path(file_str).name if file_str else 'shell profile'}"

        try:
            path = Path(file_str).expanduser()
            if not path.is_file():
                return Action(
                    title=title,
                    description=f"File already modified or removed: {file_str}",
                    risk_level=RiskLevel.SAFE,
                    kind=ActionKind.MUTATION,
                    executed=True,
                    success=True,
                )
            lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
            new_lines = [l for l in lines if l.strip() != line_content.strip()]
            new_content = "\n".join(new_lines)
            if new_content:
                new_content += "\n"
            path.write_text(new_content, encoding="utf-8")
            return Action(
                title=title,
                description=f"Removed suspicious line {line_number} from {file_str}",
                risk_level=RiskLevel.DESTRUCTIVE,
                kind=ActionKind.MUTATION,
                executed=True,
                success=True,
            )
        except OSError as e:
            return Action(
                title=title,
                description=f"Failed to edit {file_str}",
                risk_level=RiskLevel.DESTRUCTIVE,
                kind=ActionKind.MUTATION,
                executed=True,
                success=False,
                error=str(e),
            )

    def _fix_sessionstart_hook(self, finding: Finding) -> Action:
        path_str = finding.data.get("path")
        command = finding.data.get("command")
        title = "Remove malicious SessionStart hook"

        try:
            path = Path(path_str)
            if not path.is_file():
                return Action(
                    title=title,
                    description=f"Settings file already removed: {path_str}",
                    risk_level=RiskLevel.SAFE,
                    kind=ActionKind.MUTATION,
                    executed=True,
                    success=True,
                )
            data = json.loads(path.read_text(encoding="utf-8", errors="ignore"))
            removed = self._remove_hook_command(data, command)
            if removed:
                path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
            return Action(
                title=title,
                description=(
                    f"Removed malicious SessionStart hook from {path_str}"
                    if removed
                    else f"Hook command not found in {path_str} (already removed?)"
                ),
                risk_level=RiskLevel.DESTRUCTIVE,
                kind=ActionKind.MUTATION,
                executed=True,
                success=True,
            )
        except (OSError, ValueError) as e:
            return Action(
                title=title,
                description=f"Failed to edit {path_str}",
                risk_level=RiskLevel.DESTRUCTIVE,
                kind=ActionKind.MUTATION,
                executed=True,
                success=False,
                error=str(e),
            )

    def _remove_hook_command(self, data: dict, command: str) -> bool:
        removed = False
        if not isinstance(data, dict):
            return False
        hooks = data.get("hooks")
        if not isinstance(hooks, dict):
            return False
        session_start = hooks.get("SessionStart")
        if isinstance(session_start, list):
            for entry in session_start:
                if isinstance(entry, dict) and isinstance(entry.get("hooks"), list):
                    before = len(entry["hooks"])
                    entry["hooks"] = [
                        h
                        for h in entry["hooks"]
                        if not (isinstance(h, dict) and h.get("command") == command)
                    ]
                    if len(entry["hooks"]) != before:
                        removed = True
            hooks["SessionStart"] = [
                entry
                for entry in session_start
                if not (isinstance(entry, dict) and not entry.get("hooks"))
            ]
        return removed

    def _investigate_action(self, finding: Finding) -> Action:
        confidence = finding.data.get("confidence", "low")
        return Action(
            title=f"Investigate: {finding.title}",
            description=(
                f"Manual investigation recommended. "
                f"Confidence: {confidence}. {finding.description}"
            ),
            risk_level=RiskLevel.SAFE,
            kind=ActionKind.GUIDANCE,
            executed=True,
            success=True,
        )
