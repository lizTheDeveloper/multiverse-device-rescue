"""Look for software installed to watch the person using this computer.

There are three overlapping things here and they need to be told apart, not
lumped together:

- Stalkerware: sold for covertly monitoring another adult. Its presence on a
  personal machine is the finding.
- Workplace and parental monitoring: legitimate products in the setting they
  were designed for, routinely repurposed to control a partner or an adult
  family member. Reported with the context needed to judge it.
- Remote access tools: ordinary IT software that happens to give someone else
  full control of the machine. Reported so it can be accounted for, not
  because it is malicious.

The safety guidance in ``fix()`` matters as much as the detection. For someone
being monitored by a person they live with, removing the software is not
automatically the right first move: it tells the person watching that they
have been found out. That warning comes before any removal instruction.
"""

import json
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
from rescue.runtime import content_file

DATA_FILE = content_file("modules/security/stalkerware_scan/data/known_stalkerware.json")

_COMMAND_TIMEOUT = 20
_MAX_FILES_PER_LOCATION = 300

_SEVERITY_BY_NAME = {
    "critical": Severity.CRITICAL,
    "warning": Severity.WARNING,
    "info": Severity.INFO,
}

_DARWIN_APP_DIRS = [
    "/Applications",
    "~/Applications",
]

_DARWIN_PERSISTENCE_DIRS = [
    "~/Library/LaunchAgents",
    "/Library/LaunchAgents",
    "/Library/LaunchDaemons",
]

_WIN_UNINSTALL_KEYS = [
    r"HKLM\Software\Microsoft\Windows\CurrentVersion\Uninstall",
    r"HKLM\Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall",
    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Uninstall",
]

_SAFETY_WARNING = (
    "Before removing anything: if the person who may have installed this lives "
    "with you, or has ever frightened you, removing it can be dangerous. "
    "Monitoring software usually tells whoever set it up when it stops "
    "reporting, and that can escalate the situation. Talk to a domestic abuse "
    "advocate first — in the US, the National Domestic Violence Hotline is "
    "1-800-799-7233, and the Coalition Against Stalkerware "
    "(stopstalkerware.org) lists services in other countries. They can help "
    "you plan the order in which to do this safely."
)


class Module(ModuleBase):
    name = "stalkerware_scan"
    category = "security"
    platforms = [Platform.DARWIN, Platform.WIN32, Platform.LINUX]
    risk_level = RiskLevel.SAFE
    priority = 82
    depends_on = []
    estimated_duration = "20s"

    def check(self, profile: SystemProfile) -> CheckResult:
        entries = _load_known_stalkerware()
        if not entries:
            return CheckResult(
                module_name=self.name,
                error="Stalkerware indicator data could not be loaded.",
            )

        platform = profile.platform.value
        applicable = [e for e in entries if platform in e.get("platforms", [])]

        observations: list[tuple[dict, str, str]] = []
        observations.extend(self._scan_processes(profile, applicable))
        observations.extend(self._scan_installed_software(profile, applicable))

        if profile.platform == Platform.DARWIN:
            observations.extend(self._scan_darwin_paths(applicable))
        elif profile.platform == Platform.WIN32:
            observations.extend(self._scan_windows_uninstall_entries(applicable))

        return CheckResult(
            module_name=self.name, findings=self._to_findings(observations)
        )

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        """Guidance only, and safety guidance first."""
        actions: list[Action] = []
        if not findings.findings:
            return FixResult(module_name=self.name, actions=actions)

        categories = {f.data.get("stalkerware_category") for f in findings.findings}

        if "stalkerware" in categories:
            actions.append(
                Action(
                    title="Read this before removing the monitoring software",
                    description=_SAFETY_WARNING,
                    risk_level=RiskLevel.SAFE,
                    kind=ActionKind.GUIDANCE,
                    success=True,
                )
            )
            actions.append(
                Action(
                    title="Use a different device for anything sensitive",
                    description=(
                        "Assume everything typed on this computer — passwords, "
                        "messages, searches, plans — has been seen. Until it is "
                        "cleaned up, use a device the other person has never had "
                        "physical access to, on a network they do not control, for "
                        "anything that matters. Do not change your important passwords "
                        "from this computer: the monitoring software would capture the "
                        "new ones as you type them."
                    ),
                    risk_level=RiskLevel.SAFE,
                    kind=ActionKind.GUIDANCE,
                    success=True,
                )
            )
            actions.append(
                Action(
                    title="Preserve evidence before you delete anything",
                    description=(
                        "Monitoring another adult without consent is a crime in many "
                        "places, and the installed software is the evidence. "
                        "Photograph the screen showing the software, note the date, "
                        "and keep this scan's output. Deleting first leaves nothing to "
                        "show a police officer, a lawyer, or a judge."
                    ),
                    risk_level=RiskLevel.SAFE,
                    kind=ActionKind.GUIDANCE,
                    success=True,
                )
            )

        for finding in findings.findings:
            name = finding.data.get("stalkerware_name", "the software")
            category = finding.data.get("stalkerware_category")
            location = finding.data.get("location", "this machine")

            if category == "stalkerware":
                actions.append(
                    Action(
                        title=f"Remove {name} when it is safe to do so",
                        description=(
                            f"{name} was found at {location}. When you have a safety "
                            "plan in place:\n"
                            "1. Uninstall it through the normal uninstaller if one "
                            "exists — monitoring software often reinstalls itself if "
                            "only the visible files are deleted.\n"
                            "2. Check for a second copy: these products commonly "
                            "install both a background service and a startup entry.\n"
                            "3. Change every account password afterwards, from a "
                            "different device.\n"
                            "4. Turn on two-factor authentication for email first, "
                            "then everything else.\n"
                            "5. The most reliable cleanup for a machine that has been "
                            "monitored is a full operating-system reinstall. Consider "
                            "it if anything about the machine still feels wrong."
                        ),
                        risk_level=RiskLevel.MODERATE,
                        kind=ActionKind.GUIDANCE,
                        success=True,
                        data={"software": name},
                    )
                )
            elif category in {"employee_monitoring", "parental_control"}:
                actions.append(
                    Action(
                        title=f"Decide whether {name} belongs on this computer",
                        description=(
                            f"{name} was found at {location}. This is a legitimate "
                            "product, so the question is not whether it is malware but "
                            "whether it is supposed to be here:\n"
                            "- On a computer owned by an employer or school, it is "
                            "expected. It still means work can see activity on it, so "
                            "keep personal accounts off this machine.\n"
                            "- On a personal computer nobody told you about, someone "
                            "set it up to watch what you do. Treat it the same way as "
                            "any other monitoring software."
                        ),
                        risk_level=RiskLevel.SAFE,
                        kind=ActionKind.GUIDANCE,
                        success=True,
                        data={"software": name},
                    )
                )
            else:
                actions.append(
                    Action(
                        title=f"Account for the remote access tool {name}",
                        description=(
                            f"{name} was found at {location}. Remote access software "
                            "lets someone else see and control this screen. Check:\n"
                            "- Did you or someone you trust install it, and is it still "
                            "needed? If not, uninstall it.\n"
                            "- If it stays, open its settings and check whether "
                            "unattended access is enabled and which accounts or "
                            "devices are on its allow list. Remove anything you do not "
                            "recognise, and change its password.\n"
                            "- Software left behind after a 'tech support' phone call "
                            "should be removed, and the accounts used on this machine "
                            "should have their passwords changed."
                        ),
                        risk_level=RiskLevel.MODERATE,
                        kind=ActionKind.GUIDANCE,
                        success=True,
                        data={"software": name},
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    # ---------------- scanners ----------------

    def _scan_processes(
        self, profile: SystemProfile, entries: list[dict]
    ) -> list[tuple[dict, str, str]]:
        observations = []
        for proc in profile.processes:
            haystack = f"{proc.name} {proc.command}".lower()
            entry = _match(haystack, entries)
            if entry is not None:
                observations.append(
                    (entry, "running process", f"{proc.name} (pid {proc.pid})")
                )
        return observations

    def _scan_installed_software(
        self, profile: SystemProfile, entries: list[dict]
    ) -> list[tuple[dict, str, str]]:
        observations = []
        for software in profile.installed_software:
            entry = _match(software.lower(), entries)
            if entry is not None:
                observations.append((entry, "installed software", software))
        return observations

    def _scan_darwin_paths(self, entries: list[dict]) -> list[tuple[dict, str, str]]:
        observations = []
        for directory in _DARWIN_APP_DIRS:
            for path in _bounded_entries(directory):
                entry = _match(path.name.lower(), entries)
                if entry is not None:
                    observations.append((entry, "installed application", str(path)))
        for directory in _DARWIN_PERSISTENCE_DIRS:
            for path in _bounded_entries(directory):
                if path.suffix != ".plist":
                    continue
                entry = _match(path.name.lower(), entries)
                if entry is not None:
                    observations.append((entry, "startup item", str(path)))
        return observations

    def _scan_windows_uninstall_entries(
        self, entries: list[dict]
    ) -> list[tuple[dict, str, str]]:
        observations = []
        for key in _WIN_UNINSTALL_KEYS:
            output = _run(["reg", "query", key, "/s", "/v", "DisplayName"])
            for line in output.splitlines():
                if "DisplayName" not in line:
                    continue
                parts = line.split("REG_SZ")
                display_name = parts[-1].strip() if len(parts) > 1 else ""
                if not display_name:
                    continue
                entry = _match(display_name.lower(), entries)
                if entry is not None:
                    observations.append((entry, "installed program", display_name))
        return observations

    # ---------------- findings ----------------

    def _to_findings(
        self, observations: list[tuple[dict, str, str]]
    ) -> list[Finding]:
        findings: list[Finding] = []
        seen: set[tuple[str, str]] = set()

        for entry, where, location in observations:
            key = (entry["name"], location)
            if key in seen:
                continue
            seen.add(key)

            category = entry.get("category", "stalkerware")
            severity = _SEVERITY_BY_NAME.get(
                entry.get("severity", "warning"), Severity.WARNING
            )
            findings.append(
                Finding(
                    title=f"{entry['name']} found as {where}",
                    description=(
                        f"{entry['description']}\n\n"
                        f"Found as {where}: {location}."
                        + (
                            "\n\nThis product is sold for monitoring another person "
                            "without their knowledge. If nobody told you it was here, "
                            "someone installed it to watch what you do on this "
                            "computer."
                            if category == "stalkerware"
                            else ""
                        )
                    ),
                    severity=severity,
                    category=self.category,
                    data={
                        "check": "monitoring_software_found",
                        "stalkerware_name": entry["name"],
                        "stalkerware_category": category,
                        "detected_as": where,
                        "location": location,
                        "confidence": "high" if category == "stalkerware" else "medium",
                    },
                )
            )
        return findings


# ---------------- helpers ----------------


def _load_known_stalkerware() -> list[dict]:
    try:
        with open(DATA_FILE) as f:
            data = json.load(f)
    except (OSError, ValueError):
        return []
    entries = data.get("entries", [])
    return entries if isinstance(entries, list) else []


def _match(haystack: str, entries: list[dict]) -> dict | None:
    for entry in entries:
        if _pattern_regex(entry["pattern"]).search(haystack) is not None:
            return entry
    return None


def _pattern_regex(pattern: str) -> re.Pattern:
    """Compile a product name into a boundary-aware matcher.

    Several product names are short, ordinary words ("bark", "aobo"), so plain
    substring matching would accuse people over filenames like "barkeeper.app".
    Requiring a non-alphanumeric character on both sides keeps punctuation and
    path separators as boundaries while rejecting matches inside longer words.
    """
    cached = _PATTERN_CACHE.get(pattern)
    if cached is None:
        cached = re.compile(
            rf"(?<![a-z0-9]){re.escape(pattern.lower())}(?![a-z0-9])"
        )
        _PATTERN_CACHE[pattern] = cached
    return cached


_PATTERN_CACHE: dict[str, re.Pattern] = {}


def _bounded_entries(directory: str) -> list[Path]:
    try:
        base = Path(directory).expanduser()
        if not base.is_dir():
            return []
        return sorted(base.iterdir())[:_MAX_FILES_PER_LOCATION]
    except OSError:
        return []


def _run(command: list[str]) -> str:
    try:
        result = subprocess.run(
            command, capture_output=True, text=True, timeout=_COMMAND_TIMEOUT
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return result.stdout or ""
