import json
import os
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

DATA_FILE = content_file("modules/bloatware/startup_auditor/data/known_bloatware.json")


class Module(ModuleBase):
    name = "startup_auditor"
    category = "bloatware"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.MODERATE
    priority = 60
    depends_on = []
    estimated_duration = "5s"

    def check(self, profile: SystemProfile) -> CheckResult:
        output = self._run_launchctl_list()
        labels = _parse_launchctl_list(output)
        known_bloatware = _load_known_bloatware()

        findings = []
        for label in labels:
            entry = _match_bloatware(label, known_bloatware)
            if entry is not None:
                findings.append(
                    Finding(
                        title=f"Startup item: {entry['name']}",
                        description=entry["description"],
                        severity=Severity.WARNING,
                        category=self.category,
                        data={"label": label, "name": entry["name"]},
                    )
                )
        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            label = finding.data["label"]
            name = finding.data.get("name", label)
            plist_path = os.path.expanduser(f"~/Library/LaunchAgents/{label}.plist")
            try:
                result = subprocess.run(
                    ["launchctl", "unload", "-w", plist_path],
                    capture_output=True,
                    text=True,
                )
                success = result.returncode == 0
                error = None if success else (
                    result.stderr.strip() or "launchctl unload failed"
                )
            except OSError as e:
                success = False
                error = str(e)
            actions.append(
                Action(
                    title=f"Disable startup item: {name}",
                    description=(
                        f"Unloaded launchd job '{label}'. If it reappears at "
                        f"next login, remove the file at {plist_path}."
                    ),
                    risk_level=RiskLevel.MODERATE,
                    kind=ActionKind.MUTATION,
                    executed=True,
                    success=success,
                    error=error,
                )
            )
        return FixResult(module_name=self.name, actions=actions)

    def _run_launchctl_list(self) -> str:
        result = subprocess.run(
            ["launchctl", "list"],
            capture_output=True,
            text=True,
        )
        return result.stdout


def _parse_launchctl_list(output: str) -> list[str]:
    labels = []
    lines = output.strip().split("\n")
    for line in lines[1:]:
        parts = line.split()
        if len(parts) >= 3:
            labels.append(parts[-1])
    return labels


def _load_known_bloatware() -> list[dict]:
    with open(DATA_FILE) as f:
        return json.load(f)


def _match_bloatware(label: str, known_bloatware: list[dict]) -> dict | None:
    label_lower = label.lower()
    for entry in known_bloatware:
        if entry["label_pattern"].lower() in label_lower:
            return entry
    return None
