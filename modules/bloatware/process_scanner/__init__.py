import json
from pathlib import Path

from rescue.models import (
    Action,
    CheckResult,
    Finding,
    FixResult,
    Mode,
    Platform,
    ProcessInfo,
    RiskLevel,
    Severity,
    SystemProfile,
)
from rescue.module_base import ModuleBase

DATA_FILE = Path(__file__).parent / "data" / "known_bloatware.json"
CRITICAL_CATEGORIES = {"scareware"}


class Module(ModuleBase):
    name = "process_scanner"
    category = "bloatware"
    platforms = [Platform.DARWIN, Platform.WIN32, Platform.LINUX]
    risk_level = RiskLevel.MODERATE
    priority = 75
    depends_on = []
    estimated_duration = "5s"

    def check(self, profile: SystemProfile) -> CheckResult:
        known_bloatware = _load_known_bloatware()
        findings = []
        for proc in profile.processes:
            entry = _match_bloatware(proc, known_bloatware)
            if entry is not None:
                severity = (
                    Severity.CRITICAL
                    if entry["category"] in CRITICAL_CATEGORIES
                    else Severity.WARNING
                )
                findings.append(self._make_finding(proc, entry, severity))
        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            pid = finding.data.get("pid")
            name = finding.data.get("bloatware_name", "unknown")
            category = finding.data.get("bloatware_category", "unknown")
            actions.append(
                Action(
                    title=f"Suspicious process detected: {name} (pid {pid})",
                    description=(
                        f"Found {name} (pid {pid}), identified as {category}. "
                        f"This process is suspicious and may impact system performance. "
                        f"Consider terminating this process manually if it is not needed."
                    ),
                    risk_level=RiskLevel.MODERATE,
                    success=True,
                )
            )
        return FixResult(module_name=self.name, actions=actions)

    def _make_finding(
        self, proc: ProcessInfo, entry: dict, severity: Severity
    ) -> Finding:
        return Finding(
            title=f"{entry['name']} detected running",
            description=entry["description"],
            severity=severity,
            category=self.category,
            data={
                "pid": proc.pid,
                "process_name": proc.name,
                "bloatware_name": entry["name"],
                "bloatware_category": entry["category"],
            },
        )


def _load_known_bloatware() -> list[dict]:
    with open(DATA_FILE) as f:
        return json.load(f)


def _match_bloatware(proc: ProcessInfo, known_bloatware: list[dict]) -> dict | None:
    haystack = f"{proc.name} {proc.command}".lower()
    for entry in known_bloatware:
        if entry["process_pattern"].lower() in haystack:
            return entry
    return None
