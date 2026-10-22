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
from rescue.runtime import content_file

DATA_FILE = content_file("modules/bloatware/process_scanner/data/known_bloatware.json")
# Categories where the software's own purpose is the harm: scareware extracts
# money through invented problems, and a miner spends the owner's electricity
# on someone else's behalf. Adware and bundled programs are a nuisance and are
# reported as warnings.
CRITICAL_CATEGORIES = {"scareware", "cryptominer"}


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
        category = entry["category"]
        return Finding(
            title=f"{entry['name']} is running in the background",
            description=_describe(entry),
            severity=severity,
            category=self.category,
            data={
                "check": category,
                "pid": proc.pid,
                "process_name": proc.name,
                "bloatware_name": entry["name"],
                "bloatware_category": category,
            },
        )


# Adware, scareware and miners are harmful on purpose, so they never say "you
# can usually ignore this": each says what it does first. A bundled extra
# ("pup") keeps the clutter wording.
_HARMFUL_FIRST_LINE = {
    "adware": "This program shows unwanted ads or changes your browser",
    "scareware": "This program shows fake warnings to get you to pay",
    "cryptominer": "This program uses your computer to make money for someone else",
}

_STOP_IT = (
    "search for 'Task Manager' (Windows) or 'Activity Monitor' (Mac), find the "
    "name above, and choose 'End Task' or 'Quit'."
)


def _describe(entry: dict) -> str:
    name = entry["name"]
    first = _HARMFUL_FIRST_LINE.get(entry["category"])
    if first is None:
        return (
            f"We found {name} running on your device. This is a known program "
            "that often uses system resources for no good reason.\n\n"
            f"Here is what we know about it: {entry['description']}\n\n"
            "What to do: You can usually ignore this. If you want to stop it, "
            + _STOP_IT
            + " Do not delete any files."
        )
    return (
        f"{first}: we found {name} running on your device.\n\n"
        f"Here is what we know about it: {entry['description']}\n\n"
        "What to do: Stop it: " + _STOP_IT + " Then remove the app it came with. "
        "Don't pay for anything it asks you to buy, and don't call a number it shows."
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
