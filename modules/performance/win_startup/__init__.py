import subprocess

from rescue.models import (
    Action,
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

WARNING_COUNT = 5
CRITICAL_COUNT = 10


class Module(ModuleBase):
    name = "win_startup"
    category = "performance"
    platforms = [Platform.WIN32]
    risk_level = RiskLevel.SAFE
    priority = 65
    depends_on = []
    estimated_duration = "5s"

    def check(self, profile: SystemProfile) -> CheckResult:
        output = self._run_wmic_startup()
        items = _parse_startup_list(output)

        findings = []
        if len(items) >= CRITICAL_COUNT:
            findings.append(self._make_finding(items, Severity.CRITICAL))
        elif len(items) >= WARNING_COUNT:
            findings.append(self._make_finding(items, Severity.WARNING))
        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            names = finding.data.get("names", [])
            preview = ", ".join(names[:5])
            if len(names) > 5:
                preview += ", ..."
            actions.append(
                Action(
                    title="Startup items report",
                    description=(
                        f"{finding.data.get('count', len(names))} program(s) "
                        f"launch at sign-in: {preview}. Disable unneeded ones "
                        "via Task Manager > Startup apps."
                    ),
                    risk_level=RiskLevel.SAFE,
                    success=True,
                )
            )
        return FixResult(module_name=self.name, actions=actions)

    def _make_finding(self, items: list[dict[str, str]], severity: Severity) -> Finding:
        names = [item.get("Name", "") for item in items]
        return Finding(
            title=f"{len(items)} startup programs detected",
            description=(
                f"{len(items)} program(s) are configured to launch "
                "automatically at sign-in, which can slow down boot time."
            ),
            severity=severity,
            category=self.category,
            data={"names": names, "count": len(items)},
        )

    def _run_wmic_startup(self) -> str:
        try:
            result = subprocess.run(
                ["wmic", "startup", "list", "full"],
                capture_output=True,
                text=True,
            )
            return result.stdout
        except (OSError, subprocess.SubprocessError):
            return ""


def _parse_startup_list(output: str) -> list[dict[str, str]]:
    """Parse `wmic startup list full` output.

    Example::

        Caption=OneDrive
        Command=C:\\Program Files\\Microsoft OneDrive\\OneDrive.exe /background
        Location=HKU\\S-1-5-21...\\Run
        Name=OneDrive
        User=DESKTOP\\annhoward

        Caption=Skype
        Command=C:\\Program Files (x86)\\Microsoft\\Skype for Desktop\\Skype.exe /minimized /regrun
        Location=HKU\\S-1-5-21...\\Run
        Name=Skype
        User=DESKTOP\\annhoward
    """
    items: list[dict[str, str]] = []
    current: dict[str, str] = {}
    for raw_line in output.splitlines():
        line = raw_line.strip("\r\n").strip()
        if not line:
            if current:
                items.append(current)
                current = {}
            continue
        if "=" in line:
            key, _, value = line.partition("=")
            current[key.strip()] = value.strip()
    if current:
        items.append(current)
    return [item for item in items if item.get("Name")]
