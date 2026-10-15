import json
import subprocess

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


class Module(ModuleBase):
    name = "win_updates"
    category = "integrity"
    platforms = [Platform.WIN32]
    risk_level = RiskLevel.MODERATE
    priority = 55
    depends_on = []
    estimated_duration = "10s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []
        service = _parse_service_status(self._run_get_service())

        if service is not None:
            status = str(service.get("Status", "")).strip()
            # PowerShell's ConvertTo-Json serializes the ServiceController
            # Status enum inconsistently across versions: Windows PowerShell
            # 5.1 emits the raw integer value (4 == Running), while
            # PowerShell 7+ emits the enum name ("Running"). Accept both.
            if status and status.lower() not in ("running", "4"):
                findings.append(
                    Finding(
                        title="Windows Update service is not running",
                        description=(
                            "Your computer's automatic update system (the Windows Update "
                            f"service) is currently set to '{status}'. This means your "
                            "computer is not checking for or installing new security "
                            "patches.\n\n"
                            "What to do: Open the Start menu, type 'Services', and press "
                            "Enter. Scroll down to 'Windows Update', right-click it, "
                            "and select 'Start'. If it says Disabled, open Properties and set "
                            "'Startup type' to Manual (the Windows default)."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={"check": "service_status", "status": status},
                    )
                )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            check = finding.data.get("check")
            if check != "service_status":
                continue
            try:
                result = subprocess.run(
                    [
                        "powershell",
                        "-NoProfile",
                        "-Command",
                        "Start-Service -Name wuauserv",
                    ],
                    capture_output=True,
                    text=True,
                )
                success = result.returncode == 0
                error = None if success else (
                    result.stderr.strip()
                    or "PowerShell command failed (may require Administrator privileges)"
                )
            except OSError as e:
                success = False
                error = str(e)
            actions.append(
                Action(
                    title="Start Windows Update service",
                    description="Ran `Start-Service -Name wuauserv`.",
                    risk_level=RiskLevel.MODERATE,
                    kind=ActionKind.MUTATION,
                    executed=True,
                    success=success,
                    error=error,
                )
            )
        return FixResult(module_name=self.name, actions=actions)

    def _run_get_service(self) -> str:
        try:
            result = subprocess.run(
                [
                    "powershell",
                    "-NoProfile",
                    "-Command",
                    "Get-Service -Name wuauserv | ConvertTo-Json",
                ],
                capture_output=True,
                text=True,
            )
            return result.stdout
        except (OSError, subprocess.SubprocessError):
            return ""


def _parse_service_status(output: str) -> dict | None:
    if not output or not output.strip():
        return None
    try:
        return json.loads(output)
    except json.JSONDecodeError:
        return None
