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
    name = "win_defender"
    category = "security"
    platforms = [Platform.WIN32]
    risk_level = RiskLevel.MODERATE
    priority = 65
    depends_on = []
    estimated_duration = "10s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []
        status = _parse_defender_status(self._run_get_status())

        if status is None:
            return CheckResult(module_name=self.name, findings=findings)

        if status.get("AntivirusEnabled") is False:
            findings.append(
                Finding(
                    title="Windows Defender antivirus is disabled",
                    description=(
                        "Windows Defender antivirus protection is turned off, "
                        "leaving the system without real-time malware defense."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
                    data={"check": "antivirus_enabled"},
                )
            )

        if status.get("RealTimeProtectionEnabled") is False:
            findings.append(
                Finding(
                    title="Real-time protection is disabled",
                    description=(
                        "Windows Defender real-time protection is off, so new "
                        "threats will not be scanned as files are accessed."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
                    data={"check": "realtime_protection"},
                )
            )

        antivirus_age = status.get("AntivirusSignatureAge")
        if isinstance(antivirus_age, (int, float)) and antivirus_age > 7:
            findings.append(
                Finding(
                    title=f"Antivirus definitions are {int(antivirus_age)} days old",
                    description=(
                        "Windows Defender virus definitions have not updated "
                        "recently, reducing detection of newer threats."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "signature_age"},
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            check = finding.data.get("check")
            if check == "realtime_protection":
                title = "Enable real-time protection"
                ps_command = "Set-MpPreference -DisableRealtimeMonitoring $false"
            elif check == "antivirus_enabled":
                title = "Re-enable Windows Defender"
                ps_command = "Set-MpPreference -DisableRealtimeMonitoring $false"
            elif check == "signature_age":
                title = "Update virus definitions"
                ps_command = "Update-MpSignature"
            else:
                continue
            try:
                result = subprocess.run(
                    ["powershell", "-NoProfile", "-Command", ps_command],
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
                title=title,
                description=f"Ran `{ps_command}`.",
                risk_level=RiskLevel.MODERATE,
                kind=ActionKind.MUTATION,
                executed=True,
                success=success,
                    error=error,
                )
            )
        return FixResult(module_name=self.name, actions=actions)

    def _run_get_status(self) -> str:
        try:
            result = subprocess.run(
                [
                    "powershell",
                    "-NoProfile",
                    "-Command",
                    "Get-MpComputerStatus | ConvertTo-Json",
                ],
                capture_output=True,
                text=True,
            )
            return result.stdout
        except (OSError, subprocess.SubprocessError):
            return ""


def _parse_defender_status(output: str) -> dict | None:
    if not output or not output.strip():
        return None
    try:
        return json.loads(output)
    except json.JSONDecodeError:
        return None
