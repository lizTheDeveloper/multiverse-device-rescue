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

    emits_codes = [
        "security.win_defender.antivirus_enabled",
        "security.win_defender.realtime_protection",
        "security.win_defender.signature_age",
    ]

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []
        status = _parse_defender_status(self._run_get_status())

        if status is None:
            return CheckResult(module_name=self.name, findings=findings)

        if status.get("AntivirusEnabled") is False:
            findings.append(
                Finding(
                    title="Your computer's built-in antivirus is turned off",
                    description=(
                        "Windows Defender, your computer's built-in antivirus, is currently "
                        "disabled. This means your computer is not actively checking for "
                        "malicious software. This is a significant security gap that should "
                        "be addressed.\n\n"
                        "What to do: Open Windows Security by searching for it in the "
                        "Start menu, go to 'Virus & threat protection,' and ensure 'Real-time "
                        "protection' is turned on."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
                    code="security.win_defender.antivirus_enabled",
                    data={"check": "antivirus_enabled"},
                )
            )

        if status.get("RealTimeProtectionEnabled") is False:
            findings.append(
                Finding(
                    title="Your computer is not checking files as you use them",
                    description=(
                        "Real-time protection in Windows Defender is off. This feature "
                        "scans files the moment you open or save them to catch threats "
                        "immediately. Without it, your computer may not detect new malware "
                        "until you run a full scan manually.\n\n"
                        "What to do: Open Windows Security, go to 'Virus & threat protection,' "
                        "and turn on 'Real-time protection'."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
                    code="security.win_defender.realtime_protection",
                    data={"check": "realtime_protection"},
                )
            )

        antivirus_age = status.get("AntivirusSignatureAge")
        if isinstance(antivirus_age, (int, float)) and antivirus_age > 7:
            findings.append(
                Finding(
                    title=f"Your antivirus definitions are {int(antivirus_age)} days old",
                    description=(
                        f"Windows Defender's list of known threats is {int(antivirus_age)} "
                        "days old. These definitions update automatically to recognize "
                        "new malware. If they are outdated, your computer might miss "
                        "recent threats.\n\n"
                        "What to do: Open Windows Security, go to 'Virus & threat protection,' "
                        "and click 'Check for updates' under 'Virus & threat protection "
                        "updates'."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.win_defender.signature_age",
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
