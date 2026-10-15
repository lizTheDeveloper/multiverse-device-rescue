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


class Module(ModuleBase):
    name = "encryption_check"
    category = "security"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 90
    depends_on = []
    estimated_duration = "3s"

    emits_codes = [
        "security.encryption_check.filevault_disabled",
    ]

    def check(self, profile: SystemProfile) -> CheckResult:
        output = self._run_fdesetup_status()
        findings = []
        if "off" in output.lower():
            findings.append(
                Finding(
                    title="Your Mac's disk encryption is off",
                    description=(
                        "Your Mac's built-in disk encryption (FileVault) is currently "
                        "turned off. This means that if your computer is lost or stolen, "
                        "anyone who has physical access to it can read your files, photos, "
                        "and passwords.\n\n"
                        "What to do: Open System Settings, go to Privacy & Security, and "
                        "turn on FileVault. You will be asked to create a recovery key. "
                        "Write this down or save it in a password manager, as you will "
                        "need it to unlock your Mac if you forget your password."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
                    code="security.encryption_check.filevault_disabled",
                    data={"fdesetup_output": output.strip()},
                )
            )
        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for _finding in findings.findings:
            actions.append(
                Action(
                    title="Enable FileVault",
                    description=(
                        "FileVault must be enabled interactively. Run "
                        "`sudo fdesetup enable` in Terminal, follow the "
                        "prompts, and store the recovery key somewhere safe. "
                        "Initial encryption runs in the background and may "
                        "take a few hours."
                    ),
                    risk_level=RiskLevel.SAFE,
                    success=True,
                )
            )
        return FixResult(module_name=self.name, actions=actions)

    def _run_fdesetup_status(self) -> str:
        result = subprocess.run(
            ["fdesetup", "status"],
            capture_output=True,
            text=True,
        )
        return result.stdout
