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

REG_PATH = r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"


class Module(ModuleBase):
    name = "win_uac_check"
    category = "security"
    platforms = [Platform.WIN32]
    risk_level = RiskLevel.SAFE
    priority = 65
    depends_on = []
    estimated_duration = "3s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Query UAC settings from registry
        enable_lua = self._query_reg_value("EnableLUA")
        consent_prompt = self._query_reg_value("ConsentPromptBehaviorAdmin")
        secure_desktop = self._query_reg_value("PromptOnSecureDesktop")

        # Check if UAC is completely disabled (CRITICAL)
        if enable_lua == "0":
            findings.append(
                Finding(
                    title="User Account Control (UAC) is disabled",
                    description=(
                        "UAC is completely disabled (EnableLUA=0). This is a critical "
                        "security risk as it removes a key defense against malware and "
                        "unauthorized system changes. Re-enable UAC immediately."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
                    data={"setting": "EnableLUA", "value": enable_lua},
                )
            )
        # Check if UAC is set to never notify (WARNING)
        if consent_prompt == "0":
            findings.append(
                Finding(
                    title="UAC is set to 'Never notify' mode",
                    description=(
                        "ConsentPromptBehaviorAdmin is set to 0 (never notify). This "
                        "disables UAC prompts for administrative actions, reducing "
                        "protection against unauthorized changes."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"setting": "ConsentPromptBehaviorAdmin", "value": consent_prompt},
                )
            )

        # Check if secure desktop is disabled (WARNING - phishing risk)
        if secure_desktop == "0":
            findings.append(
                Finding(
                    title="Secure Desktop for UAC prompts is disabled",
                    description=(
                        "PromptOnSecureDesktop is disabled. UAC prompts will display "
                        "on the normal desktop instead of a secure desktop, increasing "
                        "the risk of phishing attacks that mimic UAC dialogs."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"setting": "PromptOnSecureDesktop", "value": secure_desktop},
                )
            )

        # If no issues found, add an INFO finding
        if not findings:
            findings.append(
                Finding(
                    title="User Account Control (UAC) is properly configured",
                    description=(
                        "UAC is enabled with secure prompts configured. The system "
                        "has good protection against unauthorized changes."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={"uac_status": "healthy"},
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        for finding in findings.findings:
            if finding.severity == Severity.INFO:
                continue

            setting = finding.data.get("setting")
            if setting == "EnableLUA":
                actions.append(
                    Action(
                        title="Enable User Account Control (UAC)",
                        description=(
                            "To re-enable UAC: Open Settings > System > About > "
                            "Advanced system settings > Advanced tab > User Account Control > "
                            "Check 'Notify me only when apps try to make changes to my computer' > OK. "
                            "Or use: reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System "
                            "/v EnableLUA /t REG_DWORD /d 1 /f"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=False,
                        error="Manual configuration required (requires Administrator privileges)",
                    )
                )
            elif setting == "ConsentPromptBehaviorAdmin":
                actions.append(
                    Action(
                        title="Change UAC prompt behavior from 'Never notify' to default",
                        description=(
                            "To change UAC behavior: Open Settings > System > About > "
                            "Advanced system settings > Advanced tab > User Account Control > "
                            "Select 'Notify me only when apps try to make changes to my computer' > OK. "
                            "Or use: reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System "
                            "/v ConsentPromptBehaviorAdmin /t REG_DWORD /d 5 /f"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=False,
                        error="Manual configuration required (requires Administrator privileges)",
                    )
                )
            elif setting == "PromptOnSecureDesktop":
                actions.append(
                    Action(
                        title="Enable Secure Desktop for UAC prompts",
                        description=(
                            "To enable secure desktop: Open Settings > System > About > "
                            "Advanced system settings > Advanced tab > User Account Control > "
                            "Check 'Display User Account Control prompts on the secure desktop' > OK. "
                            "Or use: reg add HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System "
                            "/v PromptOnSecureDesktop /t REG_DWORD /d 1 /f"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=False,
                        error="Manual configuration required (requires Administrator privileges)",
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _query_reg_value(self, value_name: str) -> str | None:
        """Query a registry value and return its data, or None if not found."""
        try:
            result = subprocess.run(
                ["reg", "query", REG_PATH, "/v", value_name],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                return None
            # Parse output like:
            # HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
            #     EnableLUA    REG_DWORD    0x1
            return _parse_reg_value(result.stdout, value_name)
        except (OSError, subprocess.SubprocessError):
            return None


def _parse_reg_value(output: str, value_name: str) -> str | None:
    """Parse reg query output to extract the value.

    Example output:
        HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System
            EnableLUA    REG_DWORD    0x1

    Returns the last whitespace-separated token on the line containing value_name.
    """
    for line in output.splitlines():
        if value_name in line:
            parts = line.split()
            if len(parts) >= 3:
                # The value is the last part (e.g., "0x1")
                value_hex = parts[-1]
                # Convert hex to decimal string
                try:
                    return str(int(value_hex, 16))
                except ValueError:
                    return None
    return None
