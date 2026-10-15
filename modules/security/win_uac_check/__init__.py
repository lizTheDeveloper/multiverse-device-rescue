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

    emits_codes = [
        "security.win_uac_check.uac_disabled",
        "security.win_uac_check.uac_never_notify",
        "security.win_uac_check.secure_desktop_disabled",
        "security.win_uac_check.uac_configured_ok",
    ]

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
                    title="Your computer's safety check (UAC) is turned off",
                    description=(
                        "Windows has a built-in safety check called User Account Control "
                        "(UAC). It asks for your permission before any program makes big "
                        "changes to your computer. Right now, this check is completely "
                        "off.\n\n"
                        "This means any program can change your system settings without "
                        "asking you. It makes it easier for unwanted software to install "
                        "itself or hide.\n\n"
                        "What to do: Type 'User Account Control' in the Windows Start "
                        "menu and select the result. Drag the slider to the top position "
                        "(the default) and click 'OK'. You may need to restart your computer."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
                    code="security.win_uac_check.uac_disabled",
                    data={"setting": "EnableLUA", "value": enable_lua},
                )
            )
        # Check if UAC is set to never notify (WARNING)
        if consent_prompt == "0":
            findings.append(
                Finding(
                    title="Your computer won't ask permission for big changes",
                    description=(
                        "Your computer is set to a mode where it never asks for your permission "
                        "when a program tries to make important changes. Normally, Windows "
                        "pops up a window asking, 'Do you allow this?' to keep you in "
                        "control.\n\n"
                        "With this setting, programs can make changes silently. This reduces "
                        "your protection against unauthorized changes.\n\n"
                        "What to do: Type 'User Account Control' in the Windows Start "
                        "menu and select the result. Move the slider to the second position "
                        "from the top (the default) and click 'OK'. You may need to restart "
                        "your computer."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.win_uac_check.uac_never_notify",
                    data={"setting": "ConsentPromptBehaviorAdmin", "value": consent_prompt},
                )
            )

        # Check if secure desktop is disabled (WARNING - phishing risk)
        if secure_desktop == "0":
            findings.append(
                Finding(
                    title="Security prompts appear on your normal screen",
                    description=(
                        "When Windows asks for permission to make a change, it usually "
                        "switches to a blank, secure screen first. This prevents fake "
                        "pop-up windows from hiding behind your real apps and tricking "
                        "you into clicking 'Yes'.\n\n"
                        "Right now, these prompts appear on your normal desktop. This "
                        "makes it easier for a fake window to look like a real security "
                        "prompt.\n\n"
                        "What to do: Type 'User Account Control' in the Start menu, move "
                        "the slider to the second position from the top (the default), "
                        "and click OK. That setting uses the secure screen again."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.win_uac_check.secure_desktop_disabled",
                    data={"setting": "PromptOnSecureDesktop", "value": secure_desktop},
                )
            )

        # If no issues found, add an INFO finding
        if not findings:
            findings.append(
                Finding(
                    title="User Account Control (UAC) is set up correctly",
                    description=(
                        "UAC is enabled with secure prompts configured. The system "
                        "has good protection against unauthorized changes."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.win_uac_check.uac_configured_ok",
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
    r"""Parse reg query output to extract the value.

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
