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
    name = "win_autorun"
    category = "security"
    platforms = [Platform.WIN32]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "5s"

    emits_codes = [
        "security.win_autorun.autorun_enabled",
        "security.win_autorun.autorun_disabled_full",
        "security.win_autorun.autorun_partial",
        "security.win_autorun.autoplay_enabled",
        "security.win_autorun.autoplay_disabled",
    ]

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Check AutoRun policy for removable drives
        autorun_policy = self._query_registry(
            "HKLM",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
            "NoDriveTypeAutoRun"
        )

        # Check AutoPlay settings
        autoplay_disabled = self._query_registry(
            "HKCU",
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers",
            "DisableAutoplay"
        )

        # Analyze AutoRun policy
        # NoDriveTypeAutoRun values:
        # - Not present or 0: AutoRun enabled for all drive types
        # - 0x91: AutoRun disabled for removable drives (USB) and fixed drives (safest)
        # - Other values disable specific drive types

        if autorun_policy is None or autorun_policy == "0":
            # AutoRun is enabled for removable drives
            findings.append(
                Finding(
                    title="AutoRun is enabled for removable drives",
                    description=(
                        "Windows AutoRun for removable drives (USB) is enabled. This is a "
                        "classic malware vector that allows automatic execution of code when "
                        "an infected USB device is connected to the system. This poses a "
                        "significant security risk, especially for older Windows versions."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.win_autorun.autorun_enabled",
                    data={"policy_value": autorun_policy},
                )
            )
        elif autorun_policy == "0x91":
            # AutoRun is properly disabled for removable and fixed drives
            findings.append(
                Finding(
                    title="AutoRun is properly disabled for removable and fixed drives",
                    description=(
                        "Windows AutoRun is disabled for both removable and fixed drives. "
                        "This is a secure configuration that prevents automatic execution "
                        "of code from USB devices and other removable media."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.win_autorun.autorun_disabled_full",
                    data={"policy_value": autorun_policy},
                )
            )
        elif autorun_policy:
            # AutoRun is partially disabled
            findings.append(
                Finding(
                    title="AutoRun is partially disabled",
                    description=(
                        f"Windows AutoRun policy is set to: {autorun_policy}. "
                        "This value disables AutoRun for some drive types but not all. "
                        "Consider setting it to 0x91 to disable AutoRun for removable and fixed drives."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.win_autorun.autorun_partial",
                    data={"policy_value": autorun_policy},
                )
            )

        # Analyze AutoPlay settings
        # DisableAutoplay values:
        # - 0 or not present: AutoPlay handlers enabled
        # - 1: AutoPlay handlers disabled

        if autoplay_disabled == "0" or autoplay_disabled is None:
            # AutoPlay is enabled
            findings.append(
                Finding(
                    title="AutoPlay is enabled for removable media",
                    description=(
                        "Windows AutoPlay for removable media is enabled. This allows "
                        "automatic execution of handlers (like opening file explorer or "
                        "launching applications) when USB devices are connected. "
                        "Consider disabling this feature to reduce attack surface."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.win_autorun.autoplay_enabled",
                    data={"autoplay_disabled": autoplay_disabled},
                )
            )
        elif autoplay_disabled == "1":
            # AutoPlay is properly disabled
            findings.append(
                Finding(
                    title="AutoPlay is properly disabled",
                    description=(
                        "Windows AutoPlay for removable media is disabled. This prevents "
                        "automatic execution of handlers when removable media is connected."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.win_autorun.autoplay_disabled",
                    data={"autoplay_disabled": autoplay_disabled},
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        # This fix is INFORMATIONAL - we provide guidance but don't modify the system
        has_autorun_warning = any(
            "AutoRun is enabled" in f.title for f in findings.findings
        )
        has_autoplay_warning = any(
            "AutoPlay is enabled" in f.title for f in findings.findings
        )

        if has_autorun_warning:
            actions.append(
                Action(
                    title="Disable AutoRun for removable drives",
                    description=(
                        "To disable AutoRun for removable and fixed drives, set the "
                        "NoDriveTypeAutoRun registry value to 0x91:\n\n"
                        "Method 1 (Group Policy Editor):\n"
                        "1. Open gpedit.msc\n"
                        "2. Navigate to: Computer Configuration > Administrative Templates > "
                        "Windows Components > AutoPlay Policies\n"
                        "3. Set 'Turn off AutoPlay' to Enabled\n"
                        "4. Set 'NoDriveTypeAutoRun' to '0x91' (All drives)\n\n"
                        "Method 2 (Registry Editor):\n"
                        "1. Open regedit.exe\n"
                        "2. Navigate to: HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\"
                        "CurrentVersion\\Policies\\Explorer\n"
                        "3. Create or modify DWORD 'NoDriveTypeAutoRun' with value 0x91\n\n"
                        "Note: This requires Administrator privileges and a system restart "
                        "may be required for the change to take effect."
                    ),
                    risk_level=RiskLevel.SAFE,
                    success=True,
                    error=None,
                )
            )

        if has_autoplay_warning:
            actions.append(
                Action(
                    title="Disable AutoPlay for removable media",
                    description=(
                        "To disable AutoPlay for removable media:\n\n"
                        "Method 1 (Settings):\n"
                        "1. Open Settings\n"
                        "2. Go to Devices > AutoPlay\n"
                        "3. Toggle 'Use AutoPlay for all media and devices' to Off\n\n"
                        "Method 2 (Registry Editor):\n"
                        "1. Open regedit.exe\n"
                        "2. Navigate to: HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\"
                        "CurrentVersion\\Explorer\\AutoplayHandlers\n"
                        "3. Create or modify DWORD 'DisableAutoplay' with value 1\n\n"
                        "This prevents automatic handlers from running when removable "
                        "media is connected."
                    ),
                    risk_level=RiskLevel.SAFE,
                    success=True,
                    error=None,
                )
            )

        return FixResult(module_name=self.name, actions=actions)

    def _query_registry(self, hive: str, path: str, value: str) -> str | None:
        """Query Windows registry using reg query command.

        Args:
            hive: Registry hive (e.g., "HKLM", "HKCU")
            path: Path to registry key
            value: Value name to query

        Returns:
            The registry value as string, or None if not found
        """
        try:
            result = subprocess.run(
                ["reg", "query", f"{hive}\\{path}", "/v", value],
                capture_output=True,
                text=True,
            )

            # Parse the output
            # Format: "    ValueName    REG_DWORD    0x91"
            if result.returncode == 0:
                for line in result.stdout.splitlines():
                    line = line.strip()
                    if value in line:
                        # Extract the value (last part of the line)
                        parts = line.split()
                        if len(parts) >= 3:
                            return parts[-1]
            return None
        except (OSError, subprocess.SubprocessError):
            return None
