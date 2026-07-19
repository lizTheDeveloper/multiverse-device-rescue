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
    name = "screen_time_audit"
    category = "security"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "5s"

    emits_codes = [
        "security.screen_time_audit.screen_time_enabled",
        "security.screen_time_audit.screen_time_no_passcode",
        "security.screen_time_audit.content_privacy_restrictions",
        "security.screen_time_audit.downtime_enabled",
        "security.screen_time_audit.app_limits_configured",
        "security.screen_time_audit.communication_limits_configured",
        "security.screen_time_audit.screen_time_disabled",
    ]

    def check(self, profile: SystemProfile) -> CheckResult:
        """Audit Screen Time and parental controls settings on macOS.

        Checks:
        - Screen Time enabled status
        - Content & Privacy Restrictions status
        - Screen Time passcode status
        - Downtime schedule configuration
        - App Limits configuration
        - Communication Limits configuration
        """
        findings = []

        # Check if Screen Time is enabled
        screen_time_enabled = self._read_defaults(
            "com.apple.ScreenTimeAgent", "ScreenTimeEnabled"
        )
        if screen_time_enabled == "1":
            findings.append(
                Finding(
                    title="Screen Time is enabled",
                    description=(
                        "Screen Time is enabled on this device. This is useful for monitoring "
                        "app usage and setting usage limits on family devices."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.screen_time_audit.screen_time_enabled",
                    data={"check": "screen_time_enabled"},
                )
            )

            # Check if Screen Time passcode is set (critical for enforcing limits)
            passcode_set = self._check_screen_time_passcode()
            if not passcode_set:
                findings.append(
                    Finding(
                        title="Screen Time enabled but no passcode is set",
                        description=(
                            "Screen Time is enabled but no passcode is configured. Without a "
                            "passcode, anyone (including children) can disable Screen Time, "
                            "bypass Downtime, or modify App Limits. Set a passcode to enforce "
                            "parental controls."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        code="security.screen_time_audit.screen_time_no_passcode",
                        data={"check": "screen_time_no_passcode"},
                    )
                )

        # Check Content & Privacy Restrictions
        content_privacy_enabled = self._read_defaults(
            "com.apple.ScreenTimeAgent", "ContentPrivacyRestrictionsEnabled"
        )
        if content_privacy_enabled == "1":
            findings.append(
                Finding(
                    title="Content & Privacy Restrictions are enabled",
                    description=(
                        "Content & Privacy Restrictions are enabled. This restricts access to "
                        "adult content, explicit movies/music, and limits app installation."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.screen_time_audit.content_privacy_restrictions",
                    data={"check": "content_privacy_restrictions"},
                )
            )

        # Check Downtime configuration
        downtime_enabled = self._read_defaults(
            "com.apple.ScreenTimeAgent", "DowntimeEnabled"
        )
        if downtime_enabled == "1":
            findings.append(
                Finding(
                    title="Downtime schedule is enabled",
                    description=(
                        "Downtime is enabled. This prevents app and call/message access during "
                        "configured times, useful for enforcing screen-free periods."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.screen_time_audit.downtime_enabled",
                    data={"check": "downtime_enabled"},
                )
            )

        # Check App Limits configuration
        app_limits_configured = self._check_app_limits()
        if app_limits_configured:
            findings.append(
                Finding(
                    title="App Limits are configured",
                    description=(
                        "App Limits are configured. This restricts the daily usage of apps by "
                        "category or individual app."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.screen_time_audit.app_limits_configured",
                    data={"check": "app_limits_configured"},
                )
            )

        # Check Communication Limits configuration
        comm_limits_configured = self._check_communication_limits()
        if comm_limits_configured:
            findings.append(
                Finding(
                    title="Communication Limits are configured",
                    description=(
                        "Communication Limits are configured. This restricts who can call or "
                        "message the user during certain times."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.screen_time_audit.communication_limits_configured",
                    data={"check": "communication_limits_configured"},
                )
            )

        # If Screen Time is not enabled, suggest it for family devices
        if screen_time_enabled != "1":
            findings.append(
                Finding(
                    title="Screen Time is not enabled",
                    description=(
                        "Screen Time is not enabled. For family devices with children, "
                        "Screen Time provides valuable parental controls including app usage "
                        "limits, Downtime scheduling, content restrictions, and more."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.screen_time_audit.screen_time_disabled",
                    data={"check": "screen_time_disabled"},
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        """Provide informational guidance on Screen Time configuration.

        This module is informational only - it does not modify Screen Time settings,
        as parental control configuration is device and family-specific and requires
        user intent and setup through System Settings.
        """
        actions = []
        for finding in findings.findings:
            check = finding.data.get("check")

            # Map check types to their informational messages
            guidance_map = {
                "screen_time_enabled": (
                    "Screen Time is Active",
                    (
                        "Screen Time is enabled on this device. Verify that it's configured "
                        "with appropriate limits and that the passcode is set and known only "
                        "to the account owner."
                    ),
                ),
                "screen_time_no_passcode": (
                    "Set Screen Time Passcode",
                    (
                        "To set a Screen Time passcode:\n"
                        "1. System Settings > Screen Time\n"
                        "2. Click 'Use Screen Time Passcode' or 'Change Screen Time Passcode'\n"
                        "3. Enter a secure 4-digit or custom passcode\n"
                        "4. Re-enter to confirm\n\n"
                        "Without a passcode, anyone can disable Screen Time and bypass "
                        "all parental controls."
                    ),
                ),
                "content_privacy_restrictions": (
                    "Content & Privacy Restrictions Active",
                    (
                        "Content & Privacy Restrictions are enabled. Review the settings to "
                        "ensure they match your family's needs. You can manage:\n"
                        "- Allowed app types and ratings\n"
                        "- Explicit content filtering\n"
                        "- Web content restrictions\n"
                        "- Siri features\n"
                        "- Privacy settings"
                    ),
                ),
                "downtime_enabled": (
                    "Downtime Schedule Active",
                    (
                        "Downtime is enabled. During these times, only calls and messages from "
                        "allowed contacts are available. Review the schedule in:\n"
                        "System Settings > Screen Time > [Device/User] > Downtime"
                    ),
                ),
                "app_limits_configured": (
                    "App Limits Configured",
                    (
                        "App Limits are configured to restrict usage by category or app. "
                        "Review and update limits in:\n"
                        "System Settings > Screen Time > [Device/User] > App Limits"
                    ),
                ),
                "communication_limits_configured": (
                    "Communication Limits Configured",
                    (
                        "Communication Limits restrict who can call or message the user. "
                        "Review allowed contacts in:\n"
                        "System Settings > Screen Time > [Device/User] > Communication Limits"
                    ),
                ),
                "screen_time_disabled": (
                    "Enable Screen Time for Family Devices",
                    (
                        "To enable Screen Time for parental controls:\n"
                        "1. System Settings > Screen Time\n"
                        "2. Click 'Enable Screen Time'\n"
                        "3. Select 'This is My Child's iPad/Mac' if setting up for a child\n"
                        "4. Set a secure Screen Time passcode\n"
                        "5. Configure App Limits, Downtime, and Communication Limits\n\n"
                        "Screen Time helps monitor and control app usage on family devices."
                    ),
                ),
            }

            if check in guidance_map:
                title, description = guidance_map[check]
                actions.append(
                    Action(
                        title=title,
                        description=description,
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _read_defaults(self, domain: str, key: str) -> str:
        """Read a macOS defaults value.

        Args:
            domain: The defaults domain (e.g., 'com.apple.ScreenTimeAgent')
            key: The preference key to read

        Returns:
            The value as a string, or empty string if not found or error occurs
        """
        try:
            result = subprocess.run(
                ["defaults", "read", domain, key],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                return result.stdout.strip()
            return ""
        except OSError:
            return ""

    def _check_screen_time_passcode(self) -> bool:
        """Check if Screen Time passcode is set.

        Returns:
            True if passcode is set, False otherwise
        """
        try:
            result = subprocess.run(
                ["defaults", "read", "com.apple.ScreenTimeAgent", "ScreenTimePasscodeSet"],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                return result.stdout.strip() == "1"
            return False
        except OSError:
            return False

    def _check_app_limits(self) -> bool:
        """Check if any App Limits are configured.

        Returns:
            True if App Limits exist, False otherwise
        """
        try:
            result = subprocess.run(
                ["defaults", "read", "com.apple.ScreenTimeAgent", "AppLimits"],
                capture_output=True,
                text=True,
            )
            # If the key exists and has content, it's configured
            if result.returncode == 0 and result.stdout.strip():
                return True
            return False
        except OSError:
            return False

    def _check_communication_limits(self) -> bool:
        """Check if Communication Limits are configured.

        Returns:
            True if Communication Limits exist, False otherwise
        """
        try:
            result = subprocess.run(
                ["defaults", "read", "com.apple.ScreenTimeAgent", "CommunicationLimits"],
                capture_output=True,
                text=True,
            )
            # If the key exists and has content, it's configured
            if result.returncode == 0 and result.stdout.strip():
                return True
            return False
        except OSError:
            return False
