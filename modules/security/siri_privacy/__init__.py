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
    name = "siri_privacy"
    category = "security"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "3s"

    emits_codes = [
        "security.siri_privacy.siri_enabled",
        "security.siri_privacy.hey_siri",
        "security.siri_privacy.siri_suggestions",
        "security.siri_privacy.siri_analytics",
        "security.siri_privacy.lockscreen_siri",
        "security.siri_privacy.siri_config_status",
    ]

    def check(self, profile: SystemProfile) -> CheckResult:
        """Check Siri privacy settings on macOS.

        Checks:
        - Siri enabled status
        - Hey Siri listening enabled
        - Siri Suggestions in Spotlight
        - Siri analytics/data sharing
        - Siri access from lock screen (security risk)
        """
        findings = []

        # Check if Siri is enabled
        siri_enabled = self._read_defaults("com.apple.assistant.support", "Assistant Enabled")
        if siri_enabled == "1":
            findings.append(
                Finding(
                    title="Siri is enabled",
                    description="Siri voice assistant is enabled on this device.",
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.siri_privacy.siri_enabled",
                    data={"check": "siri_enabled"},
                )
            )

        # Check Hey Siri listening
        hey_siri = self._read_defaults("com.apple.assistant.support", "Dictation Enabled")
        if hey_siri == "1":
            findings.append(
                Finding(
                    title="Hey Siri listening is enabled",
                    description="'Hey Siri' always-on listening is enabled.",
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.siri_privacy.hey_siri",
                    data={"check": "hey_siri"},
                )
            )

        # Check Siri Suggestions in Spotlight
        siri_suggestions = self._read_defaults(
            "com.apple.assistant.support", "Siri Data Collection Opt-In"
        )
        if siri_suggestions == "1":
            findings.append(
                Finding(
                    title="Siri Suggestions are enabled",
                    description="Siri Suggestions in Spotlight and other features are enabled.",
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.siri_privacy.siri_suggestions",
                    data={"check": "siri_suggestions"},
                )
            )

        # Check Siri analytics/data sharing
        siri_analytics = self._read_defaults(
            "com.apple.assistant.support", "Siri Analytics Opt-In"
        )
        if siri_analytics == "1":
            findings.append(
                Finding(
                    title="Siri analytics and data sharing is enabled",
                    description="Siri sends analytics and usage data to Apple.",
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.siri_privacy.siri_analytics",
                    data={"check": "siri_analytics"},
                )
            )

        # Check Siri access from lock screen (SECURITY RISK)
        lockscreen_siri = self._read_defaults("com.apple.Siri", "LockscreenEnabled")
        if lockscreen_siri == "1":
            findings.append(
                Finding(
                    title="Siri works on the lock screen, without unlocking your Mac",
                    description=(
                        "Right now, you can ask Siri questions or send messages even when "
                        "your Mac is locked. This is a normal setting, but it means anyone "
                        "who physically has your Mac could use Siri to read your messages, "
                        "check your calendar, or send texts without entering your password. "
                        "If you are worried about someone close to you using your Mac "
                        "while it is locked, turning this off is a safe way to add a layer "
                        "of protection.\n\n"
                        "What to do: Open System Settings > Siri (called Apple Intelligence "
                        "& Siri on newer Macs) and turn off 'Allow Siri when locked'."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.siri_privacy.lockscreen_siri",
                    data={"check": "lockscreen_siri"},
                )
            )

        # Report configuration status when no findings
        if not findings:
            findings.append(
                Finding(
                    title="Siri privacy configuration",
                    description="Siri privacy settings are not currently enabled or accessible.",
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.siri_privacy.siri_config_status",
                    data={"check": "siri_config_status"},
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        """Provide informational guidance on Siri privacy settings.

        This module is informational only - it does not modify any settings,
        as Siri preferences are user-specific and should be configured
        according to individual needs and organizational policies.
        """
        actions = []
        for finding in findings.findings:
            check = finding.data.get("check")

            # Map check types to their informational messages
            guidance_map = {
                "siri_enabled": (
                    "Consider disabling Siri if not needed",
                    (
                        "To disable Siri:\n"
                        "1. System Settings > Siri & Spotlight\n"
                        "2. Toggle 'Listen for 'Hey Siri'' to OFF\n"
                        "Note: This disables voice activation but Siri can still be used via button."
                    ),
                ),
                "hey_siri": (
                    "Disable 'Hey Siri' always-on listening",
                    (
                        "To disable 'Hey Siri':\n"
                        "1. System Settings > Siri & Spotlight\n"
                        "2. Uncheck 'Listen for 'Hey Siri''\n"
                        "This prevents constant microphone listening for the wake phrase."
                    ),
                ),
                "siri_suggestions": (
                    "Disable Siri Suggestions for privacy",
                    (
                        "To disable Siri Suggestions:\n"
                        "1. System Settings > Siri & Spotlight\n"
                        "2. Uncheck 'Suggestions in Spotlight' if not needed\n"
                        "This prevents Apple from analyzing your usage patterns."
                    ),
                ),
                "siri_analytics": (
                    "Disable Siri analytics and data sharing",
                    (
                        "To disable Siri analytics:\n"
                        "1. System Settings > Siri & Spotlight\n"
                        "2. Uncheck 'Siri & Dictation Analytics' at the bottom\n"
                        "This prevents sending usage data to Apple."
                    ),
                ),
                "lockscreen_siri": (
                    "Disable Siri access from lock screen",
                    (
                        "To disable Siri on lock screen (RECOMMENDED):\n"
                        "1. System Settings > Siri & Spotlight\n"
                        "2. Disable 'Allow Siri when locked' or uncheck 'Lock Screen'\n"
                        "This prevents unauthorized access to Siri and your device via the lock screen."
                    ),
                ),
                "siri_config_status": (
                    "Review Siri privacy settings",
                    (
                        "Your Siri privacy settings are configured. "
                        "Review System Settings > Siri & Spotlight to ensure settings match your privacy requirements."
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
            domain: The defaults domain (e.g., 'com.apple.assistant.support')
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
            # Key not found or domain doesn't exist - return empty
            return ""
        except OSError:
            # Command not found or permission denied
            return ""
