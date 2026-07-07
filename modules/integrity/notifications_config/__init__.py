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
    name = "notifications_config"
    category = "integrity"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "5s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Collect notification settings
        settings = self._get_notification_settings()

        # Report current settings as INFO
        self._report_notification_settings(settings, findings)

        # Flag warnings for privacy and usability concerns
        self._check_privacy_warnings(settings, findings)

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        """Fix is informational only - explains notification settings without modifying them."""
        actions = []

        for finding in findings.findings:
            check = finding.data.get("check")

            if check == "notification_info":
                actions.append(
                    Action(
                        title="Review notification settings",
                        description=(
                            "Current notification settings are displayed in the report above. "
                            "To modify notification settings, use System Settings > Notifications "
                            "or System Preferences > Notifications & Focus on older macOS versions."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "warning_dnd_enabled":
                actions.append(
                    Action(
                        title="Do Not Disturb is permanently enabled",
                        description=(
                            "You have Do Not Disturb or Focus mode permanently enabled. "
                            "This may prevent you from receiving important notifications. "
                            "To adjust, go to Control Center (top-right corner) and click Do Not Disturb "
                            "or Focus mode to set a schedule, or System Settings > Focus to configure."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "warning_preview_on_lock":
                actions.append(
                    Action(
                        title="Notification previews visible on lock screen",
                        description=(
                            "Your notification preview setting may expose sensitive information on your lock screen. "
                            "To enhance privacy, go to System Settings > Notifications, select an app, "
                            "and set 'Show previews' to 'When Unlocked' or 'Never'."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _get_notification_settings(self) -> dict:
        """Retrieve current notification settings."""
        settings = {}

        # Check Do Not Disturb / Focus mode status
        settings["focus_enabled"] = self._check_focus_enabled()

        # Check if Do Not Disturb has scheduled settings
        settings["has_focus_schedule"] = self._check_focus_schedule()

        # Check notification center status
        settings["notification_center_enabled"] = self._get_defaults_bool(
            "com.apple.ncprefs", "enabled"
        )

        # Check notification preview setting (privacy concern)
        settings["preview_on_lock"] = self._get_notification_preview_setting()

        # Check if notifications are suppressed when locked
        settings["suppress_when_locked"] = self._get_defaults_bool(
            "com.apple.ncprefs", "lockScreenNotifications"
        )

        return settings

    def _check_focus_enabled(self) -> bool:
        """Check if any Focus mode is currently enabled."""
        try:
            # Try to read the current focus status from controlcenter
            result = subprocess.run(
                ["defaults", "read", "com.apple.controlcenter", "NSStatusItem Visible FocusModes"],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                return True
        except (OSError, subprocess.SubprocessError):
            pass

        # Alternative check via ncprefs
        try:
            result = subprocess.run(
                ["defaults", "read", "com.apple.ncprefs", "doNotDisturb"],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                output = result.stdout.strip()
                return output == "1"
        except (OSError, subprocess.SubprocessError):
            pass

        return False

    def _check_focus_schedule(self) -> bool:
        """Check if Focus mode has a scheduled setting (not permanent)."""
        try:
            # Check if focus has associated schedule data
            result = subprocess.run(
                ["defaults", "read", "com.apple.ncprefs", "focusSchedules"],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                output = result.stdout.strip()
                return len(output) > 0
        except (OSError, subprocess.SubprocessError):
            pass

        return False

    def _get_notification_preview_setting(self) -> str:
        """Check notification preview setting for privacy concerns."""
        try:
            # Try to get the notification privacy setting
            result = subprocess.run(
                ["defaults", "read", "com.apple.ncprefs", "show_in_lockscreen"],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                output = result.stdout.strip()
                if output == "1":
                    return "always"
                elif output == "0":
                    return "when_unlocked"
        except (OSError, subprocess.SubprocessError):
            pass

        # Default to unknown if we can't determine
        return "unknown"

    def _get_defaults_bool(self, domain: str, key: str) -> bool:
        """Get a boolean setting from defaults, return False if not set or error."""
        try:
            result = subprocess.run(
                ["defaults", "read", domain, key],
                capture_output=True,
                text=True,
            )

            if result.returncode == 0:
                output = result.stdout.strip()
                return output == "1"
            return False
        except (OSError, subprocess.SubprocessError):
            return False

    def _report_notification_settings(
        self, settings: dict, findings: list[Finding]
    ) -> None:
        """Report current notification settings as INFO findings."""
        report_lines = []

        if settings.get("focus_enabled"):
            if settings.get("has_focus_schedule"):
                report_lines.append("- Focus mode/Do Not Disturb: ENABLED (with schedule)")
            else:
                report_lines.append("- Focus mode/Do Not Disturb: ENABLED (permanently)")
        else:
            report_lines.append("- Focus mode/Do Not Disturb: disabled")

        if settings.get("notification_center_enabled"):
            report_lines.append("- Notification Center: ENABLED")
        else:
            report_lines.append("- Notification Center: disabled")

        preview_setting = settings.get("preview_on_lock", "unknown")
        if preview_setting == "always":
            report_lines.append("- Notification previews on lock screen: YES")
        elif preview_setting == "when_unlocked":
            report_lines.append("- Notification previews on lock screen: when unlocked")
        else:
            report_lines.append("- Notification previews on lock screen: unknown")

        if settings.get("suppress_when_locked"):
            report_lines.append("- Suppress notifications when locked: YES")
        else:
            report_lines.append("- Suppress notifications when locked: NO")

        description = "Current notification settings:\n" + "\n".join(report_lines)

        findings.append(
            Finding(
                title="Notification configuration summary",
                description=description,
                severity=Severity.INFO,
                category=self.category,
                data={"check": "notification_info", "settings": settings},
            )
        )

    def _check_privacy_warnings(
        self, settings: dict, findings: list[Finding]
    ) -> None:
        """Flag warnings for privacy and usability concerns."""
        # Warning: Do Not Disturb permanently enabled (user may have forgotten)
        if (
            settings.get("focus_enabled")
            and not settings.get("has_focus_schedule")
        ):
            findings.append(
                Finding(
                    title="Do Not Disturb is permanently enabled",
                    description=(
                        "Do Not Disturb or Focus mode is permanently enabled without a schedule. "
                        "You may be missing important notifications. Consider enabling a schedule "
                        "to automatically manage when notifications are suppressed."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "warning_dnd_enabled"},
                )
            )

        # Warning: Notification previews visible on lock screen (privacy risk)
        if settings.get("preview_on_lock") == "always":
            findings.append(
                Finding(
                    title="Notification previews visible on lock screen",
                    description=(
                        "Your notification settings allow full previews to display on the lock screen. "
                        "This could expose sensitive information (messages, email content, etc.) "
                        "to anyone with physical access to your device. Consider setting previews "
                        "to 'When Unlocked' or 'Never' for better privacy."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "warning_preview_on_lock"},
                )
            )
