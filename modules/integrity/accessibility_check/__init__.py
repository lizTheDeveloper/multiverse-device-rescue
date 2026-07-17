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
    name = "accessibility_check"
    category = "integrity"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "5s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Collect accessibility settings
        settings = self._get_accessibility_settings()

        # Report current settings as INFO
        self._report_accessibility_settings(settings, findings)

        # Suggest features that might help
        self._suggest_accessibility_features(settings, findings)

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        """Fix is informational only - suggests accessibility settings to consider."""
        actions = []

        for finding in findings.findings:
            check = finding.data.get("check")

            if check == "accessibility_info":
                # Provide guidance on enabling accessibility features
                actions.append(
                    Action(
                        title="Review accessibility settings",
                        description=(
                            "Current accessibility settings are displayed in the report above. "
                            "To modify accessibility features, use System Settings > Accessibility "
                            "or System Preferences > Accessibility on older macOS versions."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "suggest_zoom":
                actions.append(
                    Action(
                        title="Consider enabling Display Zoom",
                        description=(
                            "Display Zoom enlarges UI elements throughout the system for easier reading. "
                            "Enable in System Settings > Accessibility > Display > Zoom, "
                            "or use Cmd+Option+8 to toggle."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "suggest_voiceover":
                actions.append(
                    Action(
                        title="Consider enabling VoiceOver",
                        description=(
                            "VoiceOver is a powerful screen reader that describes everything on screen. "
                            "Enable in System Settings > Accessibility > VoiceOver, "
                            "or press Cmd+F5."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "suggest_larger_text":
                actions.append(
                    Action(
                        title="Consider increasing text size",
                        description=(
                            "Larger text is easier to read. Go to System Settings > Accessibility > Display "
                            "and adjust 'Increase Contrast' or use browser zoom (Cmd++ in most apps)."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "suggest_reduce_motion":
                actions.append(
                    Action(
                        title="Consider enabling Reduce Motion",
                        description=(
                            "Reduce Motion minimizes animations that can be distracting or cause motion sickness. "
                            "Enable in System Settings > Accessibility > Display > Reduce Motion."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "suggest_increase_contrast":
                actions.append(
                    Action(
                        title="Consider enabling Increase Contrast",
                        description=(
                            "Increase Contrast enhances color contrast for better visibility. "
                            "Enable in System Settings > Accessibility > Display > Increase Contrast."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _get_accessibility_settings(self) -> dict:
        """Retrieve current accessibility settings."""
        settings = {}

        # Display zoom level
        settings["zoom_enabled"] = self._get_defaults_bool(
            "com.apple.universalaccess", "closeViewScaleMode"
        )

        # VoiceOver
        settings["voiceover_enabled"] = self._get_defaults_bool(
            "com.apple.universalaccess", "voiceOverOnOffKey"
        )

        # Font smoothing
        settings["font_smoothing"] = self._get_defaults_int("-g", "AppleFontSmoothing")

        # Reduce Motion
        settings["reduce_motion"] = self._get_defaults_bool(
            "com.apple.universalaccess", "reduceMotionEnabled"
        )

        # Increase Contrast
        settings["increase_contrast"] = self._get_defaults_bool(
            "com.apple.universalaccess", "increaseContrast"
        )

        # Sticky Keys
        settings["sticky_keys"] = self._get_defaults_bool(
            "com.apple.universalaccess", "stickyKeys"
        )

        # Slow Keys
        settings["slow_keys"] = self._get_defaults_bool(
            "com.apple.universalaccess", "slowKeys"
        )

        # Mouse tracking speed
        settings["mouse_tracking_speed"] = self._get_defaults_int(
            "-g", "com.apple.trackpad.scaling"
        )

        # Trackpad double-click speed
        settings["trackpad_double_click"] = self._get_defaults_int(
            "-g", "com.apple.trackpad.doubleClickThreshold"
        )

        # Mouse double-click speed
        settings["mouse_double_click"] = self._get_defaults_int(
            "-g", "com.apple.mouse.doubleClickThreshold"
        )

        return settings

    def _get_defaults_bool(self, domain: str, key: str) -> bool:
        """Get a boolean setting from defaults, return False if not set or error."""
        try:
            if domain == "-g":
                result = subprocess.run(
                    ["defaults", "read", "-g", key],
                    capture_output=True,
                    text=True,
                )
            else:
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

    def _get_defaults_int(self, domain: str, key: str) -> int | None:
        """Get an integer setting from defaults, return None if not set or error."""
        try:
            if domain == "-g":
                result = subprocess.run(
                    ["defaults", "read", "-g", key],
                    capture_output=True,
                    text=True,
                )
            else:
                result = subprocess.run(
                    ["defaults", "read", domain, key],
                    capture_output=True,
                    text=True,
                )

            if result.returncode == 0:
                return int(result.stdout.strip())
            return None
        except (OSError, subprocess.SubprocessError, ValueError):
            return None

    def _report_accessibility_settings(
        self, settings: dict, findings: list[Finding]
    ) -> None:
        """Report current accessibility settings as INFO findings."""
        report_lines = []

        if settings.get("zoom_enabled"):
            report_lines.append("- Display Zoom: ENABLED")
        else:
            report_lines.append("- Display Zoom: disabled")

        if settings.get("voiceover_enabled"):
            report_lines.append("- VoiceOver: ENABLED")
        else:
            report_lines.append("- VoiceOver: disabled")

        if settings.get("reduce_motion"):
            report_lines.append("- Reduce Motion: ENABLED")
        else:
            report_lines.append("- Reduce Motion: disabled")

        if settings.get("increase_contrast"):
            report_lines.append("- Increase Contrast: ENABLED")
        else:
            report_lines.append("- Increase Contrast: disabled")

        if settings.get("sticky_keys"):
            report_lines.append("- Sticky Keys: ENABLED")
        else:
            report_lines.append("- Sticky Keys: disabled")

        if settings.get("slow_keys"):
            report_lines.append("- Slow Keys: ENABLED")
        else:
            report_lines.append("- Slow Keys: disabled")

        if settings.get("font_smoothing") is not None:
            report_lines.append(f"- Font Smoothing: {settings['font_smoothing']}")

        if settings.get("mouse_tracking_speed") is not None:
            report_lines.append(
                f"- Mouse Tracking Speed: {settings['mouse_tracking_speed']}"
            )

        if settings.get("trackpad_double_click") is not None:
            report_lines.append(
                f"- Trackpad Double-click Speed: {settings['trackpad_double_click']}"
            )

        if settings.get("mouse_double_click") is not None:
            report_lines.append(
                f"- Mouse Double-click Speed: {settings['mouse_double_click']}"
            )

        description = "Current accessibility settings:\n" + "\n".join(report_lines)

        findings.append(
            Finding(
                title="Accessibility settings summary",
                description=description,
                severity=Severity.INFO,
                category=self.category,
                data={"check": "accessibility_info", "settings": settings},
            )
        )

    def _suggest_accessibility_features(
        self, settings: dict, findings: list[Finding]
    ) -> None:
        """Suggest accessibility features that might be helpful."""
        suggestions = []

        # Suggest zoom if not enabled
        if not settings.get("zoom_enabled"):
            suggestions.append("suggest_zoom")
            findings.append(
                Finding(
                    title="Display Zoom not enabled",
                    description=(
                        "Display Zoom enlarges UI elements throughout the system. "
                        "This can be helpful for users with vision difficulties."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "suggest_zoom"},
                )
            )

        # Suggest VoiceOver if not enabled
        if not settings.get("voiceover_enabled"):
            suggestions.append("suggest_voiceover")
            findings.append(
                Finding(
                    title="VoiceOver not enabled",
                    description=(
                        "VoiceOver is a powerful screen reader that describes everything on screen. "
                        "This can help users with vision impairments navigate the system."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "suggest_voiceover"},
                )
            )

        # Suggest Reduce Motion if not enabled
        if not settings.get("reduce_motion"):
            suggestions.append("suggest_reduce_motion")
            findings.append(
                Finding(
                    title="Reduce Motion not enabled",
                    description=(
                        "Reduce Motion minimizes animations that can be distracting or cause motion sickness. "
                        "This may be helpful for users sensitive to motion or with vestibular disorders."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "suggest_reduce_motion"},
                )
            )

        # Suggest Increase Contrast if not enabled
        if not settings.get("increase_contrast"):
            suggestions.append("suggest_increase_contrast")
            findings.append(
                Finding(
                    title="Increase Contrast not enabled",
                    description=(
                        "Increase Contrast enhances color contrast for better visibility. "
                        "This can help users with low vision or color blindness."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "suggest_increase_contrast"},
                )
            )
