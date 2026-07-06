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
    name = "privacy_audit"
    category = "security"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "5s"

    def check(self, profile: SystemProfile) -> CheckResult:
        """Audit privacy settings on macOS.

        Checks:
        - Location Services status
        - Personalized Ads (ad tracking)
        - Analytics sharing (diagnostics & usage data)
        - Significant Locations (timeline tracking)
        - Spotlight/Siri Suggestions data sharing
        """
        findings = []

        # Check Location Services
        location_enabled = self._read_defaults("com.apple.locationd", "LocationServicesEnabled")
        if location_enabled == "1":
            findings.append(
                Finding(
                    title="Location Services is enabled",
                    description=(
                        "Location Services is enabled. Apps can request access to your "
                        "device's location for various services. Consider disabling if not needed "
                        "for your use case."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "location_services"},
                )
            )

        # Check Personalized Ads
        personalized_ads = self._read_defaults(
            "com.apple.privacymanagementd", "PersonalizedAdsOptIn"
        )
        if personalized_ads == "1":
            findings.append(
                Finding(
                    title="Personalized Ads is enabled",
                    description=(
                        "Personalized ads are enabled. Apple uses your activity and interests "
                        "to show targeted ads in App Store, Books, and Stocks. Disable to limit "
                        "ad targeting."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "personalized_ads"},
                )
            )

        # Check Analytics sharing
        analytics_enabled = self._read_defaults(
            "com.apple.analytics", "CollectBotIdentifierEnabled"
        )
        if analytics_enabled == "1":
            findings.append(
                Finding(
                    title="Diagnostics & Usage Data sharing is enabled",
                    description=(
                        "Analytics sharing is enabled. Apple collects diagnostic and usage data "
                        "about your device. This can be disabled to improve privacy."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "analytics"},
                )
            )

        # Check Significant Locations
        sig_locations = self._read_defaults(
            "com.apple.privacymanagementd", "SignificantLocationEnabled"
        )
        if sig_locations == "1":
            findings.append(
                Finding(
                    title="Significant Locations tracking is enabled",
                    description=(
                        "Significant Locations is enabled. Your device tracks locations you "
                        "visit frequently for iCloud Keychain and Maps suggestions. "
                        "Disable to prevent location timeline collection."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "significant_locations"},
                )
            )

        # Check Spotlight Suggestions/Siri Suggestions
        siri_suggestions = self._read_defaults(
            "com.apple.assistant.support", "Siri Data Collection Opt-In"
        )
        if siri_suggestions == "1":
            findings.append(
                Finding(
                    title="Siri Suggestions data collection is enabled",
                    description=(
                        "Siri Suggestions is enabled. Apple analyzes your usage patterns "
                        "to provide suggestions in Spotlight, Siri, and other features. "
                        "Disable to prevent Apple from analyzing your app and activity data."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "siri_suggestions"},
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        """Provide informational guidance on privacy settings.

        This module is informational only - it does not modify any settings,
        as privacy preferences are user-specific and should be configured
        according to individual needs.
        """
        actions = []
        for finding in findings.findings:
            check = finding.data.get("check")

            # Map check types to their informational messages
            guidance_map = {
                "location_services": (
                    "Disable Location Services",
                    (
                        "To disable Location Services:\n"
                        "1. System Settings > Privacy & Security > Location Services\n"
                        "2. Toggle the switch to OFF\n"
                        "Note: Some features like Find My Mac require Location Services."
                    ),
                ),
                "personalized_ads": (
                    "Disable Personalized Ads",
                    (
                        "To disable Personalized Ads:\n"
                        "1. System Settings > Privacy & Security > Apple Advertising\n"
                        "2. Toggle 'Personalized Ads' to OFF"
                    ),
                ),
                "analytics": (
                    "Disable Diagnostics & Usage Data sharing",
                    (
                        "To disable analytics:\n"
                        "1. System Settings > Privacy & Security > Analytics\n"
                        "2. Uncheck all sharing options"
                    ),
                ),
                "significant_locations": (
                    "Disable Significant Locations",
                    (
                        "To disable Significant Locations:\n"
                        "1. System Settings > Privacy & Security > Location Services\n"
                        "2. System Services at the bottom\n"
                        "3. Toggle 'Significant Locations' to OFF"
                    ),
                ),
                "siri_suggestions": (
                    "Disable Siri Suggestions",
                    (
                        "To disable Siri Suggestions:\n"
                        "1. System Settings > Siri & Spotlight\n"
                        "2. Uncheck suggestion sources as desired"
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
            domain: The defaults domain (e.g., 'com.apple.locationd')
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
