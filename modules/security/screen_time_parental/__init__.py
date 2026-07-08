import subprocess
from pathlib import Path

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
    name = "screen_time_parental"
    category = "security"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "5s"

    def check(self, profile: SystemProfile) -> CheckResult:
        """Audit Screen Time parental controls and managed child accounts on macOS.

        Checks:
        - Screen Time enabled status
        - Content & Privacy Restrictions status
        - Screen Time passcode status
        - App Limits configuration
        - Downtime schedule configuration
        - Communication Limits configuration
        - Adult content filtering enabled
        - Purchase restrictions ("Ask to Buy")
        - Managed/child accounts on device
        """
        findings = []

        # Check if Screen Time is enabled
        screen_time_enabled = self._read_defaults(
            "com.apple.ScreenTimeAgent", "ScreenTimeEnabled"
        )

        if screen_time_enabled == "1":
            # Screen Time is enabled
            findings.append(
                Finding(
                    title="Screen Time is enabled",
                    description=(
                        "Screen Time is enabled on this device. This is essential for parental "
                        "controls when managing child accounts."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "screen_time_enabled"},
                )
            )

            # Check if Screen Time passcode is set (CRITICAL for parental controls)
            passcode_set = self._check_screen_time_passcode()
            if not passcode_set:
                findings.append(
                    Finding(
                        title="Screen Time enabled but no passcode is set",
                        description=(
                            "Screen Time is enabled but no passcode is configured. Without a "
                            "passcode, children can disable Screen Time, bypass Downtime, "
                            "modify App Limits, and remove all parental restrictions. "
                            "A passcode is essential to enforce parental controls."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
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
                            "adult content, explicit movies/music, limits app installation, and "
                            "controls device features."
                        ),
                        severity=Severity.INFO,
                        category=self.category,
                        data={"check": "content_privacy_restrictions"},
                    )
                )
            else:
                # Check if there are managed child accounts - if so, warn
                managed_accounts = self._check_managed_accounts()
                if managed_accounts:
                    findings.append(
                        Finding(
                            title="Content & Privacy Restrictions are disabled with managed child accounts",
                            description=(
                                f"Content & Privacy Restrictions are disabled, but this device has "
                                f"managed/child accounts: {', '.join(managed_accounts)}. "
                                f"Enable Content & Privacy Restrictions to control what these accounts "
                                f"can access on the device."
                            ),
                            severity=Severity.WARNING,
                            category=self.category,
                            data={
                                "check": "content_privacy_disabled_with_children",
                                "managed_accounts": managed_accounts,
                            },
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
                            "category or individual app for child accounts."
                        ),
                        severity=Severity.INFO,
                        category=self.category,
                        data={"check": "app_limits_configured"},
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
                            "configured times, enforcing screen-free periods for child accounts."
                        ),
                        severity=Severity.INFO,
                        category=self.category,
                        data={"check": "downtime_enabled"},
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
                            "message child accounts during certain times."
                        ),
                        severity=Severity.INFO,
                        category=self.category,
                        data={"check": "communication_limits_configured"},
                    )
                )

            # Check adult content filtering
            adult_content_filter = self._check_adult_content_filtering()
            if adult_content_filter:
                findings.append(
                    Finding(
                        title="Adult content filtering is enabled",
                        description=(
                            "Adult content filtering is enabled via Family Controls. This blocks "
                            "access to adult websites and app content."
                        ),
                        severity=Severity.INFO,
                        category=self.category,
                        data={"check": "adult_content_filtering"},
                    )
                )

            # Check "Ask to Buy" / purchase restrictions
            ask_to_buy_enabled = self._check_ask_to_buy()
            if ask_to_buy_enabled:
                findings.append(
                    Finding(
                        title="'Ask to Buy' purchase restrictions are enabled",
                        description=(
                            "'Ask to Buy' is enabled. Child accounts must request approval from "
                            "the family organizer before making purchases in the App Store."
                        ),
                        severity=Severity.INFO,
                        category=self.category,
                        data={"check": "ask_to_buy_enabled"},
                    )
                )

        else:
            # Screen Time is not enabled
            managed_accounts = self._check_managed_accounts()
            if managed_accounts:
                findings.append(
                    Finding(
                        title="Screen Time is disabled with managed child accounts",
                        description=(
                            f"Screen Time is not enabled, but this device has managed/child accounts: "
                            f"{', '.join(managed_accounts)}. Screen Time provides essential parental "
                            f"controls including app limits, Downtime, content restrictions, "
                            f"communication limits, and purchase approval. Enable Screen Time to "
                            f"protect child accounts."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={
                            "check": "screen_time_disabled_with_children",
                            "managed_accounts": managed_accounts,
                        },
                    )
                )
            else:
                findings.append(
                    Finding(
                        title="Screen Time is not enabled",
                        description=(
                            "Screen Time is not enabled. For family devices with children, "
                            "Screen Time provides valuable parental controls including app usage "
                            "limits, Downtime scheduling, content restrictions, communication limits, "
                            "and purchase approval. Enable Screen Time if managing child accounts."
                        ),
                        severity=Severity.INFO,
                        category=self.category,
                        data={"check": "screen_time_disabled"},
                    )
                )

        # Check for managed accounts regardless of Screen Time status
        managed_accounts = self._check_managed_accounts()
        if managed_accounts:
            findings.append(
                Finding(
                    title=f"Managed child account(s) detected: {len(managed_accounts)}",
                    description=(
                        f"This device has {len(managed_accounts)} managed/child account(s): "
                        f"{', '.join(managed_accounts)}. Ensure Screen Time is enabled and "
                        f"configured with appropriate parental controls for these accounts."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "managed_accounts", "accounts": managed_accounts},
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        """Provide informational guidance on Screen Time parental controls.

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
                        "with appropriate limits for child accounts and that the passcode is "
                        "set and known only to the account owner."
                    ),
                ),
                "screen_time_no_passcode": (
                    "Set Screen Time Passcode Immediately",
                    (
                        "To set a Screen Time passcode:\n"
                        "1. System Settings > Screen Time\n"
                        "2. Click 'Use Screen Time Passcode' or 'Change Screen Time Passcode'\n"
                        "3. Enter a secure 4-digit or custom passcode\n"
                        "4. Re-enter to confirm\n\n"
                        "Without a passcode, children can disable Screen Time and bypass "
                        "all parental controls. This is essential for protecting child accounts."
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
                        "- Siri features for child accounts\n"
                        "- Privacy settings"
                    ),
                ),
                "content_privacy_disabled_with_children": (
                    "Enable Content & Privacy Restrictions for Child Accounts",
                    (
                        "To enable Content & Privacy Restrictions:\n"
                        "1. System Settings > Screen Time\n"
                        "2. Select the child account from the sidebar\n"
                        "3. Enable 'Content & Privacy Restrictions'\n"
                        "4. Set restrictions for:\n"
                        "   - App Store and iTunes: restrict app types, ratings, and in-app purchases\n"
                        "   - Web content: filter adult websites\n"
                        "   - Game Center: control multiplayer and friend additions\n"
                        "   - Siri: restrict explicit language\n"
                        "   - Other features: camera, Handoff, etc."
                    ),
                ),
                "app_limits_configured": (
                    "App Limits Configured",
                    (
                        "App Limits are configured to restrict daily usage by category or app. "
                        "Review and update limits in:\n"
                        "System Settings > Screen Time > [Child Account] > App Limits\n\n"
                        "You can set different limits for weekdays and weekends."
                    ),
                ),
                "downtime_enabled": (
                    "Downtime Schedule Active",
                    (
                        "Downtime is enabled. During these times, only calls and messages from "
                        "allowed contacts are available. Review the schedule in:\n"
                        "System Settings > Screen Time > [Child Account] > Downtime\n\n"
                        "Consider setting Downtime during homework time, meals, and bedtime."
                    ),
                ),
                "communication_limits_configured": (
                    "Communication Limits Configured",
                    (
                        "Communication Limits restrict who can call or message the child account. "
                        "Review allowed contacts in:\n"
                        "System Settings > Screen Time > [Child Account] > Communication Limits\n\n"
                        "You can set different limits for different times of day."
                    ),
                ),
                "adult_content_filtering": (
                    "Adult Content Filtering Active",
                    (
                        "Adult content filtering is enabled via Family Controls. This blocks "
                        "access to adult websites and inappropriate app content. Review settings in:\n"
                        "System Settings > Screen Time > [Child Account] > Content & Privacy > "
                        "Content Restrictions"
                    ),
                ),
                "ask_to_buy_enabled": (
                    "'Ask to Buy' Enabled",
                    (
                        "'Ask to Buy' is enabled. Child accounts must request approval before "
                        "making any purchases. Review and approve requests in:\n"
                        "- Family Sharing on iPhone/iPad\n"
                        "- App Store: Purchases tab\n"
                        "- Settings > [Child Name] > [Your Name] > Family Sharing\n\n"
                        "This prevents unauthorized purchases and app installations."
                    ),
                ),
                "screen_time_disabled_with_children": (
                    "Enable Screen Time for Child Account Protection",
                    (
                        "To enable Screen Time for parental controls:\n"
                        "1. System Settings > Screen Time\n"
                        "2. Click 'Enable Screen Time'\n"
                        "3. Select 'This is My Child's Device' (if setting up for a child)\n"
                        "4. Set a secure Screen Time passcode\n"
                        "5. Configure for child account:\n"
                        "   - Set App Limits by category\n"
                        "   - Enable Downtime schedule\n"
                        "   - Configure Communication Limits\n"
                        "   - Enable Content & Privacy Restrictions\n"
                        "   - Enable 'Ask to Buy' for app purchases\n\n"
                        "Screen Time is essential for protecting child accounts on this device."
                    ),
                ),
                "screen_time_disabled": (
                    "Consider Enabling Screen Time",
                    (
                        "If this device has or will have child accounts, enable Screen Time:\n"
                        "1. System Settings > Screen Time\n"
                        "2. Click 'Enable Screen Time'\n"
                        "3. Select 'This is My Child's Device' if applicable\n"
                        "4. Set a secure passcode\n"
                        "5. Configure parental controls as needed\n\n"
                        "Screen Time provides comprehensive parental controls including app limits, "
                        "Downtime, content restrictions, and purchase approval."
                    ),
                ),
                "managed_accounts": (
                    "Review Managed Child Accounts",
                    (
                        "This device has managed/child accounts. Ensure Screen Time is enabled and "
                        "properly configured for each account with:\n"
                        "- Screen Time passcode protection\n"
                        "- App Limits appropriate for age\n"
                        "- Downtime schedule (e.g., during homework or bedtime)\n"
                        "- Communication Limits (if needed)\n"
                        "- Content & Privacy Restrictions\n"
                        "- 'Ask to Buy' enabled for app purchases\n\n"
                        "Review each account in System Settings > Screen Time to ensure "
                        "appropriate controls are active."
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

    def _check_adult_content_filtering(self) -> bool:
        """Check if adult content filtering is enabled via Family Controls.

        Returns:
            True if filtering is enabled, False otherwise
        """
        try:
            result = subprocess.run(
                ["defaults", "read", Path.home() / "Library/Preferences/com.apple.familycontrols.contentfilter"],
                capture_output=True,
                text=True,
            )
            # If the file exists and has content, filtering is configured
            if result.returncode == 0 and result.stdout.strip():
                return True
            return False
        except OSError:
            return False

    def _check_ask_to_buy(self) -> bool:
        """Check if 'Ask to Buy' / purchase restrictions are enabled.

        Returns:
            True if Ask to Buy is enabled, False otherwise
        """
        try:
            result = subprocess.run(
                ["defaults", "read", "com.apple.ScreenTimeAgent", "AskToBuyEnabled"],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                return result.stdout.strip() == "1"
            return False
        except OSError:
            return False

    def _check_managed_accounts(self) -> list[str]:
        """Check for managed/child accounts on the device via dscl.

        Returns:
            List of managed account usernames, or empty list if none found
        """
        managed_accounts = []
        try:
            # List all users
            result = subprocess.run(
                ["dscl", ".", "-list", "/Users"],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                return managed_accounts

            users = result.stdout.strip().split("\n")
            for user in users:
                user = user.strip()
                # Skip system accounts
                if user.startswith("_") or user in ("root", "daemon", "nobody"):
                    continue

                # Check if account is a managed account by looking for parental controls
                # or child account markers
                try:
                    # Check for managed flag in user record
                    check_result = subprocess.run(
                        ["dscl", ".", "-read", f"/Users/{user}", "dsAttrTypeNative:isHiddenUser"],
                        capture_output=True,
                        text=True,
                    )
                    # Also check for generateduid to identify local user accounts
                    guid_result = subprocess.run(
                        ["dscl", ".", "-read", f"/Users/{user}", "GeneratedUID"],
                        capture_output=True,
                        text=True,
                    )

                    if guid_result.returncode == 0:
                        # Try to detect if it's a child account by checking parental controls
                        # Child accounts typically have Screen Time restrictions set
                        pref_path = f"/Users/{user}/Library/Preferences/com.apple.ScreenTimeAgent.plist"
                        try:
                            pref_result = subprocess.run(
                                ["defaults", "read", pref_path],
                                capture_output=True,
                                text=True,
                            )
                            # If we can read parental control prefs, it likely has Screen Time configured
                            if pref_result.returncode == 0 and "ScreenTime" in pref_result.stdout:
                                managed_accounts.append(user)
                        except OSError:
                            pass
                except OSError:
                    pass

            return managed_accounts
        except OSError:
            return managed_accounts
