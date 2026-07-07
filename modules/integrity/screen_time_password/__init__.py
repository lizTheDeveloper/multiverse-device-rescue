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
    name = "screen_time_password"
    category = "integrity"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "5s"

    def check(self, profile: SystemProfile) -> CheckResult:
        """Check Screen Time passcode and parental controls configuration.

        Checks:
        - Screen Time is enabled
        - Screen Time passcode is set (critical for enforcing controls)
        - Content restrictions configuration
        - Parental controls on child accounts
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
                        "Screen Time is enabled on this device. Verify that a passcode is set "
                        "to prevent unauthorized changes to parental controls."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
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
                            "passcode, children can disable Screen Time and bypass all "
                            "parental controls. Set a passcode immediately to protect "
                            "parental control settings."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={"check": "screen_time_no_passcode"},
                    )
                )
        else:
            findings.append(
                Finding(
                    title="Screen Time is not enabled",
                    description=(
                        "Screen Time is not enabled. For devices with children or where "
                        "parental controls are needed, enable Screen Time and set a "
                        "passcode to protect the configuration."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "screen_time_disabled"},
                )
            )

        # Check content restrictions configuration
        content_restrictions = self._get_content_restrictions()
        if content_restrictions:
            findings.append(
                Finding(
                    title="Content restrictions are configured",
                    description=(
                        f"Content restrictions are active. Current settings: {content_restrictions}"
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "content_restrictions_configured"},
                )
            )

        # Check for child accounts with parental controls
        child_accounts = self._check_child_accounts()
        if child_accounts:
            for account, has_controls in child_accounts:
                if not has_controls:
                    findings.append(
                        Finding(
                            title=f"Child account '{account}' has no parental controls",
                            description=(
                                f"Child account '{account}' exists but does not have "
                                "parental controls configured. Set up Screen Time or "
                                "parental controls to restrict access on this account."
                            ),
                            severity=Severity.WARNING,
                            category=self.category,
                            data={"check": "child_account_no_controls"},
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            title=f"Child account '{account}' has parental controls",
                            description=(
                                f"Child account '{account}' has parental controls configured. "
                                "Verify that Screen Time passcode is set and restrictions "
                                "are appropriately configured."
                            ),
                            severity=Severity.INFO,
                            category=self.category,
                            data={"check": "child_account_has_controls"},
                        )
                    )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        """Provide informational guidance on Screen Time passcode and parental controls.

        This module is informational only - it explains how to set/reset the Screen Time
        passcode and configure parental controls, but does not modify settings as these
        require user intent and setup through System Settings.
        """
        actions = []
        for finding in findings.findings:
            check = finding.data.get("check")

            # Map check types to their informational messages
            guidance_map = {
                "screen_time_enabled": (
                    "Screen Time is Active",
                    (
                        "Screen Time is enabled on this device. Ensure that:\n"
                        "1. A strong Screen Time passcode is set\n"
                        "2. Only you know the passcode\n"
                        "3. Parental controls are configured appropriately\n\n"
                        "Without a passcode, anyone can disable Screen Time and bypass controls."
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
                        "Without a passcode, anyone can disable Screen Time and bypass all "
                        "parental controls. This is critical for protecting children from "
                        "disabling controls themselves."
                    ),
                ),
                "screen_time_disabled": (
                    "Enable Screen Time for Parental Controls",
                    (
                        "To enable Screen Time and set up parental controls:\n"
                        "1. System Settings > Screen Time\n"
                        "2. Click 'Enable Screen Time'\n"
                        "3. Select 'This is My Child's iPad/Mac' if setting up for a child\n"
                        "4. Set a secure Screen Time passcode (4+ digits)\n"
                        "5. Configure App Limits, Downtime, and Content Restrictions\n\n"
                        "Screen Time passcode is essential to prevent users from bypassing controls."
                    ),
                ),
                "content_restrictions_configured": (
                    "Review Content Restrictions",
                    (
                        "Content restrictions are active. Review settings to ensure they are "
                        "appropriate:\n"
                        "1. System Settings > Screen Time > Content & Privacy\n"
                        "2. Verify Allowed Apps and Ratings are correct\n"
                        "3. Check Web Content restrictions\n"
                        "4. Review Privacy settings\n\n"
                        "Make sure these restrictions align with your family's needs."
                    ),
                ),
                "child_account_no_controls": (
                    "Set Up Parental Controls for Child Account",
                    (
                        "To set up parental controls for a child account:\n"
                        "1. System Settings > Screen Time\n"
                        "2. Click 'Family' or select the child's account\n"
                        "3. Click 'Enable Screen Time'\n"
                        "4. Set a secure Screen Time passcode\n"
                        "5. Configure App Limits, Downtime, and Content Restrictions\n\n"
                        "Parental controls help protect children by limiting access to apps "
                        "and content, and restricting screen time."
                    ),
                ),
                "child_account_has_controls": (
                    "Parental Controls Active for Child Account",
                    (
                        "Parental controls are configured for this child account. Regularly:\n"
                        "1. Verify the Screen Time passcode is still secure\n"
                        "2. Review App Limits to ensure they're appropriate\n"
                        "3. Check Content & Privacy restrictions\n"
                        "4. Review Downtime schedule\n\n"
                        "Update controls as the child grows and your family's needs change."
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

    def _get_content_restrictions(self) -> str:
        """Get content restrictions summary.

        Returns:
            A string describing the content restrictions, or empty string if none found
        """
        try:
            result = subprocess.run(
                ["defaults", "read", "com.apple.applicationaccess"],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0 and result.stdout.strip():
                # Just return that restrictions are configured
                return "Content restrictions are active"
            return ""
        except OSError:
            return ""

    def _check_child_accounts(self) -> list[tuple[str, bool]]:
        """Check for child accounts and their parental control status.

        Returns:
            A list of tuples (username, has_parental_controls) for non-system users
        """
        child_accounts = []

        # Get list of all users
        try:
            result = subprocess.run(
                ["dscl", ".", "-list", "/Users"],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                return []

            users = result.stdout.strip().split("\n")
        except OSError:
            return []

        # Check each non-system user for parental controls
        for user in users:
            user = user.strip()
            # Skip system users (start with underscore or are root/nobody)
            if not user or user.startswith("_") or user in ("root", "nobody"):
                continue

            # Check if user has parental controls configured
            try:
                result = subprocess.run(
                    ["dscl", ".", "-read", f"/Users/{user}", "ParentalControls"],
                    capture_output=True,
                    text=True,
                )
                # If we get a result with content, parental controls are configured
                has_controls = result.returncode == 0 and bool(result.stdout.strip())
                child_accounts.append((user, has_controls))
            except OSError:
                # If dscl fails, assume no controls
                child_accounts.append((user, False))

        return child_accounts
