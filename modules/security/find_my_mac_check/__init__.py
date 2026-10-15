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
    name = "find_my_mac_check"
    category = "security"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 85
    depends_on = []
    estimated_duration = "3s"

    emits_codes = [
        "security.find_my_mac_check.find_my_mac_disabled",
        "security.find_my_mac_check.location_services_disabled",
        "security.find_my_mac_check.icloud_not_signed_in",
        "security.find_my_mac_check.configured_ok",
    ]

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Check Find My Mac status
        find_my_mac_enabled = self._check_find_my_mac_enabled()

        # Check iCloud account status
        icloud_signed_in = self._check_icloud_signed_in()

        # Check Activation Lock status
        activation_lock_enabled = self._check_activation_lock()

        # Check Location Services status
        location_services_enabled = self._check_location_services_enabled()

        # Flag CRITICAL if Find My Mac is disabled
        if not find_my_mac_enabled:
            findings.append(
                Finding(
                    title="Find My Mac is turned off",
                    description=(
                        "Find My Mac is currently off. This means that if your Mac is "
                        "ever lost or stolen, you won't be able to see where it is, lock "
                        "it, or erase your data from a distance. This is a key safety "
                        "feature for recovering a missing device.\n\n"
                        "If someone else knows your Apple Account password, they will be "
                        "able to see where this Mac is too. If that worries you, change "
                        "the password first.\n\n"
                        "What to do: Open System Settings, click your name at the top, "
                        "choose iCloud, and turn on Find My Mac."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
                    code="security.find_my_mac_check.find_my_mac_disabled",
                    data={"find_my_mac_enabled": find_my_mac_enabled},
                )
            )

        # Flag WARNING if Location Services are disabled
        if not location_services_enabled:
            findings.append(
                Finding(
                    title="Location Services are turned off",
                    description=(
                        "Location Services are off, which stops Find My Mac from working. "
                        "Find My Mac needs to know your Mac's location to help you find "
                        "it if it goes missing. Turning this on allows the feature to "
                        "work as intended.\n\n"
                        "What to do: Go to System Settings > Privacy & Security > Location "
                        "Services and turn it on. Make sure Find My Mac is also checked "
                        "in the list below."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.find_my_mac_check.location_services_disabled",
                    data={"location_services_enabled": location_services_enabled},
                )
            )

        # Flag WARNING if iCloud is not signed in
        if not icloud_signed_in:
            findings.append(
                Finding(
                    title="You are not signed in to iCloud",
                    description=(
                        "Find My Mac requires an active iCloud account to work, but you "
                        "are not currently signed in. Without a sign-in, the feature cannot "
                        "connect to your Apple ID to help locate the device.\n\n"
                        "What to do: Open System Settings and click 'Sign in' at the top "
                        "of the sidebar."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.find_my_mac_check.icloud_not_signed_in",
                    data={"icloud_signed_in": icloud_signed_in},
                )
            )

        # Flag INFO reporting Find My Mac and Activation Lock status
        if find_my_mac_enabled and location_services_enabled and icloud_signed_in:
            activation_status = (
                "enabled" if activation_lock_enabled else "disabled or unknown"
            )
            findings.append(
                Finding(
                    title="Find My Mac is properly configured",
                    description=(
                        f"Find My Mac is enabled with Location Services active and iCloud signed in. "
                        f"Activation Lock is {activation_status}. "
                        "Your device can be located and remotely managed if lost or stolen."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.find_my_mac_check.configured_ok",
                    data={
                        "find_my_mac_enabled": find_my_mac_enabled,
                        "location_services_enabled": location_services_enabled,
                        "icloud_signed_in": icloud_signed_in,
                        "activation_lock_enabled": activation_lock_enabled,
                    },
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            if finding.code == "security.find_my_mac_check.find_my_mac_disabled":
                actions.append(
                    Action(
                        title="Enable Find My Mac",
                        description=(
                            "To enable Find My Mac:\n"
                            "1. Open System Settings > [Your Name] > iCloud\n"
                            "2. Make sure you're signed in with your Apple ID\n"
                            "3. Toggle 'Find My Mac' ON\n"
                            "This requires an active iCloud account and Location Services to be enabled."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif finding.code == "security.find_my_mac_check.location_services_disabled":
                actions.append(
                    Action(
                        title="Enable Location Services",
                        description=(
                            "To enable Location Services:\n"
                            "1. Open System Settings > Privacy & Security > Location Services\n"
                            "2. Toggle 'Location Services' ON\n"
                            "3. Ensure Find My Mac has location access enabled"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif finding.code == "security.find_my_mac_check.icloud_not_signed_in":
                actions.append(
                    Action(
                        title="Sign in to iCloud",
                        description=(
                            "To sign in to iCloud:\n"
                            "1. Open System Settings > [Your Name]\n"
                            "2. If not signed in, click 'Sign in with Apple ID'\n"
                            "3. Enter your Apple ID and password\n"
                            "4. Navigate to iCloud and enable Find My Mac"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _check_find_my_mac_enabled(self) -> bool:
        """Check if Find My Mac is enabled via defaults read."""
        try:
            result = subprocess.run(
                [
                    "defaults",
                    "read",
                    "/Library/Preferences/com.apple.FindMyMac.plist",
                    "FMMEnabled",
                ],
                capture_output=True,
                text=True,
            )
            output = result.stdout.strip()
            return output == "1"
        except Exception:
            return False

    def _check_icloud_signed_in(self) -> bool:
        """Check if iCloud account is signed in via defaults read."""
        try:
            home = str(Path.home())
            result = subprocess.run(
                [
                    "defaults",
                    "read",
                    f"{home}/Library/Preferences/MobileMeAccounts.plist",
                ],
                capture_output=True,
                text=True,
            )
            # If the file exists and has content, iCloud is likely signed in
            return result.returncode == 0 and len(result.stdout.strip()) > 0
        except Exception:
            return False

    def _check_activation_lock(self) -> bool:
        """Check if Activation Lock is enabled via system_profiler."""
        try:
            result = subprocess.run(
                ["system_profiler", "SPHardwareDataType"],
                capture_output=True,
                text=True,
            )
            # Look for Activation Lock in output
            return "Activation Lock: Enabled" in result.stdout
        except Exception:
            return False

    def _check_location_services_enabled(self) -> bool:
        """Check if Location Services are enabled via defaults read."""
        try:
            result = subprocess.run(
                [
                    "defaults",
                    "read",
                    "/var/db/locationd/Library/Preferences/ByHost/com.apple.locationd",
                    "LocationServicesEnabled",
                ],
                capture_output=True,
                text=True,
            )
            output = result.stdout.strip()
            return output == "1"
        except Exception:
            return False
