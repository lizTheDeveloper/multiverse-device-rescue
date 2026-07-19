import subprocess
import plistlib
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
    name = "appleid_security_check"
    category = "security"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "5s"

    emits_codes = [
        "security.appleid_security_check.appleid_signin",
        "security.appleid_security_check.icloud_keychain",
        "security.appleid_security_check.autoupdate_disabled",
        "security.appleid_security_check.appleid_summary",
    ]

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Check Apple ID sign-in status
        appleid_signed_in = self._check_appleid_signin()
        twofa_enabled = self._check_two_factor_auth()
        keychain_enabled = self._check_icloud_keychain()
        icloud_devices = self._get_icloud_devices()
        autoupdate_enabled = self._check_autoupdate_enabled()
        mail_privacy = self._check_mail_privacy_protection()
        private_relay = self._check_private_relay()

        # Flag WARNING if Apple ID not signed in
        if not appleid_signed_in:
            findings.append(
                Finding(
                    title="Apple ID not signed in",
                    description=(
                        "No Apple ID account is currently signed in on this Mac. "
                        "This means iCloud backup, Find My, and other Apple services are not active. "
                        "Consider signing in to protect your device and data."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.appleid_security_check.appleid_signin",
                    data={"check": "appleid_signin"},
                )
            )

        # Flag WARNING if iCloud Keychain is disabled
        if not keychain_enabled:
            findings.append(
                Finding(
                    title="iCloud Keychain is disabled",
                    description=(
                        "iCloud Keychain is not enabled. Your passwords and payment information "
                        "are not being synced and backed up to iCloud. "
                        "This reduces security and makes recovery difficult if your passwords are lost."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.appleid_security_check.icloud_keychain",
                    data={"check": "icloud_keychain"},
                )
            )

        # Flag WARNING if automatic updates are disabled
        if not autoupdate_enabled:
            findings.append(
                Finding(
                    title="Automatic software updates are disabled",
                    description=(
                        "Automatic software updates are not enabled on this Mac. "
                        "Security patches are critical for protecting against vulnerabilities. "
                        "Enable automatic updates to ensure your system stays secure."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.appleid_security_check.autoupdate_disabled",
                    data={"check": "autoupdate_disabled"},
                )
            )

        # INFO finding with comprehensive security summary
        summary_lines = []
        summary_lines.append(
            f"Apple ID signed in: {'Yes' if appleid_signed_in else 'No'}"
        )
        summary_lines.append(f"Two-factor authentication: {'Enabled' if twofa_enabled else 'Not verified'}")
        summary_lines.append(f"iCloud Keychain: {'Enabled' if keychain_enabled else 'Disabled'}")
        summary_lines.append(f"Private Relay: {'Active' if private_relay else 'Not active'}")
        summary_lines.append(f"Mail Privacy Protection: {'Enabled' if mail_privacy else 'Not enabled'}")
        summary_lines.append(f"Devices on this account: {len(icloud_devices)}")
        summary_lines.append(f"Automatic updates: {'Enabled' if autoupdate_enabled else 'Disabled'}")

        findings.append(
            Finding(
                title="Apple ID and iCloud security status",
                description="\n".join(summary_lines),
                severity=Severity.INFO,
                category=self.category,
                code="security.appleid_security_check.appleid_summary",
                data={
                    "check": "appleid_summary",
                    "appleid_signed_in": appleid_signed_in,
                    "twofa_enabled": twofa_enabled,
                    "keychain_enabled": keychain_enabled,
                    "private_relay": private_relay,
                    "mail_privacy": mail_privacy,
                    "icloud_devices_count": len(icloud_devices),
                    "autoupdate_enabled": autoupdate_enabled,
                },
            )
        )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            check = finding.data.get("check")

            if check == "appleid_signin":
                actions.append(
                    Action(
                        title="Sign in to Apple ID",
                        description=(
                            "To sign in to your Apple ID on this Mac:\n"
                            "1. Go to System Settings > [Your Name] (at the top)\n"
                            "2. If not signed in, click 'Sign in with your Apple ID'\n"
                            "3. Enter your Apple ID email and password\n"
                            "4. Follow the two-factor authentication prompts\n"
                            "5. Enable iCloud features like Find My, Keychain, and backups"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=False,
                        error="Informational only - requires manual action",
                    )
                )

            elif check == "icloud_keychain":
                actions.append(
                    Action(
                        title="Enable iCloud Keychain",
                        description=(
                            "To enable iCloud Keychain:\n"
                            "1. Go to System Settings > [Your Name] > iCloud\n"
                            "2. Find 'Passwords and Keychain' or 'Keychain'\n"
                            "3. Toggle it ON\n"
                            "4. Confirm with your Apple ID password and two-factor authentication\n"
                            "This will encrypt and backup your passwords and payment information."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=False,
                        error="Informational only - requires manual action",
                    )
                )

            elif check == "autoupdate_disabled":
                actions.append(
                    Action(
                        title="Enable automatic software updates",
                        description=(
                            "To enable automatic updates:\n"
                            "1. Go to System Settings > General > Software Update\n"
                            "2. Click 'Automatic Updates'\n"
                            "3. Check the boxes for:\n"
                            "   - Install system data and security updates\n"
                            "   - Install application updates from App Store\n"
                            "   - Install macOS updates\n"
                            "Automatic updates ensure security patches are applied promptly."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=False,
                        error="Informational only - requires manual action",
                    )
                )

            elif check == "appleid_summary":
                actions.append(
                    Action(
                        title="Review Apple ID security settings",
                        description=(
                            "Review your Apple ID security at:\n"
                            "https://appleid.apple.com/account/\n\n"
                            "Key security features to verify:\n"
                            "1. Two-Factor Authentication (2FA) is ENABLED\n"
                            "2. Trusted Phone Numbers are up-to-date\n"
                            "3. Devices list shows only your devices\n"
                            "4. Trusted Devices section is clean\n"
                            "5. Security questions are set if needed\n\n"
                            "Additionally, on this Mac:\n"
                            "1. Enable iCloud Keychain for password backup\n"
                            "2. Enable automatic software updates\n"
                            "3. Keep Find My enabled for device recovery"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=False,
                        error="Informational only - requires manual action",
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _check_appleid_signin(self) -> bool:
        """Check if signed in to Apple ID via MobileMeAccounts.plist."""
        try:
            plist_path = Path.home() / "Library/Preferences/MobileMeAccounts.plist"
            if not plist_path.exists():
                return False

            with open(plist_path, "rb") as f:
                plist = plistlib.load(f)

            # Check if accounts array exists and has entries
            accounts = plist.get("Accounts", [])
            return len(accounts) > 0
        except Exception:
            return False

    def _check_two_factor_auth(self) -> bool:
        """Check if two-factor authentication is enabled.

        This checks for the presence of 2FA via system defaults.
        True if SafetyPhoneNumbers or similar indicators exist.
        """
        try:
            result = subprocess.run(
                [
                    "defaults",
                    "read",
                    str(Path.home() / "Library/Preferences/com.apple.security.plist"),
                    "AppleIDAccount",
                ],
                capture_output=True,
                text=True,
            )
            # If we get account data, 2FA is likely enabled
            return result.returncode == 0
        except Exception:
            return False

    def _check_icloud_keychain(self) -> bool:
        """Check if iCloud Keychain is enabled."""
        try:
            result = subprocess.run(
                [
                    "defaults",
                    "read",
                    str(Path.home() / "Library/Preferences/com.apple.iCloudKeychain"),
                ],
                capture_output=True,
                text=True,
            )
            # If file exists and readable, keychain is configured
            return result.returncode == 0 and result.stdout.strip()
        except Exception:
            return False

    def _check_private_relay(self) -> bool:
        """Check if iCloud Private Relay is active (Safari privacy feature)."""
        try:
            result = subprocess.run(
                [
                    "defaults",
                    "read",
                    str(Path.home() / "Library/Preferences/com.apple.Safari"),
                    "ICloudPrivateRelayEnabled",
                ],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                output = result.stdout.strip()
                return output == "1" or output.lower() == "true"
            return False
        except Exception:
            return False

    def _check_mail_privacy_protection(self) -> bool:
        """Check if Mail Privacy Protection is enabled."""
        try:
            result = subprocess.run(
                [
                    "defaults",
                    "read",
                    "com.apple.mail-shared",
                    "MailPrivacyProtectionEnabled",
                ],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                output = result.stdout.strip()
                return output == "1" or output.lower() == "true"
            return False
        except Exception:
            return False

    def _get_icloud_devices(self) -> list[str]:
        """Get list of devices signed into the Apple ID via system_profiler."""
        try:
            result = subprocess.run(
                ["system_profiler", "SPiCloudDataType"],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                # Parse device names from output
                devices = []
                for line in result.stdout.split("\n"):
                    line = line.strip()
                    if "Device Name:" in line:
                        device = line.split("Device Name:")[-1].strip()
                        if device:
                            devices.append(device)
                return devices
            return []
        except Exception:
            return []

    def _check_autoupdate_enabled(self) -> bool:
        """Check if automatic software updates are enabled."""
        try:
            result = subprocess.run(
                [
                    "defaults",
                    "read",
                    "/Library/Preferences/com.apple.SoftwareUpdate",
                    "AutomaticCheckEnabled",
                ],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                output = result.stdout.strip()
                return output == "1" or output.lower() == "true"
            return False
        except Exception:
            return False
