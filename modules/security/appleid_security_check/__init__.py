import subprocess
import plistlib
import re
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

    # The one file this module opens directly rather than reading through
    # `defaults`. An attribute so a test can supply a real fixture plist:
    # patching plistlib.load is not enough, because open() still has to succeed.
    mobileme_plist_path: Path | None = None

    def _mobileme_plist_path(self) -> Path:
        if self.mobileme_plist_path is not None:
            return Path(self.mobileme_plist_path)
        return Path.home() / "Library/Preferences/MobileMeAccounts.plist"

    emits_codes = [
        "security.appleid_security_check.appleid_signin",
        "security.appleid_security_check.icloud_keychain",
        "security.appleid_security_check.autoupdate_disabled",
        "security.appleid_security_check.appleid_summary",
        "security.appleid_security_check.icloud_keychain_unknown",
        "security.appleid_security_check.autoupdate_unknown",
    ]

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Check Apple ID sign-in status
        appleid_signed_in = self._check_appleid_signin()
        twofa_enabled = self._check_two_factor_auth()
        keychain_enabled = self._check_icloud_keychain()
        icloud_devices = self._get_icloud_devices()
        self._autoupdate_security_only = False
        autoupdate_enabled = self._check_autoupdate_enabled()
        mail_privacy = self._check_mail_privacy_protection()
        private_relay = self._check_private_relay()

        # Flag WARNING if Apple ID not signed in
        if not appleid_signed_in:
            findings.append(
                Finding(
                    title="Apple ID not signed in",
                    description=(
                        "No Apple ID is currently signed in on this Mac. This means iCloud "
                        "backup, Find My, and other Apple services are not active.\n\n"
                        "What to do: Open System Settings, click your name at the top, "
                        "and sign in with your Apple ID."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.appleid_security_check.appleid_signin",
                    data={"check": "appleid_signin"},
                )
            )

        # Each of these reads as True, False or None (couldn't tell); None is
        # "couldn't check", never "off".
        if keychain_enabled is None and appleid_signed_in:
            findings.append(
                Finding(
                    title="Couldn't check whether iCloud Keychain is on",
                    description=(
                        "Device Rescue couldn't read whether iCloud Keychain (Passwords) "
                        "is turned on for your Apple Account. This is not a sign that "
                        "anything is wrong. To see for yourself, open System Settings, "
                        "click your name, then iCloud, and look at Passwords."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.appleid_security_check.icloud_keychain_unknown",
                    data={"check": "icloud_keychain_unknown"},
                )
            )

        # Flag WARNING if iCloud Keychain is disabled
        if keychain_enabled is False:
            findings.append(
                Finding(
                    title="iCloud Keychain is disabled",
                    description=(
                        "iCloud Keychain is turned off. This means your saved passwords "
                        "and payment details are not being backed up to Apple's servers. "
                        "If you forget a password or lose your device, you may not be "
                        "able to recover them.\n\n"
                        "If someone else knows your Apple Account password, they would "
                        "see these passwords too, so change it first if that worries "
                        "you.\n\n"
                        "What to do: Open System Settings, click your name, choose "
                        "iCloud, and turn on Passwords (called Passwords & Keychain on "
                        "some versions)."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.appleid_security_check.icloud_keychain",
                    data={"check": "icloud_keychain"},
                )
            )

        if autoupdate_enabled is None:
            findings.append(
                Finding(
                    title="Couldn't check whether updates install automatically",
                    description=(
                        "Device Rescue couldn't read your Mac's automatic update settings. "
                        "This is not a sign that anything is wrong. To see for yourself, "
                        "open System Settings > General > Software Update."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.appleid_security_check.autoupdate_unknown",
                    data={"check": "autoupdate_unknown"},
                )
            )

        # Flag WARNING if automatic updates are disabled
        if autoupdate_enabled is False:
            findings.append(
                Finding(
                    title="Your Mac doesn't install updates automatically",
                    description=(
                        "Automatic updates are off, so security fixes only arrive when "
                        "you go and get them.\n\n"
                        "What to do: Open System Settings > General > Software Update, "
                        "click the info button next to Automatic Updates, and turn the "
                        "options on."
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
        def _say(value, on="Enabled", off="Disabled"):
            return "Couldn't check" if value is None else (on if value else off)

        summary_lines.append(f"iCloud Keychain: {_say(keychain_enabled)}")
        summary_lines.append(f"Private Relay: {'Active' if private_relay else 'Not active'}")
        summary_lines.append(f"Mail Privacy Protection: {'Enabled' if mail_privacy else 'Not enabled'}")
        summary_lines.append(f"Devices on this account: {len(icloud_devices)}")
        if autoupdate_enabled is True and getattr(self, "_autoupdate_security_only", False):
            # Only CriticalUpdateInstall is on: security responses install, but
            # macOS updates don't.
            summary_lines.append("Automatic updates: Security updates only")
        else:
            summary_lines.append(f"Automatic updates: {_say(autoupdate_enabled)}")

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
            plist_path = self._mobileme_plist_path()
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

    def _check_icloud_keychain(self) -> bool | None:
        """Is iCloud Keychain (Passwords) syncing? None if it couldn't be read.

        The switch is the KEYCHAIN_SYNC service of the signed-in account in
        MobileMeAccounts.plist. The old read of a com.apple.iCloudKeychain
        preferences domain, which macOS doesn't create, said "disabled" on a
        Mac with iCloud Keychain on.
        """
        path = self._mobileme_plist_path()
        try:
            if not path.exists():
                return False  # never signed in to an Apple Account
            with open(path, "rb") as f:
                plist = plistlib.load(f)
        except Exception:
            return None
        accounts = plist.get("Accounts") or []
        if not accounts:
            return False  # no Apple Account signed in, so nothing syncs
        for account in accounts:
            for service in account.get("Services") or []:
                if service.get("Name") == "KEYCHAIN_SYNC":
                    enabled = service.get("Enabled")
                    if isinstance(enabled, bool):
                        return enabled
                    if enabled in (0, 1):
                        return bool(enabled)
        return None

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

    def _check_autoupdate_enabled(self) -> bool | None:
        """Does the Mac install updates automatically? None if it couldn't tell.

        Reads the whole SoftwareUpdate domain. AutomaticCheckEnabled is absent
        unless someone changed it (macOS's default is on), so reading only that
        key reported "updates are off" on a Mac with every option on. Installs
        are on when macOS updates or security responses install automatically.
        """
        try:
            result = subprocess.run(
                ["defaults", "read", "/Library/Preferences/com.apple.SoftwareUpdate"],
                capture_output=True,
                text=True,
                timeout=15,
            )
        except Exception:
            return None
        if result.returncode != 0 or not isinstance(result.stdout, str):
            return None
        values = {
            m.group(1): m.group(2)
            for m in re.finditer(r"^\s*(\w+)\s*=\s*(\d+);", result.stdout, re.MULTILINE)
        }
        installs = [
            values.get("AutomaticallyInstallMacOSUpdates"),
            values.get("CriticalUpdateInstall"),
        ]
        self._autoupdate_security_only = (
            values.get("CriticalUpdateInstall") == "1"
            and values.get("AutomaticallyInstallMacOSUpdates") != "1"
        )
        if values.get("AutomaticCheckEnabled") == "0":
            return False
        if "1" in installs:
            return True
        if installs == ["0", "0"]:
            return False
        return None
