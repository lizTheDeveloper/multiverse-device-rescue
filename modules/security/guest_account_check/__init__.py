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
    name = "guest_account_check"
    category = "security"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "5s"

    emits_codes = [
        "security.guest_account_check.guest_enabled",
        "security.guest_account_check.guest_afp_access",
        "security.guest_account_check.guest_smb_access",
        "security.guest_account_check.guest_disabled",
    ]

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Check if Guest account is enabled
        guest_enabled = self._is_guest_enabled()
        if guest_enabled:
            findings.append(
                Finding(
                    title="Your Mac allows anyone to log in as 'Guest'",
                    description=(
                        "Your Mac has a 'Guest' account turned on. This lets anyone sitting "
                        "at your computer log in without a password. This is a common "
                        "setting, but it can be risky if you are worried about someone "
                        "else using your device.\n\n"
                        "What to do: Open System Settings > Users & Groups, click the "
                        "info button next to Guest User, and turn off 'Allow guests to "
                        "log in to this computer'."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.guest_account_check.guest_enabled",
                    data={"check": "guest_enabled"},
                )
            )

        # Check if Guest can access shared folders (AFP/AppleFileServer)
        guest_afp_access = self._guest_has_afp_access()
        if guest_afp_access:
            findings.append(
                Finding(
                    title="Guest users can open your shared folders",
                    description=(
                        "Your Mac allows the 'Guest' account to access files you have "
                        "shared over the network. This means anyone on your home network "
                        "can open these folders without a password. If you share files "
                        "with family, this might be intentional, but if you are worried "
                        "about privacy, it is safer to turn it off.\n\n"
                        "What to do: Open System Settings > Users & Groups, click the "
                        "info button next to Guest User, and turn off 'Allow guest users "
                        "to connect to shared folders'."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.guest_account_check.guest_afp_access",
                    data={"check": "guest_afp_access"},
                )
            )

        # Check if Guest can access shared folders via SMB
        guest_smb_access = self._guest_has_smb_access()
        if guest_smb_access:
            findings.append(
                Finding(
                    title="Guest users can open your shared folders",
                    description=(
                        "Your Mac allows the 'Guest' account to access files you have "
                        "shared using Windows file sharing. This means anyone on your "
                        "home network can open these folders without a password. If you "
                        "share files with family, this might be intentional, but if you "
                        "are worried about privacy, it is safer to turn it off.\n\n"
                        "What to do: Open System Settings > Users & Groups, click the "
                        "info button next to Guest User, and turn off 'Allow guest users "
                        "to connect to shared folders'."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.guest_account_check.guest_smb_access",
                    data={"check": "guest_smb_access"},
                )
            )

        # If no issues found, add an INFO finding
        if not findings:
            findings.append(
                Finding(
                    title="Guest account is properly disabled",
                    description=(
                        "The Guest account is disabled, and Guest access to shared folders is disabled. "
                        "This is the secure default configuration."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.guest_account_check.guest_disabled",
                    data={"check": "guest_disabled"},
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            check_type = finding.data.get("check")
            if check_type == "guest_enabled":
                title = "Disable Guest account"
                description = (
                    "To disable the Guest account, open System Settings > General > Users & Groups, "
                    "click the lock icon to unlock, then right-click on 'Guest' and select 'Delete'. "
                    "Alternatively, run: sudo defaults write /Library/Preferences/com.apple.loginwindow GuestEnabled 0"
                )
            elif check_type == "guest_afp_access":
                title = "Disable Guest AFP file sharing access"
                description = (
                    "To disable Guest access to shared folders via AFP, open System Settings > General > Sharing, "
                    "uncheck 'File Sharing', or use: sudo defaults write /Library/Preferences/com.apple.AppleFileServer guestAccess 0"
                )
            elif check_type == "guest_smb_access":
                title = "Disable Guest SMB file sharing access"
                description = (
                    "To disable Guest access to shared folders via SMB, open System Settings > General > Sharing, "
                    "uncheck 'File Sharing', or use: sudo defaults write /Library/Preferences/SystemConfiguration/com.apple.smb.server AllowGuestAccess 0"
                )
            elif check_type == "guest_disabled":
                title = "Guest account is secure"
                description = (
                    "No action needed. The Guest account is properly disabled and "
                    "Guest access to shared folders is disabled."
                )
            else:
                continue

            actions.append(
                Action(
                    title=title,
                    description=description,
                    risk_level=RiskLevel.SAFE,
                    success=True,
                    error=None,
                )
            )
        return FixResult(module_name=self.name, actions=actions)

    def _is_guest_enabled(self) -> bool:
        """Check if Guest account is enabled."""
        try:
            result = subprocess.run(
                [
                    "defaults",
                    "read",
                    "/Library/Preferences/com.apple.loginwindow",
                    "GuestEnabled",
                ],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                return "1" in result.stdout
            return False
        except OSError:
            return False

    def _guest_has_afp_access(self) -> bool:
        """Check if Guest can access shared folders via AFP."""
        try:
            result = subprocess.run(
                [
                    "defaults",
                    "read",
                    "/Library/Preferences/com.apple.AppleFileServer",
                    "guestAccess",
                ],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                return "1" in result.stdout
            return False
        except OSError:
            return False

    def _guest_has_smb_access(self) -> bool:
        """Check if Guest can access shared folders via SMB."""
        try:
            result = subprocess.run(
                [
                    "defaults",
                    "read",
                    "/Library/Preferences/SystemConfiguration/com.apple.smb.server",
                    "AllowGuestAccess",
                ],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                return "1" in result.stdout
            return False
        except OSError:
            return False
