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

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Check if Guest account is enabled
        guest_enabled = self._is_guest_enabled()
        if guest_enabled:
            findings.append(
                Finding(
                    title="Guest account is enabled",
                    description=(
                        "The Guest account is enabled on this Mac. "
                        "This is a security risk, especially on family or shared devices. "
                        "Anyone can log in as Guest without a password. "
                        "Disable it if you don't need it."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "guest_enabled"},
                )
            )

        # Check if Guest can access shared folders (AFP/AppleFileServer)
        guest_afp_access = self._guest_has_afp_access()
        if guest_afp_access:
            findings.append(
                Finding(
                    title="Guest can access shared folders via AFP",
                    description=(
                        "Guest account has access to shared folders via AFP (Apple File Server). "
                        "This allows anyone to access your files without authentication. "
                        "Disable this setting if you don't need Guest access to shared folders."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "guest_afp_access"},
                )
            )

        # Check if Guest can access shared folders via SMB
        guest_smb_access = self._guest_has_smb_access()
        if guest_smb_access:
            findings.append(
                Finding(
                    title="Guest can access shared folders via SMB",
                    description=(
                        "Guest account has access to shared folders via SMB (Windows file sharing). "
                        "This allows anyone to access your files without authentication. "
                        "Disable this setting if you don't need Guest access to shared folders."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
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
