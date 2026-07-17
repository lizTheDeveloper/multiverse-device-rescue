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
    name = "user_account_audit"
    category = "security"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "5s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Get list of all user accounts
        try:
            users = self._get_user_list()
        except Exception as e:
            users = []

        # Get admin group members
        try:
            admin_users = self._get_admin_users()
        except Exception as e:
            admin_users = []

        # Check if Guest account is enabled
        try:
            guest_enabled = self._is_guest_enabled()
            if guest_enabled:
                findings.append(
                    Finding(
                        title="Guest account is enabled",
                        description=(
                            "The Guest account is enabled. This allows "
                            "anyone with physical access to log in without "
                            "a password. Consider disabling it."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={"check": "guest_enabled"},
                    )
                )
        except Exception as e:
            pass

        # Check if automatic login is enabled
        try:
            auto_login_user = self._get_auto_login_user()
            if auto_login_user:
                findings.append(
                    Finding(
                        title=f"Automatic login is enabled for {auto_login_user}",
                        description=(
                            f"The system will automatically log in as '{auto_login_user}' "
                            "on startup. This bypasses the login screen and password "
                            "protection. Consider disabling it."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={"check": "auto_login"},
                    )
                )
        except Exception as e:
            pass

        # Report admin users (informational)
        if admin_users and len(admin_users) > 1:
            admin_list = ", ".join(admin_users)
            findings.append(
                Finding(
                    title=f"Multiple admin accounts found",
                    description=(
                        f"The following accounts have admin privileges: {admin_list}. "
                        "Review to ensure only necessary users have elevated access."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "admin_accounts", "users": admin_users},
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            check = finding.data.get("check")
            if check == "guest_enabled":
                actions.append(
                    Action(
                        title="Disable Guest account",
                        description=(
                            "To disable the Guest account, run:\n"
                            "sudo defaults write /Library/Preferences/com.apple.loginwindow "
                            "GuestEnabled -bool false"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )
            elif check == "auto_login":
                actions.append(
                    Action(
                        title="Disable automatic login",
                        description=(
                            "To disable automatic login, run:\n"
                            "sudo defaults delete /Library/Preferences/com.apple.loginwindow "
                            "autoLoginUser"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )
            elif check == "admin_accounts":
                users = finding.data.get("users", [])
                user_list = ", ".join(users)
                actions.append(
                    Action(
                        title="Review admin accounts",
                        description=(
                            f"The following accounts have admin privileges: {user_list}. "
                            "To remove admin access from a user, run:\n"
                            "sudo dscl . -delete /Groups/admin GroupMembers <username>"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _get_user_list(self) -> list[str]:
        """Get list of non-system user accounts."""
        result = subprocess.run(
            ["dscl", ".", "-list", "/Users"],
            capture_output=True,
            text=True,
        )
        users = [u.strip() for u in result.stdout.split("\n") if u.strip()]
        # Filter out system accounts (starting with _)
        return [u for u in users if not u.startswith("_")]

    def _get_admin_users(self) -> list[str]:
        """Get list of users in the admin group."""
        try:
            result = subprocess.run(
                ["dscl", ".", "-read", "/Groups/admin", "GroupMembership"],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                return []
            # Parse "GroupMembership: user1 user2 user3"
            line = result.stdout.strip()
            if line.startswith("GroupMembership:"):
                admin_users = line.replace("GroupMembership:", "").strip().split()
                return admin_users
            return []
        except Exception as e:
            return []

    def _is_guest_enabled(self) -> bool:
        """Check if the Guest account is enabled."""
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
            if result.returncode != 0:
                return False
            value = result.stdout.strip()
            return value == "1"
        except Exception as e:
            return False

    def _get_auto_login_user(self) -> str | None:
        """Check if automatic login is enabled and return the username."""
        try:
            result = subprocess.run(
                [
                    "defaults",
                    "read",
                    "/Library/Preferences/com.apple.loginwindow",
                    "autoLoginUser",
                ],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                return None
            username = result.stdout.strip()
            return username if username else None
        except Exception as e:
            return None
