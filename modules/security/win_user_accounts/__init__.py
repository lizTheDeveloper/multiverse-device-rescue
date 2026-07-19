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
    name = "win_user_accounts"
    category = "security"
    platforms = [Platform.WIN32]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "5s"

    emits_codes = [
        "security.win_user_accounts.guest_account_enabled",
        "security.win_user_accounts.auto_login_enabled",
        "security.win_user_accounts.no_min_password_length",
        "security.win_user_accounts.multiple_admin_accounts",
    ]

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
                        code="security.win_user_accounts.guest_account_enabled",
                        data={"check": "guest_enabled"},
                    )
                )
        except Exception as e:
            pass

        # Check if auto-login is configured
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
                        code="security.win_user_accounts.auto_login_enabled",
                        data={"check": "auto_login"},
                    )
                )
        except Exception as e:
            pass

        # Check password policy
        try:
            password_policy = self._get_password_policy()
            if password_policy and password_policy.get("min_length") == 0:
                findings.append(
                    Finding(
                        title="No minimum password length policy set",
                        description=(
                            "The password policy does not enforce a minimum password length. "
                            "Set a minimum password length requirement to strengthen security."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        code="security.win_user_accounts.no_min_password_length",
                        data={"check": "password_policy"},
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
                    code="security.win_user_accounts.multiple_admin_accounts",
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
                            "net user Guest /active:no"
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
                            "To disable automatic login:\n"
                            "1. Press Win + R\n"
                            "2. Type 'netplwiz' and press Enter\n"
                            "3. Uncheck 'Users must enter a user name and password to use this computer'\n"
                            "4. Click OK"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )
            elif check == "password_policy":
                actions.append(
                    Action(
                        title="Set minimum password length policy",
                        description=(
                            "To enforce a minimum password length:\n"
                            "1. Press Win + R\n"
                            "2. Type 'gpedit.msc' and press Enter\n"
                            "3. Navigate to: Computer Configuration > Windows Settings > Security Settings > "
                            "Account Policies > Password Policy\n"
                            "4. Set 'Minimum password length' to at least 8 characters"
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
                            "To remove admin access from a user:\n"
                            "1. Press Win + R\n"
                            "2. Type 'compmgmt.msc' and press Enter\n"
                            "3. Navigate to Local Users and Groups > Groups\n"
                            "4. Double-click 'Administrators'\n"
                            "5. Select the user to remove and click Remove"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _get_user_list(self) -> list[str]:
        """Get list of user accounts using 'net user' command."""
        result = subprocess.run(
            ["net", "user"],
            capture_output=True,
            text=True,
        )
        users = []
        lines = result.stdout.split("\n")
        # Skip header lines and footer, extract usernames
        capture = False
        for line in lines:
            line = line.strip()
            if "User accounts for" in line:
                capture = True
                continue
            if capture and line and not line.startswith("---"):
                # Split multiple usernames on same line (space-separated)
                for user in line.split():
                    if user and not user.startswith("-"):
                        users.append(user)
            if line.startswith("The command completed") or line.startswith("---"):
                break
        return users

    def _get_admin_users(self) -> list[str]:
        """Get list of users in the Administrators group."""
        try:
            result = subprocess.run(
                ["net", "localgroup", "Administrators"],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                return []
            users = []
            lines = result.stdout.split("\n")
            # Skip header lines, extract usernames
            capture = False
            for line in lines:
                line = line.strip()
                if "Alias name" in line or "Members" in line:
                    capture = True
                    continue
                if capture and line and not line.startswith("---"):
                    if line and not line.startswith("The command"):
                        users.append(line)
                if line.startswith("The command completed") or (
                    line.startswith("---") and users
                ):
                    break
            return users
        except Exception as e:
            return []

    def _is_guest_enabled(self) -> bool:
        """Check if the Guest account is enabled."""
        try:
            result = subprocess.run(
                ["net", "user", "Guest"],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                return False
            # Look for "Account active" or "Active" status
            output = result.stdout.lower()
            if "account active" in output:
                return "yes" in output or "true" in output
            return False
        except Exception as e:
            return False

    def _get_auto_login_user(self) -> str | None:
        """Check if automatic login is configured and return the username."""
        try:
            # Check registry for auto-login settings
            result = subprocess.run(
                [
                    "reg",
                    "query",
                    r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
                    "/v",
                    "AutoAdminLogon",
                ],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0 or "0x1" not in result.stdout:
                return None
            # If AutoAdminLogon is enabled, get the username
            result = subprocess.run(
                [
                    "reg",
                    "query",
                    r"HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
                    "/v",
                    "DefaultUserName",
                ],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                lines = result.stdout.split("\n")
                for line in lines:
                    if "DefaultUserName" in line:
                        parts = line.split()
                        if len(parts) >= 3:
                            return parts[-1].strip()
            return None
        except Exception as e:
            return None

    def _get_password_policy(self) -> dict | None:
        """Get password policy information using 'net accounts' command."""
        try:
            result = subprocess.run(
                ["net", "accounts"],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                return None
            policy = {}
            lines = result.stdout.split("\n")
            for line in lines:
                line = line.strip()
                if "Minimum password length" in line:
                    parts = line.split()
                    policy["min_length"] = int(parts[-1]) if parts[-1].isdigit() else 0
                if "Lockout threshold" in line:
                    parts = line.split()
                    policy["lockout_threshold"] = (
                        int(parts[-1]) if parts[-1].isdigit() else 0
                    )
            return policy if policy else None
        except Exception as e:
            return None
