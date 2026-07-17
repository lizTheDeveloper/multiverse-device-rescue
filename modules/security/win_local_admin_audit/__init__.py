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
    name = "win_local_admin_audit"
    category = "security"
    platforms = [Platform.WIN32]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "5s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Get admin group members
        admin_users = []
        try:
            admin_users = self._get_admin_users()
        except Exception as e:
            pass

        # Check if Guest account is enabled
        try:
            guest_enabled = self._is_guest_enabled()
            if guest_enabled:
                findings.append(
                    Finding(
                        title="Guest account is enabled",
                        description=(
                            "The Guest account is enabled. This is a critical security risk "
                            "as it allows unauthorized access without a password."
                        ),
                        severity=Severity.CRITICAL,
                        category=self.category,
                        data={"check": "guest_enabled"},
                    )
                )
        except Exception as e:
            pass

        # Check if built-in Administrator account is enabled
        try:
            admin_enabled = self._is_builtin_admin_enabled()
            if admin_enabled:
                findings.append(
                    Finding(
                        title="Built-in Administrator account is enabled",
                        description=(
                            "The built-in Administrator account is enabled. This account should "
                            "typically be disabled and administrative tasks performed via a "
                            "standard user account with elevated privileges when needed."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={"check": "builtin_admin_enabled"},
                    )
                )
        except Exception as e:
            pass

        # Check for excessive admin accounts (>3)
        if admin_users and len(admin_users) > 3:
            findings.append(
                Finding(
                    title=f"Excessive administrator accounts ({len(admin_users)} found)",
                    description=(
                        f"Found {len(admin_users)} administrator accounts: {', '.join(admin_users)}. "
                        "Having more than 3 admin accounts increases the attack surface. "
                        "Review and remove unnecessary administrative access."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "excessive_admins", "users": admin_users},
                )
            )

        # Check admin accounts for blank passwords
        blank_password_users = []
        no_password_expires = []
        admin_status = {}

        for user in admin_users:
            try:
                user_info = self._get_user_info(user)
                admin_status[user] = user_info

                # Check for blank password
                if user_info.get("password_required") is False:
                    blank_password_users.append(user)

                # Check for password never expires
                if user_info.get("password_never_expires") is True:
                    no_password_expires.append(user)
            except Exception as e:
                pass

        # Flag critical if any admin has no password
        if blank_password_users:
            findings.append(
                Finding(
                    title="Admin account(s) with no password",
                    description=(
                        f"The following admin account(s) have no password requirement: "
                        f"{', '.join(blank_password_users)}. This is a critical security risk. "
                        f"All admin accounts must have strong passwords."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
                    data={"check": "blank_password", "users": blank_password_users},
                )
            )

        # Flag warning if admin accounts have password never expires
        if no_password_expires:
            findings.append(
                Finding(
                    title="Admin account(s) with password never expires",
                    description=(
                        f"The following admin account(s) have 'Password Never Expires' set: "
                        f"{', '.join(no_password_expires)}. "
                        f"Passwords should expire periodically to reduce the window of "
                        f"compromise from stolen credentials."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "password_never_expires", "users": no_password_expires},
                )
            )

        # Report all admin accounts (informational)
        if admin_users:
            status_details = []
            for user in admin_users:
                if user in admin_status:
                    info = admin_status[user]
                    enabled = "Enabled" if info.get("enabled", True) else "Disabled"
                    pwd_req = "Required" if info.get("password_required", True) else "Not Required"
                    status_details.append(f"{user} ({enabled}, Password: {pwd_req})")
                else:
                    status_details.append(f"{user} (Status unknown)")

            findings.append(
                Finding(
                    title=f"Local administrator accounts found",
                    description=(
                        f"Found {len(admin_users)} administrator account(s):\n"
                        + "\n".join(f"  {detail}" for detail in status_details) +
                        "\n\nReview to ensure only necessary users have elevated access."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "admin_accounts", "users": admin_users, "status": admin_status},
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
            elif check == "builtin_admin_enabled":
                actions.append(
                    Action(
                        title="Disable built-in Administrator account",
                        description=(
                            "To disable the built-in Administrator account, run:\n"
                            "net user Administrator /active:no"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )
            elif check == "excessive_admins":
                users = finding.data.get("users", [])
                user_list = ", ".join(users)
                actions.append(
                    Action(
                        title="Review and remove unnecessary admin accounts",
                        description=(
                            f"The following accounts have admin privileges: {user_list}. "
                            "To remove admin access from a user:\n"
                            "1. Press Win + R\n"
                            "2. Type 'compmgmt.msc' and press Enter\n"
                            "3. Navigate to Local Users and Groups > Groups\n"
                            "4. Double-click 'Administrators'\n"
                            "5. Select the user to remove and click Remove\n\n"
                            "Or use: net localgroup Administrators username /delete"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )
            elif check == "blank_password":
                users = finding.data.get("users", [])
                user_list = ", ".join(users)
                actions.append(
                    Action(
                        title="Set strong password for admin accounts without password",
                        description=(
                            f"The following admin account(s) have no password: {user_list}. "
                            "You must set strong passwords immediately.\n\n"
                            "To set a password for a user:\n"
                            "1. Press Win + R\n"
                            "2. Type 'compmgmt.msc' and press Enter\n"
                            "3. Navigate to Local Users and Groups > Users\n"
                            "4. Right-click the user and select 'Set Password'\n"
                            "5. Enter a strong password (at least 12 characters with mixed case and symbols)\n\n"
                            "Or use: net user username newpassword"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )
            elif check == "password_never_expires":
                users = finding.data.get("users", [])
                user_list = ", ".join(users)
                actions.append(
                    Action(
                        title="Enable password expiration for admin accounts",
                        description=(
                            f"The following admin account(s) have 'Password Never Expires' set: {user_list}. "
                            "To disable this setting:\n\n"
                            "Option 1 - Using Local Users and Groups:\n"
                            "1. Press Win + R\n"
                            "2. Type 'compmgmt.msc' and press Enter\n"
                            "3. Navigate to Local Users and Groups > Users\n"
                            "4. Double-click the user account\n"
                            "5. Uncheck 'Password never expires' and click OK\n\n"
                            "Option 2 - Using PowerShell:\n"
                            "Set-LocalUser -Name username -PasswordNeverExpires $false"
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
                        title="Review administrator accounts",
                        description=(
                            f"Current administrator account(s): {user_list}. "
                            "Regularly audit these accounts to ensure:\n"
                            "- Only necessary users have admin privileges\n"
                            "- All accounts have strong, unique passwords\n"
                            "- Password expiration policies are enforced\n"
                            "- Accounts are actively used (disable or remove unused accounts)\n"
                            "- Built-in Administrator account is disabled\n"
                            "- Guest account is disabled"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

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
                if "Members" in line:
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
        """Check if the Guest account is enabled via PowerShell."""
        try:
            result = subprocess.run(
                [
                    "powershell",
                    "-Command",
                    "Get-LocalUser -Name Guest | Select-Object -ExpandProperty Enabled",
                ],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                return False
            output = result.stdout.strip().lower()
            return output == "true"
        except Exception as e:
            return False

    def _is_builtin_admin_enabled(self) -> bool:
        """Check if built-in Administrator account is enabled via PowerShell."""
        try:
            result = subprocess.run(
                [
                    "powershell",
                    "-Command",
                    "Get-LocalUser -Name Administrator | Select-Object -ExpandProperty Enabled",
                ],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                return False
            output = result.stdout.strip().lower()
            return output == "true"
        except Exception as e:
            return False

    def _get_user_info(self, username: str) -> dict:
        """Get user account information including password and expiration settings."""
        info = {
            "enabled": True,
            "password_required": True,
            "password_never_expires": False,
        }

        try:
            # Use net user command to get account info
            result = subprocess.run(
                ["net", "user", username],
                capture_output=True,
                text=True,
            )

            if result.returncode != 0:
                return info

            lines = result.stdout.split("\n")
            for line in lines:
                line_lower = line.lower().strip()

                # Check if account is active (Yes/No value on Account active line)
                if "account active" in line_lower:
                    info["enabled"] = line_lower.endswith("yes")

                # Check password required field
                if "password required" in line_lower:
                    info["password_required"] = line_lower.endswith("yes")

                # Check for password never expires
                if "password never expires" in line_lower:
                    info["password_never_expires"] = line_lower.endswith("yes")

            return info
        except Exception as e:
            return info
