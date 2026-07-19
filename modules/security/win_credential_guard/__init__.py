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
    name = "win_credential_guard"
    category = "security"
    platforms = [Platform.WIN32]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "10s"

    emits_codes = [
        "security.win_credential_guard.credential_guard_disabled",
        "security.win_credential_guard.windows_hello_configured",
        "security.win_credential_guard.password_min_length_below_threshold",
        "security.win_credential_guard.passwords_never_expire",
    ]

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Check if Credential Guard is enabled
        try:
            credential_guard_enabled = self._is_credential_guard_enabled()
            if not credential_guard_enabled:
                findings.append(
                    Finding(
                        title="Credential Guard is not enabled",
                        description=(
                            "Credential Guard provides hardware-based isolation for sensitive "
                            "credentials, protecting against pass-the-hash attacks. Consider enabling it "
                            "on supported systems (Windows 10/11 Pro, Enterprise, Education)."
                        ),
                        severity=Severity.INFO,
                        category=self.category,
                        code="security.win_credential_guard.credential_guard_disabled",
                        data={"check": "credential_guard"},
                    )
                )
        except Exception as e:
            pass

        # Check if Windows Hello is configured
        try:
            hello_configured = self._is_windows_hello_configured()
            if hello_configured:
                findings.append(
                    Finding(
                        title="Windows Hello is configured",
                        description=(
                            "Windows Hello provides biometric and PIN-based authentication, "
                            "offering strong credential protection."
                        ),
                        severity=Severity.INFO,
                        category=self.category,
                        code="security.win_credential_guard.windows_hello_configured",
                        data={"check": "windows_hello"},
                    )
                )
        except Exception as e:
            pass

        # Check password policy minimum length
        try:
            password_policy = self._get_password_policy()
            if password_policy and password_policy.get("min_length", 0) < 8:
                findings.append(
                    Finding(
                        title="Minimum password length policy is below recommended threshold",
                        description=(
                            f"Current minimum password length is {password_policy.get('min_length', 0)} characters. "
                            "A minimum of 8 characters is recommended for adequate security."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        code="security.win_credential_guard.password_min_length_below_threshold",
                        data={"check": "password_min_length", "current_length": password_policy.get("min_length", 0)},
                    )
                )
        except Exception as e:
            pass

        # Check if any password is set to never expire
        try:
            password_never_expires = self._get_passwords_never_expire()
            if password_never_expires:
                user_list = ", ".join(password_never_expires)
                findings.append(
                    Finding(
                        title="User accounts with passwords set to never expire",
                        description=(
                            f"The following accounts have passwords set to never expire: {user_list}. "
                            "Passwords that never expire pose a security risk. Configure password expiration policies."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        code="security.win_credential_guard.passwords_never_expire",
                        data={"check": "password_never_expires", "users": password_never_expires},
                    )
                )
        except Exception as e:
            pass

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            check = finding.data.get("check")
            if check == "credential_guard":
                actions.append(
                    Action(
                        title="Enable Credential Guard",
                        description=(
                            "To enable Credential Guard on Windows 10/11:\n"
                            "1. Press Win + R\n"
                            "2. Type 'gpedit.msc' and press Enter\n"
                            "3. Navigate to: Computer Configuration > Administrative Templates > "
                            "System > Device Guard\n"
                            "4. Set 'Turn On Virtualization Based Security' to Enabled\n"
                            "5. Restart the system for changes to take effect\n\n"
                            "Note: Your system must support virtualization extensions (Intel VT-x or AMD-V) "
                            "and have UEFI firmware with Secure Boot enabled."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )
            elif check == "windows_hello":
                actions.append(
                    Action(
                        title="Windows Hello is configured",
                        description=(
                            "Windows Hello is already set up on this system. "
                            "This provides strong biometric and PIN-based authentication."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )
            elif check == "password_min_length":
                current_length = finding.data.get("current_length", 0)
                actions.append(
                    Action(
                        title=f"Increase minimum password length (currently {current_length})",
                        description=(
                            "To enforce a minimum password length of 8+ characters:\n"
                            "1. Press Win + R\n"
                            "2. Type 'gpedit.msc' and press Enter\n"
                            "3. Navigate to: Computer Configuration > Windows Settings > Security Settings > "
                            "Account Policies > Password Policy\n"
                            "4. Set 'Minimum password length' to at least 8 characters\n"
                            "5. Click Apply and OK"
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
                        title=f"Configure password expiration for accounts: {user_list}",
                        description=(
                            "To enable password expiration for user accounts:\n"
                            "1. Press Win + R\n"
                            "2. Type 'gpedit.msc' and press Enter\n"
                            "3. Navigate to: Computer Configuration > Windows Settings > Security Settings > "
                            "Account Policies > Password Policy\n"
                            "4. Set 'Maximum password age' to a value between 30 and 90 days\n"
                            "5. Click Apply and OK\n\n"
                            "Alternatively, for specific accounts, use:\n"
                            "net user USERNAME /expires:YYYY-MM-DD"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _is_credential_guard_enabled(self) -> bool:
        """Check if Credential Guard is enabled via DeviceGuard registry."""
        try:
            result = subprocess.run(
                [
                    "reg",
                    "query",
                    r"HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard",
                    "/v",
                    "EnableVirtualizationBasedSecurity",
                ],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                return False
            # Check for 0x1 (enabled) in the output
            return "0x1" in result.stdout
        except Exception as e:
            return False

    def _is_windows_hello_configured(self) -> bool:
        """Check if Windows Hello is configured via PolicyManager registry."""
        try:
            result = subprocess.run(
                [
                    "reg",
                    "query",
                    r"HKLM\SOFTWARE\Microsoft\PolicyManager\default\Settings\AllowSignInOptions",
                    "/v",
                    "value",
                ],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                return False
            # Windows Hello is configured if the registry key exists with a value
            return "value" in result.stdout.lower()
        except Exception as e:
            return False

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
            return policy if policy else None
        except Exception as e:
            return None

    def _get_passwords_never_expire(self) -> list[str]:
        """Check if any passwords are set to never expire using PowerShell."""
        try:
            result = subprocess.run(
                [
                    "powershell",
                    "-Command",
                    "Get-LocalUser | Where-Object {$_.PasswordNeverExpires -eq $true} | Select-Object -ExpandProperty Name",
                ],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0 or not result.stdout.strip():
                return []
            # Parse the output - each line is a username
            users = [u.strip() for u in result.stdout.strip().split("\n") if u.strip()]
            return users
        except Exception as e:
            return []
