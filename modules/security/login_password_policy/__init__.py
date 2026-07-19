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
    name = "login_password_policy"
    category = "security"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "5s"

    emits_codes = [
        "security.login_password_policy.auto_login",
        "security.login_password_policy.ask_password",
        "security.login_password_policy.password_delay",
        "security.login_password_policy.guest_account_enabled",
        "security.login_password_policy.login_window_display",
        "security.login_password_policy.screensaver_timeout",
        "security.login_password_policy.remote_login_enabled",
    ]

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Check 1: Auto-login
        auto_login_user = self._get_defaults_read(
            "/Library/Preferences/com.apple.loginwindow", "autoLoginUser"
        )
        if auto_login_user and auto_login_user.strip():
            findings.append(
                Finding(
                    title="Auto-login is enabled",
                    description=(
                        f"Auto-login is enabled for user '{auto_login_user}'. "
                        "This means anyone who opens the lid can immediately access the Mac. "
                        "Disable auto-login in System Settings > General > Login Items & Extensions > "
                        "Login Options and uncheck 'Automatically log in as'."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
                    code="security.login_password_policy.auto_login",
                    data={"check": "auto_login", "user": auto_login_user},
                )
            )

        # Check 2: Password required after sleep/screensaver
        ask_password = self._get_defaults_read(
            "com.apple.screensaver", "askForPassword"
        )
        if ask_password == "0":
            findings.append(
                Finding(
                    title="Password not required after screensaver",
                    description=(
                        "Password is not required after the screensaver activates. "
                        "Enable this in System Settings > Lock Screen > "
                        "Turn on 'Require password after screensaver or screen saver begins'."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.login_password_policy.ask_password",
                    data={"check": "ask_password", "value": ask_password},
                )
            )

        # Check 3: Password delay after lock
        password_delay = self._get_defaults_read(
            "com.apple.screensaver", "askForPasswordDelay"
        )
        if password_delay:
            try:
                delay_value = int(password_delay.strip())
                if delay_value > 5:
                    findings.append(
                        Finding(
                            title=f"Password delay is {delay_value} seconds",
                            description=(
                                f"Password requirement is delayed by {delay_value} seconds after lock. "
                                "A {delay_value} second delay provides a window for unattended access. "
                                "Reduce this to 0-5 seconds in System Preferences > Security & Privacy > "
                                "General > 'Require password ... after sleep or screensaver begins'."
                            ),
                            severity=Severity.WARNING,
                            category=self.category,
                            code="security.login_password_policy.password_delay",
                            data={"check": "password_delay", "seconds": delay_value},
                        )
                    )
            except (ValueError, TypeError):
                pass

        # Check 4: Guest account enabled
        guest_auth = self._get_dscl_value("/Users/Guest", "AuthenticationAuthority")
        if guest_auth and not "No such key" in guest_auth:
            findings.append(
                Finding(
                    title="Guest account is enabled",
                    description=(
                        "The Guest account is enabled, providing a potential access point. "
                        "Disable the Guest account in System Settings > General > Login Items & Extensions > "
                        "Login Options and uncheck 'Allow guests to log in'."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.login_password_policy.guest_account_enabled",
                    data={"check": "guest_account_enabled"},
                )
            )

        # Check 5: Login window shows user list vs name+password
        show_full_name = self._get_defaults_read(
            "/Library/Preferences/com.apple.loginwindow", "SHOWFULLNAME"
        )
        login_message = "Name and password" if show_full_name == "0" else "User list"
        findings.append(
            Finding(
                title=f"Login window display: {login_message}",
                description=(
                    f"Login window is configured to show {login_message.lower()}. "
                    "For better security, disable 'Show the Sleep, Restart, and Shut Down buttons' "
                    "and 'Show password hints' in System Settings > General > Login Items & Extensions > "
                    "Login Options."
                ),
                severity=Severity.INFO,
                category=self.category,
                code="security.login_password_policy.login_window_display",
                data={"check": "login_window_display", "display": login_message},
            )
        )

        # Check 6: Screensaver timeout
        screensaver_timeout = self._get_defaults_read_current_host(
            "com.apple.screensaver", "idleTime"
        )
        if screensaver_timeout:
            try:
                timeout_value = int(screensaver_timeout.strip())
                timeout_minutes = timeout_value // 60 if timeout_value > 0 else 0
                if timeout_value == 0:
                    findings.append(
                        Finding(
                            title="Screensaver is disabled",
                            description=(
                                "The screensaver is disabled, leaving the display on indefinitely. "
                                "Enable screensaver and set it to activate within 10 minutes in "
                                "System Settings > Lock Screen."
                            ),
                            severity=Severity.WARNING,
                            category=self.category,
                            code="security.login_password_policy.screensaver_timeout",
                            data={"check": "screensaver_timeout", "seconds": timeout_value},
                        )
                    )
                elif timeout_minutes > 10:
                    findings.append(
                        Finding(
                            title=f"Screensaver timeout is {timeout_minutes} minutes",
                            description=(
                                f"Screensaver activates after {timeout_minutes} minutes of inactivity, "
                                "creating a long window of unattended access. "
                                "Set it to activate within 10 minutes in System Settings > Lock Screen."
                            ),
                            severity=Severity.WARNING,
                            category=self.category,
                            code="security.login_password_policy.screensaver_timeout",
                            data={"check": "screensaver_timeout", "seconds": timeout_value, "minutes": timeout_minutes},
                        )
                    )
            except (ValueError, TypeError):
                pass

        # Check 7: Remote login (SSH) enabled
        remote_login = self._get_systemsetup_value("getremotelogin")
        if remote_login == "On":
            findings.append(
                Finding(
                    title="Remote login (SSH) is enabled",
                    description=(
                        "SSH remote login is enabled, allowing remote command execution. "
                        "Disable this in System Settings > General > Sharing > Remote Login if not needed."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.login_password_policy.remote_login_enabled",
                    data={"check": "remote_login_enabled"},
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            check = finding.data.get("check")

            if check == "auto_login":
                user = finding.data.get("user", "unknown")
                actions.append(
                    Action(
                        title="Disable auto-login",
                        description=(
                            f"Auto-login is enabled for user '{user}'. "
                            "To disable it:\n"
                            "1. Open System Settings > General > Login Items & Extensions\n"
                            "2. Go to Login Options (may require unlocking)\n"
                            "3. Uncheck 'Automatically log in as'\n"
                            "4. Restart the Mac to apply changes"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )
            elif check == "ask_password":
                actions.append(
                    Action(
                        title="Enable password requirement after screensaver",
                        description=(
                            "To require password after screensaver:\n"
                            "1. Open System Settings > Lock Screen\n"
                            "2. Enable 'Require password after screensaver or screen saver begins'\n"
                            "3. Set to require password immediately (0 seconds delay)"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )
            elif check == "password_delay":
                delay = finding.data.get("seconds", 0)
                actions.append(
                    Action(
                        title=f"Reduce password delay from {delay} seconds",
                        description=(
                            f"Currently password is delayed {delay} seconds after lock. "
                            "To reduce this:\n"
                            "1. Open System Settings > Lock Screen\n"
                            "2. Adjust the password delay to 0-5 seconds"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )
            elif check == "guest_account_enabled":
                actions.append(
                    Action(
                        title="Disable guest account",
                        description=(
                            "To disable the guest account:\n"
                            "1. Open System Settings > General > Login Items & Extensions\n"
                            "2. Go to Login Options (may require unlocking)\n"
                            "3. Uncheck 'Allow guests to log in'"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )
            elif check == "screensaver_timeout":
                timeout_value = finding.data.get("seconds", 0)
                timeout_minutes = finding.data.get("minutes", 0)
                if timeout_value == 0:
                    desc = "Screensaver is currently disabled"
                else:
                    desc = f"Screensaver currently activates after {timeout_minutes} minutes"

                actions.append(
                    Action(
                        title="Set screensaver timeout to 10 minutes or less",
                        description=(
                            f"{desc}. "
                            "To change this:\n"
                            "1. Open System Settings > Lock Screen\n"
                            "2. Set 'Start after' to 10 minutes or less"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )
            elif check == "remote_login_enabled":
                actions.append(
                    Action(
                        title="Review and consider disabling SSH",
                        description=(
                            "SSH remote login is enabled. "
                            "To disable it:\n"
                            "1. Open System Settings > General > Sharing\n"
                            "2. Uncheck 'Remote Login'"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _get_defaults_read(self, domain: str, key: str) -> str | None:
        """Read a value from defaults. Returns None on failure."""
        try:
            result = subprocess.run(
                ["defaults", "read", domain, key],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                return result.stdout.strip()
            return None
        except Exception:
            return None

    def _get_defaults_read_current_host(self, domain: str, key: str) -> str | None:
        """Read a value from defaults -currentHost. Returns None on failure."""
        try:
            result = subprocess.run(
                ["defaults", "-currentHost", "read", domain, key],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                return result.stdout.strip()
            return None
        except Exception:
            return None

    def _get_dscl_value(self, record: str, key: str) -> str | None:
        """Query dscl for a user record value. Returns None on failure."""
        try:
            result = subprocess.run(
                ["dscl", ".", "-read", record, key],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                return result.stdout.strip()
            return None
        except Exception:
            return None

    def _get_systemsetup_value(self, setting: str) -> str | None:
        """Get a system setting from systemsetup. Returns None on failure."""
        try:
            result = subprocess.run(
                ["systemsetup", f"-{setting}"],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                output = result.stdout.strip()
                # systemsetup output is usually "key: value"
                if ": " in output:
                    return output.split(": ", 1)[1]
                return output
            return None
        except Exception:
            return None
