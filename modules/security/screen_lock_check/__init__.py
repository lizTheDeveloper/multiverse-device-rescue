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
    name = "screen_lock_check"
    category = "security"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "3s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Check if screen lock is required after sleep
        ask_for_password = self._get_defaults(
            "com.apple.screensaver", "askForPassword"
        )

        if ask_for_password == "0":
            findings.append(
                Finding(
                    title="Screen lock not required after sleep",
                    description=(
                        "Screen lock is not required after sleep or screensaver. "
                        "This is a critical security risk - an unattended Mac can be "
                        "accessed without authentication. Enable screen lock in "
                        "System Settings > Lock Screen > Require password."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
                    data={"check": "screen_lock_required", "value": "disabled"},
                )
            )
        elif ask_for_password == "1":
            # Positive finding: screen lock is enabled
            findings.append(
                Finding(
                    title="Screen lock enabled after sleep",
                    description=(
                        "Screen lock is required after sleep or screensaver. "
                        "This is a good security practice."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "screen_lock_required", "value": "enabled"},
                )
            )

        # Check automatic login (CRITICAL if enabled)
        auto_login = self._get_defaults_path(
            "/Library/Preferences/com.apple.loginwindow", "autoLoginUser"
        )
        if auto_login and auto_login.strip():
            findings.append(
                Finding(
                    title="Automatic login enabled",
                    description=(
                        f"Automatic login is enabled for user '{auto_login.strip()}'. "
                        "This is a critical security vulnerability - anyone with physical "
                        "access to your Mac can log in without a password. Disable automatic "
                        "login in System Settings > General > Login Items > Allow guests to connect."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
                    data={"check": "automatic_login", "value": auto_login.strip()},
                )
            )

        # Check screen lock delay (WARNING if > 5 seconds)
        ask_for_password_delay = self._get_defaults(
            "com.apple.screensaver", "askForPasswordDelay"
        )
        if ask_for_password_delay:
            try:
                delay_seconds = int(ask_for_password_delay)
                if delay_seconds > 5:
                    findings.append(
                        Finding(
                            title=f"Screen lock delay is {delay_seconds} seconds",
                            description=(
                                f"The delay before screen lock requires a password is {delay_seconds} seconds. "
                                "A delay longer than 5 seconds increases the risk that someone could "
                                "access your Mac before it locks. Consider reducing this delay in "
                                "System Settings > Lock Screen."
                            ),
                            severity=Severity.WARNING,
                            category=self.category,
                            data={"check": "screen_lock_delay", "value": delay_seconds},
                        )
                    )
                elif delay_seconds >= 0:
                    findings.append(
                        Finding(
                            title=f"Screen lock delay is {delay_seconds} seconds",
                            description=(
                                f"The delay before screen lock requires a password is {delay_seconds} seconds. "
                                "This is good security practice."
                            ),
                            severity=Severity.INFO,
                            category=self.category,
                            data={"check": "screen_lock_delay", "value": delay_seconds},
                        )
                    )
            except (ValueError, TypeError):
                # Could not parse delay value
                pass

        # Check screensaver idle time (WARNING if > 10 minutes or disabled)
        idle_time = self._get_defaults_currenthost(
            "com.apple.screensaver", "idleTime"
        )
        if idle_time:
            try:
                idle_seconds = int(idle_time)
                idle_minutes = idle_seconds // 60
                if idle_seconds == 0:
                    findings.append(
                        Finding(
                            title="Screensaver is disabled",
                            description=(
                                "The screensaver is disabled (idle time is 0). "
                                "While this is not a critical issue if screen lock is enabled, "
                                "it's good practice to enable the screensaver as a visual indicator "
                                "and to lock the screen after inactivity."
                            ),
                            severity=Severity.WARNING,
                            category=self.category,
                            data={"check": "screensaver_idle_time", "value": 0},
                        )
                    )
                elif idle_minutes > 10:
                    findings.append(
                        Finding(
                            title=f"Screensaver idle time is {idle_minutes} minutes",
                            description=(
                                f"The screensaver will not activate for {idle_minutes} minutes. "
                                "Consider setting it to 10 minutes or less for better security. "
                                "A longer idle time means your unattended Mac is vulnerable for longer."
                            ),
                            severity=Severity.WARNING,
                            category=self.category,
                            data={"check": "screensaver_idle_time", "value": idle_minutes},
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            title=f"Screensaver idle time is {idle_minutes} minutes",
                            description=(
                                f"The screensaver will activate after {idle_minutes} minutes of inactivity. "
                                "This is good security practice."
                            ),
                            severity=Severity.INFO,
                            category=self.category,
                            data={"check": "screensaver_idle_time", "value": idle_minutes},
                        )
                    )
            except (ValueError, TypeError):
                # Could not parse idle time value
                pass
        else:
            # Screensaver idle time not set - treat as disabled
            findings.append(
                Finding(
                    title="Screensaver idle time not configured",
                    description=(
                        "The screensaver idle time is not configured. "
                        "Consider enabling the screensaver to lock the screen after inactivity."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "screensaver_idle_time", "value": "not_set"},
                )
            )

        # Check if password hint is shown (INFO - informational about info leakage)
        hint_retries = self._get_defaults_path(
            "/Library/Preferences/com.apple.loginwindow", "RetriesUntilHint"
        )
        if hint_retries:
            try:
                hint_retries_int = int(hint_retries.strip())
                if hint_retries_int > 0:
                    findings.append(
                        Finding(
                            title=f"Password hint shown after {hint_retries_int} failed attempts",
                            description=(
                                f"A password hint is shown after {hint_retries_int} failed login attempts. "
                                "While this can be helpful for the legitimate user, it may leak information "
                                "about the password to attackers. Consider disabling this in "
                                "System Settings > General > Login Options."
                            ),
                            severity=Severity.INFO,
                            category=self.category,
                            data={"check": "password_hint", "value": hint_retries_int},
                        )
                    )
            except (ValueError, TypeError):
                # Could not parse hint retries value
                pass

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            check = finding.data.get("check")

            if check == "screen_lock_required":
                value = finding.data.get("value")
                if value == "disabled":
                    actions.append(
                        Action(
                            title="Enable screen lock after sleep",
                            description=(
                                "To enable screen lock, open System Settings > Lock Screen. "
                                "Turn ON 'Require password immediately after sleep or screen saver begins'. "
                                "This ensures your Mac locks and requires authentication when unattended."
                            ),
                            risk_level=RiskLevel.SAFE,
                            success=True,
                            error=None,
                        )
                    )
            elif check == "automatic_login":
                actions.append(
                    Action(
                        title="Disable automatic login",
                        description=(
                            "To disable automatic login, open System Settings > General > Login Items. "
                            "Uncheck 'Allow guests to connect to shared folders' or remove automatic login. "
                            "This requires a password to access your Mac."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )
            elif check == "screen_lock_delay":
                delay = finding.data.get("value")
                if delay and delay > 5:
                    actions.append(
                        Action(
                            title=f"Reduce screen lock delay from {delay} seconds",
                            description=(
                                f"To reduce the screen lock delay, open System Settings > Lock Screen. "
                                f"Current delay is {delay} seconds. Consider reducing it to 0-5 seconds "
                                "for better security. This minimizes the window where someone could access "
                                "your Mac before it locks."
                            ),
                            risk_level=RiskLevel.SAFE,
                            success=True,
                            error=None,
                        )
                    )
            elif check == "screensaver_idle_time":
                idle = finding.data.get("value")
                if idle == 0 or idle == "not_set" or (idle and idle > 10):
                    actions.append(
                        Action(
                            title="Configure screensaver idle time",
                            description=(
                                "To set screensaver idle time, open System Settings > Lock Screen. "
                                "Set 'Turn display off after' to 5-10 minutes for good security. "
                                "This ensures your unattended Mac locks automatically after inactivity."
                            ),
                            risk_level=RiskLevel.SAFE,
                            success=True,
                            error=None,
                        )
                    )
            elif check == "password_hint":
                actions.append(
                    Action(
                        title="Review password hint visibility",
                        description=(
                            "To disable password hints, open System Settings > General > Login Options. "
                            "Uncheck 'Show password hints' to prevent information leakage about your password. "
                            "This is optional but recommended for additional security."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _get_defaults(self, domain: str, key: str) -> str:
        """Get a defaults value. Returns empty string if not found or on error."""
        try:
            result = subprocess.run(
                ["defaults", "read", domain, key],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                return result.stdout.strip()
            return ""
        except Exception:
            return ""

    def _get_defaults_path(self, plist_path: str, key: str) -> str:
        """Get a defaults value from a specific plist path. Returns empty string if not found or on error."""
        try:
            result = subprocess.run(
                ["defaults", "read", plist_path, key],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                return result.stdout.strip()
            return ""
        except Exception:
            return ""

    def _get_defaults_currenthost(self, domain: str, key: str) -> str:
        """Get a defaults value for current host. Returns empty string if not found or on error."""
        try:
            result = subprocess.run(
                ["defaults", "-currentHost", "read", domain, key],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                return result.stdout.strip()
            return ""
        except Exception:
            return ""
