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

    emits_codes = [
        "security.screen_lock_check.screen_lock_required",
        "security.screen_lock_check.automatic_login",
        "security.screen_lock_check.screen_lock_delay",
        "security.screen_lock_check.screensaver_idle_time",
        "security.screen_lock_check.password_hint",
    ]

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Check if screen lock is required after sleep
        ask_for_password = self._get_defaults(
            "com.apple.screensaver", "askForPassword"
        )

        if ask_for_password == "0":
            findings.append(
                Finding(
                    title="Your Mac does not lock after sleeping",
                    description=(
                        "Your Mac is set to stay unlocked after it goes to sleep or the "
                        "screensaver starts. This means anyone who picks up your Mac can "
                        "use it without entering a password. This is a significant risk "
                        "if you leave your Mac unattended.\n\n"
                        "What to do: Open System Settings > Lock Screen and set 'Require "
                        "password after screen saver begins or display is turned off' "
                        "to Immediately."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
                    code="security.screen_lock_check.screen_lock_required",
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
                    code="security.screen_lock_check.screen_lock_required",
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
                    title=f"Your Mac logs in automatically as {auto_login.strip()}",
                    description=(
                        f"Your Mac is set to automatically log in as '{auto_login.strip()}' "
                        "when it starts up. This means anyone with physical access to "
                        "your Mac can use your account without a password. This is a "
                        "major security risk.\n\n"
                        "What to do: Open System Settings > Users & Groups and set "
                        "'Automatically log in as' to Off."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
                    code="security.screen_lock_check.automatic_login",
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
                            title=f"Your Mac waits {delay_seconds} seconds before locking",
                            description=(
                                f"Your Mac waits {delay_seconds} seconds after the screensaver "
                                "starts before asking for a password. A longer wait time "
                                "gives someone more time to use your Mac while it is "
                                "unattended. A shorter delay is safer.\n\n"
                                "What to do: Open System Settings > Lock Screen and set 'Require "
                                "password after screen saver begins or display is turned "
                                "off' to Immediately."
                            ),
                            severity=Severity.WARNING,
                            category=self.category,
                            code="security.screen_lock_check.screen_lock_delay",
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
                            code="security.screen_lock_check.screen_lock_delay",
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
                            title="Your screensaver is turned off",
                            description=(
                                "Your Mac's screensaver is disabled. This is not a major "
                                "security risk if your screen lock is working, but having "
                                "a screensaver helps show that your Mac is unattended "
                                "and can help lock the screen sooner.\n\n"
                                "What to do: Open System Settings > Lock Screen and choose a time "
                                "for 'Start Screen Saver when inactive'."
                            ),
                            severity=Severity.WARNING,
                            category=self.category,
                            code="security.screen_lock_check.screensaver_idle_time",
                            data={"check": "screensaver_idle_time", "value": 0},
                        )
                    )
                elif idle_minutes > 10:
                    findings.append(
                        Finding(
                            title=f"Your screensaver waits {idle_minutes} minutes to start",
                            description=(
                                f"Your Mac waits {idle_minutes} minutes of inactivity "
                                "before starting the screensaver. A longer wait time "
                                "means your Mac stays unlocked for longer if you step "
                                "away. Setting it to 10 minutes or less is safer.\n\n"
                                "What to do: Open System Settings > Lock Screen and set 'Start "
                                "Screen Saver when inactive' to 10 minutes or less."
                            ),
                            severity=Severity.WARNING,
                            category=self.category,
                            code="security.screen_lock_check.screensaver_idle_time",
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
                            code="security.screen_lock_check.screensaver_idle_time",
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
                    code="security.screen_lock_check.screensaver_idle_time",
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
                            code="security.screen_lock_check.password_hint",
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
