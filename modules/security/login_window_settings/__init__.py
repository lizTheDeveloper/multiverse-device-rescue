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
    name = "login_window_settings"
    category = "security"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 65
    depends_on = []
    estimated_duration = "5s"

    emits_codes = [
        "security.login_window_settings.auto_login",
        "security.login_window_settings.show_user_list",
        "security.login_window_settings.password_hints",
        "security.login_window_settings.login_settings_info",
    ]

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Check if auto-login is enabled
        try:
            result = subprocess.run(
                ["defaults", "read", "/Library/Preferences/com.apple.loginwindow", "autoLoginUser"],
                capture_output=True,
                text=True,
            )
            auto_login_user = result.stdout.strip() if result.stdout.strip() else None
        except OSError:
            auto_login_user = None

        if auto_login_user:
            findings.append(
                Finding(
                    title=f"Your Mac logs in automatically as {auto_login_user}",
                    description=(
                        f"Your Mac is set to automatically sign you in as '{auto_login_user}' "
                        "when it wakes up or restarts. This means anyone who physically "
                        "touches the computer can open your account without a password. "
                        "This is a significant risk if you share your Mac with family "
                        "or friends, or if you are worried someone close to you might "
                        "use this to get into your files or messages.\n\n"
                        "What to do: Open System Settings > Users & Groups and set "
                        "'Automatically log in as' to Off."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
                    code="security.login_window_settings.auto_login",
                    data={"check": "auto_login"},
                )
            )

        # Check if login window shows full name or list of users
        try:
            result = subprocess.run(
                ["defaults", "read", "/Library/Preferences/com.apple.loginwindow", "SHOWFULLNAME"],
                capture_output=True,
                text=True,
            )
            show_full_name = result.stdout.strip()
        except OSError:
            show_full_name = None

        # SHOWFULLNAME == 1 means show name+password, 0 means show user list
        if show_full_name == "0":
            findings.append(
                Finding(
                    title="Your login screen shows a list of user names",
                    description=(
                        "When you turn on your Mac, the login screen currently displays "
                        "a list of all user names on the computer. This tells anyone who "
                        "can see the screen exactly who has an account on the device. "
                        "For better privacy, you can change the screen to ask for a name "
                        "and password instead of showing a list.\n\n"
                        "What to do: Open System Settings > Lock Screen and set 'Login "
                        "window shows' to Name and password."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.login_window_settings.show_user_list",
                    data={"check": "show_user_list"},
                )
            )

        # Check if password hints are enabled
        try:
            result = subprocess.run(
                ["defaults", "read", "/Library/Preferences/com.apple.loginwindow", "RetriesUntilHint"],
                capture_output=True,
                text=True,
            )
            retries_until_hint = result.stdout.strip() if result.stdout.strip() else None
        except OSError:
            retries_until_hint = None

        if retries_until_hint and retries_until_hint != "0":
            try:
                retries = int(retries_until_hint)
                if retries > 0:
                    findings.append(
                        Finding(
                            title=(
                                f"Your Mac shows password hints after {retries} failed logins"
                            ),
                            description=(
                                f"Your Mac is set to display a password hint after {retries} "
                                "incorrect login attempts. Hints are often easy to guess, "
                                "which can make it simpler for someone to break into "
                                "your account. This is a common setting, but turning "
                                "it off adds a layer of protection.\n\n"
                                "What to do: Open System Settings > Lock Screen and turn off "
                                "'Show password hints'."
                            ),
                            severity=Severity.WARNING,
                            category=self.category,
                            code="security.login_window_settings.password_hints",
                            data={"check": "password_hints"},
                        )
                    )
            except ValueError:
                pass

        # Report all login window settings as INFO
        settings_info = []

        if auto_login_user:
            settings_info.append(f"Auto-login: enabled (user: {auto_login_user})")
        else:
            settings_info.append("Auto-login: disabled")

        if show_full_name == "1":
            settings_info.append("Login window: name and password")
        elif show_full_name == "0":
            settings_info.append("Login window: user list")
        else:
            settings_info.append("Login window: default configuration")

        if retries_until_hint:
            settings_info.append(f"Password hints enabled after: {retries_until_hint} attempts")
        else:
            settings_info.append("Password hints: disabled or default")

        if settings_info:
            findings.append(
                Finding(
                    title="Login window configuration",
                    description="\n".join(settings_info),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.login_window_settings.login_settings_info",
                    data={"check": "login_settings_info"},
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            check = finding.data.get("check")
            if check == "auto_login":
                label = "Disable auto-login"
                description = (
                    "To disable: System Settings > General > Login Items > "
                    "uncheck 'Allow guests to log in', or use: "
                    "defaults delete /Library/Preferences/com.apple.loginwindow autoLoginUser"
                )
            elif check == "show_user_list":
                label = "Hide user list at login"
                description = (
                    "To show name and password fields instead: System Settings > "
                    "General > Login Options > Display login window as > "
                    "'Name and password' or 'Account name and password'"
                )
            elif check == "password_hints":
                label = "Disable password hints"
                description = (
                    "To disable: defaults write /Library/Preferences/com.apple.loginwindow "
                    "RetriesUntilHint 0"
                )
            elif check == "login_settings_info":
                # Info finding - still provide helpful context
                label = "Review login window settings"
                description = (
                    "The above login window settings are informational. Review them to ensure "
                    "your security requirements are met, especially on shared or family Macs."
                )
            else:
                continue

            actions.append(
                Action(
                    title=label,
                    description=description,
                    risk_level=RiskLevel.SAFE,
                    success=True,
                    error=None,
                )
            )
        return FixResult(module_name=self.name, actions=actions)
