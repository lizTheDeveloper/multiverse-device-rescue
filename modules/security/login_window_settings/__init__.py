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
                    title="Auto-login is enabled",
                    description=(
                        f"The Mac is configured to automatically log in as '{auto_login_user}'. "
                        "This is a critical security risk on shared or family Macs, as anyone with "
                        "physical access can access the account without a password. Disable auto-login "
                        "in System Settings > General > Login Items > Allow guests to log in > OFF, "
                        "or disable auto-login via System Preferences."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
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
                    title="Login window displays user list",
                    description=(
                        "The login window is configured to show a list of users. This reveals "
                        "which user accounts exist on the system to anyone with physical access. "
                        "For better security, configure the login window to show name and password "
                        "fields instead. Go to System Settings > General > Login Options > "
                        "Display login window as > 'Name and password' or 'Account name and password'."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
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
                            title="Password hints are enabled at login",
                            description=(
                                f"The login window is configured to show password hints after "
                                f"{retries} failed login attempts. This can assist attackers in "
                                "guessing passwords. Disable password hints by setting RetriesUntilHint "
                                "to 0 or -1."
                            ),
                            severity=Severity.WARNING,
                            category=self.category,
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
