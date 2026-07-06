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
    name = "lock_screen_check"
    category = "security"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 70
    depends_on = []
    estimated_duration = "3s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Check screensaver password requirement
        try:
            result = subprocess.run(
                ["defaults", "read", "com.apple.screensaver", "askForPassword"],
                capture_output=True,
                text=True,
            )
            ask_for_password = result.stdout.strip()
        except OSError:
            ask_for_password = None

        if ask_for_password != "1":
            findings.append(
                Finding(
                    title="Screen saver password not required",
                    description=(
                        "The screen saver is not configured to require a password. "
                        "Anyone can wake the screen and access the Mac. Enable this "
                        "in System Settings > Lock Screen > 'Require password after "
                        "screen saver or lock screen begins'."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "screensaver_password"},
                )
            )

        # Check screensaver password delay
        try:
            result = subprocess.run(
                ["defaults", "read", "com.apple.screensaver", "askForPasswordDelay"],
                capture_output=True,
                text=True,
            )
            ask_for_password_delay = int(result.stdout.strip()) if result.stdout.strip() else None
        except (OSError, ValueError):
            ask_for_password_delay = None

        if ask_for_password_delay is not None and ask_for_password_delay > 60:
            findings.append(
                Finding(
                    title="Screen saver password delay is too long",
                    description=(
                        f"The delay before asking for a password is {ask_for_password_delay} "
                        "seconds. This allows unauthorized access if the screen saver activates "
                        "during a brief absence. Set this to 0 or a very short delay (< 30 seconds)."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "screensaver_delay"},
                )
            )

        # Check display sleep timeout
        try:
            result = subprocess.run(
                ["pmset", "-g"],
                capture_output=True,
                text=True,
            )
            for line in result.stdout.split("\n"):
                if "displaysleep" in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        try:
                            display_sleep = int(parts[-1])
                            if display_sleep == 0:
                                findings.append(
                                    Finding(
                                        title="Display never sleeps",
                                        description=(
                                            "The display is configured to never sleep. "
                                            "This leaves the system vulnerable if left unattended. "
                                            "Set displaysleep to a reasonable value (e.g., 5-15 minutes) "
                                            "via System Settings > Displays > Auto-lock."
                                        ),
                                        severity=Severity.WARNING,
                                        category=self.category,
                                        data={"check": "display_sleep"},
                                    )
                                )
                            break
                        except ValueError:
                            pass
        except OSError:
            pass

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            check = finding.data.get("check")
            if check == "screensaver_password":
                label = "Enable screen saver password requirement"
                description = (
                    "To enable: System Settings > Lock Screen > "
                    "toggle 'Require password after screen saver or lock screen begins'"
                )
            elif check == "screensaver_delay":
                label = "Reduce screen saver password delay"
                description = (
                    "To reduce delay: System Settings > Lock Screen > "
                    "set 'Require password after' to immediately (or < 30 seconds)"
                )
            elif check == "display_sleep":
                label = "Enable display auto-sleep"
                description = (
                    "To enable: System Settings > Displays > "
                    "set 'Auto-lock' to a reasonable timeout (e.g., 5-15 minutes)"
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
