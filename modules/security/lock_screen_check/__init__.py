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

    emits_codes = [
        "security.lock_screen_check.screensaver_password",
        "security.lock_screen_check.screensaver_delay",
        "security.lock_screen_check.display_sleep",
    ]

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
                    title=(
                        "Your Mac does not ask for a password after the screen saver starts"
                    ),
                    description=(
                        "Right now, if your screen saver is running, anyone can move the "
                        "mouse to wake it up and use your Mac without a password. This "
                        "is a common setting, but it means your files and messages are "
                        "open to anyone who walks by.\n\n"
                        "What to do: Open System Settings > Lock Screen and set 'Require "
                        "password after screen saver begins or display is turned off' to "
                        "Immediately."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.lock_screen_check.screensaver_password",
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
                    title=(
                        f"Your Mac waits {ask_for_password_delay} seconds before asking "
                        "for a password"
                    ),
                    description=(
                        f"Your Mac waits {ask_for_password_delay} seconds after the screen "
                        "saver starts before it asks for a password. If you step away "
                        "for a minute, someone could use your computer during that waiting "
                        "time.\n\n"
                        "What to do: Open System Settings > Lock Screen and set 'Require "
                        "password after screen saver begins or display is turned off' to "
                        "Immediately."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.lock_screen_check.screensaver_delay",
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
                                        title="Your Mac screen never turns off automatically",
                                        description=(
                                            "Your Mac is set to keep the screen on forever, "
                                            "even when you are not using it. If you leave "
                                            "the room, your open work remains visible "
                                            "to anyone who passes by.\n\n"
                                            "What to do: Open System Settings > Lock Screen "
                                            "and set 'Turn display off when inactive' to "
                                            "5 or 10 minutes."
                                        ),
                                        severity=Severity.WARNING,
                                        category=self.category,
                                        code="security.lock_screen_check.display_sleep",
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
