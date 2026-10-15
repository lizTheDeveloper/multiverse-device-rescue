import re
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
    name = "sleep_wake_issues"
    category = "integrity"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "3s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Get recent wake reasons
        wake_log = self._get_wake_log()
        wake_reasons = self._parse_wake_log(wake_log)

        # Check for frequent DarkWake events
        darkwake_count = sum(1 for r in wake_reasons if "DarkWake" in r)
        if darkwake_count > 10:
            findings.append(
                Finding(
                    title=(
                        f"Your Mac is waking up a lot for background tasks ({darkwake_count} "
                        "times)"
                    ),
                    description=(
                        f"We found {darkwake_count} instances where your Mac woke up briefly "
                        "to run background tasks. This is a normal maintenance process, "
                        "but if it happens too often, it can drain your battery faster "
                        "than expected.\n\n"
                        "What to do: Open System Settings > General > Login Items & Extensions. Look "
                        "for apps you don't recognize or don't need running in the background "
                        "and turn them off."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "darkwake_events", "darkwake_count": darkwake_count},
                )
            )

        # Get sleep prevention assertions
        assertions = self._get_assertions()
        if assertions:
            findings.append(
                Finding(
                    title="An app is stopping your Mac from sleeping",
                    description=(
                        f"Your Mac is currently being kept awake by: {assertions}. This "
                        "usually happens when an app is playing video, syncing files, "
                        "or running a heavy task. However, if your Mac stays awake when "
                        "you expect it to sleep, it will use more battery.\n\n"
                        "What to do: Check which app is using the most energy in System "
                        "Settings > Battery. If an app is stuck, quit it by right-clicking "
                        "its icon in the Dock and selecting Quit."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "assertions", "assertions": assertions},
                )
            )

        # Check Bluetooth wake status
        bt_wake_enabled = self._is_bluetooth_wake_enabled()
        if bt_wake_enabled:
            findings.append(
                Finding(
                    title="Bluetooth devices can wake your Mac from sleep",
                    description=(
                        "Your Mac is set to wake up when it detects Bluetooth activity, "
                        "such as when you move a wireless mouse or type on a keyboard. If "
                        "your Mac turns on unexpectedly, this is the likely cause.\n\n"
                        "What to do: Nothing, unless that bothers you. Then search System "
                        "Settings for 'wake' and turn off 'Allow Bluetooth devices to "
                        "wake this computer'."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "bluetooth_wake", "enabled": True},
                )
            )

        # Get scheduled wake events
        scheduled_events = self._get_scheduled_events()
        if scheduled_events:
            findings.append(
                Finding(
                    title=f"Planned wake-ups: {len(scheduled_events)}",
                    description=(
                        f"The system has {len(scheduled_events)} scheduled wake event(s). "
                        f"Details: {', '.join(scheduled_events[:3])}{'...' if len(scheduled_events) > 3 else ''}. "
                        "These can wake your Mac at specific times."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "check": "scheduled_events",
                        "scheduled_count": len(scheduled_events),
                        "events": scheduled_events,
                    },
                )
            )

        # Report recent wake reasons summary
        if wake_reasons:
            wake_summary = self._format_wake_summary(wake_reasons)
            findings.append(
                Finding(
                    title="Why your Mac woke up recently",
                    description=wake_summary,
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "check": "wake_reasons",
                        "total_wakes": len(wake_reasons),
                        "wake_reasons": wake_reasons[:20],  # Last 20
                    },
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        for finding in findings.findings:
            check = finding.data.get("check")

            if check == "darkwake_events":
                actions.append(
                    Action(
                        title="Reduce DarkWake events",
                        description=(
                            "To reduce DarkWake events:\n"
                            "1. Check System Settings > General > Login Items > Allow\n"
                            "2. Remove apps that don't need to launch at login\n"
                            "3. Disable Power Nap: sudo pmset -a powernap 0\n"
                            "4. Check for scheduled tasks in Automator or cron\n"
                            "5. Disable Time Machine backups while sleeping: "
                            "System Settings > General > Time Machine > Options"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "assertions":
                assertions = finding.data.get("assertions")
                actions.append(
                    Action(
                        title="Address sleep prevention assertions",
                        description=(
                            f"Active assertions preventing sleep: {assertions}\n"
                            "These are usually set by running applications. To resolve:\n"
                            "1. Identify which app is preventing sleep (check Activity Monitor)\n"
                            "2. Quit the application if not needed\n"
                            "3. Check System Settings for background app activity permissions\n"
                            "4. Consider disabling the app's background activity privileges"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "bluetooth_wake":
                actions.append(
                    Action(
                        title="Disable Bluetooth wake",
                        description=(
                            "To disable Bluetooth wake:\n"
                            "defaults write /Library/Preferences/com.apple.Bluetooth "
                            "BTPowerController -bool false\n"
                            "Note: This requires sudo. After running the command, "
                            "disconnect and reconnect your Bluetooth devices."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "scheduled_events":
                events = finding.data.get("events", [])
                actions.append(
                    Action(
                        title="Review scheduled wake events",
                        description=(
                            f"Found {len(events)} scheduled wake event(s):\n"
                            + "\n".join(events[:5])
                            + ("\n..." if len(events) > 5 else "")
                            + "\n\nTo view all: pmset -g sched\n"
                            "To remove a specific event: sudo pmset repeat cancel"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "wake_reasons":
                actions.append(
                    Action(
                        title="Recent wake reasons report",
                        description=finding.description,
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        data=finding.data,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _get_wake_log(self) -> str:
        """Get recent wake log entries."""
        try:
            result = subprocess.run(
                ["pmset", "-g", "log"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return result.stdout if result.returncode == 0 else ""
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return ""

    def _get_assertions(self) -> str:
        """Get current sleep prevention assertions."""
        try:
            result = subprocess.run(
                ["pmset", "-g", "assertions"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                # Parse assertions to find active ones
                return self._parse_assertions(result.stdout)
            return ""
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return ""

    def _get_scheduled_events(self) -> list:
        """Get scheduled wake events."""
        try:
            result = subprocess.run(
                ["pmset", "-g", "sched"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                return self._parse_scheduled_events(result.stdout)
            return []
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return []

    def _is_bluetooth_wake_enabled(self) -> bool:
        """Check if Bluetooth wake is enabled."""
        try:
            result = subprocess.run(
                ["defaults", "read", "/Library/Preferences/com.apple.Bluetooth"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            # If the defaults command succeeds, check the value
            if result.returncode == 0 and result.stdout:
                # If BTPowerController is explicitly set to 0 or false, it's disabled
                if "BTPowerController" in result.stdout and "= 0" in result.stdout:
                    return False
                # Otherwise, check if it contains a false value
                if "false" in result.stdout.lower():
                    return False
                return True
            # If the file doesn't exist (returncode != 0), Bluetooth wake is enabled by default
            return True
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return True  # Assume enabled if we can't check

    def _parse_assertions(self, output: str) -> str:
        """Parse assertions output and return summary of active assertions."""
        assertions = []
        lines = output.split("\n")

        for line in lines:
            line = line.strip()
            # Look for assertions with "on" or "enabled" status
            if "PreventUserIdleDisplaySleep" in line or "PreventSystemSleep" in line:
                if "1" in line or "on" in line.lower():
                    # Extract the assertion type
                    if "PreventUserIdleDisplaySleep" in line:
                        assertions.append("PreventUserIdleDisplaySleep")
                    elif "PreventSystemSleep" in line:
                        assertions.append("PreventSystemSleep")

        return ", ".join(assertions) if assertions else ""

    def _parse_scheduled_events(self, output: str) -> list:
        """Parse scheduled events from pmset -g sched output."""
        events = []
        lines = output.split("\n")

        for line in lines:
            line = line.strip()
            if line and not line.startswith("#") and line:
                # Extract event details
                events.append(line)

        return events

    def _parse_wake_log(self, output: str) -> list:
        """Parse wake log and extract Wake/DarkWake entries."""
        wake_reasons = []
        lines = output.split("\n")

        for line in lines:
            line = line.strip()
            if "Wake from" in line or "DarkWake" in line:
                # Extract the wake reason
                if "Wake from" in line:
                    # Format: "2024-01-15 09:30:45 +0000  Wake from Normal Sleep due to ...-"
                    match = re.search(r"Wake from (\w+) (.*)", line)
                    if match:
                        reason = f"Wake from {match.group(1)}: {match.group(2)}"
                        wake_reasons.append(reason)
                elif "DarkWake" in line:
                    # Format: "2024-01-15 09:30:45 +0000  DarkWake"
                    wake_reasons.append(line)

        # Return most recent entries (reverse order from log)
        return wake_reasons[:20]

    def _format_wake_summary(self, wake_reasons: list) -> str:
        """Format wake reasons into a readable summary."""
        if not wake_reasons:
            return "No recent wake events found."

        summary_lines = [f"Found {len(wake_reasons)} recent wake event(s):"]
        for reason in wake_reasons[:10]:  # Show first 10
            summary_lines.append(f"  - {reason}")

        if len(wake_reasons) > 10:
            summary_lines.append(f"  ... and {len(wake_reasons) - 10} more")

        summary_lines.append("\nRun 'pmset -g log' for full details.")
        return "\n".join(summary_lines)
