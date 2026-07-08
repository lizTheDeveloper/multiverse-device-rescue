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
    name = "energy_saver_check"
    category = "performance"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 60
    depends_on = []
    estimated_duration = "5s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Get current power settings
        pmset_output = self._run_pmset()
        settings = _parse_pmset(pmset_output)

        # Get scheduled wake/sleep events
        sched_output = self._run_pmset_sched()
        scheduled_events = _parse_pmset_sched(sched_output)

        # Check if on battery power
        is_on_battery = settings.get("is_on_battery", False)

        # Flag if display sleep is disabled (never sleeps)
        display_sleep = settings.get("display_sleep_minutes")
        if display_sleep == 0:
            findings.append(
                Finding(
                    title="Display sleep disabled",
                    description=(
                        "Display sleep is set to never sleep. This will cause the screen "
                        "to stay on continuously, draining battery quickly on laptops."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "check": "display_sleep_disabled",
                        "setting": "displaysleep",
                        "value": "0",
                    },
                )
            )

        # Check if computer/system sleep is disabled
        computer_sleep = settings.get("computer_sleep_minutes")
        if computer_sleep == 0:
            findings.append(
                Finding(
                    title="Computer sleep disabled",
                    description=(
                        "Computer/system sleep is set to never sleep. This will prevent "
                        "the Mac from entering low-power mode, increasing energy consumption."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "check": "computer_sleep_disabled",
                        "setting": "sleep",
                        "value": "0",
                    },
                )
            )

        # Check if disk sleep is disabled
        disk_sleep = settings.get("disk_sleep_minutes")
        if disk_sleep == 0:
            findings.append(
                Finding(
                    title="Disk sleep disabled",
                    description=(
                        "Disk sleep is disabled, so the hard drive will not spin down "
                        "during idle periods, increasing energy consumption."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "check": "disk_sleep_disabled",
                        "setting": "disksleep",
                        "value": "0",
                    },
                )
            )

        # Check Power Nap status
        powernap = settings.get("powernap")
        if powernap == 1:
            if is_on_battery:
                findings.append(
                    Finding(
                        title="Power Nap enabled on battery",
                        description=(
                            "Power Nap is enabled while on battery power. This allows the Mac "
                            "to perform background tasks even in sleep mode, which can unnecessarily "
                            "drain your battery."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={
                            "check": "power_nap_on_battery",
                            "setting": "powernap",
                            "value": "1",
                            "is_battery": True,
                        },
                    )
                )
            else:
                findings.append(
                    Finding(
                        title="Power Nap enabled on AC power",
                        description=(
                            "Power Nap is enabled. While on AC power this is fine, "
                            "it allows background tasks during sleep."
                        ),
                        severity=Severity.INFO,
                        category=self.category,
                        data={
                            "check": "power_nap_enabled",
                            "setting": "powernap",
                            "value": "1",
                            "is_battery": False,
                        },
                    )
                )

        # Check Wake for network access (wake on LAN / WiFi)
        wake_on_lan = settings.get("wakeonlan")
        if wake_on_lan == 1:
            if is_on_battery:
                findings.append(
                    Finding(
                        title="Wake for network access enabled on battery",
                        description=(
                            "Wake for network access is enabled while on battery power. "
                            "This allows the Mac to wake from sleep when receiving network traffic, "
                            "which can drain battery on laptops."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={
                            "check": "wake_on_lan_battery",
                            "setting": "wakeonlan",
                            "value": "1",
                            "is_battery": True,
                        },
                    )
                )
            else:
                findings.append(
                    Finding(
                        title="Wake for network access enabled",
                        description=(
                            "Wake for network access is enabled. This allows the Mac to wake "
                            "from sleep when receiving network traffic."
                        ),
                        severity=Severity.INFO,
                        category=self.category,
                        data={
                            "check": "wake_on_lan_enabled",
                            "setting": "wakeonlan",
                            "value": "1",
                            "is_battery": False,
                        },
                    )
                )

        # Check if prevent sleep when display is off
        prevent_sleep_display_off = settings.get("disablesleep")
        if prevent_sleep_display_off == 1:
            findings.append(
                Finding(
                    title="Prevent sleep when display is off enabled",
                    description=(
                        "The Mac is configured to prevent sleep when the display is off. "
                        "This is typically used for servers/kiosks and will increase energy consumption."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "check": "prevent_sleep_display_off",
                        "setting": "disablesleep",
                        "value": "1",
                    },
                )
            )

        # Check hibernation mode
        hibernation_mode = settings.get("hibernatemode")
        if hibernation_mode is not None:
            findings.append(
                Finding(
                    title=f"Hibernation mode: {hibernation_mode}",
                    description=(
                        f"Hibernation mode is set to {hibernation_mode}. "
                        f"Mode 0: Sleep only. Mode 3: Sleep + hibernation (default). Mode 25: Hibernate only."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "check": "hibernation_mode",
                        "setting": "hibernatemode",
                        "value": hibernation_mode,
                    },
                )
            )

        # Report scheduled wake/sleep events
        if scheduled_events:
            findings.append(
                Finding(
                    title=f"Scheduled wake/sleep events ({len(scheduled_events)})",
                    description=(
                        f"Found {len(scheduled_events)} scheduled wake or sleep events. "
                        f"These can prevent the Mac from sleeping or wake it unexpectedly. "
                        f"Events: {'; '.join(scheduled_events)}"
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "check": "scheduled_events",
                        "event_count": len(scheduled_events),
                        "events": scheduled_events,
                    },
                )
            )

        # Report current configuration if no warnings
        if not any(f.severity == Severity.WARNING for f in findings):
            findings.append(
                Finding(
                    title="Power management configuration normal",
                    description=(
                        "Power management settings appear to be properly configured. "
                        "Your Mac should sleep correctly and manage energy efficiently."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "config_normal"},
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        for finding in findings.findings:
            check = finding.data.get("check")

            if check == "display_sleep_disabled":
                actions.append(
                    Action(
                        title="Enable display sleep",
                        description=(
                            "Display sleep is disabled. To enable it, go to "
                            "System Settings > Displays > Lock screen (or Sleep). "
                            "Set an appropriate timeout (e.g., 5-10 minutes). "
                            "Or via command line: sudo pmset -a displaysleep 10"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=False,
                    )
                )

            elif check == "computer_sleep_disabled":
                actions.append(
                    Action(
                        title="Enable computer sleep",
                        description=(
                            "Computer sleep is disabled. To enable it, go to "
                            "System Settings > Energy Saver (or Battery). "
                            "Set 'Turn display off after' to an appropriate timeout (e.g., 10-30 minutes). "
                            "Or via command line: sudo pmset -a sleep 15"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=False,
                    )
                )

            elif check == "disk_sleep_disabled":
                actions.append(
                    Action(
                        title="Enable disk sleep",
                        description=(
                            "Disk sleep is disabled. Enable it to save energy. "
                            "Or via command line: sudo pmset -a disksleep 10"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=False,
                    )
                )

            elif check == "power_nap_on_battery":
                actions.append(
                    Action(
                        title="Disable Power Nap on battery",
                        description=(
                            "Power Nap is unnecessarily draining your battery while on battery power. "
                            "Go to System Settings > Battery, then disable 'Power Nap' "
                            "in the Battery section. "
                            "Or via command line: sudo pmset -b powernap 0"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=False,
                    )
                )

            elif check == "power_nap_enabled":
                actions.append(
                    Action(
                        title="Power Nap is enabled",
                        description=(
                            "Power Nap is enabled on AC power. This is acceptable for desktop Macs "
                            "but may increase energy consumption slightly. You can disable it via "
                            "System Settings > Battery if desired, or: sudo pmset -a powernap 0"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "wake_on_lan_battery":
                actions.append(
                    Action(
                        title="Disable Wake for network access on battery",
                        description=(
                            "Wake for network access is unnecessarily draining your battery. "
                            "Go to System Settings > General > Sharing, and uncheck "
                            "'Wake for network access' when on battery power. "
                            "Or via command line: sudo pmset -b wakeonlan 0"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=False,
                    )
                )

            elif check == "wake_on_lan_enabled":
                actions.append(
                    Action(
                        title="Wake for network access is enabled",
                        description=(
                            "Wake for network access is enabled. This allows the Mac to wake from sleep "
                            "when receiving network traffic. Disable in System Settings > General > Sharing "
                            "if you don't need this feature, or: sudo pmset -a wakeonlan 0"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "prevent_sleep_display_off":
                actions.append(
                    Action(
                        title="Prevent sleep when display is off is enabled",
                        description=(
                            "This setting prevents sleep when the display is off. "
                            "This is typically for servers/kiosks. Disable if you want normal sleep behavior: "
                            "sudo pmset -a disablesleep 0"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "hibernation_mode":
                mode_val = finding.data.get("value")
                actions.append(
                    Action(
                        title=f"Hibernation mode is {mode_val}",
                        description=(
                            f"Current hibernation mode: {mode_val}. "
                            "Mode 0: Sleep (RAM powered). "
                            "Mode 3: Sleep + hibernation (both RAM and disk saved). "
                            "Mode 25: Hibernate only (safe but slower to wake). "
                            "For most users, mode 3 is optimal. Change with: "
                            "sudo pmset -a hibernatemode 3"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "scheduled_events":
                event_count = finding.data.get("event_count")
                actions.append(
                    Action(
                        title=f"Scheduled wake/sleep events found ({event_count})",
                        description=(
                            f"You have {event_count} scheduled wake/sleep events. "
                            "These can prevent the Mac from sleeping or wake it unexpectedly. "
                            "Remove them in System Settings > General > Date & Time > Scheduled Power On/Off "
                            "if you don't need them. Or view all via: pmset -g sched"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "config_normal":
                actions.append(
                    Action(
                        title="Power management is properly configured",
                        description=(
                            "Your power management settings look good. Your Mac should sleep "
                            "correctly and manage energy efficiently. You can check settings anytime "
                            "with: pmset -g"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _run_pmset(self) -> str:
        """Run pmset -g and return output."""
        try:
            result = subprocess.run(
                ["pmset", "-g"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return result.stdout
        except (OSError, subprocess.SubprocessError, subprocess.TimeoutExpired):
            return ""

    def _run_pmset_sched(self) -> str:
        """Run pmset -g sched and return output."""
        try:
            result = subprocess.run(
                ["pmset", "-g", "sched"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return result.stdout
        except (OSError, subprocess.SubprocessError, subprocess.TimeoutExpired):
            return ""


def _parse_pmset(output: str) -> dict:
    """Parse pmset -g output and extract power settings."""
    settings = {}

    # Check if on battery power
    if "Currently in use:" in output:
        if "Battery Power" in output:
            settings["is_on_battery"] = True
        else:
            settings["is_on_battery"] = False

    # Parse display sleep (displaysleep)
    display_match = re.search(r"displaysleep\s+(\d+)", output)
    if display_match:
        settings["display_sleep_minutes"] = int(display_match.group(1))

    # Parse computer/system sleep (sleep)
    sleep_match = re.search(r"^\s*sleep\s+(\d+)", output, re.MULTILINE)
    if sleep_match:
        settings["computer_sleep_minutes"] = int(sleep_match.group(1))

    # Parse disk sleep (disksleep)
    disk_match = re.search(r"disksleep\s+(\d+)", output)
    if disk_match:
        settings["disk_sleep_minutes"] = int(disk_match.group(1))

    # Parse Power Nap (powernap)
    powernap_match = re.search(r"powernap\s+(\d+)", output)
    if powernap_match:
        settings["powernap"] = int(powernap_match.group(1))

    # Parse Wake on LAN (wakeonlan)
    wakeonlan_match = re.search(r"wakeonlan\s+(\d+)", output)
    if wakeonlan_match:
        settings["wakeonlan"] = int(wakeonlan_match.group(1))

    # Parse prevent sleep (disablesleep)
    disablesleep_match = re.search(r"disablesleep\s+(\d+)", output)
    if disablesleep_match:
        settings["disablesleep"] = int(disablesleep_match.group(1))

    # Parse hibernation mode
    hibernatemode_match = re.search(r"hibernatemode\s+(\d+)", output)
    if hibernatemode_match:
        settings["hibernatemode"] = int(hibernatemode_match.group(1))

    return settings


def _parse_pmset_sched(output: str) -> list:
    """Parse pmset -g sched output and extract scheduled events."""
    events = []

    # Parse lines like:
    # Scheduled power on/off events:
    # 01/01/2024 08:00:00 [System]
    if not output or "No scheduled" in output:
        return events

    lines = output.strip().split("\n")
    for line in lines:
        line = line.strip()
        # Skip header and empty lines
        if not line or "Scheduled" in line or "No scheduled" in line:
            continue
        # Match date/time patterns
        if re.match(r"\d{2}/\d{2}/\d{4}", line):
            events.append(line)

    return events
