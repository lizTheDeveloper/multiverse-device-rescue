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
    name = "energy_settings"
    category = "performance"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 60
    depends_on = []
    estimated_duration = "2s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []
        power_settings = self._get_power_settings()

        if not power_settings:
            # If we can't get settings, return empty findings
            return CheckResult(module_name=self.name, findings=findings)

        # Extract key settings
        powernap = power_settings.get("powernap", 0)
        sleep_value = power_settings.get("sleep", 0)
        displaysleep = power_settings.get("displaysleep", 0)
        disksleep = power_settings.get("disksleep", 0)
        womp = power_settings.get("womp", 0)
        hibernatemode = power_settings.get("hibernatemode", 3)

        # Check for Power Nap enabled (battery drain on laptops)
        if powernap == 1:
            findings.append(
                Finding(
                    title="Power Nap is enabled",
                    description=(
                        "Power Nap can cause battery drain overnight on laptops. "
                        "Consider disabling it on battery: sudo pmset -b powernap 0"
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "setting": "powernap",
                        "value": powernap,
                        "issue": "battery_drain",
                    },
                )
            )

        # Check if system never sleeps (battery drain on laptops)
        if sleep_value == 0:
            findings.append(
                Finding(
                    title="System never sleeps",
                    description=(
                        "System never sleeps (sleep=0), which causes battery drain on laptops. "
                        "Consider enabling sleep: sudo pmset -b sleep 10"
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "setting": "sleep",
                        "value": sleep_value,
                        "issue": "battery_drain",
                    },
                )
            )

        # Report current power settings as INFO
        settings_summary = self._format_settings_summary(
            sleep_value, displaysleep, disksleep, womp, hibernatemode
        )
        findings.append(
            Finding(
                title="Current power management settings",
                description=settings_summary,
                severity=Severity.INFO,
                category=self.category,
                data={
                    "powernap": powernap,
                    "sleep": sleep_value,
                    "displaysleep": displaysleep,
                    "disksleep": disksleep,
                    "womp": womp,
                    "hibernatemode": hibernatemode,
                },
            )
        )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        for finding in findings.findings:
            if finding.data.get("issue") == "battery_drain":
                if finding.data.get("setting") == "powernap":
                    actions.append(
                        Action(
                            title="Disable Power Nap to prevent battery drain",
                            description=(
                                "Power Nap can wake your Mac periodically to check email "
                                "and other updates, draining battery on laptops. "
                                "To disable on battery: sudo pmset -b powernap 0\n"
                                "To disable on AC: sudo pmset -c powernap 0\n"
                                "To disable all: sudo pmset -a powernap 0"
                            ),
                            risk_level=RiskLevel.SAFE,
                            success=True,
                        )
                    )
                elif finding.data.get("setting") == "sleep":
                    actions.append(
                        Action(
                            title="Enable sleep to prevent battery drain",
                            description=(
                                "The system is set to never sleep, which drains battery. "
                                "Recommended settings for laptop on battery:\n"
                                "  sudo pmset -b sleep 10          # Sleep after 10 minutes\n"
                                "  sudo pmset -b displaysleep 5    # Display sleep after 5 minutes\n"
                                "  sudo pmset -b disksleep 10      # Disk sleep after 10 minutes\n"
                                "For AC power, use longer intervals: -c instead of -b"
                            ),
                            risk_level=RiskLevel.SAFE,
                            success=True,
                        )
                    )
            else:
                # INFO findings - just report status
                actions.append(
                    Action(
                        title="Power management status report",
                        description=finding.description,
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        data=finding.data,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _get_power_settings(self) -> dict:
        """Parse pmset -g output to extract power settings."""
        try:
            result = subprocess.run(
                ["pmset", "-g"],
                capture_output=True,
                text=True,
                timeout=5,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return {}

        if result.returncode != 0:
            return {}

        settings = {}
        for line in result.stdout.split("\n"):
            line = line.strip()
            if not line or line.startswith("#"):
                continue

            # Parse key-value pairs
            # Format: "key                value" or "key                value (additional info)"
            parts = line.split()
            if len(parts) >= 2:
                key = parts[0]
                try:
                    # Try to parse value as integer
                    value = int(parts[1])
                    settings[key] = value
                except ValueError:
                    # Not an integer, skip
                    pass

        return settings

    def _format_settings_summary(
        self, sleep_val: int, display_val: int, disk_val: int, womp_val: int, hib_val: int
    ) -> str:
        """Format a summary of power settings."""
        lines = [
            f"Sleep: {sleep_val} min {'(disabled)' if sleep_val == 0 else ''}",
            f"Display sleep: {display_val} min {'(disabled)' if display_val == 0 else ''}",
            f"Disk sleep: {disk_val} min {'(disabled)' if disk_val == 0 else ''}",
            f"Wake-on-LAN (womp): {'enabled' if womp_val == 1 else 'disabled'}",
            f"Hibernation mode: {hib_val} ({'disabled' if hib_val == 0 else 'enabled' if hib_val in (3, 25) else 'other'})",
        ]
        return "\n".join(lines)
