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
    name = "power_settings"
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
        sleep_value = power_settings.get("sleep", 0)
        displaysleep = power_settings.get("displaysleep", 0)
        powernap = power_settings.get("powernap", 0)
        womp = power_settings.get("womp", 0)

        # Check if system never sleeps (sleep = 0, wastes energy and wears hardware)
        if sleep_value == 0:
            findings.append(
                Finding(
                    title="Computer never sleeps",
                    description=(
                        "Computer sleep is disabled (sleep=0). This wastes energy and increases "
                        "hardware wear. Recommended: sudo pmset -a sleep 10"
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "setting": "sleep",
                        "value": sleep_value,
                        "issue": "never_sleeps",
                    },
                )
            )

        # Check if display sleep is very short (<2 minutes, annoying for users)
        if 0 < displaysleep < 2:
            findings.append(
                Finding(
                    title="Display sleep is very short",
                    description=(
                        f"Display sleep is set to {displaysleep} minute(s), which is very short "
                        "and may be annoying. Typical: 5-10 minutes. "
                        "Adjust with: sudo pmset -a displaysleep 5"
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "setting": "displaysleep",
                        "value": displaysleep,
                        "issue": "very_short_display_sleep",
                    },
                )
            )

        # Report Power Nap setting (informational)
        if powernap == 1:
            findings.append(
                Finding(
                    title="Power Nap is enabled",
                    description=(
                        "Power Nap allows the Mac to perform periodic network operations "
                        "while asleep. Can drain battery on portable devices. "
                        "To disable: sudo pmset -a powernap 0"
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "setting": "powernap",
                        "value": powernap,
                    },
                )
            )

        # Report all power settings as INFO summary
        settings_summary = self._format_settings_summary(
            sleep_value, displaysleep, powernap, womp
        )
        findings.append(
            Finding(
                title="Current power management settings",
                description=settings_summary,
                severity=Severity.INFO,
                category=self.category,
                data={
                    "sleep": sleep_value,
                    "displaysleep": displaysleep,
                    "powernap": powernap,
                    "womp": womp,
                },
            )
        )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        for finding in findings.findings:
            issue = finding.data.get("issue")
            if issue == "never_sleeps":
                actions.append(
                    Action(
                        title="Enable computer sleep to reduce energy use",
                        description=(
                            "The system is set to never sleep, which wastes energy and causes "
                            "unnecessary hardware wear. Recommended fix:\n"
                            "  sudo pmset -a sleep 10          # Sleep after 10 minutes\n"
                            "Or adjust to your preference (5-15 minutes typical).\n"
                            "For laptops, set different times on battery and AC power:\n"
                            "  sudo pmset -b sleep 10          # Battery: sleep after 10 min\n"
                            "  sudo pmset -c sleep 20          # AC: sleep after 20 min"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif issue == "very_short_display_sleep":
                actions.append(
                    Action(
                        title="Adjust display sleep timer",
                        description=(
                            "Display sleep is set very short, which may be annoying when working. "
                            "Recommended adjustment:\n"
                            "  sudo pmset -a displaysleep 5    # Display sleep after 5 minutes\n"
                            "Adjust to your preference (typically 2-10 minutes). "
                            "Set independent times on battery and AC:\n"
                            "  sudo pmset -b displaysleep 3    # Battery: 3 minutes\n"
                            "  sudo pmset -c displaysleep 10   # AC: 10 minutes"
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
        self, sleep_val: int, display_val: int, powernap_val: int, womp_val: int
    ) -> str:
        """Format a summary of power settings."""
        lines = [
            f"Computer sleep: {sleep_val} min {'(disabled)' if sleep_val == 0 else ''}",
            f"Display sleep: {display_val} min {'(disabled)' if display_val == 0 else ''}",
            f"Power Nap: {'enabled' if powernap_val == 1 else 'disabled'}",
            f"Wake for network access (womp): {'enabled' if womp_val == 1 else 'disabled'}",
        ]
        return "\n".join(lines)
