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
    name = "clamshell_mode"
    category = "performance"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 55
    depends_on = []
    estimated_duration = "3s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Get power settings
        power_settings = self._get_power_settings()

        # Check for external display
        external_display_connected = self._has_external_display()

        if power_settings:
            powernap = power_settings.get("powernap", 0)
            proximitywake = power_settings.get("proximitywake", 0)
            tcpkeepalive = power_settings.get("tcpkeepalive", 0)
            womp = power_settings.get("womp", 0)

            # WARNING: Power Nap enabled with external display (battery drain in clamshell)
            if powernap == 1 and external_display_connected:
                findings.append(
                    Finding(
                        title="Power Nap enabled with external display",
                        description=(
                            "Power Nap is enabled while using an external display in clamshell mode. "
                            "This can cause significant battery drain as the Mac may wake periodically. "
                            "Consider disabling on battery: sudo pmset -b powernap 0"
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={
                            "setting": "powernap",
                            "value": powernap,
                            "issue": "powernap_with_external_display",
                            "external_display": True,
                        },
                    )
                )

            # WARNING: Proximity wake enabled (unexpected wakes)
            if proximitywake == 1:
                findings.append(
                    Finding(
                        title="Proximity wake is enabled",
                        description=(
                            "Proximity wake (proximitywake) is enabled, which may cause your Mac "
                            "to wake unexpectedly when your iPhone is nearby. "
                            "Consider disabling: sudo pmset -a proximitywake 0"
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={
                            "setting": "proximitywake",
                            "value": proximitywake,
                            "issue": "unexpected_wakes",
                        },
                    )
                )

            # INFO: Report clamshell-relevant power settings
            settings_summary = self._format_settings_summary(
                powernap, womp, proximitywake, tcpkeepalive, external_display_connected
            )
            findings.append(
                Finding(
                    title="Clamshell mode power settings",
                    description=settings_summary,
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "powernap": powernap,
                        "womp": womp,
                        "proximitywake": proximitywake,
                        "tcpkeepalive": tcpkeepalive,
                        "external_display": external_display_connected,
                    },
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        for finding in findings.findings:
            if finding.data.get("issue") == "powernap_with_external_display":
                actions.append(
                    Action(
                        title="Disable Power Nap to prevent clamshell battery drain",
                        description=(
                            "Power Nap can wake your Mac periodically to check email and other updates, "
                            "which is problematic when using an external display in clamshell mode. "
                            "Recommended: sudo pmset -b powernap 0"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif finding.data.get("issue") == "unexpected_wakes":
                actions.append(
                    Action(
                        title="Disable Proximity Wake",
                        description=(
                            "Proximity wake causes your Mac to wake when your iPhone is nearby. "
                            "To disable: sudo pmset -a proximitywake 0"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            else:
                # INFO findings
                actions.append(
                    Action(
                        title="Clamshell mode power settings report",
                        description=finding.description,
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        data=finding.data,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _get_power_settings(self) -> dict:
        """Parse pmset -g output to extract power settings relevant to clamshell mode."""
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

    def _has_external_display(self) -> bool:
        """Check if external display is connected via system_profiler SPDisplaysDataType."""
        try:
            result = subprocess.run(
                ["system_profiler", "SPDisplaysDataType"],
                capture_output=True,
                text=True,
                timeout=5,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return False

        if result.returncode != 0:
            return False

        # Look for external display indicator
        # Builtin displays won't have connector info, external displays will
        output_lines = result.stdout.lower()

        # Check for indicators of external display
        # External displays typically have "connector:", "plug/unplug", or are not "built-in"
        if "connector:" in output_lines or "plug/unplug" in output_lines:
            return True

        # If there's more than one display entry or a non-builtin display
        display_count = output_lines.count("display:")
        builtin_count = output_lines.count("built-in")

        # If we have displays but fewer builtin displays than total, likely external
        return display_count > builtin_count if display_count > 0 else False

    def _format_settings_summary(
        self,
        powernap: int,
        womp: int,
        proximitywake: int,
        tcpkeepalive: int,
        external_display: bool,
    ) -> str:
        """Format a summary of clamshell-relevant power settings."""
        lines = [
            f"External display connected: {'yes' if external_display else 'no'}",
            f"Power Nap: {'enabled' if powernap == 1 else 'disabled'}",
            f"Wake-on-LAN (womp): {'enabled' if womp == 1 else 'disabled'}",
            f"Proximity wake: {'enabled' if proximitywake == 1 else 'disabled'}",
            f"TCP keep-alive: {'enabled' if tcpkeepalive == 1 else 'disabled'}",
        ]
        return "\n".join(lines)
