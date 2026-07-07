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
    name = "display_config"
    category = "integrity"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "3s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Get display info from system_profiler
        system_profiler_output = self._run_system_profiler()
        displays = _parse_system_profiler(system_profiler_output)

        # Check if any displays are found
        if not displays:
            findings.append(
                Finding(
                    title="No display information available",
                    description=(
                        "Unable to retrieve display configuration information from "
                        "system_profiler. Display checks cannot be completed."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "no_display_info"},
                )
            )
            return CheckResult(module_name=self.name, findings=findings)

        # List all displays
        display_summary = ", ".join(
            [f"{d['name']} ({d['resolution']})" for d in displays]
        )
        findings.append(
            Finding(
                title="Display configuration detected",
                description=f"Connected displays: {display_summary}. Display types: "
                f"{', '.join([d.get('connection', 'Unknown') for d in displays])}.",
                severity=Severity.INFO,
                category=self.category,
                data={
                    "check": "display_list",
                    "displays": displays,
                    "count": len(displays),
                },
            )
        )

        # Check for scaled/non-native resolution
        for display in displays:
            if display.get("is_scaled"):
                findings.append(
                    Finding(
                        title=f"Display '{display['name']}' running at scaled resolution",
                        description=(
                            f"Display is running at {display['resolution']} (scaled). "
                            "Scaled resolution can cause blurriness and reduced performance. "
                            "Consider using native resolution for better clarity."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={
                            "check": "scaled_resolution",
                            "display": display["name"],
                            "resolution": display["resolution"],
                        },
                    )
                )

        # Check Night Shift and display settings
        night_shift_info = self._run_defaults_read()
        if night_shift_info.get("night_shift_enabled"):
            findings.append(
                Finding(
                    title="Night Shift is enabled",
                    description=(
                        f"Night Shift is currently enabled with schedule: "
                        f"{night_shift_info.get('schedule', 'Unknown')}. "
                        f"This reduces blue light in the evening. "
                        f"Brightness level: {night_shift_info.get('brightness', 'Unknown')}."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "check": "night_shift",
                        "enabled": True,
                        "schedule": night_shift_info.get("schedule"),
                        "brightness": night_shift_info.get("brightness"),
                    },
                )
            )

        if night_shift_info.get("true_tone_enabled"):
            findings.append(
                Finding(
                    title="True Tone is enabled",
                    description=(
                        "True Tone automatically adjusts display colors based on "
                        "ambient light. This feature is available on newer Macs."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "check": "true_tone",
                        "enabled": True,
                    },
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        for finding in findings.findings:
            check = finding.data.get("check")

            if check == "display_list":
                count = finding.data.get("count", 0)
                actions.append(
                    Action(
                        title="Display configuration documented",
                        description=(
                            f"System has {count} connected display(s). "
                            "Monitor displays for connectivity and resolution issues. "
                            "In System Settings > Displays, verify that each display is "
                            "running at its native (recommended) resolution for optimal "
                            "sharpness and color accuracy."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "no_display_info":
                actions.append(
                    Action(
                        title="Display information unavailable",
                        description=(
                            "Unable to retrieve display configuration. This may occur on "
                            "systems with display issues or in remote sessions. "
                            "Visit System Settings > Displays to manually verify your "
                            "display configuration."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "scaled_resolution":
                display_name = finding.data.get("display", "Unknown")
                actions.append(
                    Action(
                        title=f"Adjust '{display_name}' resolution",
                        description=(
                            f"Display '{display_name}' is currently running at a scaled "
                            "resolution. For crisp text and images, open System Settings > "
                            "Displays and select the 'native' or 'recommended' resolution. "
                            "Note: Lower resolutions may increase text size, but provide "
                            "better sharpness. Scaled resolutions use software scaling which "
                            "can reduce performance and image quality."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "night_shift":
                actions.append(
                    Action(
                        title="Night Shift settings reviewed",
                        description=(
                            "Night Shift is enabled and working as expected. "
                            "To adjust Night Shift settings, go to System Settings > "
                            "Displays > Night Shift. You can enable/disable it, set a "
                            "custom schedule, or adjust color temperature."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "true_tone":
                actions.append(
                    Action(
                        title="True Tone settings reviewed",
                        description=(
                            "True Tone is enabled. This feature automatically adjusts "
                            "display colors based on ambient light conditions. "
                            "To disable True Tone, go to System Settings > Displays > "
                            "True Tone and toggle it off."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _run_system_profiler(self) -> str:
        """Run system_profiler SPDisplaysDataType and return output."""
        try:
            result = subprocess.run(
                ["system_profiler", "SPDisplaysDataType"],
                capture_output=True,
                text=True,
                errors="replace",
            )
            return result.stdout
        except (OSError, subprocess.SubprocessError):
            return ""

    def _run_defaults_read(self) -> dict:
        """Run defaults read to get Night Shift and True Tone settings."""
        info = {}

        # Check Night Shift status
        try:
            result = subprocess.run(
                ["defaults", "read", "com.apple.CoreBrightness"],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                output = result.stdout
                info["night_shift_enabled"] = "1" in output or "true" in output.lower()
                # Try to extract schedule
                schedule_match = re.search(r"Schedule\s*=\s*\{[^}]*\}", output)
                if schedule_match:
                    info["schedule"] = "Custom schedule detected"
                else:
                    info["schedule"] = "Default schedule"
        except (OSError, subprocess.SubprocessError):
            pass

        # Check brightness level
        try:
            result = subprocess.run(
                ["defaults", "read", "com.apple.AppleDisplayBrightness"],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                brightness_match = re.search(r"brightness\s*=\s*([\d.]+)", result.stdout)
                if brightness_match:
                    brightness_val = float(brightness_match.group(1))
                    info["brightness"] = f"{int(brightness_val * 100)}%"
        except (OSError, subprocess.SubprocessError):
            pass

        # Check True Tone status
        try:
            result = subprocess.run(
                ["defaults", "read", "com.apple.CoreBrightness", "CBUser"],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0 and "TrueToneEnabled" in result.stdout:
                info["true_tone_enabled"] = "1" in result.stdout
        except (OSError, subprocess.SubprocessError):
            pass

        return info


def _parse_system_profiler(output: str) -> list[dict]:
    """Extract display info from system_profiler SPDisplaysDataType output."""
    displays = []

    # Split by display sections
    # Look for lines that start with "Display Name:" or similar
    current_display = {}

    lines = output.split("\n")
    for line in lines:
        line = line.strip()

        # Detect display name
        if line.startswith("Display Name:"):
            if current_display:
                displays.append(current_display)
            current_display = {"name": line.split(":", 1)[1].strip()}

        # Detect resolution
        elif line.startswith("Resolution:") and current_display:
            res_part = line.split(":", 1)[1].strip()
            current_display["resolution"] = res_part
            # Check if scaled (usually indicates "Scaled" in the resolution info)
            current_display["is_scaled"] = "scaled" in res_part.lower()

        # Detect connection type
        elif line.startswith("Connector Type:") and current_display:
            current_display["connection"] = line.split(":", 1)[1].strip()

        # Detect pixel pitch or other native indicators
        elif line.startswith("Pixel Pitch:") and current_display:
            current_display["pixel_pitch"] = line.split(":", 1)[1].strip()

    # Add the last display
    if current_display:
        displays.append(current_display)

    return displays
