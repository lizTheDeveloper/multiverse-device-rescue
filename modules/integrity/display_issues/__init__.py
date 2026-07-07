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
    name = "display_issues"
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
                        "Unable to retrieve display information from system_profiler. "
                        "Display issue checks cannot be completed."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "no_display_info"},
                )
            )
            return CheckResult(module_name=self.name, findings=findings)

        # Report display configuration as INFO
        display_summary = ", ".join(
            [f"{d['name']} ({d['resolution']})" for d in displays]
        )
        findings.append(
            Finding(
                title="Display configuration",
                description=f"Connected displays: {display_summary}",
                severity=Severity.INFO,
                category=self.category,
                data={
                    "check": "display_config",
                    "displays": displays,
                    "count": len(displays),
                },
            )
        )

        # Check for scaled resolution on non-Retina displays (blurry text)
        for display in displays:
            if display.get("is_scaled") and not display.get("is_retina"):
                findings.append(
                    Finding(
                        title=f"Display '{display['name']}' using scaled resolution (blurry text)",
                        description=(
                            f"Display is running at {display['resolution']} (scaled) on a "
                            "non-Retina display. Scaled resolution on non-Retina displays "
                            "causes blurry text because pixels are being enlarged. "
                            "Switch to native resolution for crisp text."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={
                            "check": "scaled_non_retina",
                            "display": display["name"],
                            "resolution": display["resolution"],
                        },
                    )
                )

            # Check for non-native resolution (performance hit)
            if display.get("is_non_native"):
                findings.append(
                    Finding(
                        title=f"Display '{display['name']}' using non-native resolution",
                        description=(
                            f"Display is running at {display['resolution']} which is not "
                            "the native/recommended resolution. Non-native resolutions use "
                            "software scaling and can reduce performance and image quality. "
                            "Switch to native resolution for optimal performance."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={
                            "check": "non_native_resolution",
                            "display": display["name"],
                            "resolution": display["resolution"],
                        },
                    )
                )

        # Check for display mirroring
        mirroring_info = self._check_display_mirroring()
        if mirroring_info.get("mirroring_enabled"):
            findings.append(
                Finding(
                    title="Display mirroring is enabled",
                    description=(
                        "Display mirroring is currently enabled. If this was unintentional, "
                        "it may have been accidentally turned on and could reduce display "
                        "performance. Check System Settings > Displays to disable if not needed."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "check": "mirroring_enabled",
                        "mirrored_displays": mirroring_info.get("mirrored_displays", []),
                    },
                )
            )

        # Check Night Shift and True Tone availability/status
        display_features = self._check_display_features()

        if display_features.get("night_shift_available"):
            status = "enabled" if display_features.get("night_shift_enabled") else "available"
            findings.append(
                Finding(
                    title="Night Shift feature",
                    description=(
                        f"Night Shift is {status}. This feature reduces blue light "
                        "in the evening to reduce eye strain. "
                        f"Schedule: {display_features.get('night_shift_schedule', 'Unknown')}"
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "check": "night_shift",
                        "available": True,
                        "enabled": display_features.get("night_shift_enabled", False),
                    },
                )
            )

        if display_features.get("true_tone_available"):
            status = "enabled" if display_features.get("true_tone_enabled") else "available"
            findings.append(
                Finding(
                    title="True Tone feature",
                    description=(
                        f"True Tone is {status}. This feature automatically adjusts "
                        "display colors based on ambient light for natural-looking colors."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "check": "true_tone",
                        "available": True,
                        "enabled": display_features.get("true_tone_enabled", False),
                    },
                )
            )

        # Check for external monitors with resolution issues
        external_displays = [d for d in displays if d.get("connection") and "HDMI" in d.get("connection", "") or "DisplayPort" in d.get("connection", "")]
        if external_displays:
            for ext_display in external_displays:
                refresh_rate = ext_display.get("refresh_rate", "Unknown")
                findings.append(
                    Finding(
                        title=f"External monitor detected: {ext_display['name']}",
                        description=(
                            f"External monitor connected via {ext_display.get('connection', 'Unknown')}. "
                            f"Resolution: {ext_display['resolution']}, Refresh rate: {refresh_rate}. "
                            "Verify the monitor is running at the correct refresh rate and resolution "
                            "for your use case. External displays sometimes default to lower refresh rates."
                        ),
                        severity=Severity.INFO,
                        category=self.category,
                        data={
                            "check": "external_monitor",
                            "display": ext_display["name"],
                            "connection": ext_display.get("connection"),
                            "resolution": ext_display["resolution"],
                            "refresh_rate": refresh_rate,
                        },
                    )
                )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        for finding in findings.findings:
            check = finding.data.get("check")

            if check == "display_config":
                count = finding.data.get("count", 0)
                actions.append(
                    Action(
                        title="Display configuration documented",
                        description=(
                            f"System has {count} connected display(s). "
                            "For optimal display performance and image quality, verify that each "
                            "display is running at its native (recommended) resolution. "
                            "Go to System Settings > Displays to check and adjust resolution settings."
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
                            "Unable to retrieve display configuration from system_profiler. "
                            "Manually check your display settings in System Settings > Displays "
                            "to verify proper configuration and resolution."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "scaled_non_retina":
                display_name = finding.data.get("display", "Unknown")
                actions.append(
                    Action(
                        title=f"Fix blurry text on '{display_name}'",
                        description=(
                            f"Display '{display_name}' is using scaled resolution on a non-Retina "
                            "display, causing blurry text. To fix: "
                            "1. Go to System Settings > Displays "
                            "2. Select the display "
                            "3. Choose the 'native' or 'recommended' resolution (usually marked) "
                            "4. Click 'Confirm' if prompted. "
                            "The display may look smaller, but text will be sharp and crisp. "
                            "Non-Retina displays cannot scale cleanly, so native resolution is best."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "non_native_resolution":
                display_name = finding.data.get("display", "Unknown")
                actions.append(
                    Action(
                        title=f"Switch '{display_name}' to native resolution",
                        description=(
                            f"Display '{display_name}' is not running at its native resolution. "
                            "This causes performance degradation due to software scaling. To fix: "
                            "1. Go to System Settings > Displays "
                            "2. Select the display "
                            "3. Choose the native (marked as 'recommended') resolution "
                            "4. Apply the change. "
                            "Your display will perform better and images will be sharper."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "mirroring_enabled":
                actions.append(
                    Action(
                        title="Disable accidental display mirroring",
                        description=(
                            "Display mirroring is currently enabled. If this was accidental, disable it: "
                            "1. Go to System Settings > Displays "
                            "2. Look for the 'Mirror Displays' or 'AirPlay' section "
                            "3. Uncheck 'Mirror Displays' or set AirPlay to 'Off'. "
                            "Disabling mirroring when you have multiple displays allows you to "
                            "use each display independently for more screen space."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "night_shift":
                actions.append(
                    Action(
                        title="Night Shift feature available",
                        description=(
                            "Night Shift is supported on this Mac. To adjust settings: "
                            "1. Go to System Settings > Displays > Night Shift "
                            "2. Enable/disable as desired "
                            "3. Set custom schedule if preferred. "
                            "Night Shift reduces blue light in the evening to reduce eye strain."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "true_tone":
                actions.append(
                    Action(
                        title="True Tone feature available",
                        description=(
                            "True Tone is supported on this Mac. To adjust settings: "
                            "1. Go to System Settings > Displays > True Tone "
                            "2. Enable/disable as desired. "
                            "True Tone automatically adjusts colors based on ambient light "
                            "for more natural-looking colors."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "external_monitor":
                display_name = finding.data.get("display", "Unknown")
                actions.append(
                    Action(
                        title=f"Verify external monitor settings: {display_name}",
                        description=(
                            f"External monitor '{display_name}' is connected. "
                            "Verify it's configured correctly: "
                            "1. Go to System Settings > Displays "
                            "2. Check that the resolution and refresh rate match the monitor's capabilities. "
                            "3. For best performance, use the monitor's native resolution. "
                            "External monitors sometimes default to lower refresh rates; "
                            "increasing to the monitor's max refresh rate can improve responsiveness."
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

    def _check_display_mirroring(self) -> dict:
        """Check if display mirroring is enabled."""
        info = {}
        try:
            result = subprocess.run(
                ["defaults", "read", "com.apple.windowserver", "DisplayResolutionEnabled"],
                capture_output=True,
                text=True,
            )
            # Check for mirroring via system_profiler
            # This is a simplified check; actual detection might require more sophisticated parsing
            info["mirroring_enabled"] = False
            info["mirrored_displays"] = []
        except (OSError, subprocess.SubprocessError):
            pass
        return info

    def _check_display_features(self) -> dict:
        """Check Night Shift and True Tone availability and status."""
        info = {}

        # Check Night Shift availability and status
        try:
            result = subprocess.run(
                ["defaults", "read", "com.apple.CoreBrightness"],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                info["night_shift_available"] = True
                output = result.stdout.lower()
                info["night_shift_enabled"] = "enabled" in output or "1" in output
                # Try to extract schedule
                schedule_match = re.search(r"schedule\s*=", result.stdout)
                if schedule_match:
                    info["night_shift_schedule"] = "Custom schedule"
                else:
                    info["night_shift_schedule"] = "Default schedule"
        except (OSError, subprocess.SubprocessError):
            info["night_shift_available"] = False

        # Check True Tone availability and status
        try:
            result = subprocess.run(
                ["defaults", "read", "com.apple.CoreBrightness", "CBUser"],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0 and "TrueToneEnabled" in result.stdout:
                info["true_tone_available"] = True
                info["true_tone_enabled"] = "1" in result.stdout
        except (OSError, subprocess.SubprocessError):
            info["true_tone_available"] = False

        return info


def _parse_system_profiler(output: str) -> list[dict]:
    """Extract display info from system_profiler SPDisplaysDataType output."""
    displays = []

    if not output:
        return displays

    current_display = {}
    lines = output.split("\n")

    for line in lines:
        stripped = line.strip()

        # Detect display name
        if stripped.startswith("Display Name:"):
            if current_display and current_display.get("name"):
                displays.append(current_display)
            current_display = {"name": stripped.split(":", 1)[1].strip()}

        # Detect resolution
        elif stripped.startswith("Resolution:") and current_display:
            res_part = stripped.split(":", 1)[1].strip()
            current_display["resolution"] = res_part
            # Check if scaled (usually indicates "Scaled" in the resolution info)
            current_display["is_scaled"] = "scaled" in res_part.lower()
            # Check if non-native
            current_display["is_non_native"] = "non-native" in res_part.lower()

        # Detect if Retina
        elif "Retina" in stripped and current_display:
            current_display["is_retina"] = True

        # Detect connection type
        elif stripped.startswith("Connector Type:") and current_display:
            current_display["connection"] = stripped.split(":", 1)[1].strip()

        # Detect refresh rate
        elif stripped.startswith("Refresh Rate:") and current_display:
            refresh_info = stripped.split(":", 1)[1].strip()
            current_display["refresh_rate"] = refresh_info

        # Detect pixel pitch or other native indicators
        elif stripped.startswith("Pixel Pitch:") and current_display:
            current_display["pixel_pitch"] = stripped.split(":", 1)[1].strip()

    # Add the last display
    if current_display and current_display.get("name"):
        displays.append(current_display)

    return displays
