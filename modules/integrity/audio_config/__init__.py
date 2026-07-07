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
    name = "audio_config"
    category = "integrity"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 45
    depends_on = []
    estimated_duration = "3s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Get audio devices from system_profiler
        profiler_output = self._run_system_profiler()
        devices = _parse_audio_devices(profiler_output)

        if not devices:
            findings.append(
                Finding(
                    title="Could not enumerate audio devices",
                    description=(
                        "Unable to retrieve audio device information from system_profiler. "
                        "This may indicate a system configuration issue."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "no_devices_found"},
                )
            )
            return CheckResult(module_name=self.name, findings=findings)

        # Log all available devices as INFO
        device_list = _format_device_list(devices)
        findings.append(
            Finding(
                title=f"Audio devices detected ({len(devices)} total)",
                description=f"Available audio input/output devices:\n{device_list}",
                severity=Severity.INFO,
                category=self.category,
                data={
                    "check": "devices_info",
                    "device_count": len(devices),
                    "devices": devices,
                },
            )
        )

        # Try to get current output device and volume status
        current_output = self._get_current_output_device()
        mute_status = self._get_mute_status()
        volume_level = self._get_volume_level()

        # Check for muted output (very common user issue)
        if mute_status is not None and mute_status:
            findings.append(
                Finding(
                    title="System audio is muted",
                    description=(
                        "The system audio output is currently muted. This is a common reason "
                        "why users don't hear sound. Unmute by pressing the mute key or "
                        "adjusting volume in System Settings."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "audio_muted"},
                )
            )

        # Check for low volume
        if volume_level is not None and volume_level < 10:
            findings.append(
                Finding(
                    title=f"System volume is very low ({volume_level}%)",
                    description=(
                        f"System audio volume is set to {volume_level}%, which is very quiet. "
                        "Increase volume via keyboard keys or System Settings > Sound."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "volume_low", "volume_percent": volume_level},
                )
            )

        # Check if output is routed to a device that may not be connected
        if current_output:
            if _is_likely_disconnected_device(current_output, devices):
                findings.append(
                    Finding(
                        title=f"Audio routed to potentially disconnected device: {current_output}",
                        description=(
                            f"System audio is routed to '{current_output}', which does not appear "
                            "in the list of currently connected devices. Try switching to a different "
                            "output device via System Settings > Sound."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={
                            "check": "device_not_connected",
                            "current_device": current_output,
                        },
                    )
                )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        for finding in findings.findings:
            check = finding.data.get("check")

            if check == "no_devices_found":
                actions.append(
                    Action(
                        title="Troubleshoot missing audio devices",
                        description=(
                            "Unable to detect audio devices. Try: (1) Check System Preferences > Sound "
                            "to verify a device is selected; (2) Restart CoreAudio: 'sudo launchctl stop "
                            "com.apple.audio.system.sound_presentation_assistant && sudo launchctl start "
                            "com.apple.audio.system.sound_presentation_assistant'; (3) If the issue persists, "
                            "restart your Mac or reset SMC (Intel: Shift+Ctrl+Option+Power; Apple Silicon: "
                            "press and hold the power button for 10 seconds)."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "devices_info":
                actions.append(
                    Action(
                        title="Audio devices available",
                        description=(
                            "Audio devices are properly detected. This is informational; "
                            "check the device listing above to verify your speakers or headphones "
                            "are connected and enabled."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "audio_muted":
                actions.append(
                    Action(
                        title="Unmute system audio",
                        description=(
                            "Your system audio is muted. To unmute: (1) Press the mute key (F10 or "
                            "equivalent on your Mac); (2) Or open System Settings > Sound and toggle "
                            "the mute switch off; (3) Increase volume with the volume up key (F12). "
                            "After unmuting, test a video or audio file to confirm sound is working."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "volume_low":
                volume = finding.data.get("volume_percent", 0)
                actions.append(
                    Action(
                        title="Increase system volume",
                        description=(
                            f"System volume is very low ({volume}%). To increase volume: (1) Press the "
                            "volume up key (F12) multiple times; (2) Or click the volume icon in the menu "
                            "bar and drag to increase; (3) Or open System Settings > Sound and use the "
                            "volume slider. Try incrementally raising to 50-70% and test with audio/video."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "device_not_connected":
                current = finding.data.get("current_device", "unknown")
                actions.append(
                    Action(
                        title="Switch audio output device",
                        description=(
                            f"Audio is routing to '{current}', which is not connected. To fix: (1) Click "
                            "the volume icon in the menu bar; (2) Select a different device from the "
                            "'Output Device' list; (3) Or open System Settings > Sound > Output and choose "
                            "a connected device (e.g., 'Internal Speakers', 'Headphones', or 'External USB "
                            "Device'). Then test audio again."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _run_system_profiler(self) -> str:
        """Run system_profiler SPAudioDataType and return output."""
        try:
            result = subprocess.run(
                ["system_profiler", "SPAudioDataType"],
                capture_output=True,
                text=True,
            )
            return result.stdout
        except (OSError, subprocess.SubprocessError):
            return ""

    def _get_current_output_device(self) -> str | None:
        """Try to get current output device name."""
        try:
            # Try to get the default output device using defaults
            result = subprocess.run(
                ["defaults", "read", "-g", "com.apple.sound.default.output"],
                capture_output=True,
                text=True,
                errors="replace",
            )
            if result.returncode == 0 and result.stdout.strip():
                return result.stdout.strip()
        except (OSError, subprocess.SubprocessError):
            pass
        return None

    def _get_mute_status(self) -> bool | None:
        """Check if system audio is muted."""
        try:
            # macOS stores mute status via defaults
            result = subprocess.run(
                ["defaults", "read", "-g", "com.apple.sound.beep.muted"],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                value = result.stdout.strip()
                return value == "1"
        except (OSError, subprocess.SubprocessError):
            pass
        return None

    def _get_volume_level(self) -> int | None:
        """Try to get current system volume level (0-100)."""
        try:
            # Get system volume via osascript (most reliable on macOS)
            result = subprocess.run(
                [
                    "osascript",
                    "-e",
                    "output volume of (get volume settings)",
                ],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                volume_str = result.stdout.strip()
                if volume_str.isdigit():
                    return int(volume_str)
        except (OSError, subprocess.SubprocessError):
            pass
        return None


def _parse_audio_devices(output: str) -> list[dict]:
    """Parse system_profiler SPAudioDataType output to extract audio devices."""
    devices = []

    lines = output.split("\n")
    current_device = None

    for line in lines:
        line_rstrip = line.rstrip()

        # Look for device lines: indented once (4 spaces) with device name and colon
        if line.startswith("    ") and not line.startswith("        ") and ":" in line:
            device_name = line_rstrip.split(":")[0].strip()
            current_device = {
                "name": device_name,
                "type": "unknown",
                "connected": True,
            }
            devices.append(current_device)

        # Parse device details (double-indented)
        elif current_device and line.startswith("        "):
            if "Input Channels:" in line:
                current_device["type"] = "input"
            elif "Output Channels:" in line:
                current_device["type"] = "output"

    # If no devices found, try alternative parsing
    if not devices:
        devices = _fallback_parse_audio_devices(output)

    return devices


def _fallback_parse_audio_devices(output: str) -> list[dict]:
    """Fallback parser for audio devices using simpler patterns."""
    devices = []
    lines = output.split("\n")

    for line in lines:
        # Look for lines with device type indicators
        if any(
            marker in line
            for marker in [
                "Internal Microphone",
                "Internal Speakers",
                "HDMI",
                "USB",
                "Headphones",
                "Line In",
                "Optical",
                "AirPods",
            ]
        ):
            device_name = line.strip().split(":")[0].strip()
            if device_name:
                device_type = "input" if "Mic" in device_name else "output"
                devices.append(
                    {
                        "name": device_name,
                        "type": device_type,
                        "connected": True,
                    }
                )

    return devices


def _format_device_list(devices: list[dict]) -> str:
    """Format device list for display in findings."""
    if not devices:
        return "  (no devices detected)"

    lines = []
    inputs = [d for d in devices if d.get("type") == "input"]
    outputs = [d for d in devices if d.get("type") == "output"]
    other = [d for d in devices if d.get("type") not in ("input", "output")]

    if inputs:
        lines.append("  Input devices:")
        for dev in inputs:
            lines.append(f"    - {dev.get('name', 'Unknown')}")

    if outputs:
        lines.append("  Output devices:")
        for dev in outputs:
            lines.append(f"    - {dev.get('name', 'Unknown')}")

    if other:
        lines.append("  Other devices:")
        for dev in other:
            lines.append(f"    - {dev.get('name', 'Unknown')}")

    return "\n".join(lines)


def _is_likely_disconnected_device(current_device: str, available_devices: list[dict]) -> bool:
    """Check if current output device is not in the list of available devices."""
    device_names = [d.get("name", "").lower() for d in available_devices]
    return current_device.lower() not in device_names
