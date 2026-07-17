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
    name = "audio_troubleshoot"
    category = "integrity"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 48
    depends_on = []
    estimated_duration = "4s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Get audio devices from system_profiler
        profiler_output = self._run_system_profiler()
        devices = _parse_audio_devices(profiler_output)

        if not devices:
            findings.append(
                Finding(
                    title="No audio devices detected",
                    description=(
                        "Unable to detect any audio input or output devices. "
                        "This may indicate a CoreAudio configuration issue or device driver problem."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "no_devices"},
                )
            )
            return CheckResult(module_name=self.name, findings=findings)

        # Get current output and input devices
        current_output = self._get_current_output_device()
        current_input = self._get_current_input_device()
        mute_status = self._get_mute_status()
        volume_level = self._get_volume_level()

        # Log all devices and current selections as INFO
        device_summary = _format_device_summary(
            devices, current_output, current_input, volume_level, mute_status
        )
        findings.append(
            Finding(
                title=f"Audio devices and status ({len(devices)} device(s))",
                description=device_summary,
                severity=Severity.INFO,
                category=self.category,
                data={
                    "check": "audio_devices_info",
                    "device_count": len(devices),
                    "devices": devices,
                    "current_output": current_output,
                    "current_input": current_input,
                    "volume": volume_level,
                    "muted": mute_status,
                },
            )
        )

        # Check for muted output (very common user issue)
        if mute_status is not None and mute_status:
            findings.append(
                Finding(
                    title="System audio is muted",
                    description=(
                        "The system audio output is muted. This is one of the most common reasons "
                        "why users don't hear sound. Unmute using the mute key or System Settings."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "audio_muted"},
                )
            )

        # Check for very low volume
        if volume_level is not None and volume_level <= 0:
            findings.append(
                Finding(
                    title="System volume is at 0%",
                    description=(
                        "System audio volume is set to 0%. Increase volume to hear any sound."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "volume_zero", "volume_percent": 0},
                )
            )
        elif volume_level is not None and volume_level < 10:
            findings.append(
                Finding(
                    title=f"System volume is very low ({volume_level}%)",
                    description=(
                        f"System audio volume is set to {volume_level}%, which is barely audible. "
                        "Consider increasing volume to at least 20-30%."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "volume_low", "volume_percent": volume_level},
                )
            )

        # Check for no input device (microphone issues)
        input_devices = [d for d in devices if d.get("type") == "input"]
        if not input_devices:
            findings.append(
                Finding(
                    title="No audio input device detected",
                    description=(
                        "No microphone or audio input device was detected. This may affect "
                        "video calls, voice recording, and voice commands. Check if microphone "
                        "is connected, enabled, and recognized in System Settings."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "no_input_device"},
                )
            )

        # Check if output is routed to a device that may not be connected
        if current_output:
            if _is_device_not_connected(current_output, devices):
                findings.append(
                    Finding(
                        title=f"Audio output routed to potentially disconnected device: {current_output}",
                        description=(
                            f"System audio is set to output through '{current_output}', but this device "
                            "does not appear in the list of connected devices. Try switching to Internal Speakers "
                            "or another available device in System Settings > Sound > Output tab."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={
                            "check": "output_device_disconnected",
                            "current_device": current_output,
                        },
                    )
                )

        # Check for unexpected routing (e.g., HDMI when not expected)
        if current_output and _is_unexpected_device(current_output):
            findings.append(
                Finding(
                    title=f"Audio output may be routed to unexpected device: {current_output}",
                    description=(
                        f"Audio is currently set to output through '{current_output}'. "
                        "If you don't have this device connected or selected, switch to Internal Speakers "
                        "or Headphones in System Settings > Sound > Output."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "check": "unexpected_output_device",
                        "current_device": current_output,
                    },
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        for finding in findings.findings:
            check = finding.data.get("check")

            if check == "no_devices":
                actions.append(
                    Action(
                        title="Troubleshoot missing audio devices",
                        description=(
                            "No audio devices were detected. Try the following:\n"
                            "1. Check System Settings > Sound to verify a device is selected\n"
                            "2. If connected external speakers/headphones, unplug and replug to rescan\n"
                            "3. Restart CoreAudio: 'sudo launchctl stop com.apple.audio.system.sound_presentation_assistant "
                            "&& sudo launchctl start com.apple.audio.system.sound_presentation_assistant'\n"
                            "4. If the issue persists, restart your Mac\n"
                            "5. As a last resort, reset SMC: On Apple Silicon, hold power button for 10 seconds"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "audio_devices_info":
                actions.append(
                    Action(
                        title="Audio devices detected and information listed",
                        description=(
                            "Your audio devices are properly detected. See the device listing above to verify "
                            "your speakers or microphones are connected and enabled. If you don't see a device "
                            "you expect, reconnect it and check System Settings > Sound."
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
                            "Your system audio is currently muted. To unmute:\n"
                            "1. Press the mute key (F10 or equivalent) on your keyboard\n"
                            "2. Or open System Settings > Sound and toggle the mute switch off\n"
                            "3. Increase volume with the volume up key (F12) or in System Settings\n"
                            "After unmuting, test a video or audio file to confirm sound is working."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "volume_zero":
                actions.append(
                    Action(
                        title="Increase system volume from 0%",
                        description=(
                            "Your system volume is at 0%. To hear any sound:\n"
                            "1. Press the volume up key (F12) several times\n"
                            "2. Or click the volume icon in the menu bar and drag right\n"
                            "3. Or open System Settings > Sound and move the volume slider to 50-70%\n"
                            "Test with audio or video to confirm sound is working."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "volume_low":
                volume = finding.data.get("volume_percent", 5)
                actions.append(
                    Action(
                        title=f"Increase system volume from {volume}%",
                        description=(
                            f"Your system volume is very low at {volume}%. To increase:\n"
                            "1. Press the volume up key (F12) multiple times\n"
                            "2. Or click the volume icon in the menu bar and drag right\n"
                            "3. Or open System Settings > Sound and move the volume slider to 50-70%\n"
                            "Try incrementally raising volume and test with audio/video."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "no_input_device":
                actions.append(
                    Action(
                        title="Enable or connect microphone",
                        description=(
                            "No audio input device (microphone) was detected. To fix:\n"
                            "1. If you have an external microphone, connect it via USB or 3.5mm jack\n"
                            "2. Open System Settings > Sound > Input tab\n"
                            "3. Verify the internal microphone is available and not disabled\n"
                            "4. If still missing, restart your Mac and check again\n"
                            "5. If using USB microphone, unplug and replug to rescan\n"
                            "This affects Zoom, Teams, FaceTime, and voice recording."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "output_device_disconnected":
                device = finding.data.get("current_device", "unknown")
                actions.append(
                    Action(
                        title=f"Switch from disconnected device: {device}",
                        description=(
                            f"Audio output is set to '{device}', which is not detected. To fix:\n"
                            "1. Open System Settings > Sound > Output tab\n"
                            "2. Select 'Internal Speakers' or a connected device (Headphones, USB, HDMI, etc.)\n"
                            "3. If you need to use the original device, reconnect it or restart your Mac\n"
                            "After switching, test audio to confirm it's working."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "unexpected_output_device":
                device = finding.data.get("current_device", "unknown")
                actions.append(
                    Action(
                        title=f"Review audio output routing: {device}",
                        description=(
                            f"Audio is set to output through '{device}'. If this is not your intended device:\n"
                            "1. Open System Settings > Sound > Output tab\n"
                            "2. Select your preferred device (Internal Speakers, Headphones, etc.)\n"
                            "3. You can also click the volume icon in the menu bar to quickly change the output device\n"
                            "Test audio again after making the change."
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

    def _get_current_input_device(self) -> str | None:
        """Try to get current input device name."""
        try:
            result = subprocess.run(
                ["defaults", "read", "-g", "com.apple.sound.default.input"],
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


def _format_device_summary(
    devices: list[dict],
    current_output: str | None,
    current_input: str | None,
    volume: int | None,
    muted: bool | None,
) -> str:
    """Format device and status information for display."""
    lines = []

    # Device listing
    if devices:
        inputs = [d for d in devices if d.get("type") == "input"]
        outputs = [d for d in devices if d.get("type") == "output"]
        other = [d for d in devices if d.get("type") not in ("input", "output")]

        if inputs:
            lines.append("Input devices:")
            for dev in inputs:
                lines.append(f"  - {dev.get('name', 'Unknown')}")

        if outputs:
            lines.append("Output devices:")
            for dev in outputs:
                lines.append(f"  - {dev.get('name', 'Unknown')}")

        if other:
            lines.append("Other devices:")
            for dev in other:
                lines.append(f"  - {dev.get('name', 'Unknown')}")
    else:
        lines.append("(no devices detected)")

    # Current selections
    lines.append("")
    if current_output:
        lines.append(f"Current output: {current_output}")
    else:
        lines.append("Current output: (not determined)")

    if current_input:
        lines.append(f"Current input: {current_input}")
    else:
        lines.append("Current input: (not determined)")

    # Volume status
    if volume is not None:
        mute_str = " (MUTED)" if muted else ""
        lines.append(f"Volume: {volume}%{mute_str}")
    else:
        lines.append("Volume: (not determined)")

    return "\n".join(lines)


def _is_device_not_connected(current_device: str, available_devices: list[dict]) -> bool:
    """Check if current output device is not in the list of available devices."""
    device_names = [d.get("name", "").lower() for d in available_devices]
    return current_device.lower() not in device_names


def _is_unexpected_device(device_name: str) -> bool:
    """Check if device name suggests it might be unexpected (HDMI, DisplayPort, etc.)."""
    unexpected_keywords = ["hdmi", "displayport", "dp", "thunderbolt", "usb audio"]
    return any(keyword in device_name.lower() for keyword in unexpected_keywords)
