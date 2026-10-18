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
                    title="No audio devices were found on your Mac",
                    description=(
                        "Your Mac couldn't find any speakers or microphones. This usually "
                        "means a connection issue or a setting glitch.\n\n"
                        "What to do: Check that your headphones or speakers are plugged "
                        "in. If they are, restart your Mac and see if they appear again."
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
                    title="Your Mac's sound is turned off (muted)",
                    description=(
                        "Your Mac is currently muted, so you won't hear any audio.\n\n"
                        "What to do: Press the mute key on your keyboard (often F6 with "
                        "a speaker icon) or click the speaker icon in the menu bar to "
                        "unmute."
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
                    title="Your Mac's volume is set to zero",
                    description=(
                        "Your system volume is at 0%, so no sound will play.\n\n"
                        "What to do: Press the volume up key on your keyboard or drag "
                        "the volume slider in the menu bar to a higher level."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "volume_zero", "volume_percent": 0},
                )
            )
        elif volume_level is not None and volume_level < 10:
            findings.append(
                Finding(
                    title=f"Your Mac's volume is very low ({volume_level}%)",
                    description=(
                        f"Your system volume is set to {volume_level}%, which is very "
                        "quiet.\n\n"
                        "What to do: Press the volume up key on your keyboard or adjust "
                        "the slider in the menu bar to make the sound louder."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "volume_low", "volume_percent": volume_level},
                )
            )

        # Check for no input device (microphone issues)
        # Only when the device list was actually read: an empty or unreadable
        # list is "couldn't check", not "no microphone".
        input_devices = [
            d for d in devices if d.get("type") == "input" or d.get("has_input")
        ]
        if devices and not input_devices:
            findings.append(
                Finding(
                    title="No microphone was found on your Mac",
                    description=(
                        "Your Mac doesn't see a microphone, so it can't record your voice "
                        "for calls or apps.\n\n"
                        "What to do: Check that any external mic is plugged in. Then go "
                        "to System Settings > Privacy & Security > Microphone to ensure "
                        "apps are allowed to use it."
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
                        title=f"Sound is set to go to {current_output}",
                        description=(
                            f"Your Mac is trying to play sound through '{current_output}', "
                            "but that device doesn't seem to be connected right now.\n\n"
                            "What to do: Click the speaker icon in the menu bar and select "
                            "'Internal Speakers' or another device that is currently "
                            "connected."
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
                    title=f"Sound is going to {current_output}",
                    description=(
                        f"Your Mac is sending sound to '{current_output}'. If you don't "
                        "have that device connected, you might not hear anything.\n\n"
                        "What to do: Click the speaker icon in the menu bar and choose "
                        "'Internal Speakers' or your connected headphones from the list."
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
    """Parse system_profiler SPAudioDataType output to extract audio devices.

    A device is a heading line ("MacBook Pro Microphone:") followed by
    "Key: value" detail lines. Real output nests devices under "Devices:" at
    8 spaces with details at 10; the old parser assumed devices at exactly 4
    spaces, so on a real Mac it found one device called "Devices" and
    reported "No microphone was found" on a MacBook with a built-in mic.
    """
    devices = []
    current_device = None

    for line in output.split("\n"):
        stripped = line.strip()
        if not stripped:
            continue
        if stripped.endswith(":"):
            name = stripped[:-1].strip()
            if name == "Devices" or name.startswith("Audio"):
                current_device = None
                continue
            current_device = {
                "name": name,
                "type": "unknown",
                "connected": True,
                "has_input": False,
                "has_output": False,
            }
            devices.append(current_device)
        elif current_device is not None:
            if stripped.startswith("Input Channels:"):
                current_device["has_input"] = True
                current_device["type"] = "input"
            elif stripped.startswith("Output Channels:"):
                current_device["has_output"] = True
                if current_device["type"] == "unknown":
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
