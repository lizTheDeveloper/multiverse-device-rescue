import plistlib
import re
import subprocess
from pathlib import Path

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
    name = "coreaudio_reset"
    category = "integrity"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 44
    depends_on = []
    estimated_duration = "4s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Check if coreaudiod process is running
        coreaudiod_running = self._check_coreaudiod_running()
        if not coreaudiod_running:
            findings.append(
                Finding(
                    title="CoreAudio daemon (coreaudiod) is not running",
                    description=(
                        "The CoreAudio daemon process is not running. This means the audio subsystem "
                        "may have crashed. This is a critical issue that prevents audio from working."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "coreaudiod_not_running"},
                )
            )

        # Get audio devices from system_profiler
        profiler_output = self._run_system_profiler()
        devices = _parse_audio_devices(profiler_output)

        # Check if any audio output devices are detected
        output_devices = [d for d in devices if d.get("type") == "output"]
        if not output_devices:
            findings.append(
                Finding(
                    title="No audio output devices detected",
                    description=(
                        "The system could not detect any audio output devices. This may indicate "
                        "a CoreAudio configuration issue or missing audio drivers."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "no_output_devices"},
                )
            )

        # Check current output device
        current_output = self._get_current_output_device()
        if current_output and devices:
            if _is_likely_disconnected_device(current_output, devices):
                findings.append(
                    Finding(
                        title=f"Audio output routed to unexpected device: {current_output}",
                        description=(
                            f"Audio is routed to '{current_output}', which is not in the list of "
                            "connected devices. This might indicate CoreAudio has retained stale "
                            "device preferences after unplugging audio hardware."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={
                            "check": "unexpected_output_device",
                            "current_device": current_output,
                        },
                    )
                )

        # Check CoreAudio preferences file
        coreaudio_plist = self._check_coreaudio_plist()
        if coreaudio_plist:
            findings.append(
                Finding(
                    title="CoreAudio preferences found",
                    description=(
                        "CoreAudio preferences file exists at ~/Library/Preferences/com.apple.coreaudio.plist. "
                        "This file can be corrupted and cause audio issues."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "coreaudio_plist_exists", "plist_path": coreaudio_plist},
                )
            )

        # Check for multiple output devices (can cause confusion)
        if len(output_devices) > 2:
            findings.append(
                Finding(
                    title=f"Multiple audio output devices detected ({len(output_devices)})",
                    description=(
                        f"The system has {len(output_devices)} audio output devices connected. "
                        "Multiple devices can sometimes cause routing confusion. Verify that the "
                        "correct device is selected as the default output in System Settings > Sound."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "check": "multiple_output_devices",
                        "device_count": len(output_devices),
                        "devices": [d.get("name", "Unknown") for d in output_devices],
                    },
                )
            )

        # Log all available devices as INFO
        if devices:
            device_list = _format_device_list(devices)
            findings.append(
                Finding(
                    title=f"Audio devices detected ({len(devices)} total)",
                    description=f"Available audio devices:\n{device_list}",
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "check": "devices_info",
                        "device_count": len(devices),
                        "devices": devices,
                    },
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        for finding in findings.findings:
            check = finding.data.get("check")

            if check == "coreaudiod_not_running":
                actions.append(
                    Action(
                        title="Restart CoreAudio daemon",
                        description=(
                            "CoreAudio daemon has crashed or stopped. To restart it: (1) Open Terminal; "
                            "(2) Run: 'sudo launchctl stop com.apple.audio.audio_daemon_server && sudo launchctl start "
                            "com.apple.audio.audio_daemon_server'; (3) Or restart your Mac for a complete reset; "
                            "(4) If audio still doesn't work after restart, the audio subsystem may need deeper troubleshooting."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "no_output_devices":
                actions.append(
                    Action(
                        title="Troubleshoot missing audio output devices",
                        description=(
                            "No audio output devices detected. Try: (1) Check System Settings > Sound to verify "
                            "a device is listed; (2) Unplug and replug any USB audio devices; (3) Restart CoreAudio: "
                            "in Terminal, run 'sudo launchctl stop com.apple.audio.audio_daemon_server && sudo launchctl start "
                            "com.apple.audio.audio_daemon_server'; (4) If the issue persists, restart your Mac; "
                            "(5) As a last resort, reset CoreAudio preferences by backing up and removing "
                            "~/Library/Preferences/com.apple.coreaudio.plist, then restart."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "unexpected_output_device":
                device = finding.data.get("current_device", "unknown")
                actions.append(
                    Action(
                        title=f"Reset audio output device from '{device}'",
                        description=(
                            f"Audio is routed to '{device}', which is not connected. To fix: (1) Click "
                            "the volume icon in the menu bar; (2) Select a different device from 'Output Device'; "
                            "(3) Or open System Settings > Sound > Output and choose a connected device; "
                            "(4) If the issue persists, the CoreAudio preferences file may be corrupted — "
                            "back up and remove ~/Library/Preferences/com.apple.coreaudio.plist, then restart."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "coreaudio_plist_exists":
                plist_path = finding.data.get("plist_path")
                actions.append(
                    Action(
                        title="CoreAudio preferences available for reset",
                        description=(
                            f"CoreAudio preferences file found at {plist_path}. If audio issues persist "
                            "after other troubleshooting: (1) Backup the file: 'cp "
                            f"{plist_path} {plist_path}.backup'; (2) Remove it: 'rm {plist_path}'; "
                            "(3) Restart your Mac. macOS will regenerate the file with default settings. "
                            "This can resolve corruption-related audio problems."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "multiple_output_devices":
                device_count = finding.data.get("device_count", 0)
                actions.append(
                    Action(
                        title="Verify correct audio output device is selected",
                        description=(
                            f"You have {device_count} audio output devices connected. To ensure sound works: "
                            "(1) Click the volume icon in the menu bar and check which device is selected; "
                            "(2) Select the device where you want audio to play (e.g., 'Internal Speakers', "
                            "'Headphones', or an external USB device); (3) Test audio playback; (4) If audio "
                            "still doesn't work, check that cables are connected and the device is powered on."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "devices_info":
                actions.append(
                    Action(
                        title="Audio devices are available",
                        description=(
                            "Audio devices are properly detected by the system. This is informational. "
                            "If you're not hearing sound, check: (1) Is the correct output device selected? "
                            "(2) Is audio muted? (3) Is volume set to a reasonable level? (4) Check the "
                            "audio_config module for mute and volume diagnostics."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _check_coreaudiod_running(self) -> bool:
        """Check if coreaudiod process is running via pgrep."""
        try:
            result = subprocess.run(
                ["pgrep", "-x", "coreaudiod"],
                capture_output=True,
                text=True,
            )
            return result.returncode == 0
        except (OSError, subprocess.SubprocessError):
            return False

    def _run_system_profiler(self) -> str:
        """Run system_profiler SPAudioDataType and return output."""
        try:
            result = subprocess.run(
                ["system_profiler", "SPAudioDataType"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return result.stdout
        except (OSError, subprocess.SubprocessError, subprocess.TimeoutExpired):
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

    def _check_coreaudio_plist(self) -> str | None:
        """Check if CoreAudio preferences plist exists."""
        plist_path = Path.home() / "Library" / "Preferences" / "com.apple.coreaudio.plist"
        if plist_path.exists():
            return str(plist_path)
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
