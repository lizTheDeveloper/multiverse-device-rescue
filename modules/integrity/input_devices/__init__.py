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
    name = "input_devices"
    category = "integrity"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "10s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Collect keyboard settings
        keyboard_settings = self._get_keyboard_settings()
        self._report_keyboard_settings(keyboard_settings, findings)

        # Collect trackpad settings
        trackpad_settings = self._get_trackpad_settings()
        self._report_trackpad_settings(trackpad_settings, findings)

        # Collect mouse settings
        mouse_settings = self._get_mouse_settings()
        self._report_mouse_settings(mouse_settings, findings)

        # List connected input devices
        usb_devices = self._get_usb_input_devices()
        self._report_usb_devices(usb_devices, findings)

        # List Bluetooth input devices
        bluetooth_devices = self._get_bluetooth_devices()
        self._report_bluetooth_devices(bluetooth_devices, findings)

        # Check for unusual settings
        self._check_warning_conditions(keyboard_settings, mouse_settings, trackpad_settings, findings)

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        """Fix is informational only - suggests input device settings to consider."""
        actions = []

        for finding in findings.findings:
            check = finding.data.get("check")

            if check == "input_devices_info":
                actions.append(
                    Action(
                        title="Review input device settings",
                        description=(
                            "Current input device settings are displayed in the report above. "
                            "To modify keyboard, trackpad, or mouse settings, use "
                            "System Settings > Keyboard or System Settings > Trackpad."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "slow_keyboard_repeat":
                actions.append(
                    Action(
                        title="Consider adjusting keyboard repeat rate",
                        description=(
                            "Keyboard repeat rate is unusually slow. This might indicate an accidental change. "
                            "To adjust: System Settings > Keyboard > Key repeat rate. "
                            "The default fast setting is usually 2."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "fast_keyboard_repeat":
                actions.append(
                    Action(
                        title="Consider adjusting keyboard repeat rate",
                        description=(
                            "Keyboard repeat rate is unusually fast. This might indicate an accidental change. "
                            "To adjust: System Settings > Keyboard > Key repeat rate. "
                            "Valid values are typically 2 (fastest) to 120 (slowest in milliseconds)."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "minimum_tracking_speed":
                actions.append(
                    Action(
                        title="Consider adjusting tracking speed",
                        description=(
                            "Trackpad/mouse tracking speed is at minimum, which may cause sluggish cursor response. "
                            "To adjust: System Settings > Trackpad > Tracking speed (or System Settings > Mouse). "
                            "Default is usually in the middle of the range."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "usb_devices_info":
                actions.append(
                    Action(
                        title="Review connected USB input devices",
                        description=(
                            "Current USB input devices are listed in the report above. "
                            "These devices were detected via system_profiler. "
                            "If an expected device is missing, check the physical connection and restart if needed."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "bluetooth_devices_info":
                actions.append(
                    Action(
                        title="Review Bluetooth input devices",
                        description=(
                            "Current Bluetooth input devices are listed in the report above. "
                            "To reconnect a device: System Settings > Bluetooth. "
                            "If a device doesn't appear, try unpairing and re-pairing."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _get_keyboard_settings(self) -> dict:
        """Retrieve current keyboard settings."""
        settings = {}

        # KeyRepeat (in milliseconds, lower = faster)
        settings["key_repeat"] = self._get_defaults_int("-g", "KeyRepeat")

        # InitialKeyRepeat (delay before repeat starts, in milliseconds)
        settings["initial_key_repeat"] = self._get_defaults_int("-g", "InitialKeyRepeat")

        return settings

    def _get_trackpad_settings(self) -> dict:
        """Retrieve current trackpad settings."""
        settings = {}

        # Tap to click
        settings["tap_to_click"] = self._get_defaults_bool(
            "com.apple.driver.AppleBluetoothMultitouch.trackpad", "Clicking"
        )

        # Scroll direction (1 = natural, 0 = traditional)
        settings["scroll_direction"] = self._get_defaults_bool(
            "com.apple.swipescrolldirection", "com.apple.swipescrolldirection"
        )

        # Tracking speed
        settings["tracking_speed"] = self._get_defaults_int(
            "-g", "com.apple.trackpad.scaling"
        )

        return settings

    def _get_mouse_settings(self) -> dict:
        """Retrieve current mouse settings."""
        settings = {}

        # Mouse tracking speed / scaling
        settings["mouse_scaling"] = self._get_defaults_int(
            "-g", "com.apple.mouse.scaling"
        )

        return settings

    def _get_usb_input_devices(self) -> list[str]:
        """Get list of connected USB input devices (keyboards, mice, etc)."""
        devices = []
        try:
            result = subprocess.run(
                ["system_profiler", "SPUSBDataType"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                lines = result.stdout.split("\n")
                for i, line in enumerate(lines):
                    # Look for HID (Human Interface Device) entries
                    if "HID" in line or "Keyboard" in line or "Mouse" in line or "Trackpad" in line:
                        # Capture the device name and a bit of context
                        if i > 0:
                            prev_line = lines[i - 1].strip()
                            if prev_line and not prev_line.startswith("Locations"):
                                devices.append(prev_line)
                        devices.append(line.strip())
        except (OSError, subprocess.SubprocessError, subprocess.TimeoutExpired):
            pass

        return devices

    def _get_bluetooth_devices(self) -> list[str]:
        """Get list of connected Bluetooth input devices."""
        devices = []
        try:
            result = subprocess.run(
                ["system_profiler", "SPBluetoothDataType"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                lines = result.stdout.split("\n")
                in_devices = False
                for line in lines:
                    stripped = line.strip()
                    # Look for paired devices section
                    if "Paired" in stripped or "Address" in stripped or "Device" in stripped:
                        in_devices = True
                    if in_devices and stripped and not stripped.startswith("_"):
                        devices.append(stripped)
        except (OSError, subprocess.SubprocessError, subprocess.TimeoutExpired):
            pass

        return devices

    def _get_defaults_bool(self, domain: str, key: str) -> bool:
        """Get a boolean setting from defaults, return False if not set or error."""
        try:
            if domain == "-g":
                result = subprocess.run(
                    ["defaults", "read", "-g", key],
                    capture_output=True,
                    text=True,
                )
            else:
                result = subprocess.run(
                    ["defaults", "read", domain, key],
                    capture_output=True,
                    text=True,
                )

            if result.returncode == 0:
                output = result.stdout.strip()
                return output == "1"
            return False
        except (OSError, subprocess.SubprocessError):
            return False

    def _get_defaults_int(self, domain: str, key: str) -> int | None:
        """Get an integer setting from defaults, return None if not set or error."""
        try:
            if domain == "-g":
                result = subprocess.run(
                    ["defaults", "read", "-g", key],
                    capture_output=True,
                    text=True,
                )
            else:
                result = subprocess.run(
                    ["defaults", "read", domain, key],
                    capture_output=True,
                    text=True,
                )

            if result.returncode == 0:
                return int(result.stdout.strip())
            return None
        except (OSError, subprocess.SubprocessError, ValueError):
            return None

    def _report_keyboard_settings(self, settings: dict, findings: list[Finding]) -> None:
        """Report current keyboard settings as INFO finding."""
        report_lines = []

        if settings.get("key_repeat") is not None:
            report_lines.append(f"- Key Repeat Rate: {settings['key_repeat']}ms")
        else:
            report_lines.append("- Key Repeat Rate: not set (default)")

        if settings.get("initial_key_repeat") is not None:
            report_lines.append(f"- Initial Key Repeat Delay: {settings['initial_key_repeat']}ms")
        else:
            report_lines.append("- Initial Key Repeat Delay: not set (default)")

        description = "Current keyboard settings:\n" + "\n".join(report_lines)

        findings.append(
            Finding(
                title="Keyboard settings summary",
                description=description,
                severity=Severity.INFO,
                category=self.category,
                data={"check": "input_devices_info", "settings": settings},
            )
        )

    def _report_trackpad_settings(self, settings: dict, findings: list[Finding]) -> None:
        """Report current trackpad settings as INFO finding."""
        report_lines = []

        if settings.get("tap_to_click"):
            report_lines.append("- Tap to Click: ENABLED")
        else:
            report_lines.append("- Tap to Click: disabled")

        if settings.get("scroll_direction"):
            report_lines.append("- Scroll Direction: natural (standard)")
        else:
            report_lines.append("- Scroll Direction: traditional (reversed)")

        if settings.get("tracking_speed") is not None:
            report_lines.append(f"- Tracking Speed: {settings['tracking_speed']}")
        else:
            report_lines.append("- Tracking Speed: not set (default)")

        description = "Current trackpad settings:\n" + "\n".join(report_lines)

        findings.append(
            Finding(
                title="Trackpad settings summary",
                description=description,
                severity=Severity.INFO,
                category=self.category,
                data={"check": "input_devices_info", "settings": settings},
            )
        )

    def _report_mouse_settings(self, settings: dict, findings: list[Finding]) -> None:
        """Report current mouse settings as INFO finding."""
        report_lines = []

        if settings.get("mouse_scaling") is not None:
            report_lines.append(f"- Mouse Tracking Speed: {settings['mouse_scaling']}")
        else:
            report_lines.append("- Mouse Tracking Speed: not set (default)")

        description = "Current mouse settings:\n" + "\n".join(report_lines)

        findings.append(
            Finding(
                title="Mouse settings summary",
                description=description,
                severity=Severity.INFO,
                category=self.category,
                data={"check": "input_devices_info", "settings": settings},
            )
        )

    def _report_usb_devices(self, devices: list[str], findings: list[Finding]) -> None:
        """Report connected USB input devices."""
        if devices:
            device_list = "\n".join(f"  {d}" for d in devices[:10])  # Limit to first 10
            if len(devices) > 10:
                device_list += f"\n  ... and {len(devices) - 10} more devices"
            description = f"Connected USB input devices ({len(devices)} total):\n{device_list}"
        else:
            description = "No USB input devices detected via system_profiler."

        findings.append(
            Finding(
                title="USB input devices",
                description=description,
                severity=Severity.INFO,
                category=self.category,
                data={"check": "usb_devices_info", "devices": devices},
            )
        )

    def _report_bluetooth_devices(self, devices: list[str], findings: list[Finding]) -> None:
        """Report connected Bluetooth input devices."""
        if devices:
            device_list = "\n".join(f"  {d}" for d in devices[:10])  # Limit to first 10
            if len(devices) > 10:
                device_list += f"\n  ... and {len(devices) - 10} more devices"
            description = f"Bluetooth input devices ({len(devices)} total):\n{device_list}"
        else:
            description = "No Bluetooth input devices detected or no paired devices."

        findings.append(
            Finding(
                title="Bluetooth input devices",
                description=description,
                severity=Severity.INFO,
                category=self.category,
                data={"check": "bluetooth_devices_info", "devices": devices},
            )
        )

    def _check_warning_conditions(
        self,
        keyboard_settings: dict,
        mouse_settings: dict,
        trackpad_settings: dict,
        findings: list[Finding],
    ) -> None:
        """Check for unusual settings that should trigger warnings."""
        # Check keyboard repeat rate - flag if extremely slow (>60) or extremely fast (<2)
        key_repeat = keyboard_settings.get("key_repeat")
        if key_repeat is not None:
            if key_repeat > 60:
                findings.append(
                    Finding(
                        title="Keyboard repeat rate is very slow",
                        description=(
                            f"Keyboard repeat rate is set to {key_repeat}ms, which is slower than typical. "
                            "This might be an accidental change. Normal fast setting is 2ms."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={"check": "slow_keyboard_repeat", "value": key_repeat},
                    )
                )
            elif key_repeat < 2:
                findings.append(
                    Finding(
                        title="Keyboard repeat rate is very fast",
                        description=(
                            f"Keyboard repeat rate is set to {key_repeat}ms. "
                            "This is faster than the standard fastest setting of 2ms, "
                            "which may cause unintended key repeats."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={"check": "fast_keyboard_repeat", "value": key_repeat},
                    )
                )

        # Check mouse tracking speed - flag if at minimum (very slow)
        mouse_scaling = mouse_settings.get("mouse_scaling")
        if mouse_scaling is not None and mouse_scaling <= 0:
            findings.append(
                Finding(
                    title="Mouse tracking speed at minimum",
                    description=(
                        f"Mouse tracking speed is set to {mouse_scaling}, which is the minimum. "
                        "This causes very slow cursor movement and may be an accidental change."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "minimum_tracking_speed", "value": mouse_scaling},
                )
            )

        # Check trackpad tracking speed - flag if at minimum
        trackpad_speed = trackpad_settings.get("tracking_speed")
        if trackpad_speed is not None and trackpad_speed <= 0:
            findings.append(
                Finding(
                    title="Trackpad tracking speed at minimum",
                    description=(
                        f"Trackpad tracking speed is set to {trackpad_speed}, which is the minimum. "
                        "This causes very slow cursor movement and may be an accidental change."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "minimum_tracking_speed", "value": trackpad_speed},
                )
            )
