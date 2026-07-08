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
    name = "bluetooth_diagnostics"
    category = "integrity"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "5s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Get Bluetooth info from system_profiler
        system_profiler_output = self._run_system_profiler()
        if not system_profiler_output:
            findings.append(
                Finding(
                    title="Unable to retrieve Bluetooth information",
                    description=(
                        "Could not run system_profiler SPBluetoothDataType. "
                        "Bluetooth diagnostics are unavailable."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "profiler_error"},
                )
            )
            return CheckResult(module_name=self.name, findings=findings)

        bt_info = _parse_system_profiler(system_profiler_output)

        # Check if Bluetooth is powered on
        if not bt_info.get("powered_on", True):
            if bt_info.get("paired_devices", []):
                findings.append(
                    Finding(
                        title="Bluetooth is off with paired devices",
                        description=(
                            "Bluetooth is currently powered off, but you have "
                            f"{len(bt_info['paired_devices'])} paired device(s). "
                            "Re-enable Bluetooth in System Settings to use these devices."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={
                            "check": "bluetooth_off_with_devices",
                            "paired_count": len(bt_info["paired_devices"]),
                        },
                    )
                )
            else:
                findings.append(
                    Finding(
                        title="Bluetooth is off",
                        description=(
                            "Bluetooth is currently powered off. "
                            "Enable it in System Settings if needed."
                        ),
                        severity=Severity.INFO,
                        category=self.category,
                        data={"check": "bluetooth_off"},
                    )
                )

        # Check paired device count
        paired_count = len(bt_info.get("paired_devices", []))
        if paired_count > 15:
            findings.append(
                Finding(
                    title=f"High number of paired devices ({paired_count})",
                    description=(
                        f"You have {paired_count} paired Bluetooth devices. "
                        "Having more than 15 paired devices can cause connection issues "
                        "and performance degradation. Consider removing unused devices."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "check": "too_many_paired_devices",
                        "paired_count": paired_count,
                    },
                )
            )

        # Check for low battery and stale devices
        if bt_info.get("paired_devices"):
            low_battery_devices = []
            stale_devices = []

            for device in bt_info["paired_devices"]:
                # Check for low battery
                battery = device.get("battery")
                if battery is not None and battery < 20:
                    low_battery_devices.append((device["name"], battery))

                # Check for devices that are never connected
                if not device.get("connected") and device.get("last_connected") is None:
                    stale_devices.append(device["name"])

            # Add findings for low battery devices
            for device_name, battery_level in low_battery_devices:
                findings.append(
                    Finding(
                        title=f"Low battery: {device_name} ({battery_level}%)",
                        description=(
                            f"The Bluetooth device '{device_name}' has a battery level "
                            f"of {battery_level}%. Consider charging or replacing the battery soon."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={
                            "check": "low_battery",
                            "device_name": device_name,
                            "battery_level": battery_level,
                        },
                    )
                )

            # Add finding for stale paired devices
            if stale_devices:
                findings.append(
                    Finding(
                        title=f"Stale paired devices ({len(stale_devices)})",
                        description=(
                            f"You have {len(stale_devices)} device(s) that are paired but "
                            "have never been connected or have not been used recently: "
                            f"{', '.join(stale_devices)}. "
                            "These can be safely removed to improve connection stability."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={
                            "check": "stale_devices",
                            "stale_count": len(stale_devices),
                            "devices": stale_devices,
                        },
                    )
                )

        # Add INFO finding listing all paired devices with status
        if bt_info.get("paired_devices"):
            device_summaries = []
            for device in bt_info["paired_devices"]:
                status = "Connected" if device.get("connected") else "Paired"
                battery_str = ""
                if device.get("battery") is not None:
                    battery_str = f" (Battery: {device['battery']}%)"
                device_summaries.append(f"  - {device['name']}: {status}{battery_str}")

            findings.append(
                Finding(
                    title=f"Paired Bluetooth devices ({paired_count})",
                    description=(
                        f"Current Bluetooth status:\n" + "\n".join(device_summaries)
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "check": "paired_devices_list",
                        "devices": bt_info["paired_devices"],
                    },
                )
            )

        # Add INFO finding for Bluetooth firmware version if available
        if bt_info.get("firmware_version"):
            findings.append(
                Finding(
                    title=f"Bluetooth firmware: {bt_info['firmware_version']}",
                    description=(
                        f"Bluetooth controller firmware version: {bt_info['firmware_version']}"
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "check": "firmware_version",
                        "version": bt_info["firmware_version"],
                    },
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        for finding in findings.findings:
            check = finding.data.get("check")

            if check == "profiler_error":
                actions.append(
                    Action(
                        title="Bluetooth diagnostics unavailable",
                        description=(
                            "Unable to retrieve Bluetooth information. "
                            "Try restarting your Mac or checking System Preferences."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "bluetooth_off_with_devices":
                actions.append(
                    Action(
                        title="Enable Bluetooth",
                        description=(
                            "To use your paired Bluetooth devices, enable Bluetooth in "
                            "System Settings > Bluetooth. Click the Bluetooth menu and "
                            "select 'Turn On Bluetooth'."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "bluetooth_off":
                actions.append(
                    Action(
                        title="Bluetooth is off",
                        description=(
                            "Bluetooth is currently disabled. "
                            "You can enable it in System Settings > Bluetooth if needed."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "too_many_paired_devices":
                count = finding.data.get("paired_count", 0)
                actions.append(
                    Action(
                        title="Remove unused Bluetooth devices",
                        description=(
                            f"You have {count} paired devices, which exceeds the "
                            "recommended limit of 15. To remove a device: "
                            "1. Go to System Settings > Bluetooth\n"
                            "2. Find the device you want to remove\n"
                            "3. Click the gear icon and select 'Remove'"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "low_battery":
                device_name = finding.data.get("device_name")
                actions.append(
                    Action(
                        title=f"Charge {device_name}",
                        description=(
                            f"The battery of '{device_name}' is low. "
                            "Please charge the device to restore functionality."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "stale_devices":
                devices = finding.data.get("devices", [])
                devices_str = ", ".join(devices)
                actions.append(
                    Action(
                        title=f"Remove stale devices: {devices_str}",
                        description=(
                            f"These devices are paired but unused: {devices_str}. "
                            "To remove them: "
                            "1. Go to System Settings > Bluetooth\n"
                            "2. Find each device in the list\n"
                            "3. Click the gear icon and select 'Remove'\n"
                            "This will improve Bluetooth connection stability."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "paired_devices_list":
                actions.append(
                    Action(
                        title="Paired devices overview",
                        description=(
                            "This is an informational summary of your paired Bluetooth "
                            "devices. All listed devices are available for use."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "firmware_version":
                actions.append(
                    Action(
                        title="Bluetooth firmware information",
                        description=(
                            "This is your Bluetooth controller's firmware version. "
                            "It is informational only."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _run_system_profiler(self) -> str:
        """Run system_profiler SPBluetoothDataType and return output."""
        try:
            result = subprocess.run(
                ["system_profiler", "SPBluetoothDataType"],
                capture_output=True,
                text=True,
            )
            return result.stdout
        except (OSError, subprocess.SubprocessError):
            return ""


def _parse_system_profiler(output: str) -> dict:
    """Parse system_profiler SPBluetoothDataType output."""
    info = {
        "powered_on": True,  # Default to True, disable if we see "State: Off"
        "paired_devices": [],
        "firmware_version": None,
    }

    # Check if Bluetooth is powered on
    if "State: Off" in output:
        info["powered_on"] = False

    # Try to extract firmware version
    firmware_match = re.search(r"Firmware Version:\s*(.+?)(?:\n|$)", output)
    if firmware_match:
        info["firmware_version"] = firmware_match.group(1).strip()

    # Parse paired devices
    # Look for device sections like:
    # Device:
    #     Name: AirPods Pro
    #     Address: AA:BB:CC:DD:EE:FF
    #     Connected: Yes
    #     Battery Level: 85%

    # Split by "Device:" to find individual device blocks
    device_blocks = output.split("Device:")

    for block in device_blocks[1:]:  # Skip the first empty split
        device = {}

        # Extract name
        name_match = re.search(r"Name:\s*(.+?)(?:\n|$)", block)
        if name_match:
            device["name"] = name_match.group(1).strip()
        else:
            continue  # Skip if we can't find a name

        # Extract connected status
        if "Connected: Yes" in block:
            device["connected"] = True
        else:
            device["connected"] = False

        # Extract battery level
        battery_match = re.search(r"Battery Level:\s*(\d+)%", block)
        if battery_match:
            device["battery"] = int(battery_match.group(1))
        else:
            device["battery"] = None

        # Extract last connected time
        last_connected_match = re.search(
            r"Last Connected:\s*(.+?)(?:\n|$)", block
        )
        if last_connected_match:
            device["last_connected"] = last_connected_match.group(1).strip()
        else:
            device["last_connected"] = None

        info["paired_devices"].append(device)

    return info
