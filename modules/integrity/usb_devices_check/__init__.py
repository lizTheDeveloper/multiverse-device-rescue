import re
import subprocess
from typing import Optional

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
    name = "usb_devices_check"
    category = "integrity"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "3s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Get USB info from system_profiler
        system_profiler_output = self._run_system_profiler()
        if not system_profiler_output:
            findings.append(
                Finding(
                    title="Could not retrieve USB device information",
                    description=(
                        "Failed to run system_profiler SPUSBDataType. "
                        "USB device diagnostics are unavailable."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "profiler_error"},
                )
            )
            return CheckResult(module_name=self.name, findings=findings)

        devices = _parse_usb_devices(system_profiler_output)

        if not devices:
            findings.append(
                Finding(
                    title="No USB devices detected",
                    description=(
                        "No USB devices are currently connected to this Mac."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "no_devices"},
                )
            )
            return CheckResult(module_name=self.name, findings=findings)

        # List all connected devices
        device_list = _format_device_list(devices)
        findings.append(
            Finding(
                title=f"Connected USB devices ({len(devices)})",
                description=device_list,
                severity=Severity.INFO,
                category=self.category,
                data={"check": "device_list", "device_count": len(devices)},
            )
        )

        # Check for devices in error state or not recognized
        for device in devices:
            if device.get("error_state"):
                findings.append(
                    Finding(
                        title=f"USB device not recognized: {device.get('product', 'Unknown')}",
                        description=(
                            f"Device '{device.get('product', 'Unknown')}' is in an error state "
                            "and not recognized by the system. Try: "
                            "(1) Disconnect and reconnect the device, "
                            "(2) Try a different USB port, "
                            "(3) Try a different Mac to isolate the issue."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={
                            "check": "device_error",
                            "product": device.get("product"),
                            "location": device.get("location"),
                        },
                    )
                )

        # Check for USB hubs with too many devices
        hubs_by_location = {}
        for device in devices:
            if device.get("is_hub"):
                hub_id = device.get("location", "unknown")
                if hub_id not in hubs_by_location:
                    hubs_by_location[hub_id] = {
                        "hub": device,
                        "device_count": 0,
                        "children": [],
                    }

        # Count devices attached to each hub using parent_location
        for device in devices:
            parent_loc = device.get("parent_location")
            if parent_loc and parent_loc in hubs_by_location:
                hubs_by_location[parent_loc]["device_count"] += 1
                hubs_by_location[parent_loc]["children"].append(device)

        for hub_id, hub_info in hubs_by_location.items():
            device_count = hub_info["device_count"]
            if device_count > 4:
                hub_name = hub_info["hub"].get("product", "USB Hub")
                device_list_str = ", ".join(
                    d.get("product", "Unknown") for d in hub_info["children"]
                )
                findings.append(
                    Finding(
                        title=f"USB hub overloaded: {hub_name} ({device_count} devices)",
                        description=(
                            f"'{hub_name}' has {device_count} devices connected, "
                            "exceeding the recommended limit of 4. This may cause power "
                            "brownout, dropped connections, or device failures. "
                            "Devices connected: {device_list_str}. "
                            "Try: (1) Use a powered USB hub instead, "
                            "(2) Distribute devices across multiple hubs, "
                            "(3) Prioritize which devices must stay connected."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={
                            "check": "hub_overload",
                            "hub_name": hub_name,
                            "device_count": device_count,
                            "location": hub_id,
                        },
                    )
                )

        # Check for USB 2.0 devices that could benefit from USB 3.0
        # USB 2.0 devices have "480 Mb/s" or "High-Speed" in their speed spec
        # but don't have "5 Gb/s" or "10 Gb/s" (USB 3.x)
        usb2_devices = [
            d
            for d in devices
            if (
                ("480 Mb/s" in d.get("speed", "") or "High-Speed" in d.get("speed", ""))
                and "5 Gb/s" not in d.get("speed", "")
                and "10 Gb/s" not in d.get("speed", "")
                and not d.get("is_hub")
            )
        ]
        if usb2_devices:
            usb2_list = ", ".join(d.get("product", "Unknown") for d in usb2_devices)
            findings.append(
                Finding(
                    title=f"USB 2.0 devices detected ({len(usb2_devices)})",
                    description=(
                        f"The following USB 2.0 devices are connected: {usb2_list}. "
                        "If these are high-bandwidth devices (external drives, video capture), "
                        "consider replacing with USB 3.0/3.1 versions for faster speeds."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "check": "usb2_devices",
                        "count": len(usb2_devices),
                        "devices": usb2_list,
                    },
                )
            )

        # Check for devices drawing excessive bus power
        high_power_devices = [
            d for d in devices if d.get("power_required", 0) > 400
        ]
        if high_power_devices:
            for device in high_power_devices:
                findings.append(
                    Finding(
                        title=(
                            f"High-power USB device: {device.get('product', 'Unknown')} "
                            f"({device.get('power_required')}mA)"
                        ),
                        description=(
                            f"'{device.get('product', 'Unknown')}' requires "
                            f"{device.get('power_required')}mA of bus power. "
                            "Connecting multiple high-power devices may exceed available "
                            "power on unpowered hubs. If the device disconnects, try: "
                            "(1) Use a powered USB hub, "
                            "(2) Connect to a direct USB port on the Mac, "
                            "(3) Disconnect other high-power devices."
                        ),
                        severity=Severity.INFO,
                        category=self.category,
                        data={
                            "check": "high_power_device",
                            "product": device.get("product"),
                            "power_required": device.get("power_required"),
                            "location": device.get("location"),
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
                        title="No USB devices connected",
                        description=(
                            "No USB devices are currently connected. "
                            "If you expect to see USB devices, check your connections "
                            "and try plugging in the device again."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "device_error":
                product = finding.data.get("product", "Unknown Device")
                actions.append(
                    Action(
                        title=f"Troubleshoot unrecognized device: {product}",
                        description=(
                            f"Device '{product}' is not recognized by macOS. "
                            "Try these steps in order:\n"
                            "1. Disconnect the device\n"
                            "2. Reconnect to a different USB port\n"
                            "3. Restart your Mac\n"
                            "4. If it's a hub, try connecting a device directly to the Mac\n"
                            "5. Check the manufacturer's website for macOS drivers\n"
                            "6. If still not recognized, the device may have a hardware issue"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "hub_overload":
                hub_name = finding.data.get("hub_name", "Unknown Hub")
                device_count = finding.data.get("device_count", 0)
                actions.append(
                    Action(
                        title=f"Resolve USB hub overload: {hub_name} ({device_count} devices)",
                        description=(
                            f"The hub '{hub_name}' has {device_count} devices connected. "
                            "To resolve power and stability issues:\n"
                            "1. Use a powered USB hub (5V, 2A minimum)\n"
                            "2. Disconnect non-essential devices\n"
                            "3. Prioritize power-hungry devices (external drives) to powered hubs\n"
                            "4. Distribute devices across multiple ports on your Mac\n"
                            "5. Test stability after reducing the number of devices"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "device_list":
                count = finding.data.get("device_count", 0)
                actions.append(
                    Action(
                        title=f"Connected USB devices: {count} detected",
                        description=(
                            f"System has {count} USB device(s) connected. "
                            "Review the list above to ensure all devices are recognized "
                            "and functioning properly. If any device is misbehaving, "
                            "try disconnecting and reconnecting it."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "usb2_devices":
                count = finding.data.get("count", 0)
                actions.append(
                    Action(
                        title=f"USB 2.0 devices in use ({count} detected)",
                        description=(
                            f"You have {count} USB 2.0 device(s). "
                            "These are backward compatible but significantly slower than USB 3.0+. "
                            "If you regularly transfer large files, consider upgrading to "
                            "USB 3.0 or 3.1 versions for 10-40x faster speeds."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "high_power_device":
                product = finding.data.get("product", "Unknown")
                power = finding.data.get("power_required", 0)
                actions.append(
                    Action(
                        title=f"High-power device guidance: {product} ({power}mA)",
                        description=(
                            f"The device '{product}' draws {power}mA of power. "
                            "If it frequently disconnects or isn't recognized:\n"
                            "1. Use a powered USB hub instead of bus power\n"
                            "2. Connect directly to your Mac's USB port (not through a hub)\n"
                            "3. Check if the device needs external power (check manual)\n"
                            "4. Try a different USB cable if available"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "profiler_error":
                actions.append(
                    Action(
                        title="USB diagnostics unavailable",
                        description=(
                            "Could not retrieve USB information from system_profiler. "
                            "This is typically a temporary issue. Restart your Mac or try again. "
                            "If the problem persists, your USB subsystem may need service."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _run_system_profiler(self) -> str:
        """Run system_profiler SPUSBDataType and return output."""
        try:
            result = subprocess.run(
                ["system_profiler", "SPUSBDataType"],
                capture_output=True,
                text=True,
            )
            return result.stdout
        except (OSError, subprocess.SubprocessError):
            return ""


def _parse_usb_devices(output: str) -> list[dict]:
    """Parse system_profiler SPUSBDataType output to extract USB device info."""
    devices = []

    # Split by lines
    lines = output.split("\n")

    current_device: Optional[dict] = None

    for line in lines:
        if not line.strip():
            continue

        # Determine indent level (2 spaces per level)
        indent = len(line) - len(line.lstrip())
        indent_level = indent // 2

        # Check for product names (main device indicator)
        if "Product:" in line:
            # Extract product name
            product = line.split("Product:", 1)[1].strip()

            # Save previous device
            if current_device is not None:
                devices.append(current_device)

            # Start new device
            current_device = {
                "product": product,
                "speed": "",
                "location": "",
                "power_required": 0,
                "power_available": 0,
                "manufacturer": "",
                "error_state": False,
                "is_hub": False,
                "parent_location": None,
                "indent_level": indent_level,
            }

        elif current_device is not None:
            # Extract various fields for current device
            if "Manufacturer:" in line:
                current_device["manufacturer"] = line.split("Manufacturer:", 1)[
                    1
                ].strip()

            elif "Speed:" in line:
                speed_info = line.split("Speed:", 1)[1].strip()
                current_device["speed"] = speed_info

            elif "Location ID:" in line:
                location = line.split("Location ID:", 1)[1].strip()
                # Extract just the hex number part
                location_match = re.search(r"0x[0-9a-f]+", location, re.IGNORECASE)
                if location_match:
                    current_device["location"] = location_match.group(0)

            elif "Current Required (mA):" in line:
                try:
                    power_str = line.split("Current Required (mA):", 1)[1].strip()
                    current_device["power_required"] = int(power_str)
                except ValueError:
                    pass

            elif "Current Available (mA):" in line:
                try:
                    power_str = line.split("Current Available (mA):", 1)[1].strip()
                    current_device["power_available"] = int(power_str)
                except ValueError:
                    pass

        # Check for hub designation (can be in Product line or elsewhere)
        if "Hub" in line and current_device:
            current_device["is_hub"] = True

        # Check for error states
        if current_device and ("(Error)" in line or "not recognized" in line.lower()):
            current_device["error_state"] = True

    # Add last device
    if current_device:
        devices.append(current_device)

    # Post-process to set parent_location based on indent levels
    for i, device in enumerate(devices):
        if device["indent_level"] > 0:
            # Find the most recent device with lower indent level that's a hub
            for j in range(i - 1, -1, -1):
                if devices[j]["indent_level"] < device["indent_level"]:
                    if devices[j]["is_hub"]:
                        device["parent_location"] = devices[j].get("location")
                    break

    # Remove indent_level from final devices
    for device in devices:
        device.pop("indent_level", None)

    return devices


def _format_device_list(devices: list[dict]) -> str:
    """Format device list into a readable string."""
    lines = []
    for i, device in enumerate(devices, 1):
        product = device.get("product", "Unknown")
        speed = device.get("speed", "Unknown speed")
        power = device.get("power_required", 0)
        manufacturer = device.get("manufacturer", "")

        device_type = "Hub" if device.get("is_hub") else "Device"
        mfg_str = f" ({manufacturer})" if manufacturer else ""

        power_str = f", {power}mA" if power > 0 else ""
        line = f"{i}. {product}{mfg_str} - {speed}{power_str} [{device_type}]"
        lines.append(line)

    return "\n".join(lines) if lines else "No USB devices found"
