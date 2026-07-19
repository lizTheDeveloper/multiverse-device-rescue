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
    name = "usb_device_audit"
    category = "security"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "5s"

    emits_codes = [
        "security.usb_device_audit.usb_devices",
        "security.usb_device_audit.no_vendor_devices",
        "security.usb_device_audit.storage_devices",
        "security.usb_device_audit.usb_hubs",
    ]

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Get USB devices
        usb_devices = self._get_usb_devices()
        device_count = len(usb_devices)

        # Count USB hubs
        hubs = [d for d in usb_devices if d.get("is_hub")]
        hub_count = len(hubs)

        # Find devices with no vendor info
        no_vendor_devices = [d for d in usb_devices if not d.get("vendor")]

        # Find storage devices
        storage_devices = [d for d in usb_devices if d.get("is_storage")]

        # Flag INFO for total USB devices count
        if device_count > 0:
            device_list = ", ".join(
                f"{d.get('name', 'Unknown')} ({d.get('vendor', 'Unknown Vendor')})"
                for d in usb_devices
            )
            findings.append(
                Finding(
                    title=f"USB devices detected: {device_count} device(s) connected",
                    description=(
                        f"Connected USB devices: {device_list}. "
                        "Review the list to ensure you recognize all connected devices."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.usb_device_audit.usb_devices",
                    data={
                        "check": "usb_devices",
                        "device_count": device_count,
                        "devices": usb_devices,
                    },
                )
            )

        # Flag WARNING for devices with no vendor info
        if no_vendor_devices:
            no_vendor_list = ", ".join(
                d.get("name", "Unknown Device") for d in no_vendor_devices
            )
            findings.append(
                Finding(
                    title=f"USB device(s) with unknown vendor: {len(no_vendor_devices)} device(s)",
                    description=(
                        f"Devices with missing vendor/manufacturer information: {no_vendor_list}. "
                        "This could indicate rogue devices, corrupted device info, or uncommon hardware. "
                        "Verify these devices are legitimate and recognize them."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.usb_device_audit.no_vendor_devices",
                    data={
                        "check": "no_vendor_devices",
                        "device_count": len(no_vendor_devices),
                        "devices": no_vendor_devices,
                    },
                )
            )

        # Flag INFO for USB storage devices
        if storage_devices:
            storage_list = ", ".join(
                f"{d.get('name', 'Unknown')} ({d.get('vendor', 'Unknown Vendor')})"
                for d in storage_devices
            )
            findings.append(
                Finding(
                    title=f"USB storage device(s) detected: {len(storage_devices)} device(s)",
                    description=(
                        f"External storage devices: {storage_list}. "
                        "Ensure these devices are from trusted sources."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.usb_device_audit.storage_devices",
                    data={
                        "check": "storage_devices",
                        "device_count": len(storage_devices),
                        "devices": storage_devices,
                    },
                )
            )

        # Flag INFO for USB hubs
        if hub_count > 0:
            hub_list = ", ".join(d.get("name", "Unknown Hub") for d in hubs)
            findings.append(
                Finding(
                    title=f"USB hub(s) detected: {hub_count} hub(s)",
                    description=(
                        f"USB hubs detected: {hub_list}. "
                        "Multiple daisy-chained hubs can cause power and stability issues on older Macs. "
                        "Consider using a powered hub if experiencing connectivity problems."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.usb_device_audit.usb_hubs",
                    data={
                        "check": "usb_hubs",
                        "hub_count": hub_count,
                        "hubs": hubs,
                    },
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        for finding in findings.findings:
            check = finding.data.get("check")

            if check == "usb_devices":
                actions.append(
                    Action(
                        title="Review connected USB devices",
                        description=(
                            "Review the list of connected USB devices and verify you recognize each one. "
                            "Disconnect any devices you no longer use or do not recognize. "
                            "Unknown USB devices can be security risks."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "no_vendor_devices":
                actions.append(
                    Action(
                        title="Investigate USB devices with unknown vendor",
                        description=(
                            "USB devices with missing vendor information could indicate: "
                            "(1) Rogue or malicious devices, (2) Corrupted device information, "
                            "(3) Uncommon or obscure hardware. "
                            "Disconnect any unfamiliar devices and contact the device manufacturer "
                            "if you believe the vendor information should be present."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "storage_devices":
                actions.append(
                    Action(
                        title="Review USB storage devices",
                        description=(
                            "External USB storage devices should come from trusted sources. "
                            "If you do not recognize a storage device, disconnect it immediately "
                            "to prevent potential data loss or infection. "
                            "Consider enabling FileVault encryption and keeping backups on "
                            "a trusted external drive in a secure location."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "usb_hubs":
                actions.append(
                    Action(
                        title="Review USB hub configuration",
                        description=(
                            "USB hubs are detected. Multiple daisy-chained hubs can cause: "
                            "(1) Power delivery issues, (2) Device connectivity problems, "
                            "(3) Data transfer slowdowns. "
                            "Consider using a single powered USB hub or connecting devices directly to the Mac. "
                            "Avoid daisy-chaining multiple hubs."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _get_usb_devices(self) -> list[dict]:
        """Get list of USB devices using system_profiler."""
        devices = []
        try:
            result = subprocess.run(
                ["system_profiler", "SPUSBDataType"],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                devices = self._parse_usb_output(result.stdout)
        except OSError:
            pass
        return devices

    def _parse_usb_output(self, output: str) -> list[dict]:
        """Parse system_profiler SPUSBDataType output."""
        devices = []
        lines = output.split("\n")

        current_device = {}

        for line in lines:
            if not line.strip():
                continue

            # Calculate indentation level
            indent = len(line) - len(line.lstrip())
            line_stripped = line.strip()

            # Detect device headers: lines ending with ":" at indent level 4 (under "Root Hub:")
            # Exclude structural keywords and property names
            if line_stripped.endswith(":") and indent == 4:
                # Skip structural elements and property containers
                # Use exact matching for single-word keywords to avoid partial matches
                skip_keywords = [
                    "Root Hub:", "Storage:", "Mass Storage:", "Removable:", "Capacity:",
                    "Mount Point:", "Extra Operating Current"
                ]
                if not any(kw in line_stripped for kw in skip_keywords):
                    # This is a device header
                    if current_device and current_device.get("name"):
                        devices.append(current_device)
                    current_device = {"name": line_stripped.rstrip(":"), "vendor": None, "is_hub": False, "is_storage": False}

            # Parse device properties (indent level 6+)
            elif current_device and indent >= 6:
                # Parse vendor info
                if "Vendor ID:" in line:
                    # Extract text after "Vendor ID: " which might include vendor name in parentheses
                    parts = line.split("Vendor ID:", 1)
                    if len(parts) == 2:
                        vendor_text = parts[1].strip()
                        # Extract vendor name from parentheses if present
                        if "(" in vendor_text and ")" in vendor_text:
                            vendor_name = vendor_text.split("(")[1].split(")")[0].strip()
                            current_device["vendor"] = vendor_name
                        else:
                            current_device["vendor"] = vendor_text

                elif "Manufacturer:" in line and not current_device.get("vendor"):
                    parts = line.split("Manufacturer:", 1)
                    if len(parts) == 2:
                        current_device["vendor"] = parts[1].strip()

                # Parse serial number
                elif "Serial Number:" in line:
                    parts = line.split("Serial Number:", 1)
                    if len(parts) == 2:
                        current_device["serial"] = parts[1].strip()

                # Detect hubs
                elif "Hub:" in line and "Yes" in line:
                    current_device["is_hub"] = True

                # Detect storage devices
                elif "Mass Storage" in line:
                    current_device["is_storage"] = True

        # Don't forget the last device
        if current_device and current_device.get("name"):
            devices.append(current_device)

        # Filter out empty devices and root hubs that are system components
        devices = [
            d for d in devices
            if d.get("name") and d.get("name").lower() not in ["usb", "root hub"]
        ]

        return devices
