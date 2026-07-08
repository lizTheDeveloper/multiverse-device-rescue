import json
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
    name = "win_bluetooth_check"
    category = "integrity"
    platforms = [Platform.WIN32]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "10s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Get Bluetooth adapter status
        adapter_info = self._get_bluetooth_adapters()
        if not adapter_info:
            findings.append(
                Finding(
                    title="Could not retrieve Bluetooth adapter information",
                    description=(
                        "Failed to query Bluetooth devices. Bluetooth drivers may not be installed "
                        "or you may not have Administrator privileges."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "adapter_query_failed"},
                )
            )
            return CheckResult(module_name=self.name, findings=findings)

        # Get service status
        service_status = self._get_service_status()

        # Check for adapter errors
        adapters = adapter_info.get("adapters", [])
        if adapters:
            for adapter in adapters:
                findings.append(
                    Finding(
                        title=f"Bluetooth adapter: {adapter['name']}",
                        description=(
                            f"Adapter status: {adapter['status']}. "
                            f"Instance ID: {adapter['instance_id']}"
                        ),
                        severity=Severity.INFO,
                        category=self.category,
                        data={
                            "check": "adapter_info",
                            "adapter_name": adapter["name"],
                            "adapter_status": adapter["status"],
                        },
                    )
                )

                # Flag warning if adapter has error status
                if adapter["status"].lower() not in ["ok", "working", "unknown"]:
                    findings.append(
                        Finding(
                            title=f"Bluetooth adapter error: {adapter['name']}",
                            description=(
                                f"Bluetooth adapter '{adapter['name']}' is reporting error status: {adapter['status']}. "
                                "The adapter may need to be restarted or reinstalled."
                            ),
                            severity=Severity.WARNING,
                            category=self.category,
                            data={
                                "check": "adapter_error",
                                "adapter_name": adapter["name"],
                                "adapter_status": adapter["status"],
                            },
                        )
                    )

        # Get paired devices
        paired_devices = self._get_paired_devices()
        if paired_devices and paired_devices.get("devices"):
            for device in paired_devices["devices"]:
                findings.append(
                    Finding(
                        title=f"Paired device: {device['name']}",
                        description=(
                            f"Device status: {device['status']}"
                        ),
                        severity=Severity.INFO,
                        category=self.category,
                        data={
                            "check": "paired_device_info",
                            "device_name": device["name"],
                            "device_status": device["status"],
                        },
                    )
                )

                # Flag warning if paired device has error status
                if device["status"].lower() not in ["ok", "working", "unknown"]:
                    findings.append(
                        Finding(
                            title=f"Paired device error: {device['name']}",
                            description=(
                                f"Paired device '{device['name']}' is reporting error status: {device['status']}. "
                                "Try removing and re-pairing the device."
                            ),
                            severity=Severity.WARNING,
                            category=self.category,
                            data={
                                "check": "device_error",
                                "device_name": device["name"],
                                "device_status": device["status"],
                            },
                        )
                    )

        # Check service status
        if service_status:
            status = service_status.get("status", "unknown").lower()
            startup_type = service_status.get("startup_type", "unknown").lower()

            findings.append(
                Finding(
                    title="Bluetooth Support Service status",
                    description=(
                        f"Bluetooth Support Service (bthserv) status: {status}. "
                        f"Startup type: {startup_type}"
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "check": "service_status",
                        "service_status": status,
                        "startup_type": startup_type,
                    },
                )
            )

            # Flag warning if service is stopped or disabled
            if status not in ["running", "ok"]:
                findings.append(
                    Finding(
                        title="Bluetooth Support Service is not running",
                        description=(
                            f"Bluetooth Support Service (bthserv) is not running (status: {status}). "
                            "The service may need to be started. Try restarting Windows or manually "
                            "starting the service."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={
                            "check": "service_not_running",
                            "service_status": status,
                        },
                    )
                )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        for finding in findings.findings:
            check = finding.data.get("check")

            if check == "adapter_query_failed":
                actions.append(
                    Action(
                        title="Unable to query Bluetooth adapters",
                        description=(
                            "Could not retrieve Bluetooth adapter information. "
                            "Ensure you have Administrator privileges and Bluetooth drivers are installed. "
                            "Try running PowerShell as Administrator and running: "
                            "Get-PnpDevice -Class Bluetooth"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "adapter_error":
                adapter_name = finding.data.get("adapter_name", "Unknown")
                actions.append(
                    Action(
                        title=f"Restart Bluetooth adapter '{adapter_name}'",
                        description=(
                            f"Bluetooth adapter '{adapter_name}' is reporting an error. "
                            "Try the following: (1) Restart the computer to reset the adapter. "
                            "(2) Disable and re-enable the adapter in Device Manager. "
                            "(3) Update Bluetooth drivers from the manufacturer's website. "
                            "(4) Uninstall and reinstall the Bluetooth device driver."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "device_error":
                device_name = finding.data.get("device_name", "Unknown")
                actions.append(
                    Action(
                        title=f"Re-pair Bluetooth device '{device_name}'",
                        description=(
                            f"Paired device '{device_name}' is reporting an error. "
                            "Try the following: (1) Disable Bluetooth on the device. "
                            "(2) In Windows Settings > Devices > Bluetooth, remove the device. "
                            "(3) Restart the device and re-pair it with your computer."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "service_not_running":
                actions.append(
                    Action(
                        title="Start Bluetooth Support Service",
                        description=(
                            "Bluetooth Support Service (bthserv) is not running. "
                            "Try the following: (1) Restart your computer. "
                            "(2) Open Services (services.msc) and find 'Bluetooth Support Service' (bthserv). "
                            "(3) Right-click and select 'Start' if it's not running. "
                            "(4) Set startup type to 'Automatic' to ensure it starts on boot."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "adapter_info":
                adapter_name = finding.data.get("adapter_name", "Unknown")
                actions.append(
                    Action(
                        title=f"Bluetooth adapter '{adapter_name}' is functional",
                        description=(
                            f"Bluetooth adapter '{adapter_name}' is working normally. "
                            "You can pair devices using Bluetooth Settings."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "paired_device_info":
                device_name = finding.data.get("device_name", "Unknown")
                actions.append(
                    Action(
                        title=f"Paired device '{device_name}' is functional",
                        description=(
                            f"Paired device '{device_name}' is working normally."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "service_status":
                service_status = finding.data.get("service_status", "unknown")
                actions.append(
                    Action(
                        title="Bluetooth Support Service is running",
                        description=(
                            f"Bluetooth Support Service (bthserv) is {service_status} and available for use."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _get_bluetooth_adapters(self) -> Optional[dict]:
        """Get Bluetooth adapter information from PowerShell."""
        try:
            # PowerShell command to get Bluetooth adapters
            ps_cmd = (
                "Get-PnpDevice -Class Bluetooth | "
                "Select-Object FriendlyName, Status, InstanceId | "
                "ConvertTo-Json"
            )
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                return None

            return _parse_adapter_info(result.stdout)
        except (OSError, subprocess.SubprocessError, TimeoutError):
            return None

    def _get_paired_devices(self) -> Optional[dict]:
        """Get paired Bluetooth devices from PowerShell."""
        try:
            # PowerShell command to get paired devices
            ps_cmd = (
                "Get-PnpDevice -PresentOnly | Where-Object {$_.Class -eq 'Bluetooth'} | "
                "Select-Object FriendlyName, Status | "
                "ConvertTo-Json"
            )
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                return None

            return _parse_device_info(result.stdout)
        except (OSError, subprocess.SubprocessError, TimeoutError):
            return None

    def _get_service_status(self) -> Optional[dict]:
        """Get Bluetooth Support Service status."""
        try:
            # Use sc query to get service status
            result = subprocess.run(
                ["sc", "query", "bthserv"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                return None

            return _parse_service_status(result.stdout)
        except (OSError, subprocess.SubprocessError, TimeoutError):
            return None


def _parse_adapter_info(json_output: str) -> dict:
    """Parse PowerShell JSON output from Get-PnpDevice -Class Bluetooth."""
    info = {"adapters": []}

    if not json_output.strip():
        return info

    try:
        # Handle both single object and array
        data = json.loads(json_output)
        if not isinstance(data, list):
            data = [data]

        for adapter in data:
            friendly_name = adapter.get("FriendlyName", "Unknown")
            status = adapter.get("Status", "Unknown")
            instance_id = adapter.get("InstanceId", "Unknown")

            info["adapters"].append(
                {
                    "name": friendly_name,
                    "status": status,
                    "instance_id": instance_id,
                }
            )

        return info
    except (json.JSONDecodeError, ValueError, KeyError, TypeError):
        return info


def _parse_device_info(json_output: str) -> dict:
    """Parse PowerShell JSON output for paired devices."""
    info = {"devices": []}

    if not json_output.strip():
        return info

    try:
        # Handle both single object and array
        data = json.loads(json_output)
        if not isinstance(data, list):
            data = [data]

        for device in data:
            friendly_name = device.get("FriendlyName", "Unknown")
            status = device.get("Status", "Unknown")

            info["devices"].append(
                {
                    "name": friendly_name,
                    "status": status,
                }
            )

        return info
    except (json.JSONDecodeError, ValueError, KeyError, TypeError):
        return info


def _parse_service_status(output: str) -> dict:
    """Parse sc query output for service status."""
    status_info = {"status": "unknown", "startup_type": "unknown"}

    try:
        for line in output.split("\n"):
            line = line.strip()
            if "STATE" in line:
                # Extract status (Running, Stopped, etc.)
                if "RUNNING" in line:
                    status_info["status"] = "running"
                elif "STOPPED" in line:
                    status_info["status"] = "stopped"
                else:
                    # Extract the status value
                    parts = line.split(":")
                    if len(parts) > 1:
                        status_info["status"] = parts[1].strip()
            elif "START_TYPE" in line:
                # Extract startup type
                parts = line.split(":")
                if len(parts) > 1:
                    startup = parts[1].strip()
                    if "AUTO" in startup:
                        status_info["startup_type"] = "automatic"
                    elif "DEMAND" in startup:
                        status_info["startup_type"] = "manual"
                    elif "DISABLED" in startup:
                        status_info["startup_type"] = "disabled"
                    else:
                        status_info["startup_type"] = startup

        return status_info
    except (ValueError, IndexError):
        return status_info
