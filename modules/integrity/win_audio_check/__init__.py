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
    name = "win_audio_check"
    category = "integrity"
    platforms = [Platform.WIN32]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "10s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Get audio devices
        devices_info = self._get_audio_devices()
        if not devices_info:
            findings.append(
                Finding(
                    title="Could not retrieve audio device information",
                    description=(
                        "Failed to query audio devices. Audio drivers may not be installed "
                        "or you may not have Administrator privileges."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "device_query_failed"},
                )
            )
        else:
            # Check audio devices
            devices = devices_info.get("devices", [])
            if devices:
                for device in devices:
                    findings.append(
                        Finding(
                            title=f"Audio device: {device['name']}",
                            description=(
                                f"Device status: {device['status']}. "
                                f"Instance ID: {device['instance_id']}"
                            ),
                            severity=Severity.INFO,
                            category=self.category,
                            data={
                                "check": "device_info",
                                "device_name": device["name"],
                                "device_status": device["status"],
                            },
                        )
                    )

                    # Flag warning if device has error status
                    if device["status"].lower() not in ["ok", "working", "unknown"]:
                        findings.append(
                            Finding(
                                title=f"Audio device error: {device['name']}",
                                description=(
                                    f"Audio device '{device['name']}' is reporting error status: {device['status']}. "
                                    "The device may need to be restarted or reinstalled."
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
            else:
                findings.append(
                    Finding(
                        title="No audio devices found",
                        description=(
                            "No audio endpoint devices were detected on this system. "
                            "This may indicate audio drivers are not installed."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={"check": "no_devices"},
                    )
                )

        # Check Windows Audio service (Audiosrv)
        audio_service_status = self._get_service_status("Audiosrv")
        if audio_service_status:
            status = audio_service_status.get("status", "unknown").lower()
            startup_type = audio_service_status.get("startup_type", "unknown").lower()

            findings.append(
                Finding(
                    title="Windows Audio service (Audiosrv) status",
                    description=(
                        f"Windows Audio service status: {status}. "
                        f"Startup type: {startup_type}"
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "check": "audio_service_status",
                        "service_status": status,
                        "startup_type": startup_type,
                    },
                )
            )

            # Flag CRITICAL if service is stopped
            if status not in ["running", "ok"]:
                findings.append(
                    Finding(
                        title="Windows Audio service is not running",
                        description=(
                            f"Windows Audio service (Audiosrv) is not running (status: {status}). "
                            "This is why you have no sound. Try restarting Windows or manually starting the service."
                        ),
                        severity=Severity.CRITICAL,
                        category=self.category,
                        data={
                            "check": "audio_service_not_running",
                            "service_status": status,
                        },
                    )
                )

        # Check Audio Endpoint Builder service
        endpoint_service_status = self._get_service_status("AudioEndpointBuilder")
        if endpoint_service_status:
            status = endpoint_service_status.get("status", "unknown").lower()
            startup_type = endpoint_service_status.get("startup_type", "unknown").lower()

            findings.append(
                Finding(
                    title="Audio Endpoint Builder service status",
                    description=(
                        f"Audio Endpoint Builder service status: {status}. "
                        f"Startup type: {startup_type}"
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "check": "endpoint_builder_status",
                        "service_status": status,
                        "startup_type": startup_type,
                    },
                )
            )

            # Flag warning if service is stopped
            if status not in ["running", "ok"]:
                findings.append(
                    Finding(
                        title="Audio Endpoint Builder service is not running",
                        description=(
                            f"Audio Endpoint Builder service is not running (status: {status}). "
                            "This may prevent audio devices from being properly recognized. "
                            "Try restarting Windows or manually starting the service."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={
                            "check": "endpoint_builder_not_running",
                            "service_status": status,
                        },
                    )
                )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        for finding in findings.findings:
            check = finding.data.get("check")

            if check == "device_query_failed":
                actions.append(
                    Action(
                        title="Unable to query audio devices",
                        description=(
                            "Could not retrieve audio device information. "
                            "Ensure you have Administrator privileges and audio drivers are installed. "
                            "Try running PowerShell as Administrator and running: "
                            "Get-PnpDevice -Class AudioEndpoint"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "device_error":
                device_name = finding.data.get("device_name", "Unknown")
                actions.append(
                    Action(
                        title=f"Restart audio device '{device_name}'",
                        description=(
                            f"Audio device '{device_name}' is reporting an error. "
                            "Try the following: (1) Restart the computer to reset the device. "
                            "(2) Disable and re-enable the device in Device Manager. "
                            "(3) Update audio drivers from the manufacturer's website. "
                            "(4) Uninstall and reinstall the audio device driver."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "no_devices":
                actions.append(
                    Action(
                        title="No audio devices detected",
                        description=(
                            "No audio devices were found on this system. "
                            "Try the following: (1) Check Device Manager for audio devices with error indicators. "
                            "(2) Update or reinstall audio drivers from the manufacturer's website. "
                            "(3) Check BIOS settings to ensure audio is enabled. "
                            "(4) If using external audio devices, check connections and power."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "audio_service_not_running":
                actions.append(
                    Action(
                        title="Start Windows Audio service",
                        description=(
                            "Windows Audio service (Audiosrv) is not running. "
                            "Try the following: (1) Restart your computer. "
                            "(2) Open Services (services.msc) and find 'Windows Audio' (Audiosrv). "
                            "(3) Right-click and select 'Start' if it's not running. "
                            "(4) Set startup type to 'Automatic' to ensure it starts on boot."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "endpoint_builder_not_running":
                actions.append(
                    Action(
                        title="Start Audio Endpoint Builder service",
                        description=(
                            "Audio Endpoint Builder service is not running. "
                            "Try the following: (1) Restart your computer. "
                            "(2) Open Services (services.msc) and find 'Windows Audio Device Graph Isolation' (AudioEndpointBuilder). "
                            "(3) Right-click and select 'Start' if it's not running. "
                            "(4) Set startup type to 'Automatic' to ensure it starts on boot."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "device_info":
                device_name = finding.data.get("device_name", "Unknown")
                actions.append(
                    Action(
                        title=f"Audio device '{device_name}' is functional",
                        description=(
                            f"Audio device '{device_name}' is working normally. "
                            "You can use this device for audio playback and recording."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "audio_service_status":
                service_status = finding.data.get("service_status", "unknown")
                actions.append(
                    Action(
                        title="Windows Audio service is running",
                        description=(
                            f"Windows Audio service (Audiosrv) is {service_status} and available for use."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "endpoint_builder_status":
                service_status = finding.data.get("service_status", "unknown")
                actions.append(
                    Action(
                        title="Audio Endpoint Builder service is running",
                        description=(
                            f"Audio Endpoint Builder service is {service_status} and available for use."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _get_audio_devices(self) -> Optional[dict]:
        """Get audio device information from PowerShell."""
        try:
            # PowerShell command to get audio endpoint devices
            ps_cmd = (
                "Get-PnpDevice -Class AudioEndpoint | "
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

            return _parse_device_info(result.stdout)
        except (OSError, subprocess.SubprocessError, TimeoutError):
            return None

    def _get_service_status(self, service_name: str) -> Optional[dict]:
        """Get Windows service status."""
        try:
            # Use sc query to get service status
            result = subprocess.run(
                ["sc", "query", service_name],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                return None

            return _parse_service_status(result.stdout)
        except (OSError, subprocess.SubprocessError, TimeoutError):
            return None


def _parse_device_info(json_output: str) -> dict:
    """Parse PowerShell JSON output for audio devices."""
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
            instance_id = device.get("InstanceId", "Unknown")

            info["devices"].append(
                {
                    "name": friendly_name,
                    "status": status,
                    "instance_id": instance_id,
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
