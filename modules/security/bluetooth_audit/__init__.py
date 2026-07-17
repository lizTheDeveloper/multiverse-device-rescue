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
    name = "bluetooth_audit"
    category = "security"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "5s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Get Bluetooth power state
        power_state = self._get_bluetooth_power_state()
        power_on = power_state == 1

        # Get Bluetooth discoverability state
        discoverable_state = self._get_bluetooth_discoverable_state()
        discoverable = discoverable_state == 1

        # Get paired devices
        paired_devices = self._get_paired_devices()
        device_count = len(paired_devices)

        # Flag INFO for number of paired devices
        if device_count > 0:
            device_list = ", ".join(paired_devices)
            findings.append(
                Finding(
                    title=f"Bluetooth has {device_count} paired device(s)",
                    description=(
                        f"Paired devices: {device_list}. "
                        "Verify you recognize all paired devices."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "check": "paired_devices",
                        "device_count": device_count,
                        "devices": paired_devices,
                    },
                )
            )

        # Flag WARNING if Bluetooth discoverable is enabled (security risk)
        if discoverable:
            findings.append(
                Finding(
                    title="Bluetooth is discoverable",
                    description=(
                        "Bluetooth discoverable is enabled, which allows other devices "
                        "to see and connect to this Mac without authorization. "
                        "This is a security risk."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "discoverable_state"},
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        for finding in findings.findings:
            check = finding.data.get("check")

            if check == "discoverable_state":
                actions.append(
                    Action(
                        title="Disable Bluetooth discoverability",
                        description=(
                            "To disable Bluetooth discoverability, go to "
                            "System Settings > Bluetooth, then ensure this Mac is not set as discoverable. "
                            "Alternatively, run: defaults write /Library/Preferences/com.apple.Bluetooth DiscoverableState 0"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif check == "paired_devices":
                actions.append(
                    Action(
                        title="Review paired Bluetooth devices",
                        description=(
                            "Review the list of paired devices. "
                            "Remove any devices you no longer use or do not recognize. "
                            "Go to System Settings > Bluetooth and click the minus icon next to unwanted devices."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _get_bluetooth_power_state(self) -> int:
        """Get Bluetooth power state (1 = on, 0 = off)."""
        try:
            result = subprocess.run(
                ["defaults", "read", "/Library/Preferences/com.apple.Bluetooth", "ControllerPowerState"],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                return int(result.stdout.strip())
        except (OSError, ValueError):
            pass
        return 0

    def _get_bluetooth_discoverable_state(self) -> int:
        """Get Bluetooth discoverable state (1 = discoverable, 0 = not discoverable)."""
        try:
            result = subprocess.run(
                ["defaults", "read", "/Library/Preferences/com.apple.Bluetooth", "DiscoverableState"],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                return int(result.stdout.strip())
        except (OSError, ValueError):
            pass
        return 0

    def _get_paired_devices(self) -> list[str]:
        """Get list of paired Bluetooth device names."""
        devices = []
        try:
            result = subprocess.run(
                ["system_profiler", "SPBluetoothDataType"],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                # Parse output for device names
                lines = result.stdout.split("\n")
                for i, line in enumerate(lines):
                    # Look for lines that contain device information
                    # system_profiler output format includes "Device Name: " entries
                    if "Device Name:" in line:
                        device_name = line.split("Device Name:")[-1].strip()
                        if device_name:
                            devices.append(device_name)
        except OSError:
            pass
        return devices
