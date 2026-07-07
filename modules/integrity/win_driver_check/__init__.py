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
    name = "win_driver_check"
    category = "integrity"
    platforms = [Platform.WIN32]
    risk_level = RiskLevel.SAFE
    priority = 55
    depends_on = []
    estimated_duration = "10s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Get drivers with issues (ConfigManagerErrorCode != 0)
        problem_devices = self._get_problem_devices()

        # Check for unsigned drivers
        unsigned_drivers = self._get_unsigned_drivers()

        # Get total driver count
        total_driver_count = self._get_total_driver_count()

        # Add findings for devices with driver errors
        if problem_devices:
            for device in problem_devices:
                findings.append(
                    Finding(
                        title=f"Driver error: {device['name']}",
                        description=(
                            f"Device '{device['name']}' has a driver error (Code {device['error_code']}). "
                            "This may cause the device to malfunction. Consider updating the driver or "
                            "reinstalling it from Device Manager."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={
                            "check": "driver_error",
                            "device_name": device["name"],
                            "error_code": device["error_code"],
                        },
                    )
                )

        # Add findings for unsigned drivers
        if unsigned_drivers:
            for driver in unsigned_drivers:
                findings.append(
                    Finding(
                        title=f"Unsigned driver: {driver['name']}",
                        description=(
                            f"Driver '{driver['name']}' is unsigned. Unsigned drivers are a security risk "
                            "and may be unstable. Consider updating to a signed version from the manufacturer."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={
                            "check": "unsigned_driver",
                            "driver_name": driver["name"],
                        },
                    )
                )

        # Add summary info about driver status
        problem_count = len(problem_devices) if problem_devices else 0
        unsigned_count = len(unsigned_drivers) if unsigned_drivers else 0

        if total_driver_count is not None:
            if problem_count == 0 and unsigned_count == 0:
                # All drivers are healthy
                findings.append(
                    Finding(
                        title="All drivers healthy",
                        description=(
                            f"All {total_driver_count} driver(s) are healthy and properly configured. "
                            "No driver errors or unsigned drivers detected."
                        ),
                        severity=Severity.INFO,
                        category=self.category,
                        data={
                            "check": "drivers_healthy",
                            "total_drivers": total_driver_count,
                        },
                    )
                )
            else:
                # Some drivers have issues
                findings.append(
                    Finding(
                        title="Driver summary",
                        description=(
                            f"Total drivers: {total_driver_count}. "
                            f"Devices with driver errors: {problem_count}. "
                            f"Unsigned drivers: {unsigned_count}. "
                            "Review driver issues above and update drivers as needed."
                        ),
                        severity=Severity.INFO,
                        category=self.category,
                        data={
                            "check": "driver_summary",
                            "total_drivers": total_driver_count,
                            "problem_devices": problem_count,
                            "unsigned_drivers": unsigned_count,
                        },
                    )
                )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        for finding in findings.findings:
            check = finding.data.get("check")

            if check == "driver_error":
                device_name = finding.data.get("device_name")
                error_code = finding.data.get("error_code")
                actions.append(
                    Action(
                        title=f"Update driver for {device_name}",
                        description=(
                            f"Device '{device_name}' is reporting error code {error_code}. "
                            "Recommendations: (1) Open Device Manager (devmgmt.msc). "
                            "(2) Find the device with the error (marked with a warning icon). "
                            "(3) Right-click and select 'Update driver'. "
                            "(4) Choose 'Search automatically for updated driver software'. "
                            "(5) If no update is found, try reinstalling the driver. "
                            "(6) Restart the device if prompted."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "unsigned_driver":
                driver_name = finding.data.get("driver_name")
                actions.append(
                    Action(
                        title=f"Update unsigned driver: {driver_name}",
                        description=(
                            f"Driver '{driver_name}' is unsigned, which poses a security risk. "
                            "Recommendations: (1) Visit the device manufacturer's support website. "
                            "(2) Download the latest signed driver for your device. "
                            "(3) Install the driver following the manufacturer's instructions. "
                            "(4) Restart Windows if prompted. "
                            "(5) Verify in Device Manager that the driver is now signed."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "drivers_healthy":
                actions.append(
                    Action(
                        title="All drivers are healthy",
                        description=(
                            "All drivers on this system are properly installed and configured. "
                            "Continue to keep drivers updated by regularly checking for updates "
                            "through Windows Update or manufacturer support websites."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "driver_summary":
                problem_devices = finding.data.get("problem_devices", 0)
                unsigned_drivers = finding.data.get("unsigned_drivers", 0)
                actions.append(
                    Action(
                        title="Review driver issues",
                        description=(
                            f"Found {problem_devices} device(s) with driver errors and "
                            f"{unsigned_drivers} unsigned driver(s). "
                            "Review each issue above for specific device names and update drivers accordingly. "
                            "Visit manufacturer support websites for the latest signed drivers."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _get_problem_devices(self) -> list:
        """Get devices with driver errors via WMI."""
        try:
            ps_cmd = (
                "Get-WmiObject Win32_PnPEntity | "
                "Where-Object {$_.ConfigManagerErrorCode -ne 0} | "
                "Select-Object Name, ConfigManagerErrorCode | "
                "ConvertTo-Json"
            )
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                return []

            if not result.stdout.strip():
                return []

            return _parse_problem_devices(result.stdout)
        except (OSError, subprocess.SubprocessError, TimeoutError):
            return []

    def _get_unsigned_drivers(self) -> list:
        """Get unsigned drivers via driverquery."""
        try:
            result = subprocess.run(
                ["driverquery", "/v"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                return []

            if not result.stdout.strip():
                return []

            return _parse_unsigned_drivers(result.stdout)
        except (OSError, subprocess.SubprocessError, TimeoutError):
            return []

    def _get_total_driver_count(self) -> Optional[int]:
        """Get total driver count."""
        try:
            ps_cmd = (
                "Get-WmiObject Win32_PnPEntity | "
                "Measure-Object | "
                "Select-Object Count"
            )
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0 or not result.stdout.strip():
                return None

            return _parse_count(result.stdout)
        except (OSError, subprocess.SubprocessError, TimeoutError):
            return None


def _parse_problem_devices(json_output: str) -> list:
    """Parse WMI JSON output for problem devices."""
    import json

    devices = []
    if not json_output.strip():
        return devices

    try:
        data = json.loads(json_output)
        if not isinstance(data, list):
            data = [data]

        for item in data:
            if isinstance(item, dict):
                name = item.get("Name", "Unknown")
                error_code = item.get("ConfigManagerErrorCode", "Unknown")
                devices.append({"name": name, "error_code": error_code})

        return devices
    except (json.JSONDecodeError, ValueError, KeyError):
        return devices


def _parse_unsigned_drivers(driverquery_output: str) -> list:
    """Parse driverquery output for unsigned drivers."""
    drivers = []
    if not driverquery_output.strip():
        return drivers

    try:
        lines = driverquery_output.split("\n")
        # Skip header lines until we find the table separator
        in_table = False
        for line in lines:
            line = line.strip()
            if not line:
                continue

            # Look for rows that contain "No" in the "Signed" column
            # driverquery /v format: Driver Name | Signed | ...
            # We need to find lines with driver info and check if "Signed" column is "No"

            # Split by common delimiters in the output
            parts = line.split()
            if len(parts) > 0 and "No" in line and "Signed" not in line:
                # This is a data line that might have an unsigned driver
                # Extract driver name (first part before "No")
                if "No" in line:
                    # Try to extract driver name from the line
                    # Format is typically: DriverName ... No ...
                    driver_parts = line.split()
                    if driver_parts and driver_parts[-1] == "No":
                        driver_name = " ".join(driver_parts[:-1])
                        if driver_name and driver_name != "Signed":
                            drivers.append({"name": driver_name})

        return drivers
    except (ValueError, IndexError):
        return drivers


def _parse_count(output: str) -> Optional[int]:
    """Extract count from PowerShell Measure-Object output."""
    try:
        for line in output.split("\n"):
            if "count" in line.lower():
                parts = line.split()
                for part in parts:
                    if part.isdigit():
                        return int(part)
        return None
    except (ValueError, IndexError):
        return None
