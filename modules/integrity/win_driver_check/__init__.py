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
    name = "win_driver_check"
    category = "integrity"
    platforms = [Platform.WIN32]
    risk_level = RiskLevel.SAFE
    priority = 55
    depends_on = []
    estimated_duration = "20s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Check for devices with problems
        problem_devices = self._get_problem_devices()
        if problem_devices:
            for device in problem_devices:
                findings.append(
                    Finding(
                        title=f"Device problem detected: {device['friendly_name']}",
                        description=(
                            f"Device '{device['friendly_name']}' ({device['class']}) is reporting "
                            f"status: {device['status']}. This may indicate a driver issue or "
                            "hardware malfunction. The device may not be functioning properly."
                        ),
                        severity=Severity.CRITICAL,
                        category=self.category,
                        data={
                            "check": "problem_device",
                            "friendly_name": device["friendly_name"],
                            "class": device["class"],
                            "status": device["status"],
                        },
                    )
                )

        # Check for unsigned drivers
        unsigned_drivers = self._get_unsigned_drivers()
        if unsigned_drivers:
            findings.append(
                Finding(
                    title=f"Unsigned drivers detected ({len(unsigned_drivers)})",
                    description=(
                        f"Found {len(unsigned_drivers)} unsigned system driver(s). "
                        "Unsigned drivers are a security risk and may indicate malware or "
                        "incompatible drivers. Examples: {}.".format(
                            ", ".join(unsigned_drivers[:3])
                        )
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "check": "unsigned_drivers",
                        "count": len(unsigned_drivers),
                        "drivers": unsigned_drivers,
                    },
                )
            )

        # Check for stopped drivers
        stopped_drivers = self._get_stopped_drivers()
        if stopped_drivers:
            findings.append(
                Finding(
                    title=f"Stopped drivers detected ({len(stopped_drivers)})",
                    description=(
                        f"Found {len(stopped_drivers)} driver(s) in stopped state. "
                        "These drivers may not be loaded or may have failed to start. "
                        "Examples: {}.".format(", ".join(stopped_drivers[:3]))
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "check": "stopped_drivers",
                        "count": len(stopped_drivers),
                        "drivers": stopped_drivers,
                    },
                )
            )

        # Get recently updated drivers
        recent_drivers = self._get_recent_drivers()
        if recent_drivers:
            findings.append(
                Finding(
                    title=f"Recently updated drivers ({len(recent_drivers)})",
                    description=(
                        f"Found {len(recent_drivers)} driver(s) updated in the last 30 days. "
                        "These are typically recent updates. Monitor system stability if "
                        "you experience issues after updates. Examples: {}.".format(
                            ", ".join(recent_drivers[:3])
                        )
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "check": "recent_drivers",
                        "count": len(recent_drivers),
                        "drivers": recent_drivers,
                    },
                )
            )

        # Get driver summary
        total_drivers = self._get_total_driver_count()
        if total_drivers >= 0:
            summary = {
                "total": total_drivers,
                "problematic": len(problem_devices),
                "unsigned": len(unsigned_drivers) if unsigned_drivers else 0,
                "stopped": len(stopped_drivers) if stopped_drivers else 0,
                "recent": len(recent_drivers) if recent_drivers else 0,
            }

            status_msg = "all drivers healthy"
            if problem_devices or unsigned_drivers or stopped_drivers:
                status_msg = "issues detected"
                description = (
                    f"Total drivers installed: {summary['total']}. "
                    f"Problematic: {summary['problematic']}, "
                    f"Unsigned: {summary['unsigned']}, "
                    f"Stopped: {summary['stopped']}, "
                    f"Recently updated (30 days): {summary['recent']}. "
                    "Review driver issues above and keep drivers updated."
                )
            else:
                description = (
                    f"All {summary['total']} drivers are healthy and functioning properly. "
                    f"No problematic devices, unsigned drivers, or stopped drivers detected. "
                    "Keep drivers updated for stability and security."
                )

            findings.append(
                Finding(
                    title=f"Driver summary: {status_msg}",
                    description=description,
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "driver_summary", **summary},
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        for finding in findings.findings:
            check = finding.data.get("check")

            if check == "problem_device":
                device_name = finding.data.get("friendly_name")
                actions.append(
                    Action(
                        title=f"Device issue: {device_name}",
                        description=(
                            f"The device '{device_name}' is not functioning properly. "
                            "Recommendations: (1) Open Device Manager (devmgmt.msc). "
                            "(2) Locate the device with a warning icon or error status. "
                            "(3) Right-click and select 'Update driver'. "
                            "(4) Choose 'Search automatically for updated driver software'. "
                            "(5) If that fails, visit the device manufacturer's website "
                            "and download the latest driver. (6) If the device still fails, "
                            "uninstall it and restart the system to let Windows reinstall "
                            "the default driver."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "unsigned_drivers":
                count = finding.data.get("count", 0)
                drivers = finding.data.get("drivers", [])
                actions.append(
                    Action(
                        title=f"Unsigned drivers ({count})",
                        description=(
                            f"Found {count} unsigned driver(s): {', '.join(drivers[:5])}. "
                            "Unsigned drivers are a security risk. Recommendations: "
                            "(1) Identify the driver source and manufacturer. "
                            "(2) Visit the manufacturer's website to check for a signed version. "
                            "(3) Update or replace with the manufacturer's certified driver. "
                            "(4) Consider disabling problematic drivers if they are optional. "
                            "(5) Run Windows Update to get signed driver updates. "
                            "(6) If from a trusted source, the driver may be legitimately unsigned "
                            "but should be evaluated carefully."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "stopped_drivers":
                count = finding.data.get("count", 0)
                drivers = finding.data.get("drivers", [])
                actions.append(
                    Action(
                        title=f"Stopped drivers ({count})",
                        description=(
                            f"Found {count} driver(s) in stopped state: "
                            f"{', '.join(drivers[:5])}. Recommendations: "
                            "(1) Open Device Manager (devmgmt.msc). "
                            "(2) Check if the device with this driver is disabled or has errors. "
                            "(3) Right-click the device and select 'Enable device' if disabled. "
                            "(4) If there's an error code, right-click and 'Update driver'. "
                            "(5) Restart the system if driver updates are applied. "
                            "(6) Check System event log for driver-related errors. "
                            "(7) Some stopped drivers may be optional or deactivated by policy."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "recent_drivers":
                count = finding.data.get("count", 0)
                actions.append(
                    Action(
                        title=f"Recently updated drivers ({count})",
                        description=(
                            f"Detected {count} driver(s) updated in the last 30 days. "
                            "Recommendations: (1) Monitor system stability and performance. "
                            "(2) If you experience BSOD or hardware issues, they may be "
                            "related to recent driver updates. (3) Check the Windows Update "
                            "history to see which drivers were updated. (4) If problems occur, "
                            "you can roll back a driver: Open Device Manager, right-click "
                            "the device, select Properties, go to Driver tab, and choose "
                            "'Roll Back Driver'. (5) Report issues to the manufacturer if "
                            "a driver consistently causes problems. (6) Keep Windows Update "
                            "enabled for future driver fixes."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "driver_summary":
                actions.append(
                    Action(
                        title="Driver summary",
                        description=(
                            "Driver summary shows the overall state of installed drivers on your system. "
                            "Recommendations: (1) Regularly update drivers to fix bugs and improve "
                            "security. Use Windows Update or manufacturer websites. "
                            "(2) Monitor for problematic devices and address them promptly. "
                            "(3) Avoid unsigned drivers unless from trusted sources. "
                            "(4) If you experience system instability, check Device Manager for "
                            "devices with warnings or errors. (5) Keep driver software current by "
                            "running manufacturer driver update tools where available."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _get_problem_devices(self) -> list[dict]:
        """Get devices with problem status via PowerShell Get-PnpDevice."""
        try:
            ps_cmd = (
                "Get-PnpDevice | Where-Object {$_.Status -ne 'OK'} | "
                "Select-Object Status, Class, FriendlyName, InstanceId | ConvertTo-Json"
            )
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                timeout=15,
            )
            if result.returncode != 0:
                return []

            return _parse_pnp_devices(result.stdout)
        except (OSError, subprocess.SubprocessError, TimeoutError):
            return []

    def _get_unsigned_drivers(self) -> list[str]:
        """Get unsigned drivers via PowerShell Get-WmiObject."""
        try:
            ps_cmd = (
                "Get-WmiObject Win32_SystemDriver | Where-Object {$_.IsSigned -eq $false} | "
                "Select-Object -ExpandProperty Name | ConvertTo-Json"
            )
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                timeout=15,
            )
            if result.returncode != 0:
                return []

            return _parse_string_array(result.stdout)
        except (OSError, subprocess.SubprocessError, TimeoutError):
            return []

    def _get_stopped_drivers(self) -> list[str]:
        """Get drivers in stopped state via driverquery."""
        try:
            result = subprocess.run(
                ["driverquery", "/v", "/fo", "CSV"],
                capture_output=True,
                text=True,
                timeout=15,
            )
            if result.returncode != 0:
                return []

            return _parse_driverquery_csv(result.stdout, "State", "Stopped")
        except (OSError, subprocess.SubprocessError, TimeoutError):
            return []

    def _get_recent_drivers(self) -> list[str]:
        """Get recently updated drivers (last 30 days) via PowerShell Get-WindowsDriver."""
        try:
            ps_cmd = (
                "Get-WindowsDriver -Online -ErrorAction SilentlyContinue | "
                "Where-Object {$_.Date -gt (Get-Date).AddDays(-30)} | "
                "Select-Object -ExpandProperty OriginalFileName | ConvertTo-Json"
            )
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                timeout=20,
            )
            if result.returncode != 0:
                return []

            return _parse_string_array(result.stdout)
        except (OSError, subprocess.SubprocessError, TimeoutError):
            return []

    def _get_total_driver_count(self) -> int:
        """Get total installed driver count via driverquery."""
        try:
            result = subprocess.run(
                ["driverquery"],
                capture_output=True,
                text=True,
                timeout=15,
            )
            if result.returncode != 0:
                return -1

            # Count lines: skip header (2 lines) and count data rows
            lines = [line.strip() for line in result.stdout.split("\n") if line.strip()]
            if len(lines) > 2:
                return len(lines) - 2
            return 0
        except (OSError, subprocess.SubprocessError, TimeoutError):
            return -1


def _parse_pnp_devices(json_output: str) -> list[dict]:
    """Parse PowerShell JSON output from Get-PnpDevice."""
    devices = []

    if not json_output.strip():
        return devices

    try:
        data = json.loads(json_output)
        if not isinstance(data, list):
            data = [data]

        for device in data:
            devices.append(
                {
                    "status": device.get("Status", "Unknown"),
                    "class": device.get("Class", "Unknown"),
                    "friendly_name": device.get("FriendlyName", "Unknown"),
                    "instance_id": device.get("InstanceId", "Unknown"),
                }
            )
    except (json.JSONDecodeError, ValueError, KeyError, TypeError):
        pass

    return devices


def _parse_string_array(json_output: str) -> list[str]:
    """Parse PowerShell JSON output as array of strings."""
    items = []

    if not json_output.strip():
        return items

    try:
        data = json.loads(json_output)
        if isinstance(data, list):
            items = [str(item) for item in data]
        elif isinstance(data, str):
            items = [data]
    except (json.JSONDecodeError, ValueError, TypeError):
        pass

    return items


def _parse_driverquery_csv(csv_output: str, column_name: str = "State", filter_value: str = "Stopped") -> list[str]:
    """Parse driverquery CSV output looking for drivers with specific column value."""
    drivers = []

    if not csv_output.strip():
        return drivers

    lines = csv_output.strip().split("\n")
    if len(lines) < 2:
        return drivers

    # Parse CSV header (quoted fields)
    header_line = lines[0]
    headers = _parse_csv_line(header_line)

    # Find the column index and driver name index
    column_idx = -1
    name_idx = -1
    for i, header in enumerate(headers):
        if column_name.lower() in header.lower():
            column_idx = i
        if "driver name" in header.lower() or "module name" in header.lower():
            name_idx = i

    if column_idx == -1 or name_idx == -1:
        return drivers

    # Parse data rows
    for line in lines[1:]:
        if not line.strip():
            continue

        fields = _parse_csv_line(line)
        if len(fields) > max(column_idx, name_idx):
            if filter_value in fields[column_idx]:
                drivers.append(fields[name_idx])

    return drivers


def _parse_csv_line(line: str) -> list[str]:
    """Parse a CSV line handling quoted fields."""
    fields = []
    current = ""
    in_quotes = False

    for char in line:
        if char == '"':
            in_quotes = not in_quotes
        elif char == "," and not in_quotes:
            fields.append(current.strip())
            current = ""
        else:
            current += char

    fields.append(current.strip())
    return fields
