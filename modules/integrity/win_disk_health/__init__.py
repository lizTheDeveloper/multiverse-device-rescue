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
    name = "win_disk_health"
    category = "integrity"
    platforms = [Platform.WIN32]
    risk_level = RiskLevel.SAFE
    priority = 60
    depends_on = []
    estimated_duration = "15s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Get physical disk information
        disk_info = self._get_disk_info()
        if not disk_info:
            findings.append(
                Finding(
                    title="Could not retrieve disk information",
                    description=(
                        "Failed to run Get-PhysicalDisk. Disk health cannot be assessed."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "disk_info_failed"},
                )
            )
            return CheckResult(module_name=self.name, findings=findings)

        # Check for unhealthy disks
        unhealthy_disks = disk_info.get("unhealthy_disks", [])
        if unhealthy_disks:
            for disk in unhealthy_disks:
                findings.append(
                    Finding(
                        title=f"Disk unhealthy: {disk['type']} ({disk['size']})",
                        description=(
                            f"Physical disk with {disk['type']} media type is reporting "
                            f"unhealthy status: {disk['health_status']} ({disk['operational_status']}). "
                            "This may indicate disk failure. Back up your data immediately."
                        ),
                        severity=Severity.CRITICAL,
                        category=self.category,
                        data={
                            "check": "unhealthy_disk",
                            "disk_type": disk["type"],
                            "health_status": disk["health_status"],
                            "operational_status": disk["operational_status"],
                            "size": disk["size"],
                        },
                    )
                )

        # Check for disk errors in event log
        disk_errors = self._get_disk_errors()
        if disk_errors:
            findings.append(
                Finding(
                    title=f"Disk errors found in event log",
                    description=(
                        f"Found {disk_errors['error_count']} disk-related errors in the System event log. "
                        "This may indicate hardware issues or data corruption."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "check": "disk_errors",
                        "error_count": disk_errors["error_count"],
                    },
                )
            )

        # Add informational findings about healthy disks
        healthy_disks = disk_info.get("healthy_disks", [])
        if healthy_disks and not unhealthy_disks:
            # Add summary info about all healthy disks
            disk_summary = ", ".join(
                [f"{disk['count']} {disk['type']}" for disk in healthy_disks]
            )
            total_capacity = disk_info.get("total_capacity", "unknown")

            findings.append(
                Finding(
                    title="All disks healthy",
                    description=(
                        f"All physical disks are healthy. Disk configuration: {disk_summary}. "
                        f"Total capacity: {total_capacity}. No issues detected."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "check": "disks_healthy",
                        "disk_summary": disk_summary,
                        "healthy_disks": healthy_disks,
                    },
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        for finding in findings.findings:
            check = finding.data.get("check")

            if check == "unhealthy_disk":
                disk_type = finding.data.get("disk_type")
                health_status = finding.data.get("health_status")
                actions.append(
                    Action(
                        title=f"Disk {disk_type} unhealthy",
                        description=(
                            f"A {disk_type} disk is reporting unhealthy status: {health_status}. "
                            "This may indicate disk failure. "
                            "Recommendations: (1) Back up all data immediately to an external drive. "
                            "(2) Verify backups are readable and complete. "
                            "(3) Do not continue using the device for critical work. "
                            "(4) Contact a qualified technician or manufacturer support "
                            "for disk replacement."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "disk_errors":
                error_count = finding.data.get("error_count", 0)
                actions.append(
                    Action(
                        title=f"Disk errors detected ({error_count} events)",
                        description=(
                            f"Found {error_count} disk-related error events in the System event log. "
                            "Recommendations: (1) Back up important data immediately. "
                            "(2) Run Windows Disk Check (chkdsk) to scan for file system errors. "
                            "(3) Monitor disk health closely for recurring errors. "
                            "(4) If errors persist, prepare for disk replacement."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "disk_info_failed":
                actions.append(
                    Action(
                        title="Unable to assess disk health",
                        description=(
                            "The Get-PhysicalDisk command failed. "
                            "Ensure you have Administrator privileges and run the diagnostic again. "
                            "Try running the following in PowerShell (as Administrator): "
                            "Get-PhysicalDisk | Select-Object MediaType, HealthStatus, OperationalStatus"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "disks_healthy":
                actions.append(
                    Action(
                        title="All disks healthy",
                        description=(
                            "All physical disks are healthy and functioning normally. "
                            "Continue regular backups to protect your data."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _get_disk_info(self) -> Optional[dict]:
        """Get disk information from PowerShell Get-PhysicalDisk."""
        try:
            # PowerShell command to get physical disks in JSON format
            ps_cmd = (
                "Get-PhysicalDisk | Select-Object MediaType, HealthStatus, OperationalStatus, Size | "
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

            return _parse_disk_info(result.stdout)
        except (OSError, subprocess.SubprocessError, TimeoutError):
            return None

    def _get_disk_errors(self) -> Optional[dict]:
        """Check for disk errors in the Windows System event log."""
        try:
            # PowerShell command to get disk error events (IDs: 7, 11, 51, 55)
            ps_cmd = (
                "Get-WinEvent -FilterHashtable @{LogName='System'; Id=7,11,51,55} "
                "-MaxEvents 10 -ErrorAction SilentlyContinue | Measure-Object | "
                "Select-Object Count"
            )
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                return None

            # Parse output to extract count
            error_count = _parse_event_count(result.stdout)
            if error_count and error_count > 0:
                return {"error_count": error_count}
            return None
        except (OSError, subprocess.SubprocessError, TimeoutError):
            return None


def _parse_disk_info(json_output: str) -> dict:
    """Parse PowerShell JSON output from Get-PhysicalDisk."""
    info = {"healthy_disks": [], "unhealthy_disks": [], "total_capacity": "unknown"}

    if not json_output.strip():
        return info

    try:
        # Handle both single object and array
        data = json.loads(json_output)
        if not isinstance(data, list):
            data = [data]

        disk_counts = {}
        total_bytes = 0

        for disk in data:
            media_type = disk.get("MediaType", "Unknown")
            health_status = disk.get("HealthStatus", "Unknown")
            operational_status = disk.get("OperationalStatus", "Unknown")
            size = disk.get("Size", 0)

            total_bytes += size if isinstance(size, int) else 0

            # Categorize as healthy or unhealthy
            if health_status != "Healthy" or operational_status != "OK":
                info["unhealthy_disks"].append(
                    {
                        "type": media_type,
                        "health_status": health_status,
                        "operational_status": operational_status,
                        "size": _format_bytes(size),
                    }
                )
            else:
                # Count healthy disks by type
                if media_type not in disk_counts:
                    disk_counts[media_type] = 0
                disk_counts[media_type] += 1

        # Format healthy disks list
        for disk_type, count in disk_counts.items():
            info["healthy_disks"].append({"type": disk_type, "count": count})

        # Format total capacity
        if total_bytes > 0:
            info["total_capacity"] = _format_bytes(total_bytes)

        return info
    except (json.JSONDecodeError, ValueError, KeyError):
        return info


def _parse_event_count(output: str) -> int:
    """Extract count from PowerShell Measure-Object output."""
    try:
        # Look for "Count" or "Count :" in output
        for line in output.split("\n"):
            if "count" in line.lower():
                # Extract the number
                parts = line.split()
                for part in parts:
                    if part.isdigit():
                        return int(part)
        return 0
    except (ValueError, IndexError):
        return 0


def _format_bytes(bytes_value: int) -> str:
    """Convert bytes to human-readable format."""
    if not isinstance(bytes_value, int) or bytes_value == 0:
        return "Unknown"

    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if bytes_value < 1024:
            return f"{bytes_value:.1f} {unit}"
        bytes_value /= 1024
    return f"{bytes_value:.1f} PB"
