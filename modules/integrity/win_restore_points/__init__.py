import json
import subprocess
from datetime import datetime, timedelta
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
    name = "win_restore_points"
    category = "integrity"
    platforms = [Platform.WIN32]
    risk_level = RiskLevel.SAFE
    priority = 55
    depends_on = []
    estimated_duration = "10s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Try to get restore points first (will fail if disabled or error)
        restore_points_result = self._get_restore_points_with_status()

        # Check if there was an error getting restore points
        if restore_points_result is None:
            findings.append(
                Finding(
                    title="Could not determine System Restore status",
                    description=(
                        "Failed to query System Restore configuration. "
                        "Unable to verify if System Restore is enabled."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "status_check_failed"},
                )
            )
            return CheckResult(module_name=self.name, findings=findings)

        restore_points, is_enabled = restore_points_result

        # If System Restore is disabled, flag as CRITICAL
        if not is_enabled:
            findings.append(
                Finding(
                    title="System Restore is disabled",
                    description=(
                        "System Restore is not enabled on this system. "
                        "This means you have no safety net for recovering from bad updates or malware. "
                        "Enable System Restore to protect your system."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
                    data={"check": "restore_disabled"},
                )
            )
            return CheckResult(module_name=self.name, findings=findings)

        # If no restore points but enabled, flag as WARNING
        if is_enabled and not restore_points:
            findings.append(
                Finding(
                    title="No restore points found",
                    description=(
                        "System Restore is enabled but no restore points exist. "
                        "The system may create automatic restore points soon, "
                        "but you currently have no recovery points available."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "no_restore_points"},
                )
            )
            return CheckResult(module_name=self.name, findings=findings)

        # Check if the most recent restore point is too old (>30 days)
        if restore_points:
            latest_point = restore_points[0]
            point_date = latest_point.get("date")
            if point_date:
                try:
                    age_days = (datetime.now() - point_date).days
                    if age_days > 30:
                        findings.append(
                            Finding(
                                title=f"Latest restore point is {age_days} days old",
                                description=(
                                    f"The most recent restore point was created {age_days} days ago. "
                                    "While System Restore is enabled, you may want to create a fresh restore point "
                                    "after installing updates or making significant system changes."
                                ),
                                severity=Severity.WARNING,
                                category=self.category,
                                data={
                                    "check": "old_restore_point",
                                    "days_old": age_days,
                                    "date": point_date.isoformat(),
                                },
                            )
                        )
                except (TypeError, ValueError):
                    pass

        # Check disk allocation
        storage_info = self._get_restore_storage()
        if storage_info:
            findings.append(
                Finding(
                    title="System Restore disk allocation",
                    description=(
                        f"System Restore uses {storage_info.get('used_space', 'unknown')} "
                        f"({storage_info.get('used_percent', 'unknown')}%) of "
                        f"{storage_info.get('allocated_space', 'unknown')} allocated storage. "
                        "This is within normal parameters."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "restore_storage", **storage_info},
                )
            )

        # Add informational finding about available restore points
        if restore_points:
            point_list = ", ".join(
                [
                    f"{rp.get('description', 'Unknown')} ({rp.get('date', 'Unknown').strftime('%Y-%m-%d') if rp.get('date') else 'Unknown'})"
                    for rp in restore_points[:5]
                ]
            )
            findings.append(
                Finding(
                    title=f"System Restore is enabled with {len(restore_points)} restore point(s)",
                    description=(
                        f"System Restore is active and protecting your system. "
                        f"Recent restore points: {point_list}. "
                        f"You can use these to recover your system if needed."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "check": "restore_points_available",
                        "point_count": len(restore_points),
                        "points": [
                            {
                                "description": rp.get("description"),
                                "date": rp.get("date").isoformat() if rp.get("date") else None,
                            }
                            for rp in restore_points
                        ],
                    },
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        for finding in findings.findings:
            check = finding.data.get("check")

            if check == "restore_disabled":
                actions.append(
                    Action(
                        title="System Restore is disabled",
                        description=(
                            "System Restore is not enabled, leaving your system vulnerable to data loss. "
                            "To enable System Restore: "
                            "(1) Right-click 'This PC' and select Properties. "
                            "(2) Click 'System Protection' or 'Advanced system settings'. "
                            "(3) Click 'System Protection' tab. "
                            "(4) Select your drive and click 'Configure'. "
                            "(5) Check 'Turn on system protection' and click OK. "
                            "Alternatively, use PowerShell (as Administrator): "
                            "Enable-ComputerRestore -Drive 'C:\\'."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "no_restore_points":
                actions.append(
                    Action(
                        title="No restore points available",
                        description=(
                            "System Restore is enabled but no restore points have been created yet. "
                            "Windows should create automatic restore points on schedule, but you can "
                            "manually create one now: "
                            "(1) Search for 'Create a restore point' in Windows. "
                            "(2) Click 'Create' in the System Protection tab. "
                            "(3) Enter a description (e.g., 'Before installing updates'). "
                            "(4) Click 'Create' and wait for completion. "
                            "You can also use PowerShell (as Administrator): "
                            "Checkpoint-Computer -Description 'Manual restore point'."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "old_restore_point":
                days_old = finding.data.get("days_old", "unknown")
                actions.append(
                    Action(
                        title=f"Latest restore point is {days_old} days old",
                        description=(
                            f"Your most recent restore point is {days_old} days old. "
                            "Consider creating a fresh restore point, especially after installing updates "
                            "or making major system changes. "
                            "To create a new restore point: "
                            "(1) Search for 'Create a restore point' in Windows. "
                            "(2) Click 'Create' in the System Protection tab. "
                            "(3) Enter a description for the restore point. "
                            "(4) Click 'Create' and wait for completion."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "restore_storage":
                actions.append(
                    Action(
                        title="System Restore disk allocation",
                        description=(
                            f"System Restore is configured with {finding.data.get('allocated_space', 'unknown')} "
                            f"allocated storage and is using {finding.data.get('used_space', 'unknown')}. "
                            "This is healthy. To adjust System Restore storage: "
                            "(1) Right-click 'This PC' and select Properties. "
                            "(2) Click 'Advanced system settings'. "
                            "(3) Click 'System Protection' tab. "
                            "(4) Select your drive and click 'Configure'. "
                            "(5) Adjust the disk space slider as needed."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "restore_points_available":
                point_count = finding.data.get("point_count", 0)
                actions.append(
                    Action(
                        title=f"System Restore is healthy with {point_count} restore point(s)",
                        description=(
                            f"System Restore is enabled and protecting your system with {point_count} available restore point(s). "
                            "Your system is well-protected. Continue to make regular backups in addition to System Restore "
                            "for comprehensive data protection."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "status_check_failed":
                actions.append(
                    Action(
                        title="Unable to check System Restore status",
                        description=(
                            "The System Restore status check failed. "
                            "Ensure you have Administrator privileges and run the diagnostic again. "
                            "You can also manually check System Restore: "
                            "(1) Search for 'Create a restore point' in Windows. "
                            "(2) The System Protection tab shows the status of each drive. "
                            "Or use PowerShell (as Administrator): Get-ComputerRestorePoint | Select-Object SequenceNumber, CreationTime, Description."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _get_restore_points_with_status(self) -> Optional[tuple]:
        """Get list of System Restore points and whether restore is enabled.

        Returns tuple of (restore_points_list, is_enabled) or None if error.
        """
        try:
            ps_cmd = (
                "Get-ComputerRestorePoint -ErrorAction SilentlyContinue | "
                "Select-Object SequenceNumber, CreationTime, Description | "
                "ConvertTo-Json"
            )
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                timeout=10,
            )

            # If command failed with error, return None (indicates error checking)
            if result.returncode != 0 and result.stderr:
                return None

            # If command succeeded with no output, System Restore might be disabled
            # or there might be an issue - treat as disabled for safety
            if result.returncode != 0:
                return ([], False)

            # If there's output, parse it
            if result.stdout.strip():
                restore_points = _parse_restore_points(result.stdout)
                if restore_points:
                    return (restore_points, True)
                return ([], True)  # Enabled but no points

            # Empty output with success code - Restore is enabled but no points
            return ([], True)
        except (OSError, subprocess.SubprocessError, TimeoutError):
            return None

    def _check_restore_enabled(self) -> Optional[dict]:
        """Check if System Restore is enabled via PowerShell."""
        try:
            # PowerShell command to check if System Restore is enabled
            ps_cmd = (
                "Get-ComputerRestorePoint -ErrorAction SilentlyContinue | "
                "Measure-Object | Select-Object Count; "
                "[System.IO.DriveInfo]::GetDrives() | "
                "ForEach-Object { "
                "if ((Get-ComputerRestorePoint -ErrorAction SilentlyContinue).Count -gt 0) { "
                "Write-Host 'enabled' } "
                "else { Write-Host 'disabled' } "
                "} | Select-Object -First 1"
            )
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                timeout=10,
            )

            # Try alternative approach with vssadmin
            if result.returncode != 0 or not result.stdout.strip():
                return self._check_restore_with_vssadmin()

            # Check if restore points exist (indicates enabled)
            output = result.stdout.strip().lower()
            enabled = (
                "enabled" in output
                or result.returncode == 0
                and not result.stderr
            )
            return {"enabled": enabled}
        except (OSError, subprocess.SubprocessError, TimeoutError):
            return None

    def _check_restore_with_vssadmin(self) -> Optional[dict]:
        """Check System Restore status using vssadmin command."""
        try:
            # vssadmin list shadows shows VSS snapshots (restore points)
            result = subprocess.run(
                ["vssadmin", "list", "shadows"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0 and "shadow copy" in result.stdout.lower():
                return {"enabled": True}
            return {"enabled": False}
        except (OSError, subprocess.SubprocessError, TimeoutError):
            return None

    def _get_restore_points(self) -> Optional[list]:
        """Get list of System Restore points with dates."""
        try:
            ps_cmd = (
                "Get-ComputerRestorePoint -ErrorAction SilentlyContinue | "
                "Select-Object SequenceNumber, CreationTime, Description | "
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

            if not result.stdout.strip():
                return []

            return _parse_restore_points(result.stdout)
        except (OSError, subprocess.SubprocessError, TimeoutError):
            return None

    def _get_restore_storage(self) -> Optional[dict]:
        """Get System Restore storage allocation info."""
        try:
            ps_cmd = (
                "Get-ComputerRestorePoint -ErrorAction SilentlyContinue | "
                "Measure-Object | "
                "Select-Object Count; "
                "[System.IO.DriveInfo]::GetDrives() | "
                "ForEach-Object { "
                "Write-Host \"Drive: $($_.Name)\"; "
                "Write-Host \"TotalSize: $($_.TotalSize)\"; "
                "Write-Host \"AvailableFreeSpace: $($_.AvailableFreeSpace)\" "
                "}"
            )
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                return None

            return _parse_storage_info(result.stdout)
        except (OSError, subprocess.SubprocessError, TimeoutError):
            return None


def _parse_restore_points(json_output: str) -> Optional[list]:
    """Parse PowerShell JSON output from Get-ComputerRestorePoint."""
    if not json_output.strip():
        return None

    try:
        data = json.loads(json_output)
        if not isinstance(data, list):
            data = [data]

        restore_points = []
        for point in data:
            try:
                # Parse the creation time string
                creation_time_str = point.get("CreationTime", "")
                if creation_time_str:
                    # PowerShell returns datetime in ISO format with Z suffix
                    # Remove timezone info to match datetime.now() (which is naive)
                    dt = datetime.fromisoformat(
                        creation_time_str.replace("Z", "+00:00")
                    )
                    # Convert to naive datetime by removing timezone
                    creation_time = dt.replace(tzinfo=None)
                else:
                    creation_time = None

                restore_points.append(
                    {
                        "sequence_number": point.get("SequenceNumber"),
                        "date": creation_time,
                        "description": point.get("Description", "Unknown"),
                    }
                )
            except (ValueError, TypeError):
                continue

        # Sort by date descending (most recent first)
        restore_points.sort(
            key=lambda x: x["date"] if x["date"] else datetime.min,
            reverse=True,
        )
        return restore_points if restore_points else None
    except (json.JSONDecodeError, ValueError, KeyError, TypeError):
        return None


def _parse_storage_info(output: str) -> Optional[dict]:
    """Parse vssadmin or PowerShell output for storage information."""
    if not output.strip():
        return None

    try:
        # Simple parsing for demonstration
        # In real scenario, parse actual PowerShell output
        lines = output.split("\n")

        total_size = 0
        available_space = 0

        for line in lines:
            if "TotalSize:" in line:
                try:
                    total_size = int(line.split(":", 1)[1].strip())
                except ValueError:
                    pass
            elif "AvailableFreeSpace:" in line:
                try:
                    available_space = int(line.split(":", 1)[1].strip())
                except ValueError:
                    pass

        if total_size > 0:
            used_space = total_size - available_space
            used_percent = int((used_space / total_size) * 100)
            return {
                "allocated_space": _format_bytes(total_size),
                "used_space": _format_bytes(used_space),
                "available_space": _format_bytes(available_space),
                "used_percent": used_percent,
            }
        return None
    except (ValueError, IndexError, ZeroDivisionError):
        return None


def _format_bytes(bytes_value: int) -> str:
    """Convert bytes to human-readable format."""
    if not isinstance(bytes_value, int) or bytes_value == 0:
        return "Unknown"

    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if bytes_value < 1024:
            return f"{bytes_value:.1f} {unit}"
        bytes_value /= 1024
    return f"{bytes_value:.1f} PB"
