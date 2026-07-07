import subprocess
from datetime import datetime, timedelta
from pathlib import Path

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
    name = "backup_status"
    category = "integrity"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "10s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Check if Time Machine is enabled
        is_enabled = self._check_timemachine_enabled()
        if is_enabled is False:
            findings.append(
                Finding(
                    title="Time Machine is disabled",
                    description="Automatic backups are not running. Enable Time Machine to protect against data loss.",
                    severity=Severity.CRITICAL,
                    category=self.category,
                    data={"check": "timemachine_disabled"},
                )
            )
        elif is_enabled is None:
            findings.append(
                Finding(
                    title="Could not determine Time Machine status",
                    description="Unable to read Time Machine configuration.",
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "timemachine_status_unknown"},
                )
            )

        # Check backup destination
        destination_info = self._get_destination_info()
        if destination_info is None:
            findings.append(
                Finding(
                    title="No Time Machine backup destination configured",
                    description="Set up a backup destination in Time Machine settings.",
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "no_destination"},
                )
            )
        elif not destination_info.get("connected", False):
            findings.append(
                Finding(
                    title="Time Machine backup disk is not connected",
                    description=f"Backup destination '{destination_info.get('name', 'Unknown')}' is disconnected.",
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "destination_disconnected", "destination": destination_info},
                )
            )

        # Check last backup date
        last_backup = self._get_last_backup()
        if last_backup is not None:
            days_since = (datetime.now() - last_backup).days
            if days_since > 7:
                findings.append(
                    Finding(
                        title=f"Last backup is {days_since} days old",
                        description=f"Last backup: {last_backup.strftime('%Y-%m-%d %H:%M:%S')}. Backups should run regularly.",
                        severity=Severity.WARNING,
                        category=self.category,
                        data={
                            "check": "backup_stale",
                            "last_backup": last_backup.isoformat(),
                            "days_since": days_since,
                        },
                    )
                )
            else:
                # INFO level for good backup status
                findings.append(
                    Finding(
                        title="Last backup is recent",
                        description=f"Last backup: {last_backup.strftime('%Y-%m-%d %H:%M:%S')} ({days_since} days ago)",
                        severity=Severity.INFO,
                        category=self.category,
                        data={
                            "check": "backup_current",
                            "last_backup": last_backup.isoformat(),
                            "days_since": days_since,
                        },
                    )
                )

        # Add destination info if available
        if destination_info is not None:
            findings.append(
                Finding(
                    title="Time Machine destination info",
                    description=f"Destination: {destination_info.get('name', 'Unknown')} ({destination_info.get('id', 'Unknown')})",
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "destination_info", "destination": destination_info},
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            check = finding.data.get("check")
            if check == "timemachine_disabled":
                actions.append(
                    Action(
                        title="Enable Time Machine",
                        description=(
                            "Open System Settings > General > Time Machine, "
                            "click 'Turn On', and select a backup destination."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif check == "no_destination":
                actions.append(
                    Action(
                        title="Configure Time Machine backup destination",
                        description=(
                            "Open System Settings > General > Time Machine, "
                            "click 'Select Backup Disk', and choose an external drive or network destination."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif check == "destination_disconnected":
                dest_name = finding.data.get("destination", {}).get("name", "backup disk")
                actions.append(
                    Action(
                        title=f"Reconnect '{dest_name}'",
                        description=f"Connect the Time Machine backup disk '{dest_name}' to resume automatic backups.",
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif check == "backup_stale":
                actions.append(
                    Action(
                        title="Trigger manual Time Machine backup",
                        description=(
                            "Click the Time Machine icon in the menu bar and select "
                            "'Back Up Now' to create an immediate backup."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif check == "timemachine_status_unknown":
                actions.append(
                    Action(
                        title="Verify Time Machine configuration",
                        description=(
                            "Open System Settings > General > Time Machine to check "
                            "backup status and configuration."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
        return FixResult(module_name=self.name, actions=actions)

    def _check_timemachine_enabled(self) -> bool | None:
        """Check if Time Machine is enabled via defaults read."""
        try:
            result = subprocess.run(
                [
                    "defaults",
                    "read",
                    "/Library/Preferences/com.apple.TimeMachine",
                    "AutoBackup",
                ],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                return result.stdout.strip() == "1"
            return None
        except (OSError, subprocess.SubprocessError):
            return None

    def _get_last_backup(self) -> datetime | None:
        """Get the date of the last backup using tmutil latestbackup."""
        try:
            result = subprocess.run(
                ["tmutil", "latestbackup"],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0 and result.stdout.strip():
                path = result.stdout.strip()
                # Parse path format: /Volumes/BackupDisk/Backups.backupdb/MachineName/Latest
                # or extract date from the path timestamp
                try:
                    # Try to extract date from path metadata
                    backup_path = Path(path)
                    stat = backup_path.stat()
                    return datetime.fromtimestamp(stat.st_mtime)
                except (OSError, ValueError):
                    pass
            return None
        except (OSError, subprocess.SubprocessError):
            return None

    def _get_destination_info(self) -> dict | None:
        """Get Time Machine backup destination info using tmutil destinationinfo."""
        try:
            result = subprocess.run(
                ["tmutil", "destinationinfo"],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0 and result.stdout.strip():
                return self._parse_destination_info(result.stdout)
            return None
        except (OSError, subprocess.SubprocessError):
            return None

    def _parse_destination_info(self, output: str) -> dict | None:
        """Parse tmutil destinationinfo output."""
        info = {}
        connected = False
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            if ":" in line:
                key, value = line.split(":", 1)
                key = key.strip().lower()
                value = value.strip()
                if key == "name":
                    info["name"] = value
                elif key == "id":
                    info["id"] = value
                elif key == "destination id":
                    info["id"] = value
                elif key == "kind":
                    info["kind"] = value
                elif key == "mounted":
                    connected = value.lower() == "yes"
                elif key == "bytes available":
                    try:
                        info["bytes_available"] = int(value)
                    except ValueError:
                        pass
                elif key == "bytes total":
                    try:
                        info["bytes_total"] = int(value)
                    except ValueError:
                        pass
        if info:
            info["connected"] = connected
            return info
        return None
