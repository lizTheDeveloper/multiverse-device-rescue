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
    name = "time_machine_health"
    category = "integrity"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "15s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # No Time Machine disk: nothing here to check. Whether the Mac is backed
        # up at all (another backup app, sync only, nothing) is time_machine_check's.
        destination_info = self._get_destination_info()
        if destination_info is None:
            findings.append(
                Finding(
                    title="No Time Machine disk to check",
                    description=(
                        "Drive space, the date of the last backup and recent backup errors "
                        "are checked only when Time Machine has a backup disk. Time Machine "
                        "didn't report one, so none of these were checked."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "no_destination_configured"},
                )
            )
            return CheckResult(module_name=self.name, findings=findings)

        # Check if destination is connected
        if not destination_info.get("connected", False):
            findings.append(
                Finding(
                    title=(
                        f"Your backup drive '{destination_info.get('name', 'Unknown')}' "
                        "is not connected"
                    ),
                    description=(
                        "Time Machine is set up to use this drive, but it is currently "
                        "unplugged or not powered on. Your computer is not making backups "
                        "right now.\n\n"
                        "What to do: Plug your backup drive back in. Backups will resume "
                        "automatically once it is connected."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "destination_disconnected", "destination": destination_info},
                )
            )

        # Check available space on destination
        bytes_available = destination_info.get("bytes_available")
        bytes_total = destination_info.get("bytes_total")
        if bytes_available is not None and bytes_total is not None and bytes_total > 0:
            percent_free = (bytes_available / bytes_total) * 100
            if percent_free < 10:
                findings.append(
                    Finding(
                        title=f"Your backup drive is almost full ({percent_free:.1f}% free)",
                        description=(
                            "Your backup drive is nearly full. Time Machine makes room "
                            "by deleting your oldest backups, so you keep less history "
                            "the fuller it gets.\n\n"
                            "What to do: Nothing urgent. If you want to keep older versions "
                            "of your files, move to a larger backup drive."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={
                            "check": "low_destination_space",
                            "percent_free": percent_free,
                            "bytes_available": bytes_available,
                            "bytes_total": bytes_total,
                        },
                    )
                )
            else:
                # INFO level for good space status
                findings.append(
                    Finding(
                        title=f"Backup destination has {percent_free:.1f}% free space",
                        description=f"Available: {self._format_bytes(bytes_available)} / {self._format_bytes(bytes_total)}",
                        severity=Severity.INFO,
                        category=self.category,
                        data={
                            "check": "destination_space_ok",
                            "percent_free": percent_free,
                            "bytes_available": bytes_available,
                            "bytes_total": bytes_total,
                        },
                    )
                )

        # Check last backup date
        last_backup = self._get_last_backup()
        if last_backup is not None:
            days_since = (datetime.now() - last_backup).days
            if days_since > 7:
                findings.append(
                    Finding(
                        title=f"It has been {days_since} days since your last backup",
                        description=(
                            f"Your last backup was on {last_backup.strftime('%Y-%m-%d %H:%M:%S')}. "
                            "Backups should happen regularly to keep your data safe. "
                            "If your drive is connected, check why it is not running.\n\n"
                            "What to do: Open System Settings > General > Time Machine to ensure "
                            "backups are turned on and the drive is selected."
                        ),
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
                # INFO level for recent backup
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
        else:
            findings.append(
                Finding(
                    title="We could not check your last backup date",
                    description=(
                        "We could not read the history of your backups, so we do not know "
                        "when the last one happened. \n\n"
                        "What to do: Try running the checkup again. If it still fails, "
                        "open System Settings > General > Time Machine to check the status manually."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "backup_date_unknown"},
                )
            )

        # Check if backup is currently running
        backup_running = self._check_backup_running()
        if backup_running is True:
            findings.append(
                Finding(
                    title="Time Machine backup is currently running",
                    description="A backup operation is in progress.",
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "backup_running"},
                )
            )

        # Check for recent backup errors in system log
        has_errors = self._check_recent_errors()
        if has_errors:
            findings.append(
                Finding(
                    title="Time Machine reported recent backup errors",
                    description=(
                        "Your Mac's backup system has reported errors recently. This usually "
                        "means a backup did not finish completely. \n\n"
                        "What to do: Open System Settings > General > Time Machine to see if there "
                        "are any specific messages about the backup drive."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "recent_errors"},
                )
            )

        # Add destination info if available
        if destination_info is not None:
            findings.append(
                Finding(
                    title="Time Machine destination info",
                    description=f"Destination: {destination_info.get('name', 'Unknown')} ({destination_info.get('kind', 'Unknown')})",
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
            if check == "destination_disconnected":
                dest_name = finding.data.get("destination", {}).get("name", "backup disk")
                actions.append(
                    Action(
                        title=f"Reconnect '{dest_name}'",
                        description=f"Connect the Time Machine backup disk '{dest_name}' to resume automatic backups.",
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif check == "low_destination_space":
                actions.append(
                    Action(
                        title="Free up space on Time Machine destination",
                        description=(
                            "The backup drive is running low on space. Connect an external drive with more capacity, "
                            "or delete old backups in Time Machine settings to make room for new ones."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif check == "backup_stale":
                actions.append(
                    Action(
                        title="Trigger manual Time Machine backup",
                        description=(
                            "Click the Time Machine icon in the menu bar and select 'Back Up Now' "
                            "to create an immediate backup."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif check == "backup_date_unknown":
                actions.append(
                    Action(
                        title="Check Time Machine configuration",
                        description=(
                            "Open System Settings > General > Time Machine to verify backup "
                            "destination and backup history."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif check == "recent_errors":
                actions.append(
                    Action(
                        title="Review Time Machine error logs",
                        description=(
                            "Open Console.app and search for 'Time Machine' to review recent backup errors. "
                            "Common issues include destination disconnection or insufficient permissions."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _get_destination_info(self) -> dict | None:
        """Get Time Machine backup destination info using tmutil destinationinfo."""
        try:
            result = subprocess.run(
                ["tmutil", "destinationinfo"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0 and result.stdout.strip():
                return self._parse_destination_info(result.stdout)
            return None
        except (OSError, subprocess.SubprocessError, subprocess.TimeoutExpired):
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
                elif key == "id" or key == "destination id":
                    info["id"] = value
                elif key == "kind":
                    info["kind"] = value
                elif key == "mounted":
                    connected = value.lower() in ("yes", "true", "1")
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

    def _get_last_backup(self) -> datetime | None:
        """Get the date of the last backup using tmutil latestbackup."""
        try:
            result = subprocess.run(
                ["tmutil", "latestbackup"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0 and result.stdout.strip():
                path = result.stdout.strip()
                try:
                    backup_path = Path(path)
                    stat = backup_path.stat()
                    return datetime.fromtimestamp(stat.st_mtime)
                except (OSError, ValueError):
                    pass
            return None
        except (OSError, subprocess.SubprocessError, subprocess.TimeoutExpired):
            return None

    def _check_backup_running(self) -> bool | None:
        """Check if backup is currently running via tmutil status."""
        try:
            result = subprocess.run(
                ["tmutil", "status"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0 and result.stdout.strip():
                output = result.stdout.strip()
                return "Running" in output or "backing up" in output.lower()
            return None
        except (OSError, subprocess.SubprocessError, subprocess.TimeoutExpired):
            return None

    def _check_recent_errors(self) -> bool:
        """Check for backup errors in system log from last 24 hours."""
        try:
            result = subprocess.run(
                [
                    "log",
                    "show",
                    "--predicate",
                    'subsystem == "com.apple.TimeMachine"',
                    "--last",
                    "24h",
                    "--style",
                    "compact",
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0 and result.stdout.strip():
                # Check if any line contains error keywords
                output = result.stdout.lower()
                error_keywords = ["error", "failed", "failure", "exception"]
                return any(keyword in output for keyword in error_keywords)
            return False
        except (OSError, subprocess.SubprocessError, subprocess.TimeoutExpired):
            return False

    def _format_bytes(self, bytes_value: int) -> str:
        """Format bytes to human-readable format."""
        for unit in ["B", "KB", "MB", "GB", "TB"]:
            if bytes_value < 1024:
                return f"{bytes_value:.1f} {unit}"
            bytes_value /= 1024
        return f"{bytes_value:.1f} PB"
