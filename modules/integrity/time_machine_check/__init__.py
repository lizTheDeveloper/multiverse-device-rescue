import re
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
    name = "time_machine_check"
    category = "integrity"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "5s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Check if Time Machine is configured at all
        is_configured = self._check_tm_configured()
        if is_configured is None:
            findings.append(
                Finding(
                    title="Couldn't check your Time Machine backups",
                    description=(
                        "Device Rescue couldn't read your Time Machine settings, so it "
                        "doesn't know whether backups are set up. This is not a sign that "
                        "anything is wrong. To see for yourself, open System Settings > "
                        "General > Time Machine."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "tm_unknown"},
                )
            )
            return CheckResult(module_name=self.name, findings=findings)
        if not is_configured:
            findings.append(
                Finding(
                    title="Your Mac is not automatically backing up your files",
                    description=(
                        "We could not find a backup destination set up on this Mac. "
                        "This means if you accidentally delete a file or your drive fails, "
                        "you might not be able to get your data back. "
                        "\n\n"
                        "What to do: Plug in an external drive, open System Settings > "
                        "General > Time Machine, click Add Backup Disk, and choose it."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
                    data={"check": "not_configured"},
                )
            )
            return CheckResult(module_name=self.name, findings=findings)

        # Check last backup date
        latest_backup = self._get_latest_backup()
        if latest_backup:
            days_ago = (datetime.now() - latest_backup).days
            if days_ago > 30:
                findings.append(
                    Finding(
                        title=f"Your last backup is {days_ago} days old",
                        description=(
                            f"Your most recent backup was {days_ago} days ago ({latest_backup.strftime('%Y-%m-%d %H:%M:%S')}). "
                            "Backups this old may not include your recent files. If something "
                            "goes wrong now, you might lose data created since that date. "
                            "This usually happens if the backup drive was disconnected.\n\n"
                            "What to do: Connect your backup drive, then click the Time "
                            "Machine icon in the menu bar and choose Back Up Now."
                        ),
                        severity=Severity.CRITICAL,
                        category=self.category,
                        data={"check": "stale_backup", "days_ago": days_ago, "last_backup": latest_backup.isoformat()},
                    )
                )
            elif days_ago > 7:
                findings.append(
                    Finding(
                        title=f"Your last backup is {days_ago} days old",
                        description=(
                            f"Your most recent backup was {days_ago} days ago ({latest_backup.strftime('%Y-%m-%d %H:%M:%S')}). "
                            "This is not an emergency, but it is older than the recommended "
                            "daily backup. "
                            "You are likely safe, but you may be missing very recent changes "
                            "if you need to restore files.\n\n"
                            "What to do: Connect your backup drive, then click the Time "
                            "Machine icon in the menu bar and choose Back Up Now."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={"check": "aging_backup", "days_ago": days_ago, "last_backup": latest_backup.isoformat()},
                    )
                )
            else:
                findings.append(
                    Finding(
                        title=f"Time Machine backup recent ({days_ago} days old)",
                        description=(
                            f"Last backup was {days_ago} days ago ({latest_backup.strftime('%Y-%m-%d %H:%M:%S')}). "
                            "Backups are current and up-to-date."
                        ),
                        severity=Severity.INFO,
                        category=self.category,
                        data={"check": "recent_backup", "days_ago": days_ago, "last_backup": latest_backup.isoformat()},
                    )
                )
        else:
            findings.append(
                Finding(
                    title="We could not check your last backup date",
                    description=(
                        "Time Machine is set up, but we could not read the date of your "
                        "most recent backup. "
                        "This might mean a backup has never finished, or the backup drive "
                        "is currently disconnected. "
                        "This is not a security threat, but it means we cannot confirm "
                        "your data is safe.\n\n"
                        "What to do: Open System Settings > General > Time Machine and "
                        "check that a backup disk is listed. If it is, connect it and "
                        "choose Back Up Now from the Time Machine icon in the menu bar."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "no_backup_date"},
                )
            )

        # Check if automatic backups are enabled
        status_info = self._get_tm_status()
        if status_info and not status_info.get("automatic_backups"):
            findings.append(
                Finding(
                    title="Automatic backups are turned off",
                    description=(
                        "Your Mac is set to back up only when you manually ask it to. "
                        "If you forget to start a backup, your files will not be protected. "
                        "Turning on automatic backups ensures your data is saved regularly "
                        "without you having to think about it.\n\n"
                        "What to do: Open System Settings > General > Time Machine, click "
                        "Options, and set how often to back up to Automatically every hour."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "backups_disabled"},
                )
            )

        # Check backup destination info
        dest_info = self._get_destination_info()
        if dest_info:
            findings.append(
                Finding(
                    title="Time Machine destination status",
                    description=(
                        f"Backup destination: {dest_info.get('destination_name', 'Unknown')}. "
                        f"Mount point: {dest_info.get('mount_point', 'N/A')}. "
                        f"Backup ID: {dest_info.get('backup_id', 'N/A')}. "
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "destination_info", **dest_info},
                )
            )

        # Check backup exclusions
        exclusions = self._get_backup_exclusions()
        if exclusions:
            findings.append(
                Finding(
                    title=f"Time Machine has {len(exclusions)} exclusions",
                    description=(
                        f"The following paths are excluded from Time Machine backup: {', '.join(exclusions)}. "
                        "Verify that important files are not accidentally excluded."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "exclusions", "count": len(exclusions), "exclusions": exclusions},
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        for finding in findings.findings:
            check = finding.data.get("check")

            if check == "not_configured":
                actions.append(
                    Action(
                        title="Enable Time Machine in System Settings",
                        description=(
                            "To enable Time Machine: "
                            "1. Open System Settings > General > Time Machine "
                            "2. Click 'Turn On' "
                            "3. Select a destination drive (external hard drive or Time Capsule recommended) "
                            "4. Let Time Machine complete its initial backup (this can take hours) "
                            "Time Machine will then back up automatically every hour."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "stale_backup":
                days_ago = finding.data.get("days_ago", "unknown")
                actions.append(
                    Action(
                        title=f"Address stale Time Machine backup ({days_ago} days old)",
                        description=(
                            f"Your last backup was {days_ago} days ago. To fix this: "
                            "1. Check that your backup destination drive is connected and available "
                            "2. Open System Settings > General > Time Machine "
                            "3. Click 'Backup Now' to force an immediate backup "
                            "4. Wait for the backup to complete (monitor progress in Time Machine icon in menu bar) "
                            "5. Verify the backup completes successfully in Time Machine settings"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "aging_backup":
                days_ago = finding.data.get("days_ago", "unknown")
                actions.append(
                    Action(
                        title=f"Time Machine backup is aging ({days_ago} days old)",
                        description=(
                            f"While your backup from {days_ago} days ago is recent, daily backups are recommended. "
                            "To ensure regular backups: "
                            "1. Verify your backup destination drive is connected "
                            "2. Open System Settings > General > Time Machine "
                            "3. Ensure 'Back Up Automatically' is enabled "
                            "4. Consider clicking 'Backup Now' for immediate backup"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "recent_backup":
                actions.append(
                    Action(
                        title="Time Machine backups are current",
                        description=(
                            "Your Time Machine backups are current and up-to-date. "
                            "Continue to keep your backup destination connected and available. "
                            "Automatic backups will continue hourly when the destination is accessible."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "no_backup_date":
                actions.append(
                    Action(
                        title="Investigate Time Machine backup status",
                        description=(
                            "Time Machine appears configured but no backup date could be retrieved. "
                            "To diagnose: "
                            "1. Open System Settings > General > Time Machine "
                            "2. Verify a backup destination is selected "
                            "3. Click 'Backup Now' to manually trigger a backup "
                            "4. Wait for the backup to complete "
                            "If backups continue to fail, try selecting a different destination or reconnecting your backup drive."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "backups_disabled":
                actions.append(
                    Action(
                        title="Enable automatic Time Machine backups",
                        description=(
                            "To enable automatic backups: "
                            "1. Open System Settings > General > Time Machine "
                            "2. Toggle 'Back Up Automatically' ON "
                            "3. Ensure your backup destination is connected "
                            "Time Machine will then automatically back up every hour."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "destination_info":
                destination = finding.data.get("destination_name", "unknown")
                actions.append(
                    Action(
                        title=f"Time Machine destination: {destination}",
                        description=(
                            f"Your Time Machine backup destination is configured as: {destination}. "
                            "Keep this destination connected for Time Machine to perform automatic backups. "
                            "If the destination is unavailable, backups will pause until it's reconnected."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "exclusions":
                count = finding.data.get("count", 0)
                actions.append(
                    Action(
                        title=f"Review Time Machine exclusions ({count} items)",
                        description=(
                            f"You have {count} items excluded from Time Machine backup. "
                            "Verify these exclusions are intentional. Large folders like caches, downloads, or temporary files "
                            "are commonly excluded to save space. To review or modify exclusions: "
                            "1. Open System Settings > General > Time Machine "
                            "2. Click 'Options...' "
                            "3. Review and modify the exclusion list as needed"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _check_tm_configured(self) -> bool | None:
        """Does Time Machine have a backup destination? None if it couldn't tell.

        The preferences file exists on every Mac (it holds at least
        PreferencesVersion), so "the file is readable" used to count as "Time
        Machine is set up" and produced "We could not check your last backup
        date" on a Mac with no backup disk. `tmutil destinationinfo` is the
        source of truth; the plist's Destinations key is the fallback.
        """
        try:
            result = subprocess.run(
                ["tmutil", "destinationinfo"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            text = "\n".join(
                part for part in (result.stdout, result.stderr) if isinstance(part, str)
            )
            if "No destinations configured" in text:
                return False
            if result.returncode == 0 and re.search(
                r"^\s*(Name|ID|Kind|URL)\s*:", text, re.MULTILINE
            ):
                return True
        except (OSError, subprocess.SubprocessError):
            pass
        try:
            result = subprocess.run(
                ["defaults", "read", "/Library/Preferences/com.apple.TimeMachine"],
                capture_output=True,
                text=True,
                timeout=5,
            )
        except (OSError, subprocess.SubprocessError):
            return None
        if result.returncode != 0:
            return False  # no Time Machine preferences: never set up
        out = result.stdout if isinstance(result.stdout, str) else ""
        return "Destinations" in out

    def _get_latest_backup(self) -> datetime | None:
        """Get the date of the last Time Machine backup via tmutil latestbackup."""
        try:
            result = subprocess.run(
                ["tmutil", "latestbackup"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0 and result.stdout.strip():
                backup_path = result.stdout.strip()
                # Path format: /Volumes/BackupDisk/Backups.backupdb/MacBook/2024-07-08-123456
                # Extract timestamp from the last path component
                timestamp_str = backup_path.split("/")[-1]
                # Parse timestamp format: YYYY-MM-DD-HHMMSS
                if "-" in timestamp_str:
                    try:
                        # Split into date and time parts
                        parts = timestamp_str.split("-")
                        if len(parts) >= 4:
                            year = int(parts[0])
                            month = int(parts[1])
                            day = int(parts[2])
                            time_str = parts[3]
                            hour = int(time_str[0:2])
                            minute = int(time_str[2:4])
                            second = int(time_str[4:6])
                            return datetime(year, month, day, hour, minute, second)
                    except (ValueError, IndexError):
                        pass
            return None
        except (OSError, subprocess.SubprocessError, subprocess.TimeoutExpired):
            return None

    def _get_tm_status(self) -> dict | None:
        """Get Time Machine status via tmutil status."""
        try:
            result = subprocess.run(
                ["tmutil", "status"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                status_info = {}
                output = result.stdout.strip()
                # Look for "BackupPhase" key to determine if backups are running
                # and "AutoBackup" to check if automatic backups are enabled
                if "AutoBackup" in output:
                    # Parse key-value pairs from output
                    for line in output.split("\n"):
                        if "AutoBackup" in line:
                            # Extract value: AutoBackup = 1
                            value = "1" in line or "true" in line.lower()
                            status_info["automatic_backups"] = value
                else:
                    # If AutoBackup not in output, assume enabled if tmutil reports success
                    status_info["automatic_backups"] = True
                return status_info if status_info else None
            return None
        except (OSError, subprocess.SubprocessError, subprocess.TimeoutExpired):
            return None

    def _get_destination_info(self) -> dict | None:
        """Get Time Machine destination info via tmutil destinationinfo."""
        try:
            result = subprocess.run(
                ["tmutil", "destinationinfo"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0 and result.stdout.strip():
                dest_info = {}
                output = result.stdout.strip()
                # Parse output format:
                # Backup Destination Information
                # Name: Backup Disk
                # Kind: Local
                # Mount Point: /Volumes/BackupDisk
                # ID: <backup-id>
                for line in output.split("\n"):
                    if ": " in line:
                        key, value = line.split(": ", 1)
                        key = key.strip().lower().replace(" ", "_")
                        dest_info[key] = value.strip()
                return dest_info if dest_info else None
            return None
        except (OSError, subprocess.SubprocessError, subprocess.TimeoutExpired):
            return None

    def _get_backup_exclusions(self) -> list[str]:
        """Get list of excluded paths from Time Machine backup."""
        try:
            result = subprocess.run(
                ["defaults", "read", "/Library/Preferences/com.apple.TimeMachine", "ExcludeByPath"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0 and result.stdout.strip():
                output = result.stdout.strip()
                # Parse plist array format: ( "/path1", "/path2", ... )
                exclusions = []
                for line in output.split("\n"):
                    # Extract quoted paths
                    matches = re.findall(r'"([^"]+)"', line)
                    exclusions.extend(matches)
                return exclusions
            return []
        except (OSError, subprocess.SubprocessError, subprocess.TimeoutExpired):
            return []
