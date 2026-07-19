import csv
import io
import re
import subprocess
from datetime import datetime, timedelta

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
    name = "win_scheduled_tasks_security"
    category = "security"
    platforms = [Platform.WIN32]
    risk_level = RiskLevel.SAFE
    priority = 55
    depends_on = []
    estimated_duration = "10s"

    emits_codes = [
        "security.win_scheduled_tasks_security.enumeration_failed",
        "security.win_scheduled_tasks_security.encoded_powershell",
        "security.win_scheduled_tasks_security.temp_path_system",
        "security.win_scheduled_tasks_security.non_microsoft_system",
        "security.win_scheduled_tasks_security.frequent_schedule",
        "security.win_scheduled_tasks_security.recent_boot_logon",
        "security.win_scheduled_tasks_security.hidden_attributes",
        "security.win_scheduled_tasks_security.inventory",
    ]

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []
        tasks = self._get_scheduled_tasks()

        if not tasks:
            findings.append(
                Finding(
                    title="Unable to enumerate scheduled tasks",
                    description="Could not retrieve scheduled tasks. This may be a permission issue.",
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.win_scheduled_tasks_security.enumeration_failed",
                    data={},
                )
            )
            return CheckResult(module_name=self.name, findings=findings)

        total_count = len(tasks)
        recent_tasks = []
        suspicious_tasks = []

        # Analyze each task
        for task in tasks:
            task_name = task.get("TaskName", "Unknown")
            task_path = task.get("TaskPath", "")
            command = task.get("Task To Run", "").strip('"')  # Remove quotes from CSV
            run_as_user = task.get("RunAsUser", "").strip('"')
            created_date_str = task.get("Created", "").strip('"')
            status = task.get("Status", "Unknown")
            schedule = task.get("ScheduleType", "").strip('"')
            attributes = task.get("Attributes", "").strip('"')

            # Skip Microsoft-owned tasks
            if self._is_microsoft_task(task_name, task_path, run_as_user, command):
                continue

            # Check for encoded PowerShell (CRITICAL)
            if self._has_encoded_powershell(command):
                suspicious_tasks.append(task)
                findings.append(
                    Finding(
                        title=f"Scheduled task with encoded PowerShell command",
                        description=(
                            f"Scheduled task '{task_name}' runs an encoded PowerShell command. "
                            f"This is a strong indicator of malware persistence. "
                            f"Command: {command[:100]}..."
                        ),
                        severity=Severity.CRITICAL,
                        category=self.category,
                        code="security.win_scheduled_tasks_security.encoded_powershell",
                        data={
                            "task_name": task_name,
                            "task_path": task_path,
                            "command": command,
                            "run_as_user": run_as_user,
                        },
                    )
                )

            # Check for temp directory execution as SYSTEM (CRITICAL)
            elif self._is_temp_path(command) and run_as_user == "SYSTEM":
                suspicious_tasks.append(task)
                findings.append(
                    Finding(
                        title=f"Scheduled task executing from temp directory as SYSTEM",
                        description=(
                            f"Scheduled task '{task_name}' executes from a temporary directory with SYSTEM privileges. "
                            f"This is a strong indicator of malware persistence. "
                            f"Command: {command}"
                        ),
                        severity=Severity.CRITICAL,
                        category=self.category,
                        code="security.win_scheduled_tasks_security.temp_path_system",
                        data={
                            "task_name": task_name,
                            "task_path": task_path,
                            "command": command,
                        },
                    )
                )

            # Check for non-Microsoft SYSTEM tasks (WARNING)
            elif run_as_user == "SYSTEM":
                suspicious_tasks.append(task)
                findings.append(
                    Finding(
                        title=f"Non-Microsoft scheduled task running as SYSTEM",
                        description=(
                            f"Scheduled task '{task_name}' runs with SYSTEM privileges. "
                            f"This is unusual and may indicate persistence or privilege escalation. "
                            f"Command: {command[:100]}..."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        code="security.win_scheduled_tasks_security.non_microsoft_system",
                        data={
                            "task_name": task_name,
                            "task_path": task_path,
                            "command": command,
                        },
                    )
                )

            # Check for very frequent schedules (WARNING)
            if self._is_frequent_schedule(schedule):
                suspicious_tasks.append(task)
                findings.append(
                    Finding(
                        title=f"Scheduled task with suspicious frequency",
                        description=(
                            f"Scheduled task '{task_name}' executes very frequently (every 1-5 minutes). "
                            f"This may indicate a malware beaconing pattern. "
                            f"Schedule: {schedule}"
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        code="security.win_scheduled_tasks_security.frequent_schedule",
                        data={
                            "task_name": task_name,
                            "task_path": task_path,
                            "schedule": schedule,
                        },
                    )
                )

            # Check for recent tasks with boot/logon trigger
            if self._is_recent_task(created_date_str) and self._is_boot_logon_trigger(schedule):
                recent_tasks.append(task)
                findings.append(
                    Finding(
                        title=f"Recently created scheduled task with boot/logon trigger",
                        description=(
                            f"Scheduled task '{task_name}' was created recently (within last 7 days) "
                            f"and executes at boot or logon. This may indicate malware persistence. "
                            f"Created: {created_date_str}, Schedule: {schedule}"
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        code="security.win_scheduled_tasks_security.recent_boot_logon",
                        data={
                            "task_name": task_name,
                            "task_path": task_path,
                            "created_date": created_date_str,
                            "schedule": schedule,
                        },
                    )
                )

            # Check for hidden attributes (INFO)
            if self._is_hidden_task(attributes):
                findings.append(
                    Finding(
                        title=f"Scheduled task with hidden attributes",
                        description=(
                            f"Scheduled task '{task_name}' has hidden attributes. "
                            f"Hidden tasks are often used to conceal malware. "
                            f"Attributes: {attributes}"
                        ),
                        severity=Severity.INFO,
                        category=self.category,
                        code="security.win_scheduled_tasks_security.hidden_attributes",
                        data={
                            "task_name": task_name,
                            "task_path": task_path,
                            "attributes": attributes,
                        },
                    )
                )

        # Summary findings
        findings.append(
            Finding(
                title=f"Scheduled tasks inventory ({total_count} total)",
                description=(
                    f"Found {total_count} total scheduled tasks. "
                    f"Identified {len(suspicious_tasks)} potentially suspicious tasks. "
                    f"Review the tasks listed above for any unfamiliar or suspicious entries."
                ),
                severity=Severity.INFO,
                category=self.category,
                code="security.win_scheduled_tasks_security.inventory",
                data={
                    "total_count": total_count,
                    "suspicious_count": len(suspicious_tasks),
                    "recent_additions": len(recent_tasks),
                },
            )
        )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            if finding.severity == Severity.CRITICAL:
                task_name = finding.data.get("task_name", "")
                actions.append(
                    Action(
                        title=f"Remove malicious scheduled task: {task_name}",
                        description=(
                            f"To remove the malicious scheduled task '{task_name}':\n"
                            f"1. Press Ctrl+Shift+Esc to open Task Manager\n"
                            f"2. Go to the 'Services' tab or use Task Scheduler\n"
                            f"3. Find the task '{task_name}' and right-click to delete\n"
                            f"Alternatively, run: schtasks /delete /tn \"{task_name}\" /f\n"
                            f"WARNING: Only delete tasks you are certain are malicious. "
                            f"Deleting legitimate system tasks can break Windows functionality."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=False,
                        error="Manual intervention required (informational fix)",
                    )
                )
            elif finding.severity == Severity.WARNING:
                task_name = finding.data.get("task_name", "")
                actions.append(
                    Action(
                        title=f"Review scheduled task: {task_name}",
                        description=(
                            f"Scheduled task '{task_name}' has suspicious characteristics. "
                            f"Review it carefully:\n"
                            f"1. Open Task Scheduler (Win+R -> taskschd.msc)\n"
                            f"2. Find the task '{task_name}'\n"
                            f"3. Check its properties, including:\n"
                            f"   - Command/action being executed\n"
                            f"   - User it runs as\n"
                            f"   - Schedule/triggers\n"
                            f"   - Last run time\n"
                            f"4. Search online for the task name to verify legitimacy\n"
                            f"5. If suspicious, delete it using Task Scheduler or schtasks /delete command"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=False,
                        error="Manual review required (informational fix)",
                    )
                )
        return FixResult(module_name=self.name, actions=actions)

    def _get_scheduled_tasks(self) -> list[dict[str, str]]:
        """Get all scheduled tasks via schtasks command.

        Returns a list of task dicts with keys from CSV output.
        """
        try:
            result = subprocess.run(
                ["schtasks", "/query", "/fo", "CSV", "/v"],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                return []
            return self._parse_schtasks_csv(result.stdout)
        except (OSError, subprocess.SubprocessError):
            return []

    def _parse_schtasks_csv(self, csv_output: str) -> list[dict[str, str]]:
        """Parse schtasks CSV output into list of dicts.

        The CSV has headers like: HostName, TaskName, Next Run Time, Status, etc.
        """
        tasks = []
        try:
            # Use StringIO to treat the output as a file-like object
            csv_file = io.StringIO(csv_output)
            reader = csv.DictReader(csv_file)
            if reader.fieldnames is None:
                return []

            for row in reader:
                if row:  # Skip empty rows
                    tasks.append(row)
            return tasks
        except (csv.Error, ValueError):
            return []

    def _is_microsoft_task(self, task_name: str, task_path: str, run_as_user: str, command: str) -> bool:
        """Check if a task is owned by Microsoft and safe to ignore."""
        # Microsoft-owned tasks
        microsoft_prefixes = [
            "Microsoft\\",
            "\\Microsoft",
            "Windows",
            "UpdateOrchestrator",
            "OneDrive",
            "Defender",
        ]

        full_path = f"{task_path}\\{task_name}".lower()

        for prefix in microsoft_prefixes:
            if prefix.lower() in full_path:
                return True

        # Check for Microsoft-owned binaries
        if "C:\\Windows\\System32" in command or "C:\\Windows\\SysWOW64" in command:
            if "\\Microsoft\\" in command or "\\Windows\\" in command:
                return True

        return False

    def _has_encoded_powershell(self, command: str) -> bool:
        """Check if command uses encoded PowerShell."""
        patterns = [
            r"-enc\s",
            r"-encodedcommand\s",
            r"-e\s+[A-Za-z0-9+/=]{50,}",  # Suspicious base64-like encoding
        ]
        for pattern in patterns:
            if re.search(pattern, command, re.IGNORECASE):
                return True
        return False

    def _is_temp_path(self, command: str) -> bool:
        """Check if command executes from temp directory."""
        temp_patterns = [
            r"\\Temp\\",
            r"\\TEMP\\",
            r"\\temp\\",
            r"AppData\\Local\\Temp",
            r"AppData\\Local\\temp",
            r"\\Downloads\\",
            r"\\downloads\\",
            r"ProgramData\\Temp",
        ]
        for pattern in temp_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                return True
        return False

    def _is_frequent_schedule(self, schedule: str) -> bool:
        """Check if schedule indicates very frequent execution (beaconing pattern)."""
        if not schedule:
            return False

        # Look for patterns indicating 1-5 minute intervals
        freq_patterns = [
            r"every\s+[1-5]\s+min",
            r"repeat\s+every\s+[1-5]\s+min",
            r"\*/1\s+",  # Every 1 minute (escaped asterisk)
            r"\*/2\s+",  # Every 2 minutes
            r"\*/3\s+",  # Every 3 minutes
            r"\*/4\s+",  # Every 4 minutes
            r"\*/5\s+",  # Every 5 minutes
        ]

        for pattern in freq_patterns:
            if re.search(pattern, schedule, re.IGNORECASE):
                return True
        return False

    def _is_boot_logon_trigger(self, schedule: str) -> bool:
        """Check if task triggers on boot or logon."""
        if not schedule:
            return False

        boot_logon_patterns = [
            r"at logon",
            r"at startup",
            r"at boot",
            r"on startup",
            r"on logon",
            r"system startup",
            r"user logon",
        ]

        for pattern in boot_logon_patterns:
            if re.search(pattern, schedule, re.IGNORECASE):
                return True
        return False

    def _is_recent_task(self, created_date_str: str) -> bool:
        """Check if task was created within the last 7 days."""
        if not created_date_str:
            return False

        try:
            # Try common Windows date formats
            formats = [
                "%m/%d/%Y %I:%M:%S %p",
                "%m/%d/%Y %H:%M:%S",
                "%Y-%m-%d %H:%M:%S",
                "%d/%m/%Y %H:%M:%S",
            ]

            created_date = None
            for fmt in formats:
                try:
                    created_date = datetime.strptime(created_date_str.strip(), fmt)
                    break
                except ValueError:
                    continue

            if created_date is None:
                return False

            # Check if created within last 7 days
            seven_days_ago = datetime.now() - timedelta(days=7)
            return created_date >= seven_days_ago
        except (ValueError, TypeError):
            return False

    def _is_hidden_task(self, attributes: str) -> bool:
        """Check if task has hidden attributes."""
        if not attributes:
            return False

        hidden_patterns = [
            r"hidden",
            r"H\b",  # Single letter H flag
        ]

        for pattern in hidden_patterns:
            if re.search(pattern, attributes, re.IGNORECASE):
                return True
        return False
