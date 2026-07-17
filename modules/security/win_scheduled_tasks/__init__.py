import json
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
    name = "win_scheduled_tasks"
    category = "security"
    platforms = [Platform.WIN32]
    risk_level = RiskLevel.SAFE
    priority = 55
    depends_on = []
    estimated_duration = "5s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []
        tasks = self._get_scheduled_tasks()

        if tasks is None:
            return CheckResult(module_name=self.name, findings=findings)

        # Flag all non-Microsoft tasks as INFO
        if tasks:
            findings.append(
                Finding(
                    title=f"Found {len(tasks)} non-Microsoft scheduled tasks",
                    description=(
                        "The system has non-Microsoft scheduled tasks. "
                        "Review them for unauthorized or suspicious activity."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "check": "non_microsoft_tasks",
                        "task_count": len(tasks),
                        "tasks": [t.get("TaskName", "Unknown") for t in tasks],
                    },
                )
            )

        # Check each task for suspicious patterns
        for task in tasks:
            task_name = task.get("TaskName", "Unknown")
            task_path = task.get("TaskPath", "")
            actions = task.get("Actions", [])

            # Check for suspicious execution paths
            if self._is_suspicious_path(actions):
                findings.append(
                    Finding(
                        title=f"Task '{task_name}' executes from suspicious location",
                        description=(
                            "This scheduled task is configured to execute from "
                            "a temporary, AppData, or Downloads directory, "
                            "which is common for malware persistence."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={
                            "check": "suspicious_path",
                            "task_name": task_name,
                            "task_path": task_path,
                        },
                    )
                )

            # Check for encoded/obfuscated commands
            if self._has_encoded_command(actions):
                findings.append(
                    Finding(
                        title=f"Task '{task_name}' has encoded/obfuscated command",
                        description=(
                            "This scheduled task contains base64-encoded or "
                            "obfuscated PowerShell commands (-enc flag), "
                            "which is a common malware obfuscation technique."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={
                            "check": "encoded_command",
                            "task_name": task_name,
                            "task_path": task_path,
                        },
                    )
                )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            check = finding.data.get("check")
            task_name = finding.data.get("task_name", "Unknown")

            if check == "non_microsoft_tasks":
                action = Action(
                    title="Review non-Microsoft scheduled tasks",
                    description=(
                        "Review the non-Microsoft scheduled tasks in Task Scheduler "
                        "and disable or remove any that are unauthorized or suspicious. "
                        "Right-click each task and select 'Disable' to prevent execution "
                        "without deletion, or 'Delete' to remove it entirely."
                    ),
                    risk_level=RiskLevel.SAFE,
                    success=True,
                    data={"tasks": finding.data.get("tasks", [])},
                )
            elif check == "suspicious_path":
                action = Action(
                    title=f"Review task '{task_name}' execution path",
                    description=(
                        f"The task '{task_name}' executes from a suspicious location. "
                        "Disable this task immediately in Task Scheduler and investigate "
                        "the executable location for signs of malware."
                    ),
                    risk_level=RiskLevel.SAFE,
                    success=True,
                    data={"task_name": task_name},
                )
            elif check == "encoded_command":
                action = Action(
                    title=f"Review encoded command in task '{task_name}'",
                    description=(
                        f"The task '{task_name}' contains obfuscated PowerShell commands. "
                        "Review the full command in Task Scheduler Properties by right-clicking "
                        "the task and selecting 'Properties'. Disable or delete this task if "
                        "the command appears suspicious or unauthorized."
                    ),
                    risk_level=RiskLevel.SAFE,
                    success=True,
                    data={"task_name": task_name},
                )
            else:
                continue

            actions.append(action)

        return FixResult(module_name=self.name, actions=actions)

    def _get_scheduled_tasks(self) -> list[dict] | None:
        """Get all non-Microsoft scheduled tasks via PowerShell."""
        try:
            ps_command = (
                "Get-ScheduledTask | "
                "Where-Object {$_.TaskPath -notlike '\\Microsoft\\*'} | "
                "Select-Object TaskName, TaskPath, State, @{Name='Actions';Expression={$_.Actions | ConvertTo-Json}} | "
                "ConvertTo-Json -AsArray"
            )
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_command],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                return None
            return self._parse_tasks_json(result.stdout)
        except (OSError, subprocess.SubprocessError):
            return None

    def _parse_tasks_json(self, output: str) -> list[dict] | None:
        """Parse JSON output from PowerShell."""
        if not output or not output.strip():
            return []
        try:
            tasks = json.loads(output)
            # Handle single task returned as dict vs list
            if isinstance(tasks, dict):
                return [tasks]
            return tasks if isinstance(tasks, list) else []
        except json.JSONDecodeError:
            return []

    def _is_suspicious_path(self, actions: list | str) -> bool:
        """Check if task actions contain suspicious execution paths."""
        suspicious_patterns = [
            "\\temp\\",
            "\\appdata\\",
            "\\downloads\\",
            "%temp%",
            "%appdata%",
            "\\users\\",  # User-specific appdata
        ]

        action_str = self._stringify_actions(actions)
        action_lower = action_str.lower()

        for pattern in suspicious_patterns:
            if pattern in action_lower:
                return True
        return False

    def _has_encoded_command(self, actions: list | str) -> bool:
        """Check for encoded/obfuscated PowerShell commands."""
        action_str = self._stringify_actions(actions)

        # Check for base64 encoding patterns
        if "base64" in action_str.lower():
            return True

        # Check for PowerShell -enc or -encodedcommand flags
        if " -enc " in action_str.lower() or " -encodedcommand " in action_str.lower():
            return True

        # Check for Windows API calls via base64 or obfuscated patterns
        if "frombase64" in action_str.lower() or "decodedcommand" in action_str.lower():
            return True

        return False

    def _stringify_actions(self, actions: list | str) -> str:
        """Convert actions to a single string for analysis."""
        if isinstance(actions, str):
            return actions
        if isinstance(actions, list):
            result = []
            for action in actions:
                if isinstance(action, dict):
                    # Extract Execute field from action dict
                    if "Execute" in action:
                        result.append(str(action["Execute"]))
                    # Also check for Arguments
                    if "Arguments" in action:
                        result.append(str(action["Arguments"]))
                else:
                    result.append(str(action))
            return " ".join(result)
        return ""
