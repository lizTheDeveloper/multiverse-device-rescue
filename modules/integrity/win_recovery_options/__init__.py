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
    name = "win_recovery_options"
    category = "integrity"
    platforms = [Platform.WIN32]
    risk_level = RiskLevel.SAFE
    priority = 65
    depends_on = []
    estimated_duration = "10s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Check WinRE status
        winre_status = self._check_winre()
        if not winre_status:
            findings.append(
                Finding(
                    title="Could not check Windows Recovery Environment",
                    description=(
                        "Failed to run reagentc /info. WinRE status cannot be assessed."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "winre_check_failed"},
                )
            )
        else:
            if not winre_status.get("enabled"):
                findings.append(
                    Finding(
                        title="Windows Recovery Environment (WinRE) is disabled",
                        description=(
                            "WinRE is disabled. If Windows fails to boot, you may not be able to "
                            "access recovery options. This is a critical issue that should be "
                            "addressed."
                        ),
                        severity=Severity.CRITICAL,
                        category=self.category,
                        data={"check": "winre_disabled"},
                    )
                )
            else:
                findings.append(
                    Finding(
                        title="Windows Recovery Environment (WinRE) is enabled",
                        description=(
                            f"WinRE is enabled and ready. Location: {winre_status.get('location', 'Unknown')}. "
                            "Your system can recover if it fails to boot."
                        ),
                        severity=Severity.INFO,
                        category=self.category,
                        data={"check": "winre_enabled", "location": winre_status.get("location")},
                    )
                )

        # Check System Restore status
        system_restore = self._check_system_restore()
        if not system_restore:
            findings.append(
                Finding(
                    title="Could not check System Restore status",
                    description=(
                        "Failed to check System Restore configuration via vssadmin. "
                        "Status cannot be assessed."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "system_restore_check_failed"},
                )
            )
        else:
            if not system_restore.get("enabled"):
                findings.append(
                    Finding(
                        title="System Restore is disabled",
                        description=(
                            "System Restore is disabled. You cannot roll back to a previous system state. "
                            "If a bad update or software installation breaks your system, you may have "
                            "no way to recover."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={"check": "system_restore_disabled"},
                    )
                )
            else:
                findings.append(
                    Finding(
                        title="System Restore is enabled",
                        description=(
                            "System Restore is enabled and monitoring system changes. "
                            "You can roll back to previous system states if needed."
                        ),
                        severity=Severity.INFO,
                        category=self.category,
                        data={"check": "system_restore_enabled"},
                    )
                )

        # Check restore points
        restore_points = self._get_restore_points()
        if restore_points is not None:
            if len(restore_points) == 0:
                findings.append(
                    Finding(
                        title="No restore points available",
                        description=(
                            "No restore points exist on this system. Even though System Restore is enabled, "
                            "you have no previous state to roll back to. Create a restore point manually."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={"check": "no_restore_points"},
                    )
                )
            else:
                # Check age of most recent restore point
                oldest_point = restore_points[-1]
                point_age = oldest_point.get("age_days", float("inf"))

                if point_age > 30:
                    findings.append(
                        Finding(
                            title=f"Latest restore point is {point_age} days old",
                            description=(
                                f"Your most recent restore point was created {point_age} days ago "
                                f"({oldest_point.get('creation_time', 'unknown')}). "
                                "It may not reflect your current system state. Consider creating a new "
                                "restore point regularly."
                            ),
                            severity=Severity.WARNING,
                            category=self.category,
                            data={
                                "check": "old_restore_point",
                                "age_days": point_age,
                                "creation_time": oldest_point.get("creation_time"),
                            },
                        )
                    )

                # Add info about restore points
                summary = f"{len(restore_points)} restore point(s) available. "
                if len(restore_points) > 0:
                    latest = restore_points[0]
                    summary += f"Most recent: {latest.get('creation_time', 'unknown')} ({latest.get('age_days', '?')} days old). "

                findings.append(
                    Finding(
                        title="Restore points available",
                        description=(
                            f"{summary}"
                            "You can roll back to a previous system state if needed."
                        ),
                        severity=Severity.INFO,
                        category=self.category,
                        data={
                            "check": "restore_points_available",
                            "count": len(restore_points),
                            "restore_points": restore_points,
                        },
                    )
                )

        # Summary
        findings.append(
            Finding(
                title="Recovery Configuration Summary",
                description=self._build_recovery_summary(findings),
                severity=Severity.INFO,
                category=self.category,
                data={"check": "recovery_summary"},
            )
        )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        for finding in findings.findings:
            check = finding.data.get("check")

            if check == "winre_disabled":
                actions.append(
                    Action(
                        title="Enable Windows Recovery Environment",
                        description=(
                            "WinRE is disabled. To enable it: (1) Open PowerShell as Administrator. "
                            "(2) Run: reagentc /enable. This will allow you to access recovery options "
                            "if Windows fails to boot. Note: This requires at least 250MB free space on "
                            "the system drive."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "winre_enabled":
                actions.append(
                    Action(
                        title="WinRE is properly configured",
                        description=(
                            "Windows Recovery Environment is enabled. Your system can recover from "
                            "critical boot failures. No action needed."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "system_restore_disabled":
                actions.append(
                    Action(
                        title="Enable System Restore",
                        description=(
                            "System Restore is disabled. To enable it: (1) Right-click 'This PC' or "
                            "'My Computer' > Properties. (2) Click 'System protection' in the left sidebar. "
                            "(3) Select the system drive and click 'Configure...'. (4) Choose 'Restore system "
                            "settings and previous versions of files' and click OK. (5) Restart your computer. "
                            "Once enabled, Windows will automatically create restore points."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "system_restore_enabled":
                actions.append(
                    Action(
                        title="System Restore is properly configured",
                        description=(
                            "System Restore is enabled. Windows will automatically create restore points "
                            "when system changes occur. You can also manually create restore points. "
                            "No action needed."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "no_restore_points":
                actions.append(
                    Action(
                        title="Create a manual restore point",
                        description=(
                            "You have no restore points. Create one now: (1) Right-click 'This PC' or "
                            "'My Computer' > Properties. (2) Click 'System protection' in the left sidebar. "
                            "(3) Click 'Create...' button. (4) Enter a description (e.g., 'Before major "
                            "update') and click 'Create'. The backup may take 5-10 minutes. After it "
                            "completes, you'll have a restore point to roll back to if needed."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "old_restore_point":
                age_days = finding.data.get("age_days", "unknown")
                actions.append(
                    Action(
                        title=f"Create a fresh restore point (latest is {age_days} days old)",
                        description=(
                            "Your most recent restore point is more than 30 days old. Create a fresh one: "
                            "(1) Right-click 'This PC' or 'My Computer' > Properties. (2) Click 'System "
                            "protection' in the left sidebar. (3) Click 'Create...' button. (4) Enter a "
                            "description and click 'Create'. This ensures you have a recent state to "
                            "restore if needed."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "restore_points_available":
                actions.append(
                    Action(
                        title="Restore points are available",
                        description=(
                            "Your system has restore points available for recovery. Restore points are "
                            "automatically created, but you can also manually create one before major "
                            "system changes. To manually create: Right-click 'This PC' > Properties > "
                            "System protection > Create."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "winre_check_failed" or check == "system_restore_check_failed":
                actions.append(
                    Action(
                        title="Unable to assess recovery options",
                        description=(
                            "Could not verify Windows recovery configuration. Ensure you have "
                            "Administrator privileges and run the diagnostic again. If issues persist, "
                            "open PowerShell as Administrator and try: reagentc /info and vssadmin list "
                            "shadows"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _check_winre(self) -> Optional[dict]:
        """Check Windows Recovery Environment status via reagentc."""
        try:
            result = subprocess.run(
                ["reagentc", "/info"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                return None

            return _parse_reagentc_output(result.stdout)
        except (OSError, subprocess.SubprocessError, TimeoutError):
            return None

    def _check_system_restore(self) -> Optional[dict]:
        """Check if System Restore is enabled via vssadmin."""
        try:
            result = subprocess.run(
                ["vssadmin", "list", "shadows"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            # If vssadmin returns 0, System Restore is likely enabled
            # (it would have snapshot volumes if enabled)
            if result.returncode == 0:
                # Check if there are any shadows listed
                has_shadows = "Shadow Copy Volume" in result.stdout or "Shadow Copy ID" in result.stdout
                return {"enabled": has_shadows or True}  # If command succeeds, assume enabled
            return None
        except (OSError, subprocess.SubprocessError, TimeoutError):
            return None

    def _get_restore_points(self) -> Optional[list]:
        """Get list of restore points via PowerShell Get-ComputerRestorePoint."""
        try:
            ps_cmd = (
                "Get-ComputerRestorePoint | Select-Object -First 10 "
                "Description, CreationTime | ConvertTo-Json"
            )
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                return None

            return _parse_restore_points(result.stdout)
        except (OSError, subprocess.SubprocessError, TimeoutError):
            return None

    def _build_recovery_summary(self, findings: list) -> str:
        """Build a summary of recovery configuration."""
        summary_parts = []

        winre_status = next(
            (f for f in findings if f.data.get("check") == "winre_enabled"), None
        ) or next((f for f in findings if f.data.get("check") == "winre_disabled"), None)

        restore_status = next(
            (f for f in findings if f.data.get("check") == "system_restore_enabled"),
            None,
        ) or next(
            (f for f in findings if f.data.get("check") == "system_restore_disabled"), None
        )

        restore_points = next(
            (f for f in findings if f.data.get("check") == "restore_points_available"), None
        ) or next((f for f in findings if f.data.get("check") == "no_restore_points"), None)

        if winre_status:
            winre_text = "WinRE: Enabled" if winre_status.data.get("check") == "winre_enabled" else "WinRE: Disabled"
            summary_parts.append(winre_text)

        if restore_status:
            restore_text = (
                "System Restore: Enabled"
                if restore_status.data.get("check") == "system_restore_enabled"
                else "System Restore: Disabled"
            )
            summary_parts.append(restore_text)

        if restore_points:
            if restore_points.data.get("check") == "restore_points_available":
                count = restore_points.data.get("count", 0)
                restore_text = f"Restore Points: {count} available"
            else:
                restore_text = "Restore Points: None"
            summary_parts.append(restore_text)

        if summary_parts:
            return " | ".join(summary_parts) + ". Your system recovery readiness has been assessed."
        else:
            return "Recovery status could not be fully assessed. Check admin privileges."


def _parse_reagentc_output(output: str) -> dict:
    """Parse reagentc /info output to determine WinRE status."""
    info = {"enabled": False, "location": None}

    for line in output.split("\n"):
        line = line.strip()
        if "windows recovery environment" in line.lower():
            # Line format: "Windows Recovery Environment (Windows RE) : Enabled" or "Disabled"
            if "enabled" in line.lower():
                info["enabled"] = True
            elif "disabled" in line.lower():
                info["enabled"] = False
        elif "recovery partition" in line.lower() or "location" in line.lower():
            # Extract location info if present
            if ":" in line:
                parts = line.split(":", 1)
                if len(parts) > 1:
                    info["location"] = parts[1].strip()

    return info


def _parse_restore_points(json_output: str) -> list:
    """Parse PowerShell JSON output from Get-ComputerRestorePoint."""
    restore_points = []

    if not json_output.strip():
        return restore_points

    try:
        data = json.loads(json_output)
        if not isinstance(data, list):
            data = [data]

        now = datetime.now()

        for point in data:
            description = point.get("Description", "Unknown")
            creation_time_str = point.get("CreationTime", "")

            try:
                # Parse ISO format datetime
                # PowerShell returns something like "2024-07-05T10:30:45.1234567"
                if "T" in creation_time_str:
                    creation_time = datetime.fromisoformat(creation_time_str.split(".")[0])
                else:
                    creation_time = datetime.strptime(creation_time_str, "%Y-%m-%d %H:%M:%S")

                age_days = (now - creation_time).days
                formatted_time = creation_time.strftime("%Y-%m-%d %H:%M:%S")

                restore_points.append(
                    {
                        "description": description,
                        "creation_time": formatted_time,
                        "age_days": age_days,
                    }
                )
            except (ValueError, AttributeError):
                # If we can't parse the date, skip this entry
                continue

        # Sort by creation time descending (newest first)
        restore_points.sort(key=lambda x: x.get("age_days", float("inf")))

        return restore_points
    except (json.JSONDecodeError, ValueError, KeyError, TypeError):
        return restore_points
