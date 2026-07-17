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
    name = "win_boot_time"
    category = "performance"
    platforms = [Platform.WIN32]
    risk_level = RiskLevel.SAFE
    priority = 60
    depends_on = []
    estimated_duration = "5s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Get last boot time
        last_boot_time = self._get_last_boot_time()
        if not last_boot_time:
            return CheckResult(module_name=self.name, findings=findings)

        # Calculate uptime
        now = datetime.now()
        uptime_delta = now - last_boot_time
        uptime_days = uptime_delta.days
        uptime_hours = uptime_delta.seconds // 3600
        uptime_str = f"{uptime_days}d {uptime_hours}h"

        # Get boot duration from event log
        boot_duration_seconds = self._get_boot_duration()

        # Check Fast Startup status
        fast_startup_enabled = self._is_fast_startup_enabled()

        # Build report with findings
        description_parts = []
        if boot_duration_seconds and boot_duration_seconds > 60:
            description_parts.append(
                f"Boot time is {boot_duration_seconds} seconds (exceeds 60s threshold)"
            )
            findings.append(
                Finding(
                    title="Slow boot time detected",
                    description=f"System boot takes {boot_duration_seconds} seconds, which exceeds the recommended 60-second threshold.",
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "boot_duration_seconds": boot_duration_seconds,
                        "uptime_days": uptime_days,
                        "fast_startup_enabled": fast_startup_enabled,
                    },
                )
            )
        elif boot_duration_seconds:
            description_parts.append(f"Boot time is {boot_duration_seconds} seconds")

        if uptime_days > 30:
            description_parts.append(
                f"System uptime is {uptime_str} (exceeds 30-day recommendation)"
            )
            findings.append(
                Finding(
                    title="System overdue for restart",
                    description=f"System uptime is {uptime_str}. Microsoft recommends restarting at least every 30 days for updates and memory cleanup.",
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "uptime_days": uptime_days,
                        "uptime_hours": uptime_hours,
                        "boot_duration_seconds": boot_duration_seconds,
                        "fast_startup_enabled": fast_startup_enabled,
                    },
                )
            )

        # Always add an informational finding with current status
        status_parts = []
        if boot_duration_seconds:
            status_parts.append(f"boot time: {boot_duration_seconds}s")
        status_parts.append(f"uptime: {uptime_str}")
        status_parts.append(
            f"Fast Startup: {'enabled' if fast_startup_enabled else 'disabled'}"
        )

        findings.append(
            Finding(
                title="Boot performance report",
                description="; ".join(status_parts).capitalize(),
                severity=Severity.INFO,
                category=self.category,
                data={
                    "boot_duration_seconds": boot_duration_seconds,
                    "uptime_days": uptime_days,
                    "uptime_hours": uptime_hours,
                    "fast_startup_enabled": fast_startup_enabled,
                },
            )
        )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            if finding.severity == Severity.WARNING:
                if "boot" in finding.title.lower():
                    actions.append(
                        Action(
                            title="Enable Fast Startup",
                            description=(
                                "Fast Startup reduces boot time by up to 50%. "
                                "Enable via Settings > System > Power & sleep > "
                                "Additional power settings > Change what the power button does > "
                                "Change settings that are currently unavailable > "
                                "Turn on fast startup."
                            ),
                            risk_level=RiskLevel.SAFE,
                            success=True,
                        )
                    )
                    actions.append(
                        Action(
                            title="Reduce startup items",
                            description=(
                                "Disable unnecessary startup programs in Task Manager > "
                                "Startup apps. Only keep essential applications."
                            ),
                            risk_level=RiskLevel.SAFE,
                            success=True,
                        )
                    )
                elif "uptime" in finding.title.lower():
                    actions.append(
                        Action(
                            title="Restart system",
                            description=(
                                "Restarting your system clears memory, applies updates, "
                                "and can improve performance. Schedule a restart soon."
                            ),
                            risk_level=RiskLevel.SAFE,
                            success=True,
                        )
                    )
            elif finding.severity == Severity.INFO:
                actions.append(
                    Action(
                        title="Boot performance status",
                        description=finding.description,
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
        return FixResult(module_name=self.name, actions=actions)

    def _get_last_boot_time(self) -> datetime | None:
        try:
            result = subprocess.run(
                [
                    "powershell",
                    "-NoProfile",
                    "-Command",
                    "(Get-CimInstance Win32_OperatingSystem).LastBootUpTime",
                ],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0 and result.stdout.strip():
                # Parse datetime from PowerShell output format
                # Expected format: "7/7/2026 10:30:45 AM" or similar
                output = result.stdout.strip()
                try:
                    return datetime.strptime(output, "%m/%d/%Y %I:%M:%S %p")
                except ValueError:
                    # Try alternative formats
                    try:
                        return datetime.strptime(output, "%m/%d/%Y %H:%M:%S")
                    except ValueError:
                        return None
        except (OSError, subprocess.SubprocessError, subprocess.TimeoutExpired):
            pass
        return None

    def _get_boot_duration(self) -> int | None:
        try:
            result = subprocess.run(
                [
                    "powershell",
                    "-NoProfile",
                    "-Command",
                    (
                        "$event = Get-WinEvent -FilterHashtable @{LogName='System'; ID=12} "
                        "-MaxEvents 1 -ErrorAction SilentlyContinue; "
                        "if ($event) { $event.Properties[0].Value } else { 'N/A' }"
                    ),
                ],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0 and result.stdout.strip():
                output = result.stdout.strip()
                if output and output != "N/A":
                    try:
                        # Boot time is in milliseconds
                        ms = int(output)
                        seconds = ms // 1000
                        return seconds
                    except ValueError:
                        pass
        except (OSError, subprocess.SubprocessError, subprocess.TimeoutExpired):
            pass
        return None

    def _is_fast_startup_enabled(self) -> bool:
        try:
            result = subprocess.run(
                [
                    "reg",
                    "query",
                    "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Power",
                    "/v",
                    "HiberbootEnabled",
                ],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                # Look for "0x1" in output which means enabled
                return "0x1" in result.stdout
        except (OSError, subprocess.SubprocessError, subprocess.TimeoutExpired):
            pass
        return False
