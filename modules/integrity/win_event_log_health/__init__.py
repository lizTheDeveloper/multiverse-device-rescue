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
    name = "win_event_log_health"
    category = "integrity"
    platforms = [Platform.WIN32]
    risk_level = RiskLevel.SAFE
    priority = 65
    depends_on = []
    estimated_duration = "10s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Check if Event Log service is running
        service_running = self._check_event_log_service()
        if not service_running:
            findings.append(
                Finding(
                    title="Event Log service is not running",
                    description=(
                        "The Windows Event Log service (EventLog) is not running. "
                        "This is critical as it indicates the service may have been disabled or crashed. "
                        "Event logs are essential for diagnosing crashes and security incidents. "
                        "This could indicate tampering or system instability."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
                    data={"check": "event_log_service_stopped"},
                )
            )
            return CheckResult(module_name=self.name, findings=findings)

        # Get critical/error events from System log
        system_errors = self._get_system_errors()
        if system_errors and system_errors.get("error_count", 0) > 0:
            findings.append(
                Finding(
                    title=f"Critical/error events in System log ({system_errors['error_count']} found)",
                    description=(
                        f"Found {system_errors['error_count']} critical or error events in the System event log. "
                        "These may indicate hardware failures, driver issues, or system crashes."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "check": "system_errors",
                        "error_count": system_errors["error_count"],
                    },
                )
            )

        # Check for BSODs (Event ID 1001)
        bsod_events = self._get_bsod_events()
        if bsod_events and bsod_events.get("count", 0) > 0:
            findings.append(
                Finding(
                    title=f"Recent BSOD/BugCheck events ({bsod_events['count']} found)",
                    description=(
                        f"Found {bsod_events['count']} recent Blue Screen of Death (BSOD) or BugCheck events (Event ID 1001) "
                        "in the System event log. These indicate system crashes that require investigation."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "check": "bsod_events",
                        "count": bsod_events["count"],
                    },
                )
            )

        # Check for unexpected shutdown events (Event ID 41)
        shutdown_events = self._get_unexpected_shutdown_events()
        if shutdown_events and shutdown_events.get("count", 0) > 0:
            findings.append(
                Finding(
                    title=f"Unexpected shutdown/power loss events ({shutdown_events['count']} found)",
                    description=(
                        f"Found {shutdown_events['count']} unexpected shutdown or power loss events (Event ID 41). "
                        "The system may have lost power, been forcibly shut down, or had other critical failures."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "check": "shutdown_events",
                        "count": shutdown_events["count"],
                    },
                )
            )

        # Check for service crash events (Event ID 7031, 7034)
        service_crashes = self._get_service_crashes()
        if service_crashes and service_crashes.get("count", 0) > 0:
            findings.append(
                Finding(
                    title=f"Service crash events ({service_crashes['count']} found)",
                    description=(
                        f"Found {service_crashes['count']} service crash or timeout events (Event ID 7031/7034). "
                        "Critical services are crashing or not responding, which impacts system stability."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "check": "service_crashes",
                        "count": service_crashes["count"],
                    },
                )
            )

        # Check security audit failures
        security_failures = self._get_security_failures()
        if security_failures and security_failures.get("count", 0) > 0:
            findings.append(
                Finding(
                    title=f"Security audit failure events ({security_failures['count']} found)",
                    description=(
                        f"Found {security_failures['count']} security audit failure or critical security events "
                        "in the Security event log. Investigate for potential security incidents."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "check": "security_failures",
                        "count": security_failures["count"],
                    },
                )
            )

        # Check event log sizes
        log_sizes = self._get_event_log_sizes()
        if log_sizes:
            for log_name, size_info in log_sizes.items():
                capacity_pct = size_info.get("capacity_percent", 0)
                if capacity_pct > 90:
                    findings.append(
                        Finding(
                            title=f"{log_name} log is {capacity_pct}% full",
                            description=(
                                f"The {log_name} event log is at {capacity_pct}% of maximum capacity. "
                                "When full, the oldest events will be automatically overwritten. "
                                "Consider archiving logs or increasing log retention settings."
                            ),
                            severity=Severity.WARNING,
                            category=self.category,
                            data={
                                "check": "log_full",
                                "log_name": log_name,
                                "capacity_percent": capacity_pct,
                                "current_size": size_info.get("current_size", "unknown"),
                                "max_size": size_info.get("max_size", "unknown"),
                            },
                        )
                    )

        # Add informational finding about event log health if no issues found
        if not findings:
            findings.append(
                Finding(
                    title="Event Log health is good",
                    description=(
                        "Event Log service is running normally. No critical events, BSODs, service crashes, "
                        "or full logs detected. Event log health is satisfactory."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "log_health_good"},
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        for finding in findings.findings:
            check = finding.data.get("check")

            if check == "event_log_service_stopped":
                actions.append(
                    Action(
                        title="Event Log service is not running",
                        description=(
                            "The Event Log service (EventLog) has stopped or crashed. "
                            "Recommendations: (1) Try restarting the Event Log service using Services.msc "
                            "or running: 'net start eventlog' in Command Prompt (Administrator). "
                            "(2) If it fails to start, check if the service startup type is Automatic. "
                            "(3) Check the System event log (if accessible) for related errors. "
                            "(4) If all else fails, system restore or fresh install may be needed."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "system_errors":
                error_count = finding.data.get("error_count", 0)
                actions.append(
                    Action(
                        title=f"Critical/error events found ({error_count} events)",
                        description=(
                            f"Found {error_count} critical or error events in the System event log. "
                            "Recommendations: (1) Open Event Viewer (eventvwr.msc) and navigate to Windows Logs > System. "
                            "(2) Review the most recent critical and error events for details. "
                            "(3) Note down the Event IDs and source components. "
                            "(4) Search online for the specific Event ID and error message for solutions. "
                            "(5) Check hardware if the events are hardware-related."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "bsod_events":
                count = finding.data.get("count", 0)
                actions.append(
                    Action(
                        title=f"BSOD/BugCheck events detected ({count} events)",
                        description=(
                            f"Found {count} Blue Screen of Death (BSOD) or BugCheck events (Event ID 1001). "
                            "Recommendations: (1) Open Event Viewer and check System log for Event ID 1001 entries. "
                            "(2) Look for the Stop code and driver information in the event details. "
                            "(3) Update drivers, especially GPU, chipset, and storage drivers. "
                            "(4) Run Windows Update to ensure all patches are applied. "
                            "(5) If crashes persist, consider system restore or reinstall."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "shutdown_events":
                count = finding.data.get("count", 0)
                actions.append(
                    Action(
                        title=f"Unexpected shutdown events ({count} events)",
                        description=(
                            f"Found {count} unexpected shutdown or power loss events (Event ID 41). "
                            "Recommendations: (1) Check power supply health and connections. "
                            "(2) Monitor system for thermal issues (CPU/GPU temperatures). "
                            "(3) Check for loose RAM or storage drive connections. "
                            "(4) Disable fast startup (Settings > System > Power & sleep > Additional power settings). "
                            "(5) If hardware issues persist, have components professionally tested."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "service_crashes":
                count = finding.data.get("count", 0)
                actions.append(
                    Action(
                        title=f"Service crash events ({count} events)",
                        description=(
                            f"Found {count} service crash or timeout events (Event ID 7031/7034). "
                            "Recommendations: (1) Open Event Viewer and check System log for Event ID 7031/7034. "
                            "(2) Identify which services are crashing. "
                            "(3) Try restarting the crashing service(s) in Services.msc. "
                            "(4) Update the service software or driver. "
                            "(5) If the service is a third-party component, check vendor support."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "security_failures":
                count = finding.data.get("count", 0)
                actions.append(
                    Action(
                        title=f"Security audit failures ({count} events)",
                        description=(
                            f"Found {count} security-related failure events in the Security log. "
                            "Recommendations: (1) Open Event Viewer and check Windows Logs > Security. "
                            "(2) Review recent failure events for unauthorized access attempts. "
                            "(3) Check if there are suspicious login attempts or privilege escalation attempts. "
                            "(4) Enable Windows Defender if it's disabled. "
                            "(5) Run a full antivirus/antimalware scan. "
                            "(6) Consider enabling audit logging for more detailed security monitoring."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "log_full":
                log_name = finding.data.get("log_name", "Unknown")
                capacity = finding.data.get("capacity_percent", 0)
                actions.append(
                    Action(
                        title=f"{log_name} log is full ({capacity}%)",
                        description=(
                            f"The {log_name} event log is at {capacity}% capacity. "
                            "Recommendations: (1) Open Event Viewer (eventvwr.msc). "
                            "(2) Right-click on the log ({log_name}) and select 'Properties'. "
                            "(3) Increase 'Maximum log size' (e.g., from 20 MB to 100 MB). "
                            "(4) Alternatively, select 'Overwrite events as needed' if you don't need old events. "
                            "(5) Archive important events before clearing the log. "
                            "(6) You can export the log using 'Save All Events As' before clearing."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "log_health_good":
                actions.append(
                    Action(
                        title="Event Log health is good",
                        description=(
                            "Event Log service is running normally with no critical issues detected. "
                            "Continue monitoring for any changes in system stability or suspicious events. "
                            "Periodically review the Event Viewer for any warning or error events."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _check_event_log_service(self) -> bool:
        """Check if Event Log service is running."""
        try:
            result = subprocess.run(
                ["sc", "query", "EventLog"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                # Check if status shows RUNNING (state 4)
                return "STATE        : 4  RUNNING" in result.stdout or "RUNNING" in result.stdout
            return False
        except (OSError, subprocess.SubprocessError, TimeoutError):
            return False

    def _get_system_errors(self) -> Optional[dict]:
        """Get count of critical/error events from System log."""
        try:
            ps_cmd = (
                "Get-WinEvent -LogName System -MaxEvents 50 -ErrorAction SilentlyContinue | "
                "Where-Object {$_.Level -le 2} | Measure-Object | Select-Object Count"
            )
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                count = _parse_event_count(result.stdout)
                if count > 0:
                    return {"error_count": count}
            return None
        except (OSError, subprocess.SubprocessError, TimeoutError):
            return None

    def _get_bsod_events(self) -> Optional[dict]:
        """Check for Event ID 1001 (BugCheck/BSOD)."""
        try:
            ps_cmd = (
                "Get-WinEvent -FilterHashtable @{LogName='System'; Id=1001} "
                "-MaxEvents 10 -ErrorAction SilentlyContinue | Measure-Object | "
                "Select-Object Count"
            )
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                count = _parse_event_count(result.stdout)
                if count > 0:
                    return {"count": count}
            return None
        except (OSError, subprocess.SubprocessError, TimeoutError):
            return None

    def _get_unexpected_shutdown_events(self) -> Optional[dict]:
        """Check for Event ID 41 (unexpected shutdown/power loss)."""
        try:
            ps_cmd = (
                "Get-WinEvent -FilterHashtable @{LogName='System'; Id=41} "
                "-MaxEvents 10 -ErrorAction SilentlyContinue | Measure-Object | "
                "Select-Object Count"
            )
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                count = _parse_event_count(result.stdout)
                if count > 0:
                    return {"count": count}
            return None
        except (OSError, subprocess.SubprocessError, TimeoutError):
            return None

    def _get_service_crashes(self) -> Optional[dict]:
        """Check for Event ID 7031, 7034 (service crashes)."""
        try:
            ps_cmd = (
                "Get-WinEvent -FilterHashtable @{LogName='System'; Id=7031,7034} "
                "-MaxEvents 10 -ErrorAction SilentlyContinue | Measure-Object | "
                "Select-Object Count"
            )
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                count = _parse_event_count(result.stdout)
                if count > 0:
                    return {"count": count}
            return None
        except (OSError, subprocess.SubprocessError, TimeoutError):
            return None

    def _get_security_failures(self) -> Optional[dict]:
        """Get count of security audit failure events from Security log."""
        try:
            ps_cmd = (
                "Get-WinEvent -LogName Security -MaxEvents 50 -ErrorAction SilentlyContinue | "
                "Where-Object {$_.Level -le 2} | Measure-Object | Select-Object Count"
            )
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                count = _parse_event_count(result.stdout)
                if count > 0:
                    return {"count": count}
            return None
        except (OSError, subprocess.SubprocessError, TimeoutError):
            return None

    def _get_event_log_sizes(self) -> Optional[dict]:
        """Check event log sizes and capacity."""
        try:
            ps_cmd = (
                "Get-WinEvent -ListLog System,Application,Security -ErrorAction SilentlyContinue | "
                "Select-Object LogName, @{Name='FileSize'; Expression={$_.FileSize}}, @{Name='MaxSize'; Expression={$_.MaximumSizeInBytes}} | "
                "ConvertTo-Json"
            )
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                return _parse_log_sizes(result.stdout)
            return None
        except (OSError, subprocess.SubprocessError, TimeoutError):
            return None


def _parse_event_count(output: str) -> int:
    """Extract count from PowerShell Measure-Object output."""
    try:
        for line in output.split("\n"):
            if "count" in line.lower():
                parts = line.split()
                for part in parts:
                    if part.isdigit():
                        return int(part)
        return 0
    except (ValueError, IndexError):
        return 0


def _parse_log_sizes(json_output: str) -> dict:
    """Parse PowerShell JSON output for log sizes."""
    sizes = {}

    if not json_output.strip():
        return sizes

    try:
        data = json.loads(json_output)
        if not isinstance(data, list):
            data = [data]

        for log in data:
            log_name = log.get("LogName", "Unknown")
            file_size = log.get("FileSize", 0)
            max_size = log.get("MaxSize", 1)

            if isinstance(file_size, int) and isinstance(max_size, int) and max_size > 0:
                capacity_pct = int((file_size / max_size) * 100)
                sizes[log_name] = {
                    "current_size": _format_bytes(file_size),
                    "max_size": _format_bytes(max_size),
                    "capacity_percent": capacity_pct,
                }

        return sizes if sizes else None
    except (json.JSONDecodeError, ValueError, KeyError):
        return None


def _format_bytes(bytes_value: int) -> str:
    """Convert bytes to human-readable format."""
    if not isinstance(bytes_value, int) or bytes_value == 0:
        return "0 B"

    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if bytes_value < 1024:
            return f"{bytes_value:.1f} {unit}"
        bytes_value /= 1024
    return f"{bytes_value:.1f} PB"
