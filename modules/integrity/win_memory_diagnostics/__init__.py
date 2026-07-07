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
    name = "win_memory_diagnostics"
    category = "integrity"
    platforms = [Platform.WIN32]
    risk_level = RiskLevel.SAFE
    priority = 60
    depends_on = []
    estimated_duration = "10s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Get RAM information
        ram_info = self._get_ram_info()
        if not ram_info:
            findings.append(
                Finding(
                    title="Could not retrieve RAM information",
                    description=(
                        "Failed to run Get-WmiObject Win32_OperatingSystem. "
                        "Memory health cannot be assessed."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "ram_info_failed"},
                )
            )
            return CheckResult(module_name=self.name, findings=findings)

        total_ram = ram_info.get("total_bytes", 0)
        available_ram = ram_info.get("available_bytes", 0)

        # Check for memory pressure (available < 10% of total)
        if total_ram > 0:
            memory_available_percent = (available_ram / total_ram) * 100
            if memory_available_percent < 10:
                findings.append(
                    Finding(
                        title=f"Low memory availability ({memory_available_percent:.1f}%)",
                        description=(
                            f"Only {_format_bytes(available_ram)} of "
                            f"{_format_bytes(total_ram)} RAM is available. "
                            "Memory pressure may cause performance issues and crashes. "
                            "Close unused applications or add more RAM."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={
                            "check": "low_memory_pressure",
                            "total_ram": total_ram,
                            "available_ram": available_ram,
                            "percent_available": memory_available_percent,
                        },
                    )
                )

        # Get memory diagnostic results
        diag_info = self._get_memory_diagnostics()

        if diag_info is None:
            findings.append(
                Finding(
                    title="Could not retrieve memory diagnostic results",
                    description=(
                        "Failed to query memory diagnostic event logs. "
                        "Check if you have Administrator privileges."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "diag_query_failed"},
                )
            )
        else:
            # Check if diagnostics have ever been run
            if not diag_info.get("has_run", False):
                # On older machines, this might be a concern
                os_version = profile.os_version if profile else "unknown"
                if self._is_older_windows(os_version):
                    findings.append(
                        Finding(
                            title="Memory diagnostic has never been run",
                            description=(
                                "Windows Memory Diagnostic has not been run on this system. "
                                "For older PCs, running diagnostics is recommended to ensure "
                                "RAM is not failing. Memory failures are a common cause of "
                                "blue screens and crashes."
                            ),
                            severity=Severity.WARNING,
                            category=self.category,
                            data={"check": "never_run_on_old_machine"},
                        )
                    )
            else:
                # Check if the last diagnostic found errors
                if diag_info.get("has_errors", False):
                    findings.append(
                        Finding(
                            title="Memory diagnostic found errors",
                            description=(
                                f"The last memory diagnostic (run on {diag_info.get('last_run', 'unknown date')}) "
                                "detected errors in RAM. This indicates memory failure. "
                                "You should replace the faulty RAM module to prevent system crashes."
                            ),
                            severity=Severity.WARNING,
                            category=self.category,
                            data={
                                "check": "diagnostic_errors",
                                "last_run": diag_info.get("last_run"),
                                "error_details": diag_info.get("error_details"),
                            },
                        )
                    )

        # Add informational finding about current RAM status
        if ram_info:
            info_desc = (
                f"Total RAM: {_format_bytes(total_ram)}. "
                f"Available: {_format_bytes(available_ram)}. "
            )
            if diag_info and diag_info.get("has_run"):
                info_desc += (
                    f"Last memory diagnostic run: {diag_info.get('last_run', 'unknown')}. "
                )
                if not diag_info.get("has_errors"):
                    info_desc += "Diagnostic found no errors."
            else:
                info_desc += "No recent memory diagnostic results."

            findings.append(
                Finding(
                    title="Memory status",
                    description=info_desc,
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "check": "memory_status",
                        "total_ram": total_ram,
                        "available_ram": available_ram,
                        "formatted_total": _format_bytes(total_ram),
                        "formatted_available": _format_bytes(available_ram),
                    },
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        for finding in findings.findings:
            check = finding.data.get("check")

            if check == "diagnostic_errors":
                last_run = finding.data.get("last_run", "unknown date")
                actions.append(
                    Action(
                        title="Memory errors detected by Windows Memory Diagnostic",
                        description=(
                            f"Memory errors were detected in the diagnostic run on {last_run}. "
                            "This indicates RAM failure. Recommendations: "
                            "(1) Do not continue using the device for critical work. "
                            "(2) Back up all data immediately to an external drive. "
                            "(3) Shut down the PC and do not restart until RAM is replaced. "
                            "(4) Contact a qualified technician or the computer manufacturer "
                            "for RAM replacement."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "low_memory_pressure":
                actions.append(
                    Action(
                        title="High memory pressure detected",
                        description=(
                            "Available memory is critically low. "
                            "Recommendations: "
                            "(1) Close unnecessary applications to free memory. "
                            "(2) Check Task Manager (Ctrl+Shift+Esc) for memory-consuming processes. "
                            "(3) Increase virtual memory/page file size in System settings. "
                            "(4) Consider adding more RAM if the problem persists."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "never_run_on_old_machine":
                actions.append(
                    Action(
                        title="Memory diagnostic has never been run",
                        description=(
                            "Windows Memory Diagnostic is a built-in tool to check for RAM failures. "
                            "To run it: "
                            "(1) Open Settings and search for 'Windows Memory Diagnostic'. "
                            "(2) Click 'Restart now and check for problems (recommended)'. "
                            "(3) The system will restart and run the diagnostic automatically. "
                            "This process typically takes 5-30 minutes. "
                            "RAM failures are a common cause of blue screens on older systems."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "ram_info_failed":
                actions.append(
                    Action(
                        title="Unable to assess RAM information",
                        description=(
                            "Could not retrieve RAM information from the system. "
                            "Ensure you have Administrator privileges and run the diagnostic again. "
                            "You can manually check RAM status in Windows Settings > System > About."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "diag_query_failed":
                actions.append(
                    Action(
                        title="Unable to query memory diagnostic results",
                        description=(
                            "Could not access the memory diagnostic event log. "
                            "Ensure you have Administrator privileges. "
                            "Try running the diagnostic again using Windows Memory Diagnostic tool."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "memory_status":
                actions.append(
                    Action(
                        title="Memory status",
                        description=(
                            "Current RAM status is being monitored. "
                            "Continue regular backups and monitor system stability. "
                            "If you experience crashes or blue screens, run Windows Memory Diagnostic "
                            "to check for RAM failures."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _get_ram_info(self) -> Optional[dict]:
        """Get RAM information from PowerShell Get-WmiObject."""
        try:
            ps_cmd = (
                "Get-WmiObject Win32_OperatingSystem | "
                "Select-Object TotalVisibleMemorySize, FreePhysicalMemory | "
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

            return _parse_ram_info(result.stdout)
        except (OSError, subprocess.SubprocessError, TimeoutError):
            return None

    def _get_memory_diagnostics(self) -> Optional[dict]:
        """Get memory diagnostic results from Windows event logs."""
        try:
            # Query for memory diagnostic events
            ps_cmd = (
                "Get-WinEvent -FilterHashtable @{LogName='System'; "
                "ProviderName='Microsoft-Windows-MemoryDiagnostics-Results'} "
                "-MaxEvents 5 -ErrorAction SilentlyContinue | "
                "Select-Object TimeCreated, Message | ConvertTo-Json"
            )
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                return None

            return _parse_diagnostic_results(result.stdout)
        except (OSError, subprocess.SubprocessError, TimeoutError):
            return None

    def _is_older_windows(self, os_version: str) -> bool:
        """Determine if Windows version is older (Windows 7, 8, 8.1, or older)."""
        if not os_version:
            return False
        try:
            # Windows 7 = 6.1, Windows 8 = 6.2, Windows 8.1 = 6.3, Windows 10 = 10.0
            version_parts = os_version.split(".")
            if not version_parts:
                return False
            major_version = int(version_parts[0])
            # Consider Windows 8 and earlier as "older"
            return major_version <= 6
        except (ValueError, IndexError):
            return False


def _parse_ram_info(json_output: str) -> Optional[dict]:
    """Parse PowerShell JSON output from Get-WmiObject Win32_OperatingSystem."""
    if not json_output.strip():
        return None

    try:
        data = json.loads(json_output)

        total_kb = int(data.get("TotalVisibleMemorySize", 0))
        free_kb = int(data.get("FreePhysicalMemory", 0))

        # Convert KB to bytes
        total_bytes = total_kb * 1024
        available_bytes = free_kb * 1024

        return {
            "total_bytes": total_bytes,
            "available_bytes": available_bytes,
            "formatted_total": _format_bytes(total_bytes),
            "formatted_available": _format_bytes(available_bytes),
        }
    except (json.JSONDecodeError, ValueError, KeyError, TypeError):
        return None


def _parse_diagnostic_results(json_output: str) -> Optional[dict]:
    """Parse PowerShell JSON output from memory diagnostic event log."""
    if not json_output.strip():
        return {
            "has_run": False,
            "has_errors": False,
            "last_run": None,
            "error_details": None,
        }

    try:
        data = json.loads(json_output)

        # Handle both single object and array
        if not isinstance(data, list):
            data = [data] if data else []

        if not data:
            return {
                "has_run": False,
                "has_errors": False,
                "last_run": None,
                "error_details": None,
            }

        # Get the most recent event (first in list)
        latest_event = data[0]
        time_created = latest_event.get("TimeCreated", "unknown")
        message = latest_event.get("Message", "")

        # Check if message indicates errors
        has_errors = (
            "error" in message.lower()
            or "failed" in message.lower()
            or "problem" in message.lower()
        )

        return {
            "has_run": True,
            "has_errors": has_errors,
            "last_run": str(time_created),
            "error_details": message if has_errors else None,
        }
    except (json.JSONDecodeError, ValueError, KeyError, TypeError, IndexError):
        return {
            "has_run": False,
            "has_errors": False,
            "last_run": None,
            "error_details": None,
        }


def _format_bytes(bytes_value: int) -> str:
    """Convert bytes to human-readable format."""
    if not isinstance(bytes_value, int) or bytes_value == 0:
        return "Unknown"

    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if bytes_value < 1024:
            return f"{bytes_value:.1f} {unit}"
        bytes_value /= 1024
    return f"{bytes_value:.1f} PB"
