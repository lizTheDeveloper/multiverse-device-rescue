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
    name = "win_print_spooler_check"
    category = "integrity"
    platforms = [Platform.WIN32]
    risk_level = RiskLevel.SAFE
    priority = 55
    depends_on = []
    estimated_duration = "20s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Get Print Spooler service status
        spooler_status = self._get_spooler_service_status()
        if not spooler_status:
            findings.append(
                Finding(
                    title="Could not determine Print Spooler status",
                    description=(
                        "Failed to query Print Spooler service status via 'sc query Spooler'. "
                        "Ensure you have Administrator privileges."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "spooler_status_failed"},
                )
            )
            return CheckResult(module_name=self.name, findings=findings)

        spooler_running = spooler_status.get("running", False)

        # Get printer information
        printers_info = self._get_printers_info()
        printer_count = printers_info.get("printer_count", 0) if printers_info else 0
        drivers_info = printers_info.get("drivers_info", {}) if printers_info else {}

        # Check for stuck print jobs (only if spooler running)
        stuck_jobs = None
        if spooler_running:
            stuck_jobs = self._get_stuck_print_jobs()

        # Check spooler queue folder size (only if spooler running)
        queue_size_mb = None
        if spooler_running:
            queue_size_mb = self._get_spooler_queue_size()

        # Check for remote connections (security risk)
        accepts_remote = self._check_remote_connections()

        # CRITICAL: Spooler running AND accepting remote connections (PrintNightmare)
        if spooler_running and accepts_remote:
            findings.append(
                Finding(
                    title="Print Spooler accepting remote connections (PrintNightmare risk)",
                    description=(
                        "The Print Spooler service is running and accepting remote connections. "
                        "This is a known security risk (CVE-2021-34527, PrintNightmare) that can be "
                        "exploited for remote code execution. Disable remote connections immediately "
                        "unless explicitly required."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
                    data={
                        "check": "remote_spooler_running",
                        "spooler_status": "running",
                        "accepts_remote": True,
                    },
                )
            )

        # WARNING: Stuck print jobs
        if stuck_jobs and stuck_jobs.get("count", 0) > 0:
            findings.append(
                Finding(
                    title=f"Stuck print jobs detected ({stuck_jobs['count']})",
                    description=(
                        f"Found {stuck_jobs['count']} print job(s) in an abnormal state. "
                        "These jobs may be blocking new print requests or consuming resources. "
                        "Clear the print queue to resolve this issue."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "check": "stuck_print_jobs",
                        "count": stuck_jobs["count"],
                        "jobs": stuck_jobs.get("jobs", []),
                    },
                )
            )

        # WARNING: Spooler queue folder too large
        if queue_size_mb and queue_size_mb > 100:
            findings.append(
                Finding(
                    title=f"Print spooler queue folder very large ({queue_size_mb}MB)",
                    description=(
                        f"The print spooler queue folder is {queue_size_mb}MB, indicating stale or "
                        "accumulated print jobs. This may cause performance issues or prevent printing. "
                        "Clear the print queue and remove stale jobs."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "check": "queue_size_large",
                        "size_mb": queue_size_mb,
                    },
                )
            )

        # WARNING: Spooler stopped but printers installed
        if not spooler_running and printer_count > 0:
            findings.append(
                Finding(
                    title="Print Spooler stopped but printers installed",
                    description=(
                        f"The Print Spooler service is not running, but {printer_count} printer(s) "
                        "are installed on this system. Users will be unable to print. "
                        "Start the Print Spooler service to restore printing."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "check": "spooler_stopped_with_printers",
                        "printer_count": printer_count,
                    },
                )
            )

        # INFO: Spooler status and printer information
        status_msg = "running" if spooler_running else "stopped"
        info_msg = f"Print Spooler is {status_msg}. "
        if printer_count > 0:
            info_msg += f"{printer_count} printer(s) installed. "
        else:
            info_msg += "No printers installed. "

        if drivers_info.get("total", 0) > 0:
            outdated_count = drivers_info.get("outdated", 0)
            if outdated_count > 0:
                info_msg += f"{outdated_count} potentially outdated driver(s) detected."
            else:
                info_msg += "Printer drivers appear current."

        findings.append(
            Finding(
                title="Print Spooler status summary",
                description=info_msg,
                severity=Severity.INFO,
                category=self.category,
                data={
                    "check": "spooler_status_info",
                    "spooler_running": spooler_running,
                    "printer_count": printer_count,
                    "drivers_info": drivers_info,
                    "accepts_remote": accepts_remote if accepts_remote is not None else "unknown",
                },
            )
        )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        for finding in findings.findings:
            check = finding.data.get("check")

            if check == "remote_spooler_running":
                actions.append(
                    Action(
                        title="Print Spooler accepting remote connections (PrintNightmare)",
                        description=(
                            "The Print Spooler is running and accepting remote connections. "
                            "This is a known security vulnerability (CVE-2021-34527). "
                            "Recommended actions: "
                            "(1) Disable remote printing: In Services, set Print Spooler 'Allow service to interact with desktop' to False. "
                            "(2) Or disable the service entirely if printing is not required. "
                            "(3) Apply Windows security updates to patch PrintNightmare. "
                            "(4) Consider restricting spooler access via Windows Firewall."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "stuck_print_jobs":
                actions.append(
                    Action(
                        title="Stuck print jobs detected",
                        description=(
                            f"Found {finding.data.get('count', 0)} stuck print job(s). "
                            "Recommended actions: "
                            "(1) Stop the Print Spooler service (net stop spooler). "
                            "(2) Delete all files in C:\\Windows\\System32\\spool\\PRINTERS. "
                            "(3) Restart the Print Spooler service (net start spooler). "
                            "(4) Retry printing."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "queue_size_large":
                size_mb = finding.data.get("size_mb", 0)
                actions.append(
                    Action(
                        title=f"Spooler queue folder too large ({size_mb}MB)",
                        description=(
                            f"The print spooler queue is consuming {size_mb}MB of disk space. "
                            "This typically indicates stale or accumulating print jobs. "
                            "Recommended actions: "
                            "(1) Stop the Print Spooler service (net stop spooler). "
                            "(2) Clear the spool folder: Remove all files from C:\\Windows\\System32\\spool\\PRINTERS. "
                            "(3) Restart the Print Spooler service (net start spooler). "
                            "(4) Monitor disk usage and printer queue in the future."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "spooler_stopped_with_printers":
                printer_count = finding.data.get("printer_count", 0)
                actions.append(
                    Action(
                        title=f"Print Spooler stopped ({printer_count} printer(s) installed)",
                        description=(
                            f"The Print Spooler service is not running, but {printer_count} printer(s) are installed. "
                            "Users cannot print. "
                            "Recommended actions: "
                            "(1) Start the Print Spooler service: Run 'net start spooler' in Command Prompt (as Administrator) "
                            "or use Services (services.msc). "
                            "(2) Set Print Spooler to start automatically. "
                            "(3) Test printing to verify functionality."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "spooler_status_failed":
                actions.append(
                    Action(
                        title="Unable to assess Print Spooler status",
                        description=(
                            "The Print Spooler status check failed. Ensure you are running "
                            "the diagnostic with Administrator privileges. "
                            "Try running: sc query Spooler"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "spooler_status_info":
                actions.append(
                    Action(
                        title="Print Spooler status summary",
                        description=(
                            "Print Spooler diagnostics completed. "
                            "No critical issues detected. Continue monitoring printer health."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _get_spooler_service_status(self) -> Optional[dict]:
        """Check Print Spooler service status via 'sc query Spooler'."""
        try:
            result = subprocess.run(
                ["sc", "query", "Spooler"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                return None

            # Parse output to determine if running
            output = result.stdout.lower()
            running = "state" in output and "running" in output

            return {
                "running": running,
                "output": result.stdout,
            }
        except (OSError, subprocess.SubprocessError, TimeoutError):
            return None

    def _get_printers_info(self) -> Optional[dict]:
        """Get installed printers and driver information via PowerShell."""
        try:
            # Get printers
            ps_cmd = (
                "Get-Printer -ErrorAction SilentlyContinue | "
                "Select-Object Name, DriverName, PortName, PrinterStatus | "
                "ConvertTo-Json"
            )
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                timeout=15,
            )

            printers = []
            if result.returncode == 0 and result.stdout.strip():
                try:
                    data = json.loads(result.stdout)
                    if not isinstance(data, list):
                        data = [data]
                    printers = data
                except json.JSONDecodeError:
                    pass

            # Get printer drivers
            drivers_info = {"total": 0, "outdated": 0}
            ps_cmd = (
                "Get-PrinterDriver -ErrorAction SilentlyContinue | "
                "Select-Object Name, Manufacturer, PrinterEnvironment, Version | "
                "ConvertTo-Json"
            )
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                timeout=15,
            )

            if result.returncode == 0 and result.stdout.strip():
                try:
                    drivers = json.loads(result.stdout)
                    if not isinstance(drivers, list):
                        drivers = [drivers]
                    drivers_info["total"] = len(drivers)
                    # Flag drivers with empty version or old patterns as potentially outdated
                    outdated_count = sum(
                        1 for d in drivers
                        if not d.get("Version") or "Legacy" in d.get("Name", "")
                    )
                    drivers_info["outdated"] = outdated_count
                except json.JSONDecodeError:
                    pass

            return {
                "printer_count": len(printers),
                "printers": printers,
                "drivers_info": drivers_info,
            }
        except (OSError, subprocess.SubprocessError, TimeoutError):
            return None

    def _get_stuck_print_jobs(self) -> Optional[dict]:
        """Check for stuck print jobs via PowerShell."""
        try:
            ps_cmd = (
                "Get-PrintJob -PrinterName * -ErrorAction SilentlyContinue | "
                "Where-Object {$_.JobStatus -ne 'Completed'} | "
                "Select-Object PrinterName, JobStatus, DocumentName, Size | "
                "ConvertTo-Json"
            )
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                timeout=15,
            )

            jobs = []
            if result.returncode == 0 and result.stdout.strip():
                try:
                    data = json.loads(result.stdout)
                    if not isinstance(data, list):
                        data = [data]
                    jobs = data
                except json.JSONDecodeError:
                    pass

            return {
                "count": len(jobs),
                "jobs": jobs,
            }
        except (OSError, subprocess.SubprocessError, TimeoutError):
            return None

    def _get_spooler_queue_size(self) -> Optional[int]:
        """Check print spooler queue folder size via PowerShell (in MB)."""
        try:
            ps_cmd = (
                "(Get-ChildItem -Recurse 'C:\\Windows\\System32\\spool\\PRINTERS' "
                "-ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum"
            )
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                timeout=10,
            )

            if result.returncode == 0 and result.stdout.strip():
                try:
                    size_bytes = int(result.stdout.strip())
                    size_mb = size_bytes // (1024 * 1024)
                    return size_mb
                except (ValueError, TypeError):
                    return None
            return 0
        except (OSError, subprocess.SubprocessError, TimeoutError):
            return None

    def _check_remote_connections(self) -> Optional[bool]:
        """Check if Print Spooler is accepting remote connections (security risk)."""
        try:
            # Check via Registry or Windows Firewall rules
            # We'll check if the spooler is listening on network ports
            ps_cmd = (
                "Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue | "
                "Where-Object {$_.OwningProcess -eq (Get-Process spoolsv -ErrorAction SilentlyContinue).Id} | "
                "Measure-Object | Select-Object -ExpandProperty Count"
            )
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                timeout=10,
            )

            if result.returncode == 0:
                try:
                    count = int(result.stdout.strip())
                    # If spooler is listening on network ports, it accepts remote connections
                    return count > 0
                except (ValueError, TypeError):
                    return None
            return None
        except (OSError, subprocess.SubprocessError, TimeoutError):
            return None
