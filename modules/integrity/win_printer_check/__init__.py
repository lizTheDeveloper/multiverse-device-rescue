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
    name = "win_printer_check"
    category = "integrity"
    platforms = [Platform.WIN32]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "10s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Check Print Spooler service status
        spooler_status = self._get_spooler_status()
        if spooler_status:
            status = spooler_status.get("status", "unknown").lower()
            startup_type = spooler_status.get("startup_type", "unknown").lower()

            findings.append(
                Finding(
                    title="Print Spooler service status",
                    description=(
                        f"Print Spooler service status: {status}. "
                        f"Startup type: {startup_type}"
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "check": "spooler_status",
                        "service_status": status,
                        "startup_type": startup_type,
                    },
                )
            )

            # Flag CRITICAL if spooler is stopped
            if status not in ["running", "ok"]:
                findings.append(
                    Finding(
                        title="Print Spooler service is not running",
                        description=(
                            f"Print Spooler service is not running (status: {status}). "
                            "This prevents printing. The service needs to be started."
                        ),
                        severity=Severity.CRITICAL,
                        category=self.category,
                        data={
                            "check": "spooler_stopped",
                            "service_status": status,
                        },
                    )
                )

        # Get list of printers
        printers_info = self._get_printers()
        if printers_info:
            printers = printers_info.get("printers", [])
            if printers:
                for printer in printers:
                    findings.append(
                        Finding(
                            title=f"Printer: {printer['name']}",
                            description=(
                                f"Status: {printer['status']}. "
                                f"Port: {printer['port']}. "
                                f"Driver: {printer['driver']}. "
                                f"Shared: {printer['shared']}"
                            ),
                            severity=Severity.INFO,
                            category=self.category,
                            data={
                                "check": "printer_info",
                                "printer_name": printer["name"],
                                "printer_status": printer["status"],
                                "printer_port": printer["port"],
                                "printer_driver": printer["driver"],
                                "printer_shared": printer["shared"],
                            },
                        )
                    )

                    # Flag WARNING if printer is in error or offline state
                    if printer["status"].lower() not in ["normal", "idle", "processing"]:
                        findings.append(
                            Finding(
                                title=f"Printer '{printer['name']}' has error or offline status",
                                description=(
                                    f"Printer '{printer['name']}' is in {printer['status']} state. "
                                    "The printer may be offline, out of paper, or experiencing errors."
                                ),
                                severity=Severity.WARNING,
                                category=self.category,
                                data={
                                    "check": "printer_error",
                                    "printer_name": printer["name"],
                                    "printer_status": printer["status"],
                                },
                            )
                        )

        # Check for default printer
        default_printer = self._get_default_printer()
        if default_printer:
            findings.append(
                Finding(
                    title=f"Default printer: {default_printer}",
                    description=f"Default printer is set to: {default_printer}",
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "check": "default_printer",
                        "printer_name": default_printer,
                    },
                )
            )
        else:
            findings.append(
                Finding(
                    title="No default printer set",
                    description="No default printer is currently set.",
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "no_default_printer"},
                )
            )

        # Check print queue for stuck jobs
        print_jobs = self._get_print_jobs()
        if print_jobs and print_jobs.get("jobs"):
            for job in print_jobs["jobs"]:
                findings.append(
                    Finding(
                        title=f"Print job: {job['name']} (ID: {job['id']})",
                        description=(
                            f"Job status: {job['status']}. "
                            f"Printer: {job['printer_name']}"
                        ),
                        severity=Severity.INFO,
                        category=self.category,
                        data={
                            "check": "print_job_info",
                            "job_id": job["id"],
                            "job_name": job["name"],
                            "job_status": job["status"],
                            "printer_name": job["printer_name"],
                        },
                    )
                )

                # Flag WARNING for stuck jobs (not "completed" or "normal")
                if job["status"].lower() not in ["completed", "normal", "printing"]:
                    findings.append(
                        Finding(
                            title=f"Stuck print job: {job['name']} (ID: {job['id']})",
                            description=(
                                f"Print job '{job['name']}' is stuck with status: {job['status']}. "
                                "This may block other print jobs."
                            ),
                            severity=Severity.WARNING,
                            category=self.category,
                            data={
                                "check": "stuck_print_job",
                                "job_id": job["id"],
                                "job_name": job["name"],
                                "job_status": job["status"],
                                "printer_name": job["printer_name"],
                            },
                        )
                    )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        for finding in findings.findings:
            check = finding.data.get("check")

            if check == "spooler_stopped":
                actions.append(
                    Action(
                        title="Restart Print Spooler service",
                        description=(
                            "Print Spooler service is not running. "
                            "Try the following: (1) Restart your computer. "
                            "(2) Open Services (services.msc) and find 'Print Spooler'. "
                            "(3) Right-click and select 'Start' if it's not running. "
                            "(4) Set startup type to 'Automatic' to ensure it starts on boot."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "printer_error":
                printer_name = finding.data.get("printer_name", "Unknown")
                printer_status = finding.data.get("printer_status", "Unknown")
                actions.append(
                    Action(
                        title=f"Resolve printer '{printer_name}' error",
                        description=(
                            f"Printer '{printer_name}' is in {printer_status} state. "
                            "Try the following: (1) Power-cycle the printer. "
                            "(2) Check the printer's display panel for error messages. "
                            "(3) Verify the printer is connected to the network or USB port. "
                            "(4) Restart the Print Spooler service. "
                            "(5) Remove and re-add the printer in Windows Settings."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "stuck_print_job":
                job_id = finding.data.get("job_id", "Unknown")
                job_name = finding.data.get("job_name", "Unknown")
                actions.append(
                    Action(
                        title=f"Clear stuck print job '{job_name}'",
                        description=(
                            f"Print job '{job_name}' (ID: {job_id}) is stuck. "
                            "Try the following: (1) Open Devices and Printers. "
                            "(2) Right-click the printer and select 'See what's printing'. "
                            "(3) Select the stuck job and click 'Printer' menu, then 'Cancel All Documents'. "
                            "(4) Restart the Print Spooler service if cancellation doesn't work."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "printer_info":
                printer_name = finding.data.get("printer_name", "Unknown")
                actions.append(
                    Action(
                        title=f"Printer '{printer_name}' is functional",
                        description=(
                            f"Printer '{printer_name}' is working normally."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "print_job_info":
                job_name = finding.data.get("job_name", "Unknown")
                actions.append(
                    Action(
                        title=f"Print job '{job_name}' is in queue",
                        description=(
                            f"Print job '{job_name}' is in the queue and will print normally."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "default_printer":
                printer_name = finding.data.get("printer_name", "Unknown")
                actions.append(
                    Action(
                        title=f"Default printer is set to '{printer_name}'",
                        description=(
                            f"Default printer is configured as '{printer_name}'. "
                            "This printer will be used by default when you print."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "no_default_printer":
                actions.append(
                    Action(
                        title="No default printer is set",
                        description=(
                            "No default printer is currently configured. "
                            "You will need to select a printer each time you print. "
                            "To set a default printer: (1) Open Settings > Devices > Printers & scanners. "
                            "(2) Click on a printer and select 'Manage'. "
                            "(3) Click 'Set as default'."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "spooler_status":
                service_status = finding.data.get("service_status", "unknown")
                actions.append(
                    Action(
                        title="Print Spooler service is running",
                        description=(
                            f"Print Spooler service is {service_status} and available for use."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _get_spooler_status(self) -> Optional[dict]:
        """Get Print Spooler service status."""
        try:
            result = subprocess.run(
                ["sc", "query", "Spooler"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                return None

            return _parse_service_status(result.stdout)
        except (OSError, subprocess.SubprocessError, TimeoutError):
            return None

    def _get_printers(self) -> Optional[dict]:
        """Get printer information from PowerShell."""
        try:
            ps_cmd = (
                "Get-Printer | "
                "Select-Object Name, PrinterStatus, PortName, DriverName, Shared | "
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

            return _parse_printers_info(result.stdout)
        except (OSError, subprocess.SubprocessError, TimeoutError):
            return None

    def _get_default_printer(self) -> Optional[str]:
        """Get the default printer name."""
        try:
            ps_cmd = (
                "(Get-WmiObject -Query 'select * from Win32_Printer where Default=True') | "
                "Select-Object -ExpandProperty Name"
            )
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                return None

            printer_name = result.stdout.strip()
            if printer_name:
                return printer_name
            return None
        except (OSError, subprocess.SubprocessError, TimeoutError):
            return None

    def _get_print_jobs(self) -> Optional[dict]:
        """Get print jobs from the queue."""
        try:
            ps_cmd = (
                "Get-PrintJob -PrinterName '*' | "
                "Select-Object Name, Id, PrinterName, @{Name='Status';Expression={$_.JobStatus}} | "
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

            return _parse_print_jobs_info(result.stdout)
        except (OSError, subprocess.SubprocessError, TimeoutError):
            return None


def _parse_service_status(output: str) -> dict:
    """Parse sc query output for service status."""
    status_info = {"status": "unknown", "startup_type": "unknown"}

    try:
        for line in output.split("\n"):
            line = line.strip()
            if "STATE" in line:
                # Extract status (Running, Stopped, etc.)
                if "RUNNING" in line:
                    status_info["status"] = "running"
                elif "STOPPED" in line:
                    status_info["status"] = "stopped"
                else:
                    # Extract the status value
                    parts = line.split(":")
                    if len(parts) > 1:
                        status_info["status"] = parts[1].strip()
            elif "START_TYPE" in line:
                # Extract startup type
                parts = line.split(":")
                if len(parts) > 1:
                    startup = parts[1].strip()
                    if "AUTO" in startup:
                        status_info["startup_type"] = "automatic"
                    elif "DEMAND" in startup:
                        status_info["startup_type"] = "manual"
                    elif "DISABLED" in startup:
                        status_info["startup_type"] = "disabled"
                    else:
                        status_info["startup_type"] = startup

        return status_info
    except (ValueError, IndexError):
        return status_info


def _parse_printers_info(json_output: str) -> dict:
    """Parse PowerShell JSON output for printers."""
    info = {"printers": []}

    if not json_output.strip():
        return info

    try:
        # Handle both single object and array
        data = json.loads(json_output)
        if not isinstance(data, list):
            data = [data]

        for printer in data:
            name = printer.get("Name", "Unknown")
            status = printer.get("PrinterStatus", "Unknown")
            port = printer.get("PortName", "Unknown")
            driver = printer.get("DriverName", "Unknown")
            shared = printer.get("Shared", False)

            info["printers"].append(
                {
                    "name": name,
                    "status": status,
                    "port": port,
                    "driver": driver,
                    "shared": shared,
                }
            )

        return info
    except (json.JSONDecodeError, ValueError, KeyError, TypeError):
        return info


def _parse_print_jobs_info(json_output: str) -> dict:
    """Parse PowerShell JSON output for print jobs."""
    info = {"jobs": []}

    if not json_output.strip():
        return info

    try:
        # Handle both single object and array
        data = json.loads(json_output)
        if not isinstance(data, list):
            data = [data]

        for job in data:
            name = job.get("Name", "Unknown")
            job_id = job.get("Id", "Unknown")
            printer_name = job.get("PrinterName", "Unknown")
            status = job.get("Status", "Unknown")

            info["jobs"].append(
                {
                    "name": name,
                    "id": job_id,
                    "printer_name": printer_name,
                    "status": status,
                }
            )

        return info
    except (json.JSONDecodeError, ValueError, KeyError, TypeError):
        return info
