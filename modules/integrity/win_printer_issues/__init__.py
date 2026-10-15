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
    name = "win_printer_issues"
    category = "integrity"
    platforms = [Platform.WIN32]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "15s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # List installed printers
        printer_finding = self._list_installed_printers()
        if printer_finding:
            findings.append(printer_finding)

        # Check for offline/error printers
        offline_findings = self._check_printer_status()
        findings.extend(offline_findings)

        # Check print spooler service status
        spooler_finding = self._check_spooler_service()
        if spooler_finding:
            findings.append(spooler_finding)

        # Check for stuck print jobs
        stuck_jobs_finding = self._check_stuck_print_jobs()
        if stuck_jobs_finding:
            findings.append(stuck_jobs_finding)

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            check_type = finding.data.get("check_type")
            if check_type == "printer_list":
                actions.append(
                    Action(
                        title="Installed printers listed",
                        description=finding.description,
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif check_type == "spooler_stopped":
                actions.append(
                    Action(
                        title="Print spooler is stopped",
                        description=(
                            "The Print Spooler service is not running. "
                            "This prevents all printing from working. "
                            "To fix: (1) Open Services (services.msc), "
                            "(2) Find 'Print Spooler', (3) Right-click and select 'Start', "
                            "(4) Set startup type to 'Automatic' to prevent this in the future."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif check_type == "printer_offline":
                printer_name = finding.data.get("printer_name", "Unknown")
                actions.append(
                    Action(
                        title=f"Printer '{printer_name}' is offline",
                        description=(
                            f"Printer '{printer_name}' is not responding. "
                            "To fix: (1) Check that the printer is powered on and connected to the network, "
                            "(2) Try pinging the printer's IP address to verify network connectivity, "
                            "(3) Clear the print queue by opening Settings > Devices > Printers & Scanners, "
                            "clicking the printer, and selecting 'Open queue', then clearing any stuck jobs, "
                            "(4) If available, restart the printer's web interface or control panel, "
                            "(5) Remove and re-add the printer in Windows settings."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif check_type == "stuck_print_jobs":
                actions.append(
                    Action(
                        title="Stuck print jobs detected",
                        description=(
                            "There are print jobs stuck in the queue. This prevents new print jobs from processing. "
                            "To fix: (1) Open Settings > Devices > Printers & Scanners, "
                            "(2) Click on your printer and select 'Open queue', "
                            "(3) Right-click each stuck job and select 'Cancel', "
                            "(4) If the queue still has jobs, stop the Print Spooler service: "
                            "Open Services (services.msc), right-click 'Print Spooler', click 'Stop', "
                            "(5) Navigate to C:\\Windows\\System32\\spool\\PRINTERS and delete all files, "
                            "(6) Start the Print Spooler service again, "
                            "(7) Restart your computer."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _list_installed_printers(self) -> Optional[Finding]:
        """List installed printers via PowerShell Get-Printer."""
        try:
            result = subprocess.run(
                [
                    "powershell",
                    "-NoProfile",
                    "-Command",
                    "Get-Printer | Select-Object Name, DriverName, PortName, PrinterStatus, Shared | Format-List",
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                output = result.stdout.strip()
                if output:
                    return Finding(
                        title="Installed printers",
                        description=f"Found installed printers:\n{output}",
                        severity=Severity.INFO,
                        category=self.category,
                        data={"check_type": "printer_list", "printers_output": output},
                    )
                else:
                    return Finding(
                        title="No printers installed",
                        description="No printers are currently installed on this system.",
                        severity=Severity.INFO,
                        category=self.category,
                        data={"check_type": "printer_list"},
                    )
        except (subprocess.TimeoutExpired, OSError):
            pass

        return None

    def _check_printer_status(self) -> list[Finding]:
        """Check for offline or error printers."""
        findings = []
        try:
            result = subprocess.run(
                [
                    "powershell",
                    "-NoProfile",
                    "-Command",
                    "Get-Printer | Select-Object Name, PrinterStatus | ConvertTo-Csv -NoTypeInformation",
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                output = result.stdout
                lines = output.split("\n")
                if len(lines) > 1:
                    # Skip header line (CSV header)
                    for line in lines[1:]:
                        line = line.strip()
                        if not line:
                            continue
                        # CSV format: "PrinterName","Status"
                        parts = [p.strip('"') for p in line.split('","')]
                        if len(parts) >= 2:
                            printer_name = parts[0]
                            status = parts[1]

                            # Flag offline or error states
                            if status.lower() in ["offline", "error"]:
                                findings.append(
                                    Finding(
                                        title=f"Printer '{printer_name}' is not ready",
                                        description=(
                                            f"Your printer named '{printer_name}' is currently "
                                            f"showing as {status.lower()}. This means "
                                            "it isn't ready to accept new print jobs.\n\n"
                                            "This often happens if the printer is out "
                                            "of paper, has a paper jam, or is turned "
                                            "off.\n\n"
                                            "What to do: Check the printer itself to "
                                            "make sure it is turned on, has paper, and "
                                            "is connected. If it looks fine, try turning "
                                            "it off, waiting 30 seconds, and turning "
                                            "it back on."
                                        ),
                                        severity=Severity.WARNING,
                                        category=self.category,
                                        data={
                                            "check_type": "printer_offline",
                                            "printer_name": printer_name,
                                            "status": status,
                                        },
                                    )
                                )

        except (subprocess.TimeoutExpired, OSError):
            pass

        return findings

    def _check_spooler_service(self) -> Optional[Finding]:
        """Check if Print Spooler service is running."""
        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", "Get-Service Spooler | Select-Object Status"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                output = result.stdout.lower()
                if "stopped" in output or "stop" in output:
                    return Finding(
                        title="The service that handles printing is turned off",
                        description=(
                            "Your computer has a background service called the Print Spooler "
                            "that manages sending documents to printers. Right now, this "
                            "service is stopped, which is why you can't print anything.\n\n"
                            "This is a common issue that usually happens if the service "
                            "crashed or was manually paused.\n\n"
                            "What to do: Open the Start menu, type 'Services', and press "
                            "Enter. Scroll down to 'Print Spooler', right-click it, and "
                            "select 'Start'. If it stops again, try restarting your computer."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={"check_type": "spooler_stopped"},
                    )
        except (subprocess.TimeoutExpired, OSError):
            pass

        return None

    def _check_stuck_print_jobs(self) -> Optional[Finding]:
        """Check for stuck print jobs."""
        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", "Get-PrintJob | Measure-Object | Select-Object Count"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                output = result.stdout.strip()
                # Try to extract count from output
                try:
                    # Output format is like:
                    # Count
                    # -----
                    #     3
                    lines = output.split("\n")
                    for i, line in enumerate(lines):
                        stripped = line.strip()
                        if stripped.isdigit():
                            count = int(stripped)
                            if count > 0:
                                return Finding(
                                    title=f"Your print queue is full ({count} jobs waiting)",
                                    description=(
                                        f"There are {count} documents waiting in your "
                                        "print queue that haven't finished. This usually "
                                        "happens if a printer ran out of paper, a cable "
                                        "got unplugged, or a job got stuck.\n\n"
                                        "These old jobs can block new ones from printing.\n\n"
                                        "What to do: Open the Start menu, type 'Print "
                                        "queues', and press Enter. Click on your printer, "
                                        "then choose 'Cancel All Documents' to clear "
                                        "the list. Try printing a new page to see if "
                                        "it works."
                                    ),
                                    severity=Severity.WARNING,
                                    category=self.category,
                                    data={"check_type": "stuck_print_jobs", "count": count},
                                )
                except (ValueError, IndexError):
                    pass
        except (subprocess.TimeoutExpired, OSError):
            pass

        return None
