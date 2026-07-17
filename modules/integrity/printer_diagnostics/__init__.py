import re
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
    name = "printer_diagnostics"
    category = "integrity"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "10s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Check CUPS scheduler status first
        scheduler_running = self._check_cups_scheduler()
        if not scheduler_running:
            findings.append(
                Finding(
                    title="CUPS scheduler is not running",
                    description=(
                        "The CUPS (Common Unix Printing System) scheduler is not running. "
                        "Printing will not work until the CUPS service is restarted."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
                    data={"check": "cups_scheduler", "running": False},
                )
            )

        # Get list of printers
        printers_output = self._run_lpstat_printers()
        default_printer_output = self._run_lpstat_default()
        queue_output = self._run_lpstat_queue()

        printers = _parse_printers(printers_output)
        default_printer = _parse_default_printer(default_printer_output)
        queued_jobs = _parse_queue(queue_output)

        # Check for stuck print jobs in queue
        if queued_jobs > 0:
            findings.append(
                Finding(
                    title=f"Print queue has {queued_jobs} stuck job(s)",
                    description=(
                        f"There are {queued_jobs} job(s) in the print queue that may be stuck. "
                        "These jobs can be cleared by restarting CUPS or manually removing them."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "print_queue", "jobs": queued_jobs},
                )
            )

        # Check printers status and report
        if printers:
            # Check for printers in error state
            error_printers = [p for p in printers if p.get("state") == "disabled"]
            if error_printers:
                for printer in error_printers:
                    findings.append(
                        Finding(
                            title=f"Printer '{printer['name']}' is disabled",
                            description=(
                                f"Printer '{printer['name']}' is currently disabled or in error state. "
                                "Check the printer's physical status and CUPS configuration."
                            ),
                            severity=Severity.WARNING,
                            category=self.category,
                            data={
                                "check": "printer_error",
                                "printer": printer["name"],
                                "state": printer.get("state"),
                            },
                        )
                    )
        else:
            # Only report no printers if nothing else (CUPS, queue, etc.) is already reported
            findings.append(
                Finding(
                    title="No printers configured",
                    description=(
                        "No printers are currently configured in CUPS. "
                        "Add a printer using System Preferences > Printers & Scanners or via CUPS web interface."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "no_printers"},
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        for finding in findings.findings:
            check = finding.data.get("check")

            if check == "cups_scheduler":
                actions.append(
                    Action(
                        title="Restart CUPS scheduler",
                        description=(
                            "To restart the CUPS scheduler, run: sudo launchctl stop org.cups.cupsd && "
                            "sudo launchctl start org.cups.cupsd\n\n"
                            "Alternatively, you can use: sudo /usr/sbin/cupsd\n\n"
                            "After restarting, verify CUPS is running with: lpstat -r"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "print_queue":
                actions.append(
                    Action(
                        title="Clear stuck print jobs",
                        description=(
                            "To clear stuck print jobs from the queue, run: \n"
                            "lpstat -o | awk '{print $1}' | xargs -I {} lprm {}\n\n"
                            "Or remove all jobs: sudo rm -rf /var/spool/cups/d*\n\n"
                            "Then restart CUPS: sudo launchctl stop org.cups.cupsd && "
                            "sudo launchctl start org.cups.cupsd"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "printer_error":
                printer = finding.data.get("printer")
                actions.append(
                    Action(
                        title=f"Re-enable printer '{printer}'",
                        description=(
                            f"The printer '{printer}' is disabled. "
                            "To re-enable it:\n\n"
                            "1. Open System Preferences > Printers & Scanners\n"
                            "2. Select '{printer}' from the list\n"
                            "3. Click the lock icon and authenticate if needed\n"
                            "4. Check for error messages and resolve hardware issues\n\n"
                            "Or use CUPS CLI: cupsenable " + printer
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "printers_list":
                printers = finding.data.get("printers", [])
                default = finding.data.get("default")
                actions.append(
                    Action(
                        title=f"Printer status summary",
                        description=(
                            f"You have {len(printers)} printer(s) configured: "
                            + ", ".join(printers) + "\n\n"
                            f"Default printer: {default}\n\n"
                            "Use 'lpstat -p -d' to check printer status at any time."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "no_printers":
                actions.append(
                    Action(
                        title="Add a printer",
                        description=(
                            "No printers are currently configured. To add a printer:\n\n"
                            "1. Open System Preferences > Printers & Scanners\n"
                            "2. Click the '+' button to add a printer\n"
                            "3. Select your printer from the network or USB list\n\n"
                            "Or access CUPS web interface at: http://localhost:631"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _check_cups_scheduler(self) -> bool:
        """Check if CUPS scheduler is running."""
        try:
            result = subprocess.run(
                ["lpstat", "-r"],
                capture_output=True,
                text=True,
                errors="replace",
            )
            return result.returncode == 0 and "scheduler is running" in result.stdout
        except (OSError, subprocess.SubprocessError):
            return False

    def _run_lpstat_printers(self) -> str:
        """Run lpstat -p to list printers."""
        try:
            result = subprocess.run(
                ["lpstat", "-p"],
                capture_output=True,
                text=True,
                errors="replace",
            )
            return result.stdout
        except (OSError, subprocess.SubprocessError):
            return ""

    def _run_lpstat_default(self) -> str:
        """Run lpstat -d to get default printer."""
        try:
            result = subprocess.run(
                ["lpstat", "-d"],
                capture_output=True,
                text=True,
                errors="replace",
            )
            return result.stdout
        except (OSError, subprocess.SubprocessError):
            return ""

    def _run_lpstat_queue(self) -> str:
        """Run lpstat -o to list print queue."""
        try:
            result = subprocess.run(
                ["lpstat", "-o"],
                capture_output=True,
                text=True,
                errors="replace",
            )
            return result.stdout
        except (OSError, subprocess.SubprocessError):
            return ""


def _parse_printers(output: str) -> list[dict]:
    """Parse lpstat -p output to extract printer names and states."""
    printers = []
    # Line format: printer HP-OfficeJet-Pro is idle. enabled since...
    for line in output.strip().split("\n"):
        if line.startswith("printer "):
            parts = line.split()
            if len(parts) >= 2:
                name = parts[1]
                # Check if disabled
                is_disabled = "disabled" in line
                state = "disabled" if is_disabled else "enabled"
                printers.append({"name": name, "state": state})
    return printers


def _parse_default_printer(output: str) -> Optional[str]:
    """Parse lpstat -d output to extract default printer name."""
    # Line format: system default destination: HP-OfficeJet-Pro
    match = re.search(r"destination:\s+(\S+)", output)
    if match:
        return match.group(1)
    return None


def _parse_queue(output: str) -> int:
    """Parse lpstat -o output to count jobs in queue."""
    # Each job is on a line like: HP-OfficeJet-Pro-1 user@hostname 1024 Mon Jan 1 10:00:00 2025
    lines = [line for line in output.strip().split("\n") if line.strip()]
    return len(lines)
