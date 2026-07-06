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
    name = "printer_queue"
    category = "integrity"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "10s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        printers_output = self._run_lpstat_printers()
        if printers_output is not None:
            printers_info = _parse_lpstat_printers(printers_output)

            # Report number of configured printers as INFO
            if printers_info["total"] > 0:
                findings.append(
                    Finding(
                        title=f"{printers_info['total']} printer(s) configured",
                        description=f"Available: {printers_info['enabled']}, Disabled: {printers_info['disabled']}",
                        severity=Severity.INFO,
                        category=self.category,
                        data={"check": "printer_count", "count": printers_info["total"]},
                    )
                )

            # Check for disabled printers
            if printers_info["disabled"] > 0:
                findings.append(
                    Finding(
                        title=f"{printers_info['disabled']} printer(s) disabled/paused",
                        description="Some printers are paused or disabled. They may need to be re-enabled.",
                        severity=Severity.WARNING,
                        category=self.category,
                        data={"check": "disabled_printers", "disabled_count": printers_info["disabled"]},
                    )
                )
        else:
            # lpstat failed
            findings.append(
                Finding(
                    title="Could not check printer status",
                    description="lpstat command is not available or CUPS is not running. Try running lpstat manually or check CUPS status.",
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "check_failed"},
                )
            )

        jobs_output = self._run_lpstat_jobs()
        if jobs_output is not None:
            jobs_info = _parse_lpstat_jobs(jobs_output)

            # Check for stuck jobs
            if jobs_info["stuck_count"] > 0:
                findings.append(
                    Finding(
                        title=f"{jobs_info['stuck_count']} stuck/stopped print job(s)",
                        description="Print jobs are stuck or stopped. Clear the queue or investigate the printer.",
                        severity=Severity.WARNING,
                        category=self.category,
                        data={"check": "stuck_jobs", "stuck_count": jobs_info["stuck_count"]},
                    )
                )

            # Check for old pending jobs (> 1 hour)
            if jobs_info["old_pending_count"] > 0:
                findings.append(
                    Finding(
                        title=f"{jobs_info['old_pending_count']} print job(s) pending for over 1 hour",
                        description="Jobs have been in the queue for a long time. They may be stuck or the printer may be offline.",
                        severity=Severity.WARNING,
                        category=self.category,
                        data={"check": "old_jobs", "old_job_count": jobs_info["old_pending_count"]},
                    )
                )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            check = finding.data.get("check")
            if check == "printer_count":
                # Just informational, no action needed
                pass
            elif check == "disabled_printers":
                actions.append(
                    Action(
                        title="Re-enable paused printers",
                        description=(
                            "Run `lpstat -p` to see which printers are disabled. "
                            "To re-enable, run `cupsenable <printer_name>` for each disabled printer. "
                            "Or use System Preferences > Printers & Scanners."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif check == "stuck_jobs":
                actions.append(
                    Action(
                        title="Clear stuck print jobs",
                        description=(
                            "Run `cancel -a` to clear all jobs from the queue. "
                            "Or run `cancel <job_id>` to cancel specific jobs. "
                            "Then check the printer status and try printing again."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif check == "old_jobs":
                actions.append(
                    Action(
                        title="Remove old pending jobs",
                        description=(
                            "Old jobs may be stuck. Run `cancel -a` to clear all pending jobs, "
                            "or `cancel <job_id>` to remove specific jobs. "
                            "Verify printer is online and try printing again."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif check == "check_failed":
                actions.append(
                    Action(
                        title="Manual printer queue inspection",
                        description=(
                            "CUPS may not be running or lpstat may not be available. "
                            "Try running `lpstat -p` manually to check printer status, "
                            "or check if CUPS is running with `sudo launchctl list | grep cups`."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _run_lpstat_printers(self) -> str | None:
        """Run lpstat -p to list configured printers. Returns None if lpstat is not available."""
        try:
            result = subprocess.run(
                ["lpstat", "-p"],
                capture_output=True,
                text=True,
            )
            return result.stdout
        except OSError:
            return None

    def _run_lpstat_jobs(self) -> str | None:
        """Run lpstat -o to list jobs in queue. Returns None if lpstat is not available."""
        try:
            result = subprocess.run(
                ["lpstat", "-o"],
                capture_output=True,
                text=True,
            )
            return result.stdout
        except OSError:
            return None


def _parse_lpstat_printers(output: str) -> dict:
    """Parse lpstat -p output to count enabled/disabled printers

    Example output:
    printer HP-Printer is idle.  enabled since Sat 01 Jan 2024 10:00:00 AM PST
    printer Canon-Printer is idle.  disabled since Sat 01 Jan 2024 09:00:00 AM PST
    """
    info = {"total": 0, "enabled": 0, "disabled": 0}

    for line in output.strip().splitlines():
        line = line.strip()
        if line.startswith("printer "):
            info["total"] += 1
            if "disabled" in line:
                info["disabled"] += 1
            elif "enabled" in line:
                info["enabled"] += 1

    return info


def _parse_lpstat_jobs(output: str) -> dict:
    """Parse lpstat -o output to find stuck and old jobs

    Example output:
    charlie-123    [job 2]    "test.pdf"    100%  processing
    alice-456      [job 1]    "document.pdf" 100%  stopped
    """
    info = {"stuck_count": 0, "old_pending_count": 0}

    now = datetime.now()
    one_hour_ago = now - timedelta(hours=1)

    for line in output.strip().splitlines():
        line = line.strip()
        if not line:
            continue

        # Check for stopped/stuck jobs
        if "stopped" in line.lower():
            info["stuck_count"] += 1

        # Note: lpstat -o output doesn't include timestamps by default
        # In a real implementation, we'd need to use lpstat -l for more detail
        # For now, we just flag stopped jobs as stuck

    return info
