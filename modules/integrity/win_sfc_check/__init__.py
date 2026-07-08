import json
import re
import subprocess
from datetime import datetime
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
    name = "win_sfc_check"
    category = "integrity"
    platforms = [Platform.WIN32]
    risk_level = RiskLevel.SAFE
    priority = 55
    depends_on = []
    estimated_duration = "30s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Check CBS.log for SFC results
        cbs_results = self._get_cbs_log_results()
        if cbs_results is None:
            findings.append(
                Finding(
                    title="Could not read CBS.log",
                    description=(
                        "Failed to read C:\\Windows\\Logs\\CBS\\CBS.log. "
                        "SFC scan results cannot be assessed. "
                        "Ensure you have Administrator privileges."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "cbs_log_failed"},
                )
            )
            return CheckResult(module_name=self.name, findings=findings)

        # Check for corrupted files that couldn't be repaired
        if cbs_results.get("cannot_repair_count", 0) > 0:
            cannot_repair = cbs_results.get("cannot_repair_count", 0)
            corrupted_files = cbs_results.get("cannot_repair_files", [])
            file_list = ", ".join(corrupted_files[:3])
            if len(corrupted_files) > 3:
                file_list += f", +{len(corrupted_files) - 3} more"

            findings.append(
                Finding(
                    title=f"SFC found {cannot_repair} corrupted file(s) that cannot be repaired",
                    description=(
                        f"Windows System File Checker detected {cannot_repair} corrupted system files "
                        f"that it could NOT repair. This indicates system integrity is compromised. "
                        f"Corrupted files: {file_list}. "
                        "This may cause crashes, blue screens, and broken Windows features. "
                        "Attempt to repair by running 'sfc /scannow' from an elevated Command Prompt or "
                        "use 'DISM /RestoreHealth' to restore from Windows Update."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
                    data={
                        "check": "cannot_repair",
                        "count": cannot_repair,
                        "files": corrupted_files,
                    },
                )
            )

        # Check for successfully repaired files
        if cbs_results.get("repaired_count", 0) > 0:
            repaired = cbs_results.get("repaired_count", 0)
            findings.append(
                Finding(
                    title=f"SFC found and repaired {repaired} corrupted file(s)",
                    description=(
                        f"Windows System File Checker found {repaired} corrupted system files "
                        f"and successfully repaired them. This indicates the system was previously "
                        f"broken but is now fixed. Continue monitoring for any recurring issues."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "check": "repaired",
                        "count": repaired,
                    },
                )
            )

        # Check for pending file rename operations (reboot needed)
        pending_ops = self._get_pending_file_operations()
        if pending_ops and pending_ops.get("pending_count", 0) > 0:
            findings.append(
                Finding(
                    title="Pending file rename operations detected",
                    description=(
                        f"Found {pending_ops['pending_count']} file(s) scheduled for replacement on next reboot. "
                        "These are typically files being updated by Windows Update or repaired by SFC. "
                        "A system reboot is required to complete these operations."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "check": "pending_operations",
                        "count": pending_ops.get("pending_count", 0),
                    },
                )
            )

        # Check if SFC has been run recently
        if cbs_results.get("last_scan_age_days") is not None:
            last_scan_age = cbs_results.get("last_scan_age_days", 0)
            if last_scan_age > 90:
                findings.append(
                    Finding(
                        title=f"SFC has not been run recently ({last_scan_age} days ago)",
                        description=(
                            f"The last SFC scan was {last_scan_age} days ago. "
                            "It is recommended to run SFC periodically to detect and repair corrupted "
                            "system files. Run 'sfc /scannow' from an elevated Command Prompt."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={
                            "check": "stale_scan",
                            "days_ago": last_scan_age,
                        },
                    )
                )

        # Check if no integrity violations were found
        if (cbs_results.get("cannot_repair_count", 0) == 0 and
            cbs_results.get("repaired_count", 0) == 0):
            if cbs_results.get("scan_found", False):
                findings.append(
                    Finding(
                        title="SFC scan shows no integrity violations",
                        description=(
                            "The most recent SFC scan found no integrity violations. "
                            "Windows system files are intact and healthy."
                        ),
                        severity=Severity.INFO,
                        category=self.category,
                        data={"check": "no_violations"},
                    )
                )

        # Add summary info if we have basic scan info
        if findings or cbs_results.get("scan_found", False):
            if not findings:
                # No issues found, add status info
                findings.append(
                    Finding(
                        title="SFC status check complete",
                        description="System File Checker scan results reviewed.",
                        severity=Severity.INFO,
                        category=self.category,
                        data={"check": "status_summary"},
                    )
                )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        for finding in findings.findings:
            check = finding.data.get("check")

            if check == "cannot_repair":
                count = finding.data.get("count", 0)
                actions.append(
                    Action(
                        title=f"SFC detected {count} unrepairable corrupted file(s)",
                        description=(
                            f"Windows System File Checker found {count} corrupted system files "
                            "that it could not repair automatically. "
                            "Recommendations: (1) Run 'sfc /scannow' from an elevated Command Prompt "
                            "to attempt repair again. (2) If that fails, use 'DISM /Online /Cleanup-Image /RestoreHealth' "
                            "to restore system files from Windows Update. (3) If corruption persists, "
                            "consider performing an in-place upgrade or clean Windows installation."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "repaired":
                count = finding.data.get("count", 0)
                actions.append(
                    Action(
                        title=f"SFC repaired {count} file(s)",
                        description=(
                            f"Windows System File Checker found and successfully repaired {count} corrupted files. "
                            "The system was previously broken but is now fixed. "
                            "Recommendations: (1) Monitor the system for any recurring issues. "
                            "(2) If the same problems recur, there may be underlying hardware or update issues. "
                            "(3) Check Windows Update for any pending updates. "
                            "(4) Monitor system logs for file corruption events."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "pending_operations":
                count = finding.data.get("count", 0)
                actions.append(
                    Action(
                        title=f"Pending file operations require reboot",
                        description=(
                            f"There are {count} file(s) scheduled for replacement on the next reboot. "
                            "Recommendations: (1) Save your work and close all applications. "
                            "(2) Restart the system to allow file operations to complete. "
                            "(3) After restart, run SFC again to verify all operations completed successfully."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "stale_scan":
                days_ago = finding.data.get("days_ago", 0)
                actions.append(
                    Action(
                        title=f"SFC last run {days_ago} days ago",
                        description=(
                            f"System File Checker has not been run in {days_ago} days. "
                            "It is recommended to run periodic SFC scans to maintain system integrity. "
                            "How to run: (1) Open Command Prompt as Administrator. "
                            "(2) Type: sfc /scannow "
                            "(3) A full scan typically takes 15-30 minutes. "
                            "(4) The system may require a reboot to complete repairs."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "no_violations":
                actions.append(
                    Action(
                        title="No system file integrity violations detected",
                        description=(
                            "The most recent SFC scan found no corrupted or damaged system files. "
                            "Windows system file integrity is healthy. "
                            "Recommendations: (1) Continue with regular system maintenance. "
                            "(2) Keep Windows Update current. "
                            "(3) Run SFC periodically (quarterly or after major updates)."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "cbs_log_failed":
                actions.append(
                    Action(
                        title="Unable to read CBS.log",
                        description=(
                            "Could not access the CBS log file. "
                            "Recommendations: (1) Run this diagnostic as Administrator. "
                            "(2) Verify the file exists at C:\\Windows\\Logs\\CBS\\CBS.log. "
                            "(3) If the file is missing, run 'sfc /scannow' to initialize SFC logging."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "status_summary":
                actions.append(
                    Action(
                        title="SFC status check complete",
                        description=(
                            "System File Checker status reviewed. "
                            "No immediate concerns detected. Continue regular system maintenance."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _get_cbs_log_results(self) -> Optional[dict]:
        """Parse CBS.log for SFC scan results."""
        try:
            # PowerShell command to get last SFC scan results from CBS.log
            ps_cmd = (
                'Select-String -Path "C:\\Windows\\Logs\\CBS\\CBS.log" '
                '-Pattern "Cannot repair|successfully repaired|no integrity violations" '
                "| Select-Object -Last 5 | ConvertTo-Json"
            )
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                timeout=15,
            )

            if result.returncode != 0:
                return None

            return _parse_cbs_results(result.stdout)

        except (OSError, subprocess.SubprocessError, TimeoutError):
            return None

    def _get_pending_file_operations(self) -> Optional[dict]:
        """Check for pending file rename operations via registry."""
        try:
            # Query registry for PendingFileRenameOperations
            result = subprocess.run(
                [
                    "reg",
                    "query",
                    "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager",
                    "/v",
                    "PendingFileRenameOperations",
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )

            if result.returncode != 0:
                # Key/value doesn't exist or error
                return {"pending_count": 0}

            # If we got output, parse for count
            output = result.stdout + result.stderr
            if "PendingFileRenameOperations" in output and output.strip():
                # Count the number of rename operations (each pair of lines = 1 operation)
                lines = [
                    line.strip()
                    for line in output.split("\n")
                    if line.strip() and not line.startswith("HKEY")
                ]
                # Rough count: typically 2 values per operation
                pending_count = max(1, len(lines) // 2)
                return {"pending_count": pending_count}

            return {"pending_count": 0}

        except (OSError, subprocess.SubprocessError, TimeoutError):
            return {"pending_count": 0}


def _parse_cbs_results(json_output: str) -> dict:
    """Parse CBS.log entries for SFC results."""
    results = {
        "cannot_repair_count": 0,
        "cannot_repair_files": [],
        "repaired_count": 0,
        "no_violations_found": False,
        "scan_found": False,
        "last_scan_age_days": None,
    }

    if not json_output.strip():
        return results

    try:
        lines = json_output.split("\n")
        cannot_repair_files = []
        repaired_count = 0
        cannot_repair_count = 0

        for line in lines:
            line = line.strip()
            if not line:
                continue

            # Count "Cannot repair" entries
            if "Cannot repair" in line:
                cannot_repair_count += 1
                # Try to extract filename
                match = re.search(r"file\s+([^\s]+)|Cannot repair\s+([^\s,]+)", line, re.IGNORECASE)
                if match:
                    filename = match.group(1) or match.group(2)
                    if filename and filename not in cannot_repair_files:
                        cannot_repair_files.append(filename)

            # Count "successfully repaired" entries
            if "successfully repaired" in line.lower():
                repaired_count += 1

            # Check for "no integrity violations"
            if "no integrity violations" in line.lower():
                results["no_violations_found"] = True

        results["cannot_repair_count"] = cannot_repair_count
        results["cannot_repair_files"] = cannot_repair_files
        results["repaired_count"] = repaired_count
        results["scan_found"] = True

        # Try to extract timestamp for age calculation
        results["last_scan_age_days"] = _estimate_scan_age(json_output)

        return results

    except (ValueError, AttributeError, IndexError):
        return results


def _estimate_scan_age(log_text: str) -> Optional[int]:
    """Try to estimate days since last SFC scan from log timestamps."""
    try:
        # Look for timestamp patterns in CBS.log format
        # CBS.log typically has timestamps like "2026-01-15 14:30:45.123+00:00"
        timestamp_pattern = r"(\d{4})-(\d{2})-(\d{2})\s+(\d{2}):(\d{2}):(\d{2})"
        matches = re.findall(timestamp_pattern, log_text)

        if not matches:
            return None

        # Get the last (most recent) timestamp
        last_match = matches[-1]
        year, month, day, hour, minute, second = map(int, last_match)

        try:
            last_scan = datetime(year, month, day, hour, minute, second)
            age = datetime.now() - last_scan
            return max(0, age.days)
        except ValueError:
            return None

    except (AttributeError, IndexError, ValueError):
        return None
