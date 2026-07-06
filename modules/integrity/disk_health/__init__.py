import re
import subprocess

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
    name = "disk_health"
    category = "integrity"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 60
    depends_on = []
    estimated_duration = "10s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Get disk info from diskutil info /
        disk_info = self._get_disk_info()
        if not disk_info:
            findings.append(
                Finding(
                    title="Could not retrieve disk information",
                    description=(
                        "Failed to run diskutil info /. Disk health cannot be assessed."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "disk_info_failed"},
                )
            )
            return CheckResult(module_name=self.name, findings=findings)

        # Check SMART status
        smart_status = disk_info.get("smart_status", "Unknown")
        if smart_status != "Verified":
            severity = Severity.CRITICAL if smart_status == "Failing" else Severity.WARNING
            findings.append(
                Finding(
                    title=f"Disk SMART status: {smart_status}",
                    description=(
                        f"Disk SMART status is '{smart_status}'. "
                        "This may indicate imminent disk failure. Back up your data immediately."
                    ),
                    severity=severity,
                    category=self.category,
                    data={"check": "smart_status", "smart_status": smart_status},
                )
            )

        # Check disk type
        disk_type = disk_info.get("disk_type", "Unknown")
        is_ssd = disk_info.get("is_ssd")

        # Get free space percentage for context
        free_pct_str = disk_info.get("free_pct_str", "unknown")

        # Add informational finding about disk type and health status
        if findings:  # Only add if there are issues
            findings[0].data["disk_type"] = disk_type
            findings[0].data["is_ssd"] = is_ssd
            findings[0].data["free_pct_str"] = free_pct_str
        else:
            # Add a positive finding if everything is OK
            findings.append(
                Finding(
                    title="Disk SMART status is healthy",
                    description=(
                        f"Disk type: {disk_type}. "
                        f"SMART status: {smart_status}. "
                        f"Free space: {free_pct_str}. "
                        "No issues detected."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "check": "disk_healthy",
                        "smart_status": smart_status,
                        "disk_type": disk_type,
                        "is_ssd": is_ssd,
                        "free_pct_str": free_pct_str,
                    },
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        for finding in findings.findings:
            check = finding.data.get("check")

            if check == "smart_status":
                smart_status = finding.data.get("smart_status")
                actions.append(
                    Action(
                        title="Disk SMART status warning",
                        description=(
                            f"Disk SMART status is '{smart_status}'. "
                            "This may indicate disk failure. "
                            "Recommendations: (1) Back up all data immediately to an external drive. "
                            "(2) Verify backups are readable and complete. "
                            "(3) If status is 'Failing', do not continue using the device for critical work. "
                            "(4) Contact an Apple Authorized Service Provider or qualified technician "
                            "for disk replacement."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "disk_info_failed":
                actions.append(
                    Action(
                        title="Unable to assess disk health",
                        description=(
                            "The diskutil info command failed. "
                            "Ensure you have sufficient permissions and the disk is accessible. "
                            "Try running 'diskutil info /' manually in Terminal to diagnose."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "disk_healthy":
                actions.append(
                    Action(
                        title="Disk health is normal",
                        description=(
                            "Your disk SMART status is verified and healthy. "
                            "Continue regular backups to protect your data."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _get_disk_info(self) -> dict:
        """Get disk information from diskutil info /."""
        try:
            result = subprocess.run(
                ["diskutil", "info", "/"],
                capture_output=True,
                text=True,
                errors="replace",
            )
            if result.returncode != 0:
                return {}
            return _parse_diskutil_info(result.stdout)
        except (OSError, subprocess.SubprocessError):
            return {}


def _parse_diskutil_info(output: str) -> dict:
    """Parse diskutil info output to extract disk health and type information."""
    info = {}

    # Extract SMART status
    smart_match = re.search(r"SMART Status:\s*(.+?)(?:\n|$)", output)
    if smart_match:
        info["smart_status"] = smart_match.group(1).strip()

    # Extract disk type (SSD vs HDD)
    # Look for "Solid State: Yes/No" or similar
    ssd_match = re.search(r"Solid State:\s*(Yes|No)", output, re.IGNORECASE)
    if ssd_match:
        is_ssd = ssd_match.group(1).lower() == "yes"
        info["is_ssd"] = is_ssd
        info["disk_type"] = "SSD" if is_ssd else "HDD"
    else:
        info["is_ssd"] = None
        info["disk_type"] = "Unknown"

    # Extract free space information
    free_match = re.search(r"Free Space:\s*([\d.]+\s*[KMGT]B)", output)
    total_match = re.search(r"Total Size:\s*([\d.]+\s*[KMGT]B)", output)

    if free_match and total_match:
        free_str = free_match.group(1).strip()
        # Try to parse and calculate percentage
        free_bytes = _parse_size_string(free_str)
        total_bytes = _parse_size_string(total_match.group(1).strip())
        if total_bytes and free_bytes:
            free_pct = (free_bytes / total_bytes) * 100
            info["free_pct_str"] = f"{free_pct:.1f}% ({free_str} free)"
        else:
            info["free_pct_str"] = f"{free_str} free"
    else:
        info["free_pct_str"] = "unknown"

    return info


def _parse_size_string(size_str: str) -> int:
    """Convert size string like '100 GB' to bytes."""
    match = re.match(r"([\d.]+)\s*([KMGT])B", size_str, re.IGNORECASE)
    if not match:
        return 0

    value = float(match.group(1))
    unit = match.group(2).upper()

    units = {"K": 1024, "M": 1024**2, "G": 1024**3, "T": 1024**4}
    return int(value * units.get(unit, 1))
