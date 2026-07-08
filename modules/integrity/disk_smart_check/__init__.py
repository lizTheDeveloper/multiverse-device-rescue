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
    name = "disk_smart_check"
    category = "integrity"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 55
    depends_on = []
    estimated_duration = "10s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Get SMART status and drive info
        smart_info = self._get_smart_status()

        # Get disk space info
        space_info = self._get_disk_space()

        # Get APFS health if applicable
        apfs_info = self._get_apfs_health()

        # Check SMART status
        if smart_info.get("smart_status") == "Failing":
            findings.append(
                Finding(
                    title="CRITICAL: Drive SMART status is Failing",
                    description=(
                        f"Drive {smart_info.get('drive_model', 'Unknown')} ({smart_info.get('disk_type', 'Unknown')}) "
                        "reports SMART status 'Failing'. Drive failure is imminent. "
                        "Back up your data immediately!"
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
                    data={
                        "check": "smart_failing",
                        "smart_status": "Failing",
                        "drive_model": smart_info.get("drive_model"),
                        "disk_type": smart_info.get("disk_type"),
                    },
                )
            )
        elif smart_info.get("smart_status") and smart_info.get("smart_status") != "Verified":
            findings.append(
                Finding(
                    title=f"Drive SMART status: {smart_info.get('smart_status')}",
                    description=(
                        f"Drive {smart_info.get('drive_model', 'Unknown')} ({smart_info.get('disk_type', 'Unknown')}) "
                        f"reports SMART status '{smart_info.get('smart_status')}'. Status is not verified. "
                        "Monitor drive health and back up data as a precaution."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "check": "smart_warning",
                        "smart_status": smart_info.get("smart_status"),
                        "drive_model": smart_info.get("drive_model"),
                        "disk_type": smart_info.get("disk_type"),
                    },
                )
            )
        elif smart_info.get("smart_status"):
            # Healthy SMART status - report as INFO
            findings.append(
                Finding(
                    title="Drive SMART status: Verified",
                    description=(
                        f"Drive {smart_info.get('drive_model', 'Unknown')} ({smart_info.get('disk_type', 'Unknown')}) "
                        "reports SMART status 'Verified'. Drive appears to be in good health."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "check": "smart_healthy",
                        "smart_status": "Verified",
                        "drive_model": smart_info.get("drive_model"),
                        "disk_type": smart_info.get("disk_type"),
                        "capacity_gb": space_info.get("total_gb"),
                        "free_gb": space_info.get("free_gb"),
                        "free_percent": space_info.get("free_percent"),
                    },
                )
            )

        # Check SSD wear level
        if smart_info.get("disk_type") == "SSD" or smart_info.get("disk_type") == "NVMe":
            wear_percent = smart_info.get("wear_percent")
            if wear_percent is not None:
                if wear_percent > 80:
                    findings.append(
                        Finding(
                            title=f"SSD wear level high ({wear_percent}%)",
                            description=(
                                f"SSD {smart_info.get('drive_model', 'Unknown')} "
                                f"reports wear level of {wear_percent}%. "
                                "Plan for drive replacement soon to avoid data loss."
                            ),
                            severity=Severity.WARNING,
                            category=self.category,
                            data={
                                "check": "ssd_wear",
                                "wear_percent": wear_percent,
                                "drive_model": smart_info.get("drive_model"),
                            },
                        )
                    )
                elif wear_percent > 60:
                    findings.append(
                        Finding(
                            title=f"SSD wear level elevated ({wear_percent}%)",
                            description=(
                                f"SSD {smart_info.get('drive_model', 'Unknown')} "
                                f"reports wear level of {wear_percent}%. "
                                "Monitor wear level and plan for eventual replacement."
                            ),
                            severity=Severity.INFO,
                            category=self.category,
                            data={
                                "check": "ssd_wear_info",
                                "wear_percent": wear_percent,
                                "drive_model": smart_info.get("drive_model"),
                            },
                        )
                    )

        # Check disk space
        if space_info.get("free_percent") is not None:
            free_percent = space_info.get("free_percent")
            if free_percent < 10:
                findings.append(
                    Finding(
                        title=f"Low disk space ({free_percent:.1f}% free)",
                        description=(
                            f"Only {space_info.get('free_gb'):.1f}GB of {space_info.get('total_gb'):.1f}GB "
                            f"is free ({free_percent:.1f}%). "
                            "Delete unnecessary files or back up data to external storage."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={
                            "check": "low_disk_space",
                            "free_gb": space_info.get("free_gb"),
                            "total_gb": space_info.get("total_gb"),
                            "free_percent": free_percent,
                        },
                    )
                )

        # Check APFS container health if available
        if apfs_info.get("container_issues"):
            findings.append(
                Finding(
                    title="APFS container issues detected",
                    description=(
                        f"APFS container health check found issues: {apfs_info.get('container_issues')}. "
                        "Consider running First Aid in Disk Utility."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "check": "apfs_issues",
                        "container_issues": apfs_info.get("container_issues"),
                    },
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        for finding in findings.findings:
            check = finding.data.get("check")

            if check == "smart_failing":
                actions.append(
                    Action(
                        title="CRITICAL: Back up data immediately",
                        description=(
                            "Your drive's SMART status indicates imminent failure. "
                            "Actions: (1) IMMEDIATELY back up ALL critical data to an external drive or cloud storage. "
                            "(2) Verify the backup is complete and readable. "
                            "(3) Do NOT use this device for new work. "
                            "(4) Contact an Apple Authorized Service Provider for disk replacement. "
                            "(5) Minimize restarts and power cycles."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "smart_warning":
                actions.append(
                    Action(
                        title="Drive health status unclear - back up data",
                        description=(
                            f"SMART status is '{finding.data.get('smart_status')}'. "
                            "Actions: (1) Back up important data to external storage or cloud. "
                            "(2) Run Disk Utility First Aid to check for filesystem errors. "
                            "(3) Monitor drive for unusual behavior (slowness, noise, freezing). "
                            "(4) If issues persist, have the drive tested by a technician. "
                            "(5) Plan for eventual drive replacement."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "smart_healthy":
                actions.append(
                    Action(
                        title="Drive health is good",
                        description=(
                            "Your drive's SMART status is verified and it appears healthy. "
                            "Recommendations: (1) Continue regular backups. "
                            "(2) Monitor disk space to keep at least 10% free. "
                            "(3) Check SMART status periodically. "
                            "(4) Run Disk Utility First Aid if you notice performance issues."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "ssd_wear":
                actions.append(
                    Action(
                        title="SSD wear level is high - plan replacement",
                        description=(
                            f"SSD wear level is {finding.data.get('wear_percent')}%. "
                            "Actions: (1) Continue backing up data regularly. "
                            "(2) Reduce unnecessary write operations. "
                            "(3) Plan for SSD replacement in the near future. "
                            "(4) If failure occurs, your data may become inaccessible."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "ssd_wear_info":
                actions.append(
                    Action(
                        title="SSD wear level is elevated",
                        description=(
                            f"SSD wear level is {finding.data.get('wear_percent')}%. "
                            "This is normal wear over time. "
                            "Recommendations: (1) Continue regular backups. "
                            "(2) Monitor wear level over time. "
                            "(3) Plan for eventual SSD replacement (typically at 80%+ wear)."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "low_disk_space":
                actions.append(
                    Action(
                        title="Free up disk space",
                        description=(
                            f"Only {finding.data.get('free_percent'):.1f}% of disk space is free. "
                            "Actions: (1) Delete unnecessary files, downloads, or caches. "
                            "(2) Move large files to external storage. "
                            "(3) Empty Trash. "
                            "(4) Check ~/Library/Caches and ~/Downloads for large files. "
                            "(5) Maintain at least 10% free space for optimal performance."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "apfs_issues":
                actions.append(
                    Action(
                        title="Repair APFS container",
                        description=(
                            "APFS container issues detected. "
                            f"Issues: {finding.data.get('container_issues')}. "
                            "Actions: (1) Open Disk Utility. "
                            "(2) Select the affected volume in the sidebar. "
                            "(3) Click 'First Aid' and confirm. "
                            "(4) If issues persist, back up data and consider professional recovery."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _get_smart_status(self) -> dict:
        """Get SMART status from diskutil and system_profiler."""
        info = {}

        # Try diskutil first
        try:
            result = subprocess.run(
                ["diskutil", "info", "/"],
                capture_output=True,
                text=True,
                errors="replace",
            )
            if result.returncode == 0:
                parsed = _parse_diskutil_info(result.stdout)
                info.update(parsed)
        except (OSError, subprocess.SubprocessError):
            pass

        # Always try system_profiler SPStorageDataType to get wear level and additional info
        try:
            result = subprocess.run(
                ["system_profiler", "SPStorageDataType"],
                capture_output=True,
                text=True,
                errors="replace",
            )
            if result.returncode == 0:
                parsed = _parse_storage_profiler_info(result.stdout)
                # Merge with existing info, prefer diskutil SMART status if available
                if not info.get("smart_status") and parsed.get("smart_status"):
                    info["smart_status"] = parsed["smart_status"]
                if not info.get("drive_model") and parsed.get("drive_model"):
                    info["drive_model"] = parsed["drive_model"]
                if not info.get("disk_type") and parsed.get("disk_type"):
                    info["disk_type"] = parsed["disk_type"]
                # Always add wear level if present
                if parsed.get("wear_percent"):
                    info["wear_percent"] = parsed["wear_percent"]
        except (OSError, subprocess.SubprocessError):
            pass

        # If still no SMART status, try system_profiler SPNVMeDataType
        if not info.get("smart_status"):
            try:
                result = subprocess.run(
                    ["system_profiler", "SPNVMeDataType"],
                    capture_output=True,
                    text=True,
                    errors="replace",
                )
                if result.returncode == 0:
                    parsed = _parse_nvme_profiler_info(result.stdout)
                    info.update(parsed)
            except (OSError, subprocess.SubprocessError):
                pass

        return info

    def _get_disk_space(self) -> dict:
        """Get disk space information."""
        info = {}

        try:
            result = subprocess.run(
                ["df", "-B1", "/"],
                capture_output=True,
                text=True,
                errors="replace",
            )
            if result.returncode == 0:
                parsed = _parse_df_output(result.stdout)
                info.update(parsed)
        except (OSError, subprocess.SubprocessError):
            pass

        return info

    def _get_apfs_health(self) -> dict:
        """Get APFS container health information."""
        info = {}

        try:
            result = subprocess.run(
                ["diskutil", "apfs", "list"],
                capture_output=True,
                text=True,
                errors="replace",
            )
            if result.returncode == 0:
                parsed = _parse_apfs_list(result.stdout)
                info.update(parsed)
        except (OSError, subprocess.SubprocessError):
            pass

        return info


def _parse_diskutil_info(output: str) -> dict:
    """Parse diskutil info output."""
    info = {}

    # Extract SMART status
    smart_match = re.search(r"SMART Status:\s*(.+?)(?:\n|$)", output)
    if smart_match:
        info["smart_status"] = smart_match.group(1).strip()

    # Extract drive model
    model_match = re.search(r"Device / Media Name:\s*(.+?)(?:\n|$)", output)
    if model_match:
        info["drive_model"] = model_match.group(1).strip()

    # Extract disk type
    ssd_match = re.search(r"Solid State:\s*(Yes|No)", output, re.IGNORECASE)
    if ssd_match:
        is_ssd = ssd_match.group(1).lower() == "yes"
        info["disk_type"] = "SSD" if is_ssd else "HDD"

    return info


def _parse_storage_profiler_info(output: str) -> dict:
    """Parse system_profiler SPStorageDataType output."""
    info = {}

    # Look for SMART status
    smart_match = re.search(
        r"S\.M\.A\.R\.T\. Status:\s*(.+?)(?:\n|$)",
        output,
        re.IGNORECASE,
    )
    if smart_match:
        status_text = smart_match.group(1).strip()
        if "fail" in status_text.lower():
            info["smart_status"] = "Failing"
        elif "verif" in status_text.lower():
            info["smart_status"] = "Verified"
        else:
            info["smart_status"] = status_text

    # Extract device name
    model_match = re.search(r"Device Name:\s*(.+?)(?:\n|$)", output)
    if model_match:
        info["drive_model"] = model_match.group(1).strip()

    # Determine disk type
    if "SSD" in output:
        info["disk_type"] = "SSD"
    elif "HDD" in output or "SATA" in output:
        info["disk_type"] = "HDD"

    # Look for wear percentage
    wear_match = re.search(r"Wear Level:\s*(\d+)%", output, re.IGNORECASE)
    if wear_match:
        info["wear_percent"] = int(wear_match.group(1))

    return info


def _parse_nvme_profiler_info(output: str) -> dict:
    """Parse system_profiler SPNVMeDataType output."""
    info = {}

    # Look for health status
    health_match = re.search(
        r"Health:\s*(.+?)(?:\n|$)",
        output,
        re.IGNORECASE,
    )
    if health_match:
        health_text = health_match.group(1).strip()
        if "good" in health_text.lower() or "ok" in health_text.lower():
            info["smart_status"] = "Verified"
        elif "fail" in health_text.lower():
            info["smart_status"] = "Failing"
        else:
            info["smart_status"] = health_text

    # Extract model name
    model_match = re.search(r"Model:\s*(.+?)(?:\n|$)", output)
    if model_match:
        info["drive_model"] = model_match.group(1).strip()

    # NVMe is always SSD
    info["disk_type"] = "NVMe"

    # Look for wear percentage
    wear_match = re.search(r"Wear Level:\s*(\d+)%", output, re.IGNORECASE)
    if wear_match:
        info["wear_percent"] = int(wear_match.group(1))

    return info


def _parse_df_output(output: str) -> dict:
    """Parse df -B1 output to get disk space."""
    info = {}

    lines = output.strip().split("\n")
    if len(lines) >= 2:
        parts = lines[1].split()
        if len(parts) >= 4:
            try:
                total_bytes = int(parts[1])
                used_bytes = int(parts[2])
                free_bytes = int(parts[3])

                total_gb = total_bytes / (1024**3)
                free_gb = free_bytes / (1024**3)
                free_percent = (free_bytes / total_bytes) * 100 if total_bytes > 0 else 0

                info["total_gb"] = total_gb
                info["free_gb"] = free_gb
                info["free_percent"] = free_percent
            except (ValueError, IndexError):
                pass

    return info


def _parse_apfs_list(output: str) -> dict:
    """Parse diskutil apfs list output."""
    info = {}

    # Check for common error indicators
    issues = []

    if "Repairing" in output or "Repairing" in output.lower():
        issues.append("Container is repairing")
    if "Encrypting" in output:
        issues.append("Container is encrypting")
    if "Decrypting" in output:
        issues.append("Container is decrypting")
    if "Defragmenting" in output:
        issues.append("Container is defragmenting")

    if issues:
        info["container_issues"] = ", ".join(issues)

    return info
