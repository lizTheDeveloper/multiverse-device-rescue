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
    name = "smart_status"
    category = "integrity"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 55
    depends_on = []
    estimated_duration = "5s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Try to get SMART status from multiple sources
        smart_status = None
        drive_model = None
        drive_type = None

        # Source 1: diskutil info /
        disk_info = self._get_diskutil_smart_info()
        if disk_info:
            smart_status = disk_info.get("smart_status")
            drive_model = disk_info.get("drive_model")
            drive_type = disk_info.get("disk_type")

        # Source 2: system_profiler SPStorageDataType (for SATA/SSD drives)
        if not smart_status:
            storage_info = self._get_storage_profiler_smart_info()
            if storage_info:
                smart_status = storage_info.get("smart_status")
                drive_model = storage_info.get("drive_model")
                drive_type = storage_info.get("disk_type")

        # Source 3: system_profiler SPNVMeDataType (for NVMe drives)
        if not smart_status or drive_type is None:
            nvme_info = self._get_nvme_profiler_smart_info()
            if nvme_info:
                if not smart_status:
                    smart_status = nvme_info.get("smart_status")
                if not drive_model:
                    drive_model = nvme_info.get("drive_model")
                if not drive_type:
                    drive_type = nvme_info.get("disk_type")

        # If we couldn't get SMART status from any source, report warning
        if not smart_status:
            findings.append(
                Finding(
                    title="Could not retrieve SMART status",
                    description=(
                        "Failed to retrieve disk SMART status from diskutil or system_profiler. "
                        "Disk health cannot be assessed."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "smart_status_unavailable"},
                )
            )
            return CheckResult(module_name=self.name, findings=findings)

        # Determine severity based on SMART status
        if smart_status == "Failing":
            severity = Severity.CRITICAL
        elif smart_status != "Verified":
            severity = Severity.WARNING
        else:
            severity = Severity.INFO

        # Build description with available info
        description_parts = [f"SMART Status: {smart_status}"]
        if drive_model:
            description_parts.append(f"Drive Model: {drive_model}")
        if drive_type:
            description_parts.append(f"Drive Type: {drive_type}")

        description = ", ".join(description_parts) + "."

        if severity == Severity.CRITICAL:
            description += (
                " WARNING: Your drive is failing! Back up your data immediately!"
            )
        elif severity == Severity.WARNING:
            description += (
                " CAUTION: SMART status is not verified. Back up your data as a precaution."
            )
        elif severity == Severity.INFO:
            description += " Your drive appears to be in good health."

        findings.append(
            Finding(
                title=f"Disk SMART Status: {smart_status}",
                description=description,
                severity=severity,
                category=self.category,
                data={
                    "check": "smart_status",
                    "smart_status": smart_status,
                    "drive_model": drive_model,
                    "drive_type": drive_type,
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
                drive_model = finding.data.get("drive_model", "Unknown")
                drive_type = finding.data.get("drive_type", "Unknown")

                if smart_status == "Failing":
                    actions.append(
                        Action(
                            title="CRITICAL: Drive is failing",
                            description=(
                                f"Drive SMART status is 'Failing' ({drive_model}, {drive_type}). "
                                "URGENT: Your drive is dying. "
                                "Recommendations: "
                                "(1) Back up ALL data immediately to an external drive or cloud storage. "
                                "(2) Verify backups are complete and readable. "
                                "(3) STOP using this device for critical work. "
                                "(4) Contact an Apple Authorized Service Provider for disk replacement. "
                                "(5) Do NOT restart the device unnecessarily."
                            ),
                            risk_level=RiskLevel.SAFE,
                            success=True,
                        )
                    )
                elif smart_status != "Verified":
                    actions.append(
                        Action(
                            title="Drive SMART status not verified",
                            description=(
                                f"Drive SMART status is '{smart_status}' ({drive_model}, {drive_type}). "
                                "The drive's health status is unknown. "
                                "Recommendations: "
                                "(1) Back up your important data to an external drive or cloud storage. "
                                "(2) Verify the backup is complete and readable. "
                                "(3) Monitor the drive for any unusual behavior (slow performance, noise, freezing). "
                                "(4) Consider having the drive tested by a technician. "
                                "(5) If issues persist, plan for drive replacement."
                            ),
                            risk_level=RiskLevel.SAFE,
                            success=True,
                        )
                    )
                else:  # Verified
                    actions.append(
                        Action(
                            title="Drive SMART status is healthy",
                            description=(
                                f"Drive SMART status is 'Verified' ({drive_model}, {drive_type}). "
                                "Your drive appears to be in good health. "
                                "Recommendations: "
                                "Continue regular backups to protect your data. "
                                "Monitor drive health periodically."
                            ),
                            risk_level=RiskLevel.SAFE,
                            success=True,
                        )
                    )

            elif check == "smart_status_unavailable":
                actions.append(
                    Action(
                        title="Unable to assess SMART status",
                        description=(
                            "Could not retrieve SMART status from diskutil or system_profiler. "
                            "Ensure you have sufficient permissions. "
                            "Try running 'diskutil info /' manually in Terminal to diagnose."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _get_diskutil_smart_info(self) -> dict:
        """Get SMART status from diskutil info /."""
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

    def _get_storage_profiler_smart_info(self) -> dict:
        """Get SMART status from system_profiler SPStorageDataType."""
        try:
            result = subprocess.run(
                ["system_profiler", "SPStorageDataType"],
                capture_output=True,
                text=True,
                errors="replace",
            )
            if result.returncode != 0:
                return {}
            return _parse_storage_profiler_info(result.stdout)
        except (OSError, subprocess.SubprocessError):
            return {}

    def _get_nvme_profiler_smart_info(self) -> dict:
        """Get SMART status from system_profiler SPNVMeDataType."""
        try:
            result = subprocess.run(
                ["system_profiler", "SPNVMeDataType"],
                capture_output=True,
                text=True,
                errors="replace",
            )
            if result.returncode != 0:
                return {}
            return _parse_nvme_profiler_info(result.stdout)
        except (OSError, subprocess.SubprocessError):
            return {}


def _parse_diskutil_info(output: str) -> dict:
    """Parse diskutil info output to extract SMART status information."""
    info = {}

    # Extract SMART status
    smart_match = re.search(r"SMART Status:\s*(.+?)(?:\n|$)", output)
    if smart_match:
        info["smart_status"] = smart_match.group(1).strip()

    # Extract drive model from "Device / Media Name"
    model_match = re.search(r"Device / Media Name:\s*(.+?)(?:\n|$)", output)
    if model_match:
        info["drive_model"] = model_match.group(1).strip()

    # Extract disk type (SSD vs HDD)
    ssd_match = re.search(r"Solid State:\s*(Yes|No)", output, re.IGNORECASE)
    if ssd_match:
        is_ssd = ssd_match.group(1).lower() == "yes"
        info["disk_type"] = "SSD" if is_ssd else "HDD"
    else:
        info["disk_type"] = None

    return info


def _parse_storage_profiler_info(output: str) -> dict:
    """Parse system_profiler SPStorageDataType output to extract SMART info."""
    info = {}

    # Look for SMART status in the output
    smart_match = re.search(
        r"S\.M\.A\.R\.T\. Status:\s*(.+?)(?:\n|$)",
        output,
        re.IGNORECASE,
    )
    if smart_match:
        status_text = smart_match.group(1).strip()
        # Normalize to "Verified", "Failing", etc.
        if "fail" in status_text.lower():
            info["smart_status"] = "Failing"
        elif "verif" in status_text.lower():
            info["smart_status"] = "Verified"
        else:
            info["smart_status"] = status_text

    # Extract device name/model
    model_match = re.search(r"Device Name:\s*(.+?)(?:\n|$)", output)
    if model_match:
        info["drive_model"] = model_match.group(1).strip()

    # Try to determine disk type from output
    if "SSD" in output:
        info["disk_type"] = "SSD"
    elif "HDD" in output or "SATA" in output:
        info["disk_type"] = "HDD"

    return info


def _parse_nvme_profiler_info(output: str) -> dict:
    """Parse system_profiler SPNVMeDataType output to extract SMART info."""
    info = {}

    # NVMe drives typically show health status
    # Look for common health indicators
    health_match = re.search(
        r"Health:\s*(.+?)(?:\n|$)",
        output,
        re.IGNORECASE,
    )
    if health_match:
        health_text = health_match.group(1).strip()
        # Normalize health status
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

    # NVMe drives are always SSDs
    info["disk_type"] = "NVMe"

    return info
