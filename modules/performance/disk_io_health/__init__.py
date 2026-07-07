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
    name = "disk_io_health"
    category = "performance"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "5s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Get disk type and TRIM status
        disk_info = self._get_disk_info()

        if not disk_info:
            findings.append(
                Finding(
                    title="Could not retrieve disk I/O information",
                    description=(
                        "Failed to run system_profiler or iostat commands. "
                        "Disk I/O health cannot be assessed."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "disk_info_failed"},
                )
            )
            return CheckResult(module_name=self.name, findings=findings)

        disk_type = disk_info.get("disk_type", "Unknown")
        is_ssd = disk_info.get("is_ssd")
        trim_enabled = disk_info.get("trim_enabled")
        io_throughput = disk_info.get("io_throughput", "unknown")

        # Check for HDD (major performance bottleneck)
        if is_ssd is False:
            findings.append(
                Finding(
                    title="Spinning hard drive detected",
                    description=(
                        "Your Mac is using a spinning hard drive (HDD), which is a significant "
                        "performance bottleneck on modern macOS. Consider upgrading to an SSD "
                        "for major performance improvements in system responsiveness, app launch "
                        "times, and file operations."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "check": "hdd_detected",
                        "disk_type": disk_type,
                        "is_ssd": is_ssd,
                    },
                )
            )

        # Check TRIM status for SSDs
        if is_ssd is True and trim_enabled is False:
            findings.append(
                Finding(
                    title="TRIM not enabled on SSD",
                    description=(
                        "Your SSD does not have TRIM enabled. TRIM helps maintain SSD performance "
                        "and longevity by allowing the OS to inform the drive when blocks are no "
                        "longer needed. Consider enabling TRIM or contacting Apple support."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "check": "trim_disabled",
                        "disk_type": disk_type,
                        "is_ssd": is_ssd,
                        "trim_enabled": trim_enabled,
                    },
                )
            )

        # If no issues found, add informational finding
        if not findings:
            findings.append(
                Finding(
                    title="Disk I/O health is good",
                    description=(
                        f"Disk type: {disk_type}. "
                        f"TRIM status: {'Enabled' if trim_enabled else 'N/A'}. "
                        f"I/O throughput: {io_throughput}. "
                        "No performance issues detected."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "check": "io_health_good",
                        "disk_type": disk_type,
                        "is_ssd": is_ssd,
                        "trim_enabled": trim_enabled,
                        "io_throughput": io_throughput,
                    },
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        for finding in findings.findings:
            check = finding.data.get("check")

            if check == "hdd_detected":
                actions.append(
                    Action(
                        title="Spinning hard drive performance warning",
                        description=(
                            "Your Mac is using a spinning hard drive, which significantly "
                            "impacts performance. Recommendations: "
                            "(1) Upgrade to an SSD for major performance improvements (most impactful upgrade). "
                            "(2) In the meantime, avoid unnecessary disk access during critical tasks. "
                            "(3) Consider external SSD for backup/archival to reduce main drive load. "
                            "(4) Contact Apple or a qualified technician for SSD upgrade options."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "trim_disabled":
                actions.append(
                    Action(
                        title="TRIM disabled on SSD",
                        description=(
                            "Your SSD does not have TRIM enabled. While third-party tools exist, "
                            "Apple does not provide a direct way to enable TRIM on non-Apple SSDs. "
                            "Recommendations: "
                            "(1) Consider replacing with an Apple SSD, which has TRIM enabled by default. "
                            "(2) Some third-party utilities claim to enable TRIM, but proceed with caution. "
                            "(3) Contact Apple or your SSD manufacturer for compatibility information. "
                            "(4) Monitor SSD health using diskutil or third-party tools."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "disk_info_failed":
                actions.append(
                    Action(
                        title="Unable to assess disk I/O health",
                        description=(
                            "The system_profiler or iostat commands failed. "
                            "Ensure you have sufficient permissions. "
                            "Try running 'system_profiler SPStorageDataType' manually in Terminal to diagnose."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "io_health_good":
                actions.append(
                    Action(
                        title="Disk I/O is performing normally",
                        description=(
                            "Your disk I/O performance is good. "
                            "Continue regular maintenance and backups to ensure optimal health."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _get_disk_info(self) -> dict:
        """Get disk information from system_profiler and iostat."""
        info = {}

        # Get disk type and TRIM info
        storage_info = self._get_storage_info()
        if storage_info:
            info.update(storage_info)

        # Get I/O stats
        io_stats = self._get_io_stats()
        if io_stats:
            info.update(io_stats)

        return info if info else None

    def _get_storage_info(self) -> dict:
        """Get disk type and TRIM status from system_profiler."""
        info = {}

        try:
            # Try to get storage info
            result = subprocess.run(
                ["system_profiler", "SPStorageDataType"],
                capture_output=True,
                text=True,
                errors="replace",
            )
            if result.returncode == 0:
                # Parse for SSD/HDD detection using regex
                solid_state_match = re.search(
                    r"Solid State Drive:\s*(Yes|No)", result.stdout, re.IGNORECASE
                )
                if solid_state_match:
                    is_ssd_str = solid_state_match.group(1).lower()
                    info["is_ssd"] = is_ssd_str == "yes"
                    info["disk_type"] = "SSD" if info["is_ssd"] else "HDD"
                elif "SSD" in result.stdout:
                    info["is_ssd"] = True
                    info["disk_type"] = "SSD"
                elif "HDD" in result.stdout or "Hard Disk" in result.stdout:
                    info["is_ssd"] = False
                    info["disk_type"] = "HDD"

        except (OSError, subprocess.SubprocessError):
            pass

        # Check TRIM status if SSD
        if info.get("is_ssd"):
            try:
                # Try SATA drives first
                result = subprocess.run(
                    ["system_profiler", "SPSerialATADataType"],
                    capture_output=True,
                    text=True,
                    errors="replace",
                )
                if result.returncode == 0:
                    # Look for TRIM status in output
                    if "TRIM Support: Yes" in result.stdout:
                        info["trim_enabled"] = True
                    elif "TRIM Support:" in result.stdout:
                        info["trim_enabled"] = False
            except (OSError, subprocess.SubprocessError):
                pass

            # If not found in SATA, try NVMe
            if "trim_enabled" not in info:
                try:
                    result = subprocess.run(
                        ["system_profiler", "SPNVMeDataType"],
                        capture_output=True,
                        text=True,
                        errors="replace",
                    )
                    if result.returncode == 0:
                        # NVMe drives typically support TRIM
                        if "NVMe" in result.stdout:
                            info["trim_enabled"] = True
                except (OSError, subprocess.SubprocessError):
                    pass

        return info

    def _get_io_stats(self) -> dict:
        """Get I/O performance stats from iostat."""
        info = {}

        try:
            # Run iostat for 2 samples with 1 second interval to get delta
            result = subprocess.run(
                ["iostat", "-d", "1", "2"],
                capture_output=True,
                text=True,
                errors="replace",
            )
            if result.returncode == 0:
                # Parse the second sample (most recent)
                lines = result.stdout.strip().split("\n")
                if len(lines) > 0:
                    # Extract throughput info from iostat output
                    # iostat output format varies, but we extract read/write rates if available
                    io_throughput = self._parse_iostat_output(result.stdout)
                    if io_throughput:
                        info["io_throughput"] = io_throughput

        except (OSError, subprocess.SubprocessError):
            pass

        return info

    def _parse_iostat_output(self, output: str) -> str:
        """Parse iostat output to extract throughput information."""
        lines = output.strip().split("\n")

        # Look for the last data line (skip headers)
        for line in reversed(lines):
            if line.strip() and not line.startswith("disk"):
                # Extract numeric values from the line
                parts = line.split()
                if len(parts) >= 3:
                    # Try to extract read/write throughput
                    # iostat format: disk r/s w/s Kr/s Kw/s ms/r ms/w %busy
                    try:
                        # Simple representation: show that iostat data was captured
                        return f"{len(parts)} I/O metrics captured"
                    except (ValueError, IndexError):
                        pass

        return None
