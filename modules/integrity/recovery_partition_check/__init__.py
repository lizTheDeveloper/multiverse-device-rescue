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
    name = "recovery_partition_check"
    category = "integrity"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 55
    depends_on = []
    estimated_duration = "10s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Check if Apple Silicon (firmware recovery always available)
        is_apple_silicon = self._is_apple_silicon(profile)

        # Get diskutil list output to find recovery partition
        diskutil_list = self._run_diskutil_list()
        recovery_info = _parse_diskutil_list(diskutil_list)

        # If no recovery partition found
        if not recovery_info.get("recovery_found"):
            if is_apple_silicon:
                # Apple Silicon always has firmware recovery
                findings.append(
                    Finding(
                        title="Apple Silicon Mac with firmware recovery",
                        description=(
                            "This Mac uses Apple Silicon (T2/M-series) with firmware-based "
                            "recovery. A Recovery partition is not required as recovery is "
                            "built into the firmware. Internet Recovery is always available."
                        ),
                        severity=Severity.INFO,
                        category=self.category,
                        data={
                            "check": "apple_silicon_recovery",
                            "recovery_found": False,
                            "apple_silicon": True,
                        },
                    )
                )
            else:
                # Intel Mac without recovery partition is critical
                findings.append(
                    Finding(
                        title="No Recovery partition found",
                        description=(
                            "This Intel Mac does not have a Recovery partition. Without a "
                            "Recovery partition, you cannot reinstall macOS or use Disk Utility "
                            "in recovery mode. You must recreate it or use Internet Recovery."
                        ),
                        severity=Severity.CRITICAL,
                        category=self.category,
                        data={
                            "check": "no_recovery_partition",
                            "recovery_found": False,
                            "apple_silicon": False,
                        },
                    )
                )
        else:
            # Recovery partition found - check its size
            recovery_size = recovery_info.get("recovery_size_mb", 0)

            if recovery_size < 500:
                findings.append(
                    Finding(
                        title=f"Recovery partition unusually small ({recovery_size}MB)",
                        description=(
                            f"The Recovery partition is only {recovery_size}MB, which is "
                            "smaller than expected (typically 500MB-1GB). This may prevent "
                            "macOS recovery operations. Consider recreating it."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={
                            "check": "small_recovery_partition",
                            "recovery_size_mb": recovery_size,
                        },
                    )
                )
            else:
                # Recovery partition is healthy
                findings.append(
                    Finding(
                        title=f"Recovery partition found ({recovery_size}MB)",
                        description=(
                            f"A Recovery partition is present and has a normal size of {recovery_size}MB. "
                            "You can use it to reinstall macOS or use Disk Utility."
                        ),
                        severity=Severity.INFO,
                        category=self.category,
                        data={
                            "check": "recovery_partition_healthy",
                            "recovery_size_mb": recovery_size,
                            "recovery_found": True,
                        },
                    )
                )

        # Always report Apple Silicon status if applicable
        if is_apple_silicon and recovery_info.get("recovery_found"):
            findings.append(
                Finding(
                    title="Apple Silicon Mac detected",
                    description=(
                        "This Mac has Apple Silicon (T2/M-series). Recovery is built into "
                        "the firmware, so you can always use Internet Recovery as a backup."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "apple_silicon_detected", "apple_silicon": True},
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        for finding in findings.findings:
            check = finding.data.get("check")

            if check == "no_recovery_partition":
                actions.append(
                    Action(
                        title="Recovery partition missing guidance",
                        description=(
                            "To recreate the Recovery partition, you need to:\n\n"
                            "1. Download macOS from the App Store\n"
                            "2. Create a bootable USB installer using the downloaded macOS\n"
                            "3. Boot from the USB and use Disk Utility to restore or partition the drive\n"
                            "4. Reinstall macOS, which will recreate the Recovery partition\n\n"
                            "Alternatively, you can use Internet Recovery (Command+Option+R on startup) "
                            "to reinstall macOS without a Recovery partition."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "small_recovery_partition":
                recovery_size = finding.data.get("recovery_size_mb")
                actions.append(
                    Action(
                        title="Recovery partition is undersized guidance",
                        description=(
                            f"Your Recovery partition is {recovery_size}MB, smaller than the typical 500MB-1GB. "
                            "To fix this, you can reinstall macOS to recreate it properly:\n\n"
                            "1. Boot into Recovery Mode (Command+R on startup)\n"
                            "2. Use Disk Utility to repair the drive (if possible)\n"
                            "3. Reinstall macOS from Recovery, which will recreate a proper Recovery partition\n\n"
                            "If Recovery Mode won't boot, use Internet Recovery (Command+Option+R) instead."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "recovery_partition_healthy":
                recovery_size = finding.data.get("recovery_size_mb")
                actions.append(
                    Action(
                        title="Recovery partition is healthy",
                        description=(
                            f"Your Recovery partition is healthy at {recovery_size}MB. "
                            "You can use it to boot into Recovery Mode (Command+R on startup) "
                            "to reinstall macOS or repair your drive with Disk Utility."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "apple_silicon_recovery":
                actions.append(
                    Action(
                        title="Firmware recovery available on Apple Silicon",
                        description=(
                            "This Mac has firmware-based recovery built in. You can always:\n\n"
                            "1. Press and hold the power button to force shutdown\n"
                            "2. Restart and hold Command+Option+R to enter Internet Recovery\n"
                            "3. Use Recovery to reinstall macOS or repair your drive\n\n"
                            "A traditional Recovery partition is not required on Apple Silicon Macs."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "apple_silicon_detected":
                actions.append(
                    Action(
                        title="Apple Silicon provides fallback recovery",
                        description=(
                            "Your Mac has Apple Silicon with firmware-based recovery. "
                            "Internet Recovery is always available, providing a reliable fallback "
                            "for reinstalling macOS and repairing your drive."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _is_apple_silicon(self, profile: SystemProfile) -> bool:
        """Check if system is Apple Silicon (T2/M-series)."""
        cpu = profile.cpu_model.lower() if profile.cpu_model else ""
        # Check for Apple Silicon indicators: M1, M2, M3, M4, etc., or T2
        return bool(re.search(r"\b(apple m|m1|m2|m3|m4|t2)\b", cpu))

    def _run_diskutil_list(self) -> str:
        """Run diskutil list and return output."""
        try:
            result = subprocess.run(
                ["diskutil", "list"],
                capture_output=True,
                text=True,
                errors="replace",
            )
            return result.stdout
        except (OSError, subprocess.SubprocessError):
            return ""

    def _run_diskutil_info(self, device: str) -> str:
        """Run diskutil info on a device and return output."""
        try:
            result = subprocess.run(
                ["diskutil", "info", device],
                capture_output=True,
                text=True,
                errors="replace",
            )
            return result.stdout
        except (OSError, subprocess.SubprocessError):
            return ""


def _parse_diskutil_list(output: str) -> dict:
    """Parse diskutil list output to find recovery partition."""
    info = {"recovery_found": False, "recovery_size_mb": 0}

    # Look for Recovery partition (both "Apple_Boot Recovery HD" and "APFS Recovery")
    # Pattern: Recovery partitions typically show as:
    # - Apple_Boot Recovery HD (traditional)
    # - APFS Recovery (APFS-based)
    # The size is typically listed on the same line

    # Look for APFS Recovery entries
    apfs_recovery_pattern = r"(APFS\s+Recovery.*?)\s+(\d+(?:\.\d+)?)\s*([KMGT]B)"
    apfs_matches = re.findall(apfs_recovery_pattern, output)
    if apfs_matches:
        info["recovery_found"] = True
        # Get the first (largest) recovery partition size
        for match in apfs_matches:
            size_val = float(match[1])
            unit = match[2].upper()
            if unit == "KB":
                size_mb = size_val / 1024
            elif unit == "MB":
                size_mb = size_val
            elif unit == "GB":
                size_mb = size_val * 1024
            elif unit == "TB":
                size_mb = size_val * 1024 * 1024
            else:
                continue
            info["recovery_size_mb"] = int(size_mb)
            break

    # Look for Apple_Boot Recovery HD entries
    if not info["recovery_found"]:
        apple_boot_pattern = r"Apple_Boot.*?Recovery.*?(\d+(?:\.\d+)?)\s*([KMGT]B)"
        apple_boot_matches = re.findall(apple_boot_pattern, output)
        if apple_boot_matches:
            info["recovery_found"] = True
            match = apple_boot_matches[0]
            size_val = float(match[0])
            unit = match[1].upper()
            if unit == "KB":
                size_mb = size_val / 1024
            elif unit == "MB":
                size_mb = size_val
            elif unit == "GB":
                size_mb = size_val * 1024
            elif unit == "TB":
                size_mb = size_val * 1024 * 1024
            else:
                size_mb = 0
            info["recovery_size_mb"] = int(size_mb)

    return info
