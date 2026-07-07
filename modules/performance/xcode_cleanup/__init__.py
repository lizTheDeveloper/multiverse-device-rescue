from pathlib import Path

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

# Thresholds
DERIVED_DATA_WARNING = 5 * 1024 * 1024 * 1024  # 5 GB
TOTAL_XCODE_WARNING = 20 * 1024 * 1024 * 1024  # 20 GB
CORE_SIMULATOR_WARNING = 10 * 1024 * 1024 * 1024  # 10 GB


class Module(ModuleBase):
    name = "xcode_cleanup"
    category = "performance"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 60
    depends_on = []
    estimated_duration = "10s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []
        home = Path.home()

        # Scan each Xcode-related directory
        derived_data_size = self._get_directory_size(
            home / "Library/Developer/Xcode/DerivedData"
        )
        archives_size = self._get_directory_size(
            home / "Library/Developer/Xcode/Archives"
        )
        device_support_size = self._get_directory_size(
            home / "Library/Developer/Xcode/iOS DeviceSupport"
        )
        core_simulator_size = self._get_directory_size(
            home / "Library/Developer/CoreSimulator/Devices"
        )
        xcode_caches_size = self._get_directory_size(
            home / "Library/Caches/com.apple.dt.Xcode"
        )

        # Calculate total Xcode-related usage
        total_xcode_size = (
            derived_data_size
            + archives_size
            + device_support_size
            + core_simulator_size
            + xcode_caches_size
        )

        # Report each location if it has content
        if derived_data_size > 0:
            severity = (
                Severity.WARNING
                if derived_data_size > DERIVED_DATA_WARNING
                else Severity.INFO
            )
            findings.append(
                Finding(
                    title=f"Xcode DerivedData: {_fmt_bytes(derived_data_size)}",
                    description=(
                        f"Xcode DerivedData at ~/Library/Developer/Xcode/DerivedData "
                        f"uses {_fmt_bytes(derived_data_size)}. This directory contains build artifacts "
                        f"and can be safely deleted to reclaim space."
                    ),
                    severity=severity,
                    category=self.category,
                    data={
                        "type": "derived_data",
                        "size_bytes": derived_data_size,
                        "size_formatted": _fmt_bytes(derived_data_size),
                    },
                )
            )

        if archives_size > 0:
            findings.append(
                Finding(
                    title=f"Xcode Archives: {_fmt_bytes(archives_size)}",
                    description=(
                        f"Xcode Archives at ~/Library/Developer/Xcode/Archives "
                        f"uses {_fmt_bytes(archives_size)}. These are old build archives that can be "
                        f"safely deleted unless you need them for distribution."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "type": "archives",
                        "size_bytes": archives_size,
                        "size_formatted": _fmt_bytes(archives_size),
                    },
                )
            )

        if device_support_size > 0:
            findings.append(
                Finding(
                    title=f"iOS DeviceSupport: {_fmt_bytes(device_support_size)}",
                    description=(
                        f"iOS DeviceSupport files at ~/Library/Developer/Xcode/iOS DeviceSupport "
                        f"use {_fmt_bytes(device_support_size)}. These are downloaded for specific iOS versions "
                        f"and can be safely deleted."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "type": "device_support",
                        "size_bytes": device_support_size,
                        "size_formatted": _fmt_bytes(device_support_size),
                    },
                )
            )

        if core_simulator_size > 0:
            severity = (
                Severity.WARNING
                if core_simulator_size > CORE_SIMULATOR_WARNING
                else Severity.INFO
            )
            findings.append(
                Finding(
                    title=f"CoreSimulator Devices: {_fmt_bytes(core_simulator_size)}",
                    description=(
                        f"CoreSimulator devices at ~/Library/Developer/CoreSimulator/Devices "
                        f"use {_fmt_bytes(core_simulator_size)}. These are simulator instances and their associated "
                        f"files. You can delete unused simulators."
                    ),
                    severity=severity,
                    category=self.category,
                    data={
                        "type": "core_simulator",
                        "size_bytes": core_simulator_size,
                        "size_formatted": _fmt_bytes(core_simulator_size),
                    },
                )
            )

        if xcode_caches_size > 0:
            findings.append(
                Finding(
                    title=f"Xcode Caches: {_fmt_bytes(xcode_caches_size)}",
                    description=(
                        f"Xcode caches at ~/Library/Caches/com.apple.dt.Xcode "
                        f"use {_fmt_bytes(xcode_caches_size)}. Cache files can be safely removed and will be "
                        f"regenerated as needed."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "type": "xcode_caches",
                        "size_bytes": xcode_caches_size,
                        "size_formatted": _fmt_bytes(xcode_caches_size),
                    },
                )
            )

        # Add overall warning if total Xcode usage is significant
        if total_xcode_size > TOTAL_XCODE_WARNING:
            findings.insert(
                0,
                Finding(
                    title=f"High Xcode storage usage: {_fmt_bytes(total_xcode_size)}",
                    description=(
                        f"Total Xcode-related files use {_fmt_bytes(total_xcode_size)}. "
                        f"Review the findings below for specific cleanup opportunities."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "type": "total_xcode",
                        "size_bytes": total_xcode_size,
                        "size_formatted": _fmt_bytes(total_xcode_size),
                    },
                ),
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        for finding in findings.findings:
            finding_type = finding.data.get("type", "unknown")
            size_str = finding.data.get("size_formatted", "unknown")

            if finding_type == "total_xcode":
                actions.append(
                    Action(
                        title="Total Xcode storage report",
                        description=(
                            f"Total: {size_str}. Review individual findings below to understand "
                            f"which categories have the most reclaimable space."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif finding_type == "derived_data":
                actions.append(
                    Action(
                        title=f"Xcode DerivedData: {size_str}",
                        description=(
                            f"DerivedData contains build artifacts from Xcode and can be safely deleted. "
                            f"Xcode will regenerate them on next build. "
                            f"To clean: rm -rf ~/Library/Developer/Xcode/DerivedData"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif finding_type == "archives":
                actions.append(
                    Action(
                        title=f"Xcode Archives: {size_str}",
                        description=(
                            f"Archives directory contains old build archives that can be safely deleted "
                            f"unless you need them for distribution. "
                            f"To clean: rm -rf ~/Library/Developer/Xcode/Archives"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif finding_type == "device_support":
                actions.append(
                    Action(
                        title=f"iOS DeviceSupport: {size_str}",
                        description=(
                            f"DeviceSupport files are downloaded for specific iOS versions and can be safely deleted. "
                            f"Xcode will re-download them when needed. "
                            f"To clean: rm -rf ~/Library/Developer/Xcode/iOS\\ DeviceSupport"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif finding_type == "core_simulator":
                actions.append(
                    Action(
                        title=f"CoreSimulator Devices: {size_str}",
                        description=(
                            f"CoreSimulator devices are simulator instances. Delete unused simulators from Xcode "
                            f"or via: xcrun simctl delete unavailable"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif finding_type == "xcode_caches":
                actions.append(
                    Action(
                        title=f"Xcode Caches: {size_str}",
                        description=(
                            f"Xcode caches can be safely removed and will be regenerated as needed. "
                            f"To clean: rm -rf ~/Library/Caches/com.apple.dt.Xcode"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _get_directory_size(self, path: Path) -> int:
        """Calculate total size of all files in directory, with error handling."""
        if not path.exists():
            return 0

        total_size = 0
        try:
            for item in path.rglob("*"):
                try:
                    if item.is_file(follow_symlinks=False):
                        total_size += item.stat().st_size
                except (OSError, PermissionError):
                    continue
        except (OSError, PermissionError):
            pass

        return total_size


def _fmt_bytes(n: int) -> str:
    """Format bytes as human-readable string."""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"
