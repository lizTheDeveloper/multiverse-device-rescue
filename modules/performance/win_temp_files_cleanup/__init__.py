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

# Thresholds for warnings
TEMP_SIZE_WARNING_GB = 5  # 5 GB of temp files
WINDOWS_UPDATE_CACHE_WARNING_GB = 2  # 2 GB of stale updates
RECYCLE_BIN_WARNING_GB = 2  # 2 GB of forgotten deletions


class Module(ModuleBase):
    name = "win_temp_files_cleanup"
    category = "performance"
    platforms = [Platform.WIN32]
    risk_level = RiskLevel.SAFE
    priority = 60
    depends_on = []
    estimated_duration = "30s"

    def check(self, profile: SystemProfile) -> CheckResult:
        """Audit Windows temp file accumulation."""
        findings = []
        temp_breakdown = {}
        total_reclaimable = 0

        try:
            # Check user temp directory
            user_temp_size = self._get_user_temp_size()
            if user_temp_size is not None:
                temp_breakdown["user_temp"] = user_temp_size
                total_reclaimable += user_temp_size

            # Check Windows temp directory
            windows_temp_size = self._get_windows_temp_size()
            if windows_temp_size is not None:
                temp_breakdown["windows_temp"] = windows_temp_size
                total_reclaimable += windows_temp_size

            # Check Prefetch directory
            prefetch_size = self._get_prefetch_size()
            if prefetch_size is not None:
                temp_breakdown["prefetch"] = prefetch_size
                total_reclaimable += prefetch_size

            # Check Windows Update cache
            update_cache_size = self._get_windows_update_cache_size()
            if update_cache_size is not None:
                temp_breakdown["update_cache"] = update_cache_size
                total_reclaimable += update_cache_size

            # Check Recycle Bin
            recycle_bin_size = self._get_recycle_bin_size()
            if recycle_bin_size is not None:
                temp_breakdown["recycle_bin"] = recycle_bin_size
                total_reclaimable += recycle_bin_size

            # Count old files in temp directories
            old_files_count = self._count_old_temp_files()

            # Check for warnings based on thresholds
            if total_reclaimable > TEMP_SIZE_WARNING_GB * (1024**3):
                findings.append(
                    Finding(
                        title="Excessive temp file accumulation",
                        description=(
                            f"Total temp files consume {_fmt_bytes(total_reclaimable)}, "
                            f"exceeding {TEMP_SIZE_WARNING_GB}GB threshold. "
                            "Clearing these files can reclaim significant disk space."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={
                            "total_size": total_reclaimable,
                            "breakdown": temp_breakdown,
                            "old_files_count": old_files_count,
                        },
                    )
                )

            if update_cache_size and update_cache_size > WINDOWS_UPDATE_CACHE_WARNING_GB * (1024**3):
                findings.append(
                    Finding(
                        title="Large Windows Update cache detected",
                        description=(
                            f"Windows Update cache at {_fmt_bytes(update_cache_size)} "
                            f"exceeds {WINDOWS_UPDATE_CACHE_WARNING_GB}GB. "
                            "Stale updates should be cleaned to free space."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={
                            "cache_size": update_cache_size,
                            "location": "C:\\Windows\\SoftwareDistribution\\Download",
                        },
                    )
                )

            if recycle_bin_size and recycle_bin_size > RECYCLE_BIN_WARNING_GB * (1024**3):
                findings.append(
                    Finding(
                        title="Large Recycle Bin",
                        description=(
                            f"Recycle Bin contains {_fmt_bytes(recycle_bin_size)}, "
                            f"exceeding {RECYCLE_BIN_WARNING_GB}GB. "
                            "These are forgotten deletions that can be permanently removed."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={"recycle_bin_size": recycle_bin_size},
                    )
                )

            # Always add INFO finding with breakdown
            findings.append(
                Finding(
                    title="Temp file accumulation report",
                    description=(
                        f"Total reclaimable space: {_fmt_bytes(total_reclaimable)}. "
                        f"Found {old_files_count} files older than 30 days in temp directories."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "total_reclaimable": total_reclaimable,
                        "breakdown": temp_breakdown,
                        "old_files_count": old_files_count,
                    },
                )
            )

        except Exception as e:
            findings.append(
                Finding(
                    title="Error auditing temp files",
                    description=f"Failed to audit temp file accumulation: {str(e)}",
                    severity=Severity.INFO,
                    category=self.category,
                    data={"error": str(e)},
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        """Provide informational actions for temp file cleanup.

        This is a diagnostic tool - it suggests cleanup actions but does NOT actually
        delete files, as temp cleanup should be done with Windows Disk Cleanup utility
        or manual deletion with proper validation.
        """
        actions = []

        for finding in findings.findings:
            if finding.title == "Excessive temp file accumulation":
                total_size = finding.data.get("total_size", 0)
                breakdown = finding.data.get("breakdown", {})

                action_desc = (
                    f"Run Windows Disk Cleanup (cleanmgr) to safely remove temp files:\n"
                    f"  Total space to reclaim: {_fmt_bytes(total_size)}\n"
                    f"\nBreakdown by location:\n"
                )
                for location, size in breakdown.items():
                    action_desc += f"  {location}: {_fmt_bytes(size)}\n"

                action_desc += (
                    "\nAlternatively, manually delete:\n"
                    "  User temp: %TEMP% (typically C:\\Users\\<user>\\AppData\\Local\\Temp)\n"
                    "  Windows temp: C:\\Windows\\Temp\n"
                    "  Prefetch: C:\\Windows\\Prefetch (*.pf files)\n"
                )

                actions.append(
                    Action(
                        title="Excessive temp file accumulation",
                        description=action_desc,
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif finding.title == "Large Windows Update cache detected":
                cache_size = finding.data.get("cache_size", 0)
                actions.append(
                    Action(
                        title="Clean Windows Update cache",
                        description=(
                            f"Run Windows Disk Cleanup (cleanmgr) and select "
                            f"'Windows Update Cleanup' to remove {_fmt_bytes(cache_size)} "
                            f"of stale updates.\n\n"
                            f"Or manually delete: C:\\Windows\\SoftwareDistribution\\Download"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif finding.title == "Large Recycle Bin":
                recycle_size = finding.data.get("recycle_bin_size", 0)
                actions.append(
                    Action(
                        title="Empty Recycle Bin",
                        description=(
                            f"Recycle Bin contains {_fmt_bytes(recycle_size)} of forgotten deletions. "
                            f"Right-click Recycle Bin and select 'Empty Recycle Bin' to permanently "
                            f"delete these files."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _get_user_temp_size(self) -> int | None:
        """Get size of user temp directory via PowerShell."""
        try:
            cmd = [
                "powershell",
                "-Command",
                "(Get-ChildItem -Recurse $env:TEMP -ErrorAction SilentlyContinue | "
                "Measure-Object -Property Length -Sum).Sum",
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if result.returncode == 0 and result.stdout.strip():
                return int(result.stdout.strip())
        except (subprocess.TimeoutExpired, ValueError, OSError):
            pass
        return None

    def _get_windows_temp_size(self) -> int | None:
        """Get size of Windows temp directory."""
        try:
            cmd = [
                "powershell",
                "-Command",
                "(Get-ChildItem -Recurse 'C:\\Windows\\Temp' -ErrorAction SilentlyContinue | "
                "Measure-Object -Property Length -Sum).Sum",
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if result.returncode == 0 and result.stdout.strip():
                return int(result.stdout.strip())
        except (subprocess.TimeoutExpired, ValueError, OSError):
            pass
        return None

    def _get_prefetch_size(self) -> int | None:
        """Get size of Prefetch directory."""
        try:
            cmd = [
                "powershell",
                "-Command",
                "(Get-ChildItem -Recurse 'C:\\Windows\\Prefetch' -ErrorAction SilentlyContinue | "
                "Measure-Object -Property Length -Sum).Sum",
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if result.returncode == 0 and result.stdout.strip():
                return int(result.stdout.strip())
        except (subprocess.TimeoutExpired, ValueError, OSError):
            pass
        return None

    def _get_windows_update_cache_size(self) -> int | None:
        """Get size of Windows Update cache."""
        try:
            cmd = [
                "powershell",
                "-Command",
                "(Get-ChildItem -Recurse 'C:\\Windows\\SoftwareDistribution\\Download' "
                "-ErrorAction SilentlyContinue | Measure-Object -Property Length -Sum).Sum",
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if result.returncode == 0 and result.stdout.strip():
                return int(result.stdout.strip())
        except (subprocess.TimeoutExpired, ValueError, OSError):
            pass
        return None

    def _get_recycle_bin_size(self) -> int | None:
        """Get size of Recycle Bin via PowerShell COM object."""
        try:
            cmd = [
                "powershell",
                "-Command",
                "((New-Object -ComObject Shell.Application).NameSpace(10).Items() | "
                "Measure-Object -Property Size -Sum).Sum",
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if result.returncode == 0 and result.stdout.strip():
                return int(result.stdout.strip())
        except (subprocess.TimeoutExpired, ValueError, OSError):
            pass
        return None

    def _count_old_temp_files(self) -> int:
        """Count files older than 30 days in temp directories."""
        try:
            cmd = [
                "powershell",
                "-Command",
                "$cutoff = (Get-Date).AddDays(-30); "
                "$count = (Get-ChildItem -Recurse $env:TEMP -ErrorAction SilentlyContinue | "
                "Where-Object { $_.LastWriteTime -lt $cutoff } | Measure-Object).Count; "
                "$count2 = (Get-ChildItem -Recurse 'C:\\Windows\\Temp' -ErrorAction SilentlyContinue | "
                "Where-Object { $_.LastWriteTime -lt $cutoff } | Measure-Object).Count; "
                "$count + $count2",
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            if result.returncode == 0 and result.stdout.strip():
                return int(result.stdout.strip())
        except (subprocess.TimeoutExpired, ValueError, OSError):
            pass
        return 0


def _fmt_bytes(n: int) -> str:
    """Format bytes as human-readable string."""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"
