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

# Thresholds
WINSXS_WARNING_THRESHOLD = 5 * 1024**3  # 5 GB for WinSxS component store
TEMP_WARNING_THRESHOLD = 5 * 1024**3  # 5 GB total for temp folders
TOTAL_RECLAIMABLE_WARNING_THRESHOLD = 10 * 1024**3  # 10 GB total


class Module(ModuleBase):
    name = "win_disk_cleanup"
    category = "performance"
    platforms = [Platform.WIN32]
    risk_level = RiskLevel.SAFE
    priority = 60
    depends_on = []
    estimated_duration = "30s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Check WinSxS component store
        winsxs_size = self._get_winsxs_size()

        # Check Windows Update cache
        wu_cache_size = self._get_directory_size_powershell(
            r"C:\Windows\SoftwareDistribution\Download"
        )

        # Check Windows.old folder
        windows_old_size = self._get_directory_size_powershell(
            r"C:\Windows.old"
        )
        windows_old_exists = windows_old_size > 0

        # Check Recycle Bin
        recycle_bin_size = self._get_recycle_bin_size()

        # Check system temp folder
        system_temp_size = self._get_directory_size_powershell(
            r"C:\Windows\Temp"
        )

        # Check user temp folder
        user_temp_size = self._get_directory_size_powershell(
            r"$env:TEMP"
        )

        temp_total = system_temp_size + user_temp_size

        total_reclaimable = (
            winsxs_size + wu_cache_size + windows_old_size +
            recycle_bin_size + temp_total
        )

        # Report WinSxS component store
        if winsxs_size > 0:
            findings.append(
                Finding(
                    title=f"WinSxS component store: {_fmt_bytes(winsxs_size)}",
                    description=(
                        f"Windows component store (C:\\Windows\\WinSxS) contains "
                        f"{_fmt_bytes(winsxs_size)}. Run 'Dism.exe /Online /Cleanup-Image "
                        f"/StartComponentCleanup' to recover space from unused components."
                    ),
                    severity=Severity.WARNING if winsxs_size > WINSXS_WARNING_THRESHOLD else Severity.INFO,
                    category=self.category,
                    data={
                        "type": "winsxs",
                        "size_bytes": winsxs_size,
                        "size_formatted": _fmt_bytes(winsxs_size),
                    },
                )
            )

        # Report Windows Update cache
        if wu_cache_size > 0:
            findings.append(
                Finding(
                    title=f"Windows Update cache: {_fmt_bytes(wu_cache_size)}",
                    description=(
                        f"Windows Update cache (C:\\Windows\\SoftwareDistribution\\Download) "
                        f"contains {_fmt_bytes(wu_cache_size)} that can be removed after "
                        f"updates are installed."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "type": "windows_update",
                        "size_bytes": wu_cache_size,
                        "size_formatted": _fmt_bytes(wu_cache_size),
                    },
                )
            )

        # Report Windows.old folder
        if windows_old_exists:
            findings.append(
                Finding(
                    title=f"Windows.old folder: {_fmt_bytes(windows_old_size)}",
                    description=(
                        f"Previous Windows installation folder (C:\\Windows.old) contains "
                        f"{_fmt_bytes(windows_old_size)} and can be safely deleted. "
                        f"This folder appears after a Windows upgrade and can recover 10-30GB."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "type": "windows_old",
                        "size_bytes": windows_old_size,
                        "size_formatted": _fmt_bytes(windows_old_size),
                    },
                )
            )

        # Report Recycle Bin
        if recycle_bin_size > 0:
            findings.append(
                Finding(
                    title=f"Recycle Bin: {_fmt_bytes(recycle_bin_size)}",
                    description=(
                        f"Recycle Bin contains {_fmt_bytes(recycle_bin_size)} "
                        f"of deleted files. Permanently delete to reclaim space."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "type": "recycle_bin",
                        "size_bytes": recycle_bin_size,
                        "size_formatted": _fmt_bytes(recycle_bin_size),
                    },
                )
            )

        # Report system temp folder
        if system_temp_size > 0:
            findings.append(
                Finding(
                    title=f"System TEMP directory: {_fmt_bytes(system_temp_size)}",
                    description=(
                        f"System temporary files (C:\\Windows\\Temp) contain "
                        f"{_fmt_bytes(system_temp_size)} of files that can typically be safely removed."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "type": "system_temp",
                        "size_bytes": system_temp_size,
                        "size_formatted": _fmt_bytes(system_temp_size),
                    },
                )
            )

        # Report user temp folder
        if user_temp_size > 0:
            findings.append(
                Finding(
                    title=f"User TEMP directory: {_fmt_bytes(user_temp_size)}",
                    description=(
                        f"User temporary files (%TEMP%) contain "
                        f"{_fmt_bytes(user_temp_size)} of files that can typically be safely removed."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "type": "user_temp",
                        "size_bytes": user_temp_size,
                        "size_formatted": _fmt_bytes(user_temp_size),
                    },
                )
            )

        # Add total reclaimable space finding
        if total_reclaimable > 0:
            findings.insert(
                0,
                Finding(
                    title=f"Found {_fmt_bytes(total_reclaimable)} of reclaimable disk space",
                    description=(
                        f"Comprehensive scan of WinSxS, Windows Update cache, Windows.old, "
                        f"Recycle Bin, and temp locations found {_fmt_bytes(total_reclaimable)} total. "
                        f"Review individual findings below for safe cleanup options."
                    ),
                    severity=Severity.WARNING if total_reclaimable > TOTAL_RECLAIMABLE_WARNING_THRESHOLD else Severity.INFO,
                    category=self.category,
                    data={
                        "type": "total_reclaimable",
                        "size_bytes": total_reclaimable,
                        "size_formatted": _fmt_bytes(total_reclaimable),
                    },
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        for finding in findings.findings:
            finding_type = finding.data.get("type", "unknown")
            size_str = finding.data.get("size_formatted", "unknown")

            if finding_type == "total_reclaimable":
                actions.append(
                    Action(
                        title="Total reclaimable space report",
                        description=(
                            f"Total: {size_str}. Review individual findings below to understand "
                            f"what can be safely removed. Use Windows Disk Cleanup (cleanmgr.exe) "
                            f"or Storage Sense for automated cleanup."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif finding_type == "winsxs":
                actions.append(
                    Action(
                        title=f"WinSxS component store: {size_str}",
                        description=(
                            f"WinSxS component store ({size_str}) can be cleaned. "
                            f"Run as Administrator: "
                            f"Dism.exe /Online /Cleanup-Image /StartComponentCleanup /ResetBase "
                            f"(can recover several GB on older systems with many updates)"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif finding_type == "windows_update":
                actions.append(
                    Action(
                        title=f"Windows Update cache: {size_str}",
                        description=(
                            f"Windows Update cache ({size_str}) can be safely removed after "
                            f"updates are installed. Use: Disk Cleanup (cleanmgr.exe) or "
                            f"Settings > System > Storage > Temporary files."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif finding_type == "windows_old":
                actions.append(
                    Action(
                        title=f"Windows.old folder: {size_str}",
                        description=(
                            f"Windows.old folder ({size_str}) can be safely deleted. "
                            f"Use: Disk Cleanup (cleanmgr.exe) and select 'Previous Windows installations' "
                            f"or manually delete C:\\Windows.old with admin rights."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif finding_type == "recycle_bin":
                actions.append(
                    Action(
                        title=f"Recycle Bin: {size_str}",
                        description=(
                            f"Recycle Bin ({size_str}) can be emptied. "
                            f"Right-click Recycle Bin on desktop and select 'Empty Recycle Bin'."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif finding_type == "system_temp":
                actions.append(
                    Action(
                        title=f"System TEMP directory: {size_str}",
                        description=(
                            f"System TEMP directory ({size_str}) can typically be safely cleaned. "
                            f"Close all applications before deleting. "
                            f"Use: del /q /s C:\\Windows\\Temp\\* (run as Administrator)"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif finding_type == "user_temp":
                actions.append(
                    Action(
                        title=f"User TEMP directory: {size_str}",
                        description=(
                            f"User TEMP directory ({size_str}) can typically be safely cleaned. "
                            f"Close all applications before deleting. "
                            f"Use: del /q /s %TEMP%\\* or Disk Cleanup (cleanmgr.exe)"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _get_winsxs_size(self) -> int:
        """Get WinSxS component store size using DISM."""
        try:
            cmd = [
                "dism.exe",
                "/Online",
                "/Cleanup-Image",
                "/AnalyzeComponentStore",
            ]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode == 0:
                # Parse output for component store size
                # Output typically contains: "Component Store Size : X.XX MB"
                for line in result.stdout.split("\n"):
                    if "Component Store Size" in line:
                        # Extract size value and convert to bytes
                        parts = line.split(":")
                        if len(parts) > 1:
                            size_part = parts[1].strip()
                            # Remove " MB" and convert
                            size_mb = float(size_part.replace(" MB", "").strip())
                            return int(size_mb * 1024 * 1024)
            return 0
        except (OSError, subprocess.SubprocessError, subprocess.TimeoutExpired, ValueError):
            return 0

    def _get_directory_size_powershell(self, path: str) -> int:
        """Get directory size using PowerShell."""
        try:
            cmd = [
                "powershell",
                "-NoProfile",
                "-Command",
                f"(Get-ChildItem '{path}' -Recurse -ErrorAction SilentlyContinue | Measure-Object Length -Sum).Sum",
            ]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=15,
            )
            if result.returncode == 0 and result.stdout.strip():
                try:
                    return int(result.stdout.strip())
                except ValueError:
                    return 0
            return 0
        except (OSError, subprocess.SubprocessError, subprocess.TimeoutExpired):
            return 0

    def _get_recycle_bin_size(self) -> int:
        """Get Recycle Bin size using PowerShell."""
        try:
            cmd = [
                "powershell",
                "-NoProfile",
                "-Command",
                "$shell = New-Object -ComObject Shell.Application; "
                "$recycleBin = $shell.Namespace(10); "
                "if ($recycleBin) { "
                "($recycleBin.Items() | Measure-Object -Property Size -Sum).Sum "
                "} else { 0 }",
            ]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0 and result.stdout.strip():
                try:
                    return int(result.stdout.strip())
                except ValueError:
                    return 0
            return 0
        except (OSError, subprocess.SubprocessError, subprocess.TimeoutExpired):
            return 0


def _fmt_bytes(n: int) -> str:
    """Format bytes as human-readable string."""
    if n is None or n == 0:
        return "0 B"
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"
