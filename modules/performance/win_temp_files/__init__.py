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
WU_CACHE_WARNING_THRESHOLD = 1 * 1024**3  # 1 GB for Windows Update cache
TOTAL_RECLAIMABLE_WARNING_THRESHOLD = 5 * 1024**3  # 5 GB total


class Module(ModuleBase):
    name = "win_temp_files"
    category = "performance"
    platforms = [Platform.WIN32]
    risk_level = RiskLevel.SAFE
    priority = 65
    depends_on = []
    estimated_duration = "15s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Check Windows Update cache via PowerShell
        wu_cache_size = self._get_directory_size_powershell(
            r"$env:windir\SoftwareDistribution\Download"
        )

        # Check Windows Installer cache
        installer_cache_size = self._get_directory_size_powershell(
            r"$env:windir\Installer"
        )

        # Check Prefetch folder
        prefetch_size = self._get_directory_size_powershell(
            r"$env:windir\Prefetch"
        )

        # Check user's AppData\Local\Temp
        user_temp_size = self._get_directory_size_powershell(
            r"$env:APPDATA\..\Local\Temp"
        )

        # Check Recycle Bin
        recycle_bin_size = self._get_recycle_bin_size()

        total_reclaimable = (
            wu_cache_size + installer_cache_size + prefetch_size +
            user_temp_size + recycle_bin_size
        )

        # Report each location's size
        if wu_cache_size > 0:
            findings.append(
                Finding(
                    title=f"Windows Update cache: {_fmt_bytes(wu_cache_size)}",
                    description=(
                        f"Windows Update cache ($env:windir\\SoftwareDistribution\\Download) "
                        f"contains {_fmt_bytes(wu_cache_size)} that can be removed after "
                        f"updates are installed."
                    ),
                    severity=Severity.WARNING if wu_cache_size > WU_CACHE_WARNING_THRESHOLD else Severity.INFO,
                    category=self.category,
                    data={
                        "type": "windows_update",
                        "size_bytes": wu_cache_size,
                        "size_formatted": _fmt_bytes(wu_cache_size),
                    },
                )
            )

        if installer_cache_size > 0:
            findings.append(
                Finding(
                    title=f"Windows Installer cache: {_fmt_bytes(installer_cache_size)}",
                    description=(
                        f"Windows Installer cache ($env:windir\\Installer) contains "
                        f"{_fmt_bytes(installer_cache_size)} of orphaned or old .msp/.msi files "
                        f"that may be safely removed after confirming installed software still works."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "type": "installer_cache",
                        "size_bytes": installer_cache_size,
                        "size_formatted": _fmt_bytes(installer_cache_size),
                    },
                )
            )

        if prefetch_size > 0:
            findings.append(
                Finding(
                    title=f"Prefetch directory: {_fmt_bytes(prefetch_size)}",
                    description=(
                        f"Prefetch directory ($env:windir\\Prefetch) contains "
                        f"{_fmt_bytes(prefetch_size)} of application prefetch data. "
                        f"This will be regenerated as applications are run."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "type": "prefetch",
                        "size_bytes": prefetch_size,
                        "size_formatted": _fmt_bytes(prefetch_size),
                    },
                )
            )

        if user_temp_size > 0:
            findings.append(
                Finding(
                    title=f"User TEMP directory: {_fmt_bytes(user_temp_size)}",
                    description=(
                        f"User temporary files ($env:APPDATA\\..\\Local\\Temp) contain "
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

        # Add total reclaimable space finding
        if total_reclaimable > 0:
            findings.insert(
                0,
                Finding(
                    title=f"Found {_fmt_bytes(total_reclaimable)} of recoverable space",
                    description=(
                        f"Deep scan of temp and cache locations found "
                        f"{_fmt_bytes(total_reclaimable)} total. Removing these items may improve "
                        f"disk performance and free up space on older systems."
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
                        title="Total recoverable space report",
                        description=(
                            f"Total: {size_str}. Review individual findings below to understand "
                            f"what can be safely removed. Use Windows Disk Cleanup (cleanmgr.exe) "
                            f"or Storage Sense for automated cleanup."
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
            elif finding_type == "installer_cache":
                actions.append(
                    Action(
                        title=f"Windows Installer cache: {size_str}",
                        description=(
                            f"Windows Installer cache ({size_str}) can be removed after confirming "
                            f"installed software still works. Backup $env:windir\\Installer before "
                            f"deleting. Use: Disk Cleanup (cleanmgr.exe) or carefully delete old "
                            f".msp/.msi files with admin rights."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif finding_type == "prefetch":
                actions.append(
                    Action(
                        title=f"Prefetch directory: {size_str}",
                        description=(
                            f"Prefetch data ({size_str}) can typically be removed safely. "
                            f"It will be regenerated as applications are run. "
                            f"Use: del /q $env:windir\\Prefetch\\* (run as Administrator)"
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

        return FixResult(module_name=self.name, actions=actions)

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
