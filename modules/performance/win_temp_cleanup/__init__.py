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

WARNING_THRESHOLD = 1 * 1024**3  # 1 GB


class Module(ModuleBase):
    name = "win_temp_cleanup"
    category = "performance"
    platforms = [Platform.WIN32]
    risk_level = RiskLevel.SAFE
    priority = 70
    depends_on = []
    estimated_duration = "10s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Check %TEMP% directory
        temp_size = self._get_directory_size_powershell(r"$env:TEMP")

        # Check C:\Windows\Temp
        windows_temp_size = self._get_directory_size_powershell(r"C:\Windows\Temp")

        # Check Windows Update cache
        windows_update_size = self._get_directory_size_powershell(
            r"C:\Windows\SoftwareDistribution\Download"
        )

        # Check Recycle Bin
        recycle_bin_size = self._get_recycle_bin_size()

        # Check Prefetch
        prefetch_size = self._get_directory_size_powershell(r"C:\Windows\Prefetch")

        total_reclaimable = (
            temp_size + windows_temp_size + windows_update_size +
            recycle_bin_size + prefetch_size
        )

        # Create findings for each location
        if temp_size > 0:
            findings.append(
                Finding(
                    title=f"User TEMP directory: {_fmt_bytes(temp_size)}",
                    description=(
                        f"The user temporary files directory (%TEMP%) contains "
                        f"{_fmt_bytes(temp_size)} of files that can typically be safely removed."
                    ),
                    severity=Severity.WARNING if temp_size > WARNING_THRESHOLD else Severity.INFO,
                    category=self.category,
                    data={
                        "type": "user_temp",
                        "size_bytes": temp_size,
                        "size_formatted": _fmt_bytes(temp_size),
                    },
                )
            )

        if windows_temp_size > 0:
            findings.append(
                Finding(
                    title=f"Windows TEMP directory: {_fmt_bytes(windows_temp_size)}",
                    description=(
                        f"System temporary files (C:\\Windows\\Temp) contain "
                        f"{_fmt_bytes(windows_temp_size)} that may be safely removed."
                    ),
                    severity=Severity.WARNING if windows_temp_size > WARNING_THRESHOLD else Severity.INFO,
                    category=self.category,
                    data={
                        "type": "windows_temp",
                        "size_bytes": windows_temp_size,
                        "size_formatted": _fmt_bytes(windows_temp_size),
                    },
                )
            )

        if windows_update_size > 0:
            findings.append(
                Finding(
                    title=f"Windows Update cache: {_fmt_bytes(windows_update_size)}",
                    description=(
                        f"Windows Update cache (C:\\Windows\\SoftwareDistribution\\Download) "
                        f"contains {_fmt_bytes(windows_update_size)} that can be removed "
                        f"after updates are installed."
                    ),
                    severity=Severity.WARNING if windows_update_size > WARNING_THRESHOLD else Severity.INFO,
                    category=self.category,
                    data={
                        "type": "windows_update",
                        "size_bytes": windows_update_size,
                        "size_formatted": _fmt_bytes(windows_update_size),
                    },
                )
            )

        if recycle_bin_size > 0:
            findings.append(
                Finding(
                    title=f"Recycle Bin: {_fmt_bytes(recycle_bin_size)}",
                    description=(
                        f"The Recycle Bin contains {_fmt_bytes(recycle_bin_size)} "
                        f"of deleted files. Permanently delete to reclaim space."
                    ),
                    severity=Severity.WARNING if recycle_bin_size > WARNING_THRESHOLD else Severity.INFO,
                    category=self.category,
                    data={
                        "type": "recycle_bin",
                        "size_bytes": recycle_bin_size,
                        "size_formatted": _fmt_bytes(recycle_bin_size),
                    },
                )
            )

        if prefetch_size > 0:
            findings.append(
                Finding(
                    title=f"Prefetch directory: {_fmt_bytes(prefetch_size)}",
                    description=(
                        f"The Prefetch directory (C:\\Windows\\Prefetch) contains "
                        f"{_fmt_bytes(prefetch_size)} of application prefetch data."
                    ),
                    severity=Severity.WARNING if prefetch_size > WARNING_THRESHOLD else Severity.INFO,
                    category=self.category,
                    data={
                        "type": "prefetch",
                        "size_bytes": prefetch_size,
                        "size_formatted": _fmt_bytes(prefetch_size),
                    },
                )
            )

        # Add total reclaimable space finding at the beginning
        if total_reclaimable > 0:
            findings.insert(
                0,
                Finding(
                    title=f"Found {_fmt_bytes(total_reclaimable)} of reclaimable disk space",
                    description=(
                        f"Total space used by temp files, caches, and recycle bin: "
                        f"{_fmt_bytes(total_reclaimable)}. Removing these items may improve "
                        f"disk performance and free up space."
                    ),
                    severity=Severity.WARNING if total_reclaimable > WARNING_THRESHOLD else Severity.INFO,
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
                            f"Total: {size_str}. Review individual findings below to "
                            f"understand what can be safely removed."
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
                            f"The user TEMP directory ({size_str}) can typically be safely cleaned. "
                            f"Close all applications before deleting. "
                            f"Or use: del /q /s %TEMP%\\* or Disk Cleanup (cleanmgr.exe)"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif finding_type == "windows_temp":
                actions.append(
                    Action(
                        title=f"Windows TEMP directory: {size_str}",
                        description=(
                            f"System temp files ({size_str}) can often be safely removed. "
                            f"Close applications and use: del /q /s C:\\Windows\\Temp\\*"
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
                            f"PowerShell: Remove-Item -Recurse -Force "
                            f"C:\\Windows\\SoftwareDistribution\\Download\\*"
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
                            f"The Recycle Bin ({size_str}) can be emptied. "
                            f"Right-click Recycle Bin on desktop and select 'Empty Recycle Bin'."
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
                            f"Use: del /q C:\\Windows\\Prefetch\\*"
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
