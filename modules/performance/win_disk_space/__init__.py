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

WARNING_THRESHOLD = 0.80
CRITICAL_THRESHOLD = 0.95


class Module(ModuleBase):
    name = "win_disk_space"
    category = "performance"
    platforms = [Platform.WIN32]
    risk_level = RiskLevel.SAFE
    priority = 80
    depends_on = []
    estimated_duration = "5s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []
        output = self._run_wmic()
        for caption, size, free in _parse_logicaldisk_output(output):
            if size == 0:
                continue
            used = size - free
            used_pct = used / size
            if used_pct >= CRITICAL_THRESHOLD:
                findings.append(
                    self._make_finding(caption, size, used, free, used_pct, Severity.CRITICAL)
                )
            elif used_pct >= WARNING_THRESHOLD:
                findings.append(
                    self._make_finding(caption, size, used, free, used_pct, Severity.WARNING)
                )
        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            actions.append(
                Action(
                    title=f"Disk space report for {finding.data.get('caption', 'unknown')}",
                    description=(
                        f"Drive is {finding.data.get('used_pct_str', '?')} full. "
                        f"Free: {_fmt_bytes(finding.data.get('free_bytes', 0))}. "
                        "Consider running Disk Cleanup (cleanmgr.exe) or the "
                        "win_startup module to free space."
                    ),
                    risk_level=RiskLevel.SAFE,
                    success=True,
                )
            )
        return FixResult(module_name=self.name, actions=actions)

    def _run_wmic(self) -> str:
        try:
            result = subprocess.run(
                ["wmic", "logicaldisk", "get", "size,freespace,caption"],
                capture_output=True,
                text=True,
            )
            return result.stdout
        except (OSError, subprocess.SubprocessError):
            return ""

    def _make_finding(
        self, caption: str, size: int, used: int, free: int, used_pct: float, severity: Severity
    ) -> Finding:
        return Finding(
            title=f"Drive {caption} is {used_pct:.0%} full",
            description=(
                f"{caption} : {_fmt_bytes(used)} used of {_fmt_bytes(size)} "
                f"({_fmt_bytes(free)} free)"
            ),
            severity=severity,
            category=self.category,
            data={
                "caption": caption,
                "used_pct": used_pct,
                "used_pct_str": f"{used_pct:.0%}",
                "free_bytes": free,
                "total_bytes": size,
            },
        )


def _parse_logicaldisk_output(output: str) -> list[tuple[str, int, int]]:
    """Parse `wmic logicaldisk get size,freespace,caption` table output.

    `wmic ... get` sorts columns alphabetically regardless of the order
    fields were requested in, so the header is always::

        Caption  FreeSpace     Size
        C:       107374182400  256060514304
        D:       53687091200   107374182400
    """
    drives: list[tuple[str, int, int]] = []
    lines = [line for line in output.splitlines() if line.strip()]
    if len(lines) < 2:
        return drives
    for line in lines[1:]:
        parts = line.split()
        if len(parts) != 3:
            continue
        caption, free_str, size_str = parts
        try:
            free = int(free_str)
            size = int(size_str)
        except ValueError:
            continue
        drives.append((caption, size, free))
    return drives


def _fmt_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"
