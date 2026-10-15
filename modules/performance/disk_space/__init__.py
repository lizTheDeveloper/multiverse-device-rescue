from rescue.models import (
    Action,
    CheckResult,
    DiskInfo,
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
    name = "disk_space"
    category = "performance"
    platforms = [Platform.DARWIN, Platform.WIN32, Platform.LINUX]
    risk_level = RiskLevel.SAFE
    priority = 80
    depends_on = []
    estimated_duration = "5s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []
        for disk in profile.disks:
            if disk.total_bytes == 0:
                continue
            used_pct = disk.used_bytes / disk.total_bytes
            if used_pct >= CRITICAL_THRESHOLD:
                findings.append(self._make_finding(disk, used_pct, Severity.CRITICAL))
            elif used_pct >= WARNING_THRESHOLD:
                findings.append(self._make_finding(disk, used_pct, Severity.WARNING))
        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            actions.append(
                Action(
                    title=f"Disk space report for {finding.data.get('mount_point', 'unknown')}",
                    description=(
                        f"Disk is {finding.data.get('used_pct_str', '?')} full. "
                        f"Free: {_fmt_bytes(finding.data.get('free_bytes', 0))}. "
                        f"Consider running the disk_reclaimer module to free space."
                    ),
                    risk_level=RiskLevel.SAFE,
                    success=True,
                )
            )
        return FixResult(module_name=self.name, actions=actions)

    def _make_finding(
        self, disk: DiskInfo, used_pct: float, severity: Severity
    ) -> Finding:
        return Finding(
            title=f"Your disk {disk.mount_point} is {used_pct:.0%} full",
            description=(
                f"Your drive {disk.mount_point} is running low on space. Currently, {_fmt_bytes(disk.used_bytes)} "
                f"of {_fmt_bytes(disk.total_bytes)} is used, leaving only {_fmt_bytes(disk.free_bytes)} "
                "free. Running out of space can slow down your computer and stop apps "
                "from saving new files.\n\n"
                "What to do: Open the Finder, go to your main folder, and look for large "
                "files or folders you no longer need. You can move them to an external "
                "drive or delete them to free up space."
            ),
            severity=severity,
            category=self.category,
            data={
                "mount_point": disk.mount_point,
                "device": disk.device,
                "used_pct": used_pct,
                "used_pct_str": f"{used_pct:.0%}",
                "free_bytes": disk.free_bytes,
                "total_bytes": disk.total_bytes,
            },
        )


def _fmt_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"
