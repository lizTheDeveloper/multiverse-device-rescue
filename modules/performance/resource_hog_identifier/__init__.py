from rescue.models import (
    Action,
    CheckResult,
    Finding,
    FixResult,
    Mode,
    Platform,
    ProcessInfo,
    RiskLevel,
    Severity,
    SystemProfile,
)
from rescue.module_base import ModuleBase

CPU_WARNING_PCT = 50.0
CPU_CRITICAL_PCT = 90.0
MEM_WARNING_RATIO = 0.10
MEM_CRITICAL_RATIO = 0.25


class Module(ModuleBase):
    name = "resource_hog_identifier"
    category = "performance"
    platforms = [Platform.DARWIN, Platform.WIN32, Platform.LINUX]
    risk_level = RiskLevel.MODERATE
    priority = 70
    depends_on = []
    estimated_duration = "5s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []
        mem_warning_bytes = profile.ram_bytes * MEM_WARNING_RATIO
        mem_critical_bytes = profile.ram_bytes * MEM_CRITICAL_RATIO
        for proc in profile.processes:
            is_critical = (
                proc.cpu_percent >= CPU_CRITICAL_PCT
                or proc.memory_bytes >= mem_critical_bytes
            )
            is_warning = (
                proc.cpu_percent >= CPU_WARNING_PCT
                or proc.memory_bytes >= mem_warning_bytes
            )
            if is_critical:
                findings.append(self._make_finding(proc, Severity.CRITICAL))
            elif is_warning:
                findings.append(self._make_finding(proc, Severity.WARNING))
        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        """
        Provide informational actions about resource hogs.
        This is a diagnostic tool - it reports which processes are resource hogs
        and suggests actions, but does NOT actually kill processes.
        """
        actions = []
        for finding in findings.findings:
            pid = finding.data.get("pid")
            name = finding.data.get("name", "unknown")
            cpu_percent = finding.data.get("cpu_percent", 0)
            memory_bytes = finding.data.get("memory_bytes", 0)

            actions.append(
                Action(
                    title=f"Resource hog detected: {name} (pid {pid})",
                    description=(
                        f"{name} (pid {pid}) is consuming excessive resources:\n"
                        f"  CPU: {cpu_percent:.1f}%\n"
                        f"  RAM: {_fmt_bytes(memory_bytes)}\n"
                        f"Consider terminating this process if it is not essential."
                    ),
                    risk_level=RiskLevel.SAFE,
                    success=True,
                )
            )
        return FixResult(module_name=self.name, actions=actions)

    def _make_finding(self, proc: ProcessInfo, severity: Severity) -> Finding:
        return Finding(
            title=f"{proc.name} is consuming excessive resources",
            description=(
                f"{proc.name} (pid {proc.pid}): {proc.cpu_percent:.1f}% CPU, "
                f"{_fmt_bytes(proc.memory_bytes)} RAM"
            ),
            severity=severity,
            category=self.category,
            data={
                "pid": proc.pid,
                "name": proc.name,
                "cpu_percent": proc.cpu_percent,
                "memory_bytes": proc.memory_bytes,
                "command": proc.command,
            },
        )


def _fmt_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"
