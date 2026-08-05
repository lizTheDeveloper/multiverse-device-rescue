"""Why this Linux machine feels slow: memory, swap, and the kernel's own
pressure metric.

"Free memory" is the most misread number in Linux. A healthy system shows very
little of it, because the kernel uses everything spare as disk cache and gives
it back on demand. Reporting low free memory as a problem — which many tools do
— is wrong on every well-tuned machine. This module reads MemAvailable, the
value the kernel itself computes for "how much could a new process actually
get", and it reads Pressure Stall Information, which measures the thing users
actually feel: time lost waiting on memory.

PSI is the honest metric here. `some avg60` over 20% means processes spent more
than a fifth of the last minute stalled waiting for memory — that is the
stuttering, beachballing experience, quantified. It is available on kernels 4.20
and later; when it is not present the module falls back to available-memory and
swap ratios and says which it used.
"""

from pathlib import Path

from rescue.models import (
    Action,
    ActionKind,
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

# Fractions of total RAM still available before this is worth mentioning.
_AVAILABLE_WARNING = 0.15
_AVAILABLE_CRITICAL = 0.05

# Fraction of configured swap in use. Some swap use is normal and healthy —
# the kernel pages out genuinely idle memory. Heavy use is not.
_SWAP_WARNING = 0.50
_SWAP_CRITICAL = 0.80

# Percent of the last 60 seconds during which at least one task stalled on
# memory. Above this, the machine is perceptibly slow.
_PSI_WARNING = 10.0
_PSI_CRITICAL = 25.0

# Processes using more than this fraction of RAM are named, since one process is
# usually the whole explanation.
_HOG_FRACTION = 0.10


class Module(ModuleBase):
    name = "linux_memory_pressure"
    category = "performance"
    platforms = [Platform.LINUX]
    risk_level = RiskLevel.SAFE
    priority = 70
    depends_on = []
    estimated_duration = "5s"

    emits_codes = [
        "performance.linux_memory_pressure.memory_stall",
        "performance.linux_memory_pressure.low_available_memory",
        "performance.linux_memory_pressure.heavy_swap_use",
        "performance.linux_memory_pressure.no_swap_configured",
        "performance.linux_memory_pressure.memory_hog",
    ]

    meminfo_path: str = "/proc/meminfo"
    psi_path: str = "/proc/pressure/memory"

    def check(self, profile: SystemProfile) -> CheckResult:
        if profile.platform is not Platform.LINUX:
            return CheckResult(
                module_name=self.name,
                supported=False,
                unsupported_reason=(
                    "This check reads /proc/meminfo and /proc/pressure; this host reports "
                    f"{profile.platform.value}."
                ),
            )

        meminfo = self._meminfo()
        if not meminfo:
            return CheckResult(
                module_name=self.name,
                error=f"{self.meminfo_path} could not be read.",
            )

        total = meminfo.get("MemTotal", 0)
        available = meminfo.get("MemAvailable", 0)
        swap_total = meminfo.get("SwapTotal", 0)
        swap_free = meminfo.get("SwapFree", 0)
        if total <= 0:
            return CheckResult(module_name=self.name, error="MemTotal was zero or missing.")

        findings: list[Finding] = []

        psi = self._psi()
        if psi is not None:
            severity = None
            if psi >= _PSI_CRITICAL:
                severity = Severity.CRITICAL
            elif psi >= _PSI_WARNING:
                severity = Severity.WARNING
            if severity is not None:
                findings.append(
                    Finding(
                        title=f"Processes spent {psi:.0f}% of the last minute waiting for memory",
                        description=(
                            "This is the kernel's own measure of memory stall, and it maps "
                            "directly onto what you feel: windows that take a moment to "
                            "redraw, typing that lags, a machine that seems busy doing "
                            "nothing.\n\n"
                            "Anything above 10% is noticeable; above 25% the machine is "
                            "spending more time waiting than working."
                        ),
                        severity=severity,
                        category=self.category,
                        code="performance.linux_memory_pressure.memory_stall",
                        confidence=0.95,
                        data={"check": "memory_stall", "psi_some_avg60": psi},
                    )
                )

        available_fraction = available / total
        if available_fraction <= _AVAILABLE_CRITICAL or available_fraction <= _AVAILABLE_WARNING:
            findings.append(
                Finding(
                    title=f"Only {_fmt(available)} of {_fmt(total)} memory is available",
                    description=(
                        "MemAvailable is the kernel's estimate of how much memory a new "
                        "program could actually get without swapping. It is not the same "
                        "as 'free' — a healthy Linux machine has almost no free memory, "
                        "because the kernel uses the rest as cache and hands it back on "
                        "demand. This number being low is the one that matters.\n\n"
                        "Once it reaches zero the kernel starts killing processes to "
                        "recover, which is what 'applications close by themselves' means."
                    ),
                    severity=(
                        Severity.CRITICAL if available_fraction <= _AVAILABLE_CRITICAL
                        else Severity.WARNING
                    ),
                    category=self.category,
                    code="performance.linux_memory_pressure.low_available_memory",
                    confidence=0.9,
                    data={
                        "check": "low_available_memory",
                        "available_bytes": available,
                        "total_bytes": total,
                        "available_fraction": round(available_fraction, 4),
                    },
                )
            )

        if swap_total > 0:
            swap_used_fraction = (swap_total - swap_free) / swap_total
            if swap_used_fraction >= _SWAP_WARNING:
                findings.append(
                    Finding(
                        title=f"{swap_used_fraction:.0%} of swap is in use",
                        description=(
                            f"{_fmt(swap_total - swap_free)} of {_fmt(swap_total)} swap is "
                            "occupied. Some swap use is normal and good — the kernel moves "
                            "genuinely idle pages out to make room for cache. Heavy use "
                            "means active memory is being paged to disk, and every touch "
                            "of that memory now costs a disk read."
                        ),
                        severity=(
                            Severity.CRITICAL if swap_used_fraction >= _SWAP_CRITICAL
                            else Severity.WARNING
                        ),
                        category=self.category,
                        code="performance.linux_memory_pressure.heavy_swap_use",
                        confidence=0.9,
                        data={
                            "check": "heavy_swap_use",
                            "swap_used_bytes": swap_total - swap_free,
                            "swap_total_bytes": swap_total,
                            "used_fraction": round(swap_used_fraction, 4),
                        },
                    )
                )
        elif available_fraction <= _AVAILABLE_WARNING:
            # No swap is a legitimate configuration; it only becomes a finding
            # when memory is already tight, because then the kernel has no
            # option between "slow" and "kill something".
            findings.append(
                Finding(
                    title="No swap is configured, and memory is already tight",
                    description=(
                        "With no swap, the kernel has nowhere to put idle pages when "
                        "memory runs short. Instead of getting slow, the machine jumps "
                        "straight to killing processes. A small swap file or zram gives it "
                        "a gentler option."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="performance.linux_memory_pressure.no_swap_configured",
                    confidence=0.8,
                    data={"check": "no_swap_configured"},
                )
            )

        findings.extend(self._hog_findings(profile, total))
        return CheckResult(module_name=self.name, findings=findings)

    def _meminfo(self) -> dict[str, int]:
        try:
            text = Path(self.meminfo_path).read_text(errors="replace")
        except OSError:
            return {}
        values: dict[str, int] = {}
        for line in text.splitlines():
            key, _, rest = line.partition(":")
            fields = rest.split()
            if not fields:
                continue
            try:
                amount = int(fields[0])
            except ValueError:
                continue
            # /proc/meminfo is in kB except for a few unitless counters.
            values[key.strip()] = amount * 1024 if len(fields) > 1 else amount
        return values

    def _psi(self) -> float | None:
        """Return `some avg60` from /proc/pressure/memory, or None if unavailable."""
        try:
            text = Path(self.psi_path).read_text(errors="replace")
        except OSError:
            return None
        for line in text.splitlines():
            if not line.startswith("some "):
                continue
            for field in line.split():
                if field.startswith("avg60="):
                    try:
                        return float(field.split("=", 1)[1])
                    except ValueError:
                        return None
        return None

    def _hog_findings(self, profile: SystemProfile, total: int) -> list[Finding]:
        hogs = [
            process for process in profile.processes
            if process.memory_bytes >= total * _HOG_FRACTION
        ]
        hogs.sort(key=lambda p: p.memory_bytes, reverse=True)
        return [
            Finding(
                title=f"{process.name} is using {_fmt(process.memory_bytes)} of memory",
                description=(
                    f"PID {process.pid} holds {process.memory_bytes / total:.0%} of this "
                    "machine's RAM.\n\n"
                    f"  {process.command[:200]}\n\n"
                    "This is not automatically a problem — browsers, virtual machines, and "
                    "language servers legitimately use a lot. It is here so that when the "
                    "machine is short of memory you can see where it went."
                ),
                severity=Severity.INFO,
                category=self.category,
                code="performance.linux_memory_pressure.memory_hog",
                confidence=0.9,
                data={
                    "check": "memory_hog",
                    "pid": process.pid,
                    "name": process.name,
                    "memory_bytes": process.memory_bytes,
                },
            )
            for process in hogs[:5]
        ]

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions: list[Action] = []
        seen: set[str] = set()
        for finding in findings.findings:
            check = finding.data.get("check")
            if check in seen and check != "memory_hog":
                continue
            seen.add(check)

            if check in ("memory_stall", "low_available_memory"):
                actions.append(self._guidance(
                    "Find what is using the memory, then decide",
                    "  1. See the current picture, sorted by memory:\n"
                    "         ps -eo pid,rss,comm --sort=-rss | head -15\n"
                    "  2. Watch it live if it comes and goes:\n"
                    "         systemd-cgtop -m\n"
                    "  3. Browsers are the usual answer — each tab is a process. Closing "
                    "tabs genuinely works.\n"
                    "  4. If nothing obvious accounts for it, check for a leak: a process "
                    "whose memory only ever grows, never falls, over hours.\n\n"
                    "The tool does not kill processes for you. Killing the wrong one loses "
                    "unsaved work.",
                    check,
                ))
            elif check == "heavy_swap_use":
                actions.append(self._guidance(
                    "Relieve swap pressure",
                    "  1. Close the largest memory consumers (see above) — swap usually "
                    "drains on its own once the pressure lifts.\n"
                    "  2. If it does not and you need it back immediately:\n"
                    "         sudo swapoff -a && sudo swapon -a\n"
                    "     Only do this when enough free RAM exists to hold what is in "
                    "swap; otherwise the kernel starts killing processes.\n"
                    "  3. On a machine with a slow disk, consider zram — compressed swap "
                    "in RAM, much faster than swapping to disk:\n"
                    "         sudo apt install systemd-zram-generator   # or zram-generator",
                    check,
                ))
            elif check == "no_swap_configured":
                actions.append(self._guidance(
                    "Add some swap so the kernel has an option other than killing things",
                    "A 2-4 GB swap file is enough to smooth over spikes:\n"
                    "    sudo fallocate -l 4G /swapfile\n"
                    "    sudo chmod 600 /swapfile\n"
                    "    sudo mkswap /swapfile\n"
                    "    sudo swapon /swapfile\n"
                    "    echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab\n\n"
                    "On a laptop that hibernates, swap must be at least as large as RAM "
                    "for hibernation to work.",
                    check,
                ))
            elif check == "memory_hog":
                actions.append(self._guidance(
                    f"Consider whether {finding.data.get('name')} needs that much memory",
                    f"    ps -p {finding.data.get('pid')} -o pid,rss,etime,args\n\n"
                    "If it is something you are actively using, this is fine. If it has "
                    "been running for days and is still growing, restarting it is the "
                    "cheapest fix for a leak.",
                    check,
                ))
        return FixResult(module_name=self.name, actions=actions)

    def _guidance(self, title: str, description: str, check: str) -> Action:
        return Action(
            title=title,
            description=description,
            risk_level=RiskLevel.SAFE,
            kind=ActionKind.GUIDANCE,
            data={"check": check},
        )


def _fmt(n: int) -> str:
    value = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(value) < 1024:
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} PB"
