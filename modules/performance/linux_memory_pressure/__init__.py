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
                        title=(
                            "Your computer is lagging because it is waiting for memory "
                            f"({psi:.0f}%)"
                        ),
                        description=(
                            f"Your computer spent {psi:.0f}% of the last minute waiting "
                            "for memory to become available. "
                            "This is why things feel slow, like typing lagging or windows "
                            "taking a moment to open. "
                            "This is a performance issue, not a security problem, but "
                            "it makes the computer hard to use.\n\n"
                            "What to do: Close programs you are not using, especially "
                            "web browsers with many tabs. "
                            "If the lag continues, restart your computer."
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
                    title=(
                        f"Your computer is running out of usable memory ({_fmt(available)} left)"
                    ),
                    description=(
                        f"Your computer has {_fmt(available)} of its {_fmt(total)} memory left that it can "
                        "use right now. "
                        "This is not the same as 'free' memory, which is usually low on "
                        "healthy computers. "
                        "However, when this number gets very low, your computer may start "
                        "closing apps on its own "
                        "to make room, which can cause you to lose unsaved work.\n\n"
                        "What to do: Close any programs or browser tabs you are not using. "
                        "If this happens often, "
                        "restarting your computer will clear this memory."
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
                        title=(
                            f"Your computer is leaning hard on swap ({swap_used_fraction:.0%})"
                        ),
                        description=(
                            f"Your computer is using {swap_used_fraction:.0%} ({_fmt(swap_total - swap_free)} of "
                            f"{_fmt(swap_total)}) of its 'swap' "
                            "space. Swap is overflow space "
                            "on your disk used when your main memory is full. Using "
                            "a little is normal, but using "
                            "this much means your computer is working very hard to keep "
                            "up, which makes it feel slow.\n\n"
                            "What to do: Close programs you are not using to free up main "
                            "memory. This should reduce the "
                            "use of swap and speed up your computer."
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
                    title="Memory is running low and there's no swap to fall back on",
                    description=(
                        "Your computer does not have 'swap' (overflow space on disk) set "
                        "up, and it is running low on "
                        "main memory. Without swap, the computer cannot slow "
                        "down gracefully; instead, "
                        "it may suddenly close your apps to prevent a crash.\n\n"
                        "What to do: Adding a swap file is a technical fix. If you are not "
                        "comfortable doing this, close unused programs to free up main "
                        "memory for now."
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
