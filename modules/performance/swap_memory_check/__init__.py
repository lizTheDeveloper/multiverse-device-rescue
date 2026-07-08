import subprocess
import re

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


class Module(ModuleBase):
    name = "swap_memory_check"
    category = "performance"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 75
    depends_on = []
    estimated_duration = "3s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        try:
            memory_info = self._get_memory_info(profile)
        except Exception as e:
            return CheckResult(module_name=self.name, findings=findings)

        total_ram_bytes = profile.ram_bytes
        swap_used_bytes = memory_info.get("swap_used_bytes", 0)
        swap_total_bytes = memory_info.get("swap_total_bytes", 0)
        page_outs = memory_info.get("page_outs", 0)
        page_ins = memory_info.get("page_ins", 0)
        compressed_pages = memory_info.get("compressed_pages", 0)
        page_size = memory_info.get("page_size", 4096)
        active_pages = memory_info.get("active_pages", 0)
        inactive_pages = memory_info.get("inactive_pages", 0)
        wired_pages = memory_info.get("wired_pages", 0)
        free_pages = memory_info.get("free_pages", 0)
        memory_pressure = memory_info.get("memory_pressure", 0)

        # Check CRITICAL conditions first
        # CRITICAL: swap used > physical RAM (severe memory pressure)
        if swap_used_bytes > total_ram_bytes:
            findings.append(
                Finding(
                    title="Critical: Swap usage exceeds physical RAM",
                    description=(
                        f"Swap usage ({_fmt_bytes(swap_used_bytes)}) exceeds physical RAM "
                        f"({_fmt_bytes(total_ram_bytes)}). The system is experiencing severe "
                        "memory pressure. Performance is critically impacted. "
                        "Close large applications or add RAM immediately."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
                    data={
                        "check": "critical_swap_exceeds_ram",
                        "swap_used_bytes": swap_used_bytes,
                        "total_ram_bytes": total_ram_bytes,
                    },
                )
            )

        # WARNING: Page-outs are very high (>1M pages — system is thrashing)
        if page_outs > 1_000_000:
            findings.append(
                Finding(
                    title="Warning: High page-out activity detected",
                    description=(
                        f"System has paged out {page_outs:,} pages (over 1 million). "
                        f"This indicates memory pressure and system thrashing. "
                        f"The system is writing memory to disk excessively, which severely "
                        "degrades performance. Close large applications or add RAM."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "check": "high_page_outs",
                        "page_outs": page_outs,
                    },
                )
            )

        # WARNING: Memory pressure is "critical"
        if memory_pressure == 2:  # Critical level is 2
            findings.append(
                Finding(
                    title="Warning: Critical memory pressure detected",
                    description=(
                        "The system is reporting critical memory pressure. "
                        "Memory is severely constrained and performance is impacted. "
                        "Close applications or consider adding RAM."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "check": "critical_memory_pressure",
                        "memory_pressure": memory_pressure,
                    },
                )
            )

        # INFO: Report swap usage
        if swap_total_bytes > 0:
            swap_usage_pct = (swap_used_bytes / swap_total_bytes) * 100
            findings.append(
                Finding(
                    title="Swap memory status",
                    description=(
                        f"Swap: {_fmt_bytes(swap_used_bytes)} used of "
                        f"{_fmt_bytes(swap_total_bytes)} total ({swap_usage_pct:.1f}% full). "
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "check": "swap_status",
                        "swap_used_bytes": swap_used_bytes,
                        "swap_total_bytes": swap_total_bytes,
                        "swap_usage_pct": swap_usage_pct,
                    },
                )
            )

        # INFO: Report memory stats
        active_bytes = active_pages * page_size
        inactive_bytes = inactive_pages * page_size
        wired_bytes = wired_pages * page_size
        compressed_bytes = compressed_pages * page_size
        free_bytes = free_pages * page_size

        findings.append(
            Finding(
                title="Memory allocation status",
                description=(
                    f"Active: {_fmt_bytes(active_bytes)}, "
                    f"Inactive: {_fmt_bytes(inactive_bytes)}, "
                    f"Wired: {_fmt_bytes(wired_bytes)}, "
                    f"Compressed: {_fmt_bytes(compressed_bytes)}, "
                    f"Free: {_fmt_bytes(free_bytes)}."
                ),
                severity=Severity.INFO,
                category=self.category,
                data={
                    "check": "memory_stats",
                    "active_bytes": active_bytes,
                    "inactive_bytes": inactive_bytes,
                    "wired_bytes": wired_bytes,
                    "compressed_bytes": compressed_bytes,
                    "free_bytes": free_bytes,
                },
            )
        )

        # INFO: Report page activity
        findings.append(
            Finding(
                title="Page activity metrics",
                description=(
                    f"Page-ins: {page_ins:,}, Page-outs: {page_outs:,}. "
                    f"High page-out activity indicates memory pressure."
                ),
                severity=Severity.INFO,
                category=self.category,
                data={
                    "check": "page_activity",
                    "page_ins": page_ins,
                    "page_outs": page_outs,
                },
            )
        )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        for finding in findings.findings:
            check = finding.data.get("check")

            if check == "critical_swap_exceeds_ram":
                actions.append(
                    Action(
                        title="Address critical swap usage",
                        description=(
                            "Swap usage exceeds physical RAM. Immediate actions:\n"
                            "1. Open Activity Monitor (Cmd+Space, type 'Activity Monitor')\n"
                            "2. Click the Memory tab and sort by memory usage\n"
                            "3. Close applications using the most memory\n"
                            "4. Restart high-memory applications if needed\n"
                            "5. Consider upgrading RAM or reducing concurrent applications.\n"
                            "6. Check for memory leaks by restarting applications."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif check == "high_page_outs":
                actions.append(
                    Action(
                        title="Reduce page-out activity (system thrashing)",
                        description=(
                            "High page-out activity indicates severe memory pressure. "
                            "The system is writing memory to disk excessively. Actions:\n"
                            "1. Open Activity Monitor (Cmd+Space, type 'Activity Monitor')\n"
                            "2. Click the Memory tab and sort by memory usage\n"
                            "3. Close large applications (browsers, IDEs, VMs, etc.)\n"
                            "4. Close browser tabs to reduce memory footprint\n"
                            "5. Restart the system if issues persist\n"
                            "6. Consider adding more RAM if this is a recurring issue."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif check == "critical_memory_pressure":
                actions.append(
                    Action(
                        title="Reduce critical memory pressure",
                        description=(
                            "The system is reporting critical memory pressure. "
                            "Recommended actions:\n"
                            "1. Open Activity Monitor (Cmd+Space, type 'Activity Monitor')\n"
                            "2. Review the Memory tab and identify large consumers\n"
                            "3. Close unnecessary applications\n"
                            "4. Close browser tabs and unnecessary browser windows\n"
                            "5. Avoid running memory-intensive applications simultaneously\n"
                            "6. Consider upgrading RAM if this is persistent."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _get_memory_info(self, profile: SystemProfile) -> dict:
        """Collect swap and memory information from sysctl and vm_stat."""
        info = {}

        # Get swap usage via sysctl vm.swapusage
        try:
            result = subprocess.run(
                ["sysctl", "vm.swapusage"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                self._parse_swap_usage(result.stdout, info)
        except Exception as e:
            pass

        # Get memory statistics from vm_stat
        try:
            result = subprocess.run(
                ["vm_stat"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                self._parse_vm_stat(result.stdout, info)
        except Exception as e:
            pass

        # Get memory pressure level
        try:
            result = subprocess.run(
                ["sysctl", "kern.memorystatus_vm_pressure_level"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                match = re.search(
                    r"kern\.memorystatus_vm_pressure_level:\s+(\d+)", result.stdout
                )
                if match:
                    info["memory_pressure"] = int(match.group(1))
        except Exception as e:
            pass

        return info

    def _parse_swap_usage(self, output: str, info: dict) -> None:
        """Parse vm.swapusage output and extract swap metrics.

        Format: "vm.swapusage: total = 4096.00M  used = 2560.00M  free = 1536.00M  (encrypted)"
        """
        # Extract total
        match_total = re.search(r"total\s*=\s*([\d.]+)([MG]?)", output)
        if match_total:
            value = float(match_total.group(1))
            unit = match_total.group(2)
            info["swap_total_bytes"] = self._convert_to_bytes(value, unit)

        # Extract used
        match_used = re.search(r"used\s*=\s*([\d.]+)([MG]?)", output)
        if match_used:
            value = float(match_used.group(1))
            unit = match_used.group(2)
            info["swap_used_bytes"] = self._convert_to_bytes(value, unit)

    def _parse_vm_stat(self, output: str, info: dict) -> None:
        """Parse vm_stat output and extract memory metrics."""
        lines = output.split("\n")

        # First line contains page size: "Mach Virtual Memory Statistics: (page size of 16384 bytes)"
        if lines:
            match = re.search(r"page size of (\d+) bytes", lines[0])
            if match:
                info["page_size"] = int(match.group(1))

        # Parse individual memory statistics
        for line in lines[1:]:
            line = line.strip()
            if not line:
                continue
            # Format: "Pages free:                        262144."
            # Also handle multi-word keys like "Pages wired down:"
            match = re.match(r"Pages\s+([\w\s]+):\s+(\d+)\.", line)
            if match:
                key = match.group(1).strip()
                value = int(match.group(2))

                if key == "free":
                    info["free_pages"] = value
                elif key == "active":
                    info["active_pages"] = value
                elif key == "inactive":
                    info["inactive_pages"] = value
                elif key == "wired down":
                    info["wired_pages"] = value
                elif key == "compressed":
                    info["compressed_pages"] = value
                elif key == "pageins":
                    info["page_ins"] = value
                elif key == "pageouts":
                    info["page_outs"] = value

    def _convert_to_bytes(self, value: float, unit: str) -> int:
        """Convert value with unit (M, G, etc.) to bytes."""
        if unit == "G":
            return int(value * 1024 * 1024 * 1024)
        elif unit == "M":
            return int(value * 1024 * 1024)
        elif unit == "K":
            return int(value * 1024)
        else:
            # Assume bytes if no unit
            return int(value)


def _fmt_bytes(n: int) -> str:
    """Format bytes into human-readable units."""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"
