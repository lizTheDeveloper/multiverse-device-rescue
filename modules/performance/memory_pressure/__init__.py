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
    name = "memory_pressure"
    category = "performance"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 75
    depends_on = []
    estimated_duration = "3s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        try:
            memory_info = self._get_memory_info()
        except Exception as e:
            return CheckResult(module_name=self.name, findings=findings)

        total_bytes = memory_info.get("total_bytes", 0)
        total_pages = memory_info.get("total_pages", 0)
        page_size = memory_info.get("page_size", 4096)
        free_pages = memory_info.get("free_pages", 0)
        inactive_pages = memory_info.get("inactive_pages", 0)
        compressed_pages = memory_info.get("compressed_pages", 0)
        swap_used_mb = memory_info.get("swap_used_mb", 0)

        # Check CRITICAL conditions first (before WARNING)
        # CRITICAL: swap used > 50% of physical RAM
        if total_bytes > 0:
            swap_used_bytes = swap_used_mb * 1024 * 1024
            swap_pct_of_ram = swap_used_bytes / total_bytes if total_bytes > 0 else 0
            if swap_pct_of_ram > 0.50:
                findings.append(
                    Finding(
                        title="Critical: Extreme memory pressure detected",
                        description=(
                            f"Swap usage ({_fmt_bytes(swap_used_bytes)}) exceeds 50% of "
                            f"physical RAM ({_fmt_bytes(total_bytes)}). The system is "
                            "severely memory-constrained and performance is likely critical. "
                            "Close applications or add RAM."
                        ),
                        severity=Severity.CRITICAL,
                        category=self.category,
                        data={
                            "check": "critical_swap",
                            "swap_used_mb": swap_used_mb,
                            "swap_pct_of_ram": swap_pct_of_ram,
                        },
                    )
                )

        # WARNING: swap used > 2GB
        if swap_used_mb > 2048:
            findings.append(
                Finding(
                    title="High swap usage",
                    description=(
                        f"Swap is using {_fmt_bytes(swap_used_mb * 1024 * 1024)} "
                        f"(>{_fmt_bytes(2048 * 1024 * 1024)}). This indicates memory pressure. "
                        "Consider closing large applications or checking Activity Monitor."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "check": "swap_usage",
                        "swap_used_mb": swap_used_mb,
                    },
                )
            )

        # WARNING: free+inactive pages < 10% of total
        if total_pages > 0:
            available_pages = free_pages + inactive_pages
            available_pct = available_pages / total_pages
            if available_pct < 0.10:
                findings.append(
                    Finding(
                        title="Low available memory",
                        description=(
                            f"Free and inactive memory is only {available_pct:.1%} of total "
                            f"({_fmt_bytes(available_pages * page_size)} of "
                            f"{_fmt_bytes(total_bytes)}). The system has limited memory "
                            "available for new applications."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={
                            "check": "low_available",
                            "available_pct": available_pct,
                            "available_pages": available_pages,
                        },
                    )
                )

        # INFO: Report compressed memory (common on older Macs under pressure)
        if compressed_pages > 0:
            compressed_mb = (compressed_pages * page_size) / (1024 * 1024)
            findings.append(
                Finding(
                    title="Compressed memory detected",
                    description=(
                        f"The system is using {compressed_mb:.1f} MB of compressed memory. "
                        "This is a normal macOS memory optimization, but high compression "
                        "can impact performance. Monitor if performance degrades."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "check": "compressed_memory",
                        "compressed_mb": compressed_mb,
                    },
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            check = finding.data.get("check")
            if check == "critical_swap":
                actions.append(
                    Action(
                        title="Address critical memory pressure",
                        description=(
                            "The system is experiencing critical memory pressure. "
                            "Immediate actions:\n"
                            "1. Open Activity Monitor (Cmd+Space, type 'Activity Monitor')\n"
                            "2. Click the Memory tab and sort by memory usage\n"
                            "3. Close applications using the most memory\n"
                            "4. If issues persist, consider upgrading RAM or reducing open apps.\n"
                            "5. Check for memory leaks: restart affected applications."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif check == "swap_usage":
                actions.append(
                    Action(
                        title="Reduce swap usage",
                        description=(
                            "High swap usage indicates memory pressure. Recommended steps:\n"
                            "1. Open Activity Monitor (Cmd+Space, type 'Activity Monitor')\n"
                            "2. Click the Memory tab to see memory usage by app\n"
                            "3. Close unnecessary applications\n"
                            "4. Check for stuck or unresponsive processes\n"
                            "5. Restart the system if memory doesn't improve."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif check == "low_available":
                actions.append(
                    Action(
                        title="Free up available memory",
                        description=(
                            "The system has limited free memory available. "
                            "To improve performance:\n"
                            "1. Open Activity Monitor (Cmd+Space, type 'Activity Monitor')\n"
                            "2. Sort by memory usage and close unnecessary apps\n"
                            "3. Browser tabs and background services consume significant memory\n"
                            "4. Consider restarting the system to clear memory caches."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif check == "compressed_memory":
                actions.append(
                    Action(
                        title="Monitor compressed memory",
                        description=(
                            "The system is compressing memory for optimization. This is normal, "
                            "but if you notice performance issues:\n"
                            "1. Open Activity Monitor (Cmd+Space, type 'Activity Monitor')\n"
                            "2. Check the Memory tab for applications using excessive memory\n"
                            "3. Close or restart resource-heavy applications\n"
                            "4. Monitor system performance over time."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _get_memory_info(self) -> dict:
        """Collect memory information from sysctl and vm_stat."""
        info = {}

        # Get total physical memory
        try:
            result = subprocess.run(
                ["sysctl", "hw.memsize"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                # Parse "hw.memsize: 8589934592"
                match = re.search(r"hw\.memsize:\s+(\d+)", result.stdout)
                if match:
                    info["total_bytes"] = int(match.group(1))
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

        # Get swap usage
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

        # Calculate total_pages if we have page_size and total_bytes
        if "total_bytes" in info and "page_size" in info:
            info["total_pages"] = info["total_bytes"] // info["page_size"]

        return info

    def _parse_vm_stat(self, output: str, info: dict) -> None:
        """Parse vm_stat output and extract memory metrics."""
        lines = output.split("\n")

        # First line contains page size: "Mach Virtual Memory Statistics: (page size of 16384 bytes)"
        if lines:
            match = re.search(r"page size of (\d+) bytes", lines[0])
            if match:
                info["page_size"] = int(match.group(1))

        # Parse individual memory statistics
        page_stats = {}
        for line in lines[1:]:
            line = line.strip()
            if not line:
                continue
            # Format: "Pages free:                        262144."
            match = re.match(r"Pages\s+(\w+):\s+(\d+)\.", line)
            if match:
                key = match.group(1)
                value = int(match.group(2))
                page_stats[key] = value

        # Map page stats to info dict
        info["free_pages"] = page_stats.get("free", 0)
        info["active_pages"] = page_stats.get("active", 0)
        info["inactive_pages"] = page_stats.get("inactive", 0)
        info["wired_pages"] = page_stats.get("wired", 0)
        info["compressed_pages"] = page_stats.get("compressed", 0)

    def _parse_swap_usage(self, output: str, info: dict) -> None:
        """Parse vm.swapusage output and extract swap metrics."""
        # Format: "vm.swapusage: total = 4096.00M  used = 2560.00M  free = 1536.00M  (encrypted)"
        match = re.search(r"used\s*=\s*([\d.]+)([MG]?)", output)
        if match:
            value_str = match.group(1)
            unit = match.group(2)
            value = float(value_str)

            # Convert to MB
            if unit == "G":
                value *= 1024
            elif unit == "M":
                pass
            elif unit == "":
                # Assume bytes if no unit
                value /= (1024 * 1024)

            info["swap_used_mb"] = value


def _fmt_bytes(n: int) -> str:
    """Format bytes into human-readable units."""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"
