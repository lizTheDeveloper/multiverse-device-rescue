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
    name = "memory_pressure_check"
    category = "performance"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 80
    depends_on = []
    estimated_duration = "3s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        try:
            memory_info = self._get_memory_info()
        except Exception as e:
            return CheckResult(module_name=self.name, findings=findings)

        # Extract memory metrics
        pressure_level = memory_info.get("pressure_level")
        total_bytes = memory_info.get("total_bytes", 0)
        page_size = memory_info.get("page_size", 4096)

        free_pages = memory_info.get("free_pages", 0)
        active_pages = memory_info.get("active_pages", 0)
        inactive_pages = memory_info.get("inactive_pages", 0)
        speculative_pages = memory_info.get("speculative_pages", 0)
        wired_pages = memory_info.get("wired_pages", 0)
        compressed_pages = memory_info.get("compressed_pages", 0)
        pageouts = memory_info.get("pageouts", 0)

        swap_total_mb = memory_info.get("swap_total_mb", 0)
        swap_used_mb = memory_info.get("swap_used_mb", 0)
        swap_free_mb = memory_info.get("swap_free_mb", 0)

        # Calculate available memory
        available_pages = free_pages + inactive_pages + speculative_pages
        available_bytes = available_pages * page_size

        # Calculate percentages
        wired_bytes = wired_pages * page_size
        wired_pct = (wired_bytes / total_bytes * 100) if total_bytes > 0 else 0

        swap_used_pct = (swap_used_mb / swap_total_mb * 100) if swap_total_mb > 0 else 0

        # CRITICAL: memory pressure is "critical" level
        if pressure_level == "critical":
            findings.append(
                Finding(
                    title="CRITICAL: System memory pressure at critical level",
                    description=(
                        "The system is experiencing critical memory pressure and may be thrashing. "
                        "Performance is severely degraded. Close applications immediately or add RAM."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
                    data={
                        "check": "critical_pressure",
                        "pressure_level": pressure_level,
                    },
                )
            )

        # WARNING: swap usage > 50% of total swap
        if swap_total_mb > 0 and swap_used_pct > 50:
            findings.append(
                Finding(
                    title="WARNING: Heavy swap usage detected",
                    description=(
                        f"Swap is using {swap_used_pct:.1f}% of total swap "
                        f"({_fmt_bytes(swap_used_mb * 1024 * 1024)} of "
                        f"{_fmt_bytes(swap_total_mb * 1024 * 1024)}). "
                        "Heavy swapping indicates memory pressure and significantly impacts performance."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "check": "high_swap_usage",
                        "swap_used_pct": swap_used_pct,
                        "swap_used_mb": swap_used_mb,
                    },
                )
            )

        # WARNING: pageout rate is high (>1000 pageouts)
        if pageouts > 1000:
            findings.append(
                Finding(
                    title="WARNING: High memory page-out rate",
                    description=(
                        f"System has written {pageouts} pages to disk. "
                        "This indicates memory pressure is causing pages to be swapped out, "
                        "which significantly degrades performance."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "check": "high_pageout",
                        "pageouts": pageouts,
                    },
                )
            )

        # WARNING: wired memory > 60% of total RAM
        if wired_pct > 60:
            findings.append(
                Finding(
                    title="WARNING: High kernel/driver memory usage",
                    description=(
                        f"Wired memory (kernel and drivers) is {wired_pct:.1f}% of total RAM "
                        f"({_fmt_bytes(wired_bytes)} of {_fmt_bytes(total_bytes)}). "
                        "This leaves limited memory for applications. Consider restarting or checking Activity Monitor."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "check": "high_wired",
                        "wired_pct": wired_pct,
                        "wired_bytes": wired_bytes,
                    },
                )
            )

        # INFO: Memory breakdown
        free_bytes = free_pages * page_size
        active_bytes = active_pages * page_size
        inactive_bytes = inactive_pages * page_size
        speculative_bytes = speculative_pages * page_size
        compressed_bytes = compressed_pages * page_size

        info_description = (
            f"Memory Statistics:\n"
            f"  Physical RAM: {_fmt_bytes(total_bytes)}\n"
            f"  Available: {_fmt_bytes(available_bytes)} "
            f"(free: {_fmt_bytes(free_bytes)}, inactive: {_fmt_bytes(inactive_bytes)}, "
            f"speculative: {_fmt_bytes(speculative_bytes)})\n"
            f"  Active: {_fmt_bytes(active_bytes)}\n"
            f"  Wired: {_fmt_bytes(wired_bytes)}\n"
            f"  Compressed: {_fmt_bytes(compressed_bytes)}\n"
            f"  Swap: {_fmt_bytes(swap_used_mb * 1024 * 1024)} used of "
            f"{_fmt_bytes(swap_total_mb * 1024 * 1024)}\n"
            f"  Page-outs: {pageouts}\n"
            f"  Pressure Level: {pressure_level if pressure_level else 'normal'}"
        )

        findings.append(
            Finding(
                title="Memory Breakdown",
                description=info_description,
                severity=Severity.INFO,
                category=self.category,
                data={
                    "check": "memory_breakdown",
                    "available_bytes": available_bytes,
                    "active_bytes": active_bytes,
                    "wired_bytes": wired_bytes,
                    "compressed_bytes": compressed_bytes,
                    "swap_used_mb": swap_used_mb,
                    "pageouts": pageouts,
                },
            )
        )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            check = finding.data.get("check")

            if check == "critical_pressure":
                actions.append(
                    Action(
                        title="Address critical memory pressure",
                        description=(
                            "The system is at critical memory pressure. Take immediate action:\n"
                            "1. Open Activity Monitor (Cmd+Space, type 'Activity Monitor')\n"
                            "2. Click the Memory tab and sort by memory usage (highest first)\n"
                            "3. Close unnecessary applications, starting with the highest consumers\n"
                            "4. Restart the system if memory pressure doesn't decrease\n"
                            "5. Consider upgrading RAM if this happens frequently\n"
                            "6. Check for memory leaks by restarting problematic applications"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "high_swap_usage":
                swap_pct = finding.data.get("swap_used_pct", 0)
                actions.append(
                    Action(
                        title=f"Reduce swap usage ({swap_pct:.1f}% of swap in use)",
                        description=(
                            "Heavy swap usage indicates the system is out of physical RAM. "
                            "Each access to swapped memory is 100x slower than RAM. "
                            "Recommended steps:\n"
                            "1. Open Activity Monitor (Cmd+Space, type 'Activity Monitor')\n"
                            "2. Click the Memory tab to see which apps use the most memory\n"
                            "3. Close or restart applications using excessive memory\n"
                            "4. Check for background services running unnecessary tasks\n"
                            "5. Restart the system to clear swap\n"
                            "6. Consider adding more RAM if this is a regular issue"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "high_pageout":
                pageouts = finding.data.get("pageouts", 0)
                actions.append(
                    Action(
                        title=f"High page-out rate detected ({pageouts} pages)",
                        description=(
                            "The system is swapping application memory to disk, which is very slow. "
                            "This happens when physical RAM is exhausted. Actions to take:\n"
                            "1. Open Activity Monitor (Cmd+Space, type 'Activity Monitor')\n"
                            "2. Check the Memory tab for applications using the most RAM\n"
                            "3. Close memory-intensive applications (browsers, video apps, IDEs)\n"
                            "4. Restart the system to reset memory statistics\n"
                            "5. Monitor if the problem recurs\n"
                            "6. If persistent, add more RAM to improve performance"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "high_wired":
                wired_pct = finding.data.get("wired_pct", 0)
                actions.append(
                    Action(
                        title=f"High kernel memory usage ({wired_pct:.1f}% wired)",
                        description=(
                            "Kernel and driver memory is consuming a large portion of RAM. "
                            "This memory cannot be released for applications. Try these steps:\n"
                            "1. Restart the system to reset kernel memory usage\n"
                            "2. Disable unnecessary kernel extensions if you've installed custom ones\n"
                            "3. Check System Preferences for background features you don't need "
                            "(e.g., iCloud, Time Machine, Spotlight indexing)\n"
                            "4. Update macOS and drivers to latest versions\n"
                            "5. If problem persists, reinstall macOS\n"
                            "6. In Activity Monitor, check for unusual processes consuming memory"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "memory_breakdown":
                actions.append(
                    Action(
                        title="Monitor system memory",
                        description=(
                            "Memory is currently balanced. Monitor periodically to ensure "
                            "the system stays healthy:\n"
                            "1. Regularly check Activity Monitor for memory-hungry applications\n"
                            "2. Restart the system weekly to clear memory caches\n"
                            "3. Watch for swap usage increasing, which indicates memory pressure\n"
                            "4. If you see warning signs, close applications early\n"
                            "5. Consider upgrading RAM if your workflow has grown"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _get_memory_info(self) -> dict:
        """Collect comprehensive memory information from macOS commands."""
        info = {}

        # Get memory pressure level
        try:
            result = subprocess.run(
                ["memory_pressure"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                self._parse_memory_pressure(result.stdout, info)
        except Exception as e:
            pass

        # Get total physical memory
        try:
            result = subprocess.run(
                ["sysctl", "hw.memsize"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                match = re.search(r"hw\.memsize:\s+(\d+)", result.stdout)
                if match:
                    info["total_bytes"] = int(match.group(1))
        except Exception as e:
            pass

        # Get page size
        try:
            result = subprocess.run(
                ["sysctl", "hw.pagesize"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                match = re.search(r"hw\.pagesize:\s+(\d+)", result.stdout)
                if match:
                    info["page_size"] = int(match.group(1))
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

        # Get compressor mode
        try:
            result = subprocess.run(
                ["sysctl", "vm.compressor_mode"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                match = re.search(r"vm\.compressor_mode:\s+(\d+)", result.stdout)
                if match:
                    info["compressor_mode"] = int(match.group(1))
        except Exception as e:
            pass

        return info

    def _parse_memory_pressure(self, output: str, info: dict) -> None:
        """Parse memory_pressure command output and extract pressure level.

        Output format:
        System memory pressure level: normal (or warning, critical)
        """
        lines = output.split("\n")
        for line in lines:
            line = line.strip()
            if "pressure level:" in line.lower():
                # Extract the level (normal, warning, or critical)
                parts = line.split(":")
                if len(parts) > 1:
                    level = parts[1].strip().lower()
                    # Take just the first word in case there's extra text
                    level = level.split()[0]
                    if level in ("normal", "warning", "critical"):
                        info["pressure_level"] = level

    def _parse_vm_stat(self, output: str, info: dict) -> None:
        """Parse vm_stat output and extract memory metrics."""
        lines = output.split("\n")

        # First line contains page size
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
        info["speculative_pages"] = page_stats.get("speculative", 0)
        info["wired_pages"] = page_stats.get("wired", 0)
        info["compressed_pages"] = page_stats.get("compressed", 0)
        info["pageouts"] = page_stats.get("pageouts", 0)

    def _parse_swap_usage(self, output: str, info: dict) -> None:
        """Parse vm.swapusage output and extract swap metrics.

        Format: "vm.swapusage: total = 4096.00M  used = 2560.00M  free = 1536.00M  (encrypted)"
        """
        # Parse total swap
        match_total = re.search(r"total\s*=\s*([\d.]+)([MG]?)", output)
        if match_total:
            value = float(match_total.group(1))
            unit = match_total.group(2)
            if unit == "G":
                value *= 1024
            info["swap_total_mb"] = value

        # Parse used swap
        match_used = re.search(r"used\s*=\s*([\d.]+)([MG]?)", output)
        if match_used:
            value = float(match_used.group(1))
            unit = match_used.group(2)
            if unit == "G":
                value *= 1024
            info["swap_used_mb"] = value

        # Parse free swap
        match_free = re.search(r"free\s*=\s*([\d.]+)([MG]?)", output)
        if match_free:
            value = float(match_free.group(1))
            unit = match_free.group(2)
            if unit == "G":
                value *= 1024
            info["swap_free_mb"] = value


def _fmt_bytes(n: int) -> str:
    """Format bytes into human-readable units."""
    if isinstance(n, float):
        n = int(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"
