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
    name = "swap_usage"
    category = "performance"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 70
    depends_on = []
    estimated_duration = "3s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        try:
            swap_info = self._get_swap_info(profile)
        except Exception as e:
            return CheckResult(module_name=self.name, findings=findings)

        total_ram_bytes = profile.ram_bytes
        swap_total_bytes = swap_info.get("total_bytes", 0)
        swap_used_bytes = swap_info.get("used_bytes", 0)
        swap_free_bytes = swap_info.get("free_bytes", 0)
        compressor_mode = swap_info.get("compressor_mode")
        memory_pressure = swap_info.get("memory_pressure")

        # Check CRITICAL conditions first
        # CRITICAL: swap used > physical RAM size (severe memory pressure)
        if swap_used_bytes > total_ram_bytes:
            findings.append(
                Finding(
                    title="Critical: Swap usage exceeds physical RAM",
                    description=(
                        f"Swap usage ({_fmt_bytes(swap_used_bytes)}) exceeds physical RAM "
                        f"({_fmt_bytes(total_ram_bytes)}). The system is experiencing severe "
                        "memory pressure and performance is critically impacted. "
                        "Close applications or add RAM immediately."
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
        # WARNING: swap usage > 50% of physical RAM
        elif total_ram_bytes > 0 and swap_used_bytes > (total_ram_bytes * 0.5):
            swap_pct = (swap_used_bytes / total_ram_bytes) * 100
            findings.append(
                Finding(
                    title="Warning: High swap usage",
                    description=(
                        f"Swap usage ({_fmt_bytes(swap_used_bytes)}) exceeds 50% of physical RAM "
                        f"({_fmt_bytes(total_ram_bytes)}). The system is memory-starved and "
                        "performance is degraded. Close large applications or add RAM."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "check": "warning_swap_usage",
                        "swap_used_bytes": swap_used_bytes,
                        "swap_pct_of_ram": swap_pct,
                        "total_ram_bytes": total_ram_bytes,
                    },
                )
            )

        # INFO: Report swap usage and memory status
        if swap_total_bytes > 0:
            swap_usage_pct = (swap_used_bytes / swap_total_bytes) * 100
            findings.append(
                Finding(
                    title="Swap usage status",
                    description=(
                        f"Swap: {_fmt_bytes(swap_used_bytes)} used of "
                        f"{_fmt_bytes(swap_total_bytes)} total ({swap_usage_pct:.1f}% full). "
                        f"Free swap: {_fmt_bytes(swap_free_bytes)}."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "check": "swap_status",
                        "swap_used_bytes": swap_used_bytes,
                        "swap_total_bytes": swap_total_bytes,
                        "swap_free_bytes": swap_free_bytes,
                        "swap_usage_pct": swap_usage_pct,
                    },
                )
            )

        # INFO: Report memory compression status
        if compressor_mode is not None:
            findings.append(
                Finding(
                    title="Memory compression status",
                    description=(
                        f"Memory compression (WKdm) is {'enabled' if compressor_mode == 1 else 'disabled'}. "
                        "This is a macOS feature that compresses inactive memory to reduce swap usage."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "check": "compressor_mode",
                        "compressor_mode": compressor_mode,
                    },
                )
            )

        # INFO: Report memory pressure level
        if memory_pressure is not None:
            pressure_names = {
                0: "Normal",
                1: "Warning",
                2: "Critical",
            }
            pressure_name = pressure_names.get(memory_pressure, "Unknown")
            findings.append(
                Finding(
                    title="Memory pressure level",
                    description=(
                        f"Current memory pressure: {pressure_name} (level {memory_pressure}). "
                        "Higher levels indicate the system is under memory stress."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "check": "memory_pressure",
                        "memory_pressure": memory_pressure,
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
                            "Swap usage exceeds physical RAM size. Immediate actions:\n"
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
            elif check == "warning_swap_usage":
                actions.append(
                    Action(
                        title="Reduce swap usage",
                        description=(
                            "Swap usage is high relative to physical RAM. Recommended steps:\n"
                            "1. Open Activity Monitor (Cmd+Space, type 'Activity Monitor')\n"
                            "2. Click the Memory tab to see memory usage by app\n"
                            "3. Close unnecessary applications\n"
                            "4. Check for stuck or unresponsive processes\n"
                            "5. Monitor performance and restart if swap doesn't decrease.\n"
                            "6. Consider adding more RAM if this is a persistent issue."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _get_swap_info(self, profile: SystemProfile) -> dict:
        """Collect swap and memory information from sysctl."""
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

        # Get memory compressor mode
        try:
            result = subprocess.run(
                ["sysctl", "vm.compressor_mode"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                # Parse "vm.compressor_mode: 1" or similar
                match = re.search(r"vm\.compressor_mode:\s+(\d+)", result.stdout)
                if match:
                    info["compressor_mode"] = int(match.group(1))
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
                # Parse "kern.memorystatus_vm_pressure_level: 0" or similar
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
            info["total_bytes"] = self._convert_to_bytes(value, unit)

        # Extract used
        match_used = re.search(r"used\s*=\s*([\d.]+)([MG]?)", output)
        if match_used:
            value = float(match_used.group(1))
            unit = match_used.group(2)
            info["used_bytes"] = self._convert_to_bytes(value, unit)

        # Extract free
        match_free = re.search(r"free\s*=\s*([\d.]+)([MG]?)", output)
        if match_free:
            value = float(match_free.group(1))
            unit = match_free.group(2)
            info["free_bytes"] = self._convert_to_bytes(value, unit)

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
