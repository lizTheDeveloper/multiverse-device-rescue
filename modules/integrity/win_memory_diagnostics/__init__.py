import json
import subprocess
from typing import Optional

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
    name = "win_memory_diagnostics"
    category = "integrity"
    platforms = [Platform.WIN32]
    risk_level = RiskLevel.SAFE
    priority = 55
    depends_on = []
    estimated_duration = "10s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Get physical memory information
        physical_memory = self._get_physical_memory()
        if not physical_memory:
            findings.append(
                Finding(
                    title="Could not retrieve physical memory information",
                    description=(
                        "Failed to run Get-WmiObject Win32_PhysicalMemory. "
                        "Memory health cannot be assessed."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "memory_info_failed"},
                )
            )
            return CheckResult(module_name=self.name, findings=findings)

        # Check for memory errors in event log
        memory_errors = self._get_memory_errors()
        if memory_errors and memory_errors.get("has_errors"):
            findings.append(
                Finding(
                    title="Memory diagnostic errors found",
                    description=(
                        f"Windows Memory Diagnostic found {memory_errors.get('error_count', 'unknown')} error(s). "
                        "Bad RAM detected. Replace faulty memory modules immediately to prevent data corruption and system instability."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
                    data={
                        "check": "memory_errors_critical",
                        "error_count": memory_errors.get("error_count"),
                    },
                )
            )

        # Get RAM utilization info
        ram_utilization = self._get_ram_utilization()
        if ram_utilization:
            usable_bytes = ram_utilization.get("total_bytes", 0)
            free_bytes = ram_utilization.get("free_bytes", 0)

            # Compare with physical memory capacity
            physical_capacity = sum(
                m.get("capacity", 0) for m in physical_memory.get("modules", [])
            )

            # Check if usable is significantly less than installed
            if physical_capacity > 0 and usable_bytes < (physical_capacity * 0.9):
                missing_percent = ((physical_capacity - usable_bytes) / physical_capacity) * 100
                findings.append(
                    Finding(
                        title=f"Usable RAM less than installed ({missing_percent:.1f}% missing)",
                        description=(
                            f"Only {_format_bytes(usable_bytes)} of {_format_bytes(physical_capacity)} is usable. "
                            f"Missing {missing_percent:.1f}%. This indicates possible bad RAM or BIOS configuration issue."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={
                            "check": "ram_mismatch",
                            "total_bytes": physical_capacity,
                            "usable_bytes": usable_bytes,
                            "missing_percent": missing_percent,
                        },
                    )
                )

            # Check if total RAM is too low (use usable amount)
            total_gb = usable_bytes / (1024 ** 3)
            if total_gb < 4:
                findings.append(
                    Finding(
                        title=f"Low RAM ({total_gb:.1f} GB)",
                        description=(
                            f"System has only {total_gb:.1f} GB of RAM installed. "
                            "This is below the recommended minimum for modern Windows systems (4 GB or more). "
                            "Consider upgrading RAM for better performance."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={
                            "check": "low_ram",
                            "total_gb": total_gb,
                        },
                    )
                )

        # Check for mismatched RAM modules
        mismatched = self._check_mismatched_ram(physical_memory)
        if mismatched:
            findings.append(
                Finding(
                    title="Mismatched RAM modules detected",
                    description=(
                        "RAM modules with different speeds or capacities are installed. "
                        "All modules will run at the speed of the slowest module, impacting performance."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "check": "mismatched_ram",
                        "details": mismatched,
                    },
                )
            )

        # Add informational findings about RAM configuration
        if physical_memory.get("modules"):
            total_capacity = sum(
                m.get("capacity", 0) for m in physical_memory.get("modules", [])
            )
            speeds = [
                m.get("speed") for m in physical_memory.get("modules", []) if m.get("speed")
            ]
            module_count = len(physical_memory.get("modules", []))

            ram_summary = f"{module_count} module(s), {_format_bytes(total_capacity)} total"
            if speeds:
                speed_str = f"{speeds[0]} MHz"
                if len(set(speeds)) > 1:
                    speed_str = f"{min(speeds)}-{max(speeds)} MHz"
                ram_summary += f", {speed_str}"

            findings.append(
                Finding(
                    title="RAM configuration",
                    description=ram_summary,
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "check": "ram_info",
                        "module_count": module_count,
                        "total_capacity": total_capacity,
                        "speeds": speeds,
                    },
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        for finding in findings.findings:
            check = finding.data.get("check")

            if check == "memory_errors_critical":
                error_count = finding.data.get("error_count", 0)
                actions.append(
                    Action(
                        title=f"Bad RAM detected ({error_count} error(s))",
                        description=(
                            f"Windows Memory Diagnostic found {error_count} RAM error(s). "
                            "This indicates faulty RAM modules. "
                            "Recommendations: (1) Identify which DIMM is failing (run Memory Diagnostic to see details). "
                            "(2) Purchase replacement RAM of the same type and speed. "
                            "(3) Shut down the system and replace the faulty module(s). "
                            "(4) Run Memory Diagnostic again to verify the fix. "
                            "Do not continue using the system with bad RAM as it will cause data corruption."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "ram_mismatch":
                missing_percent = finding.data.get("missing_percent", 0)
                actions.append(
                    Action(
                        title=f"Usable RAM less than installed ({missing_percent:.1f}% missing)",
                        description=(
                            f"{missing_percent:.1f}% of installed RAM is not usable. "
                            "Recommendations: (1) Run Windows Memory Diagnostic (mdsched.exe) to check for bad RAM. "
                            "(2) Check BIOS settings to ensure all RAM is detected. "
                            "(3) Reseat RAM modules (power off, remove and reinstall each DIMM firmly). "
                            "(4) If the problem persists, one or more modules may be faulty and need replacement."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "mismatched_ram":
                actions.append(
                    Action(
                        title="Mismatched RAM modules",
                        description=(
                            "RAM modules with different speeds or capacities are installed together. "
                            "All modules will run at the speed of the slowest module. "
                            "Recommendations: (1) For best performance, use matching RAM modules. "
                            "(2) If upgrading, purchase RAM with the same speed and type as existing modules. "
                            "(3) Consider replacing all modules with a matched set for optimal performance."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "low_ram":
                total_gb = finding.data.get("total_gb", 0)
                actions.append(
                    Action(
                        title=f"Low RAM ({total_gb:.1f} GB)",
                        description=(
                            f"System has only {total_gb:.1f} GB of RAM. "
                            "This is below recommended levels for modern Windows. "
                            "Recommendations: (1) Upgrade to at least 8 GB of RAM for acceptable performance. "
                            "(2) For multitasking or demanding applications, 16 GB or more is recommended. "
                            "(3) Check available upgrade options for your system (some laptops have soldered RAM). "
                            "(4) In the meantime, disable unnecessary startup programs and use lighter applications."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "memory_info_failed":
                actions.append(
                    Action(
                        title="Unable to assess RAM health",
                        description=(
                            "The Get-WmiObject Win32_PhysicalMemory command failed. "
                            "Ensure you have Administrator privileges and run the diagnostic again. "
                            "Try running the following in PowerShell (as Administrator): "
                            "Get-WmiObject Win32_PhysicalMemory | Select-Object BankLabel, Capacity, Speed, Manufacturer"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "ram_info":
                actions.append(
                    Action(
                        title="RAM configuration normal",
                        description=(
                            "RAM configuration is healthy and within expected parameters. "
                            "Continue monitoring for performance issues."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _get_physical_memory(self) -> Optional[dict]:
        """Get physical memory information from PowerShell Get-WmiObject Win32_PhysicalMemory."""
        try:
            ps_cmd = (
                "Get-WmiObject Win32_PhysicalMemory | "
                "Select-Object BankLabel, Capacity, Speed, Manufacturer, MemoryType, FormFactor | "
                "ConvertTo-Json"
            )
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                return None

            return _parse_physical_memory(result.stdout)
        except (OSError, subprocess.SubprocessError, TimeoutError):
            return None

    def _get_memory_errors(self) -> Optional[dict]:
        """Check for memory errors in Windows Memory Diagnostic event log."""
        try:
            ps_cmd = (
                "Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='Microsoft-Windows-MemoryDiagnostics-Results'} "
                "-MaxEvents 5 -ErrorAction SilentlyContinue | Measure-Object | Select-Object Count"
            )
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                return None

            error_count = _parse_event_count(result.stdout)
            if error_count and error_count > 0:
                return {"has_errors": True, "error_count": error_count}
            return None
        except (OSError, subprocess.SubprocessError, TimeoutError):
            return None

    def _get_ram_utilization(self) -> Optional[dict]:
        """Get total and free RAM information from Win32_OperatingSystem."""
        try:
            ps_cmd = (
                "(Get-WmiObject Win32_OperatingSystem) | "
                "Select-Object TotalVisibleMemorySize, FreePhysicalMemory | "
                "ConvertTo-Json"
            )
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                return None

            return _parse_ram_utilization(result.stdout)
        except (OSError, subprocess.SubprocessError, TimeoutError):
            return None

    def _check_mismatched_ram(self, physical_memory: dict) -> Optional[str]:
        """Check if RAM modules have mismatched speeds or capacities."""
        modules = physical_memory.get("modules", [])
        if not modules or len(modules) < 2:
            return None

        speeds = [m.get("speed") for m in modules if m.get("speed")]
        capacities = [m.get("capacity") for m in modules if m.get("capacity")]

        # Check for speed mismatch
        if speeds and len(set(speeds)) > 1:
            min_speed = min(speeds)
            max_speed = max(speeds)
            return f"Speed mismatch: {min_speed}-{max_speed} MHz"

        # Check for capacity mismatch
        if capacities and len(set(capacities)) > 1:
            min_cap = _format_bytes(min(capacities))
            max_cap = _format_bytes(max(capacities))
            return f"Capacity mismatch: {min_cap}-{max_cap}"

        return None


def _parse_physical_memory(json_output: str) -> dict:
    """Parse PowerShell JSON output from Get-WmiObject Win32_PhysicalMemory."""
    info = {"modules": []}

    if not json_output.strip():
        return info

    try:
        # Handle both single object and array
        data = json.loads(json_output)
        if not isinstance(data, list):
            data = [data]

        for module in data:
            info["modules"].append(
                {
                    "bank_label": module.get("BankLabel", "Unknown"),
                    "capacity": module.get("Capacity", 0),
                    "speed": module.get("Speed", 0),
                    "manufacturer": module.get("Manufacturer", "Unknown"),
                    "memory_type": module.get("MemoryType", "Unknown"),
                    "form_factor": module.get("FormFactor", "Unknown"),
                }
            )

        return info
    except (json.JSONDecodeError, ValueError, KeyError):
        return info


def _parse_ram_utilization(json_output: str) -> dict:
    """Parse PowerShell JSON output from Get-WmiObject Win32_OperatingSystem."""
    info = {
        "total_bytes": 0,
        "free_bytes": 0,
        "usable_bytes": 0,
    }

    if not json_output.strip():
        return info

    try:
        data = json.loads(json_output)

        # Convert from KB to bytes
        total_kb = data.get("TotalVisibleMemorySize", 0)
        free_kb = data.get("FreePhysicalMemory", 0)

        info["total_bytes"] = total_kb * 1024 if isinstance(total_kb, int) else 0
        info["free_bytes"] = free_kb * 1024 if isinstance(free_kb, int) else 0
        info["usable_bytes"] = info["total_bytes"]  # Usable = total visible

        return info
    except (json.JSONDecodeError, ValueError, KeyError):
        return info


def _parse_event_count(output: str) -> int:
    """Extract count from PowerShell Measure-Object output."""
    try:
        # Look for "Count" line first, then find the number
        lines = output.split("\n")
        found_count = False
        for i, line in enumerate(lines):
            if "count" in line.lower():
                found_count = True
                # Try to find digits on this line
                parts = line.split()
                for part in parts:
                    if part.isdigit():
                        return int(part)
                # If not on this line, look on following lines
                for j in range(i + 1, min(i + 3, len(lines))):
                    next_line = lines[j].strip()
                    if next_line.isdigit():
                        return int(next_line)
        # If no "Count" header found, just look for any digit string
        if not found_count:
            for line in lines:
                line_stripped = line.strip()
                if line_stripped.isdigit():
                    return int(line_stripped)
        return 0
    except (ValueError, IndexError):
        return 0


def _format_bytes(bytes_value: int) -> str:
    """Convert bytes to human-readable format."""
    if not isinstance(bytes_value, int) or bytes_value == 0:
        return "Unknown"

    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if bytes_value < 1024:
            return f"{bytes_value:.1f} {unit}"
        bytes_value /= 1024
    return f"{bytes_value:.1f} PB"
