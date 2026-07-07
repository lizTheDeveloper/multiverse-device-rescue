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
    name = "thermal_throttle"
    category = "performance"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 70
    depends_on = []
    estimated_duration = "3s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        try:
            thermal_info = self._get_thermal_info()
        except Exception as e:
            return CheckResult(module_name=self.name, findings=findings)

        current_freq = thermal_info.get("current_freq_mhz", 0)
        max_freq = thermal_info.get("max_freq_mhz", 0)
        thermal_state = thermal_info.get("thermal_state", "unknown")
        is_throttling = thermal_info.get("is_throttling", False)

        # WARNING: Thermal throttling is active
        if is_throttling:
            findings.append(
                Finding(
                    title="CPU thermal throttling detected",
                    description=(
                        "The CPU is being thermally throttled. Your system is running too "
                        "hot and reducing CPU speed to prevent damage. This significantly "
                        "impacts performance. Check cooling: clean vents, check fans, ensure "
                        "proper ventilation, and reduce workload."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "check": "thermal_throttling_active",
                        "thermal_state": thermal_state,
                        "current_freq_mhz": current_freq,
                        "max_freq_mhz": max_freq,
                    },
                )
            )

        # WARNING: CPU running below max frequency (but not actively throttling)
        if (
            not is_throttling
            and current_freq > 0
            and max_freq > 0
            and current_freq < max_freq * 0.9
        ):
            freq_pct = (current_freq / max_freq * 100) if max_freq > 0 else 0
            findings.append(
                Finding(
                    title="CPU running below max frequency",
                    description=(
                        f"CPU is running at {freq_pct:.1f}% of maximum frequency "
                        f"({current_freq} MHz vs {max_freq} MHz). This may indicate thermal "
                        "constraints or power-saving mode. Check system cooling and power "
                        "settings."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "check": "low_cpu_frequency",
                        "current_freq_mhz": current_freq,
                        "max_freq_mhz": max_freq,
                        "frequency_pct": freq_pct,
                    },
                )
            )

        # INFO: Report current thermal state and CPU speed
        if current_freq > 0 and max_freq > 0:
            findings.append(
                Finding(
                    title="CPU thermal and frequency status",
                    description=(
                        f"Current CPU frequency: {current_freq} MHz, "
                        f"Maximum frequency: {max_freq} MHz. "
                        f"Thermal state: {thermal_state}."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "check": "thermal_info",
                        "thermal_state": thermal_state,
                        "current_freq_mhz": current_freq,
                        "max_freq_mhz": max_freq,
                    },
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            check = finding.data.get("check")
            if check == "thermal_throttling_active":
                actions.append(
                    Action(
                        title="Address active CPU thermal throttling",
                        description=(
                            "Your Mac's CPU is being thermally throttled due to overheating. "
                            "Immediate actions to cool your system:\n"
                            "1. Check cooling vents: Use compressed air to clean intake/exhaust vents\n"
                            "2. Verify fans are running: Listen for fan noise or check System Information\n"
                            "3. Reduce workload: Close CPU-intensive applications (Chrome tabs, video editing, etc.)\n"
                            "4. Improve airflow: Ensure your Mac isn't on soft surfaces (pillow, blanket)\n"
                            "5. External cooling: Use a laptop cooling pad for sustained use\n"
                            "6. Check for dust inside: Have a technician clean internal fans if vents are clean\n"
                            "7. Restart your Mac: Sometimes helps reset thermal management\n"
                            "8. Reset SMC: Power off, press Shift+Ctrl+Option+Power for 10s (Intel) or restart holding Power (Apple Silicon)\n"
                            "If throttling continues, the system may need professional repair."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif check == "low_cpu_frequency":
                actions.append(
                    Action(
                        title="Investigate reduced CPU frequency",
                        description=(
                            "The CPU is running below maximum frequency. This can indicate "
                            "thermal constraints or power-saving settings. Steps to investigate:\n"
                            "1. Check Energy Saver settings: System Settings > Energy Saver\n"
                            "   - For laptops: Adjust 'Reduced motion' and 'lower power' mode settings\n"
                            "   - Ensure performance mode is enabled if plugged in\n"
                            "2. Monitor CPU temperature: Use third-party tools (Macs Fan Control) "
                            "or Activity Monitor\n"
                            "3. Check Activity Monitor: Look for high-CPU processes consuming resources\n"
                            "4. Verify cooling: Ensure vents are clean and fans are working\n"
                            "5. Reset SMC: If on Intel, run SMC reset procedure\n"
                            "6. Check for malware: Run Activity Monitor scan for suspicious processes"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif check == "thermal_info":
                actions.append(
                    Action(
                        title="Monitor CPU thermal and frequency status",
                        description=(
                            "Your system's CPU is currently operating at its reported "
                            "temperature and frequency. Monitor this over time:\n"
                            "1. Use Activity Monitor (Applications > Utilities) to check CPU usage\n"
                            "2. Monitor temperature trends during normal work\n"
                            "3. If performance degrades or system becomes hot, address cooling\n"
                            "4. For Mac models known for thermal issues, consider:\n"
                            "   - Using a cooling pad during sustained workloads\n"
                            "   - Keeping the system in a cool environment\n"
                            "   - Closing unnecessary applications"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _get_thermal_info(self) -> dict:
        """Collect thermal and CPU frequency information from pmset and sysctl."""
        info = {}

        # Get thermal state from pmset
        try:
            result = subprocess.run(
                ["pmset", "-g", "therm"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                self._parse_pmset_therm(result.stdout, info)
        except Exception:
            pass

        # Get current CPU frequency
        try:
            result = subprocess.run(
                ["sysctl", "hw.cpufrequency"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                # Parse "hw.cpufrequency: 2400000000" (in Hz)
                match = re.search(r"hw\.cpufrequency:\s+(\d+)", result.stdout)
                if match:
                    freq_hz = int(match.group(1))
                    info["current_freq_mhz"] = freq_hz // 1_000_000
        except Exception:
            pass

        # Get max CPU frequency
        try:
            result = subprocess.run(
                ["sysctl", "hw.cpufrequency_max"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                # Parse "hw.cpufrequency_max: 3200000000" (in Hz)
                match = re.search(r"hw\.cpufrequency_max:\s+(\d+)", result.stdout)
                if match:
                    freq_hz = int(match.group(1))
                    info["max_freq_mhz"] = freq_hz // 1_000_000
        except Exception:
            pass

        # Determine if throttling is active based on thermal state
        thermal_state = info.get("thermal_state", "Unknown")
        info["is_throttling"] = thermal_state in ["Critical", "Throttled"]

        return info

    def _parse_pmset_therm(self, output: str, info: dict) -> None:
        """Parse pmset -g therm output to extract thermal state."""
        lines = output.split("\n")
        for line in lines:
            line = line.strip()
            if not line:
                continue
            # Look for lines like "Thermal state: Normal"
            # Format can vary; common formats include:
            # "Thermal state: Normal" or "Thermal state: Throttled"
            # Also look for "System-wide Dynamic Power and Thermal Management:"
            # followed by temperature lines
            if "Thermal" in line and ":" in line:
                # Extract thermal state
                parts = line.split(":")
                if len(parts) >= 2:
                    state = parts[-1].strip()
                    info["thermal_state"] = state
                    break

        # If no explicit "Thermal state:" line, check for other indicators
        if "thermal_state" not in info:
            # Some versions may not have explicit state; assume Normal if we got output
            if output.strip():
                info["thermal_state"] = "Normal"
            else:
                info["thermal_state"] = "Unknown"
