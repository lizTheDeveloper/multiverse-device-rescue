import re
import subprocess
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

# Temperature thresholds (in Celsius)
TEMP_CRITICAL_THRESHOLD = 95.0
TEMP_WARNING_THRESHOLD = 80.0


class Module(ModuleBase):
    name = "thermal_throttle_check"
    category = "performance"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 60
    depends_on = []
    estimated_duration = "3s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Get CPU temperature
        temp_data = self._get_cpu_temperature()
        if temp_data:
            findings.extend(self._check_temperature(temp_data))

        # Get CPU frequency info
        freq_data = self._get_cpu_frequency()
        if freq_data:
            findings.extend(self._check_cpu_frequency(freq_data))

        # Check thermal throttling state
        throttle_data = self._get_thermal_throttle_state()
        if throttle_data:
            findings.extend(self._check_throttle_state(throttle_data))

        # Check fan speeds
        fan_data = self._get_fan_speeds()
        if fan_data:
            findings.extend(self._check_fan_speeds(fan_data))

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        """
        Provide informational actions about thermal issues.
        This is a diagnostic tool - it reports thermal problems and suggests actions,
        but does NOT modify the system.
        """
        actions = []

        for finding in findings.findings:
            if finding.severity == Severity.CRITICAL:
                actions.append(
                    Action(
                        title=f"Critical thermal condition detected: {finding.title}",
                        description=(
                            f"{finding.description}\n\n"
                            "CRITICAL: Your Mac is at risk of thermal damage. Immediate action required:\n"
                            "1. Stop all intensive tasks immediately\n"
                            "2. Shut down and let the Mac cool for 30+ minutes\n"
                            "3. Check for dust in fan vents - gently clean with compressed air\n"
                            "4. Ensure the Mac is on a hard, flat surface for proper ventilation\n"
                            "5. If problem persists, the thermal paste may need replacement - visit Apple Service or qualified technician\n"
                            "6. Consider an external cooling pad (USB-powered fan mat)\n"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif finding.severity == Severity.WARNING:
                actions.append(
                    Action(
                        title=f"Thermal warning: {finding.title}",
                        description=(
                            f"{finding.description}\n\n"
                            "WARNING: Your Mac is thermal throttling. To improve performance:\n"
                            "1. Use compressed air to clean fan vents (shut down first)\n"
                            "2. Ensure proper ventilation - use on a hard surface, not blankets or pillows\n"
                            "3. Close unnecessary applications consuming CPU\n"
                            "4. Reduce screen brightness slightly (saves power and heat)\n"
                            "5. Consider a cooling pad for extended heavy workloads\n"
                            "6. If older Mac, thermal paste may be degraded - consult an Apple Service Provider\n"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif finding.severity == Severity.INFO:
                # Only add INFO actions if they're significant thermal reports
                if "fan" in finding.title.lower() or "throttle" in finding.title.lower():
                    actions.append(
                        Action(
                            title=f"Thermal status: {finding.title}",
                            description=finding.description,
                            risk_level=RiskLevel.SAFE,
                            success=True,
                        )
                    )

        return FixResult(module_name=self.name, actions=actions)

    def _get_cpu_temperature(self) -> dict | None:
        """Get CPU temperature using powermetrics (primary) or ioreg (fallback)."""
        # Try powermetrics first
        try:
            result = subprocess.run(
                ["sudo", "powermetrics", "--samplers", "smc", "-n", "1", "-i", "100"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                return {"source": "powermetrics", "output": result.stdout}
        except Exception:
            pass

        # Fallback to ioreg
        try:
            result = subprocess.run(
                ["ioreg", "-r", "-n", "AppleSMC"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                return {"source": "ioreg", "output": result.stdout}
        except Exception:
            pass

        return None

    def _get_cpu_frequency(self) -> dict | None:
        """Get current and max CPU frequency."""
        try:
            current_result = subprocess.run(
                ["sysctl", "hw.cpufrequency"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            max_result = subprocess.run(
                ["sysctl", "hw.cpufrequency_max"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if current_result.returncode == 0 and max_result.returncode == 0:
                return {
                    "current": current_result.stdout.strip(),
                    "max": max_result.stdout.strip(),
                }
        except Exception:
            pass

        return None

    def _get_thermal_throttle_state(self) -> dict | None:
        """Check thermal throttle state via pmset."""
        try:
            result = subprocess.run(
                ["pmset", "-g", "thermlog"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                return {"output": result.stdout}
        except Exception:
            pass

        return None

    def _get_fan_speeds(self) -> dict | None:
        """Get fan speed info from ioreg."""
        try:
            result = subprocess.run(
                ["ioreg", "-r", "-n", "AppleSMCFan"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                return {"output": result.stdout}
        except Exception:
            pass

        return None

    def _check_temperature(self, temp_data: dict) -> list[Finding]:
        """Check CPU temperature and create findings."""
        findings = []

        if temp_data["source"] == "powermetrics":
            temp = self._parse_powermetrics_temp(temp_data["output"])
        else:
            temp = self._parse_ioreg_temp(temp_data["output"])

        if temp is not None:
            if temp > TEMP_CRITICAL_THRESHOLD:
                findings.append(
                    Finding(
                        title="CPU temperature critical",
                        description=f"CPU die temperature is {temp:.1f}°C (CRITICAL - above {TEMP_CRITICAL_THRESHOLD}°C)",
                        severity=Severity.CRITICAL,
                        category=self.category,
                        data={
                            "check": "cpu_temperature",
                            "value": temp,
                            "threshold": TEMP_CRITICAL_THRESHOLD,
                        },
                    )
                )
            elif temp > TEMP_WARNING_THRESHOLD:
                findings.append(
                    Finding(
                        title="CPU temperature elevated",
                        description=f"CPU die temperature is {temp:.1f}°C (WARNING - above {TEMP_WARNING_THRESHOLD}°C). Thermal throttling is likely active.",
                        severity=Severity.WARNING,
                        category=self.category,
                        data={
                            "check": "cpu_temperature",
                            "value": temp,
                            "threshold": TEMP_WARNING_THRESHOLD,
                        },
                    )
                )
            else:
                findings.append(
                    Finding(
                        title="CPU temperature normal",
                        description=f"CPU die temperature is {temp:.1f}°C (normal)",
                        severity=Severity.INFO,
                        category=self.category,
                        data={
                            "check": "cpu_temperature",
                            "value": temp,
                        },
                    )
                )

        return findings

    def _check_cpu_frequency(self, freq_data: dict) -> list[Finding]:
        """Check if CPU is running at reduced frequency due to throttling."""
        findings = []

        try:
            # Parse current frequency: "hw.cpufrequency: 2000000000"
            current_match = re.search(r":\s*(\d+)", freq_data["current"])
            max_match = re.search(r":\s*(\d+)", freq_data["max"])

            if current_match and max_match:
                current_hz = int(current_match.group(1))
                max_hz = int(max_match.group(1))

                current_ghz = current_hz / 1e9
                max_ghz = max_hz / 1e9

                # Calculate percentage of max
                freq_percent = (current_hz / max_hz) * 100 if max_hz > 0 else 100

                if freq_percent < 80:
                    findings.append(
                        Finding(
                            title="CPU running at reduced frequency",
                            description=f"Current CPU frequency: {current_ghz:.2f} GHz (max: {max_ghz:.2f} GHz, {freq_percent:.0f}% of max). CPU is throttled.",
                            severity=Severity.WARNING,
                            category=self.category,
                            data={
                                "check": "cpu_frequency",
                                "current_ghz": current_ghz,
                                "max_ghz": max_ghz,
                                "percent_of_max": freq_percent,
                            },
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            title="CPU frequency normal",
                            description=f"Current CPU frequency: {current_ghz:.2f} GHz (max: {max_ghz:.2f} GHz, {freq_percent:.0f}% of max)",
                            severity=Severity.INFO,
                            category=self.category,
                            data={
                                "check": "cpu_frequency",
                                "current_ghz": current_ghz,
                                "max_ghz": max_ghz,
                                "percent_of_max": freq_percent,
                            },
                        )
                    )
        except (ValueError, AttributeError):
            pass

        return findings

    def _check_throttle_state(self, throttle_data: dict) -> list[Finding]:
        """Check if thermal throttling is active from pmset output."""
        findings = []

        output = throttle_data["output"].lower()

        # Look for indicators of active throttling
        if "throttled" in output or "true" in output:
            findings.append(
                Finding(
                    title="Thermal throttling is active",
                    description="System is currently applying thermal throttling to reduce CPU temperature. Performance is being reduced.",
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "thermal_throttle_state"},
                )
            )
        else:
            findings.append(
                Finding(
                    title="No active thermal throttling",
                    description="System is not currently thermal throttling",
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "thermal_throttle_state"},
                )
            )

        return findings

    def _check_fan_speeds(self, fan_data: dict) -> list[Finding]:
        """Check fan speeds for signs of thermal stress."""
        findings = []

        output = fan_data["output"]

        # Parse for fan data - ioreg output contains fan RPM info
        # Look for max RPM patterns in ioreg output
        max_rpm_matches = re.findall(r"\"ActualSpeed\"\s*=\s*(\d+)", output)
        nominal_rpm_matches = re.findall(r"\"NominalSpeed\"\s*=\s*(\d+)", output)

        if max_rpm_matches and nominal_rpm_matches:
            try:
                max_actual = max(int(m) for m in max_rpm_matches)
                max_nominal = max(int(m) for m in nominal_rpm_matches)

                # If fans running at >95% of nominal speed, system is under thermal stress
                if max_nominal > 0 and max_actual > (max_nominal * 0.95):
                    findings.append(
                        Finding(
                            title="Fans running at high speed",
                            description=f"Maximum fan speed: {max_actual} RPM (nominal: {max_nominal} RPM, {(max_actual/max_nominal)*100:.0f}% of max). Fans are working hard to cool the system.",
                            severity=Severity.WARNING,
                            category=self.category,
                            data={
                                "check": "fan_speed",
                                "max_actual_rpm": max_actual,
                                "max_nominal_rpm": max_nominal,
                                "percent_of_nominal": (max_actual / max_nominal) * 100,
                            },
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            title="Fan speeds normal",
                            description=f"Maximum fan speed: {max_actual} RPM (nominal: {max_nominal} RPM)",
                            severity=Severity.INFO,
                            category=self.category,
                            data={
                                "check": "fan_speed",
                                "max_actual_rpm": max_actual,
                                "max_nominal_rpm": max_nominal,
                            },
                        )
                    )
            except (ValueError, StopIteration):
                pass

        return findings

    def _parse_powermetrics_temp(self, output: str) -> float | None:
        """Extract CPU die temperature from powermetrics output."""
        # Look for "CPU die temperature" line
        match = re.search(r"CPU die temperature\s*:\s*([\d.]+)\s*°C", output)
        if match:
            return float(match.group(1))
        return None

    def _parse_ioreg_temp(self, output: str) -> float | None:
        """Extract temperature sensor data from ioreg output."""
        # Look for temperature sensor values in ioreg
        # ioreg format often has "CurrentReading" for temperatures
        matches = re.findall(r"\"CurrentReading\"\s*=\s*(\d+)", output)
        if matches:
            # Values are typically in millidegrees, convert to Celsius
            # Heuristic: if value > 200, it's likely millidegrees
            temp_raw = int(matches[0])
            if temp_raw > 200:
                return temp_raw / 1000.0
            else:
                return float(temp_raw)
        return None
