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


class Module(ModuleBase):
    name = "smc_reset_check"
    category = "integrity"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "10s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Determine CPU architecture
        cpu_brand = self._get_cpu_brand()
        is_apple_silicon = _is_apple_silicon(cpu_brand)

        if is_apple_silicon:
            # Apple Silicon doesn't have traditional SMC reset
            findings.append(
                Finding(
                    title="Apple Silicon detected",
                    description=(
                        "This Mac has Apple Silicon (M1/M2/M3 or newer). SMC reset does not "
                        "apply to Apple Silicon Macs. The SMC is integrated into the chip and "
                        "automatically managed by macOS. If experiencing fan, thermal, or power "
                        "issues, restart the Mac first."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "apple_silicon", "cpu_brand": cpu_brand},
                )
            )
            return CheckResult(module_name=self.name, findings=findings)

        # Intel Mac - check for SMC reset symptoms
        # Check battery charging status
        batt_output = self._run_pmset_batt()
        batt_info = _parse_pmset_batt(batt_output)

        if batt_info.get("is_plugged_in") and batt_info.get("is_charging") is False:
            findings.append(
                Finding(
                    title="Battery not charging despite being plugged in",
                    description=(
                        "The battery is plugged in but not charging. This may indicate "
                        "an SMC issue. If the issue persists after restart, an SMC reset "
                        "may be needed."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "battery_not_charging", "power_source": batt_info.get("power_source")},
                )
            )

        # Check thermal throttling
        therm_output = self._run_pmset_therm()
        therm_info = _parse_pmset_therm(therm_output)

        if therm_info.get("thermal_throttling"):
            findings.append(
                Finding(
                    title="Thermal throttling detected",
                    description=(
                        "CPU thermal throttling is active, meaning the CPU speed is being "
                        "reduced to manage temperature. This may indicate an SMC issue or "
                        "thermal sensor malfunction."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "thermal_throttling"},
                )
            )

        # Check fan speeds via system_profiler
        power_output = self._run_system_profiler()
        fan_info = _parse_system_profiler_fans(power_output)

        if fan_info.get("fans_at_max"):
            findings.append(
                Finding(
                    title="Fans running at maximum speed constantly",
                    description=(
                        "One or more fans are running at maximum RPM constantly. This may "
                        "indicate an SMC issue or thermal sensor malfunction. The system may "
                        "be reporting high temperatures incorrectly."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "check": "fans_at_max",
                        "fan_data": fan_info.get("fan_data", []),
                    },
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        for finding in findings.findings:
            check = finding.data.get("check")

            if check == "apple_silicon":
                actions.append(
                    Action(
                        title="Apple Silicon - restart instead",
                        description=(
                            "Apple Silicon Macs do not require SMC resets. If you are experiencing "
                            "issues with fans, thermal management, battery charging, or sleep/wake, "
                            "try restarting the Mac first. Hold down the power button for 10 seconds "
                            "to force shutdown, then press power again to restart."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "battery_not_charging":
                actions.append(
                    Action(
                        title="Troubleshoot battery charging issue",
                        description=(
                            "Try these steps:\n"
                            "1. Restart the Mac completely (not just sleep)\n"
                            "2. Check that the power adapter is properly connected\n"
                            "3. Try a different USB-C cable if available\n"
                            "4. Leave the Mac plugged in for at least 15 minutes\n"
                            "If the battery still won't charge after restart, an SMC reset may help:\n"
                            "   - Shut down the Mac completely\n"
                            "   - Press Shift + Control + Option (all on left side) + Power button\n"
                            "   - Hold all four keys for 10 seconds\n"
                            "   - Release all keys and wait a few seconds\n"
                            "   - Power on normally\n"
                            "If battery still won't charge, contact Apple Support."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "thermal_throttling":
                actions.append(
                    Action(
                        title="Troubleshoot thermal throttling",
                        description=(
                            "Thermal throttling may indicate an SMC issue. Try these steps:\n"
                            "1. Restart the Mac completely\n"
                            "2. Check that air vents are not blocked or dusty\n"
                            "3. Use the Mac on a hard, flat surface (not on a bed or pillow)\n"
                            "4. Monitor temperatures using Activity Monitor (Window > Dock > Temperatures)\n"
                            "If throttling continues after restart, an SMC reset may help:\n"
                            "   - Shut down the Mac completely\n"
                            "   - Press Shift + Control + Option (all on left side) + Power button\n"
                            "   - Hold all four keys for 10 seconds\n"
                            "   - Release all keys and wait a few seconds\n"
                            "   - Power on normally"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "fans_at_max":
                actions.append(
                    Action(
                        title="Troubleshoot fans running at maximum",
                        description=(
                            "Fans constantly at maximum may indicate an SMC issue. Try these steps:\n"
                            "1. Restart the Mac completely\n"
                            "2. Check that air vents are not blocked or dusty\n"
                            "3. Close unnecessary applications consuming CPU\n"
                            "4. Check Activity Monitor for processes using high CPU\n"
                            "If fans remain loud after restart, an SMC reset may help:\n"
                            "   - Shut down the Mac completely\n"
                            "   - Press Shift + Control + Option (all on left side) + Power button\n"
                            "   - Hold all four keys for 10 seconds\n"
                            "   - Release all keys and wait a few seconds\n"
                            "   - Power on normally\n"
                            "Note: After SMC reset, fans may run at full speed briefly as they initialize."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _get_cpu_brand(self) -> str:
        """Get CPU brand string."""
        try:
            result = subprocess.run(
                ["sysctl", "-n", "machdep.cpu.brand_string"],
                capture_output=True,
                text=True,
            )
            return result.stdout.strip()
        except (OSError, subprocess.SubprocessError):
            return ""

    def _run_system_profiler(self) -> str:
        """Run system_profiler SPPowerDataType and return output."""
        try:
            result = subprocess.run(
                ["system_profiler", "SPPowerDataType"],
                capture_output=True,
                text=True,
            )
            return result.stdout
        except (OSError, subprocess.SubprocessError):
            return ""

    def _run_pmset_batt(self) -> str:
        """Run pmset -g batt and return output."""
        try:
            result = subprocess.run(
                ["pmset", "-g", "batt"],
                capture_output=True,
                text=True,
            )
            return result.stdout
        except (OSError, subprocess.SubprocessError):
            return ""

    def _run_pmset_therm(self) -> str:
        """Run pmset -g therm and return output."""
        try:
            result = subprocess.run(
                ["pmset", "-g", "therm"],
                capture_output=True,
                text=True,
            )
            return result.stdout
        except (OSError, subprocess.SubprocessError):
            return ""


def _is_apple_silicon(cpu_brand: str) -> bool:
    """Check if CPU is Apple Silicon."""
    if not cpu_brand:
        return False
    return "Apple" in cpu_brand


def _parse_pmset_batt(output: str) -> dict:
    """Parse pmset -g batt output."""
    info = {
        "is_plugged_in": False,
        "is_charging": None,
        "power_source": "unknown",
    }

    if not output:
        return info

    # Check for "AC Power" or "Battery Power"
    if "AC Power" in output:
        info["is_plugged_in"] = True
        info["power_source"] = "AC"
    elif "Battery Power" in output:
        info["is_plugged_in"] = False
        info["power_source"] = "Battery"

    # Check charging status - check "not charging" first since "charging" is a substring
    if "not charging" in output.lower():
        info["is_charging"] = False
    elif "discharging" in output.lower():
        info["is_charging"] = False
    elif "charging" in output.lower():
        info["is_charging"] = True

    return info


def _parse_pmset_therm(output: str) -> dict:
    """Parse pmset -g therm output."""
    info = {
        "thermal_throttling": False,
    }

    if not output:
        return info

    # Check for CPU Speed Limit
    if "CPU Speed Limit" in output:
        # If CPU speed is limited below 100%, there's thermal throttling
        limit_match = re.search(r"CPU Speed Limit:\s*(\d+)%", output)
        if limit_match:
            limit_percent = int(limit_match.group(1))
            if limit_percent < 100:
                info["thermal_throttling"] = True

    return info


def _parse_system_profiler_fans(output: str) -> dict:
    """Parse system_profiler SPPowerDataType for fan information."""
    info = {
        "fans_at_max": False,
        "fan_data": [],
    }

    if not output:
        return info

    # Look for fan speed patterns
    # Common pattern: "Current Speed: XXXX RPM" or similar
    fan_lines = []
    for line in output.split("\n"):
        if "Current Speed" in line and "RPM" in line:
            fan_lines.append(line.strip())

    if fan_lines:
        info["fan_data"] = fan_lines

    # Heuristic: If we find multiple fans and they're all reported at very high speeds,
    # or if we see patterns indicating max speed, flag it
    # This is conservative - we only flag if it's very clear
    if fan_lines and len(fan_lines) > 0:
        # Extract RPM values
        rpms = []
        for line in fan_lines:
            rpm_match = re.search(r"(\d+)\s*RPM", line)
            if rpm_match:
                rpms.append(int(rpm_match.group(1)))

        # If we have RPM data and can determine max typical speed
        # Most fans max out at 5000-8000 RPM. If multiple fans are near max, flag it.
        if rpms and len(rpms) >= 2:
            avg_rpm = sum(rpms) / len(rpms)
            # If average is above 6000 RPM and they're all high, suspect max speed
            if avg_rpm > 6000 and all(rpm > 5500 for rpm in rpms):
                info["fans_at_max"] = True

    return info
