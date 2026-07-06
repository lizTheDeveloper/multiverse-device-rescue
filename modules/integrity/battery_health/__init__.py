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
    name = "battery_health"
    category = "integrity"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "5s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Get battery info from system_profiler
        system_profiler_output = self._run_system_profiler()
        battery_info = _parse_system_profiler(system_profiler_output)

        # Check if battery is installed
        if not battery_info.get("battery_installed"):
            findings.append(
                Finding(
                    title="No battery detected",
                    description=(
                        "This device does not have a battery (e.g., a desktop Mac "
                        "or iMac). Battery health checks do not apply."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "no_battery"},
                )
            )
            return CheckResult(module_name=self.name, findings=findings)

        # Get battery info from ioreg for detailed capacity data
        ioreg_output = self._run_ioreg()
        ioreg_info = _parse_ioreg(ioreg_output)

        # Check cycle count
        cycle_count = ioreg_info.get("cycle_count")
        if cycle_count is not None and cycle_count > 1000:
            findings.append(
                Finding(
                    title=f"High battery cycle count ({cycle_count})",
                    description=(
                        f"Battery cycle count is {cycle_count}, exceeding Apple's "
                        "rated limit of ~1000 cycles. Battery capacity will degrade "
                        "over time. Consider battery service if capacity is low."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "cycle_count", "cycle_count": cycle_count},
                )
            )

        # Check battery condition
        condition = battery_info.get("condition", "Unknown").strip()
        if condition in ("Replace Soon", "Replace Now", "Service Battery"):
            severity = Severity.CRITICAL if condition == "Replace Now" else Severity.WARNING
            findings.append(
                Finding(
                    title=f"Battery condition: {condition}",
                    description=(
                        f"System reports battery condition as '{condition}'. "
                        "Battery service or replacement may be needed."
                    ),
                    severity=severity,
                    category=self.category,
                    data={"check": "battery_condition", "condition": condition},
                )
            )

        # Check maximum capacity percentage
        design_capacity = ioreg_info.get("design_capacity")
        max_capacity = ioreg_info.get("max_capacity")
        if design_capacity and max_capacity and design_capacity > 0:
            capacity_percent = (max_capacity / design_capacity) * 100
            if capacity_percent < 80:
                findings.append(
                    Finding(
                        title=f"Battery capacity degraded ({capacity_percent:.1f}%)",
                        description=(
                            f"Battery maximum capacity is {capacity_percent:.1f}% of "
                            "design capacity. This is normal aging; if it falls below "
                            "50%, service is recommended."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={
                            "check": "capacity_percent",
                            "capacity_percent": capacity_percent,
                            "max_capacity": max_capacity,
                            "design_capacity": design_capacity,
                        },
                    )
                )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        for finding in findings.findings:
            check = finding.data.get("check")

            if check == "no_battery":
                actions.append(
                    Action(
                        title="No battery to service",
                        description=(
                            "This device is a desktop Mac and does not have a battery. "
                            "No action needed."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "cycle_count":
                actions.append(
                    Action(
                        title="Battery cycle count guidance",
                        description=(
                            "High cycle count indicates the battery has aged past Apple's "
                            "rated lifespan. If your device shuts down unexpectedly, or if "
                            "capacity is below 50%, visit an Apple Authorized Service Provider "
                            "for battery replacement. Battery health can be checked in System "
                            "Settings > General > About > System Report > Battery."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "battery_condition":
                condition = finding.data.get("condition")
                actions.append(
                    Action(
                        title="Battery service guidance",
                        description=(
                            f"System reports battery condition as '{condition}'. "
                            "Visit an Apple Authorized Service Provider to arrange battery "
                            "replacement. Do not continue using the device if it suddenly "
                            "loses power or shuts down without warning."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "capacity_percent":
                capacity = finding.data.get("capacity_percent")
                actions.append(
                    Action(
                        title="Battery capacity degradation guidance",
                        description=(
                            f"Battery capacity has degraded to {capacity:.1f}% of design capacity. "
                            "Degradation of 10-20% is normal for a 2-3 year old battery. When capacity "
                            "drops below 50%, consider battery service. For now, you can calibrate the "
                            "battery by: (1) fully charging to 100%, (2) using it until it shuts down, "
                            "(3) waiting 5+ hours, (4) charging without interruption to 100%."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _run_ioreg(self) -> str:
        """Run ioreg -l and return output."""
        try:
            result = subprocess.run(
                ["ioreg", "-l"],
                capture_output=True,
                text=True,
            )
            return result.stdout
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


def _parse_ioreg(output: str) -> dict:
    """Extract battery info from ioreg -l output."""
    info = {}

    # Look for CycleCount
    cycle_match = re.search(r'"CycleCount"\s*=\s*(\d+)', output)
    if cycle_match:
        info["cycle_count"] = int(cycle_match.group(1))

    # Look for DesignCapacity
    design_match = re.search(r'"DesignCapacity"\s*=\s*(\d+)', output)
    if design_match:
        info["design_capacity"] = int(design_match.group(1))

    # Look for MaxCapacity
    max_match = re.search(r'"MaxCapacity"\s*=\s*(\d+)', output)
    if max_match:
        info["max_capacity"] = int(max_match.group(1))

    return info


def _parse_system_profiler(output: str) -> dict:
    """Extract battery info from system_profiler SPPowerDataType output."""
    info = {}

    # Check if battery is installed
    if "Battery Installed: No" in output:
        info["battery_installed"] = False
    elif "Battery Installed: Yes" in output:
        info["battery_installed"] = True
    else:
        # Default to checking for battery info section
        info["battery_installed"] = "Condition:" in output

    # Look for Condition
    condition_match = re.search(r"Condition:\s*(.+?)(?:\n|$)", output)
    if condition_match:
        info["condition"] = condition_match.group(1).strip()

    return info
