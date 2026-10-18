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
                    title=f"Your battery has been charged {cycle_count} times",
                    description=(
                        f"Your battery has gone through {cycle_count} full charge cycles. "
                        "Apple designs Mac batteries to last about 1,000 cycles before "
                        "they start losing power faster.\n\n"
                        "It just means your battery is getting older and may not hold "
                        "a charge as long as it used to.\n\n"
                        "What to do: Nothing needs to be done right now. If you notice "
                        "your Mac dying much faster than before, you can check the battery "
                        "health in System Settings > Battery, or visit an Apple Store "
                        "for a replacement."
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
                    title=f"Your battery needs attention ({condition})",
                    description=(
                        f"Your Mac's system reports the battery condition as '{condition}'. "
                        "It means the battery is aging and may not perform as well as "
                        "it did when new.\n\n"
                        "What to do: You can check the details in System Settings > Battery. "
                        "If the battery is draining quickly or shutting down unexpectedly, "
                        "consider having it serviced by Apple."
                    ),
                    severity=severity,
                    category=self.category,
                    data={"check": "battery_condition", "condition": condition},
                )
            )

        # Check maximum capacity percentage
        design_capacity = ioreg_info.get("design_capacity")
        max_capacity = ioreg_info.get("max_capacity")
        capacity_percent = _capacity_percent(battery_info, ioreg_info)
        if capacity_percent is not None:
            if capacity_percent < 80:
                findings.append(
                    Finding(
                        title=(
                            f"Your battery holds {capacity_percent:.1f}% of its original power"
                        ),
                        description=(
                            f"Your battery can currently hold {capacity_percent:.1f}% "
                            "of the power it had when it was new. Batteries naturally "
                            "lose some capacity over time.\n\n"
                            "What to do: Nothing needs to be done unless you are frustrated "
                            "with how quickly your Mac runs out of power. If it is a "
                            "major issue, you can replace the battery at an Apple Store."
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
                errors="replace",
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

    # Apple silicon Macs report MaxCapacity as a percentage (100) and keep the
    # real full-charge capacity in mAh in AppleRawMaxCapacity.
    raw_match = re.search(r'"AppleRawMaxCapacity"\s*=\s*(\d+)', output)
    if raw_match:
        info["raw_max_capacity"] = int(raw_match.group(1))

    return info


def _capacity_percent(battery_info: dict, ioreg_info: dict) -> float | None:
    """How much of its design capacity the battery still holds, or None.

    Prefers macOS's own figure (system_profiler's "Maximum Capacity: 85%",
    the number System Settings shows). On Apple silicon ioreg's MaxCapacity is
    already a percentage, so dividing it by DesignCapacity (mAh) reported a
    healthy 85% battery as 1.6%.
    """
    reported = battery_info.get("max_capacity_percent")
    if reported is not None:
        return float(reported)
    design = ioreg_info.get("design_capacity")
    if not design or design <= 0:
        return None
    raw = ioreg_info.get("raw_max_capacity")
    if raw:
        return raw / design * 100
    max_capacity = ioreg_info.get("max_capacity")
    if not max_capacity:
        return None
    if max_capacity <= 100 < design:
        return float(max_capacity)  # already a percentage
    return max_capacity / design * 100


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

    capacity_match = re.search(r"Maximum Capacity:\s*(\d+)\s*%", output)
    if capacity_match:
        info["max_capacity_percent"] = int(capacity_match.group(1))

    return info
