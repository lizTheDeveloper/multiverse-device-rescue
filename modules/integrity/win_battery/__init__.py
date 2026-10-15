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
    name = "win_battery"
    category = "integrity"
    platforms = [Platform.WIN32]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "5s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Get battery info from WMI
        battery_info = self._get_battery_info()

        # Check if battery is installed
        if not battery_info:
            findings.append(
                Finding(
                    title="No battery detected",
                    description=(
                        "This device does not have a battery (e.g., a desktop PC). "
                        "Battery health checks do not apply."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "no_battery"},
                )
            )
            return CheckResult(module_name=self.name, findings=findings)

        # Check battery capacity percentage
        design_capacity = battery_info.get("design_capacity")
        full_charge_capacity = battery_info.get("full_charge_capacity")

        if design_capacity and full_charge_capacity and design_capacity > 0:
            capacity_percent = (full_charge_capacity / design_capacity) * 100

            # Flag CRITICAL if capacity is below 50%
            if capacity_percent < 50:
                findings.append(
                    Finding(
                        title=(
                            f"Your battery holds much less charge than when new ({capacity_percent:.1f}%)"
                        ),
                        description=(
                            f"Your battery can currently hold {capacity_percent:.1f}% "
                            "of its original capacity. This is a significant drop, meaning "
                            "your computer will run out of power much faster than it "
                            "used to.\n\n"
                            "What to do: Consider having the battery replaced by a professional "
                            "to restore your battery life."
                        ),
                        severity=Severity.CRITICAL,
                        category=self.category,
                        data={
                            "check": "capacity_critical",
                            "capacity_percent": capacity_percent,
                            "full_charge_capacity": full_charge_capacity,
                            "design_capacity": design_capacity,
                        },
                    )
                )
            # Flag WARNING if capacity is below 80%
            elif capacity_percent < 80:
                findings.append(
                    Finding(
                        title=f"Your battery is aging ({capacity_percent:.1f}% capacity)",
                        description=(
                            f"Your battery currently holds {capacity_percent:.1f}% of "
                            "its original capacity. It just means the battery will last "
                            "a bit shorter than it did when new.\n\n"
                            "What to do: Nothing right now. Keep an eye on it, but no "
                            "action is needed unless it drops below 50%."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={
                            "check": "capacity_warning",
                            "capacity_percent": capacity_percent,
                            "full_charge_capacity": full_charge_capacity,
                            "design_capacity": design_capacity,
                        },
                    )
                )

        # Check battery status
        battery_status = battery_info.get("battery_status")
        if battery_status is not None and battery_status not in (1, 2):
            # Status 1 = Discharging, 2 = AC power
            # Other values indicate charging issues
            findings.append(
                Finding(
                    title="Your battery is not charging as expected",
                    description=(
                        f"Your battery status is currently {_get_battery_status_text(battery_status)}. "
                        "This usually means the power adapter is not connected properly "
                        "or the battery needs attention.\n\n"
                        "What to do: Unplug and replug your power adapter to ensure it "
                        "is secure. If it still does not charge, try restarting your "
                        "computer."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "check": "battery_status",
                        "battery_status": battery_status,
                        "status_text": _get_battery_status_text(battery_status),
                    },
                )
            )

        # Add informational finding if battery is healthy
        if not findings:
            findings.append(
                Finding(
                    title="Battery healthy",
                    description=(
                        f"Battery is in good condition. "
                        f"Current capacity: {capacity_percent:.1f}% of design capacity."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "check": "battery_healthy",
                        "capacity_percent": capacity_percent,
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
                            "This device is a desktop PC and does not have a battery. "
                            "No action needed."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "capacity_critical":
                capacity = finding.data.get("capacity_percent")
                actions.append(
                    Action(
                        title="Battery replacement recommended",
                        description=(
                            f"Battery capacity has degraded to {capacity:.1f}%. "
                            "Contact a qualified technician or your device manufacturer "
                            "for battery replacement. Do not rely on the battery for "
                            "critical work."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "capacity_warning":
                capacity = finding.data.get("capacity_percent")
                actions.append(
                    Action(
                        title="Battery capacity degradation guidance",
                        description=(
                            f"Battery capacity has degraded to {capacity:.1f}% of design capacity. "
                            "Degradation of 10-20% is normal for a 2-3 year old battery. "
                            "When capacity drops below 50%, consider battery service."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "battery_status":
                status_text = finding.data.get("status_text")
                actions.append(
                    Action(
                        title="Battery charging issue",
                        description=(
                            f"Battery status is {status_text}. "
                            "Check that the power adapter is properly connected and functioning. "
                            "If the battery does not charge, consider battery service or "
                            "power adapter replacement."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "battery_healthy":
                actions.append(
                    Action(
                        title="Battery is healthy",
                        description=(
                            "Battery is functioning normally. Continue with regular use and "
                            "monitor battery health over time."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _get_battery_info(self) -> Optional[dict]:
        """Get battery information from WMI."""
        try:
            # PowerShell command to get battery info in JSON format
            ps_cmd = (
                "Get-WmiObject Win32_Battery | Select-Object BatteryStatus, "
                "DesignCapacity, FullChargeCapacity, EstimatedChargeRemaining | "
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

            return _parse_battery_info(result.stdout)
        except (OSError, subprocess.SubprocessError, TimeoutError):
            return None


def _parse_battery_info(json_output: str) -> Optional[dict]:
    """Parse PowerShell JSON output from Get-WmiObject Win32_Battery."""
    if not json_output.strip():
        return None

    try:
        data = json.loads(json_output)
        # Handle both single object and array
        if isinstance(data, list):
            if not data:
                return None
            data = data[0]

        # Extract battery info
        info = {
            "battery_status": data.get("BatteryStatus"),
            "design_capacity": data.get("DesignCapacity"),
            "full_charge_capacity": data.get("FullChargeCapacity"),
            "estimated_charge": data.get("EstimatedChargeRemaining"),
        }

        return info if any(info.values()) else None
    except (json.JSONDecodeError, ValueError, KeyError, TypeError):
        return None


def _get_battery_status_text(status_code: int) -> str:
    """Convert battery status code to human-readable text."""
    status_map = {
        1: "Discharging",
        2: "AC Power",
        3: "Charging",
        4: "Charging (High)",
        5: "Charging (Low)",
    }
    return status_map.get(status_code, f"Unknown ({status_code})")
