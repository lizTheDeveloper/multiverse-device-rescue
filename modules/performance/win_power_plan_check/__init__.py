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
    name = "win_power_plan_check"
    category = "performance"
    platforms = [Platform.WIN32]
    risk_level = RiskLevel.SAFE
    priority = 65
    depends_on = []
    estimated_duration = "3s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Get active power plan
        active_scheme = self._get_active_scheme()
        active_plan_name = _parse_active_scheme(active_scheme) if active_scheme else None

        if active_plan_name:
            # Report active plan as INFO
            findings.append(
                Finding(
                    title=f"Active power plan: {active_plan_name}",
                    description=f"System is using '{active_plan_name}' power plan.",
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "type": "active_plan",
                        "plan_name": active_plan_name,
                    },
                )
            )

            # Check if Power Saver is active (WARNING on desktop)
            if "Power Saver" in active_plan_name:
                findings.append(
                    Finding(
                        title="Power Saver plan active",
                        description=(
                            "Power Saver mode restricts CPU and memory speeds to reduce power consumption. "
                            "This can cause noticeable performance degradation. Consider switching to "
                            "Balanced or High Performance mode."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={
                            "type": "power_saver_active",
                            "plan_name": active_plan_name,
                        },
                    )
                )

        # Check processor throttling settings
        proc_max = self._get_processor_max_state()
        if proc_max is not None:
            findings.append(
                Finding(
                    title=f"Processor max state: {proc_max}%",
                    description=f"Maximum processor state is set to {proc_max}%.",
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "type": "processor_max",
                        "value": proc_max,
                    },
                )
            )

            # Warning if processor is artificially limited
            if proc_max < 100:
                findings.append(
                    Finding(
                        title="Processor artificially limited",
                        description=(
                            f"Maximum processor state is set to {proc_max}%, which artificially limits "
                            "CPU performance. This can cause slowdowns. Set maximum processor state to 100% "
                            "for full performance."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={
                            "type": "processor_limited",
                            "max_state": proc_max,
                        },
                    )
                )

        # Check hard disk timeout
        disk_timeout = self._get_disk_idle_timeout()
        if disk_timeout is not None:
            timeout_seconds = disk_timeout
            timeout_minutes = timeout_seconds // 60 if timeout_seconds > 0 else 0

            if timeout_seconds == 0:
                description = "Hard disk is set to never turn off."
                severity = Severity.INFO
            else:
                description = f"Hard disk is set to turn off after {timeout_minutes} minutes ({timeout_seconds} seconds)."
                severity = Severity.INFO

            findings.append(
                Finding(
                    title=f"Hard disk idle timeout: {timeout_minutes} min",
                    description=description,
                    severity=severity,
                    category=self.category,
                    data={
                        "type": "disk_timeout",
                        "seconds": timeout_seconds,
                        "minutes": timeout_minutes,
                    },
                )
            )

            # Warning if timeout is very short
            if 0 < timeout_seconds < 300:  # Less than 5 minutes
                findings.append(
                    Finding(
                        title="Hard disk timeout too short",
                        description=(
                            f"Hard disk is set to turn off after only {timeout_minutes} minute(s). "
                            "This can cause disk I/O lag when the disk needs to spin back up. "
                            "Consider increasing to at least 5-10 minutes."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={
                            "type": "disk_timeout_short",
                            "seconds": timeout_seconds,
                        },
                    )
                )

        # Check sleep settings
        sleep_timeout = self._get_sleep_idle_timeout()
        if sleep_timeout is not None:
            if sleep_timeout == 0:
                sleep_desc = "System is set to never enter sleep mode."
            else:
                sleep_minutes = sleep_timeout // 60 if sleep_timeout > 0 else 0
                sleep_desc = (
                    f"System is set to enter sleep mode after {sleep_minutes} minute(s) "
                    f"({sleep_timeout} seconds) of inactivity."
                )

            findings.append(
                Finding(
                    title=f"Sleep timeout: {sleep_timeout // 60 if sleep_timeout > 0 else 0} min",
                    description=sleep_desc,
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "type": "sleep_timeout",
                        "seconds": sleep_timeout,
                    },
                )
            )

        # Check USB selective suspend
        usb_suspend = self._get_usb_selective_suspend()
        if usb_suspend is not None:
            if usb_suspend:
                usb_desc = (
                    "USB Selective Suspend is enabled. This allows the system to power down USB devices "
                    "to save power, but may cause intermittent connectivity issues with USB devices."
                )
                severity = Severity.INFO
            else:
                usb_desc = (
                    "USB Selective Suspend is disabled. All USB devices remain powered, "
                    "which may consume more power but ensures consistent connectivity."
                )
                severity = Severity.INFO

            findings.append(
                Finding(
                    title=f"USB Selective Suspend: {'enabled' if usb_suspend else 'disabled'}",
                    description=usb_desc,
                    severity=severity,
                    category=self.category,
                    data={
                        "type": "usb_selective_suspend",
                        "enabled": usb_suspend,
                    },
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        """
        Provide informational actions about power settings.
        This is a diagnostic tool - it reports settings and suggests adjustments
        but does NOT modify settings automatically.
        """
        actions = []

        for finding in findings.findings:
            finding_type = finding.data.get("type")

            if finding_type == "power_saver_active":
                actions.append(
                    Action(
                        title="Switch from Power Saver mode",
                        description=(
                            "Power Saver mode restricts performance to save power. "
                            "To switch to Balanced or High Performance mode:\n"
                            "1. Windows 10: Settings > System > Power & sleep > Power mode\n"
                            "2. Windows 11: Settings > System > Power & battery > Power mode\n"
                            "3. Or use Control Panel > Power Options > Choose a power plan"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif finding_type == "processor_limited":
                actions.append(
                    Action(
                        title="Increase maximum processor state to 100%",
                        description=(
                            "To restore full CPU performance:\n"
                            "1. Go to Control Panel > Power Options\n"
                            "2. Click 'Change plan settings' for your current plan\n"
                            "3. Click 'Change advanced power settings'\n"
                            "4. Expand 'Processor power management'\n"
                            "5. Expand 'Maximum processor state'\n"
                            "6. Set both 'On battery' and 'Plugged in' to 100%"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif finding_type == "disk_timeout_short":
                actions.append(
                    Action(
                        title="Increase hard disk idle timeout",
                        description=(
                            "Short disk timeouts can cause lag when the disk spins back up. "
                            "To adjust:\n"
                            "1. Go to Control Panel > Power Options\n"
                            "2. Click 'Change plan settings' for your current plan\n"
                            "3. Click 'Change advanced power settings'\n"
                            "4. Expand 'Hard disk'\n"
                            "5. Expand 'Turn off hard disk after'\n"
                            "6. Set to 10 minutes or longer (or 0 to disable)"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif finding_type == "active_plan":
                actions.append(
                    Action(
                        title=f"Current power plan: {finding.data.get('plan_name')}",
                        description=(
                            "Monitor system performance and power consumption. "
                            "Adjust power settings as needed for your use case."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif finding_type == "processor_max":
                actions.append(
                    Action(
                        title=f"Processor max state at {finding.data.get('value')}%",
                        description="Current processor maximum state setting.",
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif finding_type == "disk_timeout":
                timeout_sec = finding.data.get("seconds", 0)
                if timeout_sec == 0:
                    desc = "Hard disk will not automatically turn off."
                else:
                    desc = f"Hard disk idle timeout is set to {timeout_sec} seconds."
                actions.append(
                    Action(
                        title="Hard disk idle setting",
                        description=desc,
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif finding_type == "sleep_timeout":
                actions.append(
                    Action(
                        title="Sleep timeout setting",
                        description=(
                            f"Sleep timeout is set to {finding.data.get('seconds')} seconds. "
                            "Adjust in Control Panel > Power Options > Change plan settings > "
                            "Change advanced power settings > Sleep"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif finding_type == "usb_selective_suspend":
                usb_status = "enabled" if finding.data.get("enabled") else "disabled"
                actions.append(
                    Action(
                        title=f"USB Selective Suspend is {usb_status}",
                        description=(
                            "To change this setting, go to Control Panel > Power Options > "
                            "Change plan settings > Change advanced power settings > "
                            "USB settings > USB selective suspend setting"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _get_active_scheme(self) -> str:
        """Get the active power scheme using powercfg /getactivescheme"""
        try:
            result = subprocess.run(
                ["powercfg", "/getactivescheme"],
                capture_output=True,
                text=True,
            )
            return result.stdout
        except (OSError, subprocess.SubprocessError):
            return ""

    def _get_processor_max_state(self) -> int | None:
        """Get maximum processor state as percentage"""
        try:
            result = subprocess.run(
                ["powercfg", "/query", "SCHEME_CURRENT", "SUB_PROCESSOR", "PROCTHROTTLEMAX"],
                capture_output=True,
                text=True,
            )
            # Parse output like "Current AC Power Setting Index: 0x64 (100)"
            match = re.search(r"0x[0-9a-fA-F]+\s+\((\d+)\)", result.stdout)
            if match:
                return int(match.group(1))
        except (OSError, subprocess.SubprocessError, ValueError):
            pass
        return None

    def _get_disk_idle_timeout(self) -> int | None:
        """Get hard disk idle timeout in seconds"""
        try:
            result = subprocess.run(
                ["powercfg", "/query", "SCHEME_CURRENT", "SUB_DISK", "DISKIDLE"],
                capture_output=True,
                text=True,
            )
            # Parse output like "Current AC Power Setting Index: 0x1e0 (480)"
            # Value is in seconds
            match = re.search(r"0x[0-9a-fA-F]+\s+\((\d+)\)", result.stdout)
            if match:
                return int(match.group(1))
        except (OSError, subprocess.SubprocessError, ValueError):
            pass
        return None

    def _get_sleep_idle_timeout(self) -> int | None:
        """Get sleep idle timeout in seconds"""
        try:
            result = subprocess.run(
                ["powercfg", "/query", "SCHEME_CURRENT", "SUB_SLEEP", "STANDBYIDLE"],
                capture_output=True,
                text=True,
            )
            # Parse output like "Current AC Power Setting Index: 0x708 (1800)"
            # Value is in seconds
            match = re.search(r"0x[0-9a-fA-F]+\s+\((\d+)\)", result.stdout)
            if match:
                return int(match.group(1))
        except (OSError, subprocess.SubprocessError, ValueError):
            pass
        return None

    def _get_usb_selective_suspend(self) -> bool | None:
        """Get USB selective suspend setting"""
        try:
            result = subprocess.run(
                [
                    "powercfg",
                    "/query",
                    "SCHEME_CURRENT",
                    "2a737441-1930-4402-8d77-b2bebba308a3",
                    "48e6b7a6-50f5-4782-a5d4-53bb8f07e226",
                ],
                capture_output=True,
                text=True,
            )
            # Parse output: 0 = disabled, 1 = enabled
            match = re.search(r"0x[0-9a-fA-F]+\s+\(([01])\)", result.stdout)
            if match:
                return int(match.group(1)) == 1
        except (OSError, subprocess.SubprocessError, ValueError):
            pass
        return None


def _parse_active_scheme(output: str) -> str | None:
    """Parse `powercfg /getactivescheme` output.

    Example::

        Power Scheme GUID : 381b4222-f694-41f0-9685-ff5bb260df2e (Balanced)
    """
    for line in output.splitlines():
        line = line.strip()
        if "Power Scheme GUID" in line and "(" in line and ")" in line:
            # Extract text between last parentheses
            start = line.rfind("(")
            end = line.rfind(")")
            if start != -1 and end != -1:
                return line[start + 1 : end]
    return None
