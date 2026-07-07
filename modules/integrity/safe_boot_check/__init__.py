import subprocess
from datetime import datetime, timedelta

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
    name = "safe_boot_check"
    category = "integrity"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "5s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Check if booted in Safe Mode
        safe_mode = self._check_safe_mode()
        if safe_mode is True:
            findings.append(
                Finding(
                    title="System booted in Safe Mode",
                    description="Mac is currently running in Safe Mode. This is a common troubleshooting step that disables third-party extensions and background processes.",
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "safe_mode", "enabled": True},
                )
            )

        # Check boot volume
        boot_volume = self._get_boot_volume()
        if boot_volume is not None:
            findings.append(
                Finding(
                    title="Boot volume information",
                    description=f"System booted from: {boot_volume}",
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "boot_volume", "volume": boot_volume},
                )
            )

        # Check verbose boot
        verbose_boot = self._check_verbose_boot()
        if verbose_boot is True:
            findings.append(
                Finding(
                    title="Verbose boot enabled",
                    description="Verbose boot mode is enabled. The system displays detailed boot messages.",
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "verbose_boot", "enabled": True},
                )
            )

        # Check boot time and uptime
        boot_time = self._get_boot_time()
        if boot_time is not None:
            uptime = datetime.now() - boot_time
            uptime_days = uptime.days

            # Flag WARNING if uptime exceeds 30 days
            if uptime_days > 30:
                findings.append(
                    Finding(
                        title="System has not been restarted in over 30 days",
                        description=f"Uptime: {uptime_days} days. Long uptime may indicate pending system updates or accumulated memory issues.",
                        severity=Severity.WARNING,
                        category=self.category,
                        data={"check": "uptime_exceeds_30days", "uptime_days": uptime_days},
                    )
                )
            else:
                findings.append(
                    Finding(
                        title="System uptime",
                        description=f"Last boot: {boot_time.strftime('%Y-%m-%d %H:%M:%S')} ({uptime_days} days {uptime.seconds // 3600} hours ago)",
                        severity=Severity.INFO,
                        category=self.category,
                        data={"check": "uptime", "uptime_days": uptime_days, "boot_time": boot_time.isoformat()},
                    )
                )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            check = finding.data.get("check")
            if check == "safe_mode":
                actions.append(
                    Action(
                        title="Exit Safe Mode",
                        description=(
                            "To exit Safe Mode, restart your Mac normally. "
                            "Safe Mode disables third-party extensions and loads only essential system software. "
                            "If you were troubleshooting a specific issue, consider what caused you to enter Safe Mode and whether to reinstall problematic software."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif check == "uptime_exceeds_30days":
                actions.append(
                    Action(
                        title="Consider restarting your Mac",
                        description=(
                            "Your system has not been restarted in over 30 days. "
                            "Consider restarting your Mac to apply pending updates and clear accumulated memory. "
                            "To restart, go to Apple menu > Restart or press Control-Power (or Control-Touch ID) and select Restart."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
        return FixResult(module_name=self.name, actions=actions)

    def _check_safe_mode(self) -> bool | None:
        """Check if system is booted in Safe Mode."""
        # Check sysctl kern.safeboot (returns 1 if in safe mode)
        try:
            result = subprocess.run(
                ["sysctl", "kern.safeboot"],
                capture_output=True,
                text=True,
            )
            output = result.stdout.strip()
            if "kern.safeboot:" in output:
                value = output.split(":", 1)[1].strip()
                return value == "1"
        except (OSError, subprocess.SubprocessError):
            pass

        # Fallback: check nvram boot-args for "-x" flag
        try:
            result = subprocess.run(
                ["nvram", "boot-args"],
                capture_output=True,
                text=True,
            )
            output = result.stdout.strip()
            return "-x" in output
        except (OSError, subprocess.SubprocessError):
            return None

    def _get_boot_volume(self) -> str | None:
        """Get boot volume information."""
        try:
            result = subprocess.run(
                ["bless", "--info", "--getBoot"],
                capture_output=True,
                text=True,
            )
            output = result.stdout.strip()
            if output:
                return output
        except (OSError, subprocess.SubprocessError):
            pass
        return None

    def _check_verbose_boot(self) -> bool | None:
        """Check if verbose boot is enabled."""
        try:
            result = subprocess.run(
                ["nvram", "boot-args"],
                capture_output=True,
                text=True,
            )
            output = result.stdout.strip()
            return "-v" in output
        except (OSError, subprocess.SubprocessError):
            return None

    def _get_boot_time(self) -> datetime | None:
        """Get system boot time from kern.boottime."""
        try:
            result = subprocess.run(
                ["sysctl", "kern.boottime"],
                capture_output=True,
                text=True,
            )
            output = result.stdout.strip()
            # Output format: kern.boottime: { sec = 1688067234, usec = 123456 } Wed Jun 28 14:00:34 2023
            if "sec =" in output:
                # Extract the sec value
                parts = output.split("sec =")
                if len(parts) > 1:
                    sec_str = parts[1].split(",")[0].strip()
                    try:
                        boot_timestamp = int(sec_str)
                        return datetime.fromtimestamp(boot_timestamp)
                    except (ValueError, OSError):
                        pass
        except (OSError, subprocess.SubprocessError):
            pass
        return None
