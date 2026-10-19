import re
import subprocess
from datetime import datetime

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
    name = "time_sync_check"
    category = "integrity"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "5s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Check NTP enabled status
        ntp_enabled = self._check_ntp_enabled()
        if ntp_enabled is False:
            findings.append(
                Finding(
                    title="Your Mac is not syncing its clock automatically",
                    description=(
                        "Your Mac is not using Network Time Protocol (NTP) to keep its "
                        "clock accurate. If the clock drifts, websites may show security "
                        "warnings because they can't check their certificates.\n\n"
                        "What to do: Open System Settings, click General, then Date & "
                        "Time. Make sure 'Set time and date automatically' is turned on."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "ntp_enabled", "enabled": False},
                )
            )

        elif ntp_enabled is None:
            findings.append(
                Finding(
                    title="Couldn't check whether your clock sets itself",
                    description=(
                        "Reading the 'Set time and date automatically' setting needs "
                        "administrator access, so Reclaim City couldn't check it. This "
                        "is not a sign that anything is wrong. To see for yourself, open "
                        "System Settings > General > Date & Time."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "ntp_unknown", "enabled": None},
                )
            )

        # Check NTP server
        ntp_server = self._get_ntp_server()
        if ntp_server is not None:
            findings.append(
                Finding(
                    title="Your time server setting",
                    description=f"Network time server: {ntp_server}",
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "ntp_server", "server": ntp_server},
                )
            )

        # Check timezone auto setting
        timezone_auto = self._check_timezone_auto()
        if timezone_auto is False:
            findings.append(
                Finding(
                    title="Automatic timezone setting is off",
                    description="System is not set to automatically detect timezone.",
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "timezone_auto", "auto": False},
                )
            )

        # Report current system time (informational)
        current_time = self._get_current_time()
        if current_time is not None:
            findings.append(
                Finding(
                    title="Your current system time",
                    description=f"System time: {current_time}",
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "current_time", "time": current_time},
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            check = finding.data.get("check")
            if check == "ntp_enabled":
                actions.append(
                    Action(
                        title="Enable Network Time Protocol",
                        description=(
                            "To enable NTP, open System Settings > General > Date & Time, "
                            "then enable 'Set date and time automatically'. "
                            "Alternatively, run: sudo systemsetup -setusingnetworktime on"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
        return FixResult(module_name=self.name, actions=actions)

    def _check_ntp_enabled(self) -> bool | None:
        """Check if NTP is enabled. Returns True/False or None if unable to determine."""
        try:
            result = subprocess.run(
                ["systemsetup", "-getusingnetworktime"],
                capture_output=True,
                text=True,
            )
            output = result.stdout.strip() if isinstance(result.stdout, str) else ""
        except (OSError, subprocess.SubprocessError):
            return None
        # "Network Time: On" / "Network Time: Off". Without admin rights
        # systemsetup prints "You need administrator access to run this
        # tool... exiting!" instead, which used to read as "off".
        match = re.search(r"Network Time:\s*(On|Off)\b", output)
        if not match:
            return None
        return match.group(1) == "On"

    def _get_ntp_server(self) -> str | None:
        """Get configured NTP server."""
        try:
            result = subprocess.run(
                ["systemsetup", "-getnetworktimeserver"],
                capture_output=True,
                text=True,
            )
            output = result.stdout.strip()
            if output and "Network time server:" in output:
                return output.split("Network time server:", 1)[1].strip()
        except (OSError, subprocess.SubprocessError):
            pass
        return None

    def _check_timezone_auto(self) -> bool | None:
        """Check if automatic timezone detection is enabled."""
        try:
            result = subprocess.run(
                ["defaults", "read", "/Library/Preferences/com.apple.timezone.auto", "Active"],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0 or not isinstance(result.stdout, str):
                return None  # key absent (never changed) or unreadable
            output = result.stdout.strip()
            if output in ("0", "1"):
                return output == "1"
            return None
        except (OSError, subprocess.SubprocessError):
            return None

    def _get_current_time(self) -> str | None:
        """Get current system time."""
        try:
            result = subprocess.run(
                ["date"],
                capture_output=True,
                text=True,
            )
            return result.stdout.strip()
        except (OSError, subprocess.SubprocessError):
            return None
