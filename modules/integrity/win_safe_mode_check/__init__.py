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
    name = "win_safe_mode_check"
    category = "integrity"
    platforms = [Platform.WIN32]
    risk_level = RiskLevel.SAFE
    priority = 65
    depends_on = []
    estimated_duration = "10s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Check current boot mode via bcdedit
        current_safeboot = self._check_current_safeboot()
        if current_safeboot:
            findings.append(
                Finding(
                    title=f"System currently running in Safe Mode ({current_safeboot})",
                    description=(
                        f"Windows is currently running in Safe Mode ({current_safeboot}). "
                        "This mode has limited functionality and driver support. "
                        "System booted with reduced drivers and services for troubleshooting."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "current_safeboot", "mode": current_safeboot},
                )
            )

        # Check if Safe Mode is set as default boot
        safeboot_default = self._check_safeboot_default()
        if safeboot_default:
            findings.append(
                Finding(
                    title="Safe Mode is set as default boot configuration",
                    description=(
                        "The boot configuration is set to use Safe Mode by default. "
                        "This is a common issue when users boot into Safe Mode for troubleshooting "
                        "and forget to change it back to normal boot. "
                        "System will continue to boot in Safe Mode until configuration is changed."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "safeboot_default"},
                )
            )

        # Check system uptime
        uptime_info = self._get_uptime()
        if uptime_info:
            days = uptime_info.get("days", 0)
            uptime_str = uptime_info.get("uptime_str", "unknown")

            if days > 30:
                findings.append(
                    Finding(
                        title=f"System uptime exceeds 30 days ({uptime_str})",
                        description=(
                            f"System has been running for {uptime_str} without restart. "
                            "Long uptime may prevent critical Windows updates from being applied. "
                            "Regular restarts are recommended to ensure security patches are installed."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={"check": "high_uptime", "days": days, "uptime_str": uptime_str},
                    )
                )

        # Add INFO finding with boot status summary
        if not findings:
            # System is running normally
            uptime_str = uptime_info.get("uptime_str", "unknown") if uptime_info else "unknown"
            findings.append(
                Finding(
                    title="System booting normally",
                    description=(
                        f"System is running in normal boot mode (not Safe Mode). "
                        f"Current uptime: {uptime_str}. "
                        "No boot configuration issues detected."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "boot_normal"},
                )
            )
        else:
            # Add boot status info even if issues exist
            uptime_str = uptime_info.get("uptime_str", "unknown") if uptime_info else "unknown"
            findings.append(
                Finding(
                    title=f"Boot status info - Uptime: {uptime_str}",
                    description=(
                        f"Current system uptime: {uptime_str}. "
                        "Review warnings above for boot configuration issues."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "uptime_info", "uptime_str": uptime_str},
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        for finding in findings.findings:
            check = finding.data.get("check")

            if check == "current_safeboot":
                safeboot_mode = finding.data.get("mode", "unknown")
                actions.append(
                    Action(
                        title=f"System running in Safe Mode ({safeboot_mode})",
                        description=(
                            f"System is currently running in {safeboot_mode} Safe Mode. "
                            "To boot normally: "
                            "(1) Open System Configuration (msconfig): Press Windows+R, type 'msconfig', press Enter. "
                            "(2) Go to Boot tab. "
                            "(3) Uncheck 'Safe boot' option. "
                            "(4) Click OK and restart the system. "
                            "If you need to stay in Safe Mode for troubleshooting, ensure you disable it "
                            "after completing your diagnostics."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "safeboot_default":
                actions.append(
                    Action(
                        title="Safe Mode is default boot option",
                        description=(
                            "Safe Mode is set as the default boot configuration. "
                            "This should be changed back to normal boot. "
                            "To fix: "
                            "(1) Open Command Prompt as Administrator. "
                            "(2) Run: bcdedit /deletevalue {current} safeboot "
                            "(3) Restart the system. "
                            "Alternatively, use System Configuration (msconfig) > Boot tab "
                            "and uncheck the 'Safe boot' option."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "high_uptime":
                days = finding.data.get("days", 0)
                actions.append(
                    Action(
                        title=f"System needs restart (uptime: {days} days)",
                        description=(
                            f"System uptime is {days} days, which may prevent Windows updates from being applied. "
                            "Recommended actions: "
                            "(1) Save all open work and close applications. "
                            "(2) Restart the system to allow pending updates to install. "
                            "(3) Check Windows Update (Settings > Update & Security > Windows Update) "
                            "after restart to ensure all updates are current. "
                            "Regular restarts are important for security and system stability."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "boot_normal":
                actions.append(
                    Action(
                        title="System booting normally",
                        description=(
                            "System is running in normal boot mode. "
                            "All drivers and services are loaded normally. "
                            "Continue regular system maintenance and updates."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "uptime_info":
                uptime_str = finding.data.get("uptime_str", "unknown")
                actions.append(
                    Action(
                        title=f"System uptime: {uptime_str}",
                        description=(
                            f"Current uptime: {uptime_str}. "
                            "Consider reviewing boot configuration warnings above."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _check_current_safeboot(self) -> Optional[str]:
        """Check if system is currently running in Safe Mode via bcdedit."""
        try:
            result = subprocess.run(
                ["bcdedit", "/enum", "{current}"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode != 0:
                return None

            output = result.stdout.lower()

            # Check for safeboot options
            if "safeboot" in output:
                if "safeboot" in output:
                    # Determine which Safe Mode variant
                    if "minimal" in output:
                        return "Minimal"
                    elif "network" in output:
                        return "Network"
                    elif "dsrepair" in output:
                        return "Directory Services Repair"
                    else:
                        return "Standard"

            return None
        except (OSError, subprocess.SubprocessError, TimeoutError):
            return None

    def _check_safeboot_default(self) -> bool:
        """Check if Safe Mode is set as default boot option via bcdedit."""
        try:
            # Check boot options in BCD
            result = subprocess.run(
                ["bcdedit", "/enum", "bootmgr"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode != 0:
                return False

            output = result.stdout.lower()

            # Look for default boot with safeboot option
            if "safeboot" in output:
                return True

            return False
        except (OSError, subprocess.SubprocessError, TimeoutError):
            return False

    def _get_uptime(self) -> Optional[dict]:
        """Get system uptime information via PowerShell."""
        try:
            ps_cmd = (
                "Get-CimInstance Win32_OperatingSystem | "
                "Select-Object LastBootUpTime | ConvertTo-Json"
            )
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                return None

            data = json.loads(result.stdout)
            last_boot = data.get("LastBootUpTime")

            if not last_boot:
                return None

            # Parse the datetime string (format: YYYY-MM-DDTHH:MM:SS)
            # Calculate uptime
            from datetime import datetime
            boot_time = datetime.fromisoformat(last_boot)
            now = datetime.now()
            uptime = now - boot_time

            days = uptime.days
            hours = (uptime.seconds // 3600) % 24
            minutes = (uptime.seconds // 60) % 60

            uptime_str = f"{days}d {hours}h {minutes}m"

            return {
                "days": days,
                "hours": hours,
                "minutes": minutes,
                "uptime_str": uptime_str,
                "last_boot_time": last_boot,
            }
        except (OSError, subprocess.SubprocessError, TimeoutError, json.JSONDecodeError, ValueError):
            return None
