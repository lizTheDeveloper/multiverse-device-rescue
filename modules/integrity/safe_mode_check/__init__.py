import glob
import os
import re
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
    name = "safe_mode_check"
    category = "integrity"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "10s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Check if currently in Safe Mode via nvram
        in_safe_mode_nvram = self._check_safe_mode_nvram()

        # Check if currently in Safe Mode via sysctl
        in_safe_mode_sysctl = self._check_safe_mode_sysctl()

        # Get boot volume info
        boot_volume = self._get_boot_volume()

        # Get last boot time
        boot_time = self._get_boot_time()

        # Check for verbose boot flag
        verbose_boot = self._check_verbose_boot()

        # Get boot disk info
        disk_info = self._get_boot_disk_info()

        # Check for kernel panics
        panic_files = self._get_panic_files()
        recent_panics = self._count_recent_panics(panic_files, days=7)

        # Determine if in Safe Mode
        in_safe_mode = in_safe_mode_nvram or in_safe_mode_sysctl

        # Flag if in Safe Mode
        if in_safe_mode:
            findings.append(
                Finding(
                    title="Currently booted in Safe Mode",
                    description=(
                        "This Mac is currently running in Safe Mode. Safe Mode is a "
                        "diagnostic mode that disables third-party kernel extensions and "
                        "startup items. Something may have forced this boot mode, indicating "
                        "a potential system issue."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "safe_mode_enabled"},
                )
            )

        # Flag if multiple kernel panics detected
        if recent_panics > 1:
            findings.append(
                Finding(
                    title=f"Multiple kernel panics detected ({recent_panics} in last 7 days)",
                    description=(
                        f"Found {recent_panics} kernel panic log files in the last 7 days. "
                        "Multiple panics may indicate a hardware issue, faulty driver, or "
                        "serious software problem that needs investigation."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
                    data={"check": "multiple_panics", "count": recent_panics},
                )
            )

        # Add INFO finding with boot details
        findings.append(
            Finding(
                title="Boot mode and diagnostics",
                description=(
                    f"Boot mode: {'Safe Mode' if in_safe_mode else 'Normal'}. "
                    f"Boot volume: {boot_volume or 'Unknown'}. "
                    f"Boot time: {boot_time or 'Unknown'}. "
                    f"Verbose boot: {'Enabled' if verbose_boot else 'Disabled'}. "
                    f"Kernel panics (last 7 days): {recent_panics}."
                ),
                severity=Severity.INFO,
                category=self.category,
                data={
                    "check": "boot_diagnostics",
                    "in_safe_mode": in_safe_mode,
                    "boot_volume": boot_volume,
                    "boot_time": boot_time,
                    "verbose_boot": verbose_boot,
                    "panic_count": recent_panics,
                    "disk_filesystem": disk_info.get("filesystem"),
                },
            )
        )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        for finding in findings.findings:
            check = finding.data.get("check")

            if check == "safe_mode_enabled":
                actions.append(
                    Action(
                        title="Exit Safe Mode",
                        description=(
                            "To exit Safe Mode, restart your Mac normally without holding "
                            "Shift. If the Mac automatically boots into Safe Mode again, "
                            "it suggests a startup item or kernel extension is causing issues. "
                            "Try these steps: (1) Boot into Safe Mode and disable third-party "
                            "startup items in System Preferences > General > Login Items; "
                            "(2) Use Activity Monitor to identify resource-heavy processes; "
                            "(3) If issues persist, run Apple Diagnostics (Command-D on startup)."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "multiple_panics":
                panic_count = finding.data.get("count", 0)
                actions.append(
                    Action(
                        title="Investigate kernel panics",
                        description=(
                            f"Detected {panic_count} kernel panics in the last 7 days. "
                            "This indicates a serious system issue. Recommended steps: "
                            "(1) Examine panic logs in Console app (/Applications/Utilities/Console.app) "
                            "at ~/Library/Logs/DiagnosticReports/ for clues about what driver or "
                            "component is failing; (2) Run Apple Diagnostics (hold Command-D during boot) "
                            "to check for hardware failures; (3) Update macOS and all software to the latest "
                            "versions; (4) If a specific kernel extension is mentioned in panics, try "
                            "uninstalling or updating it; (5) If hardware issues are suspected, contact "
                            "Apple Support or visit an Apple Authorized Service Provider."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "boot_diagnostics":
                in_safe_mode = finding.data.get("in_safe_mode", False)
                panic_count = finding.data.get("panic_count", 0)

                if not in_safe_mode and panic_count == 0:
                    actions.append(
                        Action(
                            title="Boot diagnostics normal",
                            description=(
                                "Your Mac is booting normally with no recent kernel panics. "
                                "No action needed."
                            ),
                            risk_level=RiskLevel.SAFE,
                            success=True,
                        )
                    )
                elif panic_count == 1:
                    actions.append(
                        Action(
                            title="Single kernel panic detected",
                            description=(
                                "A single kernel panic in the last 7 days may be a transient issue. "
                                "Monitor the system and run Apple Diagnostics if panics continue to occur. "
                                "View the panic log in Console to identify the affected driver or component."
                            ),
                            risk_level=RiskLevel.SAFE,
                            success=True,
                        )
                    )

        return FixResult(module_name=self.name, actions=actions)

    def _check_safe_mode_nvram(self) -> bool:
        """Check if -x flag is present in nvram boot-args."""
        try:
            result = subprocess.run(
                ["nvram", "boot-args"],
                capture_output=True,
                text=True,
                errors="replace",
            )
            return "-x" in result.stdout
        except (OSError, subprocess.SubprocessError):
            return False

    def _check_safe_mode_sysctl(self) -> bool:
        """Check if kern.safeboot is set to 1."""
        try:
            result = subprocess.run(
                ["sysctl", "-n", "kern.safeboot"],
                capture_output=True,
                text=True,
                errors="replace",
            )
            return result.stdout.strip() == "1"
        except (OSError, subprocess.SubprocessError):
            return False

    def _get_boot_volume(self) -> str:
        """Get boot volume via bless --info --getBoot."""
        try:
            result = subprocess.run(
                ["bless", "--info", "--getBoot"],
                capture_output=True,
                text=True,
                errors="replace",
            )
            if result.returncode == 0:
                # Output typically looks like: /Volumes/Macintosh HD
                return result.stdout.strip()
            return None
        except (OSError, subprocess.SubprocessError):
            return None

    def _get_boot_time(self) -> str:
        """Get last boot time via sysctl kern.boottime."""
        try:
            result = subprocess.run(
                ["sysctl", "-n", "kern.boottime"],
                capture_output=True,
                text=True,
                errors="replace",
            )
            if result.returncode == 0:
                # Output is like: { sec = 1672531200, usec = 123456 }
                # Extract the unix timestamp
                match = re.search(r"sec = (\d+)", result.stdout)
                if match:
                    timestamp = int(match.group(1))
                    boot_dt = datetime.fromtimestamp(timestamp)
                    return boot_dt.strftime("%Y-%m-%d %H:%M:%S")
            return None
        except (OSError, subprocess.SubprocessError):
            return None

    def _check_verbose_boot(self) -> bool:
        """Check if verbose boot (-v flag) is enabled in nvram."""
        try:
            result = subprocess.run(
                ["nvram", "boot-args"],
                capture_output=True,
                text=True,
                errors="replace",
            )
            return "-v" in result.stdout
        except (OSError, subprocess.SubprocessError):
            return False

    def _get_boot_disk_info(self) -> dict:
        """Get boot disk filesystem info via diskutil."""
        info = {}
        try:
            result = subprocess.run(
                ["diskutil", "info", "/"],
                capture_output=True,
                text=True,
                errors="replace",
            )
            if result.returncode == 0:
                # Look for Type (filesystem) in output
                match = re.search(r"Type\s*:\s*(.+?)(?:\n|$)", result.stdout)
                if match:
                    info["filesystem"] = match.group(1).strip()
        except (OSError, subprocess.SubprocessError):
            pass
        return info

    def _get_panic_files(self) -> list[str]:
        """Get list of kernel panic files from DiagnosticReports."""
        panic_dir = os.path.expanduser("~/Library/Logs/DiagnosticReports/")
        if not os.path.exists(panic_dir):
            return []
        # Look for .panic files
        return glob.glob(os.path.join(panic_dir, "*.panic"))

    def _count_recent_panics(self, panic_files: list[str], days: int = 7) -> int:
        """Count panic files from the last N days."""
        cutoff_time = datetime.now() - timedelta(days=days)
        count = 0
        for panic_file in panic_files:
            try:
                mtime = os.path.getmtime(panic_file)
                file_time = datetime.fromtimestamp(mtime)
                if file_time >= cutoff_time:
                    count += 1
            except (OSError, ValueError):
                pass
        return count
