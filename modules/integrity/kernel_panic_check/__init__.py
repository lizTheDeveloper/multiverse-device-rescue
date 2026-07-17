import os
import time
from pathlib import Path
from datetime import datetime, timedelta
from collections import defaultdict

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

# Thresholds for kernel panic frequency
CRITICAL_THRESHOLD = 3  # 3+ panics in 30 days
WARNING_THRESHOLD = 1  # 1-2 panics in 30 days
DAYS_TO_CHECK = 30

# Common panic causes to search for in panic logs
PANIC_CAUSES = {
    "gpu": "Graphics/GPU issue",
    "metal": "Metal/GPU issue",
    "thunderbolt": "Thunderbolt issue",
    "usb": "USB issue",
    "thermal": "Thermal issue",
    "memory": "Memory/RAM issue",
    "kernel_panic": "Kernel panic",
    "kext": "Third-party kernel extension",
    "driver": "Driver issue",
    "smc": "System Management Controller issue",
}


class Module(ModuleBase):
    name = "kernel_panic_check"
    category = "integrity"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "5s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Get panic directories
        system_panic_dir = self._system_panic_dir()
        user_panic_dir = self._user_panic_dir()

        # Collect panic files from both locations
        panic_files = []

        if system_panic_dir.exists():
            panic_files.extend(system_panic_dir.glob("*.panic"))

        if user_panic_dir.exists():
            panic_files.extend(user_panic_dir.glob("*.panic"))

        if not panic_files:
            return CheckResult(module_name=self.name, findings=findings)

        # Filter to last 30 days and extract dates
        now = time.time()
        thirty_days_ago = now - (DAYS_TO_CHECK * 24 * 60 * 60)

        recent_panics = []

        for panic_file in panic_files:
            mtime = os.path.getmtime(panic_file)
            if mtime >= thirty_days_ago:
                panic_date = datetime.fromtimestamp(mtime)
                panic_causes = self._identify_panic_causes(panic_file)
                recent_panics.append(
                    {
                        "file": panic_file,
                        "date": panic_date,
                        "mtime": mtime,
                        "causes": panic_causes,
                    }
                )

        if not recent_panics:
            # No recent panics - healthy
            findings.append(
                Finding(
                    title="No kernel panics detected in last 30 days",
                    description="Your system has not experienced any kernel panics in the last 30 days. This is a good sign of system stability.",
                    severity=Severity.INFO,
                    category=self.category,
                    data={"panic_count": 0},
                )
            )
            return CheckResult(module_name=self.name, findings=findings)

        # Determine severity based on panic count
        panic_count = len(recent_panics)

        if panic_count >= CRITICAL_THRESHOLD:
            severity = Severity.CRITICAL
            severity_desc = "CRITICAL"
        elif panic_count >= WARNING_THRESHOLD:
            severity = Severity.WARNING
            severity_desc = "WARNING"
        else:
            severity = Severity.INFO
            severity_desc = "INFO"

        # Create main finding for panic count
        most_recent_date = max(p["date"] for p in recent_panics).strftime(
            "%Y-%m-%d %H:%M:%S"
        )

        findings.append(
            Finding(
                title=f"Kernel panics detected: {panic_count} in last 30 days",
                description=(
                    f"Your system has experienced {panic_count} kernel panics in the last 30 days. "
                    f"Most recent: {most_recent_date}. "
                    f"Kernel panics indicate serious hardware or system software issues. "
                    f"This may be caused by faulty hardware (GPU, RAM, storage), "
                    f"incompatible third-party kernel extensions (kexts), or system software bugs."
                ),
                severity=severity,
                category=self.category,
                data={
                    "panic_count": panic_count,
                    "most_recent_date": most_recent_date,
                    "severity_level": severity_desc,
                },
            )
        )

        # Analyze panic causes
        all_causes = defaultdict(int)
        for panic in recent_panics:
            for cause in panic["causes"]:
                all_causes[cause] += 1

        if all_causes:
            causes_str = ", ".join(
                f"{cause}: {count}" for cause, count in sorted(
                    all_causes.items(), key=lambda x: x[1], reverse=True
                )[:3]
            )

            findings.append(
                Finding(
                    title="Identified potential panic causes",
                    description=(
                        f"Analysis of panic logs suggests these potential causes: {causes_str}. "
                        f"Common causes include GPU drivers, memory issues, Thunderbolt devices, "
                        f"and third-party kernel extensions."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={"identified_causes": dict(all_causes)},
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        for finding in findings.findings:
            panic_count = finding.data.get("panic_count", 0)
            identified_causes = finding.data.get("identified_causes", {})

            if panic_count == 0:
                # No panics - just reassurance
                actions.append(
                    Action(
                        title="System is stable",
                        description=(
                            "Your system shows no signs of kernel panics. Continue monitoring "
                            "and maintain regular backups as part of good system hygiene."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif panic_count >= CRITICAL_THRESHOLD:
                actions.append(
                    Action(
                        title=f"Critical: {panic_count} kernel panics detected",
                        description=(
                            f"Your system has experienced {panic_count} kernel panics in 30 days. "
                            f"This is a serious issue. Recommended steps:\n"
                            f"1. Check Apple System Report (About This Mac > System Report) for hardware issues\n"
                            f"2. Boot into Safe Mode (Cmd+Shift during startup) to test with minimal extensions\n"
                            f"3. Check System Preferences for third-party kernel extensions (System Settings > General > Login Items > Allow)\n"
                            f"4. Reset SMC (System Management Controller):\n"
                            f"   - Apple Silicon: Shut down, wait 30 seconds, hold power button until Apple logo appears\n"
                            f"   - Intel: Shut down, hold Ctrl+Option+Shift+Power for 10 seconds\n"
                            f"5. Test RAM using Memory Diagnostics (Cmd+D at startup, or in Utilities)\n"
                            f"6. If panics continue, contact Apple Support or visit an Apple Service Provider"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif panic_count >= WARNING_THRESHOLD:
                actions.append(
                    Action(
                        title=f"Warning: {panic_count} kernel panics detected",
                        description=(
                            f"Your system has experienced {panic_count} kernel panic(s) in the last 30 days. "
                            f"Recommended steps:\n"
                            f"1. Check for macOS updates: System Settings > General > Software Update\n"
                            f"2. Update all installed applications to latest versions\n"
                            f"3. Check System Report (About This Mac > System Report) for any hardware warnings\n"
                            f"4. Review recently installed software or system changes\n"
                            f"5. Disable third-party kernel extensions if you've recently installed any\n"
                            f"6. Monitor system logs for patterns"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            # Add specific cause-based actions
            if identified_causes:
                causes_str = ",".join(identified_causes.keys()).lower()

                if "graphics/gpu issue" in causes_str or "metal/gpu issue" in causes_str:
                    actions.append(
                        Action(
                            title="Address potential GPU/Graphics issues",
                            description=(
                                "GPU-related panics suggest graphics driver or hardware issues. "
                                "Try: (1) Update macOS and all GPU drivers, (2) Reset NVRAM (Cmd+Option+P+R at startup), "
                                "(3) Disable Metal acceleration in applications if possible, "
                                "(4) Check for Thunderbolt/USB-C GPU enclosure issues"
                            ),
                            risk_level=RiskLevel.SAFE,
                            success=True,
                        )
                    )

                if "memory/ram issue" in causes_str:
                    actions.append(
                        Action(
                            title="Test system memory (RAM)",
                            description=(
                                "Memory-related panics suggest faulty RAM. "
                                "Run Memory Diagnostics: Restart and hold Cmd+D, or use Utilities > Memory Diagnostics. "
                                "If errors are found, contact Apple Support for hardware replacement."
                            ),
                            risk_level=RiskLevel.SAFE,
                            success=True,
                        )
                    )

                if "thunderbolt issue" in causes_str or "usb issue" in causes_str:
                    actions.append(
                        Action(
                            title="Troubleshoot Thunderbolt/USB devices",
                            description=(
                                "Thunderbolt or USB device panics suggest hardware incompatibility. "
                                "Try: (1) Disconnect all external devices, (2) Restart and test, "
                                "(3) Reconnect devices one at a time, (4) Update device firmware if available, "
                                "(5) Try different USB/Thunderbolt ports"
                            ),
                            risk_level=RiskLevel.SAFE,
                            success=True,
                        )
                    )

                if "third-party kernel extension" in causes_str or "driver issue" in causes_str:
                    actions.append(
                        Action(
                            title="Review and disable third-party kernel extensions",
                            description=(
                                "Kernel extension (kext) panics suggest incompatible software. "
                                "Go to System Settings > General > Login Items > Allow in the Security section "
                                "to see and manage kernel extensions. Consider uninstalling recently added extensions "
                                "or drivers, especially for printers, graphics, or virtualization software."
                            ),
                            risk_level=RiskLevel.SAFE,
                            success=True,
                        )
                    )

        return FixResult(module_name=self.name, actions=actions)

    def _system_panic_dir(self) -> Path:
        """Return path to system-wide panic reports."""
        return Path("/Library/Logs/DiagnosticReports")

    def _user_panic_dir(self) -> Path:
        """Return path to user panic reports."""
        return Path.home() / "Library" / "Logs" / "DiagnosticReports"

    def _identify_panic_causes(self, panic_file: Path) -> list[str]:
        """Identify likely panic causes from panic log content.

        Searches panic file content for keywords indicating specific issues.
        Returns list of identified cause categories.
        """
        causes = []

        try:
            # Read panic file content
            with open(panic_file, "r", errors="ignore") as f:
                content = f.read().lower()

            # Search for panic cause indicators
            for cause_key, cause_label in PANIC_CAUSES.items():
                if cause_key in content:
                    causes.append(cause_label)

        except (IOError, OSError):
            # If we can't read the file, return empty list
            pass

        return causes
