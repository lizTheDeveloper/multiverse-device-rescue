import re
from datetime import datetime, timedelta
from pathlib import Path

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
    name = "app_crash_analyzer"
    category = "integrity"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "10s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Scan diagnostic reports directory
        diagnostic_dir = Path.home() / "Library" / "Logs" / "DiagnosticReports"
        crash_files = self._scan_crash_files(diagnostic_dir)

        if not crash_files:
            findings.append(
                Finding(
                    title="No crash reports found",
                    description=(
                        "No crash reports found in ~/Library/Logs/DiagnosticReports/. "
                        "The system appears to be stable."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "no_crashes"},
                )
            )
            return CheckResult(module_name=self.name, findings=findings)

        # Parse crash files
        crashes = self._parse_crash_files(crash_files)

        # Filter to last 7 days
        seven_days_ago = datetime.now() - timedelta(days=7)
        recent_crashes = [c for c in crashes if c["timestamp"] >= seven_days_ago]

        # Count crashes per app
        app_crash_counts = {}
        app_crash_types = {}
        system_process_crashes = []

        for crash in recent_crashes:
            app_name = crash["app_name"]
            crash_reason = crash["crash_reason"]
            is_system = crash["is_system_process"]

            if app_name not in app_crash_counts:
                app_crash_counts[app_name] = 0
                app_crash_types[app_name] = []

            app_crash_counts[app_name] += 1
            app_crash_types[app_name].append(crash_reason)

            if is_system:
                system_process_crashes.append((app_name, crash_reason))

        # Check for unstable apps (>5 crashes in 7 days)
        unstable_apps = [
            (app, count)
            for app, count in sorted(
                app_crash_counts.items(), key=lambda x: x[1], reverse=True
            )
            if count > 5
        ]

        # Check for memory-related crashes
        memory_crash_apps = []
        for app, reasons in app_crash_types.items():
            if app_crash_counts[app] > 5:  # Only flag if already flagged as unstable
                memory_crashes = [r for r in reasons if "EXC_BAD_ACCESS" in r]
                if memory_crashes:
                    memory_crash_apps.append((app, len(memory_crashes)))

        # Generate findings
        total_recent_crashes = len(recent_crashes)
        total_all_crashes = len(crash_files)

        # Info: crash summary
        if recent_crashes:
            top_crashers = sorted(
                app_crash_counts.items(), key=lambda x: x[1], reverse=True
            )[:5]
            top_crashers_str = ", ".join([f"{app} ({count})" for app, count in top_crashers])

            findings.append(
                Finding(
                    title=f"Crash report summary: {total_recent_crashes} recent, {total_all_crashes} total",
                    description=(
                        f"Found {total_recent_crashes} crash reports in the last 7 days "
                        f"(total: {total_all_crashes}). "
                        f"Top 5 most-crashing apps: {top_crashers_str}"
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "check": "crash_summary",
                        "total_recent": total_recent_crashes,
                        "total_all": total_all_crashes,
                        "top_crashers": top_crashers,
                    },
                )
            )

        # Warning: unstable apps
        for app, count in unstable_apps:
            findings.append(
                Finding(
                    title=f"Unstable app: {app} crashed {count} times in 7 days",
                    description=(
                        f"Application '{app}' has crashed {count} times in the last 7 days, "
                        "indicating instability. This may be due to bugs in the application, "
                        "incompatibility with the current macOS version, or missing updates. "
                        "Consider reinstalling the application or checking for updates."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "unstable_app", "app_name": app, "crash_count": count},
                )
            )

        # Warning: system process crashes
        if system_process_crashes:
            system_apps_unique = set(app for app, _ in system_process_crashes)
            findings.append(
                Finding(
                    title=f"System process crashes detected: {', '.join(sorted(system_apps_unique))}",
                    description=(
                        f"System processes are crashing: {', '.join(sorted(system_apps_unique))}. "
                        "This indicates a potential OS issue rather than just an app problem. "
                        "System process crashes may be caused by corrupted system files, "
                        "failed updates, or hardware issues. Consider running Disk Utility "
                        "First Aid or reinstalling macOS if the issue persists."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "check": "system_crashes",
                        "system_apps": list(system_apps_unique),
                    },
                )
            )

        # Warning: memory-related crashes
        if memory_crash_apps:
            memory_apps_str = ", ".join([f"{app} ({count})" for app, count in memory_crash_apps])
            findings.append(
                Finding(
                    title=f"Memory-related crashes (EXC_BAD_ACCESS): {memory_apps_str}",
                    description=(
                        f"Apps with memory-related crashes: {memory_apps_str}. "
                        "EXC_BAD_ACCESS errors typically indicate attempting to access invalid memory. "
                        "This may indicate bad RAM, incompatible app versions, or OS issues. "
                        "Run Memory Diagnostics and check for RAM issues. Consider updating apps "
                        "and restarting the system."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "check": "memory_crashes",
                        "affected_apps": memory_crash_apps,
                    },
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        for finding in findings.findings:
            check = finding.data.get("check")

            if check == "no_crashes":
                actions.append(
                    Action(
                        title="System is stable",
                        description=(
                            "No crash reports detected. Continue monitoring system stability. "
                            "Crash reports will accumulate over time as applications are used."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "crash_summary":
                actions.append(
                    Action(
                        title="Crash report review completed",
                        description=(
                            "Crash report analysis complete. Review the findings above for any "
                            "unstable apps or system issues. Check individual app stability and "
                            "consider updates or reinstalls for frequently crashing applications."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "unstable_app":
                app_name = finding.data.get("app_name")
                crash_count = finding.data.get("crash_count")
                actions.append(
                    Action(
                        title=f"Remediate unstable app: {app_name}",
                        description=(
                            f"Application '{app_name}' has crashed {crash_count} times in 7 days. "
                            f"Recommended steps:\n"
                            f"1. Try updating {app_name} to the latest version via App Store or developer website\n"
                            f"2. If crashes continue, uninstall and reinstall the application\n"
                            f"3. Check if {app_name} is compatible with your macOS version\n"
                            f"4. Report the issue to the app developer with crash details\n"
                            f"Crash reports can be found in ~/Library/Logs/DiagnosticReports/"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "system_crashes":
                system_apps = finding.data.get("system_apps", [])
                actions.append(
                    Action(
                        title="Investigate system process crashes",
                        description=(
                            f"System processes are crashing: {', '.join(system_apps)}. "
                            "This is a more serious issue than individual app crashes. "
                            "Recommended steps:\n"
                            "1. Run Disk Utility First Aid to check for filesystem issues\n"
                            "2. Restart the Mac and see if crashes continue\n"
                            "3. Check System Settings > General > Software Update for OS updates\n"
                            "4. If the issue persists, consider backing up and reinstalling macOS\n"
                            "5. If crashes continue after OS reinstall, hardware diagnostics may be needed"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "memory_crashes":
                affected_apps = finding.data.get("affected_apps", [])
                actions.append(
                    Action(
                        title="Investigate memory-related crashes",
                        description=(
                            f"Memory-related crashes detected: {', '.join([app for app, _ in affected_apps])}. "
                            "EXC_BAD_ACCESS errors may indicate RAM issues. "
                            "Recommended steps:\n"
                            "1. Run Apple Diagnostics or Memory Diagnostics:\n"
                            "   - Restart Mac and hold D (or Cmd+Option+D for remote diagnostics)\n"
                            "2. Update all affected applications to the latest versions\n"
                            "3. Restart the Mac and monitor if crashes stop\n"
                            "4. If crashes persist, contact Apple Support to check for hardware issues"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _scan_crash_files(self, diagnostic_dir: Path) -> list[Path]:
        """Scan diagnostic reports directory for crash and IPS files."""
        crash_files = []

        if not diagnostic_dir.exists():
            return crash_files

        try:
            crash_files.extend(diagnostic_dir.glob("*.crash"))
            crash_files.extend(diagnostic_dir.glob("*.ips"))
        except (OSError, PermissionError):
            pass

        return sorted(crash_files, key=lambda p: p.stat().st_mtime, reverse=True)

    def _parse_crash_files(self, crash_files: list[Path]) -> list[dict]:
        """Parse crash files and extract relevant information."""
        crashes = []

        for file_path in crash_files:
            try:
                crash_info = self._parse_single_crash_file(file_path)
                if crash_info:
                    crashes.append(crash_info)
            except (OSError, PermissionError, ValueError):
                pass

        return crashes

    def _parse_single_crash_file(self, file_path: Path) -> dict | None:
        """Parse a single crash file and extract app name, timestamp, crash reason."""
        try:
            with open(file_path, "r", encoding="utf-8", errors="replace") as f:
                content = f.read()
        except (OSError, PermissionError):
            return None

        # Extract timestamp from file modification time
        try:
            mtime = datetime.fromtimestamp(file_path.stat().st_mtime)
        except (OSError, ValueError):
            mtime = datetime.now()

        # Extract app name from filename (e.g., "AppName_2024-01-15-123456.crash")
        app_name = file_path.stem.split("_")[0]

        # Extract exception type/crash reason
        crash_reason = self._extract_crash_reason(content)

        # Check if it's a system process
        is_system = self._is_system_process(app_name, content)

        return {
            "file_path": str(file_path),
            "app_name": app_name,
            "timestamp": mtime,
            "crash_reason": crash_reason,
            "is_system_process": is_system,
        }

    def _extract_crash_reason(self, content: str) -> str:
        """Extract the exception type from crash file content."""
        # Look for "Exception Type: XXXX" pattern
        exception_match = re.search(r"Exception Type:\s*(\w+)", content)
        if exception_match:
            return exception_match.group(1)

        # Look for "Exception Type:" without capturing
        if "Exception Type:" in content:
            lines = content.split("\n")
            for i, line in enumerate(lines):
                if "Exception Type:" in line:
                    parts = line.split(":", 1)
                    if len(parts) > 1:
                        return parts[1].strip()

        # Look for common crash codes
        for code in ["SIGKILL", "SIGABRT", "SIGSEGV", "SIGBUS", "EXC_BAD_ACCESS"]:
            if code in content:
                return code

        return "Unknown"

    def _is_system_process(self, app_name: str, content: str) -> bool:
        """Determine if the crashed app is a system process."""
        # System process indicators
        system_indicators = [
            "kernel",
            "systemd",
            "launchd",
            "WindowServer",
            "Finder",
            "Dock",
            "loginwindow",
            "SystemUIServer",
            "Spotlight",
            "mdworker",
            "mds",
            "fseventsd",
            "Safari",  # Safari is critical system component
            "Mail",    # Mail is critical
            "Keychain",
        ]

        app_lower = app_name.lower()
        for indicator in system_indicators:
            if indicator.lower() in app_lower:
                return True

        # Check if content indicates system context
        if "System Framework" in content or "Core OS" in content:
            return True

        return False
