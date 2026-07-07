import os
import time
from pathlib import Path
from collections import defaultdict
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

# Thresholds for crash frequency in 30 days
CRASH_WARNING_THRESHOLD = 5  # 5+ crashes in 30 days
DAYS_TO_CHECK = 30

# System apps that are critical - flag if they're crashing
SYSTEM_CRITICAL_APPS = {"Finder", "WindowServer", "loginwindow"}


class Module(ModuleBase):
    name = "application_crash_report"
    category = "integrity"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "10s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []
        reports_dir = self._reports_dir()

        # Handle missing or empty directory
        if not reports_dir.exists():
            return CheckResult(module_name=self.name, findings=findings)

        # Scan for crash files
        crash_files = list(reports_dir.glob("*.crash")) + list(reports_dir.glob("*.ips"))

        if not crash_files:
            return CheckResult(module_name=self.name, findings=findings)

        # Filter to last 30 days and group by app
        now = time.time()
        thirty_days_ago = now - (DAYS_TO_CHECK * 24 * 60 * 60)

        crashes_by_app = defaultdict(list)
        total_recent_crashes = 0

        for crash_file in crash_files:
            mtime = os.path.getmtime(crash_file)
            if mtime >= thirty_days_ago:
                app_name = self._parse_app_name(crash_file)
                crashes_by_app[app_name].append(crash_file)
                total_recent_crashes += 1

        # Check for system apps crashing (always flag as WARNING)
        for app_name, files in crashes_by_app.items():
            if app_name in SYSTEM_CRITICAL_APPS:
                crash_count = len(files)
                most_recent_mtime = max(os.path.getmtime(f) for f in files)
                most_recent_date = datetime.fromtimestamp(most_recent_mtime).strftime(
                    "%Y-%m-%d %H:%M:%S"
                )

                findings.append(
                    Finding(
                        title=f"Critical system app '{app_name}' is crashing",
                        description=(
                            f"The system application '{app_name}' has crashed {crash_count} times "
                            f"in the last {DAYS_TO_CHECK} days (most recent: {most_recent_date}). "
                            f"This suggests a serious system issue that requires attention."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={
                            "app_name": app_name,
                            "crash_count": crash_count,
                            "most_recent_date": most_recent_date,
                            "is_system_app": True,
                        },
                    )
                )

        # Check for apps that exceed the crash threshold (non-system apps)
        for app_name, files in sorted(
            crashes_by_app.items(), key=lambda x: len(x[1]), reverse=True
        ):
            if app_name in SYSTEM_CRITICAL_APPS:
                continue  # Already handled above

            crash_count = len(files)

            if crash_count >= CRASH_WARNING_THRESHOLD:
                most_recent_mtime = max(os.path.getmtime(f) for f in files)
                most_recent_date = datetime.fromtimestamp(most_recent_mtime).strftime(
                    "%Y-%m-%d %H:%M:%S"
                )

                findings.append(
                    Finding(
                        title=f"Application '{app_name}' crashed {crash_count} times in {DAYS_TO_CHECK} days",
                        description=(
                            f"The application '{app_name}' has crashed {crash_count} times "
                            f"in the last {DAYS_TO_CHECK} days (most recent: {most_recent_date}). "
                            f"This may indicate a persistent problem with the application."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={
                            "app_name": app_name,
                            "crash_count": crash_count,
                            "most_recent_date": most_recent_date,
                            "is_system_app": False,
                        },
                    )
                )

        # Add summary finding if there are any crashes
        if total_recent_crashes > 0:
            # Get top 5 crashers
            top_5 = sorted(
                crashes_by_app.items(), key=lambda x: len(x[1]), reverse=True
            )[:5]
            top_5_with_counts = [(app, len(files)) for app, files in top_5]
            top_5_str = ", ".join(
                f"{app}: {count}" for app, count in top_5_with_counts
            )

            findings.append(
                Finding(
                    title=f"Application crash summary: {total_recent_crashes} total crashes in {DAYS_TO_CHECK} days",
                    description=(
                        f"Total application crashes in the last {DAYS_TO_CHECK} days: {total_recent_crashes}. "
                        f"Top crashing apps: {top_5_str}. "
                        f"Review ~/Library/Logs/DiagnosticReports/ for detailed crash logs."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "total_crashes": total_recent_crashes,
                        "top_5_crashers": dict(top_5_with_counts),
                    },
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        for finding in findings.findings:
            app_name = finding.data.get("app_name")
            is_system_app = finding.data.get("is_system_app", False)

            if app_name:
                # Individual app action
                if is_system_app:
                    actions.append(
                        Action(
                            title=f"Address crashes for system app '{app_name}'",
                            description=(
                                f"The critical system application '{app_name}' is crashing. "
                                f"Consider: (1) updating macOS to the latest version, "
                                f"(2) restarting your Mac, "
                                f"(3) running Disk Utility to verify the disk, "
                                f"(4) resetting the NVRAM/PRAM, or "
                                f"(5) contacting Apple Support if the issue persists."
                            ),
                            risk_level=RiskLevel.SAFE,
                            success=True,
                        )
                    )
                else:
                    actions.append(
                        Action(
                            title=f"Address crashes for '{app_name}'",
                            description=(
                                f"The application '{app_name}' is crashing frequently. "
                                f"Consider: (1) updating the app to the latest version through "
                                f"App Store or the developer's website, "
                                f"(2) reinstalling the app if updates don't help, "
                                f"(3) checking the app developer's website for known issues, "
                                f"(4) checking if conflicting extensions or plugins exist, or "
                                f"(5) contacting the app's developer for support."
                            ),
                            risk_level=RiskLevel.SAFE,
                            success=True,
                        )
                    )
            else:
                # Summary action
                total_crashes = finding.data.get("total_crashes", 0)
                actions.append(
                    Action(
                        title=f"Review {total_crashes} application crashes",
                        description=(
                            f"A total of {total_crashes} application crashes were found "
                            f"in the last {DAYS_TO_CHECK} days. Review the crash logs at "
                            f"~/Library/Logs/DiagnosticReports/ for more details. "
                            f"Common causes: insufficient RAM, outdated app versions, "
                            f"conflicting extensions, or system issues. Start by updating "
                            f"macOS and all installed applications."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _reports_dir(self) -> Path:
        """Return the path to DiagnosticReports directory. Can be patched in tests."""
        return Path.home() / "Library" / "Logs" / "DiagnosticReports"

    def _parse_app_name(self, crash_file: Path) -> str:
        """Parse application name from crash filename.

        Format: AppName_YYYY-MM-DD_counter.crash or .ips
        Uses rsplit('_', 2) to handle app names with underscores.
        Example: Visual_Studio_Code_2026-07-06_001.crash
        -> stem: Visual_Studio_Code_2026-07-06_001
        -> rsplit('_', 2): ['Visual_Studio_Code', '2026-07-06', '001']
        -> returns: Visual_Studio_Code
        """
        stem = crash_file.stem
        parts = stem.rsplit("_", 2)
        if len(parts) >= 2:
            return parts[0]
        return stem
