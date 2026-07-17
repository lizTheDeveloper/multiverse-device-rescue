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

# Thresholds for crash frequency
WARNING_THRESHOLD = 3  # 3+ crashes in 7 days
CRITICAL_THRESHOLD = 10  # 10+ crashes in 7 days
DAYS_TO_CHECK = 7


class Module(ModuleBase):
    name = "crash_log_analyzer"
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

        # Filter to last 7 days and group by app
        now = time.time()
        seven_days_ago = now - (DAYS_TO_CHECK * 24 * 60 * 60)

        crashes_by_app = defaultdict(list)
        total_recent_crashes = 0

        for crash_file in crash_files:
            mtime = os.path.getmtime(crash_file)
            if mtime >= seven_days_ago:
                app_name = self._parse_app_name(crash_file)
                crashes_by_app[app_name].append(crash_file)
                total_recent_crashes += 1

        # Create findings for apps that exceed thresholds
        for app_name, files in sorted(
            crashes_by_app.items(), key=lambda x: len(x[1]), reverse=True
        ):
            crash_count = len(files)

            if crash_count >= CRITICAL_THRESHOLD:
                severity = Severity.CRITICAL
            elif crash_count >= WARNING_THRESHOLD:
                severity = Severity.WARNING
            else:
                continue  # Don't flag apps below threshold

            # Get most recent crash timestamp
            most_recent_mtime = max(os.path.getmtime(f) for f in files)
            most_recent_date = datetime.fromtimestamp(most_recent_mtime).strftime(
                "%Y-%m-%d %H:%M:%S"
            )

            findings.append(
                Finding(
                    title=f"{app_name} crashed {crash_count} times in 7 days",
                    description=(
                        f"The application '{app_name}' has crashed {crash_count} times "
                        f"in the last 7 days. Most recent crash: {most_recent_date}. "
                        f"This may indicate a serious problem with the application."
                    ),
                    severity=severity,
                    category=self.category,
                    data={
                        "app_name": app_name,
                        "crash_count": crash_count,
                        "most_recent_date": most_recent_date,
                    },
                )
            )

        # Add summary finding if there are any crashes
        if total_recent_crashes > 0 and findings:
            # Get top 5 crashers - store just app name and count
            top_5 = sorted(
                crashes_by_app.items(), key=lambda x: len(x[1]), reverse=True
            )[:5]
            top_5_with_counts = [(app, len(files)) for app, files in top_5]
            top_5_str = ", ".join(
                f"{app}: {count} crashes" for app, count in top_5_with_counts
            )

            findings.append(
                Finding(
                    title=f"Crash report summary: {total_recent_crashes} total crashes in 7 days",
                    description=(
                        f"Total crashes in the last 7 days: {total_recent_crashes}. "
                        f"Top 5 most-crashed apps: {top_5_str}. "
                        f"Review ~/Library/Logs/DiagnosticReports/ for details."
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

            if app_name:
                # Individual app action
                actions.append(
                    Action(
                        title=f"Address crashes for {app_name}",
                        description=(
                            f"The app '{app_name}' is crashing frequently. "
                            f"Consider: (1) updating the app to the latest version, "
                            f"(2) reinstalling the app if updates don't help, "
                            f"(3) checking the app developer's website for known issues, "
                            f"(4) checking System Settings > General > About > System Report "
                            f"for any related system issues, or (5) contacting Apple Support "
                            f"if the app is an Apple product."
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
                        title=f"Review {total_crashes} crashes in DiagnosticReports",
                        description=(
                            f"A total of {total_crashes} application crashes were found "
                            f"in the last 7 days. This suggests system or application instability. "
                            f"Review the crash logs at ~/Library/Logs/DiagnosticReports/ "
                            f"for more details. Common causes: insufficient RAM, conflicting "
                            f"extensions, or outdated app versions. Start by updating macOS "
                            f"and all installed applications."
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
