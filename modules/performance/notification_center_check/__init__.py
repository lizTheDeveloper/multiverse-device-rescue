import os
import subprocess
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

# Thresholds
APPS_WARNING_THRESHOLD = 50
DB_SIZE_WARNING_BYTES = 500 * 1024 * 1024  # 500 MB
ALERT_APPS_WARNING_THRESHOLD = 10

# Apps that typically shouldn't send notifications (notification-heavy bloat)
BLOAT_APPS = {
    "Games",
    "Flashcard Hero",
    "Poker",
    "Chess",
    "Solitaire",
    "Sudoku",
    "Minesweeper",
}


class Module(ModuleBase):
    name = "notification_center_check"
    category = "performance"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "3s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Check notification database size
        db_finding = self._check_database_size()
        if db_finding:
            findings.append(db_finding)

        # Count apps with notification permissions and check styles
        apps_info = self._get_notification_apps()
        if apps_info:
            apps_count = apps_info.get("app_count", 0)
            alert_count = apps_info.get("alert_count", 0)
            has_dnd = apps_info.get("dnd_active", False)

            # Check if too many apps have permissions
            if apps_count > APPS_WARNING_THRESHOLD:
                findings.append(
                    Finding(
                        title="Notification overload: too many apps have permissions",
                        description=(
                            f"{apps_count} apps have notification permissions. "
                            f"This can cause UI lag and battery drain. "
                            f"Consider disabling notifications for apps you don't use."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={
                            "app_count": apps_count,
                            "check": "app_permission_count",
                        },
                    )
                )

            # Check if too many apps use Alerts style
            if alert_count > ALERT_APPS_WARNING_THRESHOLD:
                findings.append(
                    Finding(
                        title="Too many apps using Alerts notification style",
                        description=(
                            f"{alert_count} apps are set to 'Alerts' style, which interrupt workflow "
                            f"and stay on screen. Consider changing non-critical apps to 'Banners' style."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={
                            "alert_count": alert_count,
                            "check": "alert_style_count",
                        },
                    )
                )

            # Add info summary
            findings.append(
                Finding(
                    title="Notification Center configuration summary",
                    description=(
                        f"Apps with permissions: {apps_count}\n"
                        f"Apps using Alerts style: {alert_count}\n"
                        f"Do Not Disturb active: {'Yes' if has_dnd else 'No'}"
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "app_count": apps_count,
                        "alert_count": alert_count,
                        "dnd_active": has_dnd,
                        "check": "configuration_summary",
                    },
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        """
        Provide informational actions for notification center health.
        This is a diagnostic tool - it suggests actions but never modifies settings.
        """
        actions = []

        for finding in findings.findings:
            check_type = finding.data.get("check")

            if check_type == "database_size":
                db_size = finding.data.get("db_size_bytes", 0)
                actions.append(
                    Action(
                        title="Notification database is bloated",
                        description=(
                            f"Notification Center database is {_fmt_bytes(db_size)}, "
                            f"exceeding the 500MB threshold. This can cause UI lag and performance issues.\n"
                            f"To resolve:\n"
                            f"  1. Open System Settings > Notifications\n"
                            f"  2. Review and disable notifications for apps you don't actively use\n"
                            f"  3. Consider disabling notifications for background apps\n"
                            f"  4. Disable notifications for games and entertainment apps"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check_type == "app_permission_count":
                app_count = finding.data.get("app_count", 0)
                actions.append(
                    Action(
                        title="Too many apps have notification permissions",
                        description=(
                            f"{app_count} apps have notification permissions. This causes constant interruptions.\n"
                            f"To resolve:\n"
                            f"  1. Open System Settings > Notifications\n"
                            f"  2. Sort apps by notification settings\n"
                            f"  3. Disable 'Allow Notifications' for apps you don't actively monitor\n"
                            f"  4. Focus on keeping only essential apps (mail, messages, calendar)"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check_type == "alert_style_count":
                alert_count = finding.data.get("alert_count", 0)
                actions.append(
                    Action(
                        title="Too many apps using Alerts notification style",
                        description=(
                            f"{alert_count} apps are set to 'Alerts' style, causing constant interruptions.\n"
                            f"To resolve:\n"
                            f"  1. Open System Settings > Notifications\n"
                            f"  2. For each app using 'Alerts', change to 'Banners' for less disruptive notifications\n"
                            f"  3. Keep 'Alerts' only for time-critical apps (messages, calendar reminders)\n"
                            f"  4. Disable 'Sound' and 'Badge' for non-essential notifications"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _check_database_size(self) -> Finding | None:
        """Check notification database size at ~/Library/Application Support/NotificationCenter/"""
        try:
            nc_path = Path.home() / "Library" / "Application Support" / "NotificationCenter"
            if not nc_path.exists():
                return None

            total_size = 0
            for root, dirs, files in os.walk(nc_path):
                for file in files:
                    file_path = Path(root) / file
                    try:
                        total_size += file_path.stat().st_size
                    except OSError:
                        pass

            if total_size > DB_SIZE_WARNING_BYTES:
                return Finding(
                    title="Notification database is bloated",
                    description=(
                        f"Notification Center database is {_fmt_bytes(total_size)}, "
                        f"exceeding the 500MB threshold. This can cause UI lag."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "db_size_bytes": total_size,
                        "check": "database_size",
                    },
                )

        except Exception:
            # Silently ignore errors accessing the database
            pass

        return None

    def _get_notification_apps(self) -> dict | None:
        """Get notification app settings from defaults."""
        try:
            # Read the notification preferences plist
            prefs_path = Path.home() / "Library" / "Preferences" / "com.apple.ncprefs.plist"
            if not prefs_path.exists():
                return None

            # Use defaults to read the plist
            result = subprocess.run(
                ["defaults", "read", str(prefs_path)],
                capture_output=True,
                text=True,
                timeout=5,
            )

            if result.returncode != 0:
                return None

            # Parse the output to count apps and styles
            output = result.stdout
            app_count = 0
            alert_count = 0
            has_dnd = False

            # Count app entries (rough heuristic: look for app bundle IDs)
            # Each app typically has an entry like "com.apple.mail"
            lines = output.split("\n")
            for line in lines:
                # Look for bundle ID patterns
                if "com." in line and "{" not in line and "}" not in line:
                    app_count += 1
                # Check for "alertStyle = 1" which indicates Alerts
                if "alertStyle = 1" in line:
                    alert_count += 1
                # Check for Do Not Disturb
                if "doNotDisturb" in line and "1" in line.split("=")[-1]:
                    has_dnd = True

            return {
                "app_count": max(0, app_count),
                "alert_count": alert_count,
                "dnd_active": has_dnd,
            }

        except subprocess.TimeoutExpired:
            return None
        except Exception:
            # Silently ignore errors reading preferences
            return None


def _fmt_bytes(n: int) -> str:
    """Format bytes as human-readable string."""
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"
