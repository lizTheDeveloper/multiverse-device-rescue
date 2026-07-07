import json
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
    name = "software_inventory"
    category = "integrity"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "30s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        try:
            apps_data = self._get_applications_data()
        except Exception:
            return CheckResult(module_name=self.name, findings=findings)

        old_1year_apps = []
        old_2year_apps = []
        apps_32bit = []

        now = datetime.now()
        one_year_ago = now - timedelta(days=365)
        two_years_ago = now - timedelta(days=730)

        apps_data = apps_data or []

        for app in apps_data:
            app_name = app.get("_name", "Unknown")
            app_version = app.get("version", "Unknown")
            last_modified_str = app.get("lastModified")

            # Check app age
            if last_modified_str:
                try:
                    last_modified = datetime.fromisoformat(last_modified_str)
                    if last_modified < two_years_ago:
                        old_2year_apps.append((app_name, app_version, last_modified))
                    elif last_modified < one_year_ago:
                        old_1year_apps.append((app_name, app_version, last_modified))
                except (ValueError, TypeError):
                    pass

            # Check for 32-bit apps
            if app.get("_is32bit"):
                apps_32bit.append(app_name)

        # Create findings for old apps (2+ years)
        if old_2year_apps:
            app_names = [f"{name} ({version})" for name, version, _ in old_2year_apps]
            findings.append(
                Finding(
                    title=f"{len(old_2year_apps)} app(s) not updated in 2+ years",
                    description="These apps may have unpatched vulnerabilities: "
                    + ", ".join(app_names),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "check": "old_2year_apps",
                        "apps": app_names,
                        "count": len(old_2year_apps),
                    },
                )
            )

        # Create findings for old apps (1+ year)
        if old_1year_apps:
            app_names = [f"{name} ({version})" for name, version, _ in old_1year_apps]
            findings.append(
                Finding(
                    title=f"{len(old_1year_apps)} app(s) not updated in 1+ year",
                    description="These apps should be updated for security: "
                    + ", ".join(app_names),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "check": "old_1year_apps",
                        "apps": app_names,
                        "count": len(old_1year_apps),
                    },
                )
            )

        # Create findings for 32-bit apps
        if apps_32bit:
            findings.append(
                Finding(
                    title=f"{len(apps_32bit)} 32-bit app(s) installed",
                    description="These apps won't run on macOS Catalina (10.15) or later: "
                    + ", ".join(apps_32bit),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "check": "32bit_apps",
                        "apps": apps_32bit,
                        "count": len(apps_32bit),
                    },
                )
            )

        # Add info finding with summary
        findings.append(
            Finding(
                title=f"Software inventory: {len(apps_data)} application(s) installed",
                description=f"Total: {len(apps_data)} apps. Old (2+ years): {len(old_2year_apps)}. "
                f"Old (1+ year): {len(old_1year_apps)}. 32-bit: {len(apps_32bit)}.",
                severity=Severity.INFO,
                category=self.category,
                data={
                    "check": "software_summary",
                    "total_apps": len(apps_data),
                    "old_2year_count": len(old_2year_apps),
                    "old_1year_count": len(old_1year_apps),
                    "apps_32bit_count": len(apps_32bit),
                },
            )
        )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            check = finding.data.get("check")

            if check == "old_2year_apps":
                actions.append(
                    Action(
                        title="Update or remove 2+ year old applications",
                        description="Apps older than 2 years may have unpatched security "
                        "vulnerabilities. Consider updating them or removing them if no longer "
                        "needed. Check the App Store or vendors' websites for updates.",
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif check == "old_1year_apps":
                actions.append(
                    Action(
                        title="Update applications not updated in 1+ year",
                        description="Apps not updated for over a year should be checked for "
                        "security updates. Visit the App Store or vendor websites to update them.",
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif check == "32bit_apps":
                actions.append(
                    Action(
                        title="Address 32-bit application compatibility",
                        description="32-bit apps are incompatible with macOS Catalina (10.15+). "
                        "Update these apps to 64-bit versions if available, or remove them. "
                        "Check vendors' websites for 64-bit versions.",
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif check == "software_summary":
                actions.append(
                    Action(
                        title="Software inventory summary",
                        description=f"Total applications: {finding.data.get('total_apps', 0)}. "
                        f"See detailed findings above for applications needing attention.",
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _get_applications_data(self) -> list[dict]:
        """Fetch application data using system_profiler SPApplicationsDataType -json."""
        try:
            result = subprocess.run(
                ["system_profiler", "SPApplicationsDataType", "-json"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode != 0:
                return []

            data = json.loads(result.stdout)
            # system_profiler returns {"SPApplicationsDataType": [...]}
            apps = data.get("SPApplicationsDataType", [])
            return apps
        except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError):
            return []


def _parse_date(date_str: str) -> datetime | None:
    """Parse ISO format datetime strings."""
    if not date_str:
        return None
    try:
        return datetime.fromisoformat(date_str)
    except (ValueError, TypeError):
        return None
