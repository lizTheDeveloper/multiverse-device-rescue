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


class Module(ModuleBase):
    name = "accessibility_permissions"
    category = "security"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "5s"

    # Well-known apps that are commonly granted accessibility access
    WELL_KNOWN_APPS = {
        "com.apple.Finder",
        "com.apple.Spotlight",
        "com.apple.SystemUIServer",
        "com.apple.universalaccess",
        "com.apple.accessibility",
        "com.apple.loginwindow",
        "com.apple.Security",
        "com.apple.Automator",
        "com.apple.dt.Xcode",
        "com.jetbrains.pycharm",
        "com.jetbrains.datagrip",
        "com.jetbrains.webstorm",
        "com.jetbrains.intellij",
        "com.sublimetext.3",
        "com.microsoft.VSCode",
        "org.vim.MacVim",
        "com.apple.Terminal",
        "com.googlecode.iterm2",
        "org.alacritty",
        "io.wezfurlong.wezterm",
        "com.apple.Script Editor",
        "org.hammerspoon.Hammerspoon",
        "org.gnu.emacs",
        "com.alfredapp.Alfred",
        "com.getdropbox.dropbox",
        "com.google.drive",
        "com.apple.iCloud.sync",
    }

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Query both system and user TCC databases
        system_db = "/Library/Application Support/com.apple.TCC/TCC.db"
        user_db = str(Path.home() / "Library/Application Support/com.apple.TCC/TCC.db")

        system_rows = self._query_tcc(system_db)
        user_rows = self._query_tcc(user_db)

        # Combine and deduplicate apps with accessibility access
        all_apps = []
        seen = set()
        for rows in [system_rows, user_rows]:
            for app in rows:
                if app not in seen:
                    all_apps.append(app)
                    seen.add(app)

        if not all_apps:
            return CheckResult(module_name=self.name, findings=[])

        # Separate well-known apps from suspicious ones
        well_known = []
        suspicious = []
        for app in sorted(all_apps):
            if app in self.WELL_KNOWN_APPS or app.startswith("com.apple."):
                well_known.append(app)
            else:
                suspicious.append(app)

        # Always add INFO finding listing all apps with accessibility access
        app_list = ", ".join(sorted(all_apps))
        findings.append(
            Finding(
                title=f"Accessibility access: {len(all_apps)} app(s)",
                description=(
                    f"{len(all_apps)} app(s) have been granted Accessibility access: "
                    f"{app_list}. "
                    "Accessibility access is a powerful permission that allows "
                    "apps to control your system. Review to ensure only trusted "
                    "apps have this access."
                ),
                severity=Severity.INFO,
                category=self.category,
                data={"check": "accessibility_access", "apps": sorted(all_apps)},
            )
        )

        # Flag WARNING if suspicious apps have accessibility access
        if suspicious:
            findings.append(
                Finding(
                    title=f"Suspicious accessibility access: {len(suspicious)} app(s)",
                    description=(
                        f"{len(suspicious)} unknown or suspicious app(s) have been granted "
                        f"Accessibility access: {', '.join(suspicious)}. "
                        "These apps may not be trusted system or well-known applications. "
                        "Malware often abuses accessibility permissions to control your system "
                        "without permission. Investigate and revoke access for apps you don't recognize."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "suspicious_accessibility", "apps": suspicious},
                )
            )

        # Flag WARNING if excessive number of apps have accessibility access
        if len(all_apps) > 10:
            findings.append(
                Finding(
                    title=f"Excessive accessibility access: {len(all_apps)} app(s)",
                    description=(
                        f"{len(all_apps)} app(s) have accessibility access, which exceeds "
                        "the recommended limit of 10. Having too many apps with this powerful "
                        "permission increases the attack surface. Review and revoke access "
                        "for apps that don't strictly need it."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "excessive_accessibility", "count": len(all_apps)},
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            check = finding.data.get("check")

            if check == "accessibility_access":
                apps = finding.data.get("apps", [])
                app_list = ", ".join(sorted(apps))
                actions.append(
                    Action(
                        title="Review and manage Accessibility access",
                        description=(
                            f"Apps with Accessibility access: {app_list}.\n"
                            "To manage Accessibility permissions, open System Settings > "
                            "Privacy & Security > Accessibility. Review each app and "
                            "toggle off access for apps you don't trust or don't need."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )
            elif check == "suspicious_accessibility":
                apps = finding.data.get("apps", [])
                app_list = ", ".join(sorted(apps))
                actions.append(
                    Action(
                        title="Revoke Accessibility access from suspicious apps",
                        description=(
                            f"Suspicious apps with Accessibility access: {app_list}.\n"
                            "To revoke access, open System Settings > Privacy & Security > "
                            "Accessibility and remove these apps from the list. If you "
                            "installed any of these apps, consider uninstalling them."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )
            elif check == "excessive_accessibility":
                count = finding.data.get("count", 0)
                actions.append(
                    Action(
                        title="Reduce number of apps with Accessibility access",
                        description=(
                            f"{count} app(s) currently have Accessibility access. "
                            "To reduce this number, open System Settings > Privacy & Security > "
                            "Accessibility and audit each app. Remove access for applications "
                            "that don't require it, especially ones you rarely use."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _query_tcc(self, db_path: str) -> list[str]:
        """Query TCC database for apps with accessibility access.

        Returns list of app bundle identifiers with accessibility access.
        Returns [] on any failure (permission denied, file not found, etc).
        """
        try:
            result = subprocess.run(
                [
                    "sqlite3",
                    db_path,
                    "SELECT client FROM access WHERE service='kTCCServiceAccessibility' AND auth_value=2",
                ],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                return []
            apps = []
            for line in result.stdout.strip().split("\n"):
                if line:
                    apps.append(line)
            return apps
        except OSError:
            return []
        except Exception:
            return []
