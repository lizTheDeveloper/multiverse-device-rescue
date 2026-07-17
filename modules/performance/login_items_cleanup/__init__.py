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

# Known resource-heavy apps that slow down boot when in login items
RESOURCE_HEAVY_APPS = {
    "Dropbox",
    "Google Drive",
    "OneDrive",
    "Creative Cloud",
    "Steam",
    "Spotify",
    "Slack",
    "Discord",
    "Adobe",
    "Zoom",
    "Microsoft Teams",
}


class Module(ModuleBase):
    name = "login_items_cleanup"
    category = "performance"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 65
    depends_on = []
    estimated_duration = "5s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Get login items via osascript
        login_items = self._get_login_items_via_osascript()

        # Get launch agents
        launch_agents = self._get_launch_agents()

        # Combine all login items
        all_items = set(login_items + launch_agents)
        all_items_list = sorted(list(all_items))

        # Check for broken login items (app no longer installed)
        broken_items = self._find_broken_items(login_items)

        # Identify resource-heavy items
        resource_heavy = self._identify_resource_heavy(all_items_list)

        item_count = len(all_items)

        # Add INFO finding with all login items
        if all_items_list:
            findings.append(
                Finding(
                    title=f"Login items count: {item_count}",
                    description=(
                        f"System has {item_count} login item(s): {', '.join(all_items_list)}. "
                        f"Each item adds to boot time and memory usage."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "type": "login_items_list",
                        "count": item_count,
                        "items": all_items_list,
                    },
                )
            )

        # Flag WARNING if more than 8 login items
        if item_count > 8:
            findings.insert(
                0,
                Finding(
                    title=f"Excessive login items ({item_count})",
                    description=(
                        f"System has {item_count} login items (recommended: 8 or fewer). "
                        f"Excessive login items significantly slow down boot time and consume resources. "
                        f"Review and disable unnecessary items."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "type": "excessive_login_items",
                        "count": item_count,
                    },
                ),
            )

        # Flag WARNING for resource-heavy items
        if resource_heavy:
            findings.insert(
                0,
                Finding(
                    title=f"Resource-heavy login items detected ({len(resource_heavy)})",
                    description=(
                        f"Found {len(resource_heavy)} known resource-intensive app(s) in login items: "
                        f"{', '.join(resource_heavy)}. These consume significant RAM and CPU at startup. "
                        f"Consider disabling them if not needed at boot."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "type": "resource_heavy_items",
                        "items": resource_heavy,
                        "count": len(resource_heavy),
                    },
                ),
            )

        # Flag WARNING for broken items
        if broken_items:
            findings.insert(
                0,
                Finding(
                    title=f"Broken login items ({len(broken_items)})",
                    description=(
                        f"Found {len(broken_items)} login item(s) for applications that are no longer installed: "
                        f"{', '.join(broken_items)}. These should be removed."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "type": "broken_login_items",
                        "items": broken_items,
                        "count": len(broken_items),
                    },
                ),
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        for finding in findings.findings:
            finding_type = finding.data.get("type", "unknown")

            if finding_type == "login_items_list":
                count = finding.data.get("count", 0)
                actions.append(
                    Action(
                        title=f"Login items count: {count}",
                        description=(
                            f"System has {count} login item(s). To manage login items:\n"
                            f"1. Open System Settings > General > Login Items\n"
                            f"2. Review each item and disable unnecessary ones\n"
                            f"3. Remove items by selecting and clicking the minus (-) button"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif finding_type == "excessive_login_items":
                count = finding.data.get("count", 0)
                actions.append(
                    Action(
                        title=f"Excessive login items ({count})",
                        description=(
                            f"You have {count} login items. Recommended maximum is 8. To reduce:\n"
                            f"1. Open System Settings > General > Login Items\n"
                            f"2. Identify which apps you actually need at startup\n"
                            f"3. Remove unnecessary items by selecting and clicking the minus (-) button\n"
                            f"4. Consider cloud services (Dropbox, OneDrive, Google Drive) as non-essential\n"
                            f"5. Disable communication apps (Slack, Discord, Teams) if not required at boot"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif finding_type == "resource_heavy_items":
                items = finding.data.get("items", [])
                actions.append(
                    Action(
                        title=f"Resource-heavy login items: {', '.join(items)}",
                        description=(
                            f"The following resource-intensive apps are in login items:\n"
                            f"{', '.join(items)}\n\n"
                            f"To disable them:\n"
                            f"1. Open System Settings > General > Login Items\n"
                            f"2. Find each app and remove by clicking the minus (-) button\n"
                            f"3. You can still launch them manually when needed"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif finding_type == "broken_login_items":
                items = finding.data.get("items", [])
                actions.append(
                    Action(
                        title=f"Broken login items: {', '.join(items)}",
                        description=(
                            f"The following login items reference uninstalled apps:\n"
                            f"{', '.join(items)}\n\n"
                            f"To remove them:\n"
                            f"1. Open System Settings > General > Login Items\n"
                            f"2. Select each broken item and click the minus (-) button"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _get_login_items_via_osascript(self) -> list[str]:
        """Get login items using osascript (System Events)."""
        try:
            cmd = [
                "osascript",
                "-e",
                'tell application "System Events" to get the name of every login item',
            ]
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                timeout=5,
            )

            if result.returncode == 0 and result.stdout.strip():
                # osascript returns items separated by commas
                items = [item.strip() for item in result.stdout.strip().split(",")]
                return [item for item in items if item]

            return []
        except (subprocess.TimeoutExpired, OSError, Exception):
            return []

    def _get_launch_agents(self) -> list[str]:
        """Get login-triggered launch agents from ~/Library/LaunchAgents."""
        agents = []
        launch_agents_dir = Path.home() / "Library" / "LaunchAgents"

        if not launch_agents_dir.exists():
            return agents

        try:
            for plist_file in launch_agents_dir.glob("*.plist"):
                try:
                    # Extract the service name from the plist filename
                    agent_name = plist_file.stem
                    agents.append(agent_name)
                except (OSError, PermissionError):
                    continue
        except (OSError, PermissionError):
            pass

        return agents

    def _find_broken_items(self, login_items: list[str]) -> list[str]:
        """Identify login items where the app is no longer installed."""
        broken = []

        # Check if each login item exists in common app locations
        for item in login_items:
            if not self._app_exists(item):
                broken.append(item)

        return broken

    def _app_exists(self, app_name: str) -> bool:
        """Check if an application exists in common locations."""
        common_paths = [
            Path("/Applications") / f"{app_name}.app",
            Path.home() / "Applications" / f"{app_name}.app",
            Path("/usr/local/opt") / f"{app_name}",
        ]

        for path in common_paths:
            if path.exists():
                return True

        return False

    def _identify_resource_heavy(self, items: list[str]) -> list[str]:
        """Identify known resource-heavy apps in login items."""
        heavy = []

        for item in items:
            # Check if item contains any keywords for resource-heavy apps
            for heavy_app in RESOURCE_HEAVY_APPS:
                if heavy_app.lower() in item.lower():
                    heavy.append(item)
                    break

        return heavy
