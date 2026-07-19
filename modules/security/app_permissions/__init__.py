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
    name = "app_permissions"
    category = "security"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "5s"

    emits_codes = [
        "security.app_permissions.accessibility_access",
        "security.app_permissions.full_disk_access",
        "security.app_permissions.screen_recording",
        "security.app_permissions.camera_access",
        "security.app_permissions.microphone_access",
    ]

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Query both system and user TCC databases
        system_db = "/Library/Application Support/com.apple.TCC/TCC.db"
        user_db = str(Path.home() / "Library/Application Support/com.apple.TCC/TCC.db")

        system_rows = self._query_tcc(system_db)
        user_rows = self._query_tcc(user_db)

        # Combine and bucket by service
        all_rows = system_rows + user_rows
        services = {
            "kTCCServiceAccessibility": [],
            "kTCCServiceSystemPolicyAllFiles": [],
            "kTCCServiceScreenCapture": [],
            "kTCCServiceCamera": [],
            "kTCCServiceMicrophone": [],
        }

        seen_pairs = set()  # Deduplicate (client, service) pairs across DBs
        for client, service, auth_value in all_rows:
            if service in services and (client, service) not in seen_pairs:
                services[service].append(client)
                seen_pairs.add((client, service))

        # Flag INFO for each service with apps
        if services["kTCCServiceAccessibility"]:
            apps = services["kTCCServiceAccessibility"]
            count = len(apps)
            severity = Severity.WARNING if count > 10 else Severity.INFO
            findings.append(
                Finding(
                    title=f"Accessibility access: {count} app(s)",
                    description=(
                        f"{count} app(s) have been granted Accessibility access: "
                        f"{', '.join(sorted(apps))}. "
                        "Accessibility access is a powerful permission that allows "
                        "apps to control your system. Review to ensure only trusted "
                        "apps have this access."
                    ),
                    severity=severity,
                    category=self.category,
                    code="security.app_permissions.accessibility_access",
                    data={"check": "accessibility_access", "apps": apps},
                )
            )

        if services["kTCCServiceSystemPolicyAllFiles"]:
            apps = services["kTCCServiceSystemPolicyAllFiles"]
            findings.append(
                Finding(
                    title=f"Full Disk Access: {len(apps)} app(s)",
                    description=(
                        f"{len(apps)} app(s) have been granted Full Disk Access: "
                        f"{', '.join(sorted(apps))}. "
                        "Full Disk Access allows apps to read all files on your system. "
                        "Review to ensure only necessary apps have this permission."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.app_permissions.full_disk_access",
                    data={"check": "full_disk_access", "apps": apps},
                )
            )

        if services["kTCCServiceScreenCapture"]:
            apps = services["kTCCServiceScreenCapture"]
            findings.append(
                Finding(
                    title=f"Screen Recording: {len(apps)} app(s)",
                    description=(
                        f"{len(apps)} app(s) have been granted Screen Recording permission: "
                        f"{', '.join(sorted(apps))}. "
                        "Screen Recording allows apps to capture your screen content. "
                        "Review to ensure you trust these apps."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.app_permissions.screen_recording",
                    data={"check": "screen_recording", "apps": apps},
                )
            )

        if services["kTCCServiceCamera"]:
            apps = services["kTCCServiceCamera"]
            findings.append(
                Finding(
                    title=f"Camera access: {len(apps)} app(s)",
                    description=(
                        f"{len(apps)} app(s) have been granted Camera access: "
                        f"{', '.join(sorted(apps))}. "
                        "Review to ensure you trust these apps with access to your camera."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.app_permissions.camera_access",
                    data={"check": "camera_access", "apps": apps},
                )
            )

        if services["kTCCServiceMicrophone"]:
            apps = services["kTCCServiceMicrophone"]
            findings.append(
                Finding(
                    title=f"Microphone access: {len(apps)} app(s)",
                    description=(
                        f"{len(apps)} app(s) have been granted Microphone access: "
                        f"{', '.join(sorted(apps))}. "
                        "Review to ensure you trust these apps with access to your microphone."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.app_permissions.microphone_access",
                    data={"check": "microphone_access", "apps": apps},
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            check = finding.data.get("check")
            apps = finding.data.get("apps", [])
            app_list = ", ".join(sorted(apps))

            if check == "accessibility_access":
                actions.append(
                    Action(
                        title="Review and manage Accessibility access",
                        description=(
                            f"Apps with Accessibility access: {app_list}.\n"
                            "To manage Accessibility permissions, open System Settings > "
                            "Privacy & Security > Accessibility. Review each app and "
                            "toggle off access for apps you don't trust."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )
            elif check == "full_disk_access":
                actions.append(
                    Action(
                        title="Review and manage Full Disk Access",
                        description=(
                            f"Apps with Full Disk Access: {app_list}.\n"
                            "To manage Full Disk Access, open System Settings > "
                            "Privacy & Security > Full Disk Access. Remove access "
                            "for apps that don't need to read all files."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )
            elif check == "screen_recording":
                actions.append(
                    Action(
                        title="Review and manage Screen Recording permission",
                        description=(
                            f"Apps with Screen Recording access: {app_list}.\n"
                            "To manage Screen Recording, open System Settings > "
                            "Privacy & Security > Screen Recording. Remove access "
                            "for apps you don't trust with screen content."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )
            elif check == "camera_access":
                actions.append(
                    Action(
                        title="Review and manage Camera access",
                        description=(
                            f"Apps with Camera access: {app_list}.\n"
                            "To manage Camera access, open System Settings > "
                            "Privacy & Security > Camera. Remove access for apps "
                            "that don't need camera access."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )
            elif check == "microphone_access":
                actions.append(
                    Action(
                        title="Review and manage Microphone access",
                        description=(
                            f"Apps with Microphone access: {app_list}.\n"
                            "To manage Microphone access, open System Settings > "
                            "Privacy & Security > Microphone. Remove access for apps "
                            "that don't need microphone access."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _query_tcc(self, db_path: str) -> list[tuple[str, str, str]]:
        """Query TCC database for all granted permissions.

        Returns list of (client, service, auth_value) tuples.
        Returns [] on any failure (permission denied, file not found, etc).
        """
        try:
            result = subprocess.run(
                ["sqlite3", db_path, "SELECT client, service, auth_value FROM access WHERE auth_value=2"],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                return []
            rows = []
            for line in result.stdout.strip().split("\n"):
                if not line:
                    continue
                parts = line.split("|")
                if len(parts) >= 3:
                    client, service, auth_value = parts[0], parts[1], parts[2]
                    rows.append((client, service, auth_value))
            return rows
        except OSError:
            return []
        except Exception:
            return []
