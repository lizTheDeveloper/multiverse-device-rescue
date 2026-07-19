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
    name = "privacy_permissions_audit"
    category = "security"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "5s"

    # TCC service identifiers and display names
    TCC_SERVICES = {
        "kTCCServiceCamera": "Camera",
        "kTCCServiceMicrophone": "Microphone",
        "kTCCServiceScreenCapture": "Screen Recording",
        "kTCCServiceAccessibility": "Accessibility",
        "kTCCServiceSystemPolicyAllFiles": "Full Disk Access",
        "kTCCServiceAddressBook": "Contacts",
    }

    emits_codes = [
        "security.privacy_permissions_audit.camera_access",
        "security.privacy_permissions_audit.microphone_access",
        "security.privacy_permissions_audit.screen_recording_access",
        "security.privacy_permissions_audit.accessibility_access",
        "security.privacy_permissions_audit.full_disk_access",
        "security.privacy_permissions_audit.contacts_access",
        "security.privacy_permissions_audit.excessive_camera",
        "security.privacy_permissions_audit.excessive_microphone",
        "security.privacy_permissions_audit.camera_microphone_combo",
        "security.privacy_permissions_audit.screen_accessibility_combo",
    ]

    # Maps TCC service identifiers to their stable finding code suffix.
    SERVICE_CODE_SUFFIX = {
        "kTCCServiceCamera": "camera_access",
        "kTCCServiceMicrophone": "microphone_access",
        "kTCCServiceScreenCapture": "screen_recording_access",
        "kTCCServiceAccessibility": "accessibility_access",
        "kTCCServiceSystemPolicyAllFiles": "full_disk_access",
        "kTCCServiceAddressBook": "contacts_access",
    }

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Query both system and user TCC databases
        system_db = "/Library/Application Support/com.apple.TCC/TCC.db"
        user_db = str(Path.home() / "Library/Application Support/com.apple.TCC/TCC.db")

        # Collect all apps per service
        services_data = {}
        for service, display_name in self.TCC_SERVICES.items():
            system_apps = self._query_tcc(system_db, service)
            user_apps = self._query_tcc(user_db, service)
            all_apps = list(set(system_apps + user_apps))
            if all_apps:
                services_data[service] = {
                    "display_name": display_name,
                    "apps": sorted(all_apps),
                }

        if not services_data:
            return CheckResult(module_name=self.name, findings=[])

        # Add INFO findings for each service with apps
        for service, data in services_data.items():
            display_name = data["display_name"]
            apps = data["apps"]
            app_list = ", ".join(apps)
            check_name = self.SERVICE_CODE_SUFFIX.get(service, f"{service.lower()}_access")
            if service == "kTCCServiceCamera":
                code = "security.privacy_permissions_audit.camera_access"
            elif service == "kTCCServiceMicrophone":
                code = "security.privacy_permissions_audit.microphone_access"
            elif service == "kTCCServiceScreenCapture":
                code = "security.privacy_permissions_audit.screen_recording_access"
            elif service == "kTCCServiceAccessibility":
                code = "security.privacy_permissions_audit.accessibility_access"
            elif service == "kTCCServiceSystemPolicyAllFiles":
                code = "security.privacy_permissions_audit.full_disk_access"
            elif service == "kTCCServiceAddressBook":
                code = "security.privacy_permissions_audit.contacts_access"
            else:
                code = None
            findings.append(
                Finding(
                    title=f"{display_name} access: {len(apps)} app(s)",
                    description=(
                        f"{len(apps)} app(s) have been granted {display_name} access: "
                        f"{app_list}. "
                        f"Review in System Settings > Privacy & Security to ensure only "
                        f"trusted apps have access."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code=code,
                    data={
                        "check": check_name,
                        "service": service,
                        "display_name": display_name,
                        "apps": apps,
                    },
                )
            )

        # Check for dangerous combinations
        camera_apps = set(services_data.get("kTCCServiceCamera", {}).get("apps", []))
        microphone_apps = set(services_data.get("kTCCServiceMicrophone", {}).get("apps", []))
        screen_apps = set(services_data.get("kTCCServiceScreenCapture", {}).get("apps", []))
        accessibility_apps = set(services_data.get("kTCCServiceAccessibility", {}).get("apps", []))

        # Flag if >10 apps have camera access (surveillance risk)
        if len(camera_apps) > 10:
            findings.append(
                Finding(
                    title=f"Excessive camera access: {len(camera_apps)} app(s)",
                    description=(
                        f"{len(camera_apps)} app(s) have camera access, which exceeds "
                        "the recommended limit of 10. Having too many apps with camera access "
                        "increases surveillance risk. Review and revoke access for apps that "
                        "don't strictly need it."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.privacy_permissions_audit.excessive_camera",
                    data={
                        "check": "excessive_camera",
                        "apps": sorted(camera_apps),
                        "count": len(camera_apps),
                    },
                )
            )

        # Flag if >10 apps have microphone access
        if len(microphone_apps) > 10:
            findings.append(
                Finding(
                    title=f"Excessive microphone access: {len(microphone_apps)} app(s)",
                    description=(
                        f"{len(microphone_apps)} app(s) have microphone access, which exceeds "
                        "the recommended limit of 10. Having too many apps with microphone access "
                        "increases privacy risk. Review and revoke access for apps that "
                        "don't strictly need it."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.privacy_permissions_audit.excessive_microphone",
                    data={
                        "check": "excessive_microphone",
                        "apps": sorted(microphone_apps),
                        "count": len(microphone_apps),
                    },
                )
            )

        # Identify apps with both camera AND microphone access (surveillance risk)
        both_cam_mic = camera_apps & microphone_apps
        if both_cam_mic:
            findings.append(
                Finding(
                    title=f"Surveillance risk: {len(both_cam_mic)} app(s) with camera + microphone",
                    description=(
                        f"{len(both_cam_mic)} app(s) have both camera and microphone access: "
                        f"{', '.join(sorted(both_cam_mic))}. "
                        "Apps with both camera and microphone access pose a higher surveillance risk. "
                        "Verify these apps are legitimate and necessary, and consider revoking access "
                        "for apps you don't fully trust."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.privacy_permissions_audit.camera_microphone_combo",
                    data={
                        "check": "camera_microphone_combo",
                        "apps": sorted(both_cam_mic),
                    },
                )
            )

        # Identify apps with screen recording + accessibility (total control)
        screen_and_accessibility = screen_apps & accessibility_apps
        if screen_and_accessibility:
            findings.append(
                Finding(
                    title=f"High control risk: {len(screen_and_accessibility)} app(s) with screen recording + accessibility",
                    description=(
                        f"{len(screen_and_accessibility)} app(s) have both screen recording and accessibility access: "
                        f"{', '.join(sorted(screen_and_accessibility))}. "
                        "Apps with both screen recording and accessibility access have complete control over your system, "
                        "including the ability to see everything on screen and simulate all user interactions. "
                        "This poses severe risk. These should only be trusted applications like security software or "
                        "legitimate system tools. Investigate immediately and revoke access for any unknown apps."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.privacy_permissions_audit.screen_accessibility_combo",
                    data={
                        "check": "screen_accessibility_combo",
                        "apps": sorted(screen_and_accessibility),
                    },
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        seen_checks = set()

        for finding in findings.findings:
            check = finding.data.get("check")

            # Avoid duplicate actions for the same check type
            if check in seen_checks:
                continue
            seen_checks.add(check)

            if check and check.endswith("_access"):
                display_name = finding.data.get("display_name", "permission")
                apps = finding.data.get("apps", [])
                app_list = ", ".join(sorted(apps))
                actions.append(
                    Action(
                        title=f"Review and manage {display_name} access",
                        description=(
                            f"Apps with {display_name} access: {app_list}.\n"
                            "To manage these permissions, open System Settings > "
                            "Privacy & Security and find the relevant section. Review each app "
                            "and toggle off access for apps you don't trust or don't need."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )
            elif check == "excessive_camera":
                count = finding.data.get("count", 0)
                apps = finding.data.get("apps", [])
                app_list = ", ".join(sorted(apps))
                actions.append(
                    Action(
                        title="Reduce excessive camera access",
                        description=(
                            f"{count} app(s) have camera access: {app_list}.\n"
                            "To manage this, open System Settings > Privacy & Security > Camera. "
                            "Review each app and disable camera access for those that don't strictly need it."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )
            elif check == "excessive_microphone":
                count = finding.data.get("count", 0)
                apps = finding.data.get("apps", [])
                app_list = ", ".join(sorted(apps))
                actions.append(
                    Action(
                        title="Reduce excessive microphone access",
                        description=(
                            f"{count} app(s) have microphone access: {app_list}.\n"
                            "To manage this, open System Settings > Privacy & Security > Microphone. "
                            "Review each app and disable microphone access for those that don't strictly need it."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )
            elif check == "camera_microphone_combo":
                apps = finding.data.get("apps", [])
                app_list = ", ".join(sorted(apps))
                actions.append(
                    Action(
                        title="Review apps with both camera and microphone access",
                        description=(
                            f"Apps with both camera and microphone access: {app_list}.\n"
                            "Review System Settings > Privacy & Security > Camera and Microphone "
                            "to verify these apps are legitimate. Consider revoking access for apps "
                            "you don't fully trust."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )
            elif check == "screen_accessibility_combo":
                apps = finding.data.get("apps", [])
                app_list = ", ".join(sorted(apps))
                actions.append(
                    Action(
                        title="URGENT: Review apps with screen recording + accessibility access",
                        description=(
                            f"Apps with both screen recording and accessibility access: {app_list}.\n"
                            "These apps have complete control over your system. Verify they are legitimate: "
                            "Open System Settings > Privacy & Security > Screen Recording and Accessibility. "
                            "Revoke access immediately for any unknown or suspicious apps. Only keep access "
                            "for trusted security software or legitimate system tools."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _query_tcc(self, db_path: str, service: str) -> list[str]:
        """Query TCC database for apps with a specific service access.

        Args:
            db_path: Path to TCC.db file
            service: TCC service identifier (e.g., 'kTCCServiceCamera')

        Returns:
            List of app bundle identifiers with the specified service access.
            Returns [] on any failure (permission denied, file not found, etc).
        """
        try:
            result = subprocess.run(
                [
                    "sqlite3",
                    db_path,
                    f"SELECT client FROM access WHERE service='{service}' AND auth_value=2",
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
