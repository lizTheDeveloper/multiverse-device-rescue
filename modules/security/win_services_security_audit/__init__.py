import json
import subprocess

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

# Common system services that are expected to run as LocalSystem
EXPECTED_LOCALSYSTEM_SERVICES = {
    "System",
    "Registry",
    "csrss",
    "lsass",
    "services",
    "lsm",
    "winlogon",
    "svchost",
    "spoolsv",
    "SearchIndexer",
    "Winmgmt",
    "PolicyAgent",
    "ProtectedStorage",
    "RemoteRegistry",
    "SecurityHealthService",
}

# User-writable directories to check for
USER_WRITABLE_DIRS = [
    "\\AppData\\",
    "\\Temp\\",
    "\\Downloads\\",
    "\\Documents\\",
]


class Module(ModuleBase):
    name = "win_services_security_audit"
    category = "security"
    platforms = [Platform.WIN32]
    risk_level = RiskLevel.SAFE
    priority = 55
    depends_on = []
    estimated_duration = "10s"

    emits_codes = [
        "security.win_services_security_audit.unquoted_path",
        "security.win_services_security_audit.user_writable_dir",
        "security.win_services_security_audit.overprivileged",
        "security.win_services_security_audit.stopped_auto_start",
        "security.win_services_security_audit.summary",
    ]

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Get service information
        services = self._get_services_info()
        if not services:
            return CheckResult(module_name=self.name, findings=findings)

        # Check for unquoted paths with spaces
        unquoted_findings = self._check_unquoted_paths(services)
        findings.extend(unquoted_findings)

        # Check for services running from user-writable directories
        writable_dir_findings = self._check_user_writable_dirs(services)
        findings.extend(writable_dir_findings)

        # Check for overprivileged services
        overprivileged_findings = self._check_overprivileged_services(services)
        findings.extend(overprivileged_findings)

        # Check for stopped auto-start services
        stopped_auto_findings = self._check_stopped_auto_start_services(services)
        findings.extend(stopped_auto_findings)

        # Add service summary as INFO
        summary = self._generate_service_summary(services)
        findings.append(summary)

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        for finding in findings.findings:
            check_type = finding.data.get("check_type")

            if check_type == "unquoted_path":
                service_name = finding.data.get("service_name", "")
                path = finding.data.get("path", "")
                actions.append(
                    Action(
                        title=f"Fix unquoted path for service '{service_name}'",
                        description=(
                            f"Service '{service_name}' has an unquoted path with spaces: {path}\n"
                            f"To fix, run (as Administrator):\n"
                            f"  powershell -Command \"& {{$svc = Get-WmiObject Win32_Service "
                            f"-Filter 'Name=\\\"{service_name}\\\"'; "
                            f"$svc.Change($null, '\\\"$($svc.PathName)\\\"\\''); }}\"\n"
                            f"Or use the Registry Editor to modify "
                            f"HKLM\\System\\CurrentControlSet\\Services\\{service_name}\\ImagePath"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=False,
                    )
                )

            elif check_type == "user_writable_dir":
                service_name = finding.data.get("service_name", "")
                path = finding.data.get("path", "")
                actions.append(
                    Action(
                        title=f"Review service '{service_name}' in user-writable directory",
                        description=(
                            f"Service '{service_name}' binary is located in user-writable path: {path}\n"
                            f"This could allow privilege escalation if an unprivileged user "
                            f"modifies the binary.\n"
                            f"Action: Move the service binary to a system-protected directory "
                            f"(e.g., C:\\Program Files or C:\\Windows\\System32) and update "
                            f"the service configuration."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=False,
                    )
                )

            elif check_type == "overprivileged":
                service_name = finding.data.get("service_name", "")
                actions.append(
                    Action(
                        title=f"Review service account for '{service_name}'",
                        description=(
                            f"Service '{service_name}' is running as LocalSystem but may not require "
                            f"that privilege level.\n"
                            f"Action: Review whether this service truly needs LocalSystem privileges. "
                            f"Consider running it under a dedicated service account with minimal "
                            f"required permissions."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=False,
                    )
                )

            elif check_type == "stopped_auto_start":
                service_name = finding.data.get("service_name", "")
                actions.append(
                    Action(
                        title=f"Investigate stopped auto-start service '{service_name}'",
                        description=(
                            f"Service '{service_name}' is set to auto-start (Automatic or "
                            f"Automatic Delayed Start) but is currently stopped.\n"
                            f"This may indicate a crash or missing dependency.\n"
                            f"Action: Check the System Event Log for errors, verify dependencies, "
                            f"and review the service binary integrity."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=False,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _get_services_info(self) -> list[dict]:
        """Get Windows services info using PowerShell."""
        try:
            result = subprocess.run(
                [
                    "powershell",
                    "-Command",
                    (
                        "Get-WmiObject Win32_Service | Select-Object Name, DisplayName, "
                        "PathName, StartMode, State, StartName | ConvertTo-Json"
                    ),
                ],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode != 0:
                return []
            output = result.stdout.strip()
            if not output:
                return []
            services = json.loads(output)
            # Handle case where only one service is returned (not an array)
            if isinstance(services, dict):
                services = [services]
            return services if isinstance(services, list) else []
        except (OSError, subprocess.SubprocessError, json.JSONDecodeError, ValueError):
            return []

    def _check_unquoted_paths(self, services: list[dict]) -> list[Finding]:
        """Check for services with unquoted paths containing spaces."""
        findings = []
        for svc in services:
            path = svc.get("PathName", "").strip()
            if not path:
                continue
            # Check if path is unquoted and contains spaces
            if not path.startswith('"') and " " in path:
                name = svc.get("Name", "Unknown")
                display_name = svc.get("DisplayName", name)
                findings.append(
                    Finding(
                        title=(
                            f"Service '{display_name}' has a path with spaces that is "
                            "not protected"
                        ),
                        description=(
                            f"The background program '{display_name}' ({name}) is saved "
                            "in a folder with spaces in its name, but the path is not "
                            f"enclosed in quotes: {path}. This is a technical gap that "
                            "can be dangerous. Because the path is not properly protected, "
                            "a malicious program could potentially trick your computer "
                            "into running a fake version of this service instead of the "
                            "real one.\n\n"
                            "What to do: This usually requires a system administrator "
                            "to fix. Search for 'Services' in the Start menu, right-click "
                            f"'{display_name}', select 'Properties', and check the 'Path "
                            "to service executable' field. If you are not comfortable "
                            "editing this, please ask a trusted IT professional to help "
                            "you add quotes around the path."
                        ),
                        severity=Severity.CRITICAL,
                        category=self.category,
                        code="security.win_services_security_audit.unquoted_path",
                        data={
                            "check_type": "unquoted_path",
                            "service_name": name,
                            "display_name": display_name,
                            "path": path,
                        },
                    )
                )
        return findings

    def _check_user_writable_dirs(self, services: list[dict]) -> list[Finding]:
        """Check for services running from user-writable directories."""
        findings = []
        for svc in services:
            path = svc.get("PathName", "").strip()
            if not path:
                continue
            # Remove quotes and arguments from path
            clean_path = path.strip('"').split(" ")[0]
            for writable_dir in USER_WRITABLE_DIRS:
                if writable_dir.lower() in clean_path.lower():
                    name = svc.get("Name", "Unknown")
                    display_name = svc.get("DisplayName", name)
                    findings.append(
                        Finding(
                            title=(
                                f"Service '{display_name}' is stored in a folder anyone can change"
                            ),
                            description=(
                                f"The program '{display_name}' ({name}) is saved in a "
                                "location where regular users can easily modify files: "
                                f"{clean_path}. Normally, important system programs are "
                                "stored in protected folders. Because this one is in "
                                "an open folder, a malicious program could potentially "
                                "replace it with a fake version to gain more power on "
                                "your computer.\n\n"
                                "What to do: Check if this is a standard Windows service "
                                "or a third-party app. If it is a third-party app, look "
                                "for an official installer to reinstall it, which usually "
                                "moves it to a safer, protected folder. Do not delete "
                                "the file manually, as this might break the app."
                            ),
                            severity=Severity.WARNING,
                            category=self.category,
                            code="security.win_services_security_audit.user_writable_dir",
                            data={
                                "check_type": "user_writable_dir",
                                "service_name": name,
                                "display_name": display_name,
                                "path": clean_path,
                            },
                        )
                    )
                    break
        return findings

    def _check_overprivileged_services(self, services: list[dict]) -> list[Finding]:
        """Check for services running as LocalSystem that may be overprivileged."""
        findings = []
        for svc in services:
            start_name = svc.get("StartName", "").strip()
            if not start_name or start_name.upper() != "LOCALSYSTEM":
                continue
            name = svc.get("Name", "Unknown")
            if name in EXPECTED_LOCALSYSTEM_SERVICES:
                continue
            display_name = svc.get("DisplayName", name)
            # Flag suspicious third-party services running as LocalSystem
            findings.append(
                Finding(
                    title=f"Service '{display_name}' runs with full system privileges",
                    description=(
                        f"Your computer runs a background program called '{display_name}' "
                        f"({name}) with the highest level of access, known as LocalSystem. "
                        "This is common for system tools, but less common for third-party "
                        "apps. Running with full access is risky because if this app "
                        "has a flaw, a bad actor could use it to control your whole computer.\n\n"
                        "What to do: If you recognize the app, keep it updated; that's "
                        "the main protection. If you don't, look it up before changing "
                        "anything, since changing a service's account can break it."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.win_services_security_audit.overprivileged",
                    data={
                        "check_type": "overprivileged",
                        "service_name": name,
                        "display_name": display_name,
                    },
                )
            )
        return findings

    def _check_stopped_auto_start_services(self, services: list[dict]) -> list[Finding]:
        """Check for auto-start services that are stopped (may indicate crash)."""
        findings = []
        for svc in services:
            start_mode = svc.get("StartMode", "").strip()
            state = svc.get("State", "").strip()
            # Check if it's supposed to auto-start but is stopped
            if start_mode in ("Automatic", "Automatic (Delayed Start)") and state != "Running":
                name = svc.get("Name", "Unknown")
                display_name = svc.get("DisplayName", name)
                findings.append(
                    Finding(
                        title=f"Service '{display_name}' is supposed to start but is stopped",
                        description=(
                            f"The program '{display_name}' ({name}) is set to start automatically "
                            f"when you turn on your computer ({start_mode}), but it is "
                            f"currently {state}. This often happens if the program crashed "
                            "or if a recent update broke it. It just means this specific "
                            "background task is not running right now.\n\n"
                            "What to do: Search for 'Services' in the Start menu, find "
                            f"'{display_name}', right-click it, and select 'Start'. If "
                            "it starts and stays running, you are likely fine. If it "
                            "stops again, check the app's website for updates or known "
                            "issues."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        code="security.win_services_security_audit.stopped_auto_start",
                        data={
                            "check_type": "stopped_auto_start",
                            "service_name": name,
                            "display_name": display_name,
                            "start_mode": start_mode,
                            "state": state,
                        },
                    )
                )
        return findings

    def _generate_service_summary(self, services: list[dict]) -> Finding:
        """Generate a summary of services by state and start type."""
        total = len(services)
        by_state = {}
        by_start_mode = {}

        for svc in services:
            state = svc.get("State", "Unknown").strip()
            start_mode = svc.get("StartMode", "Unknown").strip()

            by_state[state] = by_state.get(state, 0) + 1
            by_start_mode[start_mode] = by_start_mode.get(start_mode, 0) + 1

        state_str = ", ".join(f"{k}: {v}" for k, v in sorted(by_state.items()))
        start_str = ", ".join(f"{k}: {v}" for k, v in sorted(by_start_mode.items()))

        return Finding(
            title="Windows services audit summary",
            description=(
                f"Total services: {total}\n"
                f"By state: {state_str}\n"
                f"By start mode: {start_str}"
            ),
            severity=Severity.INFO,
            category=self.category,
            code="security.win_services_security_audit.summary",
            data={
                "check_type": "summary",
                "total_services": total,
                "by_state": by_state,
                "by_start_mode": by_start_mode,
            },
        )
