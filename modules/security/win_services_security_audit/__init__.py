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
                        title=f"Service with unquoted path containing spaces: {display_name}",
                        description=(
                            f"Service '{display_name}' ({name}) has an unquoted path with spaces: {path}\n"
                            f"This is a privilege escalation vulnerability (CVE classic). "
                            f"A lower-privileged user could place a malicious executable "
                            f"in an earlier directory in the path to hijack the service."
                        ),
                        severity=Severity.CRITICAL,
                        category=self.category,
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
                            title=f"Service running from user-writable directory: {display_name}",
                            description=(
                                f"Service '{display_name}' ({name}) binary is located in a "
                                f"user-writable directory: {clean_path}\n"
                                f"This allows an unprivileged user to potentially modify the "
                                f"service binary and achieve privilege escalation."
                            ),
                            severity=Severity.WARNING,
                            category=self.category,
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
                    title=f"Third-party service running as LocalSystem: {display_name}",
                    description=(
                        f"Service '{display_name}' ({name}) is running as LocalSystem. "
                        f"This grants the service full system privileges. "
                        f"Verify that this service actually requires LocalSystem privileges, "
                        f"and consider running it under a dedicated low-privileged service account."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
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
                        title=f"Auto-start service stopped: {display_name}",
                        description=(
                            f"Service '{display_name}' ({name}) is configured to auto-start "
                            f"({start_mode}) but is currently {state}. "
                            f"This may indicate the service crashed or is experiencing issues."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
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
            data={
                "check_type": "summary",
                "total_services": total,
                "by_state": by_state,
                "by_start_mode": by_start_mode,
            },
        )
