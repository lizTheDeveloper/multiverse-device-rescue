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

# Thresholds
WARNING_SERVICE_COUNT = 100

# Known bloatware service patterns
BLOATWARE_PATTERNS = [
    "Update",  # Third-party app updates
    "Telemetry",
    "OneNote",
    "Cortana",
    "DiagTrack",  # Diagnostic Tracking
    "dmwappushservice",
    "WifiDirectSvc",
    "AppReadiness",
    "StorageSpacesSvc",
]


class Module(ModuleBase):
    name = "win_services_audit"
    category = "performance"
    platforms = [Platform.WIN32]
    risk_level = RiskLevel.SAFE
    priority = 60
    depends_on = []
    estimated_duration = "10s"

    def check(self, profile: SystemProfile) -> CheckResult:
        services = self._get_all_services()
        running_services = [s for s in services if s.get("Status") == "Running"]
        stopped_auto_services = [
            s for s in services
            if s.get("Status") == "Stopped" and s.get("StartType") == "Automatic"
        ]
        bloatware_services = [
            s for s in services
            if self._is_bloatware(s.get("Name", ""))
        ]

        findings = []

        # Service count summary
        findings.append(
            Finding(
                title=f"{len(running_services)} services running",
                description=(
                    f"Total services running: {len(running_services)}. "
                    f"Each service consumes memory and CPU. "
                    f"Fewer is better for performance."
                ),
                severity=Severity.INFO,
                category=self.category,
                data={
                    "type": "service_count",
                    "count": len(running_services),
                },
            )
        )

        # Warning for high service count
        if len(running_services) >= WARNING_SERVICE_COUNT:
            findings.append(
                Finding(
                    title=f"High number of running services ({len(running_services)})",
                    description=(
                        f"{len(running_services)} services are running. "
                        "This is unusually high and may impact performance. "
                        "Review and disable unnecessary services."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "type": "high_service_count",
                        "count": len(running_services),
                    },
                )
            )

        # Warning for stopped automatic services
        if stopped_auto_services:
            names = [s.get("Name", "") for s in stopped_auto_services]
            findings.append(
                Finding(
                    title=f"{len(stopped_auto_services)} automatic services are stopped",
                    description=(
                        f"{len(stopped_auto_services)} service(s) set to start automatically "
                        "are currently stopped. This may indicate a crash or configuration issue: "
                        f"{', '.join(names[:3])}{'...' if len(names) > 3 else ''}"
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "type": "stopped_auto_services",
                        "count": len(stopped_auto_services),
                        "names": names,
                    },
                )
            )

        # Info for bloatware services
        if bloatware_services:
            names = [s.get("Name", "") for s in bloatware_services]
            findings.append(
                Finding(
                    title=f"{len(bloatware_services)} potential bloatware services",
                    description=(
                        f"{len(bloatware_services)} service(s) appear to be bloatware or telemetry. "
                        f"Examples: {', '.join(names[:3])}{'...' if len(names) > 3 else ''}. "
                        "Consider disabling these via Services.msc."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "type": "bloatware_services",
                        "count": len(bloatware_services),
                        "names": names,
                    },
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            finding_type = finding.data.get("type")

            if finding_type == "service_count":
                actions.append(
                    Action(
                        title="Service count report",
                        description=(
                            f"Total running services: {finding.data.get('count', 0)}. "
                            "Open Services.msc (services.msc) and review each service. "
                            "Disable services you don't recognize or need."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif finding_type == "high_service_count":
                actions.append(
                    Action(
                        title="High service count detected",
                        description=(
                            f"{finding.data.get('count', 0)} services running is excessive. "
                            "Open Services.msc and disable: non-essential Microsoft services, "
                            "printer/scanner drivers if not used, remote desktop if not needed, "
                            "telemetry services."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif finding_type == "stopped_auto_services":
                names = finding.data.get("names", [])
                preview = ", ".join(names[:3])
                if len(names) > 3:
                    preview += ", ..."
                actions.append(
                    Action(
                        title="Stopped automatic services found",
                        description=(
                            f"These services are set to start automatically but are stopped: {preview}. "
                            "This may indicate a problem. Check Event Viewer for crash logs or "
                            "try restarting them via Services.msc."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif finding_type == "bloatware_services":
                names = finding.data.get("names", [])
                preview = ", ".join(names[:3])
                if len(names) > 3:
                    preview += ", ..."
                actions.append(
                    Action(
                        title="Bloatware services detected",
                        description=(
                            f"Consider disabling these services: {preview}. "
                            "Right-click each in Services.msc > Properties, set Startup Type to Disabled, "
                            "then click Stop."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _get_all_services(self) -> list[dict[str, str]]:
        """Get all services (running and stopped) via PowerShell."""
        try:
            ps_script = "Get-Service | Select-Object Name, DisplayName, Status, StartType | Format-List"
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_script],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                return []
            return _parse_powershell_service_output(result.stdout)
        except (OSError, subprocess.SubprocessError):
            return []

    def _is_bloatware(self, service_name: str) -> bool:
        """Check if a service name matches known bloatware patterns."""
        service_lower = service_name.lower()
        return any(pattern.lower() in service_lower for pattern in BLOATWARE_PATTERNS)


def _parse_powershell_service_output(output: str) -> list[dict[str, str]]:
    """Parse PowerShell Get-Service output in Format-List format.

    Example::

        Name        : AdobeARMservice
        DisplayName : Adobe Acrobat Update Service
        Status      : Running
        StartType   : Automatic

        Name        : AdobeFlashPlayerUpdateSvc
        DisplayName : Adobe Flash Player Update Service
        Status      : Stopped
        StartType   : Automatic
    """
    services: list[dict[str, str]] = []
    current: dict[str, str] = {}

    for line in output.splitlines():
        line = line.strip()
        if not line:
            if current:
                services.append(current)
                current = {}
            continue

        if ":" in line:
            key, _, value = line.partition(":")
            key = key.strip()
            value = value.strip()
            current[key] = value

    if current:
        services.append(current)

    return services
