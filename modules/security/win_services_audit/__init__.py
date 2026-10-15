import subprocess
from pathlib import PureWindowsPath

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

# Known bloatware service names from manufacturers and third parties
BLOATWARE_SERVICES = {
    # HP/Hewlett-Packard
    "hpqvfxs",
    "hpqbam",
    "hpqsrmon",
    "hpqIdleEngine",
    "hpdevmgmt",
    # Dell
    "DellSystemDetect",
    "DellClientManagementService",
    "DellUEMService",
    "DellUEM",
    # Lenovo
    "Lssd",
    "LenovoStatusService",
    "LenovoCompanion",
    # Norton/Symantec
    "CCDMonitor",
    # McAfee
    "McAPExe",
    "mfefire",
    # Avast/AVG
    "avpsus",
    "avgui",
    # Other common bloatware
    "FastBootDrivers",
    "TDIService",
}

SUSPICIOUS_PATH_PATTERNS = [
    "temp",
    "appdata",
    "downloads",
    "users\\",
    "%temp%",
    "%appdata%",
]

# Known Microsoft/Windows service names
MICROSOFT_SERVICES = {
    "windefend",
    "wuauserv",
    "audiosrv",
    "audiodev",
    "dclocator",
    "dfsrepl",
    "dfsn",
    "dfsr",
    "dhcp",
    "dnscache",
    "eventlog",
    "gpsvc",
    "kdc",
    "lsass",
    "lsm",
    "netbt",
    "netdde",
    "netlogon",
    "netman",
    "nsi",
    "rpcss",
    "samss",
    "spooler",
    "srvsvc",
    "svchost",
    "system",
    "tcpip",
    "termservice",
    "w32time",
    "winmgmt",
    "bits",
    "cryptsvc",
    "ikeext",
    "iphlpsvc",
    "mpssvc",
    "wecsvc",
    "wmiApSrv",
    "wscsvc",
    "wuauserv",
    "nvagent",  # NVIDIA often preinstalled
}

MICROSOFT_VENDORS = {
    "microsoft",
    "windows",
    "intel",
    "broadcom",
    "realtek",
    "amd",
}


class Module(ModuleBase):
    name = "win_services_audit"
    category = "security"
    platforms = [Platform.WIN32]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "10s"

    emits_codes = [
        "security.win_services_audit.suspicious_path",
        "security.win_services_audit.excessive_autostart",
        "security.win_services_audit.stopped_autostart",
        "security.win_services_audit.bloatware_detected",
        "security.win_services_audit.non_microsoft_autostart",
    ]

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Get service data from PowerShell
        services_data = self._get_services_data()
        if not services_data:
            return CheckResult(module_name=self.name, findings=[])

        auto_start_services = []
        suspicious_path_services = []
        bloatware_services = []
        stopped_auto_start_services = []

        for service in services_data:
            name = service.get("Name", "").strip()
            display_name = service.get("DisplayName", "").strip()
            status = service.get("Status", "").strip()
            start_type = service.get("StartType", "").strip()
            path = service.get("PathName", "").strip()

            if not name or not start_type:
                continue

            # Check for auto-start services
            is_auto_start = start_type in ("Automatic", "Boot", "System")

            if is_auto_start:
                auto_start_services.append(name)

                # Check if it's a known bloatware service
                if name.lower() in {s.lower() for s in BLOATWARE_SERVICES}:
                    bloatware_services.append({
                        "name": name,
                        "display_name": display_name,
                    })

                # Check for suspicious paths
                if path and self._is_suspicious_path(path):
                    suspicious_path_services.append({
                        "name": name,
                        "display_name": display_name,
                        "path": path,
                    })

            # Check for stopped services set to auto-start
            if is_auto_start and status == "Stopped":
                stopped_auto_start_services.append({
                    "name": name,
                    "display_name": display_name,
                })

        # Generate findings

        # Flag WARNING for services running from suspicious locations
        for svc in suspicious_path_services:
            findings.append(
                Finding(
                    title=f"Program '{svc['display_name']}' runs from an unusual location",
                    description=(
                        f"We found a background program named '{svc['display_name']}' "
                        "that starts automatically when you turn on your computer. It "
                        "is stored in a folder that is not a standard place for such "
                        f"programs: {svc['path']}. This is not normal, but it does not "
                        "automatically mean your computer is hacked. It could be a leftover "
                        "from a past installation or a piece of software that moved itself. "
                        "Please check if you recognize this program.\n\n"
                        "What to do: If you don't recognize it, open Services (type "
                        "services.msc in the Start menu), double-click it, and set "
                        "Startup type to Disabled. Don't delete its file; an expert may "
                        "want to look at it."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.win_services_audit.suspicious_path",
                    data=svc,
                )
            )

        # Flag WARNING for excessive auto-start services (>40)
        if len(auto_start_services) > 40:
            findings.append(
                Finding(
                    title=f"Many programs start automatically ({len(auto_start_services)})",
                    description=(
                        f"Your computer is set to start {len(auto_start_services)} different "
                        "background programs every time you turn it on. This is a lot. "
                        "It can make your computer take longer to boot up and use more "
                        "battery.\n\n"
                        "What to do: Nothing urgent. Leave services alone unless a "
                        "technical helper suggests a change. For apps, open Task Manager "
                        "(Ctrl+Shift+Esc) > Startup apps and turn off ones you don't use."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.win_services_audit.excessive_autostart",
                    data={"count": len(auto_start_services), "services": auto_start_services},
                )
            )

        # Flag WARNING for stopped auto-start services
        if stopped_auto_start_services:
            findings.append(
                Finding(
                    title=(
                        f"{len(stopped_auto_start_services)} programs are set to start "
                        "but are currently off"
                    ),
                    description=(
                        f"We found {len(stopped_auto_start_services)} background programs "
                        "that are set to start automatically, but they are currently "
                        "stopped. This usually happens when a program is missing a file "
                        "it needs or was uninstalled incorrectly. It is likely harmless, "
                        "but it can cause small errors or slow down your computer slightly.\n\n"
                        "What to do: You can usually ignore this. If you want to clean "
                        "it up, open 'Services' (type 'services.msc' in the Start menu), "
                        "find the listed programs, and change their 'Startup type' to "
                        "'Manual'. This stops them from trying to start and failing."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.win_services_audit.stopped_autostart",
                    data={
                        "count": len(stopped_auto_start_services),
                        "services": stopped_auto_start_services,
                    },
                )
            )

        # Flag INFO listing bloatware services
        if bloatware_services:
            findings.append(
                Finding(
                    title=f"Detected {len(bloatware_services)} bloatware service(s)",
                    description=(
                        f"Found {len(bloatware_services)} known bloatware or pre-installed manufacturer service(s) "
                        "set to auto-start. These services consume resources and may not be necessary."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.win_services_audit.bloatware_detected",
                    data={
                        "count": len(bloatware_services),
                        "services": bloatware_services,
                    },
                )
            )

        # Flag INFO listing non-Microsoft auto-start services
        non_microsoft_auto_start = self._filter_non_microsoft(auto_start_services)
        if non_microsoft_auto_start and not bloatware_services:
            # Only report if we didn't already report bloatware
            findings.append(
                Finding(
                    title=f"Found {len(non_microsoft_auto_start)} non-Microsoft auto-start service(s)",
                    description=(
                        f"Detected {len(non_microsoft_auto_start)} third-party services set to auto-start. "
                        "Review these to ensure they are necessary."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.win_services_audit.non_microsoft_autostart",
                    data={
                        "count": len(non_microsoft_auto_start),
                        "services": non_microsoft_auto_start,
                    },
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            if finding.code == "security.win_services_audit.bloatware_detected":
                services = finding.data.get("services", [])
                for svc in services:
                    name = svc.get("name", "") if isinstance(svc, dict) else svc
                    actions.append(
                        Action(
                            title=f"Disable bloatware service: {name}",
                            description=(
                                f"To disable the service '{name}', open services.msc, "
                                f"find '{name}', right-click and select 'Properties', "
                                "then set 'Startup type' to 'Disabled' and click 'Stop'."
                            ),
                            risk_level=RiskLevel.SAFE,
                            success=True,
                            data={"service_name": name},
                        )
                    )
        return FixResult(module_name=self.name, actions=actions)

    def _get_services_data(self) -> list[dict]:
        """Fetch service information using PowerShell."""
        try:
            # Use PowerShell to get service details
            script = (
                "$services = Get-Service | Select-Object Name, DisplayName, Status, StartType; "
                "$output = @(); "
                "foreach ($svc in $services) { "
                "  $wmi = Get-WmiObject Win32_Service -Filter \"Name='$($svc.Name)'\" 2>$null; "
                "  $output += @{ "
                "    Name = $svc.Name; "
                "    DisplayName = $svc.DisplayName; "
                "    Status = $svc.Status; "
                "    StartType = $svc.StartType; "
                "    PathName = if ($wmi) { $wmi.PathName } else { '' } "
                "  } "
                "}; "
                "$output | ConvertTo-Json"
            )

            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", script],
                capture_output=True,
                text=True,
                timeout=30,
            )

            if result.returncode != 0:
                return []

            # Parse JSON output
            import json
            try:
                data = json.loads(result.stdout)
                # Ensure we have a list
                if isinstance(data, dict):
                    data = [data]
                elif not isinstance(data, list):
                    return []
                return data
            except (json.JSONDecodeError, ValueError):
                return []

        except (OSError, subprocess.SubprocessError, subprocess.TimeoutExpired):
            return []

    def _is_suspicious_path(self, path: str) -> bool:
        """Check if a service path looks suspicious."""
        if not path:
            return False

        path_lower = path.lower()

        # Remove quoted paths
        if path_lower.startswith('"'):
            path_lower = path_lower.lstrip('"')

        for pattern in SUSPICIOUS_PATH_PATTERNS:
            if pattern in path_lower:
                return True

        return False

    def _filter_non_microsoft(self, service_names: list[str]) -> list[str]:
        """Filter out Microsoft services from a list."""
        non_microsoft = []
        for name in service_names:
            name_lower = name.lower()
            # Check if it's in the known Microsoft services list
            if name_lower in MICROSOFT_SERVICES:
                continue
            # Check if name contains Microsoft vendor keywords
            is_microsoft = any(
                vendor in name_lower for vendor in MICROSOFT_VENDORS
            )
            if not is_microsoft:
                non_microsoft.append(name)
        return non_microsoft
