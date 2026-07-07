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
                    title=f"Service running from suspicious path: {svc['name']}",
                    description=(
                        f"The service '{svc['display_name']}' ({svc['name']}) is set to "
                        f"auto-start and runs from a suspicious path: {svc['path']}. "
                        "This could indicate malware or compromised system files."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data=svc,
                )
            )

        # Flag WARNING for excessive auto-start services (>40)
        if len(auto_start_services) > 40:
            findings.append(
                Finding(
                    title=f"Excessive number of auto-start services ({len(auto_start_services)})",
                    description=(
                        f"Found {len(auto_start_services)} services set to auto-start. "
                        "A large number of auto-start services can impact system startup time "
                        "and may include unnecessary or malicious services."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"count": len(auto_start_services), "services": auto_start_services},
                )
            )

        # Flag WARNING for stopped auto-start services
        if stopped_auto_start_services:
            findings.append(
                Finding(
                    title=f"Stopped services set to auto-start ({len(stopped_auto_start_services)})",
                    description=(
                        f"Found {len(stopped_auto_start_services)} service(s) configured to auto-start "
                        "but currently stopped. This may indicate broken dependencies, missing files, "
                        "or orphaned services."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
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
            if "bloatware" in finding.title.lower():
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
