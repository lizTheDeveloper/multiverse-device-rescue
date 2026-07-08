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

# Known bloatware and performance-impacting startup items
BLOATWARE_PATTERNS = {
    "onedrive",
    "teams",
    "skype",
    "cortana",
    "groove",
    "maps",
    "feedback",
    "xbox",
    "nvidia",
    "amd",
    "corsair",
    "razer",
    "logitech",
    "discord",
    "steam",
    "dropbox",
    "google drive",
    "bitdefender",
    "kaspersky",
    "mcafee",
    "avast",
    "avira",
}

# Suspicious paths that indicate malware/adware
SUSPICIOUS_PATHS = {
    r"\appdata\local\temp",
    r"\appdata\roaming\temp",
    r"\users\*\downloads",
    r"\temp\",
    r"\programdata\temp",
    r":\$recycle",
}


class Module(ModuleBase):
    name = "win_startup_programs_audit"
    category = "performance"
    platforms = [Platform.WIN32]
    risk_level = RiskLevel.SAFE
    priority = 60
    depends_on = []
    estimated_duration = "10s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Collect all startup items from various sources
        startup_items = self._collect_startup_items()

        if not startup_items:
            findings.append(
                Finding(
                    title="Could not enumerate startup programs",
                    description="Unable to query startup programs from registry, PowerShell, or Task Scheduler.",
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "enumeration_failed"},
                )
            )
            return CheckResult(module_name=self.name, findings=findings)

        # Count total startup items
        total_items = len(startup_items)
        excessive_count = total_items > 15

        # Analyze startup items
        bloatware_items = []
        suspicious_path_items = []

        for item in startup_items:
            name_lower = item.get("name", "").lower()
            command_lower = item.get("command", "").lower()
            path_lower = item.get("path", "").lower()

            # Check for bloatware
            if any(pattern in name_lower or pattern in command_lower for pattern in BLOATWARE_PATTERNS):
                bloatware_items.append(item)

            # Check for suspicious paths
            if any(pattern in path_lower for pattern in SUSPICIOUS_PATHS):
                suspicious_path_items.append(item)

        # Flag WARNING for excessive startup programs
        if excessive_count:
            findings.append(
                Finding(
                    title=f"Excessive startup programs: {total_items} items (>15)",
                    description=(
                        f"Your system has {total_items} startup items, which is unusually high. "
                        "Too many startup programs significantly slow down boot time and system responsiveness. "
                        "Consider disabling unnecessary items via Task Manager (Startup tab) or Services (msconfig)."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "check": "excessive_count",
                        "count": total_items,
                        "threshold": 15,
                    },
                )
            )

        # Flag WARNING for suspicious paths
        if suspicious_path_items:
            findings.append(
                Finding(
                    title=f"Found {len(suspicious_path_items)} startup item(s) in suspicious paths",
                    description=(
                        "Startup items running from temporary or download directories may indicate malware or adware. "
                        "Items: " + ", ".join([f"{i['name']}" for i in suspicious_path_items[:3]])
                        + ("..." if len(suspicious_path_items) > 3 else "")
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "check": "suspicious_paths",
                        "items": suspicious_path_items,
                    },
                )
            )

        # Flag WARNING for known performance-impacting bloatware
        if bloatware_items:
            findings.append(
                Finding(
                    title=f"Found {len(bloatware_items)} potentially unnecessary startup item(s)",
                    description=(
                        "These startup items are known to impact boot/system performance: "
                        + ", ".join([f"{i['name']}" for i in bloatware_items[:3]])
                        + ("..." if len(bloatware_items) > 3 else "")
                        + "\nConsider disabling via Task Manager Startup tab or Services settings."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "check": "bloatware_detected",
                        "items": bloatware_items,
                    },
                )
            )

        # Flag INFO listing all startup programs
        findings.append(
            Finding(
                title=f"Startup programs audit: {total_items} item(s) found",
                description=(
                    f"Total startup programs detected: {total_items}\n"
                    f"  From Win32_StartupCommand: {len([i for i in startup_items if i.get('source') == 'Win32_StartupCommand'])}\n"
                    f"  From Registry (HKCU Run): {len([i for i in startup_items if i.get('source') == 'registry_user'])}\n"
                    f"  From Registry (HKLM Run): {len([i for i in startup_items if i.get('source') == 'registry_system'])}\n"
                    f"  From Startup folders: {len([i for i in startup_items if i.get('source') == 'startup_folder'])}\n"
                    f"  From Task Scheduler: {len([i for i in startup_items if i.get('source') == 'task_scheduler'])}"
                ),
                severity=Severity.INFO,
                category=self.category,
                data={
                    "check": "startup_programs_list",
                    "total_count": total_items,
                    "items": startup_items,
                },
            )
        )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        """
        Provide informational actions for startup program optimization.
        This is a diagnostic tool - it reports startup items but does NOT modify the system.
        """
        actions = []

        for finding in findings.findings:
            check = finding.data.get("check")

            if check == "excessive_count":
                count = finding.data.get("count", 0)
                actions.append(
                    Action(
                        title="Reduce excessive startup programs",
                        description=(
                            f"You have {count} startup items. To improve boot time:\n"
                            "1. Open Task Manager (Ctrl+Shift+Esc) and go to Startup tab\n"
                            "2. Right-click unnecessary programs and select Disable\n"
                            "3. Alternatively, open Services (services.msc) and disable startup services\n"
                            "4. Be careful not to disable essential Windows services (Windows Update, Defender, etc.)\n"
                            "Target: Reduce to <10 startup programs for optimal performance"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=False,
                        error="Manual action required in Task Manager or Services",
                    )
                )

            elif check == "suspicious_paths":
                items = finding.data.get("items", [])
                if items:
                    sample_items = items[:2]
                    actions.append(
                        Action(
                            title="Review startup items in suspicious paths",
                            description=(
                                "The following startup items are running from temporary/download directories:\n"
                                + "\n".join([f"  - {i['name']} ({i.get('path', 'unknown')})" for i in sample_items])
                                + "\n\nThese may be malware or adware. Recommendations:\n"
                                "1. Search the file path in Windows Defender or VirusTotal\n"
                                "2. If malicious, use Malwarebytes or Windows Defender Offline scan\n"
                                "3. Disable or uninstall the suspicious application\n"
                                "4. Consider a full system malware scan"
                            ),
                            risk_level=RiskLevel.MODERATE,
                            success=False,
                            error="Manual investigation and removal required",
                        )
                    )

            elif check == "bloatware_detected":
                items = finding.data.get("items", [])
                if items:
                    sample_items = items[:3]
                    actions.append(
                        Action(
                            title="Disable performance-impacting startup items",
                            description=(
                                "The following startup items are known to impact performance:\n"
                                + "\n".join([f"  - {i['name']}" for i in sample_items])
                                + "\n\nTo disable:\n"
                                "1. Open Task Manager (Ctrl+Shift+Esc) → Startup tab\n"
                                "2. Right-click each item and select Disable\n"
                                "3. Or use Settings > Apps > Startup to disable items\n"
                                "\nThese items can always be re-enabled if needed."
                            ),
                            risk_level=RiskLevel.SAFE,
                            success=False,
                            error="Manual action required in Task Manager",
                        )
                    )

        return FixResult(module_name=self.name, actions=actions)

    def _collect_startup_items(self) -> list[dict]:
        """Collect startup items from all sources."""
        items = []

        # Get startup items from Win32_StartupCommand
        items.extend(self._get_cim_startup_items())

        # Get items from registry
        items.extend(self._get_registry_startup_items())

        # Get items from startup folders
        items.extend(self._get_startup_folder_items())

        # Get items from Task Scheduler
        items.extend(self._get_task_scheduler_items())

        # Deduplicate based on name and path
        seen = set()
        unique_items = []
        for item in items:
            key = (item.get("name", "").lower(), item.get("path", "").lower())
            if key not in seen:
                seen.add(key)
                unique_items.append(item)

        return unique_items

    def _get_cim_startup_items(self) -> list[dict]:
        """Get startup items via Win32_StartupCommand."""
        items = []
        try:
            result = subprocess.run(
                [
                    "powershell",
                    "-NoProfile",
                    "-Command",
                    (
                        "$items = @(); "
                        "Get-CimInstance Win32_StartupCommand -ErrorAction SilentlyContinue | "
                        "ForEach-Object { "
                        "  $items += @{ "
                        "    name = $_.Name; "
                        "    command = $_.Command; "
                        "    location = $_.Location; "
                        "    user = $_.User "
                        "  } "
                        "}; "
                        "ConvertTo-Json $items -AsArray"
                    ),
                ],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0 and result.stdout.strip():
                try:
                    data = json.loads(result.stdout)
                    if isinstance(data, list):
                        for item in data:
                            items.append(
                                {
                                    "name": item.get("name", ""),
                                    "command": item.get("command", ""),
                                    "path": item.get("location", ""),
                                    "user": item.get("user", ""),
                                    "source": "Win32_StartupCommand",
                                }
                            )
                except json.JSONDecodeError:
                    pass
        except (OSError, subprocess.SubprocessError):
            pass

        return items

    def _get_registry_startup_items(self) -> list[dict]:
        """Get startup items from registry Run keys."""
        items = []

        # HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
        items.extend(self._query_registry_key(
            r"HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "registry_user"
        ))

        # HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
        items.extend(self._query_registry_key(
            r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "registry_system"
        ))

        return items

    def _query_registry_key(self, key_path: str, source_label: str) -> list[dict]:
        """Query a registry key and return startup items."""
        items = []
        try:
            result = subprocess.run(
                ["reg", "query", key_path],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                for line in result.stdout.split("\n"):
                    line = line.strip()
                    if line and not line.startswith(key_path) and line:
                        # Parse registry output: "name REG_SZ value"
                        parts = line.split(None, 2)
                        if len(parts) >= 3:
                            name = parts[0]
                            value = parts[2] if len(parts) > 2 else ""
                            items.append(
                                {
                                    "name": name,
                                    "command": value,
                                    "path": value,
                                    "source": source_label,
                                }
                            )
        except (OSError, subprocess.SubprocessError):
            pass

        return items

    def _get_startup_folder_items(self) -> list[dict]:
        """Get items from startup folders (shell:startup and shell:common startup)."""
        items = []
        try:
            result = subprocess.run(
                [
                    "powershell",
                    "-NoProfile",
                    "-Command",
                    (
                        "$items = @(); "
                        "$paths = @("
                        "  [System.Environment]::GetFolderPath('Startup'), "
                        "  [System.Environment]::GetFolderPath('CommonStartup') "
                        "); "
                        "foreach ($path in $paths) { "
                        "  if (Test-Path $path) { "
                        "    Get-ChildItem $path -ErrorAction SilentlyContinue | "
                        "    ForEach-Object { "
                        "      $items += @{ "
                        "        name = $_.Name; "
                        "        path = $_.FullName; "
                        "        command = $_.FullName "
                        "      } "
                        "    } "
                        "  } "
                        "}; "
                        "ConvertTo-Json $items -AsArray"
                    ),
                ],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0 and result.stdout.strip():
                try:
                    data = json.loads(result.stdout)
                    if isinstance(data, list):
                        for item in data:
                            items.append(
                                {
                                    "name": item.get("name", ""),
                                    "command": item.get("command", ""),
                                    "path": item.get("path", ""),
                                    "source": "startup_folder",
                                }
                            )
                except json.JSONDecodeError:
                    pass
        except (OSError, subprocess.SubprocessError):
            pass

        return items

    def _get_task_scheduler_items(self) -> list[dict]:
        """Get logon task scheduler items."""
        items = []
        try:
            result = subprocess.run(
                ["schtasks", "/query", "/fo", "CSV", "/v"],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                lines = result.stdout.split("\n")
                if len(lines) > 1:
                    # Parse CSV output
                    headers = lines[0].split(",")
                    trigger_idx = -1
                    taskname_idx = -1

                    for i, header in enumerate(headers):
                        if "trigger" in header.lower():
                            trigger_idx = i
                        if "taskname" in header.lower():
                            taskname_idx = i

                    for line in lines[1:]:
                        if not line.strip() or "At logon" not in line:
                            continue

                        parts = line.split(",")
                        if taskname_idx >= 0 and taskname_idx < len(parts):
                            taskname = parts[taskname_idx].strip().strip('"')
                            if taskname and not taskname.startswith("\\Microsoft"):
                                items.append(
                                    {
                                        "name": taskname,
                                        "command": taskname,
                                        "path": taskname,
                                        "source": "task_scheduler",
                                    }
                                )
        except (OSError, subprocess.SubprocessError):
            pass

        return items
