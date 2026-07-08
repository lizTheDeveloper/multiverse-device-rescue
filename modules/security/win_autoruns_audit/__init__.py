import re
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


class Module(ModuleBase):
    name = "win_autoruns_audit"
    category = "security"
    platforms = [Platform.WIN32]
    risk_level = RiskLevel.SAFE
    priority = 55
    depends_on = []
    estimated_duration = "10s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []
        autoruns = {}

        # Collect all autorun entries from different locations
        autoruns["HKLM\\Run"] = self._query_registry_run("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run")
        autoruns["HKCU\\Run"] = self._query_registry_run("HKCU", r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run")
        autoruns["HKLM\\RunOnce"] = self._query_registry_run("HKLM", r"SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce")
        autoruns["Startup (Current User)"] = self._get_startup_folder_entries("APPDATA")
        autoruns["Startup (All Users)"] = self._get_startup_folder_entries("PROGRAMDATA")

        # Flatten and analyze all entries
        all_entries = {}
        for location, entries in autoruns.items():
            if entries:
                all_entries.update({f"{location}: {k}": v for k, v in entries.items()})

        total_count = len(all_entries)

        # Check for suspicious entries
        for location_entry, command in all_entries.items():
            location, entry_name = location_entry.rsplit(": ", 1)

            # Check for temp directory execution (CRITICAL)
            if self._is_temp_path(command):
                findings.append(
                    Finding(
                        title=f"Autorun entry executing from temp directory",
                        description=(
                            f"Autorun entry '{entry_name}' at {location} executes from a "
                            f"temporary directory. This is a strong indicator of malware persistence. "
                            f"Command: {command}"
                        ),
                        severity=Severity.CRITICAL,
                        category=self.category,
                        data={
                            "entry_name": entry_name,
                            "location": location,
                            "command": command,
                        },
                    )
                )

            # Check for obfuscated commands (WARNING)
            elif self._is_obfuscated_command(command):
                findings.append(
                    Finding(
                        title=f"Autorun entry with obfuscated command",
                        description=(
                            f"Autorun entry '{entry_name}' at {location} uses obfuscated or "
                            f"encoded command execution. This may indicate malware. "
                            f"Command: {command}"
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={
                            "entry_name": entry_name,
                            "location": location,
                            "command": command,
                        },
                    )
                )

        # Check for excessive autorun entries (WARNING)
        if total_count > 20:
            findings.append(
                Finding(
                    title=f"Excessive number of autorun entries ({total_count})",
                    description=(
                        f"The system has {total_count} autorun entries across all locations. "
                        f"This exceeds the typical count of ~20 and may indicate bloatware or malware. "
                        f"Review startup programs in msconfig or Task Manager."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"total_autorun_count": total_count},
                )
            )

        # Always list all entries (INFO)
        if all_entries:
            entry_list = "\n".join(
                [f"  {location}: {entry_name} -> {command}" for location, entry_name, command in
                 [(loc.rsplit(": ", 1)[0], loc.rsplit(": ", 1)[1], cmd) for loc, cmd in all_entries.items()]]
            )
            findings.append(
                Finding(
                    title=f"Autorun entries inventory ({total_count} total)",
                    description=(
                        f"Found {total_count} autorun entries across all locations:\n{entry_list}"
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "total_count": total_count,
                        "entries_by_location": autoruns,
                    },
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            if finding.severity == Severity.CRITICAL:
                entry_name = finding.data.get("entry_name", "")
                location = finding.data.get("location", "")
                actions.append(
                    Action(
                        title=f"Remove suspicious autorun entry: {entry_name}",
                        description=(
                            f"To remove the malicious autorun entry '{entry_name}' from {location}:\n"
                            f"1. Press Win+R, type 'regedit' and hit Enter\n"
                            f"2. Navigate to the registry location for this entry\n"
                            f"3. Delete the entry '{entry_name}'\n"
                            f"Alternatively, use 'msconfig' (Win+R -> msconfig) to disable startup programs."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=False,
                        error="Manual intervention required (informational fix)",
                    )
                )
            elif finding.severity == Severity.WARNING and "obfuscated" in finding.title.lower():
                entry_name = finding.data.get("entry_name", "")
                location = finding.data.get("location", "")
                actions.append(
                    Action(
                        title=f"Review obfuscated autorun entry: {entry_name}",
                        description=(
                            f"Autorun entry '{entry_name}' at {location} uses obfuscated commands. "
                            f"Verify this entry is legitimate:\n"
                            f"1. Search for the entry name online or in your installed software\n"
                            f"2. Use 'msconfig' (Win+R -> msconfig) to disable it and test if the system still works\n"
                            f"3. If legitimate, re-enable it. If not, remove it via regedit."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=False,
                        error="Manual review required (informational fix)",
                    )
                )
        return FixResult(module_name=self.name, actions=actions)

    def _query_registry_run(self, hive: str, path: str) -> dict[str, str]:
        """Query a registry location for autorun entries using reg query.

        Returns a dict of {entry_name: command_path}
        """
        try:
            result = subprocess.run(
                ["reg", "query", f"{hive}\\{path}", "/v", "*"],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                return {}
            return self._parse_reg_query_output(result.stdout)
        except (OSError, subprocess.SubprocessError):
            return {}

    def _parse_reg_query_output(self, output: str) -> dict[str, str]:
        """Parse the output of 'reg query' command.

        Example output:
            HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run
                Windows Defender    REG_SZ    C:\\Program Files\\Windows Defender\\MSASCuiL.exe
                OneDrive            REG_SZ    C:\\Users\\User\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe
        """
        entries = {}
        for line in output.splitlines():
            line = line.strip()
            # Skip header lines and empty lines
            if not line or line.startswith("HKEY_"):
                continue
            # Parse the entry line: NAME REG_TYPE VALUE
            # The pattern is: value_name<spaces>REG_TYPE<spaces>data
            # We need to find REG_SZ or REG_DWORD to split correctly
            if "REG_SZ" in line or "REG_DWORD" in line:
                # Find the position of the REG type
                reg_match = None
                reg_pos = -1
                if "REG_SZ" in line:
                    reg_pos = line.find("REG_SZ")
                    reg_match = "REG_SZ"
                elif "REG_DWORD" in line:
                    reg_pos = line.find("REG_DWORD")
                    reg_match = "REG_DWORD"

                if reg_pos > 0:
                    name = line[:reg_pos].strip()
                    # Find the value after the REG type
                    value_start = reg_pos + len(reg_match)
                    value = line[value_start:].strip()
                    if name and value:
                        entries[name] = value
        return entries

    def _get_startup_folder_entries(self, folder_type: str) -> dict[str, str]:
        """Get entries from Windows Startup folder using PowerShell.

        folder_type: "APPDATA" for current user or "PROGRAMDATA" for all users
        """
        try:
            if folder_type == "APPDATA":
                ps_cmd = (
                    'Get-ChildItem "$env:APPDATA\\Microsoft\\Windows\\Start Menu\\Programs\\Startup" '
                    '-ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name'
                )
            else:  # PROGRAMDATA
                ps_cmd = (
                    'Get-ChildItem "$env:PROGRAMDATA\\Microsoft\\Windows\\Start Menu\\Programs\\Startup" '
                    '-ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name'
                )

            result = subprocess.run(
                ["powershell", "-Command", ps_cmd],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                return {}

            entries = {}
            for line in result.stdout.splitlines():
                line = line.strip()
                if line:
                    entries[line] = f"Startup folder: {line}"
            return entries
        except (OSError, subprocess.SubprocessError):
            return {}

    def _is_temp_path(self, command: str) -> bool:
        """Check if command path is in a temp directory."""
        temp_patterns = [
            r"\\Temp\\",
            r"\\TEMP\\",
            r"\\temp\\",
            r"AppData\\Local\\Temp",
            r"AppData\\Local\\temp",
            r"\\Downloads\\",
            r"\\downloads\\",
        ]
        for pattern in temp_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                return True
        return False

    def _is_obfuscated_command(self, command: str) -> bool:
        """Check if command uses obfuscation techniques."""
        obfuscation_patterns = [
            r"-enc ",  # PowerShell encoded command
            r"-e ",    # Short form of -encoded
            r"IEX\(",  # PowerShell IEX (Invoke-Expression)
            r"Invoke-Expression",
            r"\|.*iex",  # Pipe to IEX
            r"cmd.*\/c.*\|",  # cmd with pipe (often used to hide commands)
            r"powershell.*-decode",
            r"certutil.*-decode",
            r"base64",
        ]
        for pattern in obfuscation_patterns:
            if re.search(pattern, command, re.IGNORECASE):
                return True
        return False
