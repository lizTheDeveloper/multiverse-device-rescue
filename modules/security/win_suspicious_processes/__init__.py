import subprocess
import re
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

# Known malware process names
KNOWN_MALWARE = {
    "xmrig",
    "coinhive",
    "cryptonight",
    "minergate",
    "emotet",
    "trickbot",
    "cobalt_strike",
    "mimikatz",
    "lazagne",
    "meterpreter",
}

# Suspicious path patterns
SUSPICIOUS_PATH_PATTERNS = [
    r"C:\\Users\\[^\\]+\\AppData\\Local\\Temp",
    r"C:\\Windows\\Temp",
]


class Module(ModuleBase):
    name = "win_suspicious_processes"
    category = "security"
    platforms = [Platform.WIN32]
    risk_level = RiskLevel.SAFE
    priority = 55
    depends_on = []
    estimated_duration = "10s"

    emits_codes = [
        "security.win_suspicious_processes.known_malware",
        "security.win_suspicious_processes.mining_software",
        "security.win_suspicious_processes.suspicious_path",
        "security.win_suspicious_processes.no_file_path",
        "security.win_suspicious_processes.encoded_powershell",
        "security.win_suspicious_processes.summary",
    ]

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Get list of running processes
        processes = self._get_processes()
        if not processes:
            return CheckResult(module_name=self.name, findings=findings)

        # Check for known malware processes
        for proc in processes:
            proc_name_lower = proc.get("Name", "").lower()

            # Check for known malware
            if any(malware in proc_name_lower for malware in KNOWN_MALWARE):
                findings.append(
                    Finding(
                        title=f"A program named {proc['Name']} looks like known malware",
                        description=(
                            f"We found a program running on your computer called {proc['Name']} "
                            f"(ID {proc['Id']}). Its name matches a list of known harmful "
                            "software. This is a serious sign that your computer may "
                            "be compromised.\n\n"
                            "What to do: Run a full scan with your antivirus software "
                            "immediately. If you do not have one, download a reputable "
                            "free tool like Malwarebytes. Do not use the computer for "
                            "banking or email until the scan is complete."
                        ),
                        severity=Severity.CRITICAL,
                        category=self.category,
                        code="security.win_suspicious_processes.known_malware",
                        data={
                            "pid": proc["Id"],
                            "name": proc["Name"],
                            "path": proc.get("Path", ""),
                            "type": "known_malware",
                        },
                    )
                )
                continue

            # Check for special case: nicehash only flagged if unexpected
            if "nicehash" in proc_name_lower:
                findings.append(
                    Finding(
                        title=f"A program named {proc['Name']} is mining cryptocurrency",
                        description=(
                            f"We found a program called {proc['Name']} (ID {proc['Id']}) "
                            "that is using your computer's power to mine cryptocurrency. "
                            "This is often done without permission to steal processing "
                            "power.\n\n"
                            "What to do: If you did not install this software, end the "
                            "task in Task Manager (right-click the taskbar, select Task "
                            "Manager, find the process, and click 'End Task'). Then run "
                            "a full antivirus scan to remove the source."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        code="security.win_suspicious_processes.mining_software",
                        data={
                            "pid": proc["Id"],
                            "name": proc["Name"],
                            "path": proc.get("Path", ""),
                            "type": "mining_software",
                        },
                    )
                )
                continue

            # Check for suspicious paths
            proc_path = proc.get("Path", "")
            if proc_path and self._matches_suspicious_path(proc_path):
                findings.append(
                    Finding(
                        title=(
                            f"A program named {proc['Name']} is running from a temporary folder"
                        ),
                        description=(
                            f"The program {proc['Name']} (ID {proc['Id']}) is running "
                            f"from a temporary folder: {proc_path}. Legitimate apps usually "
                            "install in standard locations like 'Program Files'. Running "
                            "from a temporary folder is a common trick used by malware "
                            "to hide itself.\n\n"
                            "What to do: Check if you recognize this program. If not, "
                            "end the task in Task Manager and run a full antivirus scan. "
                            "Do not delete the file manually; let the antivirus handle "
                            "removal to ensure all related files are cleaned."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        code="security.win_suspicious_processes.suspicious_path",
                        data={
                            "pid": proc["Id"],
                            "name": proc["Name"],
                            "path": proc_path,
                            "type": "suspicious_path",
                        },
                    )
                )
                continue

            # Check for processes with no file path (in-memory injection)
            if proc["Name"].lower() != "system" and not proc_path:
                findings.append(
                    Finding(
                        title=f"A program named {proc['Name']} has no file location",
                        description=(
                            f"The program {proc['Name']} (ID {proc['Id']}) is running, "
                            "but we cannot find its file on your disk. This can happen "
                            "with certain system processes, but it is also a technique "
                            "used by malware to hide its presence, so it's worth a closer "
                            "look.\n\n"
                            "What to do: Run a full scan with your antivirus software. "
                            "If the scan is clean and you do not recognize the program "
                            "name, you can safely ignore it, but keep an eye on your "
                            "computer's performance."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        code="security.win_suspicious_processes.no_file_path",
                        data={
                            "pid": proc["Id"],
                            "name": proc["Name"],
                            "type": "no_file_path",
                        },
                    )
                )
                continue

        # Check for encoded PowerShell commands
        ps_findings = self._check_powershell_commands()
        findings.extend(ps_findings)

        # Add informational summary if any suspicious processes found
        if findings:
            summary_count = len([f for f in findings if f.severity != Severity.INFO])
            findings.insert(
                0,
                Finding(
                    title="Suspicious process activity detected",
                    description=(
                        f"Found {summary_count} suspicious process(es) during scan. "
                        "Review findings and investigate or remove suspicious processes."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.win_suspicious_processes.summary",
                    data={"count": summary_count, "type": "summary"},
                ),
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            # Skip summary findings
            if finding.data.get("type") == "summary":
                continue

            proc_name = finding.data.get("name", "Unknown")
            proc_id = finding.data.get("pid", "Unknown")

            severity_map = {
                Severity.CRITICAL: RiskLevel.MODERATE,
                Severity.WARNING: RiskLevel.MODERATE,
            }
            risk = severity_map.get(finding.severity, RiskLevel.SAFE)

            actions.append(
                Action(
                    title=f"Investigate and remove suspicious process: {proc_name}",
                    description=(
                        f"Process {proc_name} (PID {proc_id}) requires investigation. "
                        "Use Windows Task Manager to end the process, then run a full "
                        "antivirus scan. Do not force kill processes without understanding "
                        "their function, as this may cause system instability."
                    ),
                    risk_level=risk,
                    success=True,
                    data={"pid": proc_id, "name": proc_name},
                )
            )

        return FixResult(module_name=self.name, actions=actions)

    def _get_processes(self) -> list[dict]:
        """Get list of running processes via PowerShell."""
        try:
            cmd = [
                "powershell",
                "-NoProfile",
                "-Command",
                "Get-Process | Select-Object Name, Id, @{n='Path';e={$_.Path}}, CPU, WorkingSet64 | ConvertTo-Json",
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if result.returncode == 0 and result.stdout:
                import json

                try:
                    data = json.loads(result.stdout)
                    # Handle both single process (dict) and multiple (list)
                    if isinstance(data, dict):
                        return [data]
                    return data if isinstance(data, list) else []
                except json.JSONDecodeError:
                    return []
            return []
        except (OSError, subprocess.SubprocessError, subprocess.TimeoutExpired):
            return []

    def _matches_suspicious_path(self, path: str) -> bool:
        """Check if path matches suspicious patterns."""
        path_lower = path.lower()
        for pattern in SUSPICIOUS_PATH_PATTERNS:
            if re.search(pattern, path_lower, re.IGNORECASE):
                return True
        return False

    def _check_powershell_commands(self) -> list[Finding]:
        """Check for PowerShell processes running encoded commands."""
        findings = []
        try:
            cmd = [
                "powershell",
                "-NoProfile",
                "-Command",
                "Get-Process powershell -ErrorAction SilentlyContinue | ForEach-Object { $pid = $_.Id; (Get-CimInstance Win32_Process -Filter \"ProcessId=$pid\").CommandLine } | ConvertTo-Json",
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if result.returncode == 0 and result.stdout:
                import json

                try:
                    command_lines = json.loads(result.stdout)
                    if not isinstance(command_lines, list):
                        command_lines = [command_lines]

                    for cmd_line in command_lines:
                        if cmd_line and self._is_encoded_command(cmd_line):
                            findings.append(
                                Finding(
                                    title="PowerShell is running a hidden command",
                                    description=(
                                        "We found a PowerShell process running a command "
                                        "that is encoded (hidden in a scrambled format). "
                                        "This is a common technique used by malware to "
                                        "hide what it is doing.\n\n"
                                        "What to do: Run a full scan with your antivirus "
                                        "software. If you do not use PowerShell regularly, "
                                        "this is likely a sign of an infection that needs "
                                        "to be cleaned."
                                    ),
                                    severity=Severity.WARNING,
                                    category=self.category,
                                    code="security.win_suspicious_processes.encoded_powershell",
                                    data={
                                        "command": cmd_line[:100],
                                        "type": "encoded_powershell",
                                    },
                                )
                            )
                except json.JSONDecodeError:
                    pass
        except (OSError, subprocess.SubprocessError, subprocess.TimeoutExpired):
            pass

        return findings

    def _is_encoded_command(self, cmd_line: str) -> bool:
        """Check if PowerShell command uses encoding flags."""
        cmd_lower = cmd_line.lower()
        # Look for common encoding parameters
        encoding_patterns = [
            r"-encodedcommand",
            r"-ec\s",
            r"-enc\s",
            r"-e\s",
        ]
        for pattern in encoding_patterns:
            if re.search(pattern, cmd_lower):
                return True
        return False
