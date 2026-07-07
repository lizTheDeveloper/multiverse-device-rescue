import subprocess
from typing import Optional

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
    name = "win_startup_repair"
    category = "integrity"
    platforms = [Platform.WIN32]
    risk_level = RiskLevel.SAFE
    priority = 65
    depends_on = []
    estimated_duration = "20s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Check boot configuration
        boot_config = self._get_boot_config()
        if not boot_config:
            findings.append(
                Finding(
                    title="Could not retrieve boot configuration",
                    description=(
                        "Failed to run bcdedit. Boot configuration cannot be assessed."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "boot_config_failed"},
                )
            )
            return CheckResult(module_name=self.name, findings=findings)

        # Check if recovery sequence is available
        recovery_status = boot_config.get("recovery_enabled", False)
        if not recovery_status:
            findings.append(
                Finding(
                    title="Recovery mode not available",
                    description=(
                        "The Windows recovery sequence is missing or disabled. "
                        "This may prevent system recovery in case of boot issues."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "recovery_missing"},
                )
            )

        # Check for unusual boot entries
        unusual_entries = boot_config.get("unusual_entries", [])
        if unusual_entries:
            findings.append(
                Finding(
                    title="Unusual boot configuration entries detected",
                    description=(
                        f"Found {len(unusual_entries)} unusual entries in boot configuration: "
                        f"{', '.join(unusual_entries[:3])}{'...' if len(unusual_entries) > 3 else ''}. "
                        "This may indicate boot configuration tampering or corruption."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "check": "unusual_entries",
                        "entries": unusual_entries,
                    },
                )
            )

        # Check boot performance diagnostics
        boot_degradation = self._get_boot_degradation()
        if boot_degradation:
            findings.append(
                Finding(
                    title="Boot performance degradation detected",
                    description=(
                        f"Found {boot_degradation['event_count']} boot performance degradation events. "
                        "This may indicate slow boot components or driver issues."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "check": "boot_degradation",
                        "event_count": boot_degradation["event_count"],
                    },
                )
            )

        # Check for multiple boot entries (dual boot)
        boot_entries = boot_config.get("boot_entry_count", 0)
        if boot_entries > 1:
            findings.append(
                Finding(
                    title=f"Multiple boot entries detected ({boot_entries})",
                    description=(
                        f"System has {boot_entries} boot entries. "
                        "This may indicate dual boot setup or orphaned boot entries."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "check": "multiple_boot_entries",
                        "boot_entries": boot_entries,
                    },
                )
            )

        # Add informational finding about boot status
        if not findings or all(f.severity != Severity.CRITICAL for f in findings):
            boot_timeout = boot_config.get("boot_timeout", "unknown")
            boot_device = boot_config.get("boot_device", "unknown")
            findings.append(
                Finding(
                    title="Boot configuration status",
                    description=(
                        f"Boot configuration: {boot_entries} entries, "
                        f"timeout={boot_timeout}s, "
                        f"recovery={'enabled' if recovery_status else 'disabled'}, "
                        f"device={boot_device}."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "check": "boot_status",
                        "boot_entries": boot_entries,
                        "boot_timeout": boot_timeout,
                        "recovery_enabled": recovery_status,
                        "boot_device": boot_device,
                    },
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        for finding in findings.findings:
            check = finding.data.get("check")

            if check == "recovery_missing":
                actions.append(
                    Action(
                        title="Recovery mode not available",
                        description=(
                            "The Windows recovery sequence is missing or disabled. "
                            "Recommendations: (1) Boot into Windows Recovery Environment using installation media. "
                            "(2) Run 'Startup Repair' from the recovery options. "
                            "(3) If recovery media is unavailable, use Windows installation media or recovery USB. "
                            "(4) From recovery, you can restore boot configuration or reset Windows."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "boot_degradation":
                event_count = finding.data.get("event_count", 0)
                actions.append(
                    Action(
                        title=f"Boot performance issues detected ({event_count} events)",
                        description=(
                            f"Found {event_count} boot performance degradation events. "
                            "Recommendations: (1) Run Windows Startup Settings to disable unnecessary startup programs. "
                            "(2) Check Device Manager for driver issues (yellow exclamation marks). "
                            "(3) Run 'msconfig' and disable unnecessary services on Startup tab. "
                            "(4) Update chipset and system drivers. "
                            "(5) Consider running 'sfc /scannow' to repair system files."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "unusual_entries":
                entries = finding.data.get("entries", [])
                actions.append(
                    Action(
                        title="Unusual boot entries detected",
                        description=(
                            f"Found {len(entries)} unusual boot configuration entries. "
                            "Recommendations: (1) Review boot entries with 'bcdedit /enum' command. "
                            "(2) Remove orphaned or suspicious entries with 'bcdedit /delete' (requires admin). "
                            "(3) If unsure, use 'startup repair' from recovery environment. "
                            "(4) Backup system before making boot configuration changes."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "multiple_boot_entries":
                boot_entries = finding.data.get("boot_entries", 0)
                actions.append(
                    Action(
                        title=f"Multiple boot entries ({boot_entries})",
                        description=(
                            f"System has {boot_entries} boot entries. "
                            "Recommendations: (1) Use 'bcdedit /enum' to list all entries. "
                            "(2) Identify which entry is current and which are orphaned. "
                            "(3) Remove orphaned entries with 'bcdedit /delete {identifier}' (requires admin). "
                            "(4) Set default boot entry with 'bcdedit /default {identifier}'. "
                            "(5) If managing dual boot, ensure all entries are intentional."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "boot_status":
                actions.append(
                    Action(
                        title="Boot configuration summary",
                        description=(
                            "Boot configuration is available. "
                            "Regular maintenance recommendations: (1) Periodically check boot configuration. "
                            "(2) Keep Windows and drivers updated. "
                            "(3) Monitor startup performance. "
                            "(4) Maintain regular system backups. "
                            "(5) Consider enabling System Protection for volume shadow copies."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "boot_config_failed":
                actions.append(
                    Action(
                        title="Unable to assess boot configuration",
                        description=(
                            "Failed to retrieve boot configuration. "
                            "Ensure you have Administrator privileges. "
                            "Try running 'bcdedit /enum' in Command Prompt (as Administrator). "
                            "If command fails, boot into Safe Mode and try again. "
                            "If boot is severely damaged, use Windows Recovery Environment with startup repair."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _get_boot_config(self) -> Optional[dict]:
        """Get boot configuration from bcdedit."""
        try:
            config = {
                "recovery_enabled": False,
                "boot_entry_count": 0,
                "boot_timeout": "unknown",
                "boot_device": "unknown",
                "unusual_entries": [],
            }

            # Get current boot configuration
            result = subprocess.run(
                ["bcdedit", "/enum", "{current}"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                return None

            # Parse current boot config
            current_config = _parse_bcdedit_output(result.stdout)
            if "device" in current_config:
                config["boot_device"] = current_config["device"]
            if "timeout" in current_config:
                config["boot_timeout"] = current_config["timeout"]

            # Check recovery sequence
            result = subprocess.run(
                ["bcdedit", "/enum", "{recoverysequence}"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0 and result.stdout.strip():
                config["recovery_enabled"] = True

            # Get boot manager timeout
            result = subprocess.run(
                ["bcdedit", "/enum", "{bootmgr}"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                bootmgr_config = _parse_bcdedit_output(result.stdout)
                if "timeout" in bootmgr_config:
                    config["boot_timeout"] = bootmgr_config["timeout"]

            # Count boot entries
            result = subprocess.run(
                ["bcdedit", "/enum"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                boot_entries = _count_boot_entries(result.stdout)
                config["boot_entry_count"] = boot_entries

                # Check for unusual entries
                unusual = _find_unusual_entries(result.stdout)
                if unusual:
                    config["unusual_entries"] = unusual

            return config
        except (OSError, subprocess.SubprocessError, TimeoutError):
            return None

    def _get_boot_degradation(self) -> Optional[dict]:
        """Check for boot performance degradation events."""
        try:
            # PowerShell command to get boot performance diagnostics
            ps_cmd = (
                "Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-Diagnostics-Performance/Operational'; "
                "ID=100} -MaxEvents 5 -ErrorAction SilentlyContinue | Measure-Object | Select-Object Count"
            )
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                return None

            # Parse output to extract count
            event_count = _parse_event_count(result.stdout)
            if event_count and event_count > 0:
                return {"event_count": event_count}
            return None
        except (OSError, subprocess.SubprocessError, TimeoutError):
            return None


def _parse_bcdedit_output(output: str) -> dict:
    """Parse bcdedit output to extract key-value pairs."""
    config = {}
    for line in output.split("\n"):
        line = line.strip()
        if not line:
            continue
        # Look for lines with format "key    value"
        if "device" in line.lower():
            parts = line.split(None, 1)
            if len(parts) > 1:
                config["device"] = parts[1]
        elif "timeout" in line.lower():
            parts = line.split()
            for i, part in enumerate(parts):
                if part.isdigit():
                    config["timeout"] = part
                    break
    return config


def _count_boot_entries(bcdedit_output: str) -> int:
    """Count number of boot entries in bcdedit output."""
    count = 0
    for line in bcdedit_output.split("\n"):
        line = line.strip()
        # Look for Windows Boot Loader entries
        if line.startswith("identifier") or "Windows Boot Loader" in line:
            count += 1
    return count


def _find_unusual_entries(bcdedit_output: str) -> list:
    """Find unusual or suspicious entries in boot configuration."""
    unusual = []
    # Look for entries with suspicious or unusual names
    suspicious_keywords = [
        "debug",
        "safeboot",
        "custom",
        "backup",
        "recovery",
    ]
    lines = bcdedit_output.split("\n")
    for line in lines:
        lower_line = line.lower()
        for keyword in suspicious_keywords:
            if keyword in lower_line and "identifier" not in lower_line:
                # Avoid duplicate entries
                entry = line.strip()
                if entry and entry not in unusual:
                    unusual.append(entry[:60])  # Truncate for readability
                break
    return unusual


def _parse_event_count(output: str) -> int:
    """Extract count from PowerShell Measure-Object output."""
    try:
        for line in output.split("\n"):
            if "count" in line.lower():
                parts = line.split()
                for part in parts:
                    if part.isdigit():
                        return int(part)
        return 0
    except (ValueError, IndexError):
        return 0
