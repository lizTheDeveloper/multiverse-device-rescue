import json
import subprocess
from datetime import datetime, timedelta

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
    name = "win_defender_deep_check"
    category = "security"
    platforms = [Platform.WIN32]
    risk_level = RiskLevel.SAFE
    priority = 66
    depends_on = []
    estimated_duration = "15s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Get Defender preferences
        pref_output = self._run_get_preferences()
        prefs = _parse_json_output(pref_output)

        # Get Defender computer status
        status_output = self._run_get_status()
        status = _parse_json_output(status_output)

        if prefs is None and status is None:
            return CheckResult(module_name=self.name, findings=findings)

        # Check 1: Real-time protection (CRITICAL if disabled)
        if prefs and prefs.get("DisableRealtimeMonitoring") is True:
            findings.append(
                Finding(
                    title="Real-time protection is disabled",
                    description=(
                        "Windows Defender real-time protection is disabled. "
                        "Files are not scanned as they are accessed, leaving the system vulnerable."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
                    data={"check": "realtime_disabled"},
                )
            )

        # Check 2: Cloud protection (WARNING if off)
        if prefs and prefs.get("MAPSReporting") == 0:
            findings.append(
                Finding(
                    title="Cloud protection is disabled",
                    description=(
                        "Windows Defender cloud protection (MAPS) is off. "
                        "This reduces detection of new and emerging threats."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "cloud_protection_off"},
                )
            )

        # Check 3: Tamper protection (WARNING if disabled)
        if prefs and prefs.get("DisableTamperProtection") is True:
            findings.append(
                Finding(
                    title="Tamper protection is disabled",
                    description=(
                        "Windows Defender tamper protection is disabled. "
                        "Malware could disable Defender protections."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "tamper_protection_disabled"},
                )
            )

        # Check 4: Scan exclusions (WARNING if too many)
        exclusion_count = self._count_exclusions(prefs)
        if exclusion_count > 10:
            findings.append(
                Finding(
                    title=f"High number of scan exclusions ({exclusion_count})",
                    description=(
                        "Many exclusions from Defender scans increase risk. "
                        "Malware often hides in excluded paths to avoid detection."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "check": "excessive_exclusions",
                        "exclusion_count": exclusion_count,
                    },
                )
            )

        # Check 5: PUA protection (WARNING if disabled)
        if prefs and prefs.get("PUAProtection") == 0:
            findings.append(
                Finding(
                    title="PUA (Potentially Unwanted App) protection is disabled",
                    description=(
                        "Windows Defender PUA protection is off. "
                        "Unwanted applications like adware may not be detected."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "pua_protection_disabled"},
                )
            )

        # Check 6: Last full scan date (WARNING if >30 days)
        if status and status.get("FullScanEndTime"):
            last_scan = self._parse_scan_time(status.get("FullScanEndTime"))
            if last_scan:
                days_since = (datetime.now() - last_scan).days
                if days_since > 30:
                    findings.append(
                        Finding(
                            title=f"Last full scan was {days_since} days ago",
                            description=(
                                "Full system scans should run regularly (at least monthly). "
                                "A stale last scan means threats could have accumulated."
                            ),
                            severity=Severity.WARNING,
                            category=self.category,
                            data={
                                "check": "stale_full_scan",
                                "days_since_scan": days_since,
                            },
                        )
                    )

        # Check 7: Controlled folder access (WARNING if disabled)
        if prefs and prefs.get("EnableControlledFolderAccess") == 0:
            findings.append(
                Finding(
                    title="Controlled folder access is disabled",
                    description=(
                        "Windows Defender controlled folder access is off. "
                        "Ransomware could modify files in protected folders."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "controlled_folder_access_disabled"},
                )
            )

        # Info: Report summary
        if not findings:
            findings.append(
                Finding(
                    title="Windows Defender configuration summary",
                    description="All deep Defender checks passed. Protection appears well-configured.",
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "all_passed"},
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            check = finding.data.get("check")
            if check == "realtime_disabled":
                actions.append(
                    Action(
                        title="Enable real-time protection",
                        description=(
                            "Open Windows Security > Virus & threat protection > "
                            "Manage settings, and enable 'Real-time protection'."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=False,
                        error="Manual action required - cannot auto-enable with current permissions",
                    )
                )
            elif check == "cloud_protection_off":
                actions.append(
                    Action(
                        title="Enable cloud protection",
                        description=(
                            "Open Windows Security > Virus & threat protection > "
                            "Manage settings, and enable 'Cloud-delivered protection'."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=False,
                        error="Manual action required - cannot auto-enable with current permissions",
                    )
                )
            elif check == "tamper_protection_disabled":
                actions.append(
                    Action(
                        title="Enable tamper protection",
                        description=(
                            "Open Windows Security > Virus & threat protection > "
                            "Manage settings, and enable 'Tamper protection'."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=False,
                        error="Manual action required - cannot auto-enable with current permissions",
                    )
                )
            elif check == "excessive_exclusions":
                count = finding.data.get("exclusion_count", 0)
                actions.append(
                    Action(
                        title=f"Review {count} scan exclusions",
                        description=(
                            "Open Windows Security > Virus & threat protection > "
                            "Manage settings > Exclusions. Review each exclusion and remove any "
                            "that are not needed."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=False,
                        error="Manual action required - review exclusions",
                    )
                )
            elif check == "pua_protection_disabled":
                actions.append(
                    Action(
                        title="Enable PUA protection",
                        description=(
                            "Open Windows Security > Virus & threat protection > "
                            "Manage settings, and enable 'PUA protection'."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=False,
                        error="Manual action required - cannot auto-enable with current permissions",
                    )
                )
            elif check == "stale_full_scan":
                days = finding.data.get("days_since_scan", 0)
                actions.append(
                    Action(
                        title=f"Run full system scan (last scan {days} days ago)",
                        description=(
                            "Open Windows Security > Virus & threat protection > "
                            "Scan options, select 'Full scan', and click 'Scan now'."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=False,
                        error="Manual action required - full scan takes significant time",
                    )
                )
            elif check == "controlled_folder_access_disabled":
                actions.append(
                    Action(
                        title="Enable controlled folder access",
                        description=(
                            "Open Windows Security > Virus & threat protection > "
                            "Ransomware protection, and enable 'Controlled folder access'."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=False,
                        error="Manual action required - cannot auto-enable with current permissions",
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _run_get_preferences(self) -> str:
        try:
            result = subprocess.run(
                [
                    "powershell",
                    "-NoProfile",
                    "-Command",
                    "Get-MpPreference | ConvertTo-Json",
                ],
                capture_output=True,
                text=True,
            )
            return result.stdout
        except (OSError, subprocess.SubprocessError):
            return ""

    def _run_get_status(self) -> str:
        try:
            result = subprocess.run(
                [
                    "powershell",
                    "-NoProfile",
                    "-Command",
                    "Get-MpComputerStatus | ConvertTo-Json",
                ],
                capture_output=True,
                text=True,
            )
            return result.stdout
        except (OSError, subprocess.SubprocessError):
            return ""

    def _count_exclusions(self, prefs: dict | None) -> int:
        """Count total exclusions from path, extension, and process."""
        if not prefs:
            return 0
        count = 0
        if prefs.get("ExclusionPath"):
            paths = prefs.get("ExclusionPath", [])
            count += len(paths) if isinstance(paths, list) else (1 if paths else 0)
        if prefs.get("ExclusionExtension"):
            exts = prefs.get("ExclusionExtension", [])
            count += len(exts) if isinstance(exts, list) else (1 if exts else 0)
        if prefs.get("ExclusionProcess"):
            procs = prefs.get("ExclusionProcess", [])
            count += len(procs) if isinstance(procs, list) else (1 if procs else 0)
        return count

    def _parse_scan_time(self, time_str: str) -> datetime | None:
        """Parse PowerShell datetime string."""
        if not time_str:
            return None
        try:
            # Handle ISO format from PowerShell
            return datetime.fromisoformat(time_str.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            try:
                # Try parsing common Windows datetime formats
                return datetime.strptime(time_str, "%m/%d/%Y %I:%M:%S %p")
            except ValueError:
                return None


def _parse_json_output(output: str) -> dict | None:
    """Parse JSON output from PowerShell commands."""
    if not output or not output.strip():
        return None
    try:
        return json.loads(output)
    except json.JSONDecodeError:
        return None
