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

    emits_codes = [
        "security.win_defender_deep_check.realtime_disabled",
        "security.win_defender_deep_check.cloud_protection_off",
        "security.win_defender_deep_check.tamper_protection_disabled",
        "security.win_defender_deep_check.excessive_exclusions",
        "security.win_defender_deep_check.pua_protection_disabled",
        "security.win_defender_deep_check.stale_full_scan",
        "security.win_defender_deep_check.controlled_folder_access_disabled",
        "security.win_defender_deep_check.all_passed",
    ]

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
                    title="Your computer's main security shield is turned off",
                    description=(
                        "Windows Defender's real-time protection is currently disabled. "
                        "This feature scans files the moment they are opened or downloaded "
                        "to catch threats immediately. Without it, your computer is not "
                        "actively checking for new dangers as you use it.\n\n"
                        "This is a significant gap in your security. It does not mean "
                        "you are currently hacked, but it means new threats can enter "
                        "without being stopped.\n\n"
                        "What to do: Open Windows Security (search for it in the Start "
                        "menu), go to 'Virus & threat protection,' and turn on 'Real-time "
                        "protection'."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
                    code="security.win_defender_deep_check.realtime_disabled",
                    data={"check": "realtime_disabled"},
                )
            )

        # Check 2: Cloud protection (WARNING if off)
        if prefs and prefs.get("MAPSReporting") == 0:
            findings.append(
                Finding(
                    title="Windows Defender's cloud help is turned off",
                    description=(
                        "Windows Defender uses a cloud service to check if a file is a "
                        "known threat. This feature is currently off. It helps catch very "
                        "new viruses that your computer might not have seen before.\n\n"
                        "This is a minor gap. Your computer is still protected by its "
                        "local rules, but it may miss brand-new threats that the cloud "
                        "would have caught.\n\n"
                        "What to do: Open Windows Security, go to 'Virus & threat protection' "
                        "> 'Manage settings,' and turn on 'Cloud-based protection'."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.win_defender_deep_check.cloud_protection_off",
                    data={"check": "cloud_protection_off"},
                )
            )

        # Check 3: Tamper protection (WARNING if disabled)
        if prefs and prefs.get("DisableTamperProtection") is True:
            findings.append(
                Finding(
                    title="Windows Defender's self-defense is turned off",
                    description=(
                        "Tamper protection is a feature that stops other programs from "
                        "changing Windows Defender's settings. It is currently disabled. "
                        "This means a malicious program could potentially turn off your "
                        "security protections without you knowing.\n\n"
                        "This is a warning sign. It doesn't mean something is wrong right "
                        "now, but it makes it easier for bad software to disable your "
                        "defenses.\n\n"
                        "What to do: Open Windows Security, go to 'Virus & threat protection' "
                        "> 'Manage settings,' and turn on 'Tamper protection'."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.win_defender_deep_check.tamper_protection_disabled",
                    data={"check": "tamper_protection_disabled"},
                )
            )

        # Check 4: Scan exclusions (WARNING if too many)
        exclusion_count = self._count_exclusions(prefs)
        if exclusion_count > 10:
            findings.append(
                Finding(
                    title=f"Defender is ignoring {exclusion_count} folders",
                    description=(
                        f"Windows Defender has {exclusion_count} specific folders or files "
                        "that it is told to ignore. When Defender ignores a folder, it "
                        "does not scan anything inside it.\n\n"
                        "Having many exclusions is risky because malware often tries "
                        "to hide in these ignored spots to avoid being detected. If you "
                        "did not add these exclusions yourself, they could be a sign "
                        "of a problem.\n\n"
                        "What to do: Open Windows Security, go to 'Virus & threat protection' "
                        "> 'Manage settings' > 'Exclusions.' Review the list and remove "
                        "any folders you do not recognize or did not add intentionally."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.win_defender_deep_check.excessive_exclusions",
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
                    title="Protection against unwanted apps is off",
                    description=(
                        "Windows Defender has a setting to block 'Potentially Unwanted "
                        "Applications' (PUAs). These are not viruses, but they can be "
                        "annoying, like adware that shows pop-ups or software that tracks "
                        "your browsing. This setting is currently off.\n\n"
                        "This is a minor issue. Your computer is still protected from "
                        "serious viruses, but you might see more unwanted ads or software.\n\n"
                        "What to do: Open Windows Security, go to 'Virus & threat protection' "
                        "> 'Manage settings,' and turn on 'PUA protection'."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.win_defender_deep_check.pua_protection_disabled",
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
                            title=f"Your last full security scan was {days_since} days ago",
                            description=(
                                "Windows Defender last did a full scan of your entire "
                                f"computer {days_since} days ago. A full scan checks every "
                                "file, which is more thorough than the quick checks it "
                                "does while you work.\n\n"
                                "This is a reminder, not an alarm. It just means your "
                                "computer hasn't had a deep check in a while.\n\n"
                                "What to do: Open Windows Security, go to 'Virus & threat "
                                "protection' > 'Scan options,' select 'Full scan,' and "
                                "click 'Scan now'."
                            ),
                            severity=Severity.WARNING,
                            category=self.category,
                            code="security.win_defender_deep_check.stale_full_scan",
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
                    title="Windows Defender's ransomware shield is off",
                    description=(
                        "Controlled folder access is a feature that stops programs from "
                        "changing your important files (like photos and documents) unless "
                        "you allow it. It is currently disabled. This is a key defense "
                        "against ransomware, which tries to lock your files.\n\n"
                        "This is a warning. It does not mean ransomware is on your computer, "
                        "but it means your files are less protected if a threat appears.\n\n"
                        "What to do: Open Windows Security, go to 'Virus & threat protection' "
                        "> 'Ransomware protection,' and turn on 'Controlled folder access'."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.win_defender_deep_check.controlled_folder_access_disabled",
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
                    code="security.win_defender_deep_check.all_passed",
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
