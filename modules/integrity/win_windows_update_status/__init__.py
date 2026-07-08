import json
import subprocess
from datetime import datetime, timedelta
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
    name = "win_windows_update_status"
    category = "integrity"
    platforms = [Platform.WIN32]
    risk_level = RiskLevel.SAFE
    priority = 65
    depends_on = []
    estimated_duration = "20s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Check Windows Update service status
        service_status = self._get_service_status()
        if service_status:
            if service_status.get("is_disabled"):
                findings.append(
                    Finding(
                        title="Windows Update service is disabled",
                        description=(
                            "The Windows Update service (wuauserv) is disabled. "
                            "No security updates will be installed. This is a critical security risk."
                        ),
                        severity=Severity.CRITICAL,
                        category=self.category,
                        data={"check": "service_disabled"},
                    )
                )
            elif not service_status.get("is_running"):
                findings.append(
                    Finding(
                        title="Windows Update service is not running",
                        description=(
                            "The Windows Update service (wuauserv) is not currently running. "
                            "Updates may not be installed. Ensure the service is enabled and running."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={"check": "service_not_running"},
                    )
                )

        # Check if updates are paused
        pause_status = self._get_pause_status()
        if pause_status and pause_status.get("is_paused"):
            findings.append(
                Finding(
                    title="Windows Update is paused",
                    description=(
                        f"Windows Update is paused until {pause_status.get('pause_expiry', 'unknown date')}. "
                        "No updates will be installed while paused. Resume updates in Settings."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "updates_paused", "expiry": pause_status.get("pause_expiry")},
                )
            )

        # Check last update install date
        last_update = self._get_last_update_date()
        if last_update:
            days_since_update = (datetime.now() - last_update).days
            if days_since_update > 90:
                findings.append(
                    Finding(
                        title=f"No updates installed in {days_since_update} days",
                        description=(
                            f"The last Windows Update was installed {days_since_update} days ago ({last_update.date()}). "
                            "This is beyond the recommended 90-day interval for security updates. "
                            "Run Windows Update immediately to install critical security patches."
                        ),
                        severity=Severity.CRITICAL,
                        category=self.category,
                        data={
                            "check": "no_recent_updates",
                            "days_since": days_since_update,
                            "last_date": last_update.isoformat(),
                        },
                    )
                )
            elif days_since_update > 30:
                findings.append(
                    Finding(
                        title=f"No updates installed in {days_since_update} days",
                        description=(
                            f"The last Windows Update was installed {days_since_update} days ago ({last_update.date()}). "
                            "Ensure updates are enabled and run Windows Update soon."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={
                            "check": "stale_updates",
                            "days_since": days_since_update,
                            "last_date": last_update.isoformat(),
                        },
                    )
                )
            else:
                findings.append(
                    Finding(
                        title=f"Last update installed {days_since_update} days ago",
                        description=(
                            f"Windows Update is current. Last update installed on {last_update.date()}. "
                            "System is up to date with security patches."
                        ),
                        severity=Severity.INFO,
                        category=self.category,
                        data={
                            "check": "updates_current",
                            "days_since": days_since_update,
                            "last_date": last_update.isoformat(),
                        },
                    )
                )

        # Check for pending updates
        pending_updates = self._get_pending_updates()
        if pending_updates:
            mandatory_count = pending_updates.get("mandatory_count", 0)
            total_count = pending_updates.get("total_count", 0)
            if mandatory_count > 0:
                findings.append(
                    Finding(
                        title=f"{mandatory_count} mandatory update(s) pending",
                        description=(
                            f"There are {mandatory_count} mandatory update(s) and {total_count - mandatory_count} "
                            f"optional update(s) waiting to be installed. "
                            "Run Windows Update to install these security patches immediately."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={
                            "check": "pending_mandatory_updates",
                            "mandatory_count": mandatory_count,
                            "total_count": total_count,
                            "updates": pending_updates.get("updates", []),
                        },
                    )
                )
            else:
                findings.append(
                    Finding(
                        title=f"{total_count} optional update(s) available",
                        description=(
                            f"There are {total_count} optional update(s) available. "
                            "These are not mandatory security updates but may include improvements."
                        ),
                        severity=Severity.INFO,
                        category=self.category,
                        data={
                            "check": "pending_optional_updates",
                            "total_count": total_count,
                            "updates": pending_updates.get("updates", []),
                        },
                    )
                )

        # Check for failed updates
        failed_updates = self._get_failed_updates()
        if failed_updates and failed_updates.get("failure_count", 0) > 0:
            findings.append(
                Finding(
                    title=f"{failed_updates['failure_count']} failed update(s) detected",
                    description=(
                        f"Windows Update has failed {failed_updates['failure_count']} time(s) recently. "
                        "These failed installations may be blocking current updates. "
                        "Try running Windows Update again or check Settings > System > Troubleshoot > Reset this PC."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "check": "failed_updates",
                        "failure_count": failed_updates["failure_count"],
                    },
                )
            )

        # If no critical findings, add a summary info finding
        if not findings:
            findings.append(
                Finding(
                    title="Windows Update status: Healthy",
                    description=(
                        "Windows Update service is enabled and running. "
                        "System is current with updates and no updates are pending. "
                        "Security patch status is good."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "status_healthy"},
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        for finding in findings.findings:
            check = finding.data.get("check")

            if check == "service_disabled":
                actions.append(
                    Action(
                        title="Enable Windows Update service",
                        description=(
                            "The Windows Update service is disabled, preventing security updates. "
                            "Recommendations: (1) Open Settings > Apps > Optional features. "
                            "(2) Ensure Windows Update is enabled. "
                            "(3) Or use Services.msc to set 'Windows Update' (wuauserv) service to 'Automatic' and start it. "
                            "(4) Restart your computer. "
                            "(5) Run Windows Update to install pending security patches."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "service_not_running":
                actions.append(
                    Action(
                        title="Start Windows Update service",
                        description=(
                            "The Windows Update service is not running. "
                            "Recommendations: (1) Open Services.msc (services application). "
                            "(2) Find 'Windows Update' (wuauserv) and double-click it. "
                            "(3) Set Startup type to 'Automatic'. "
                            "(4) Click 'Start' to start the service. "
                            "(5) Click OK and restart your computer. "
                            "(6) Run Windows Update to install pending updates."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "updates_paused":
                expiry = finding.data.get("expiry", "unknown date")
                actions.append(
                    Action(
                        title="Resume Windows Update",
                        description=(
                            f"Windows Update is paused until {expiry}. "
                            "Recommendations: (1) Open Settings > System > About. "
                            "(2) Click on 'Advanced options' > 'Windows Update'. "
                            "(3) Under 'Pause updates', turn off the pause. "
                            "(4) Windows Update will automatically check for and install updates."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "no_recent_updates":
                days_since = finding.data.get("days_since", 0)
                actions.append(
                    Action(
                        title=f"Install critical updates (no updates in {days_since} days)",
                        description=(
                            f"No updates have been installed in {days_since} days. "
                            "This is a critical security risk. "
                            "Recommendations: (1) Open Settings > System > System update. "
                            "(2) Click 'Check for updates'. "
                            "(3) Let Windows download and install all available updates. "
                            "(4) Your computer may restart several times—do not interrupt the process. "
                            "(5) Ensure your device is plugged in and connected to the internet during this process."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "stale_updates":
                days_since = finding.data.get("days_since", 0)
                actions.append(
                    Action(
                        title=f"Install updates (no updates in {days_since} days)",
                        description=(
                            f"Updates are available but have not been installed in {days_since} days. "
                            "Recommendations: (1) Open Settings > System > System update. "
                            "(2) Click 'Check for updates'. "
                            "(3) Install all available updates. "
                            "(4) Restart when prompted."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "pending_mandatory_updates":
                mandatory_count = finding.data.get("mandatory_count", 0)
                actions.append(
                    Action(
                        title=f"Install {mandatory_count} mandatory update(s)",
                        description=(
                            f"There are {mandatory_count} mandatory security update(s) waiting to be installed. "
                            "Recommendations: (1) Open Settings > System > System update. "
                            "(2) You should see a notification or 'Install updates' button. "
                            "(3) Click to install updates. "
                            "(4) Your computer may restart—save your work first."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "pending_optional_updates":
                total_count = finding.data.get("total_count", 0)
                actions.append(
                    Action(
                        title=f"Optional: Install {total_count} optional update(s)",
                        description=(
                            f"There are {total_count} optional update(s) available. "
                            "These are not critical security updates but may include improvements. "
                            "Recommendations: (1) Open Settings > System > System update. "
                            "(2) Click 'Optional updates'. "
                            "(3) Review and install any that apply to your device."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "failed_updates":
                failure_count = finding.data.get("failure_count", 0)
                actions.append(
                    Action(
                        title=f"Resolve {failure_count} failed update(s)",
                        description=(
                            f"Windows Update has failed {failure_count} time(s). "
                            "Recommendations: (1) Restart your computer and try Windows Update again. "
                            "(2) If failures continue, try using Settings > System > Troubleshoot > Reset this PC. "
                            "(3) Or manually check: Settings > System > System update > Advanced options > Check now."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "updates_current" or check == "status_healthy":
                actions.append(
                    Action(
                        title="Windows Update status is healthy",
                        description=(
                            "Your system is current with security updates. "
                            "Continue to keep Windows Update enabled and allow updates to install regularly. "
                            "Consider enabling automatic updates in Settings > System > About > Advanced system settings > Automatic Updates."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _get_service_status(self) -> Optional[dict]:
        """Check Windows Update service status via sc query wuauserv."""
        try:
            result = subprocess.run(
                ["sc", "query", "wuauserv"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                return None

            output = result.stdout.lower()
            # Check if service is disabled
            if "disabled" in output:
                return {"is_disabled": True, "is_running": False}
            # Check if service is running
            is_running = "running" in output
            return {"is_disabled": False, "is_running": is_running}
        except (OSError, subprocess.SubprocessError, TimeoutError):
            return None

    def _get_pause_status(self) -> Optional[dict]:
        """Check if Windows Update is paused via registry."""
        try:
            ps_cmd = (
                'reg query "HKLM\\SOFTWARE\\Microsoft\\WindowsUpdate\\UX\\Settings" /v PauseUpdatesExpiryTime'
            )
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0 and "PauseUpdatesExpiryTime" in result.stdout:
                # Parse the timestamp
                # Format: REG_DWORD 0x637a8d00
                # This needs conversion from Windows FILETIME to datetime
                # For now, just indicate it's paused
                return {
                    "is_paused": True,
                    "pause_expiry": "configured date (check Settings for exact date)",
                }
            return {"is_paused": False}
        except (OSError, subprocess.SubprocessError, TimeoutError):
            return None

    def _get_last_update_date(self) -> Optional[datetime]:
        """Get last update install date via PowerShell Get-HotFix."""
        try:
            ps_cmd = (
                "(Get-HotFix | Sort-Object InstalledOn -Descending | "
                "Select-Object -First 1).InstalledOn"
            )
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0 or not result.stdout.strip():
                return None

            # Parse the date from PowerShell output
            date_str = result.stdout.strip()
            try:
                # PowerShell returns various formats, try common ones
                for fmt in ["%m/%d/%Y %I:%M:%S %p", "%m/%d/%Y", "%Y-%m-%d"]:
                    try:
                        return datetime.strptime(date_str, fmt)
                    except ValueError:
                        continue
                # If no format matched, try parsing with datetime.fromisoformat
                return datetime.fromisoformat(date_str)
            except (ValueError, AttributeError):
                return None
        except (OSError, subprocess.SubprocessError, TimeoutError):
            return None

    def _get_pending_updates(self) -> Optional[dict]:
        """List pending updates via PowerShell."""
        try:
            ps_cmd = (
                "(New-Object -ComObject Microsoft.Update.Session)."
                "CreateUpdateSearcher().Search('IsInstalled=0').Updates | "
                "Select-Object Title, IsMandatory | ConvertTo-Json"
            )
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                timeout=15,
            )
            if result.returncode != 0 or not result.stdout.strip():
                return None

            return _parse_pending_updates(result.stdout)
        except (OSError, subprocess.SubprocessError, TimeoutError):
            return None

    def _get_failed_updates(self) -> Optional[dict]:
        """Check for failed update installations in event log."""
        try:
            ps_cmd = (
                "Get-WinEvent -LogName System -FilterXPath "
                '"*[System[Provider[@Name=\'Microsoft-Windows-WindowsUpdateClient\'] and (EventID=20 or EventID=25)]]" '
                "-MaxEvents 10 -ErrorAction SilentlyContinue | Measure-Object | Select-Object Count"
            )
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                return None

            # Parse count from output
            failure_count = _parse_event_count(result.stdout)
            if failure_count and failure_count > 0:
                return {"failure_count": failure_count}
            return None
        except (OSError, subprocess.SubprocessError, TimeoutError):
            return None


def _parse_pending_updates(json_output: str) -> Optional[dict]:
    """Parse PowerShell JSON output for pending updates."""
    if not json_output.strip():
        return None

    try:
        data = json.loads(json_output)
        if not isinstance(data, list):
            data = [data]

        updates = []
        mandatory_count = 0
        total_count = len(data)

        for update in data:
            title = update.get("Title", "Unknown")
            is_mandatory = update.get("IsMandatory", False)
            if is_mandatory:
                mandatory_count += 1
            updates.append({"title": title, "is_mandatory": is_mandatory})

        return {
            "mandatory_count": mandatory_count,
            "total_count": total_count,
            "updates": updates,
        }
    except (json.JSONDecodeError, ValueError, KeyError, TypeError):
        return None


def _parse_event_count(output: str) -> int:
    """Extract count from PowerShell Measure-Object output."""
    try:
        for line in output.split("\n"):
            if "count" in line.lower():
                # Extract the number
                parts = line.split()
                for part in parts:
                    if part.isdigit():
                        return int(part)
        return 0
    except (ValueError, IndexError):
        return 0
