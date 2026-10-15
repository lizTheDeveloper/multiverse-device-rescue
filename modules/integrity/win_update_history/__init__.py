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
    name = "win_update_history"
    category = "integrity"
    platforms = [Platform.WIN32]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "10s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Check Windows Update service status
        service_status = self._check_update_service()
        if service_status is False:
            findings.append(
                Finding(
                    title="Windows Update is turned off",
                    description=(
                        "The background service that checks for Windows updates is currently "
                        "stopped. This means your computer is not automatically downloading "
                        "security fixes, which leaves you open to known problems.\n\n"
                        "What to do: Open Start, type 'Services', and press Enter. Find "
                        "'Windows Update' in the list, right-click it, and select 'Start'. "
                        "If it stops again, check if a program is blocking it."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "service_stopped"},
                )
            )
        elif service_status is None:
            findings.append(
                Finding(
                    title="Could not check Windows Update status",
                    description=(
                        "The checkup could not verify if your Windows Update service is "
                        "running because it lacked the necessary permissions. This is "
                        "not the same as everything being fine; we simply couldn't see "
                        "the status.\n\n"
                        "What to do: Run the checkup again as an administrator. On Windows, "
                        "right-click the app icon and select 'Run as administrator'."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "service_check_failed"},
                )
            )

        # Get recent update history
        update_history = self._get_update_history()
        last_update_date = None

        if update_history:
            recent_updates = update_history.get("recent_updates", [])
            last_update_date = update_history.get("last_update_date")

            if recent_updates:
                # Add INFO about recent updates
                update_summary = ", ".join(
                    [f"{u['kb']} ({u['date']})" for u in recent_updates[:5]]
                )
                findings.append(
                    Finding(
                        title="Recent Windows updates installed",
                        description=(
                            f"Found {len(recent_updates)} installed update(s). "
                            f"Recent updates: {update_summary}. "
                            f"Last update: {last_update_date}"
                        ),
                        severity=Severity.INFO,
                        category=self.category,
                        data={
                            "check": "recent_updates",
                            "update_count": len(recent_updates),
                            "recent_updates": recent_updates[:10],
                            "last_update_date": last_update_date,
                        },
                    )
                )
            else:
                findings.append(
                    Finding(
                        title="No recent Windows updates found",
                        description=(
                            "Could not retrieve Windows Update history. "
                            "Update information may not be available."
                        ),
                        severity=Severity.INFO,
                        category=self.category,
                        data={"check": "no_update_history"},
                    )
                )

        # Check if updates are too old
        if last_update_date:
            try:
                # Parse date string (format: YYYY-MM-DD)
                last_date = datetime.strptime(last_update_date, "%Y-%m-%d")
                days_since_update = (datetime.now() - last_date).days

                if days_since_update >= 90:
                    findings.append(
                        Finding(
                            title=f"No Windows updates in {days_since_update} days",
                            description=(
                                f"Your last Windows update was {days_since_update} days "
                                f"ago ({last_update_date}). Updates often fix security "
                                "holes that other software can exploit. Going this long "
                                "without updates is risky.\n\n"
                                "What to do: Open Start, type 'Windows Update', and select "
                                "'Check for updates'. Install any available updates and "
                                "restart your computer if prompted."
                            ),
                            severity=Severity.CRITICAL,
                            category=self.category,
                            data={
                                "check": "no_updates_90_days",
                                "days_since_update": days_since_update,
                                "last_update_date": last_update_date,
                            },
                        )
                    )
                elif days_since_update >= 30:
                    findings.append(
                        Finding(
                            title=f"Last Windows update was {days_since_update} days ago",
                            description=(
                                f"Your last Windows update was {days_since_update} days "
                                f"ago ({last_update_date}). While not an emergency, it "
                                "is a good idea to stay current to ensure you have the "
                                "latest security patches.\n\n"
                                "What to do: Open Start, type 'Windows Update', and select "
                                "'Check for updates' to see if anything new is available."
                            ),
                            severity=Severity.WARNING,
                            category=self.category,
                            data={
                                "check": "no_updates_30_days",
                                "days_since_update": days_since_update,
                                "last_update_date": last_update_date,
                            },
                        )
                    )
            except ValueError:
                # Could not parse date
                pass

        # Check for pending updates
        pending_updates = self._check_pending_updates()
        if pending_updates:
            if pending_updates.get("count", 0) > 0:
                findings.append(
                    Finding(
                        title=f"{pending_updates['count']} pending Windows update(s)",
                        description=(
                            f"Found {pending_updates['count']} pending update(s) waiting to be installed. "
                            "Your system may require a restart to complete installations."
                        ),
                        severity=Severity.INFO,
                        category=self.category,
                        data={
                            "check": "pending_updates",
                            "pending_count": pending_updates["count"],
                        },
                    )
                )

        # Check for failed updates
        failed_updates = self._check_failed_updates()
        if failed_updates and failed_updates.get("count", 0) > 0:
            findings.append(
                Finding(
                    title=f"{failed_updates['count']} Windows updates failed to install",
                    description=(
                        f"Windows tried to install {failed_updates['count']} updates but "
                        "ran into errors. These updates often contain important security "
                        "fixes, so the failures matter.\n\n"
                        "What to do: Open Start, type 'Windows Update', and select 'Check "
                        "for updates'. If they fail again, restart your computer and "
                        "try again. If problems persist, search for 'Troubleshoot' in "
                        "Settings and run the Windows Update troubleshooter."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "check": "failed_updates",
                        "failed_count": failed_updates["count"],
                    },
                )
            )

        # If no findings yet, add a positive finding
        if not findings:
            findings.append(
                Finding(
                    title="Windows Update status is healthy",
                    description=(
                        "Windows Update service is running and no issues detected. "
                        "System appears to be up to date."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "all_healthy"},
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        for finding in findings.findings:
            check = finding.data.get("check")

            if check == "service_stopped":
                actions.append(
                    Action(
                        title="Windows Update service is stopped",
                        description=(
                            "The Windows Update service (wuauserv) is not running. "
                            "To fix this: (1) Open Services (services.msc). "
                            "(2) Find 'Windows Update' in the list. "
                            "(3) Right-click and select 'Start'. "
                            "(4) Set Startup type to 'Automatic'. "
                            "Alternatively, run as Administrator: "
                            "net start wuauserv"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "service_check_failed":
                actions.append(
                    Action(
                        title="Could not check Windows Update service",
                        description=(
                            "Failed to determine Windows Update service status. "
                            "Ensure you are running with Administrator privileges. "
                            "Run this tool again as Administrator."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "no_updates_90_days":
                days = finding.data.get("days_since_update", 90)
                actions.append(
                    Action(
                        title=f"Critical: No updates in {days} days",
                        description=(
                            f"Your system has not received updates for {days} days. "
                            "This is a critical security risk. "
                            "To fix: (1) Open Settings > Update & Security > Windows Update. "
                            "(2) Click 'Check for updates'. "
                            "(3) Install all available updates. "
                            "(4) Restart if prompted. "
                            "If updates fail to install, try: "
                            "(a) Disconnect from VPN if using one. "
                            "(b) Disable antivirus temporarily. "
                            "(c) Check disk space (need ~20GB free). "
                            "(d) Visit https://support.microsoft.com/help/ for manual updates."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "no_updates_30_days":
                days = finding.data.get("days_since_update", 30)
                actions.append(
                    Action(
                        title=f"Last update was {days} days ago",
                        description=(
                            f"It's been {days} days since the last Windows update. "
                            "To check for updates: (1) Open Settings > Update & Security > Windows Update. "
                            "(2) Click 'Check for updates'. "
                            "(3) Install any available updates and restart if needed."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "pending_updates":
                count = finding.data.get("pending_count", 0)
                actions.append(
                    Action(
                        title=f"{count} pending update(s) waiting",
                        description=(
                            f"There are {count} pending update(s) to be installed. "
                            "To complete installation: (1) Open Settings > Update & Security > Windows Update. "
                            "(2) Review pending updates. "
                            "(3) Click 'Restart now' when ready to install and restart. "
                            "Or schedule the restart for a convenient time."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "failed_updates":
                count = finding.data.get("failed_count", 0)
                actions.append(
                    Action(
                        title=f"{count} failed update(s) detected",
                        description=(
                            f"Found {count} failed update installation(s). "
                            "This may prevent future updates from installing successfully. "
                            "To fix: (1) Open Settings > Update & Security > Troubleshoot. "
                            "(2) Run 'Additional troubleshooters' > 'Windows Update'. "
                            "(3) Let it attempt to fix the issues. "
                            "If problems persist, try running: "
                            "powershell -Command \"Stop-Service -Name wuauserv; "
                            "Remove-Item -Path C:\\Windows\\SoftwareDistribution -Recurse; "
                            "Start-Service -Name wuauserv\" (as Administrator)"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "recent_updates":
                actions.append(
                    Action(
                        title="Recent updates installed",
                        description=(
                            "Your system has recent Windows updates installed. "
                            "Continue to check for updates regularly to stay secure."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check in ("all_healthy", "no_update_history"):
                actions.append(
                    Action(
                        title="Windows Update status is healthy",
                        description=(
                            "Windows Update service is running normally. "
                            "Continue to check for updates regularly (at least monthly) "
                            "to maintain security."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _check_update_service(self) -> Optional[bool]:
        """Check if Windows Update service is running. Returns True/False/None."""
        try:
            result = subprocess.run(
                ["sc", "query", "wuauserv"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                # Check if service is running
                if "RUNNING" in result.stdout:
                    return True
                else:
                    return False
            return None
        except (OSError, subprocess.SubprocessError, TimeoutError):
            return None

    def _get_update_history(self) -> Optional[dict]:
        """Get recent update history from PowerShell Get-HotFix."""
        try:
            ps_cmd = (
                "Get-HotFix | Sort-Object InstalledOn -Descending | "
                "Select-Object -First 20 | "
                "Select-Object @{Name='KB'; Expression={$_.HotFixID}}, "
                "@{Name='InstalledOn'; Expression={$_.InstalledOn.ToString('yyyy-MM-dd')}} | "
                "ConvertTo-Json"
            )
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                return None

            return _parse_update_history(result.stdout)
        except (OSError, subprocess.SubprocessError, TimeoutError):
            return None

    def _check_pending_updates(self) -> Optional[dict]:
        """Check for pending Windows updates using COM object."""
        try:
            ps_cmd = (
                "$UpdateSession = New-Object -ComObject Microsoft.Update.Session; "
                "$UpdateSearcher = $UpdateSession.CreateUpdateSearcher(); "
                "try { "
                "$SearchResult = $UpdateSearcher.Search('IsInstalled=0'); "
                "$UpdateCount = $SearchResult.Updates.Count; "
                "Write-Output $UpdateCount "
                "} catch { Write-Output '0' }"
            )
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                timeout=15,
            )
            if result.returncode == 0:
                try:
                    count = int(result.stdout.strip())
                    return {"count": count}
                except ValueError:
                    return None
            return None
        except (OSError, subprocess.SubprocessError, TimeoutError):
            return None

    def _check_failed_updates(self) -> Optional[dict]:
        """Check for failed Windows updates in event log."""
        try:
            ps_cmd = (
                "Get-WinEvent -FilterHashtable @{LogName='System'; "
                "ProviderName='Windows Update'; Level=2,3} "
                "-MaxEvents 50 -ErrorAction SilentlyContinue | "
                "Where-Object {$_.Message -match 'failed|error'} | "
                "Measure-Object | Select-Object Count"
            )
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                count = _parse_event_count(result.stdout)
                if count and count > 0:
                    return {"count": count}
            return None
        except (OSError, subprocess.SubprocessError, TimeoutError):
            return None


def _parse_update_history(json_output: str) -> dict:
    """Parse PowerShell JSON output from Get-HotFix."""
    info = {"recent_updates": [], "last_update_date": None}

    if not json_output.strip():
        return info

    try:
        data = json.loads(json_output)
        if not isinstance(data, list):
            data = [data]

        for update in data:
            kb = update.get("KB", "Unknown")
            installed_on = update.get("InstalledOn", "Unknown")
            info["recent_updates"].append({"kb": kb, "date": installed_on})

        if info["recent_updates"]:
            info["last_update_date"] = info["recent_updates"][0]["date"]

        return info
    except (json.JSONDecodeError, ValueError, KeyError, TypeError):
        return info


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
