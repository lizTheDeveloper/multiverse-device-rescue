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
    name = "win_wmi_health"
    category = "integrity"
    platforms = [Platform.WIN32]
    risk_level = RiskLevel.SAFE
    priority = 55
    depends_on = []
    estimated_duration = "20s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Check WMI service status
        service_status = self._check_wmi_service()
        if service_status is None:
            findings.append(
                Finding(
                    title="Could not check WMI service status",
                    description=(
                        "Failed to query WMI service status. Unable to determine if WMI service is running."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "service_check_failed"},
                )
            )
        elif service_status["running"]:
            # Service is running, check repository
            repo_status = self._check_wmi_repository()
            if repo_status is None:
                findings.append(
                    Finding(
                        title="Could not verify WMI repository",
                        description=(
                            "Failed to run winmgmt /verifyrepository. WMI repository health cannot be verified."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={"check": "repo_verify_failed"},
                    )
                )
            elif not repo_status["valid"]:
                findings.append(
                    Finding(
                        title="WMI repository is corrupted",
                        description=(
                            "WMI repository verification failed. The repository may be corrupted, "
                            "which can cause scripts to fail, SCCM/Intune issues, and system management breakdowns. "
                            "The WMI service needs to be stopped and the repository rebuilt."
                        ),
                        severity=Severity.CRITICAL,
                        category=self.category,
                        data={"check": "repo_corrupted"},
                    )
                )
            else:
                # Repository is valid, check size
                repo_size = self._get_wmi_repository_size()
                if repo_size is not None and repo_size["size_mb"] > 500:
                    findings.append(
                        Finding(
                            title=f"WMI repository is bloated ({repo_size['size_mb']} MB)",
                            description=(
                                f"WMI repository size is {repo_size['size_mb']} MB, exceeding the 500 MB threshold. "
                                "A bloated repository can cause performance issues and management tool slowdowns. "
                                "The repository may need to be rebuilt."
                            ),
                            severity=Severity.WARNING,
                            category=self.category,
                            data={
                                "check": "repo_bloated",
                                "size_mb": repo_size["size_mb"],
                            },
                        )
                    )

            # Check for WMI errors in event log
            wmi_errors = self._get_wmi_errors()
            if wmi_errors is not None and wmi_errors["error_count"] > 0:
                findings.append(
                    Finding(
                        title=f"WMI errors found in event log ({wmi_errors['error_count']} events)",
                        description=(
                            f"Found {wmi_errors['error_count']} WMI-related errors in the event log. "
                            "This may indicate WMI health issues affecting system management tools."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={
                            "check": "wmi_errors",
                            "error_count": wmi_errors["error_count"],
                        },
                    )
                )

            # Add info about WMI service running
            if not findings or (findings and all(f.severity != Severity.CRITICAL for f in findings)):
                wmi_test = self._test_wmi_query()
                if wmi_test and wmi_test["success"]:
                    repo_size = self._get_wmi_repository_size()
                    size_str = (
                        f"{repo_size['size_mb']} MB"
                        if repo_size
                        else "unknown"
                    )
                    findings.append(
                        Finding(
                            title="WMI service is healthy and responsive",
                            description=(
                                f"WMI service is running and responding to queries. "
                                f"Repository size: {size_str}. "
                                f"OS detected: {wmi_test.get('os_caption', 'unknown')}. "
                                "No critical issues detected."
                            ),
                            severity=Severity.INFO,
                            category=self.category,
                            data={
                                "check": "wmi_healthy",
                                "os_caption": wmi_test.get("os_caption", "unknown"),
                                "os_version": wmi_test.get("os_version", "unknown"),
                                "repo_size_mb": repo_size["size_mb"] if repo_size else None,
                            },
                        )
                    )
        else:
            findings.append(
                Finding(
                    title="WMI service is not running",
                    description=(
                        "The Windows Management Instrumentation service (winmgmt) is not running. "
                        "This will cause scripts to fail, SCCM/Intune issues, and system management breakdowns. "
                        "The service must be restarted."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
                    data={"check": "service_not_running", "status": service_status.get("status", "unknown")},
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        for finding in findings.findings:
            check = finding.data.get("check")

            if check == "service_not_running":
                actions.append(
                    Action(
                        title="WMI service is not running",
                        description=(
                            "The Windows Management Instrumentation service is not running. "
                            "To restart it, run the following in Command Prompt (as Administrator): "
                            "net start winmgmt"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "repo_corrupted":
                actions.append(
                    Action(
                        title="WMI repository is corrupted",
                        description=(
                            "The WMI repository is corrupted and needs to be rebuilt. "
                            "To salvage the repository, run the following in Command Prompt (as Administrator): "
                            "winmgmt /salvagerepository"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "repo_bloated":
                size_mb = finding.data.get("size_mb", 0)
                actions.append(
                    Action(
                        title=f"WMI repository is bloated ({size_mb} MB)",
                        description=(
                            f"The WMI repository size is {size_mb} MB and may need to be rebuilt. "
                            "To rebuild the repository, run the following in Command Prompt (as Administrator): "
                            "winmgmt /salvagerepository"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "wmi_errors":
                error_count = finding.data.get("error_count", 0)
                actions.append(
                    Action(
                        title=f"WMI errors detected ({error_count} events)",
                        description=(
                            f"Found {error_count} WMI-related errors in the event log. "
                            "To troubleshoot and rebuild the repository if needed, run the following in Command Prompt (as Administrator): "
                            "winmgmt /salvagerepository"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "service_check_failed":
                actions.append(
                    Action(
                        title="Unable to check WMI service status",
                        description=(
                            "Unable to query WMI service status. Ensure you have Administrator privileges "
                            "and run the diagnostic again. Try running the following in Command Prompt (as Administrator): "
                            "sc query winmgmt"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "repo_verify_failed":
                actions.append(
                    Action(
                        title="Unable to verify WMI repository",
                        description=(
                            "Unable to verify WMI repository. Ensure you have Administrator privileges "
                            "and run the diagnostic again. Try running the following in Command Prompt (as Administrator): "
                            "winmgmt /verifyrepository"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "wmi_healthy":
                os_caption = finding.data.get("os_caption", "unknown")
                actions.append(
                    Action(
                        title="WMI service is healthy",
                        description=(
                            f"WMI service is running and responsive. "
                            f"Detected OS: {os_caption}. "
                            "Continue monitoring for any WMI-related issues."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _check_wmi_service(self) -> Optional[dict]:
        """Check WMI service (winmgmt) status via sc query."""
        try:
            result = subprocess.run(
                ["sc", "query", "winmgmt"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                return None

            return _parse_service_status(result.stdout)
        except (OSError, subprocess.SubprocessError, TimeoutError):
            return None

    def _check_wmi_repository(self) -> Optional[dict]:
        """Verify WMI repository via winmgmt /verifyrepository."""
        try:
            result = subprocess.run(
                ["winmgmt", "/verifyrepository"],
                capture_output=True,
                text=True,
                timeout=15,
            )
            # winmgmt /verifyrepository returns 0 if valid, non-zero if corrupted
            return {"valid": result.returncode == 0}
        except (OSError, subprocess.SubprocessError, TimeoutError):
            return None

    def _test_wmi_query(self) -> Optional[dict]:
        """Test WMI via PowerShell Get-WmiObject query."""
        try:
            ps_cmd = (
                "Get-WmiObject Win32_OperatingSystem | "
                "Select-Object Caption, Version | ConvertTo-Json"
            )
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                return None

            return _parse_wmi_os_info(result.stdout)
        except (OSError, subprocess.SubprocessError, TimeoutError):
            return None

    def _get_wmi_repository_size(self) -> Optional[dict]:
        """Get WMI repository size from C:\Windows\System32\wbem\Repository."""
        try:
            ps_cmd = (
                "(Get-ChildItem -Recurse C:\\Windows\\System32\\wbem\\Repository -ErrorAction SilentlyContinue | "
                "Measure-Object -Property Length -Sum).Sum"
            )
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                return None

            try:
                size_bytes = int(result.stdout.strip())
                size_mb = size_bytes / (1024 * 1024)
                return {"size_bytes": size_bytes, "size_mb": round(size_mb, 2)}
            except (ValueError, AttributeError):
                return None
        except (OSError, subprocess.SubprocessError, TimeoutError):
            return None

    def _get_wmi_errors(self) -> Optional[dict]:
        """Check for WMI-related errors in Windows event log."""
        try:
            ps_cmd = (
                "Get-WinEvent -LogName 'Microsoft-Windows-WMI-Activity/Operational' "
                "-MaxEvents 20 -ErrorAction SilentlyContinue | "
                "Where-Object {$_.Level -le 3} | Measure-Object | Select-Object Count"
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
            error_count = _parse_event_count(result.stdout)
            return {"error_count": error_count}
        except (OSError, subprocess.SubprocessError, TimeoutError):
            return None


def _parse_service_status(sc_output: str) -> dict:
    """Parse sc query winmgmt output."""
    status = {
        "running": False,
        "status": "unknown",
    }

    if not sc_output.strip():
        return status

    try:
        for line in sc_output.split("\n"):
            line = line.strip()
            if "STATE" in line.upper():
                # Line format: "STATE              : 4  RUNNING"
                parts = line.split(":")
                if len(parts) > 1:
                    state_str = parts[1].strip().upper()
                    status["status"] = state_str
                    status["running"] = "RUNNING" in state_str
                break
        return status
    except (ValueError, IndexError, AttributeError):
        return status


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


def _parse_wmi_os_info(json_output: str) -> dict:
    """Parse PowerShell JSON output from Get-WmiObject Win32_OperatingSystem."""
    import json

    info = {
        "success": False,
        "os_caption": None,
        "os_version": None,
    }

    if not json_output.strip():
        return info

    try:
        data = json.loads(json_output)
        info["success"] = True
        info["os_caption"] = data.get("Caption", "unknown")
        info["os_version"] = data.get("Version", "unknown")
        return info
    except (json.JSONDecodeError, ValueError, KeyError, AttributeError):
        return info
