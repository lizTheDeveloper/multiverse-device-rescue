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
    name = "win_sfc_check"
    category = "integrity"
    platforms = [Platform.WIN32]
    risk_level = RiskLevel.SAFE
    priority = 55
    depends_on = []
    estimated_duration = "30s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Check CBS log for SFC scan results
        sfc_result = self._get_sfc_status()
        if sfc_result is None:
            findings.append(
                Finding(
                    title="Could not retrieve SFC scan status",
                    description=(
                        "Failed to read Windows CBS log. SFC scan status cannot be assessed. "
                        "Ensure you have Administrator privileges."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "sfc_status_failed"},
                )
            )
        else:
            # Process SFC findings
            if sfc_result.get("corrupt_found"):
                if sfc_result.get("corrupt_repaired"):
                    findings.append(
                        Finding(
                            title="Corrupt files found and repaired",
                            description=(
                                f"System File Checker found {sfc_result.get('corrupt_count', 'unknown')} "
                                "corrupt file(s) and successfully repaired them. "
                                "The system should be stable now. Monitor for any recurring issues."
                            ),
                            severity=Severity.WARNING,
                            category=self.category,
                            data={
                                "check": "sfc_corrupt_repaired",
                                "corrupt_count": sfc_result.get("corrupt_count"),
                            },
                        )
                    )
                else:
                    findings.append(
                        Finding(
                            title="Corrupt files found but NOT repaired",
                            description=(
                                f"System File Checker found {sfc_result.get('corrupt_count', 'unknown')} "
                                "corrupt file(s) but was unable to repair them. "
                                "This indicates serious system file corruption that requires intervention. "
                                "Run 'sfc /scannow' as Administrator in Command Prompt to attempt repairs, "
                                "or use DISM to restore files from Windows Update."
                            ),
                            severity=Severity.CRITICAL,
                            category=self.category,
                            data={
                                "check": "sfc_corrupt_not_repaired",
                                "corrupt_count": sfc_result.get("corrupt_count"),
                            },
                        )
                    )
            elif sfc_result.get("no_violations"):
                findings.append(
                    Finding(
                        title="No SFC integrity violations found",
                        description=(
                            "System File Checker scan completed successfully and found "
                            "no integrity violations. System files are healthy."
                        ),
                        severity=Severity.INFO,
                        category=self.category,
                        data={"check": "sfc_healthy"},
                    )
                )

        # Check DISM component store health
        dism_result = self._get_dism_health()
        if dism_result is None:
            findings.append(
                Finding(
                    title="Could not assess DISM component store health",
                    description=(
                        "Failed to run DISM /CheckHealth command. "
                        "Ensure you have Administrator privileges."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "dism_status_failed"},
                )
            )
        else:
            # Process DISM findings
            if dism_result.get("component_corruption"):
                findings.append(
                    Finding(
                        title="DISM detected component store corruption",
                        description=(
                            "The Windows component store has corruption issues detected by DISM. "
                            "This may prevent Windows Update and feature updates from working properly. "
                            "Run 'DISM /Online /Cleanup-Image /RestoreHealth' to attempt repairs."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={"check": "dism_corruption"},
                    )
                )
            elif dism_result.get("repairable_corruption"):
                findings.append(
                    Finding(
                        title="DISM detected repairable component store corruption",
                        description=(
                            "The Windows component store has repairable corruption. "
                            "Run 'DISM /Online /Cleanup-Image /RestoreHealth' to repair."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={"check": "dism_repairable"},
                    )
                )
            elif dism_result.get("healthy"):
                findings.append(
                    Finding(
                        title="DISM component store is healthy",
                        description=(
                            "The Windows component store is healthy with no corruption detected. "
                            "Windows Update and feature updates should work normally."
                        ),
                        severity=Severity.INFO,
                        category=self.category,
                        data={"check": "dism_healthy"},
                    )
                )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        for finding in findings.findings:
            check = finding.data.get("check")

            if check == "sfc_corrupt_repaired":
                corrupt_count = finding.data.get("corrupt_count", 0)
                actions.append(
                    Action(
                        title=f"Corrupt files repaired by SFC ({corrupt_count} file(s))",
                        description=(
                            f"System File Checker previously found and repaired {corrupt_count} "
                            "corrupt file(s). The system should be stable now. "
                            "Recommendations: (1) Monitor system stability for any recurring issues. "
                            "(2) If problems persist, run 'sfc /scannow' again as Administrator. "
                            "(3) Run Windows Update to ensure system is fully patched."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "sfc_corrupt_not_repaired":
                corrupt_count = finding.data.get("corrupt_count", 0)
                actions.append(
                    Action(
                        title=f"Corrupt system files require intervention ({corrupt_count} file(s))",
                        description=(
                            f"System File Checker found {corrupt_count} corrupt file(s) that could not be "
                            "automatically repaired. Manual intervention is required. "
                            "Recommendations: "
                            "(1) Run 'sfc /scannow' in Command Prompt as Administrator to attempt repairs. "
                            "(2) If that fails, run 'DISM /Online /Cleanup-Image /RestoreHealth' to restore "
                            "files from Windows Update. "
                            "(3) As a last resort, use System Restore or Windows Reset. "
                            "(4) If the problem persists after these steps, contact Microsoft Support."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "sfc_status_failed":
                actions.append(
                    Action(
                        title="Unable to assess SFC status",
                        description=(
                            "The CBS log could not be read to determine SFC status. "
                            "Recommendations: (1) Ensure you run this diagnostic with Administrator "
                            "privileges. (2) Try running 'sfc /scannow' manually in Command Prompt as "
                            "Administrator to check system file integrity. (3) This will create a detailed "
                            "log in %windir%\\Logs\\CBS\\CBS.log that records any issues found."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "sfc_healthy":
                actions.append(
                    Action(
                        title="System files are healthy",
                        description=(
                            "No SFC integrity violations detected. System files are intact and healthy. "
                            "Continue regular backups and keep Windows updated."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "dism_corruption":
                actions.append(
                    Action(
                        title="DISM component store corruption detected",
                        description=(
                            "The Windows component store has corruption that may affect Windows Update "
                            "and feature updates. Recommendations: "
                            "(1) Run 'DISM /Online /Cleanup-Image /RestoreHealth' in Command Prompt as "
                            "Administrator. This will download and restore corrupted components from Windows Update. "
                            "(2) If the network is limited, the scan may take significant time. "
                            "(3) After restoration, restart Windows. "
                            "(4) If corruption persists, consider Windows Reset or professional support."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "dism_repairable":
                actions.append(
                    Action(
                        title="DISM component store has repairable corruption",
                        description=(
                            "The Windows component store has corruption that can be repaired. "
                            "Recommendations: "
                            "(1) Run 'DISM /Online /Cleanup-Image /RestoreHealth' in Command Prompt as "
                            "Administrator to repair the corruption. "
                            "(2) Ensure a stable internet connection as this will download files from "
                            "Windows Update. "
                            "(3) Allow adequate time for completion (can take 15-30 minutes). "
                            "(4) Restart Windows after completion."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "dism_status_failed":
                actions.append(
                    Action(
                        title="Unable to assess DISM component store health",
                        description=(
                            "The DISM /CheckHealth command could not be executed. "
                            "Recommendations: (1) Ensure you run this diagnostic with Administrator "
                            "privileges. (2) Try running 'DISM /Online /Cleanup-Image /CheckHealth' manually "
                            "in Command Prompt as Administrator to check component store health. "
                            "(3) If it reports corruption, follow up with "
                            "'DISM /Online /Cleanup-Image /RestoreHealth'."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "dism_healthy":
                actions.append(
                    Action(
                        title="DISM component store is healthy",
                        description=(
                            "The Windows component store is healthy with no corruption detected. "
                            "Windows Update and feature updates should function normally. "
                            "Continue regular system maintenance and updates."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _get_sfc_status(self) -> Optional[dict]:
        """Get SFC scan status from CBS log."""
        try:
            ps_cmd = (
                "Get-Content $env:windir\\Logs\\CBS\\CBS.log -Tail 100 -ErrorAction SilentlyContinue"
            )
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                return None

            return _parse_sfc_log(result.stdout)
        except (OSError, subprocess.SubprocessError, TimeoutError):
            return None

    def _get_dism_health(self) -> Optional[dict]:
        """Check DISM component store health."""
        try:
            ps_cmd = "DISM /Online /Cleanup-Image /CheckHealth"
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                timeout=30,
            )
            # DISM may return non-zero exit code even on success, check output
            output = result.stdout + result.stderr
            return _parse_dism_output(output)
        except (OSError, subprocess.SubprocessError, TimeoutError):
            return None


def _parse_sfc_log(log_output: str) -> dict:
    """Parse CBS log to extract SFC scan results."""
    result = {
        "corrupt_found": False,
        "corrupt_repaired": False,
        "no_violations": False,
        "corrupt_count": 0,
    }

    if not log_output.strip():
        return result

    log_lower = log_output.lower()

    # Check for various SFC result patterns
    if "windows resource protection found corrupt files" in log_lower:
        result["corrupt_found"] = True
        # Look for repair status
        if "and successfully repaired them" in log_lower:
            result["corrupt_repaired"] = True
        else:
            result["corrupt_repaired"] = False

        # Try to extract count of corrupt files
        import re

        match = re.search(r"(\d+)\s+file", log_lower)
        if match:
            result["corrupt_count"] = int(match.group(1))

    elif "windows resource protection did not find any integrity violations" in log_lower:
        result["no_violations"] = True

    return result


def _parse_dism_output(output: str) -> dict:
    """Parse DISM output to determine component store health."""
    result = {
        "healthy": False,
        "repairable_corruption": False,
        "component_corruption": False,
    }

    if not output.strip():
        return result

    output_lower = output.lower()

    # DISM health status messages
    if "the component store is repairable" in output_lower:
        result["repairable_corruption"] = True
    elif "the component store is corrupted" in output_lower:
        result["component_corruption"] = True
    elif "the component store is healthy" in output_lower:
        result["healthy"] = True

    return result
