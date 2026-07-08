import re
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
    name = "win_dism_health"
    category = "integrity"
    platforms = [Platform.WIN32]
    risk_level = RiskLevel.SAFE
    priority = 58
    depends_on = []
    estimated_duration = "30s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Check DISM component store health
        health_status = self._check_health()
        if health_status is None:
            findings.append(
                Finding(
                    title="Could not check DISM component store health",
                    description=(
                        "Failed to run DISM /CheckHealth command. "
                        "Ensure you have Administrator privileges and try again."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "health_check_failed"},
                )
            )
        else:
            # Process health status
            if health_status.get("corrupted"):
                findings.append(
                    Finding(
                        title="CRITICAL: Component store is corrupted",
                        description=(
                            "The Windows component store is corrupted and may be unrepairable. "
                            "This will prevent Windows Update and feature updates from working. "
                            "The component store requires professional intervention or system recovery."
                        ),
                        severity=Severity.CRITICAL,
                        category=self.category,
                        data={"check": "corrupted"},
                    )
                )
            elif health_status.get("repairable"):
                findings.append(
                    Finding(
                        title="CRITICAL: Component store is corrupted but repairable",
                        description=(
                            "The Windows component store has corruption that can be repaired using DISM. "
                            "Without repair, Windows Update and feature updates will not function properly. "
                            "Run 'DISM /Online /Cleanup-Image /RestoreHealth' from Administrator command prompt."
                        ),
                        severity=Severity.CRITICAL,
                        category=self.category,
                        data={"check": "repairable"},
                    )
                )
            elif health_status.get("healthy"):
                findings.append(
                    Finding(
                        title="Component store is healthy",
                        description=(
                            f"The Windows component store is healthy with no corruption detected. "
                            f"Component store size: {health_status.get('store_size', 'unknown')}. "
                            "Windows Update and feature updates should function normally."
                        ),
                        severity=Severity.INFO,
                        category=self.category,
                        data={
                            "check": "healthy",
                            "store_size": health_status.get("store_size"),
                        },
                    )
                )

        # Analyze component store size and cleanup status
        store_info = self._analyze_component_store()
        if store_info is None:
            findings.append(
                Finding(
                    title="Could not analyze component store",
                    description=(
                        "Failed to run DISM /AnalyzeComponentStore command. "
                        "Component store size cannot be assessed."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "analyze_failed"},
                )
            )
        else:
            # Check if cleanup is recommended
            if store_info.get("cleanup_recommended"):
                findings.append(
                    Finding(
                        title="WARNING: Component store cleanup recommended",
                        description=(
                            f"The WinSxS component store is {store_info.get('store_size', 'bloated')} "
                            "and cleanup is recommended to free up disk space. "
                            "Run 'DISM /Online /Cleanup-Image /StartComponentCleanup' to reduce the size."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={
                            "check": "cleanup_recommended",
                            "store_size": store_info.get("store_size"),
                        },
                    )
                )

            # Check if component store exceeds 10GB
            elif store_info.get("exceeds_10gb"):
                findings.append(
                    Finding(
                        title="WARNING: Component store is larger than 10GB",
                        description=(
                            f"The WinSxS component store is {store_info.get('store_size')} "
                            "and is consuming significant disk space. "
                            "Consider running 'DISM /Online /Cleanup-Image /StartComponentCleanup' "
                            "to optimize the installation."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={
                            "check": "exceeds_10gb",
                            "store_size": store_info.get("store_size"),
                        },
                    )
                )

        # Check for pending repairs
        pending_repairs = self._check_pending_repairs()
        if pending_repairs is not None and pending_repairs.get("has_pending"):
            findings.append(
                Finding(
                    title="Component store has pending repairs",
                    description=(
                        "The component store has pending repair operations from a previous attempt. "
                        "These repairs may need to be completed. "
                        "Restart Windows and run DISM again if issues persist."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "pending_repairs"},
                )
            )

        # Check if Windows Update source files are available
        windows_update_available = self._check_windows_update_source()
        if windows_update_available is not None:
            if not windows_update_available.get("available"):
                findings.append(
                    Finding(
                        title="Windows Update source files may not be available",
                        description=(
                            "Windows Update source files appear to be unavailable or inaccessible. "
                            "This may prevent DISM repair operations from completing successfully. "
                            "Ensure a stable internet connection and Windows Update is functioning."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={"check": "no_wu_source"},
                    )
                )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        for finding in findings.findings:
            check = finding.data.get("check")

            if check == "corrupted":
                actions.append(
                    Action(
                        title="Component store is corrupted and unrepairable",
                        description=(
                            "The Windows component store is corrupted and cannot be repaired using DISM. "
                            "This is a serious system issue. Recommendations: "
                            "(1) First try running 'DISM /Online /Cleanup-Image /RestoreHealth' from "
                            "Administrator command prompt to attempt recovery. "
                            "(2) If that fails, consider using Windows Reset or System Image recovery. "
                            "(3) As a last resort, professional support or clean Windows reinstall may be needed. "
                            "(4) Back up important data immediately before attempting major system changes."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "repairable":
                actions.append(
                    Action(
                        title="Component store corruption can be repaired",
                        description=(
                            "The Windows component store has corruption that can be repaired using DISM. "
                            "Recommendations: "
                            "(1) Open Command Prompt as Administrator. "
                            "(2) Run: DISM /Online /Cleanup-Image /RestoreHealth "
                            "(3) This will download and restore corrupted components from Windows Update. "
                            "(4) Ensure a stable internet connection as this may take 15-30 minutes. "
                            "(5) Restart Windows after the operation completes. "
                            "(6) If the operation fails, you may need to run Windows Reset."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "cleanup_recommended":
                store_size = finding.data.get("store_size", "bloated")
                actions.append(
                    Action(
                        title=f"Component store cleanup recommended ({store_size})",
                        description=(
                            f"The WinSxS component store is {store_size} and consuming significant disk space. "
                            "Recommendations: "
                            "(1) Open Command Prompt as Administrator. "
                            "(2) Run: DISM /Online /Cleanup-Image /StartComponentCleanup "
                            "(3) This will remove superseded components and free disk space. "
                            "(4) Allow 15-30 minutes for the operation to complete. "
                            "(5) System restart is usually recommended after cleanup. "
                            "(6) For more aggressive cleanup (if this doesn't free enough space), use: "
                            "DISM /Online /Cleanup-Image /StartComponentCleanup /ResetBase"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "exceeds_10gb":
                store_size = finding.data.get("store_size", "10GB or more")
                actions.append(
                    Action(
                        title=f"Component store optimization recommended ({store_size})",
                        description=(
                            f"The WinSxS component store is {store_size}. While not necessarily problematic, "
                            "this indicates optimization opportunities. Recommendations: "
                            "(1) Monitor disk usage to ensure adequate free space remains. "
                            "(2) If disk space is limited, run component store cleanup: "
                            "DISM /Online /Cleanup-Image /StartComponentCleanup "
                            "(3) Regular system maintenance and old update cleanup helps prevent excessive growth. "
                            "(4) If you rarely install new features, aggressive cleanup with /ResetBase may help."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "pending_repairs":
                actions.append(
                    Action(
                        title="Component store has pending repairs",
                        description=(
                            "The component store has pending repair operations from a previous DISM attempt. "
                            "Recommendations: "
                            "(1) Restart Windows to allow pending operations to complete. "
                            "(2) After restart, run this diagnostic again to verify status. "
                            "(3) If repairs still show as pending, run DISM again: "
                            "DISM /Online /Cleanup-Image /RestoreHealth "
                            "(4) Check Windows Update to ensure updates are installing correctly."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "no_wu_source":
                actions.append(
                    Action(
                        title="Windows Update source files unavailable",
                        description=(
                            "Windows Update source files are not available for DISM repair operations. "
                            "This can prevent automatic repair of corrupted components. Recommendations: "
                            "(1) Ensure a stable, unrestricted internet connection. "
                            "(2) Check that Windows Update is enabled and functioning: Settings > Update & Security. "
                            "(3) Try running: DISM /Online /Cleanup-Image /RestoreHealth "
                            "with a confirmed internet connection. "
                            "(4) If issues persist, you may need to use Windows installation media "
                            "or contact Microsoft Support."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "health_check_failed":
                actions.append(
                    Action(
                        title="Unable to check component store health",
                        description=(
                            "The DISM health check command could not be executed. "
                            "Recommendations: "
                            "(1) Ensure you have Administrator privileges. "
                            "(2) Open Command Prompt as Administrator (right-click, Run as administrator). "
                            "(3) Try running manually: DISM /Online /Cleanup-Image /CheckHealth "
                            "(4) Check the output for error messages. "
                            "(5) If errors persist, verify Windows is fully updated and try again."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "analyze_failed":
                actions.append(
                    Action(
                        title="Unable to analyze component store",
                        description=(
                            "The DISM AnalyzeComponentStore command could not be executed. "
                            "Component store size analysis is unavailable. Recommendations: "
                            "(1) Ensure you have Administrator privileges. "
                            "(2) Try running manually: DISM /Online /Cleanup-Image /AnalyzeComponentStore "
                            "(3) This will show the current size of the WinSxS folder and cleanup recommendations."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "healthy":
                store_size = finding.data.get("store_size", "unknown")
                actions.append(
                    Action(
                        title=f"Component store is healthy ({store_size})",
                        description=(
                            "The Windows component store is healthy with no corruption detected. "
                            "No immediate action needed. "
                            "Recommendations: "
                            "(1) Continue regular system maintenance and updates. "
                            "(2) Monitor disk space usage to ensure adequate free space remains. "
                            "(3) Run this diagnostic periodically to ensure ongoing health."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _check_health(self) -> Optional[dict]:
        """Run DISM CheckHealth command to get component store health status."""
        try:
            result = subprocess.run(
                ["Dism.exe", "/Online", "/Cleanup-Image", "/CheckHealth"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            output = result.stdout + result.stderr
            return _parse_health_output(output)
        except (OSError, subprocess.SubprocessError, TimeoutError):
            return None

    def _analyze_component_store(self) -> Optional[dict]:
        """Run DISM AnalyzeComponentStore to get component store size and cleanup status."""
        try:
            result = subprocess.run(
                ["Dism.exe", "/Online", "/Cleanup-Image", "/AnalyzeComponentStore"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            output = result.stdout + result.stderr
            return _parse_analyze_output(output)
        except (OSError, subprocess.SubprocessError, TimeoutError):
            return None

    def _check_pending_repairs(self) -> Optional[dict]:
        """Check if there are pending repairs in the component store."""
        try:
            # Query Windows event log for DISM pending repairs
            ps_cmd = (
                "Get-WinEvent -FilterHashtable @{LogName='System'; ProviderName='DISM'} "
                "-MaxEvents 20 -ErrorAction SilentlyContinue | "
                "Select-Object @{N='Message';E={$_.Message}} | "
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

            output = result.stdout
            return _parse_pending_repairs(output)
        except (OSError, subprocess.SubprocessError, TimeoutError):
            return None

    def _check_windows_update_source(self) -> Optional[dict]:
        """Check if Windows Update source files are available for repair."""
        try:
            # Check if Windows Update service is running and accessible
            ps_cmd = "Get-Service wuauserv | Select-Object -ExpandProperty Status"
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                return {"available": False}

            status = result.stdout.strip().lower()
            available = "running" in status or "stopped" in status  # Service exists
            return {"available": available}
        except (OSError, subprocess.SubprocessError, TimeoutError):
            return None


def _parse_health_output(output: str) -> dict:
    """Parse DISM /CheckHealth output to determine component store health."""
    result = {
        "healthy": False,
        "repairable": False,
        "corrupted": False,
        "store_size": "unknown",
    }

    if not output.strip():
        return result

    output_lower = output.lower()

    # Check health status messages
    if "the component store is healthy" in output_lower:
        result["healthy"] = True
    elif "the component store is repairable" in output_lower:
        result["repairable"] = True
    elif "the component store is corrupted" in output_lower:
        result["corrupted"] = True

    # Try to extract store size if available
    size_match = re.search(r"(\d+(?:,\d+)*)\s*(?:MB|GB|KB)", output, re.IGNORECASE)
    if size_match:
        result["store_size"] = size_match.group(0)

    return result


def _parse_analyze_output(output: str) -> dict:
    """Parse DISM /AnalyzeComponentStore output for size and cleanup status."""
    result = {
        "store_size": "unknown",
        "cleanup_recommended": False,
        "exceeds_10gb": False,
    }

    if not output.strip():
        return result

    output_lower = output.lower()

    # Look for cleanup recommendation
    if "component cleanup is recommended" in output_lower or "cleanup is recommended" in output_lower:
        result["cleanup_recommended"] = True

    # Try to extract component store size
    size_match = re.search(r"(\d+(?:,\d+)*\.?\d*)\s*(?:MB|GB|KB)", output, re.IGNORECASE)
    if size_match:
        size_str = size_match.group(0)
        result["store_size"] = size_str

        # Check if it exceeds 10GB
        if "gb" in size_str.lower():
            try:
                size_num = float(size_str.split()[0].replace(",", ""))
                if size_num > 10:
                    result["exceeds_10gb"] = True
            except (ValueError, IndexError):
                pass

    return result


def _parse_pending_repairs(output: str) -> dict:
    """Parse event log for pending DISM repairs."""
    result = {"has_pending": False}

    if not output.strip():
        return result

    output_lower = output.lower()

    # Check for pending repair indicators
    if "pending" in output_lower or "scheduled" in output_lower:
        result["has_pending"] = True

    return result
