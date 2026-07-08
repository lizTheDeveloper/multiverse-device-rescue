import subprocess
from datetime import datetime
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
    name = "win_shadow_copies_check"
    category = "integrity"
    platforms = [Platform.WIN32]
    risk_level = RiskLevel.SAFE
    priority = 55
    depends_on = []
    estimated_duration = "10s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Check VSS service status
        vss_running = self._check_vss_service()

        # Check System Restore enabled status
        restore_enabled = self._check_system_restore_enabled()

        # Get shadow copy information
        shadow_info = self._get_shadow_copies()

        # Get shadow copy storage information
        storage_info = self._get_shadow_storage()

        # Determine critical issues
        if not vss_running:
            findings.append(
                Finding(
                    title="VSS service is disabled",
                    description=(
                        "The Volume Shadow Copy Service (VSS) is not running. "
                        "This means Windows cannot create restore points or shadow copies. "
                        "Ransomware often disables VSS to prevent recovery. "
                        "Your system is vulnerable to data loss."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
                    data={"check": "vss_disabled"},
                )
            )

        if (
            not vss_running
            and not restore_enabled
            and (not shadow_info or shadow_info.get("count", 0) == 0)
        ):
            findings.append(
                Finding(
                    title="No recovery capability available",
                    description=(
                        "VSS is disabled, System Restore is disabled, and no shadow copies exist. "
                        "Your system has no recovery capability. "
                        "If data is lost or corrupted, recovery will not be possible."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
                    data={"check": "no_recovery_capability"},
                )
            )

        # Check System Restore status
        if not restore_enabled:
            findings.append(
                Finding(
                    title="System Restore is disabled",
                    description=(
                        "System Restore is disabled on this system. "
                        "You cannot use Previous Versions or restore to an earlier point in time. "
                        "Enabling System Restore provides a safety net against data corruption and malware."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "restore_disabled"},
                )
            )

        # Check shadow copy storage allocation
        if storage_info:
            percent_allocated = storage_info.get("percent_allocated", 0)
            if 0 < percent_allocated < 5:
                findings.append(
                    Finding(
                        title="Shadow copy storage allocation is very small",
                        description=(
                            f"Shadow copy storage is only {percent_allocated}% of disk capacity. "
                            "This limits the number of restore points that can be kept. "
                            "Consider increasing the allocation to at least 5-10% for better protection."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={
                            "check": "small_storage_allocation",
                            "percent_allocated": percent_allocated,
                            "storage_info": storage_info,
                        },
                    )
                )

        # Add informational findings about restore points and shadow copies
        if shadow_info:
            count = shadow_info.get("count", 0)
            oldest = shadow_info.get("oldest_date")
            newest = shadow_info.get("newest_date")

            info_msg = f"Found {count} shadow copy/restore point(s). "
            if oldest and newest:
                info_msg += f"Oldest: {oldest}, Newest: {newest}. "
            if storage_info:
                info_msg += (
                    f"Storage allocated: {storage_info.get('allocated_human', 'unknown')} "
                    f"({storage_info.get('percent_allocated', 'unknown')}% of disk)."
                )

            findings.append(
                Finding(
                    title=f"Shadow copies available: {count} restore point(s)",
                    description=info_msg,
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "check": "restore_points_available",
                        "count": count,
                        "oldest_date": oldest,
                        "newest_date": newest,
                        "storage_info": storage_info,
                    },
                )
            )

        # If no critical issues but also no findings, add a success message
        if not findings:
            findings.append(
                Finding(
                    title="VSS and System Restore healthy",
                    description=(
                        "Volume Shadow Copy Service is running and System Restore is enabled. "
                        "Your system has recovery capability configured."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "vss_healthy"},
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        for finding in findings.findings:
            check = finding.data.get("check")

            if check == "vss_disabled":
                actions.append(
                    Action(
                        title="Enable Volume Shadow Copy Service",
                        description=(
                            "The VSS service is not running. "
                            "To re-enable it: (1) Open Services (services.msc) as Administrator. "
                            "(2) Find 'Volume Shadow Copy' service. (3) Right-click and select 'Start'. "
                            "(4) Set Startup Type to 'Automatic'. "
                            "This will allow Windows to create shadow copies for backups and recovery. "
                            "Note: If a ransomware attack disabled this, investigate the system thoroughly "
                            "before enabling it again."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "no_recovery_capability":
                actions.append(
                    Action(
                        title="Restore recovery capability",
                        description=(
                            "Your system has no recovery capability. "
                            "Steps to restore: (1) Enable VSS: Open Services (services.msc) as Administrator, "
                            "find 'Volume Shadow Copy', right-click and select Start, set Startup Type to Automatic. "
                            "(2) Enable System Restore: Right-click C: drive > Properties > System Protection tab > "
                            "Select drive and click Configure > adjust slider to allocate space for restore points > click OK. "
                            "(3) Create a manual restore point: Type 'Create a restore point' in Windows Search > "
                            "click Create button. "
                            "If you suspect ransomware, scan the system thoroughly before enabling these features."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "restore_disabled":
                actions.append(
                    Action(
                        title="Enable System Restore",
                        description=(
                            "System Restore is disabled. "
                            "To enable it: (1) Right-click the C: drive (or your system drive) > Properties. "
                            "(2) Go to the System Protection tab. (3) Select your drive and click Configure. "
                            "(4) Choose 'Turn on system protection' and adjust the slider to allocate space "
                            "(recommend 5-10% of disk). (5) Click OK. "
                            "This will enable creation of restore points that you can use to revert "
                            "system changes if needed."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "small_storage_allocation":
                percent = finding.data.get("percent_allocated", 0)
                actions.append(
                    Action(
                        title=f"Increase shadow copy storage allocation (currently {percent}%)",
                        description=(
                            f"Current shadow copy storage is only {percent}% of disk capacity, "
                            "which limits the number of restore points available. "
                            "To increase: (1) Right-click your system drive > Properties. "
                            "(2) Go to System Protection tab > Configure. "
                            "(3) Increase the slider to allocate 5-10% of disk (or more on larger drives). "
                            "(4) Click OK. "
                            "This allows Windows to keep more restore points and gives you better protection "
                            "against data loss."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "restore_points_available":
                count = finding.data.get("count", 0)
                actions.append(
                    Action(
                        title=f"Recovery capability available ({count} restore point(s))",
                        description=(
                            f"Your system has {count} shadow copy/restore point(s) available. "
                            "This means you can recover from system problems. "
                            "Best practices: (1) Keep System Restore and VSS enabled. "
                            "(2) Allocate 5-10% of your disk to shadow copies. "
                            "(3) Create manual restore points before major system changes. "
                            "(4) Keep backups in addition to restore points for critical data. "
                            "(5) Monitor VSS and System Restore regularly."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "vss_healthy":
                actions.append(
                    Action(
                        title="System recovery protection is enabled",
                        description=(
                            "VSS and System Restore are properly configured. "
                            "Your system has recovery capability for shadow copies and restore points. "
                            "Continue to: (1) Keep VSS and System Restore enabled. "
                            "(2) Monitor available disk space for restore points. "
                            "(3) Create regular backups for critical data. "
                            "(4) Test restore functionality periodically to ensure it works when needed."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _check_vss_service(self) -> bool:
        """Check if VSS service is running via 'sc query VSS'."""
        try:
            result = subprocess.run(
                ["sc", "query", "VSS"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode != 0:
                return False
            # Check for RUNNING state in output
            return "RUNNING" in result.stdout
        except (OSError, subprocess.SubprocessError, TimeoutError):
            return False

    def _check_system_restore_enabled(self) -> bool:
        """Check if System Restore is enabled via registry query."""
        try:
            result = subprocess.run(
                [
                    "reg",
                    "query",
                    "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SystemRestore",
                    "/v",
                    "RPSessionInterval",
                ],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode != 0:
                return False
            # If registry key exists, System Restore is enabled
            return True
        except (OSError, subprocess.SubprocessError, TimeoutError):
            return False

    def _get_shadow_copies(self) -> Optional[dict]:
        """Get shadow copy information via 'vssadmin list shadows'."""
        try:
            result = subprocess.run(
                ["vssadmin", "list", "shadows"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                return None

            return _parse_shadow_copies(result.stdout)
        except (OSError, subprocess.SubprocessError, TimeoutError):
            return None

    def _get_shadow_storage(self) -> Optional[dict]:
        """Get shadow copy storage information via 'vssadmin list shadowstorage'."""
        try:
            result = subprocess.run(
                ["vssadmin", "list", "shadowstorage"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                return None

            return _parse_shadow_storage(result.stdout)
        except (OSError, subprocess.SubprocessError, TimeoutError):
            return None


def _parse_shadow_copies(output: str) -> Optional[dict]:
    """Parse output from 'vssadmin list shadows'."""
    info = {"count": 0, "oldest_date": None, "newest_date": None}

    if not output.strip():
        return info

    lines = output.split("\n")
    shadow_count = 0
    dates = []

    for line in lines:
        # Try to get count from "Number of shadow copies on this system:" line
        if "Number of shadow copies on this system:" in line:
            try:
                count_str = line.split(":", 1)[-1].strip()
                shadow_count = int(count_str)
            except (ValueError, IndexError):
                pass
        # Count shadows as fallback
        elif "Shadow Copy ID:" in line or "Shadow Copy Volume:" in line:
            shadow_count += 1
        # Extract creation date
        if "Creation time:" in line:
            date_str = line.split("Creation time:", 1)[-1].strip()
            if date_str:
                dates.append(date_str)
                try:
                    # Try to parse the date for sorting
                    parsed = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
                    dates[-1] = (date_str, parsed)
                except (ValueError, AttributeError):
                    dates[-1] = (date_str, None)

    info["count"] = shadow_count

    # Sort dates and get oldest/newest
    valid_dates = [d for d in dates if isinstance(d, tuple) and d[1] is not None]
    if valid_dates:
        valid_dates.sort(key=lambda x: x[1])
        info["oldest_date"] = valid_dates[0][0]
        info["newest_date"] = valid_dates[-1][0]
    elif dates:
        # If no parsed dates, use string representation
        info["oldest_date"] = dates[0][0] if isinstance(dates[0], tuple) else dates[0]
        info["newest_date"] = dates[-1][0] if isinstance(dates[-1], tuple) else dates[-1]

    return info


def _parse_shadow_storage(output: str) -> Optional[dict]:
    """Parse output from 'vssadmin list shadowstorage'."""
    info = {"allocated": 0, "allocated_human": "unknown", "percent_allocated": 0}

    if not output.strip():
        return info

    lines = output.split("\n")

    for line in lines:
        # Look for allocation information
        if "Used" in line and "out of" in line:
            # Example: "Used: 10.20 GB out of 100.50 GB (10%)"
            try:
                parts = line.split("out of")
                if len(parts) >= 2:
                    right_part = parts[1].strip()
                    # Extract allocated size
                    allocated_str = right_part.split("(")[0].strip()
                    info["allocated_human"] = allocated_str

                    # Extract percentage
                    if "(" in right_part and ")" in right_part:
                        percent_str = right_part.split("(")[1].split(")")[0].replace("%", "").strip()
                        try:
                            info["percent_allocated"] = int(percent_str)
                        except ValueError:
                            pass
            except (IndexError, ValueError):
                pass

    return info
