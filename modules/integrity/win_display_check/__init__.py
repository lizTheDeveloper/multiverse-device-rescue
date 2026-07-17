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
    name = "win_display_check"
    category = "integrity"
    platforms = [Platform.WIN32]
    risk_level = RiskLevel.SAFE
    priority = 55
    depends_on = []
    estimated_duration = "10s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Get display information
        display_info = self._get_display_info()
        if not display_info:
            findings.append(
                Finding(
                    title="Could not retrieve display information",
                    description=(
                        "Failed to run Get-CimInstance for display adapters. "
                        "Display health cannot be assessed."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "display_info_failed"},
                )
            )
            return CheckResult(module_name=self.name, findings=findings)

        # Check for multiple monitors
        monitor_count = self._get_monitor_count()
        displays = display_info.get("displays", [])

        # Check for outdated display drivers
        outdated_drivers = []
        for display in displays:
            if display.get("is_outdated_driver"):
                outdated_drivers.append(display)

        if outdated_drivers:
            for driver in outdated_drivers:
                findings.append(
                    Finding(
                        title=f"Outdated display driver: {driver['name']}",
                        description=(
                            f"Display adapter '{driver['name']}' has a driver that is over 2 years old. "
                            f"Driver version: {driver['driver_version']}, "
                            f"Driver date: {driver['driver_date']}. "
                            "Outdated drivers may cause display issues, reduced performance, or compatibility problems. "
                            "Consider updating through Device Manager or manufacturer website."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={
                            "check": "outdated_driver",
                            "adapter_name": driver["name"],
                            "driver_version": driver["driver_version"],
                            "driver_date": driver["driver_date"],
                        },
                    )
                )

        # Check for high DPI scaling
        dpi_info = self._get_dpi_scaling()
        if dpi_info and dpi_info.get("dpi_level") and dpi_info["dpi_level"] > 120:
            findings.append(
                Finding(
                    title=f"High DPI scaling detected ({dpi_info['dpi_level']})",
                    description=(
                        f"Display scaling is set to {dpi_info['dpi_level']}% DPI. "
                        "Very high DPI scaling can cause some applications to appear blurry or scaled incorrectly. "
                        "This is especially common on high-resolution displays. "
                        "Some older applications may not scale properly with high DPI values. "
                        "You can adjust scaling in Display Settings if you experience visual issues."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "check": "high_dpi_scaling",
                        "dpi_level": dpi_info["dpi_level"],
                    },
                )
            )

        # Add informational findings about display configuration
        if displays:
            resolution_list = [
                f"{d['name']}: {d['resolution']}"
                for d in displays
                if d.get("resolution")
            ]
            resolution_summary = ", ".join(resolution_list) if resolution_list else "Unknown"

            findings.append(
                Finding(
                    title="Display configuration",
                    description=(
                        f"Display adapters: {len(displays)}. "
                        f"Connected monitors: {monitor_count if monitor_count else 'Unknown'}. "
                        f"Resolution(s): {resolution_summary}. "
                        "All display adapters and monitors are detected and configured."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "check": "display_config",
                        "adapter_count": len(displays),
                        "monitor_count": monitor_count or 0,
                        "displays": displays,
                    },
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        for finding in findings.findings:
            check = finding.data.get("check")

            if check == "outdated_driver":
                adapter_name = finding.data.get("adapter_name", "Unknown")
                actions.append(
                    Action(
                        title=f"Update display driver: {adapter_name}",
                        description=(
                            f"Display driver for '{adapter_name}' is outdated. "
                            "Recommendations: (1) Open Device Manager (devmgmt.msc). "
                            "(2) Expand 'Display adapters'. "
                            f"(3) Right-click '{adapter_name}' and select 'Update driver'. "
                            "(4) Choose 'Search automatically for updated driver software'. "
                            "Alternatively, visit the graphics card manufacturer's website "
                            "(NVIDIA, AMD, or Intel) and download the latest driver directly."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "high_dpi_scaling":
                dpi_level = finding.data.get("dpi_level", 0)
                actions.append(
                    Action(
                        title=f"High DPI scaling ({dpi_level}%)",
                        description=(
                            f"Your display is scaled to {dpi_level}% DPI. "
                            "If you experience blurry text or scaling issues: "
                            "(1) Right-click on the affected application. "
                            "(2) Select 'Properties' -> 'Compatibility'. "
                            "(3) Check 'Disable fullscreen optimizations'. "
                            "(4) Try 'Change high DPI settings' and enable 'Override high DPI scaling behavior'. "
                            "For system-wide changes, go to Settings -> Display -> Scale and layout."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "display_info_failed":
                actions.append(
                    Action(
                        title="Unable to assess display configuration",
                        description=(
                            "The display detection failed. "
                            "Ensure you have Administrator privileges and run the diagnostic again. "
                            "Try running the following in PowerShell (as Administrator): "
                            "Get-CimInstance Win32_VideoController | Select-Object Name, VideoModeDescription"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "display_config":
                monitor_count = finding.data.get("monitor_count", 0)
                actions.append(
                    Action(
                        title="Display configuration is normal",
                        description=(
                            f"All displays are configured properly. "
                            f"Detected {monitor_count} monitor(s) with {finding.data.get('adapter_count', 0)} adapter(s). "
                            "No configuration issues detected."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _get_display_info(self) -> Optional[dict]:
        """Get display information from PowerShell Get-CimInstance."""
        try:
            # PowerShell command to get video controller information
            ps_cmd = (
                "Get-CimInstance Win32_VideoController | "
                "Select-Object Name, VideoModeDescription, CurrentHorizontalResolution, "
                "CurrentVerticalResolution, CurrentRefreshRate, DriverVersion, DriverDate, AdapterRAM | "
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

            return _parse_display_info(result.stdout)
        except (OSError, subprocess.SubprocessError, TimeoutError):
            return None

    def _get_monitor_count(self) -> Optional[int]:
        """Get count of connected monitors."""
        try:
            ps_cmd = "Get-CimInstance Win32_DesktopMonitor | Measure-Object | Select-Object Count"
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                return None

            return _parse_monitor_count(result.stdout)
        except (OSError, subprocess.SubprocessError, TimeoutError):
            return None

    def _get_dpi_scaling(self) -> Optional[dict]:
        """Get display DPI scaling from registry."""
        try:
            ps_cmd = 'reg query "HKCU\\Control Panel\\Desktop" /v LogPixels'
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                return None

            return _parse_dpi_scaling(result.stdout)
        except (OSError, subprocess.SubprocessError, TimeoutError):
            return None


def _parse_display_info(json_output: str) -> dict:
    """Parse PowerShell JSON output from Get-CimInstance Win32_VideoController."""
    info = {"displays": []}

    if not json_output.strip():
        return info

    try:
        # Handle both single object and array
        data = json.loads(json_output)
        if not isinstance(data, list):
            data = [data]

        for display in data:
            name = display.get("Name", "Unknown")
            driver_version = display.get("DriverVersion", "Unknown")
            driver_date = display.get("DriverDate", None)
            adapter_ram = display.get("AdapterRAM", 0)

            # Parse resolution
            h_res = display.get("CurrentHorizontalResolution", 0)
            v_res = display.get("CurrentVerticalResolution", 0)
            refresh_rate = display.get("CurrentRefreshRate", 0)

            if h_res and v_res:
                resolution = f"{h_res}x{v_res}"
                if refresh_rate:
                    resolution += f" @ {refresh_rate}Hz"
            else:
                resolution = "Unknown"

            # Check if driver is outdated (> 2 years old)
            is_outdated = False
            if driver_date:
                try:
                    # PowerShell returns date as a string like "20210315000000.000000+000"
                    date_str = str(driver_date)
                    if len(date_str) >= 8:
                        year = int(date_str[:4])
                        month = int(date_str[4:6])
                        day = int(date_str[6:8])
                        driver_dt = datetime(year, month, day)
                        cutoff_date = datetime.now() - timedelta(days=730)  # 2 years
                        is_outdated = driver_dt < cutoff_date
                except (ValueError, TypeError):
                    is_outdated = False

            info["displays"].append(
                {
                    "name": name,
                    "resolution": resolution,
                    "driver_version": driver_version,
                    "driver_date": driver_date,
                    "adapter_ram": adapter_ram,
                    "is_outdated_driver": is_outdated,
                }
            )

        return info
    except (json.JSONDecodeError, ValueError, KeyError):
        return info


def _parse_monitor_count(output: str) -> int:
    """Extract monitor count from PowerShell Measure-Object output."""
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


def _parse_dpi_scaling(output: str) -> Optional[dict]:
    """Parse DPI scaling from registry query output."""
    try:
        # Format is like: "    LogPixels    REG_DWORD    0x78"
        for line in output.split("\n"):
            if "LogPixels" in line:
                parts = line.split()
                for i, part in enumerate(parts):
                    if "0x" in part.lower():
                        hex_value = int(part, 16)
                        return {"dpi_level": hex_value}
        return None
    except (ValueError, IndexError):
        return None
