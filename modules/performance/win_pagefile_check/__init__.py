import subprocess
import json
import re

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

# Thresholds
LOW_DISK_THRESHOLD_PERCENT = 10  # Warning if pagefile drive is <10% free
PAGEFILE_USAGE_THRESHOLD_PERCENT = 80  # Warning if usage > 80%


class Module(ModuleBase):
    name = "win_pagefile_check"
    category = "performance"
    platforms = [Platform.WIN32]
    risk_level = RiskLevel.SAFE
    priority = 65
    depends_on = []
    estimated_duration = "5s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Get pagefile configuration and usage
        pagefile_settings = self._get_pagefile_settings()
        pagefile_usage = self._get_pagefile_usage()
        total_ram_bytes = profile.ram_bytes
        total_ram_mb = total_ram_bytes // (1024 * 1024)

        # Check if no pagefile exists at all
        if not pagefile_settings and not pagefile_usage:
            findings.append(
                Finding(
                    title="No pagefile found",
                    description=(
                        "Pagefile (virtual memory) is not detected on this system. "
                        "Without a pagefile, the system will crash when physical RAM is exhausted. "
                        "This is critical for stability, especially on machines with limited RAM."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
                    data={"type": "no_pagefile"},
                )
            )
            return CheckResult(module_name=self.name, findings=findings)

        # If we have settings, analyze them
        if pagefile_settings:
            pagefile_location = pagefile_settings.get("location", "Unknown")
            pagefile_max_mb = pagefile_settings.get("max_size_mb", 0)
            pagefile_initial_mb = pagefile_settings.get("initial_size_mb", 0)

            # Check if pagefile max size is less than physical RAM
            if pagefile_max_mb > 0 and pagefile_max_mb < total_ram_mb:
                findings.append(
                    Finding(
                        title="Pagefile max size is smaller than physical RAM",
                        description=(
                            f"Pagefile maximum size is {pagefile_max_mb}MB but system has {total_ram_mb}MB RAM. "
                            f"If RAM is fully consumed, pagefile can only provide {pagefile_max_mb}MB of virtual memory, "
                            f"leaving {total_ram_mb - pagefile_max_mb}MB of memory requests unmet. "
                            f"Pagefile max should be at least equal to RAM size."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={
                            "type": "pagefile_too_small",
                            "pagefile_max_mb": pagefile_max_mb,
                            "ram_mb": total_ram_mb,
                            "location": pagefile_location,
                        },
                    )
                )

            # Check if pagefile is on a nearly full drive
            drive_free_percent = pagefile_settings.get("drive_free_percent")
            if drive_free_percent is not None and drive_free_percent < LOW_DISK_THRESHOLD_PERCENT:
                findings.append(
                    Finding(
                        title="Pagefile drive is nearly full",
                        description=(
                            f"The drive containing pagefile ({pagefile_location}) has only {drive_free_percent}% free space. "
                            f"Pagefile needs free disk space to expand under memory pressure. "
                            f"Free up at least 10% of the drive."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={
                            "type": "pagefile_drive_nearly_full",
                            "location": pagefile_location,
                            "free_percent": drive_free_percent,
                        },
                    )
                )

        # If we have usage info, check if pagefile usage is high
        if pagefile_usage:
            current_usage_mb = pagefile_usage.get("current_usage_mb", 0)
            allocated_size_mb = pagefile_usage.get("allocated_size_mb", 0)
            peak_usage_mb = pagefile_usage.get("peak_usage_mb", 0)

            if allocated_size_mb > 0:
                usage_percent = (current_usage_mb / allocated_size_mb) * 100
                if usage_percent > PAGEFILE_USAGE_THRESHOLD_PERCENT:
                    findings.append(
                        Finding(
                            title="Pagefile usage is high",
                            description=(
                                f"Pagefile usage is {usage_percent:.1f}% ({current_usage_mb}MB of {allocated_size_mb}MB allocated). "
                                f"System is under significant memory pressure. "
                                f"Consider increasing pagefile size or adding more RAM."
                            ),
                            severity=Severity.WARNING,
                            category=self.category,
                            data={
                                "type": "pagefile_high_usage",
                                "current_usage_mb": current_usage_mb,
                                "allocated_size_mb": allocated_size_mb,
                                "usage_percent": usage_percent,
                                "peak_usage_mb": peak_usage_mb,
                            },
                        )
                    )

        # Always add INFO finding with pagefile configuration summary
        pagefile_location = pagefile_settings.get("location", "Unknown") if pagefile_settings else "Unknown"
        pagefile_max_mb = pagefile_settings.get("max_size_mb", 0) if pagefile_settings else 0
        pagefile_initial_mb = pagefile_settings.get("initial_size_mb", 0) if pagefile_settings else 0
        current_usage_mb = pagefile_usage.get("current_usage_mb", 0) if pagefile_usage else 0
        allocated_size_mb = pagefile_usage.get("allocated_size_mb", 0) if pagefile_usage else 0

        # Calculate pagefile status string
        if pagefile_max_mb > 0:
            pagefile_config = f"{pagefile_initial_mb}MB-{pagefile_max_mb}MB"
        else:
            pagefile_config = "Not configured"

        findings.append(
            Finding(
                title="Pagefile configuration summary",
                description=(
                    f"Location: {pagefile_location}\n"
                    f"Configured size: {pagefile_config}\n"
                    f"Current usage: {current_usage_mb}MB/{allocated_size_mb}MB\n"
                    f"System RAM: {total_ram_mb}MB\n"
                    f"Pagefile-to-RAM ratio: {(pagefile_max_mb / total_ram_mb if total_ram_mb > 0 else 0):.2f}x"
                ),
                severity=Severity.INFO,
                category=self.category,
                data={
                    "type": "pagefile_status",
                    "location": pagefile_location,
                    "configured_size": pagefile_config,
                    "current_usage_mb": current_usage_mb,
                    "allocated_size_mb": allocated_size_mb,
                    "ram_mb": total_ram_mb,
                    "pagefile_to_ram_ratio": pagefile_max_mb / total_ram_mb if total_ram_mb > 0 else 0,
                },
            )
        )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        """
        Provide informational actions about pagefile configuration.
        This is a diagnostic tool - it reports issues and suggests solutions,
        but does NOT modify system settings.
        """
        actions = []
        for finding in findings.findings:
            finding_type = finding.data.get("type")

            if finding_type == "no_pagefile":
                actions.append(
                    Action(
                        title="Enable pagefile (Virtual Memory)",
                        description=(
                            "Pagefile is not configured. To enable:\n"
                            "1. Right-click 'This PC' and select 'Properties'.\n"
                            "2. Click 'Advanced system settings' on the left.\n"
                            "3. Under 'Performance', click 'Settings'.\n"
                            "4. Go to the 'Advanced' tab and click 'Change' under 'Virtual Memory'.\n"
                            "5. Uncheck 'Automatically manage paging file size'.\n"
                            "6. Select a drive (ideally with free space) and set initial and maximum size "
                            "(recommended: 1.5x to 3x physical RAM).\n"
                            "7. Click 'Set' and restart the computer."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif finding_type == "pagefile_too_small":
                ram_mb = finding.data.get("ram_mb", 0)
                pagefile_max_mb = finding.data.get("pagefile_max_mb", 0)
                actions.append(
                    Action(
                        title="Increase pagefile size",
                        description=(
                            f"Pagefile maximum size ({pagefile_max_mb}MB) is smaller than RAM ({ram_mb}MB). "
                            f"Recommended minimum: {ram_mb}MB. "
                            f"Recommended optimal: {int(ram_mb * 1.5)}-{int(ram_mb * 3)}MB.\n"
                            "To adjust:\n"
                            "1. Right-click 'This PC' > 'Properties'.\n"
                            "2. Click 'Advanced system settings'.\n"
                            "3. Under 'Performance', click 'Settings' > 'Advanced' tab.\n"
                            "4. Click 'Change' under 'Virtual Memory'.\n"
                            f"5. Set Initial size: {ram_mb}MB, Maximum size: {int(ram_mb * 1.5)}MB.\n"
                            "6. Click 'Set' and restart."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif finding_type == "pagefile_drive_nearly_full":
                location = finding.data.get("location", "the pagefile drive")
                actions.append(
                    Action(
                        title="Free up disk space for pagefile",
                        description=(
                            f"The drive containing pagefile ({location}) is nearly full. "
                            "Pagefile needs room to grow under memory pressure.\n"
                            "Options:\n"
                            "1. Run Disk Cleanup (cleanmgr.exe) to remove temporary files.\n"
                            "2. Uninstall unused programs from Control Panel.\n"
                            "3. Move pagefile to a different drive with more free space "
                            "(via Virtual Memory settings).\n"
                            "4. Compress old files or move them to external storage.\n"
                            "Goal: Free at least 10% of the drive."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif finding_type == "pagefile_high_usage":
                actions.append(
                    Action(
                        title="Address high pagefile usage",
                        description=(
                            "Pagefile is being used heavily, indicating memory pressure. "
                            "Options:\n"
                            "1. Increase pagefile size via Virtual Memory settings.\n"
                            "2. Add more physical RAM to the system.\n"
                            "3. Close memory-intensive applications.\n"
                            "4. Check for memory leaks or malware (run Disk Cleanup or antivirus).\n"
                            "5. Reduce startup programs using Task Manager or startup optimization tools."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif finding_type == "pagefile_status":
                actions.append(
                    Action(
                        title="Pagefile configuration report",
                        description=finding.description,
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        data=finding.data,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _get_pagefile_settings(self) -> dict | None:
        """Get pagefile settings via PowerShell Win32_PageFileSetting."""
        try:
            script = (
                "Get-WmiObject Win32_PageFileSetting | "
                "Select-Object Name, InitialSize, MaximumSize | ConvertTo-Json"
            )
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", script],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0 and result.stdout.strip():
                return self._parse_pagefile_settings(result.stdout)
        except (OSError, subprocess.SubprocessError, subprocess.TimeoutExpired):
            pass
        return None

    def _get_pagefile_usage(self) -> dict | None:
        """Get pagefile usage via PowerShell Win32_PageFileUsage."""
        try:
            script = (
                "Get-WmiObject Win32_PageFileUsage | "
                "Select-Object Name, CurrentUsage, AllocatedBaseSize, PeakUsage | ConvertTo-Json"
            )
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", script],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0 and result.stdout.strip():
                return self._parse_pagefile_usage(result.stdout)
        except (OSError, subprocess.SubprocessError, subprocess.TimeoutExpired):
            pass
        return None

    def _parse_pagefile_settings(self, json_output: str) -> dict | None:
        """Parse PowerShell Win32_PageFileSetting JSON output."""
        try:
            data = json.loads(json_output.strip())
            # Handle both single object and array
            if isinstance(data, list):
                if not data:
                    return None
                data = data[0]
            if not isinstance(data, dict):
                return None

            # Extract pagefile info
            name = data.get("Name", "")
            initial_size = int(data.get("InitialSize", 0))
            maximum_size = int(data.get("MaximumSize", 0))

            if not name:
                return None

            result = {
                "location": name,
                "initial_size_mb": initial_size,
                "max_size_mb": maximum_size,
            }

            # Try to get drive free space
            drive_free_percent = self._get_drive_free_percent(name)
            if drive_free_percent is not None:
                result["drive_free_percent"] = drive_free_percent

            return result
        except (json.JSONDecodeError, ValueError, TypeError):
            pass
        return None

    def _parse_pagefile_usage(self, json_output: str) -> dict | None:
        """Parse PowerShell Win32_PageFileUsage JSON output."""
        try:
            data = json.loads(json_output.strip())
            # Handle both single object and array
            if isinstance(data, list):
                if not data:
                    return None
                data = data[0]
            if not isinstance(data, dict):
                return None

            current_usage = int(data.get("CurrentUsage", 0))
            allocated_base_size = int(data.get("AllocatedBaseSize", 0))
            peak_usage = int(data.get("PeakUsage", 0))

            return {
                "current_usage_mb": current_usage,
                "allocated_size_mb": allocated_base_size,
                "peak_usage_mb": peak_usage,
            }
        except (json.JSONDecodeError, ValueError, TypeError):
            pass
        return None

    def _get_drive_free_percent(self, pagefile_path: str) -> int | None:
        """Get free space percentage for the drive containing pagefile."""
        try:
            # Extract drive letter from path (e.g., "C:\pagefile.sys" -> "C")
            drive_letter = None
            match = re.match(r"([A-Za-z]):", pagefile_path)
            if match:
                drive_letter = match.group(1)
            else:
                return None

            script = (
                f"Get-Volume -DriveLetter {drive_letter} | "
                "Select-Object SizeRemaining, Size | ConvertTo-Json"
            )
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", script],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0 and result.stdout.strip():
                drive_info = json.loads(result.stdout.strip())
                if isinstance(drive_info, dict):
                    size_remaining = drive_info.get("SizeRemaining")
                    total_size = drive_info.get("Size")
                    if size_remaining is not None and total_size and total_size > 0:
                        return int((size_remaining / total_size) * 100)
        except (OSError, subprocess.SubprocessError, json.JSONDecodeError, ValueError, TypeError, subprocess.TimeoutExpired):
            pass
        return None
