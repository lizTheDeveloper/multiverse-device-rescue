import subprocess
import json

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
MIN_PAGEFILE_SIZE_MB = 0  # Disabled flag
LOW_DISK_THRESHOLD_PERCENT = 10  # Warning if pagefile drive is <10% free


class Module(ModuleBase):
    name = "win_pagefile"
    category = "performance"
    platforms = [Platform.WIN32]
    risk_level = RiskLevel.SAFE
    priority = 55
    depends_on = []
    estimated_duration = "5s"

    def check(self, profile: SystemProfile) -> CheckResult:
        pagefile_info = self._get_pagefile_info()
        total_ram_mb = profile.ram_bytes // (1024 * 1024)

        findings = []

        # If no pagefile data, try to get at least basic info
        if not pagefile_info.get("settings") and not pagefile_info.get("usage"):
            return CheckResult(module_name=self.name, findings=findings)

        pagefile_settings = pagefile_info.get("settings", {})
        pagefile_usage = pagefile_info.get("usage", {})

        # Check if pagefile is disabled
        if pagefile_settings.get("disabled", False):
            findings.append(
                Finding(
                    title="Your computer's extra memory (pagefile) is turned off",
                    description=(
                        "Your computer uses a file on your hard drive as extra memory "
                        "when your physical RAM runs out. This file is currently turned "
                        "off.\n\n"
                        "This means that if you open too many programs at once, your computer "
                        "might freeze or crash because it runs out of memory.\n\n"
                        "What to do: Type 'Advanced system settings' in the Start menu, "
                        "then choose Performance Settings > Advanced > Virtual memory > "
                        "Change, and tick 'Automatically manage paging file size for all "
                        "drives'."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"type": "pagefile_disabled"},
                )
            )
        else:
            # Get pagefile size in MB
            pagefile_size_mb = pagefile_settings.get("size_mb", 0)
            pagefile_location = pagefile_settings.get("location", "Unknown")

            # Check if pagefile is too small for machines with <8GB RAM
            if total_ram_mb < 8192 and pagefile_size_mb < total_ram_mb:
                findings.append(
                    Finding(
                        title=(
                            f"Your extra memory file is smaller than your RAM ({pagefile_size_mb}MB "
                            f"vs {total_ram_mb}MB)"
                        ),
                        description=(
                            f"Your computer has {total_ram_mb}MB of physical memory, but "
                            f"the file it uses for extra memory is only {pagefile_size_mb}MB.\n\n"
                            "On computers with less than 8GB of RAM, this file should "
                            "usually be at least as big as your physical memory. If it's "
                            "too small, your computer might crash when you try to do "
                            "heavy tasks.\n\n"
                            "What to do: Type 'Advanced system settings' in the Start menu, "
                        "then choose Performance Settings > Advanced > Virtual memory > "
                        "Change, and tick 'Automatically manage paging file size for all "
                        "drives'."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={
                            "type": "pagefile_too_small",
                            "pagefile_mb": pagefile_size_mb,
                            "ram_mb": total_ram_mb,
                        },
                    )
                )

            # Check disk space where pagefile is located
            pagefile_drive_free_percent = pagefile_settings.get(
                "drive_free_percent", None
            )
            if (
                pagefile_drive_free_percent is not None
                and pagefile_drive_free_percent < LOW_DISK_THRESHOLD_PERCENT
            ):
                findings.append(
                    Finding(
                        title=(
                            "The drive holding your extra memory file is almost full "
                            f"({pagefile_location})"
                        ),
                        description=(
                            f"The drive where your extra memory file lives ({pagefile_location}) "
                            f"has only {pagefile_drive_free_percent}% free space.\n\n"
                            "Your computer needs free space on this drive to expand the "
                            "extra memory file when needed. If the drive is too full, "
                            "the computer may crash or become very slow.\n\n"
                            "What to do: Open File Explorer, click on the drive shown "
                            "above, and look for large files you no longer need. You "
                            "can also go to Settings > System > Storage to see what is "
                            "taking up space and remove unnecessary items."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={
                            "type": "pagefile_drive_full",
                            "location": pagefile_location,
                            "free_percent": pagefile_drive_free_percent,
                        },
                    )
                )

            # Info: Report pagefile status
            pagefile_usage_percent = pagefile_usage.get("usage_percent", 0)
            findings.append(
                Finding(
                    title="Pagefile status",
                    description=(
                        f"Pagefile: {pagefile_location}, "
                        f"Size: {pagefile_size_mb}MB, "
                        f"Current usage: {pagefile_usage_percent}%. "
                        f"RAM: {total_ram_mb}MB."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "type": "pagefile_status",
                        "location": pagefile_location,
                        "size_mb": pagefile_size_mb,
                        "usage_percent": pagefile_usage_percent,
                        "ram_mb": total_ram_mb,
                    },
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            finding_type = finding.data.get("type")

            if finding_type == "pagefile_disabled":
                actions.append(
                    Action(
                        title="Enable pagefile",
                        description=(
                            "Pagefile is disabled. To re-enable: "
                            "1. Right-click 'This PC' > Properties > Advanced system settings. "
                            "2. Click 'Settings' under Performance. "
                            "3. Go to 'Advanced' tab > 'Virtual Memory' > 'Change'. "
                            "4. Select a drive with free space and set pagefile size."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif finding_type == "pagefile_too_small":
                ram_mb = finding.data.get("ram_mb", 0)
                actions.append(
                    Action(
                        title="Increase pagefile size",
                        description=(
                            f"Pagefile should be at least {ram_mb}MB on this machine. "
                            "To increase: "
                            "1. Right-click 'This PC' > Properties > Advanced system settings. "
                            "2. Click 'Settings' under Performance. "
                            "3. Go to 'Advanced' tab > 'Virtual Memory' > 'Change'. "
                            f"4. Set minimum and maximum to {ram_mb}MB (or 1.5x RAM for flexibility)."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif finding_type == "pagefile_drive_full":
                location = finding.data.get("location", "the pagefile drive")
                actions.append(
                    Action(
                        title="Free up disk space",
                        description=(
                            f"The drive containing pagefile ({location}) is nearly full. "
                            "Free up space by: "
                            "1. Deleting unnecessary files or programs. "
                            "2. Running Disk Cleanup (cleanmgr.exe). "
                            "3. Moving pagefile to a different drive if available."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif finding_type == "pagefile_status":
                location = finding.data.get("location", "Unknown")
                size_mb = finding.data.get("size_mb", 0)
                actions.append(
                    Action(
                        title="Pagefile configuration report",
                        description=(
                            f"Pagefile at {location}: {size_mb}MB. "
                            "Monitor usage. If it consistently uses >80% of size, consider increasing it."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _get_pagefile_info(self) -> dict:
        """Get pagefile settings, usage, and drive info via PowerShell."""
        info = {
            "settings": {},
            "usage": {},
        }

        try:
            # Get pagefile settings
            settings_script = (
                "Get-WmiObject Win32_PageFileSetting | "
                "Select-Object Name, InitialSize, MaximumSize | ConvertTo-Json"
            )
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", settings_script],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0 and result.stdout.strip():
                settings_data = self._parse_pagefile_settings(result.stdout)
                info["settings"] = settings_data
        except (OSError, subprocess.SubprocessError):
            pass

        try:
            # Get pagefile usage
            usage_script = (
                "Get-WmiObject Win32_PageFileUsage | "
                "Select-Object Name, CurrentUsage, AllocatedBaseSize | ConvertTo-Json"
            )
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", usage_script],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0 and result.stdout.strip():
                usage_data = self._parse_pagefile_usage(result.stdout)
                info["usage"] = usage_data
        except (OSError, subprocess.SubprocessError):
            pass

        # Merge settings and usage, and check drive space if pagefile exists
        if info["settings"]:
            pagefile_location = info["settings"].get("location", "")
            if pagefile_location:
                # Try to get drive free space
                drive_letter = pagefile_location.split(":")[0] if ":" in pagefile_location else ""
                if drive_letter:
                    try:
                        drive_script = (
                            f"Get-Volume -DriveLetter {drive_letter} | "
                            "Select-Object SizeRemaining, Size | ConvertTo-Json"
                        )
                        result = subprocess.run(
                            ["powershell", "-NoProfile", "-Command", drive_script],
                            capture_output=True,
                            text=True,
                        )
                        if result.returncode == 0 and result.stdout.strip():
                            drive_info = json.loads(result.stdout.strip())
                            if isinstance(drive_info, dict):
                                size_remaining = drive_info.get("SizeRemaining")
                                total_size = drive_info.get("Size")
                                if size_remaining and total_size and total_size > 0:
                                    free_percent = int(
                                        (size_remaining / total_size) * 100
                                    )
                                    info["settings"][
                                        "drive_free_percent"
                                    ] = free_percent
                    except (OSError, subprocess.SubprocessError, json.JSONDecodeError, ValueError):
                        pass

        return info

    def _parse_pagefile_settings(self, json_output: str) -> dict:
        """Parse PowerShell pagefile settings JSON output."""
        try:
            data = json.loads(json_output.strip())
            # Handle both single object and array
            if isinstance(data, list) and data:
                data = data[0]
            if isinstance(data, dict):
                # Check if pagefile is disabled (Name is null or empty)
                if not data.get("Name"):
                    return {"disabled": True}

                name = data.get("Name", "")
                initial_size = int(data.get("InitialSize", 0))
                maximum_size = int(data.get("MaximumSize", 0))

                # Use maximum size as the pagefile size, fall back to initial if max is 0
                pagefile_size_mb = maximum_size if maximum_size > 0 else initial_size

                return {
                    "disabled": False,
                    "location": name,
                    "size_mb": pagefile_size_mb,
                }
        except (json.JSONDecodeError, ValueError, TypeError):
            pass

        return {"disabled": False}

    def _parse_pagefile_usage(self, json_output: str) -> dict:
        """Parse PowerShell pagefile usage JSON output."""
        try:
            data = json.loads(json_output.strip())
            # Handle both single object and array
            if isinstance(data, list) and data:
                data = data[0]
            if isinstance(data, dict):
                current_usage = int(data.get("CurrentUsage", 0))
                allocated_base_size = int(data.get("AllocatedBaseSize", 0))

                if allocated_base_size > 0:
                    usage_percent = int((current_usage / allocated_base_size) * 100)
                else:
                    usage_percent = 0

                return {
                    "usage_percent": usage_percent,
                }
        except (json.JSONDecodeError, ValueError, TypeError):
            pass

        return {"usage_percent": 0}
