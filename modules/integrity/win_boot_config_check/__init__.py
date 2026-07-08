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
    name = "win_boot_config_check"
    category = "integrity"
    platforms = [Platform.WIN32]
    risk_level = RiskLevel.SAFE
    priority = 65
    depends_on = []
    estimated_duration = "10s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Check boot entries
        boot_entries = self._get_boot_entries()
        if not boot_entries:
            findings.append(
                Finding(
                    title="Could not retrieve boot configuration",
                    description=(
                        "Failed to run bcdedit /enum. Boot configuration cannot be assessed."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "bcdedit_failed"},
                )
            )
            return CheckResult(module_name=self.name, findings=findings)

        # Check boot type
        boot_type_info = self._check_boot_type()
        if boot_type_info:
            findings.append(
                Finding(
                    title=f"Boot type: {boot_type_info['type']}",
                    description=(
                        f"System is using {boot_type_info['type']} boot. "
                        f"Loader: {boot_type_info['loader']}. "
                        "This is a standard boot configuration."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "boot_type_info", "boot_type": boot_type_info["type"]},
                )
            )

        # Check Secure Boot
        secure_boot_info = self._check_secure_boot()
        if secure_boot_info is not None:
            if not secure_boot_info["enabled"]:
                findings.append(
                    Finding(
                        title="Secure Boot is disabled",
                        description=(
                            "Secure Boot is currently disabled. This is a security risk "
                            "and is required for Windows 11. "
                            "Consider enabling Secure Boot in BIOS/UEFI settings."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={"check": "secure_boot_disabled"},
                    )
                )
            else:
                findings.append(
                    Finding(
                        title="Secure Boot is enabled",
                        description=(
                            "Secure Boot is enabled, protecting against malicious boot code."
                        ),
                        severity=Severity.INFO,
                        category=self.category,
                        data={"check": "secure_boot_enabled"},
                    )
                )

        # Check boot timeout
        timeout_info = self._get_boot_timeout()
        if timeout_info is not None:
            if timeout_info["timeout"] == 0:
                findings.append(
                    Finding(
                        title="Boot timeout is 0 seconds",
                        description=(
                            "Boot timeout is set to 0 seconds, which means you cannot select "
                            "recovery options or alternative boot entries. "
                            "Consider setting timeout to at least 5 seconds."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={"check": "boot_timeout_zero"},
                    )
                )
            else:
                findings.append(
                    Finding(
                        title=f"Boot timeout: {timeout_info['timeout']} seconds",
                        description=(
                            f"Boot timeout is set to {timeout_info['timeout']} seconds. "
                            "This allows time to select boot options at startup."
                        ),
                        severity=Severity.INFO,
                        category=self.category,
                        data={
                            "check": "boot_timeout_info",
                            "timeout": timeout_info["timeout"],
                        },
                    )
                )

        # Check for multiple boot entries
        if boot_entries.get("entry_count", 0) > 1:
            entries_info = ", ".join(boot_entries.get("entries", [])[:5])
            findings.append(
                Finding(
                    title=f"Multiple boot entries found ({boot_entries['entry_count']})",
                    description=(
                        f"Found {boot_entries['entry_count']} boot entries. "
                        f"Entries: {entries_info}. "
                        "This may indicate dual-boot or multiple OS installation."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "check": "multiple_boot_entries",
                        "entry_count": boot_entries["entry_count"],
                        "entries": boot_entries.get("entries", []),
                    },
                )
            )

        # Check Windows Boot Manager
        if boot_entries.get("default_boot_entry"):
            findings.append(
                Finding(
                    title=f"Default boot entry: {boot_entries['default_boot_entry']}",
                    description=(
                        f"Default boot entry is set to: {boot_entries['default_boot_entry']}. "
                        "This is the entry that will boot on next restart."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "check": "default_boot_entry",
                        "entry": boot_entries["default_boot_entry"],
                    },
                )
            )

        # Check Windows Recovery Environment
        recovery_info = self._check_recovery()
        if recovery_info is not None:
            if not recovery_info["enabled"]:
                findings.append(
                    Finding(
                        title="Windows Recovery Environment (RE) is disabled",
                        description=(
                            "Windows RE is disabled. This means you cannot boot into recovery "
                            "to troubleshoot boot failures. Consider enabling Windows RE."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={"check": "windows_re_disabled"},
                    )
                )
            else:
                findings.append(
                    Finding(
                        title="Windows Recovery Environment (RE) is enabled",
                        description=(
                            "Windows RE is enabled and can be used for troubleshooting boot issues."
                        ),
                        severity=Severity.INFO,
                        category=self.category,
                        data={"check": "windows_re_enabled"},
                    )
                )

        # Check Fast Startup
        fast_startup_info = self._check_fast_startup()
        if fast_startup_info is not None:
            if fast_startup_info["enabled"]:
                findings.append(
                    Finding(
                        title="Fast Startup is enabled",
                        description=(
                            "Fast Startup is enabled, which speeds up boot time but may cause "
                            "issues with dual-boot configurations and external drives. "
                            "If you experience boot problems, consider disabling Fast Startup."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={"check": "fast_startup_enabled"},
                    )
                )
            else:
                findings.append(
                    Finding(
                        title="Fast Startup is disabled",
                        description=(
                            "Fast Startup is disabled. Boot will be slightly slower but more compatible."
                        ),
                        severity=Severity.INFO,
                        category=self.category,
                        data={"check": "fast_startup_disabled"},
                    )
                )

        # Check last clean boot
        clean_boot_info = self._check_clean_boot()
        if clean_boot_info:
            findings.append(
                Finding(
                    title=f"Last clean boot: {clean_boot_info['time']}",
                    description=(
                        f"System last booted cleanly at {clean_boot_info['time']}. "
                        "This indicates no shutdown errors."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "check": "clean_boot_info",
                        "time": clean_boot_info["time"],
                    },
                )
            )

        if not findings:
            findings.append(
                Finding(
                    title="Boot configuration appears normal",
                    description=(
                        "All checked boot configuration settings appear to be in a normal state. "
                        "No immediate issues detected."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "boot_config_normal"},
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        for finding in findings.findings:
            check = finding.data.get("check")

            if check == "secure_boot_disabled":
                actions.append(
                    Action(
                        title="Secure Boot is disabled",
                        description=(
                            "Secure Boot is disabled. To enable it: "
                            "(1) Restart your computer and enter BIOS/UEFI settings "
                            "(usually F2, Del, F10, or F12 depending on manufacturer). "
                            "(2) Look for 'Secure Boot' or 'Security' settings. "
                            "(3) Enable Secure Boot. "
                            "(4) Save and exit. "
                            "Note: You may need to disable Fast Startup in Windows first to avoid issues."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "boot_timeout_zero":
                actions.append(
                    Action(
                        title="Boot timeout is 0 seconds",
                        description=(
                            "Boot timeout is set to 0 seconds. To fix this and enable boot menu access: "
                            "Run 'bcdedit /timeout 5' in PowerShell (as Administrator) "
                            "to set a 5-second timeout. "
                            "Or use 'bcdedit /timeout 30' for a longer timeout."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "windows_re_disabled":
                actions.append(
                    Action(
                        title="Windows Recovery Environment is disabled",
                        description=(
                            "Windows RE is disabled. To enable it: "
                            "Run 'reagentc /enable' in PowerShell (as Administrator). "
                            "If this fails, you may need to ensure a recovery partition exists "
                            "or contact Microsoft support."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "fast_startup_enabled":
                actions.append(
                    Action(
                        title="Fast Startup is enabled",
                        description=(
                            "Fast Startup is enabled, which may cause boot issues with dual-boot or external drives. "
                            "To disable it: "
                            "(1) Open Settings > System > Power & battery > Power settings. "
                            "(2) Click 'Choose what the power buttons do'. "
                            "(3) Check if 'Turn on fast startup' is checked. "
                            "(4) Uncheck it and save. "
                            "Alternatively, disable Hibernation: 'powercfg /h off' (as Administrator)."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "bcdedit_failed":
                actions.append(
                    Action(
                        title="Cannot assess boot configuration",
                        description=(
                            "The bcdedit command failed. Ensure you have Administrator privileges. "
                            "Try running: 'bcdedit /enum' in PowerShell (as Administrator). "
                            "If this still fails, the boot configuration may be corrupted. "
                            "You may need to use 'bootrec /scanos' and 'bootrec /rebuildbcd' "
                            "from Windows Recovery Environment."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check in [
                "boot_type_info",
                "secure_boot_enabled",
                "boot_timeout_info",
                "multiple_boot_entries",
                "default_boot_entry",
                "windows_re_enabled",
                "fast_startup_disabled",
                "clean_boot_info",
                "boot_config_normal",
            ]:
                actions.append(
                    Action(
                        title=finding.title,
                        description=finding.description,
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _get_boot_entries(self) -> Optional[dict]:
        """Get boot entries from bcdedit /enum."""
        try:
            result = subprocess.run(
                ["bcdedit", "/enum"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                return None

            return _parse_bcdedit_enum(result.stdout)
        except (OSError, subprocess.SubprocessError, TimeoutError):
            return None

    def _check_boot_type(self) -> Optional[dict]:
        """Check boot type (UEFI vs Legacy BIOS)."""
        try:
            result = subprocess.run(
                ["bcdedit", "/enum", "{current}"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                return None

            return _parse_boot_type(result.stdout)
        except (OSError, subprocess.SubprocessError, TimeoutError):
            return None

    def _check_secure_boot(self) -> Optional[dict]:
        """Check if Secure Boot is enabled via PowerShell."""
        try:
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", "Confirm-SecureBootUEFI"],
                capture_output=True,
                text=True,
                timeout=10,
            )

            enabled = result.returncode == 0 and "true" in result.stdout.lower()
            return {"enabled": enabled}
        except (OSError, subprocess.SubprocessError, TimeoutError):
            return None

    def _get_boot_timeout(self) -> Optional[dict]:
        """Get boot timeout from bcdedit /enum {bootmgr}."""
        try:
            result = subprocess.run(
                ["bcdedit", "/enum", "{bootmgr}"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                return None

            return _parse_boot_timeout(result.stdout)
        except (OSError, subprocess.SubprocessError, TimeoutError):
            return None

    def _check_recovery(self) -> Optional[dict]:
        """Check Windows Recovery Environment status via reagentc /info."""
        try:
            result = subprocess.run(
                ["reagentc", "/info"],
                capture_output=True,
                text=True,
                timeout=10,
            )

            # reagentc /info returns 0 if RE is available/enabled
            enabled = result.returncode == 0 and "Enabled" in result.stdout
            return {"enabled": enabled}
        except (OSError, subprocess.SubprocessError, TimeoutError):
            return None

    def _check_fast_startup(self) -> Optional[dict]:
        """Check if Fast Startup is enabled via registry."""
        try:
            result = subprocess.run(
                [
                    "reg",
                    "query",
                    r"HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power",
                    "/v",
                    "HiberbootEnabled",
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )

            # If the key exists and is 1, Fast Startup is enabled
            enabled = result.returncode == 0 and "0x1" in result.stdout
            return {"enabled": enabled}
        except (OSError, subprocess.SubprocessError, TimeoutError):
            return None

    def _check_clean_boot(self) -> Optional[dict]:
        """Check last clean boot via event log."""
        try:
            ps_cmd = (
                "Get-WinEvent -LogName System -FilterXPath \"*[System[EventID=12]]\" "
                "-MaxEvents 1 -ErrorAction SilentlyContinue | Select-Object -ExpandProperty TimeCreated"
            )
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                timeout=10,
            )

            if result.returncode == 0 and result.stdout.strip():
                time_str = result.stdout.strip().split("\n")[0]
                return {"time": time_str}
            return None
        except (OSError, subprocess.SubprocessError, TimeoutError):
            return None


def _parse_bcdedit_enum(output: str) -> dict:
    """Parse bcdedit /enum output."""
    entries = []
    default_entry = None
    current_entry = None

    for line in output.split("\n"):
        line = line.strip()

        # Look for entry identifiers
        if line.startswith("identifier"):
            current_entry = line.split()[-1] if line.split() else None

        # Look for display name
        if "description" in line.lower():
            parts = line.split(None, 1)
            if len(parts) > 1:
                entry_name = parts[1]
                entries.append(entry_name)

        # Look for default entry
        if "default" in line.lower() and "{" in line:
            default_entry = line.split("{")[-1].split("}")[0]
            if default_entry:
                default_entry = "{" + default_entry + "}"

    return {
        "entries": entries,
        "entry_count": len(entries),
        "default_boot_entry": default_entry or (entries[0] if entries else None),
    }


def _parse_boot_type(output: str) -> Optional[dict]:
    """Parse boot type from bcdedit /enum {current}."""
    boot_type = "Unknown"
    loader = "Unknown"

    for line in output.split("\n"):
        line_lower = line.lower()

        if "winload.efi" in line_lower:
            boot_type = "UEFI"
            loader = "winload.efi"
            break
        elif "winload.exe" in line_lower:
            boot_type = "Legacy BIOS"
            loader = "winload.exe"
            break

    if boot_type != "Unknown":
        return {"type": boot_type, "loader": loader}
    return None


def _parse_boot_timeout(output: str) -> Optional[dict]:
    """Parse boot timeout from bcdedit /enum {bootmgr}."""
    for line in output.split("\n"):
        if "timeout" in line.lower():
            parts = line.split()
            for i, part in enumerate(parts):
                if part.isdigit():
                    try:
                        return {"timeout": int(part)}
                    except ValueError:
                        pass
    return None
