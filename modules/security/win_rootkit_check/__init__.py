import json
import subprocess

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
    name = "win_rootkit_check"
    category = "security"
    platforms = [Platform.WIN32]
    risk_level = RiskLevel.SAFE
    priority = 75
    depends_on = []
    estimated_duration = "30s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Check for unsigned drivers
        unsigned_drivers = self._check_unsigned_drivers()
        if unsigned_drivers:
            findings.append(
                Finding(
                    title=f"Found {len(unsigned_drivers)} unsigned driver(s) in System32",
                    description=(
                        "Unsigned drivers in system32\\drivers may indicate rootkit "
                        "or driver-based malware. Found drivers: "
                        + ", ".join(unsigned_drivers[:3])
                        + ("..." if len(unsigned_drivers) > 3 else "")
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
                    data={"check": "unsigned_drivers", "drivers": unsigned_drivers},
                )
            )

        # Check for Alternate Data Streams on system executables
        ads_found = self._check_alternate_data_streams()
        if ads_found:
            findings.append(
                Finding(
                    title=f"Found {len(ads_found)} file(s) with Alternate Data Streams",
                    description=(
                        "Alternate Data Streams on system executables may hide malicious "
                        "code. Found in: " + ", ".join(ads_found[:3])
                        + ("..." if len(ads_found) > 3 else "")
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "alternate_data_streams", "files": ads_found},
                )
            )

        # Check Secure Boot status
        secure_boot_status = self._check_secure_boot()
        if secure_boot_status == "disabled":
            findings.append(
                Finding(
                    title="Secure Boot is disabled on UEFI system",
                    description=(
                        "Secure Boot is disabled, allowing unsigned bootloaders or kernels "
                        "to load, increasing risk of bootkit infection."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
                    data={"check": "secure_boot_disabled"},
                )
            )

        # Check for hidden services
        hidden_services = self._check_hidden_services()
        if hidden_services:
            findings.append(
                Finding(
                    title=f"Found {len(hidden_services)} potentially hidden service(s)",
                    description=(
                        "Services visible via sc query but not in Get-Service may indicate "
                        "hidden or rootkit services. Found: "
                        + ", ".join(hidden_services[:3])
                        + ("..." if len(hidden_services) > 3 else "")
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "hidden_services", "services": hidden_services},
                )
            )

        # Check boot configuration
        boot_issues = self._check_boot_configuration()
        if boot_issues:
            findings.append(
                Finding(
                    title=f"Found {len(boot_issues)} unusual boot configuration entries",
                    description=(
                        "Boot configuration has unexpected entries that may indicate tampering. "
                        + ", ".join(boot_issues[:2])
                        + ("..." if len(boot_issues) > 2 else "")
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "boot_tampering", "issues": boot_issues},
                )
            )

        # If no issues found, add INFO finding
        if not findings:
            findings.append(
                Finding(
                    title="All rootkit checks passed",
                    description=(
                        "No obvious rootkit indicators detected. Rootkit checks include: "
                        "unsigned drivers, alternate data streams, secure boot status, "
                        "hidden services, and boot configuration."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "all_passed"},
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
                        title="Enable Secure Boot",
                        description=(
                            "Secure Boot is disabled. Enable it in UEFI/BIOS settings "
                            "(Settings > System > Recovery > Advanced Startup > Restart now > Troubleshoot > "
                            "Advanced options > UEFI Firmware Settings)."
                        ),
                        risk_level=RiskLevel.MODERATE,
                        success=False,
                        error="Manual action required in UEFI/BIOS",
                    )
                )
            elif check == "unsigned_drivers":
                drivers = finding.data.get("drivers", [])
                actions.append(
                    Action(
                        title=f"Review unsigned drivers: {', '.join(drivers[:2])}",
                        description=(
                            "Unsigned drivers may indicate rootkit infection. "
                            "Review with your IT security team or run offline malware scan "
                            "using Windows Defender Offline or Microsoft Safety Scanner."
                        ),
                        risk_level=RiskLevel.MODERATE,
                        success=False,
                        error="Manual investigation required",
                    )
                )
            elif check == "alternate_data_streams":
                files = finding.data.get("files", [])
                actions.append(
                    Action(
                        title=f"Review ADS on files: {', '.join(files[:2])}",
                        description=(
                            "Alternate Data Streams may hide malicious code. "
                            "Remove with: Remove-Item 'filepath' -Stream 'streamname' "
                            "(requires admin and careful verification)."
                        ),
                        risk_level=RiskLevel.MODERATE,
                        success=False,
                        error="Manual action required",
                    )
                )
            elif check == "hidden_services":
                services = finding.data.get("services", [])
                actions.append(
                    Action(
                        title=f"Review hidden services: {', '.join(services[:2])}",
                        description=(
                            "These services may be hidden by rootkit. "
                            "Verify legitimacy and disable/remove if unauthorized."
                        ),
                        risk_level=RiskLevel.MODERATE,
                        success=False,
                        error="Manual review required",
                    )
                )
            elif check == "boot_tampering":
                actions.append(
                    Action(
                        title="Review boot configuration",
                        description=(
                            "Boot configuration may have been modified. "
                            "Run 'bcdedit /enum' to review all entries and compare with "
                            "baseline or trusted system."
                        ),
                        risk_level=RiskLevel.MODERATE,
                        success=False,
                        error="Manual review required",
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _check_unsigned_drivers(self) -> list[str]:
        """Check for unsigned drivers in System32\\drivers."""
        try:
            result = subprocess.run(
                [
                    "powershell",
                    "-NoProfile",
                    "-Command",
                    (
                        "$drivers = @(); "
                        "driverquery /v 2>$null | Select-Object -Skip 1 | "
                        "ForEach-Object { "
                        "  if ($_ -match 'No.*System32') { "
                        "    $name = ($_ -split '\\s+')[0]; "
                        "    $drivers += $name "
                        "  } "
                        "}; "
                        "ConvertTo-Json $drivers -AsArray"
                    ),
                ],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0 and result.stdout.strip():
                try:
                    drivers = json.loads(result.stdout)
                    return drivers if isinstance(drivers, list) else []
                except json.JSONDecodeError:
                    return []
        except (OSError, subprocess.SubprocessError):
            pass
        return []

    def _check_alternate_data_streams(self) -> list[str]:
        """Check for Alternate Data Streams on system executables."""
        try:
            result = subprocess.run(
                [
                    "powershell",
                    "-NoProfile",
                    "-Command",
                    (
                        "$files = @(); "
                        "Get-Item 'C:\\Windows\\System32\\*.exe' -Stream * -ErrorAction SilentlyContinue | "
                        "Where-Object {$_.Stream -ne ':$DATA'} | "
                        "Select-Object -ExpandProperty FileName -Unique | "
                        "ForEach-Object { $files += [System.IO.Path]::GetFileName($_) }; "
                        "ConvertTo-Json $files -AsArray"
                    ),
                ],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0 and result.stdout.strip():
                try:
                    files = json.loads(result.stdout)
                    return files if isinstance(files, list) else []
                except json.JSONDecodeError:
                    return []
        except (OSError, subprocess.SubprocessError):
            pass
        return []

    def _check_secure_boot(self) -> str | None:
        """Check if Secure Boot is enabled. Returns 'enabled', 'disabled', or None."""
        try:
            result = subprocess.run(
                [
                    "powershell",
                    "-NoProfile",
                    "-Command",
                    "Confirm-SecureBootUEFI -ErrorAction SilentlyContinue",
                ],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                output = result.stdout.strip().lower()
                if "true" in output or "enabled" in output:
                    return "enabled"
                elif "false" in output or "disabled" in output:
                    return "disabled"
        except (OSError, subprocess.SubprocessError):
            pass

        # Fallback to bcdedit
        try:
            result = subprocess.run(
                ["bcdedit", "/enum", "{current}"],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                if "secureboot" in result.stdout.lower():
                    output = result.stdout.lower()
                    if "off" in output or "no" in output:
                        return "disabled"
                    elif "on" in output or "yes" in output:
                        return "enabled"
        except (OSError, subprocess.SubprocessError):
            pass

        return None

    def _check_hidden_services(self) -> list[str]:
        """Check for services visible via sc query but not in Get-Service."""
        try:
            # Get services from Get-Service
            ps_result = subprocess.run(
                [
                    "powershell",
                    "-NoProfile",
                    "-Command",
                    "Get-Service -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name | ConvertTo-Json",
                ],
                capture_output=True,
                text=True,
            )
            get_service_names = set()
            if ps_result.returncode == 0 and ps_result.stdout.strip():
                try:
                    names = json.loads(ps_result.stdout)
                    get_service_names = set(names) if isinstance(names, list) else {names}
                except json.JSONDecodeError:
                    pass

            # Get services from sc query
            sc_result = subprocess.run(
                ["sc", "query", "state=", "all"],
                capture_output=True,
                text=True,
            )
            sc_names = set()
            if sc_result.returncode == 0:
                for line in sc_result.stdout.split("\n"):
                    if "SERVICE_NAME:" in line:
                        name = line.replace("SERVICE_NAME:", "").strip()
                        if name:
                            sc_names.add(name)

            # Find services in sc query but not in Get-Service
            hidden = list(sc_names - get_service_names)
            # Filter out common false positives
            filtered = [
                s for s in hidden if s and not s.startswith("_") and len(s) > 2
            ]
            return filtered[:10]  # Limit to 10 results

        except (OSError, subprocess.SubprocessError):
            pass
        return []

    def _check_boot_configuration(self) -> list[str]:
        """Check for suspicious boot configuration entries."""
        issues = []
        try:
            result = subprocess.run(
                ["bcdedit", "/enum"],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                lines = result.stdout.lower()
                # Check for suspicious indicators
                if "safemodecount" in lines:
                    issues.append("Unusual safe mode boot count detected")
                if "debugtype" in lines:
                    issues.append("Debug/test signing mode detected")
                if "nointegritychecks" in lines:
                    issues.append("Integrity checks disabled")
                if "loadoptions" in lines and any(
                    x in lines
                    for x in ["noeventhammer", "nopagefile", "redirect="]
                ):
                    issues.append("Suspicious load options detected")
        except (OSError, subprocess.SubprocessError):
            pass
        return issues
