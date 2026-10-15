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

    emits_codes = [
        "security.win_rootkit_check.unsigned_drivers",
        "security.win_rootkit_check.alternate_data_streams",
        "security.win_rootkit_check.secure_boot_disabled",
        "security.win_rootkit_check.hidden_services",
        "security.win_rootkit_check.boot_tampering",
        "security.win_rootkit_check.all_passed",
    ]

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Check for unsigned drivers
        unsigned_drivers = self._check_unsigned_drivers()
        if unsigned_drivers:
            findings.append(
                Finding(
                    title=(
                        f"Found {len(unsigned_drivers)} driver(s) without a security signature"
                    ),
                    description=(
                        f"We found {len(unsigned_drivers)} driver(s) in your system folder "
                        "that lack a security signature. Signatures prove a driver is "
                        "from a trusted maker. Unsigned drivers can be legitimate (like "
                        "older hardware) or malicious, so this needs a closer look.\n\n"
                        "Found: " + ", ".join(unsigned_drivers[:3]) + ("..." if len(unsigned_drivers) > 3 else "") + "\n\n"
                        "What to do: Look up each name. If it belongs to hardware or "
                        "software you use, it's probably fine. If not, run a Microsoft "
                        "Defender Offline scan: Windows Security > Virus & threat "
                        "protection > Scan options."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
                    code="security.win_rootkit_check.unsigned_drivers",
                    data={"check": "unsigned_drivers", "drivers": unsigned_drivers},
                )
            )

        # Check for Alternate Data Streams on system executables
        ads_found = self._check_alternate_data_streams()
        if ads_found:
            findings.append(
                Finding(
                    title=f"Found {len(ads_found)} system file(s) with hidden data streams",
                    description=(
                        f"We found {len(ads_found)} system file(s) with 'Alternate Data "
                        "Streams.' These are hidden sections inside files that can store "
                        "extra data. While sometimes used for legitimate purposes, they "
                        "are often used to hide malware.\n\n"
                        "Found in: " + ", ".join(ads_found[:3]) + ("..." if len(ads_found) > 3 else "") + "\n\n"
                        "What to do: Look up each name. If it belongs to hardware or "
                        "software you use, it's probably fine. If not, run a Microsoft "
                        "Defender Offline scan: Windows Security > Virus & threat "
                        "protection > Scan options."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.win_rootkit_check.alternate_data_streams",
                    data={"check": "alternate_data_streams", "files": ads_found},
                )
            )

        # Check Secure Boot status
        secure_boot_status = self._check_secure_boot()
        if secure_boot_status == "disabled":
            findings.append(
                Finding(
                    title="Your computer's Secure Boot protection is turned off",
                    description=(
                        "Secure Boot is a security feature that prevents unauthorized "
                        "software from running before Windows starts. It is currently "
                        "disabled, which makes it easier for certain types of malware "
                        "to hide on your computer.\n\n"
                        "What to do: Go to Settings > System > Recovery > Advanced "
                        "startup > Restart now, then Troubleshoot > Advanced options > "
                        "UEFI Firmware Settings, and turn Secure Boot on."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
                    code="security.win_rootkit_check.secure_boot_disabled",
                    data={"check": "secure_boot_disabled"},
                )
            )

        # Check for hidden services
        hidden_services = self._check_hidden_services()
        if hidden_services:
            findings.append(
                Finding(
                    title=f"Found {len(hidden_services)} service(s) that appear to be hidden",
                    description=(
                        f"We found {len(hidden_services)} service(s) that are visible "
                        "to some system tools but hidden from others. This is a common "
                        "technique used by malware to stay out of sight.\n\n"
                        "Found: " + ", ".join(hidden_services[:3]) + ("..." if len(hidden_services) > 3 else "") + "\n\n"
                        "If you think someone close to you may have installed this, talk "
                        "to an advocate first (US National Domestic Violence Hotline: "
                        "1-800-799-7233, or text START to 88788) before removing it, as "
                        "removal can alert them.\n\n"
                        "What to do: Don't stop or delete anything yet. Run a Microsoft "
                        "Defender Offline scan: Windows Security > Virus & threat "
                        "protection > Scan options."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.win_rootkit_check.hidden_services",
                    data={"check": "hidden_services", "services": hidden_services},
                )
            )

        # Check boot configuration
        boot_issues = self._check_boot_configuration()
        if boot_issues:
            findings.append(
                Finding(
                    title=(
                        f"Found {len(boot_issues)} unusual entry(ies) in your startup settings"
                    ),
                    description=(
                        f"We found {len(boot_issues)} unusual entry(ies) in your computer's "
                        "startup configuration. These settings control what loads when "
                        "your computer turns on. Unusual entries can indicate that someone "
                        "or something has modified your system.\n\n"
                        "Found: " + ", ".join(boot_issues[:2]) + ("..." if len(boot_issues) > 2 else "") + "\n\n"
                        "What to do: Run a Microsoft Defender Offline scan: Windows "
                        "Security > Virus & threat protection > Scan options. If an "
                        "entry still looks wrong afterwards, ask a technical helper to "
                        "review it."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.win_rootkit_check.boot_tampering",
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
                    code="security.win_rootkit_check.all_passed",
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
