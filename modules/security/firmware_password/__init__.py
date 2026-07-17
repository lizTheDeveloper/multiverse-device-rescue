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
    name = "firmware_password"
    category = "security"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 60
    depends_on = []
    estimated_duration = "2s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Detect chip type
        chip_type = self._get_chip_type()

        if chip_type is None:
            findings.append(
                Finding(
                    title="Unable to determine CPU architecture",
                    description=(
                        "Could not detect whether this is an Intel or Apple Silicon Mac. "
                        "Firmware password/Startup Security status could not be checked."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "chip_type_detection"},
                )
            )
            return CheckResult(module_name=self.name, findings=findings)

        # Add info about chip type
        findings.append(
            Finding(
                title=f"System architecture: {chip_type}",
                description=f"This Mac uses {chip_type} processor.",
                severity=Severity.INFO,
                category=self.category,
                data={"check": "chip_type", "chip_type": chip_type},
            )
        )

        if chip_type == "Intel":
            self._check_intel_firmware_password(findings)
        elif chip_type == "Apple Silicon":
            self._check_apple_silicon_startup_security(findings)

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        """
        Provide informational guidance on firmware password and startup security.
        Does not modify the system.
        """
        actions = []

        for finding in findings.findings:
            check = finding.data.get("check")

            if check == "firmware_password_not_set":
                actions.append(
                    Action(
                        title="Enable Firmware Password on Intel Mac",
                        description=(
                            "Firmware password adds another layer of protection by "
                            "requiring a password before the Mac can be started up from an "
                            "external drive or into Recovery Mode. This is important for "
                            "protecting against physical device theft and unauthorized access.\n\n"
                            "To enable:\n"
                            "1. Reboot into Recovery Mode (Cmd+R during startup)\n"
                            "2. Go to Utilities > Firmware Password Utility\n"
                            "3. Click Set Password and create a secure password\n"
                            "4. Remember this password - it cannot be easily reset\n\n"
                            "Note: If you forget the firmware password, you will need to "
                            "contact Apple Support or visit an Apple Store for assistance."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "firmware_password_set":
                actions.append(
                    Action(
                        title="Firmware Password Status: Protected",
                        description=(
                            "This Mac has a firmware password set, which provides protection "
                            "against unauthorized startup from external media and access to "
                            "Recovery Mode. This is good security practice for asset protection."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "startup_security_info":
                actions.append(
                    Action(
                        title="Startup Security Utility Status",
                        description=(
                            "Apple Silicon Macs use the Startup Security Utility instead of "
                            "firmware passwords. This provides multiple security options:\n\n"
                            "Security Policies:\n"
                            "- Full Security: Requires signed software and allows booting from "
                            "external drives\n"
                            "- Reduced Security: Allows older versions of macOS and updates to "
                            "older versions\n"
                            "- Permissive Security: Allows booting into single-user mode and "
                            "NVRAM reset\n\n"
                            "Secure Boot Options:\n"
                            "- Full Security: Maximum protection\n"
                            "- Medium Security: Allows some modifications\n"
                            "- No Security: Minimal protection\n\n"
                            "To review or change these settings:\n"
                            "1. Reboot into Recovery Mode (Cmd+R during startup)\n"
                            "2. Go to Utilities > Startup Security Utility\n"
                            "3. Select your drive and adjust the settings as needed\n"
                            "4. You may be prompted to enter your Apple ID credentials"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "chip_type":
                # No action needed for chip type info
                pass

        return FixResult(module_name=self.name, actions=actions)

    def _get_chip_type(self) -> str | None:
        """
        Detect CPU architecture using uname -m.
        Returns: "Intel", "Apple Silicon", or None if unable to determine
        """
        try:
            result = subprocess.run(
                ["/usr/bin/uname", "-m"],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                return None
            arch = result.stdout.strip().lower()
            if "arm" in arch:
                return "Apple Silicon"
            elif "x86" in arch:
                return "Intel"
            return None
        except (OSError, subprocess.SubprocessError):
            return None

    def _check_intel_firmware_password(self, findings: list) -> None:
        """
        Check firmware password status on Intel Macs using firmwarepasswd -check.
        Adds findings to the list.
        """
        try:
            result = subprocess.run(
                ["/usr/libexec/firmwarepasswd", "-check"],
                capture_output=True,
                text=True,
            )
            output = result.stdout.lower() + result.stderr.lower()

            # If the output contains "yes", firmware password is set
            if "yes" in output:
                findings.append(
                    Finding(
                        title="Firmware Password: Protected",
                        description=(
                            "A firmware password is set on this Intel Mac. "
                            "This provides protection against unauthorized startup from "
                            "external drives and access to Recovery Mode, which is important "
                            "for stolen device protection and IT asset management."
                        ),
                        severity=Severity.INFO,
                        category=self.category,
                        data={"check": "firmware_password_set"},
                    )
                )
            # If output contains "no", firmware password is not set
            elif "no" in output:
                findings.append(
                    Finding(
                        title="Firmware Password: Not Set",
                        description=(
                            "No firmware password is configured on this Intel Mac. "
                            "Without a firmware password, anyone with physical access can boot from "
                            "an external drive or access Recovery Mode, potentially compromising "
                            "the device. This is a significant security gap for stolen device "
                            "protection and IT asset management."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={"check": "firmware_password_not_set"},
                    )
                )
            else:
                # Unable to determine status
                findings.append(
                    Finding(
                        title="Firmware Password: Unable to determine status",
                        description=(
                            "The firmware password status could not be determined. "
                            "This check may require administrator privileges to run properly."
                        ),
                        severity=Severity.INFO,
                        category=self.category,
                        data={"check": "firmware_password_unknown"},
                    )
                )

        except PermissionError:
            findings.append(
                Finding(
                    title="Firmware Password: Permission denied",
                    description=(
                        "The firmware password check requires administrator (sudo) privileges. "
                        "Run this check with elevated privileges to determine the status."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "firmware_password_permission_denied"},
                )
            )
        except (OSError, subprocess.SubprocessError):
            findings.append(
                Finding(
                    title="Firmware Password: Check unavailable",
                    description=(
                        "Unable to check firmware password status. "
                        "The firmwarepasswd utility may not be available on this system."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "firmware_password_unavailable"},
                )
            )

    def _check_apple_silicon_startup_security(self, findings: list) -> None:
        """
        Check Startup Security Utility status on Apple Silicon Macs.
        Adds findings to the list.
        """
        # For Apple Silicon, we report informational status
        # The Startup Security Utility is only accessible from Recovery Mode
        findings.append(
            Finding(
                title="Startup Security Utility: Apple Silicon",
                description=(
                    "This Apple Silicon Mac uses the Startup Security Utility to manage "
                    "firmware security. The startup security settings control allowed boot "
                    "methods, external media access, and secure boot options. "
                    "Review these settings in Recovery Mode to ensure they match your "
                    "organization's security policies."
                ),
                severity=Severity.INFO,
                category=self.category,
                data={"check": "startup_security_info"},
            )
        )
