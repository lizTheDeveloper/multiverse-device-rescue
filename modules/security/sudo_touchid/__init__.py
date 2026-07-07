import subprocess
from pathlib import Path

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
    name = "sudo_touchid"
    category = "security"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 60
    depends_on = []
    estimated_duration = "2s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Check if Touch ID hardware is available
        has_touchid_hardware = self._has_touchid_hardware()

        # Check enrolled fingerprints
        fingerprint_count = self._get_enrolled_fingerprints()

        # Check if Touch ID for sudo is enabled
        sudo_touchid_enabled = self._is_sudo_touchid_enabled()

        # Check if Touch ID for Apple Pay is enabled
        applepay_touchid_enabled = self._is_applepay_touchid_enabled()

        # Report Touch ID status
        if has_touchid_hardware:
            status = "Touch ID hardware detected"
            if fingerprint_count > 0:
                status += f" with {fingerprint_count} fingerprint(s) enrolled"
            else:
                status += " but no fingerprints enrolled"

            findings.append(
                Finding(
                    title="Touch ID status",
                    description=status,
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "check": "touchid_status",
                        "fingerprints": fingerprint_count,
                        "has_hardware": True,
                    },
                )
            )

            # Warn if no fingerprints are enrolled
            if fingerprint_count == 0:
                findings.append(
                    Finding(
                        title="No fingerprints enrolled",
                        description=(
                            "This Mac has Touch ID hardware but no fingerprints are enrolled. "
                            "Enroll fingerprints in System Settings > Face ID & Passcode "
                            "to use Touch ID for sudo and other authentication."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={"check": "no_fingerprints"},
                    )
                )

            # Suggest Touch ID for sudo if not enabled
            if not sudo_touchid_enabled:
                findings.append(
                    Finding(
                        title="Touch ID for sudo not enabled",
                        description=(
                            "Touch ID is not configured for sudo authentication. Enabling this "
                            "provides both convenience and enhanced security by requiring biometric "
                            "authentication for privileged operations."
                        ),
                        severity=Severity.INFO,
                        category=self.category,
                        data={"check": "sudo_not_enabled"},
                    )
                )

            # Report Apple Pay Touch ID status
            if applepay_touchid_enabled:
                findings.append(
                    Finding(
                        title="Touch ID for Apple Pay enabled",
                        description="Touch ID is configured for Apple Pay authentication.",
                        severity=Severity.INFO,
                        category=self.category,
                        data={"check": "applepay_enabled"},
                    )
                )
        else:
            findings.append(
                Finding(
                    title="No Touch ID hardware detected",
                    description=(
                        "This Mac does not have Touch ID hardware. "
                        "Touch ID is available on newer Mac models with M-series chips."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "no_hardware", "has_hardware": False},
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            check = finding.data.get("check")
            if check == "touchid_status":
                label = "Touch ID status"
                description = (
                    f"Found {finding.data.get('fingerprints', 0)} fingerprint(s) enrolled. "
                    "Touch ID provides biometric authentication for your Mac."
                )
            elif check == "no_fingerprints":
                label = "Enroll fingerprints for Touch ID"
                description = (
                    "To enroll fingerprints: System Settings > Face ID & Passcode > "
                    "Add Fingerprint (follow the on-screen prompts to scan your fingerprints)"
                )
            elif check == "sudo_not_enabled":
                label = "Enable Touch ID for sudo"
                description = (
                    "To enable: Edit /etc/pam.d/sudo and add the line "
                    "'auth       sufficient     pam_tid.so' after the 'auth       sufficient     pam_smartcard.so' line. "
                    "This requires root privileges and sudo access."
                )
            elif check == "applepay_enabled":
                label = "Touch ID for Apple Pay is enabled"
                description = (
                    "Your Touch ID is configured for Apple Pay. "
                    "This provides secure payment authentication."
                )
            elif check == "no_hardware":
                label = "No Touch ID hardware available"
                description = (
                    "This Mac does not have Touch ID hardware. "
                    "Consider upgrading to a newer Mac model with Touch ID support for enhanced security."
                )
            else:
                continue

            actions.append(
                Action(
                    title=label,
                    description=description,
                    risk_level=RiskLevel.SAFE,
                    success=True,
                    error=None,
                )
            )
        return FixResult(module_name=self.name, actions=actions)

    def _has_touchid_hardware(self) -> bool:
        """Check if the Mac has Touch ID hardware."""
        try:
            result = subprocess.run(
                ["system_profiler", "SPiBridgeDataType"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return "Touch ID" in result.stdout
        except (OSError, subprocess.TimeoutExpired):
            return False

    def _get_enrolled_fingerprints(self) -> int:
        """Get the number of enrolled fingerprints using bioutil -rs."""
        try:
            result = subprocess.run(
                ["bioutil", "-rs"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            # Count non-empty, non-header lines that represent fingerprints
            if result.returncode == 0:
                lines = result.stdout.strip().split("\n")
                # Filter out empty lines and header-like lines
                fingerprint_lines = [
                    l for l in lines if l.strip() and not l.startswith("Fingerprints")
                ]
                return len(fingerprint_lines)
            return 0
        except (OSError, subprocess.TimeoutExpired):
            return 0

    def _is_sudo_touchid_enabled(self) -> bool:
        """Check if Touch ID for sudo is enabled by checking /etc/pam.d/sudo."""
        try:
            sudo_pam_path = Path("/etc/pam.d/sudo")
            if sudo_pam_path.exists():
                content = sudo_pam_path.read_text()
                return "pam_tid.so" in content
            return False
        except (OSError, PermissionError):
            return False

    def _is_applepay_touchid_enabled(self) -> bool:
        """Check if Touch ID for Apple Pay is enabled."""
        try:
            result = subprocess.run(
                ["defaults", "read", "com.apple.ApplePay", "ApplePayEnabled"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return result.stdout.strip() == "1"
        except (OSError, subprocess.TimeoutExpired):
            return False
