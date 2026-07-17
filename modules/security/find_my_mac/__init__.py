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
    name = "find_my_mac"
    category = "security"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 85
    depends_on = []
    estimated_duration = "2s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Check if Find My Mac is enabled
        fmm_enabled = self._check_find_my_mac_enabled()
        if not fmm_enabled:
            findings.append(
                Finding(
                    title="Find My Mac is disabled",
                    description=(
                        "Find My Mac is disabled. If this device is lost or stolen, "
                        "you will not be able to locate, lock, or remotely wipe it. "
                        "This is critical for device recovery."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
                    data={"find_my_mac_enabled": fmm_enabled},
                )
            )

        # Check if Send Last Location is enabled
        send_last_location = self._check_send_last_location()
        if not send_last_location:
            findings.append(
                Finding(
                    title="Send Last Location is disabled",
                    description=(
                        "Send Last Location is disabled. The device will not send "
                        "its final location when the battery is critically low, "
                        "reducing recovery chances for a lost device."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"send_last_location": send_last_location},
                )
            )

        # Check if Activation Lock is enabled
        activation_lock = self._check_activation_lock()
        if activation_lock is None:
            # Could not determine; provide INFO
            findings.append(
                Finding(
                    title="Activation Lock status could not be determined",
                    description=(
                        "Could not verify Activation Lock status. This feature helps "
                        "prevent unauthorized access if Find My is enabled."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={"activation_lock": activation_lock},
                )
            )
        elif fmm_enabled and send_last_location:
            # All good
            findings.append(
                Finding(
                    title="Find My Mac is properly configured",
                    description=(
                        "Find My Mac and Send Last Location are both enabled. "
                        "Your device can be located and remotely managed if lost or stolen."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "find_my_mac_enabled": fmm_enabled,
                        "send_last_location": send_last_location,
                        "activation_lock": activation_lock,
                    },
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            if "Find My Mac is disabled" in finding.title:
                actions.append(
                    Action(
                        title="Enable Find My Mac",
                        description=(
                            "Find My Mac must be enabled in System Settings. "
                            "1. Open System Settings > [Your Name] > iCloud\n"
                            "2. Make sure you're signed in with your Apple ID\n"
                            "3. Toggle 'Find My Mac' ON\n"
                            "This requires an active iCloud account."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif "Send Last Location is disabled" in finding.title:
                actions.append(
                    Action(
                        title="Enable Send Last Location",
                        description=(
                            "Send Last Location must be enabled in Find My settings. "
                            "1. Open System Settings > [Your Name] > iCloud\n"
                            "2. Click 'Find My'\n"
                            "3. Enable 'Send Last Location'\n"
                            "This ensures the device's final location is sent when battery is low."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _check_find_my_mac_enabled(self) -> bool:
        """Check if Find My Mac is enabled via defaults read."""
        try:
            result = subprocess.run(
                ["defaults", "read", "com.apple.FindMyMac", "FMMEnabled"],
                capture_output=True,
                text=True,
            )
            # Output will be "1" if enabled, "0" if disabled, or error if not found
            output = result.stdout.strip()
            return output == "1"
        except Exception:
            return False

    def _check_send_last_location(self) -> bool:
        """Check if Send Last Location is enabled via defaults read."""
        try:
            result = subprocess.run(
                ["defaults", "read", "com.apple.FindMyMac", "SendLastLocation"],
                capture_output=True,
                text=True,
            )
            output = result.stdout.strip()
            return output == "1"
        except Exception:
            return False

    def _check_activation_lock(self) -> bool | None:
        """Check if Activation Lock is enabled via nvram."""
        try:
            result = subprocess.run(
                ["nvram", "-p"],
                capture_output=True,
                text=True,
            )
            # Look for fmm-mobileme-token in output
            return "fmm-mobileme-token" in result.stdout
        except Exception:
            return None
