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
    name = "airdrop_config"
    category = "security"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "5s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Get AirDrop discoverability mode
        discoverable_mode = self._get_airdrop_mode()

        # Check Bluetooth status
        bluetooth_enabled = self._is_bluetooth_enabled()

        # Check Wi-Fi status
        wifi_enabled = self._is_wifi_enabled()

        # Flag WARNING if AirDrop is set to "Everyone" (security risk, especially for minors)
        if discoverable_mode == "Everyone":
            findings.append(
                Finding(
                    title="AirDrop is set to 'Everyone'",
                    description=(
                        "AirDrop is discoverable by everyone on nearby networks. "
                        "This is a security risk, especially for children's devices, "
                        "as anyone nearby can send unsolicited files. "
                        "Recommended setting is 'Contacts Only'."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "airdrop_mode"},
                )
            )

        # Flag INFO if set to "Contacts Only" (recommended setting)
        elif discoverable_mode == "Contacts Only":
            findings.append(
                Finding(
                    title="AirDrop is set to 'Contacts Only'",
                    description=(
                        "AirDrop is configured to receive files only from contacts. "
                        "This is the recommended security setting."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "airdrop_mode"},
                )
            )

        # Flag INFO if disabled (safe but limits functionality)
        elif discoverable_mode == "Off":
            findings.append(
                Finding(
                    title="AirDrop is disabled",
                    description=(
                        "AirDrop is disabled, which is safe but limits file sharing functionality. "
                        "Enable 'Contacts Only' mode to balance security and usability."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "airdrop_mode"},
                )
            )

        # Check if Bluetooth and Wi-Fi are enabled
        if not bluetooth_enabled:
            findings.append(
                Finding(
                    title="Bluetooth is disabled",
                    description=(
                        "Bluetooth is required for AirDrop functionality. "
                        "Enable Bluetooth in System Settings > Bluetooth to use AirDrop."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "bluetooth_status"},
                )
            )

        if not wifi_enabled:
            findings.append(
                Finding(
                    title="Wi-Fi is disabled",
                    description=(
                        "Wi-Fi is required for AirDrop functionality. "
                        "Enable Wi-Fi in System Settings > Wi-Fi to use AirDrop."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "wifi_status"},
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        for finding in findings.findings:
            check = finding.data.get("check")

            if check == "airdrop_mode":
                actions.append(
                    Action(
                        title="Change AirDrop to 'Contacts Only'",
                        description=(
                            "To change AirDrop setting, go to System Settings > General > AirDrop, "
                            "then select 'Contacts Only'. This balances security and functionality. "
                            "Alternatively, use: defaults write com.apple.sharingd DiscoverableMode Contacts"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif check == "bluetooth_status":
                actions.append(
                    Action(
                        title="Enable Bluetooth",
                        description=(
                            "To enable Bluetooth, go to System Settings > Bluetooth and toggle it on. "
                            "Bluetooth is required for AirDrop to function."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif check == "wifi_status":
                actions.append(
                    Action(
                        title="Enable Wi-Fi",
                        description=(
                            "To enable Wi-Fi, go to System Settings > Wi-Fi and toggle it on. "
                            "Wi-Fi is required for AirDrop to function."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _get_airdrop_mode(self) -> str:
        """Get AirDrop discoverability mode: 'Everyone', 'Contacts Only', or 'Off'."""
        try:
            result = subprocess.run(
                ["defaults", "read", "com.apple.sharingd", "DiscoverableMode"],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                mode = result.stdout.strip()
                return mode
        except OSError:
            pass
        return "Off"

    def _is_bluetooth_enabled(self) -> bool:
        """Check if Bluetooth is enabled."""
        try:
            result = subprocess.run(
                ["defaults", "read", "/Library/Preferences/com.apple.Bluetooth", "ControllerPowerState"],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                return int(result.stdout.strip()) == 1
        except (OSError, ValueError):
            pass
        return False

    def _is_wifi_enabled(self) -> bool:
        """Check if Wi-Fi is enabled."""
        try:
            result = subprocess.run(
                ["networksetup", "-getairportpower", "en0"],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                # Output format: "Wi-Fi Power (en0): On" or "Wi-Fi Power (en0): Off"
                return "On" in result.stdout
        except OSError:
            pass
        return False
