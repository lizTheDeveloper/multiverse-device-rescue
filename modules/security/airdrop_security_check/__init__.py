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
    name = "airdrop_security_check"
    category = "security"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "3s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Check AirDrop discoverability
        airdrop_mode = self._get_airdrop_mode()

        # Check Bluetooth status
        bluetooth_enabled = self._is_bluetooth_enabled()

        # Check Wi-Fi status
        wifi_enabled = self._is_wifi_enabled()

        # Check Handoff status
        handoff_enabled = self._is_handoff_enabled()

        # Check Bluetooth sharing
        bluetooth_sharing_enabled = self._is_bluetooth_sharing_enabled()

        # Flag WARNING if AirDrop is set to "Everyone"
        if airdrop_mode == "Everyone":
            findings.append(
                Finding(
                    title="AirDrop set to Everyone",
                    description=(
                        "AirDrop is set to 'Everyone', which allows anyone nearby to send files to your device. "
                        "This is a privacy risk and has been used for harassment. "
                        "Consider setting AirDrop to 'Contacts Only' or 'No One'."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "airdrop_mode_everyone"},
                )
            )

        # Flag WARNING if Bluetooth sharing is enabled
        if bluetooth_sharing_enabled:
            findings.append(
                Finding(
                    title="Bluetooth sharing is enabled",
                    description=(
                        "Bluetooth sharing is enabled, which allows files to be received via Bluetooth. "
                        "Consider disabling it if not actively used, as it may allow unauthorized file transfers."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "bluetooth_sharing_enabled"},
                )
            )

        # Flag INFO reporting AirDrop mode, Bluetooth status, and sharing configuration
        status_parts = []
        if airdrop_mode:
            status_parts.append(f"AirDrop mode: {airdrop_mode}")
        if bluetooth_enabled is not None:
            status_parts.append(f"Bluetooth: {'enabled' if bluetooth_enabled else 'disabled'}")
        if wifi_enabled is not None:
            status_parts.append(f"Wi-Fi: {'enabled' if wifi_enabled else 'disabled'}")
        if handoff_enabled is not None:
            status_parts.append(f"Handoff: {'enabled' if handoff_enabled else 'disabled'}")
        if bluetooth_sharing_enabled is not None:
            status_parts.append(f"Bluetooth sharing: {'enabled' if bluetooth_sharing_enabled else 'disabled'}")

        if status_parts:
            findings.append(
                Finding(
                    title="AirDrop and sharing configuration",
                    description="\n".join(status_parts),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "check": "sharing_config",
                        "airdrop_mode": airdrop_mode,
                        "bluetooth_enabled": bluetooth_enabled,
                        "wifi_enabled": wifi_enabled,
                        "handoff_enabled": handoff_enabled,
                        "bluetooth_sharing_enabled": bluetooth_sharing_enabled,
                    },
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            check = finding.data.get("check")

            if check == "airdrop_mode_everyone":
                actions.append(
                    Action(
                        title="Change AirDrop to Contacts Only",
                        description=(
                            "AirDrop is currently set to 'Everyone'. To change this:\n"
                            "1. Open System Settings\n"
                            "2. Go to General > AirDrop\n"
                            "3. Change the setting from 'Everyone' to 'Contacts Only' or 'No One'\n"
                            "This restricts AirDrop to only people in your contacts, or disables it entirely."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )
            elif check == "bluetooth_sharing_enabled":
                actions.append(
                    Action(
                        title="Disable Bluetooth sharing",
                        description=(
                            "Bluetooth sharing is currently enabled. To disable it:\n"
                            "1. Open System Settings\n"
                            "2. Go to General > AirDrop\n"
                            "3. Uncheck 'Bluetooth Sharing' if the option is visible, or\n"
                            "4. Go to Bluetooth settings and disable file sharing for paired devices"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )
            elif check == "sharing_config":
                actions.append(
                    Action(
                        title="Review sharing configuration",
                        description=(
                            "Your current sharing configuration has been reported. "
                            "Review the settings and adjust AirDrop and Bluetooth sharing preferences "
                            "according to your security and privacy needs."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _get_airdrop_mode(self) -> str | None:
        """Get AirDrop discoverability mode: Off, Contacts Only, or Everyone.

        Returns the mode string, or None if unable to determine.
        """
        try:
            result = subprocess.run(
                ["defaults", "read", "com.apple.sharingd", "DiscoverableMode"],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                mode = result.stdout.strip()
                # Map numeric values to readable names if needed
                mode_map = {
                    "0": "Off",
                    "1": "Contacts Only",
                    "2": "Everyone",
                }
                return mode_map.get(mode, mode)
            return None
        except Exception:
            return None

    def _is_bluetooth_enabled(self) -> bool | None:
        """Check if Bluetooth is enabled.

        Returns True if enabled, False if disabled, None if unable to determine.
        """
        try:
            result = subprocess.run(
                ["defaults", "read", "/Library/Preferences/com.apple.Bluetooth", "ControllerPowerState"],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                return result.stdout.strip() == "1"
            return None
        except Exception:
            return None

    def _is_wifi_enabled(self) -> bool | None:
        """Check if Wi-Fi is enabled.

        Returns True if enabled, False if disabled, None if unable to determine.
        """
        try:
            result = subprocess.run(
                ["networksetup", "-getairportpower", "en0"],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                output = result.stdout.strip().lower()
                return "on" in output
            return None
        except Exception:
            return None

    def _is_handoff_enabled(self) -> bool | None:
        """Check if Handoff is enabled.

        Returns True if enabled, False if disabled, None if unable to determine.
        """
        try:
            db_path = Path.home() / "Library/Preferences/ByHost/com.apple.coreservices.useractivityd.plist"
            result = subprocess.run(
                ["defaults", "read", str(db_path), "ActivityAdvertisingAllowed"],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                return result.stdout.strip() == "1"
            return None
        except Exception:
            return None

    def _is_bluetooth_sharing_enabled(self) -> bool | None:
        """Check if Bluetooth sharing is enabled.

        Returns True if enabled, False if disabled, None if unable to determine.
        """
        try:
            result = subprocess.run(
                ["defaults", "read", "com.apple.Bluetooth", "PrefKeyServicesEnabled"],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                return result.stdout.strip() == "1"
            return None
        except Exception:
            return None
