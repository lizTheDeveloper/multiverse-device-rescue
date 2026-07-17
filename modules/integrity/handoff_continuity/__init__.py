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
    name = "handoff_continuity"
    category = "integrity"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 45
    depends_on = []
    estimated_duration = "5s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Check if Handoff is enabled
        handoff_enabled = self._is_handoff_enabled()

        # Check if Bluetooth is on (required for Handoff)
        bluetooth_on = self._is_bluetooth_on()

        # Check if Wi-Fi is on (required for AirDrop/Continuity)
        wifi_on = self._is_wifi_on()

        # Check if iCloud is signed in (required for Handoff between devices)
        icloud_signed_in = self._is_icloud_signed_in()

        # Report Handoff configuration
        findings.append(
            Finding(
                title=f"Handoff is {'enabled' if handoff_enabled else 'disabled'}",
                description=(
                    "Handoff allows you to start a task on one device and continue it on another. "
                    f"Currently: {'enabled' if handoff_enabled else 'disabled'}."
                ),
                severity=Severity.INFO,
                category=self.category,
                data={"check": "handoff_status", "enabled": handoff_enabled},
            )
        )

        # Report Bluetooth status
        findings.append(
            Finding(
                title=f"Bluetooth is {'on' if bluetooth_on else 'off'}",
                description=(
                    "Bluetooth is required for Handoff, AirDrop, Continuity Camera, and Universal Clipboard. "
                    f"Currently: {'on' if bluetooth_on else 'off'}."
                ),
                severity=Severity.INFO if bluetooth_on else Severity.WARNING,
                category=self.category,
                data={"check": "bluetooth_status", "enabled": bluetooth_on},
            )
        )

        # Report Wi-Fi status
        findings.append(
            Finding(
                title=f"Wi-Fi is {'on' if wifi_on else 'off'}",
                description=(
                    "Wi-Fi is required for AirDrop, Continuity, and Handoff to work properly. "
                    f"Currently: {'on' if wifi_on else 'off'}."
                ),
                severity=Severity.INFO if wifi_on else Severity.WARNING,
                category=self.category,
                data={"check": "wifi_status", "enabled": wifi_on},
            )
        )

        # Report iCloud sign-in status
        findings.append(
            Finding(
                title=f"iCloud is {'signed in' if icloud_signed_in else 'not signed in'}",
                description=(
                    "iCloud sign-in is required for Handoff to work between your Apple devices. "
                    f"Currently: {'signed in' if icloud_signed_in else 'not signed in'}."
                ),
                severity=Severity.INFO if icloud_signed_in else Severity.WARNING,
                category=self.category,
                data={"check": "icloud_status", "signed_in": icloud_signed_in},
            )
        )

        # Flag WARNING if Bluetooth is off
        if not bluetooth_on:
            findings.append(
                Finding(
                    title="Bluetooth is off - Handoff and Continuity features will not work",
                    description=(
                        "Bluetooth must be enabled for Handoff, AirDrop, Continuity Camera, "
                        "and Universal Clipboard to work. Without Bluetooth, you cannot use these Apple ecosystem features."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "bluetooth_warning"},
                )
            )

        # Flag WARNING if Handoff is disabled but iCloud is signed in
        if not handoff_enabled and icloud_signed_in:
            findings.append(
                Finding(
                    title="Handoff is disabled despite iCloud being signed in",
                    description=(
                        "Handoff is currently disabled, but you have iCloud signed in. "
                        "If you have other Apple devices, you may want to enable Handoff to use cross-device features."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "handoff_warning"},
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        for finding in findings.findings:
            check = finding.data.get("check")

            if check == "handoff_status":
                if finding.data.get("enabled"):
                    actions.append(
                        Action(
                            title="Handoff is enabled",
                            description=(
                                "Handoff is currently enabled. You can start a task on this Mac "
                                "and continue it on your iPhone, iPad, or other Mac. "
                                "To disable Handoff, open System Settings > General > AirDrop & Handoff "
                                "and toggle off 'Allow Handoff between this Mac and your iCloud devices'."
                            ),
                            risk_level=RiskLevel.SAFE,
                            success=True,
                        )
                    )
                else:
                    actions.append(
                        Action(
                            title="Enable Handoff for cross-device continuity",
                            description=(
                                "To enable Handoff, open System Settings > General > AirDrop & Handoff "
                                "and toggle on 'Allow Handoff between this Mac and your iCloud devices'. "
                                "Make sure iCloud is signed in and Bluetooth and Wi-Fi are enabled."
                            ),
                            risk_level=RiskLevel.SAFE,
                            success=True,
                        )
                    )

            elif check == "bluetooth_status":
                if finding.data.get("enabled"):
                    actions.append(
                        Action(
                            title="Bluetooth is enabled",
                            description=(
                                "Bluetooth is on and required services (Handoff, AirDrop, Continuity Camera) can work. "
                                "If you're experiencing issues, try turning Bluetooth off and on again: "
                                "click the Bluetooth icon in the menu bar and toggle it off, then back on."
                            ),
                            risk_level=RiskLevel.SAFE,
                            success=True,
                        )
                    )
                else:
                    actions.append(
                        Action(
                            title="Turn on Bluetooth",
                            description=(
                                "Bluetooth is currently off. To enable it, click the Bluetooth icon in the menu bar "
                                "and select 'Turn Bluetooth On'. If you don't see the Bluetooth icon, "
                                "open System Settings > Bluetooth and toggle it on. "
                                "Bluetooth is required for Handoff, AirDrop, Continuity Camera, and more."
                            ),
                            risk_level=RiskLevel.SAFE,
                            success=True,
                        )
                    )

            elif check == "wifi_status":
                if finding.data.get("enabled"):
                    actions.append(
                        Action(
                            title="Wi-Fi is enabled",
                            description=(
                                "Wi-Fi is on. This is required for AirDrop, Continuity, and Handoff to work. "
                                "If you're experiencing connectivity issues, try disconnecting and reconnecting to your Wi-Fi network."
                            ),
                            risk_level=RiskLevel.SAFE,
                            success=True,
                        )
                    )
                else:
                    actions.append(
                        Action(
                            title="Turn on Wi-Fi",
                            description=(
                                "Wi-Fi is currently off. To enable it, click the Wi-Fi icon in the menu bar "
                                "and select your network. If you don't see the Wi-Fi icon, "
                                "open System Settings > Wi-Fi and toggle it on. "
                                "Wi-Fi is required for AirDrop, Continuity, and Handoff."
                            ),
                            risk_level=RiskLevel.SAFE,
                            success=True,
                        )
                    )

            elif check == "icloud_status":
                if finding.data.get("signed_in"):
                    actions.append(
                        Action(
                            title="iCloud is signed in",
                            description=(
                                "You're signed into iCloud, which is required for Handoff, Universal Clipboard, "
                                "and other cross-device features. Verify you're using the correct Apple ID."
                            ),
                            risk_level=RiskLevel.SAFE,
                            success=True,
                        )
                    )
                else:
                    actions.append(
                        Action(
                            title="Sign in to iCloud",
                            description=(
                                "To use Handoff and other Apple ecosystem features, you need to be signed in to iCloud. "
                                "Open System Settings > [Your Name] > Sign in with your Apple ID. "
                                "If you don't have an Apple ID, you can create one at appleid.apple.com."
                            ),
                            risk_level=RiskLevel.SAFE,
                            success=True,
                        )
                    )

            elif check == "bluetooth_warning":
                actions.append(
                    Action(
                        title="Enable Bluetooth to use Handoff and Continuity",
                        description=(
                            "Bluetooth must be enabled for Handoff, AirDrop, Continuity Camera, "
                            "and Universal Clipboard to work. Click the Bluetooth icon in the menu bar "
                            "and select 'Turn Bluetooth On', or open System Settings > Bluetooth and toggle it on."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "handoff_warning":
                actions.append(
                    Action(
                        title="Consider enabling Handoff",
                        description=(
                            "If you have other Apple devices (iPhone, iPad, Apple Watch), "
                            "enabling Handoff allows you to start a task on one device and continue it on another. "
                            "To enable, open System Settings > General > AirDrop & Handoff "
                            "and toggle on 'Allow Handoff between this Mac and your iCloud devices'."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _is_handoff_enabled(self) -> bool:
        """Check if Handoff is enabled."""
        try:
            result = subprocess.run(
                ["defaults", "read", "com.apple.coreservices.useractivityd", "ActivityReceivingAllowed"],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                return result.stdout.strip() == "1"
        except OSError:
            pass
        return False

    def _is_bluetooth_on(self) -> bool:
        """Check if Bluetooth is on."""
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

    def _is_wifi_on(self) -> bool:
        """Check if Wi-Fi is on."""
        try:
            result = subprocess.run(
                ["networksetup", "-getairportpower", "en0"],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                # Output format: "AirPort Power (en0): On" or "AirPort Power (en0): Off"
                return "On" in result.stdout
        except OSError:
            pass
        return False

    def _is_icloud_signed_in(self) -> bool:
        """Check if iCloud is signed in."""
        try:
            result = subprocess.run(
                ["defaults", "read", "com.apple.iCloud.plist", "MobileMeAccounts"],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0 and result.stdout.strip():
                # If we get output, iCloud is signed in
                return True
        except OSError:
            pass
        return False
