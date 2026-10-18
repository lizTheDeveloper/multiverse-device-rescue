import re
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

        # Each reading is True (on), False (off) or None (couldn't tell). On
        # macOS 26 several of the old places these settings lived are gone
        # (com.apple.Bluetooth ControllerPowerState, the "com.apple.iCloud"
        # domain); a value that couldn't be read is "couldn't check", never "off".
        handoff_enabled = self._is_handoff_enabled()
        bluetooth_on = self._is_bluetooth_on()
        wifi_on = self._is_wifi_on()
        icloud_signed_in = self._is_icloud_signed_in()

        handoff_word = (
            "couldn't be checked" if handoff_enabled is None
            else ("enabled" if handoff_enabled else "disabled")
        )
        findings.append(
            Finding(
                title=(
                    "Couldn't check whether Handoff is on" if handoff_enabled is None
                    else f"Handoff is {handoff_word}"
                ),
                description=(
                    "Handoff allows you to start a task on one device and continue it on another. "
                    f"Currently: {handoff_word}."
                ),
                severity=Severity.INFO,
                category=self.category,
                data={"check": "handoff_status", "enabled": handoff_enabled},
            )
        )

        if bluetooth_on is None:
            findings.append(
                Finding(
                    title="Couldn't check whether Bluetooth is on",
                    description=(
                        "Device Rescue couldn't read your Mac's Bluetooth setting. This "
                        "is not a sign that anything is wrong. To see for yourself, open "
                        "System Settings > Bluetooth."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "bluetooth_unknown", "enabled": None},
                )
            )
        else:
            findings.append(
                Finding(
                    title=f"Bluetooth is {'on' if bluetooth_on else 'off'}",
                    description=(
                        f"Your Mac's Bluetooth is currently {'on' if bluetooth_on else 'off'}. "
                        "This setting controls whether your Mac can connect to nearby devices "
                        "for features like AirDrop or Handoff. If it is off, those features "
                        "simply won't work until you turn it back on.\n\n"
                        "What to do: Nothing is needed if you are happy with the current "
                        "state. If you want to use AirDrop or Handoff, open System Settings "
                        "> Bluetooth and turn it on."
                    ),
                    severity=Severity.INFO if bluetooth_on else Severity.WARNING,
                    category=self.category,
                    data={"check": "bluetooth_status", "enabled": bluetooth_on},
                )
            )

        if wifi_on is None:
            findings.append(
                Finding(
                    title="Couldn't check whether Wi-Fi is on",
                    description=(
                        "Device Rescue couldn't read your Mac's Wi-Fi setting. This is "
                        "not a sign that anything is wrong."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "wifi_unknown", "enabled": None},
                )
            )
        else:
            findings.append(
                Finding(
                    title=f"Wi-Fi is {'on' if wifi_on else 'off'}",
                    description=(
                        f"Your Mac's Wi-Fi is currently {'on' if wifi_on else 'off'}. This "
                        "setting controls whether your Mac can connect to wireless networks. "
                        "If it is off, you won't be able to use the internet or features "
                        "like AirDrop until you turn it back on.\n\n"
                        "What to do: Nothing is needed if you are happy with the current "
                        "state. If you want to connect to a network, open System Settings "
                        "> Wi-Fi and turn it on."
                    ),
                    severity=Severity.INFO if wifi_on else Severity.WARNING,
                    category=self.category,
                    data={"check": "wifi_status", "enabled": wifi_on},
                )
            )

        if icloud_signed_in is None:
            findings.append(
                Finding(
                    title="Couldn't check whether iCloud is signed in",
                    description=(
                        "Device Rescue couldn't read your iCloud account settings. This is "
                        "not a sign that anything is wrong. To see for yourself, open "
                        "System Settings and look for your name at the top."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "icloud_unknown", "signed_in": None},
                )
            )
        else:
            findings.append(
                Finding(
                    title=f"iCloud is {'signed in' if icloud_signed_in else 'not signed in'}",
                    description=(
                        f"Your Mac is currently {'signed in' if icloud_signed_in else 'not signed in'} "
                        "to iCloud. iCloud is Apple's service that syncs your data, like "
                        "photos and notes, across your devices. If you are not signed in, "
                        "features like Handoff won't work between your Apple devices.\n\n"
                        "What to do: Nothing is needed if you are happy with the current "
                        "state. If you want to sync your data, open System Settings > Apple "
                        "Account and sign in."
                    ),
                    severity=Severity.INFO if icloud_signed_in else Severity.WARNING,
                    category=self.category,
                    data={"check": "icloud_status", "signed_in": icloud_signed_in},
                )
            )

        # Flag WARNING if Bluetooth is off
        if bluetooth_on is False:
            findings.append(
                Finding(
                    title="Bluetooth is off, so some Apple features won't work",
                    description=(
                        "Your Mac's Bluetooth is turned off. This means features like "
                        "AirDrop, Handoff, and Universal Clipboard will not work until "
                        "you turn Bluetooth back on.\n\n"
                        "What to do: If you want to use these features, open System Settings "
                        "> Bluetooth and turn it on."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "bluetooth_warning"},
                )
            )

        # Flag WARNING if Handoff is disabled but iCloud is signed in
        if handoff_enabled is False and icloud_signed_in is True:
            findings.append(
                Finding(
                    title="Handoff is turned off, even though you are signed in to iCloud",
                    description=(
                        "Handoff is currently disabled on your Mac. This feature lets "
                        "you start a task on one device and finish it on another. Since "
                        "you are signed in to iCloud, you can turn Handoff back on if "
                        "you want to use it.\n\n"
                        "What to do: If you want to use Handoff, open System Settings "
                        "> General > AirDrop & Handoff and turn on Handoff."
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

    @staticmethod
    def _safe(call):
        """Run ``call()`` (a subprocess.run), returning None if it couldn't run."""
        try:
            return call()
        except (OSError, subprocess.SubprocessError):
            return None

    def _is_handoff_enabled(self) -> bool | None:
        """Is Handoff on? None if the setting couldn't be read."""
        result = self._safe(lambda: subprocess.run(
            ["defaults", "read", "com.apple.coreservices.useractivityd", "ActivityReceivingAllowed"],
            capture_output=True, text=True, timeout=20,
        ))
        if result is None or result.returncode != 0 or not isinstance(result.stdout, str):
            return None
        value = result.stdout.strip()
        if value in ("1", "0"):
            return value == "1"
        return None

    def _is_bluetooth_on(self) -> bool | None:
        """Is Bluetooth on? None if it couldn't be read.

        Older macOS kept ControllerPowerState in com.apple.Bluetooth; macOS 26
        does not, and system_profiler's "State: On" is the source of truth.
        """
        result = self._safe(lambda: subprocess.run(
            ["defaults", "read", "/Library/Preferences/com.apple.Bluetooth", "ControllerPowerState"],
            capture_output=True, text=True, timeout=20,
        ))
        if result is not None and result.returncode == 0 and isinstance(result.stdout, str):
            value = result.stdout.strip()
            if value in ("1", "0"):
                return value == "1"
        result = self._safe(lambda: subprocess.run(
            ["system_profiler", "SPBluetoothDataType"],
            capture_output=True, text=True, timeout=20,
        ))
        if result is None or result.returncode != 0 or not isinstance(result.stdout, str):
            return None
        match = re.search(r"^\s*(?:State|Bluetooth Power):\s*(On|Off)\b", result.stdout,
                          re.MULTILINE | re.IGNORECASE)
        if not match:
            return None
        return match.group(1).lower() == "on"

    def _is_wifi_on(self) -> bool | None:
        """Is Wi-Fi on? None if it couldn't be read."""
        result = self._safe(lambda: subprocess.run(
            ["networksetup", "-getairportpower", "en0"],
            capture_output=True, text=True, timeout=20,
        ))
        if result is None or result.returncode != 0 or not isinstance(result.stdout, str):
            return None
        # "Wi-Fi Power (en0): On" (older: "AirPort Power (en0): On")
        match = re.search(r"Power \([^)]*\):\s*(On|Off)\b", result.stdout)
        if not match:
            return None
        return match.group(1) == "On"

    def _is_icloud_signed_in(self) -> bool | None:
        """Is an iCloud account signed in? None if it couldn't be read.

        The accounts live in the MobileMeAccounts domain; the old read of a
        "com.apple.iCloud.plist" domain never existed and always said "not
        signed in".
        """
        result = self._safe(lambda: subprocess.run(
            ["defaults", "read", "MobileMeAccounts", "Accounts"],
            capture_output=True, text=True, timeout=20,
        ))
        if result is None or result.returncode != 0 or not isinstance(result.stdout, str):
            return None
        out = result.stdout
        if re.search(r"\b(AccountID|AccountDSID|MobileMeAccountDisplay)\b", out):
            return True
        if re.fullmatch(r"\s*\(\s*\)\s*", out):
            return False  # the list exists and is empty: signed out
        return None
