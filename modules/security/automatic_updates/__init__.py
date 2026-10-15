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
    name = "automatic_updates"
    category = "security"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 75
    depends_on = []
    estimated_duration = "3s"

    emits_codes = [
        "security.automatic_updates.automatic_check",
        "security.automatic_updates.automatic_download",
        "security.automatic_updates.auto_install_macos",
        "security.automatic_updates.critical_update",
        "security.automatic_updates.config_data",
        "security.automatic_updates.app_store_auto",
    ]

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Check automatic check for updates
        auto_check = self._read_defaults(
            "/Library/Preferences/com.apple.SoftwareUpdate",
            "AutomaticCheckEnabled",
        )
        if auto_check == "0":
            findings.append(
                Finding(
                    title="Your Mac is not checking for updates automatically",
                    description=(
                        "Your Mac is set to not check for new software updates on its "
                        "own. However, if you don't check manually, you might miss important "
                        "security fixes.\n\n"
                        "What to do: Open System Settings > General > Software Update "
                        "> Automatic Updates, and turn on 'Check for updates'."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.automatic_updates.automatic_check",
                    data={"check": "automatic_check"},
                )
            )

        # Check automatic download
        auto_download = self._read_defaults(
            "/Library/Preferences/com.apple.SoftwareUpdate",
            "AutomaticDownload",
        )
        if auto_download == "0":
            findings.append(
                Finding(
                    title="Your Mac is not downloading updates automatically",
                    description=(
                        "Your Mac is set to not download updates once they are found. "
                        "It just means you have to click 'Download' yourself when an update "
                        "is ready.\n\n"
                        "What to do: Open System Settings > General > Software Update "
                        "> Automatic Updates, and turn on 'Download new updates when available'."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.automatic_updates.automatic_download",
                    data={"check": "automatic_download"},
                )
            )

        # Check auto install macOS updates
        auto_install_macos = self._read_defaults(
            "/Library/Preferences/com.apple.SoftwareUpdate",
            "AutomaticallyInstallMacOSUpdates",
        )
        if auto_install_macos == "0":
            findings.append(
                Finding(
                    title="Your Mac is not installing macOS updates automatically",
                    description=(
                        "Your Mac is set to ask you before installing new versions of "
                        "macOS, so you'll need to install them yourself when they "
                        "appear.\n\n"
                        "What to do: Open System Settings > General > Software Update "
                        "> Automatic Updates, and turn on 'Install macOS updates' if you "
                        "want them to happen in the background."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.automatic_updates.auto_install_macos",
                    data={"check": "auto_install_macos"},
                )
            )

        # Check auto install critical updates
        critical_update = self._read_defaults(
            "/Library/Preferences/com.apple.SoftwareUpdate",
            "CriticalUpdateInstall",
        )
        if critical_update == "0":
            findings.append(
                Finding(
                    title=(
                        "Your Mac is not installing critical security updates automatically"
                    ),
                    description=(
                        "Your Mac is set to ask you before installing critical security "
                        "patches. However, these patches fix serious vulnerabilities, "
                        "so it is best to let them install.\n\n"
                        "What to do: Open System Settings > General > Software Update "
                        "> Automatic Updates, and turn on 'Install critical security updates'."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
                    code="security.automatic_updates.critical_update",
                    data={"check": "critical_update"},
                )
            )

        # Check auto install config data (XProtect, etc)
        config_data = self._read_defaults(
            "/Library/Preferences/com.apple.SoftwareUpdate",
            "ConfigDataInstall",
        )
        if config_data == "0":
            findings.append(
                Finding(
                    title=(
                        "Your Mac is not updating its security detection data automatically"
                    ),
                    description=(
                        "Your Mac is set to not automatically update its internal security "
                        "databases (like XProtect, which helps block malware). It just "
                        "means your Mac might not know about the newest types of malware.\n\n"
                        "What to do: Open System Settings > General > Software Update "
                        "> Automatic Updates, and turn on 'Install system data files and "
                        "security updates'."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.automatic_updates.config_data",
                    data={"check": "config_data"},
                )
            )

        # Check App Store auto-updates
        app_store_auto = self._read_defaults(
            "/Library/Preferences/com.apple.commerce",
            "AutoUpdate",
        )
        if app_store_auto == "0":
            findings.append(
                Finding(
                    title="App Store apps are not updating automatically",
                    description=(
                        "Your Mac is set to not automatically update apps you downloaded "
                        "from the App Store. It just means you have to check the App Store "
                        "manually to update your apps.\n\n"
                        "What to do: Open the App Store, choose App Store > Settings from "
                        "the menu bar, and turn on Automatic Updates."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.automatic_updates.app_store_auto",
                    data={"check": "app_store_auto"},
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            check = finding.data.get("check")
            if check == "automatic_check":
                label = "Enable automatic software update check"
                description = (
                    "To enable: System Settings > General > Software Update > "
                    "Automatic Updates > Check for updates"
                )
            elif check == "automatic_download":
                label = "Enable automatic software update download"
                description = (
                    "To enable: System Settings > General > Software Update > "
                    "Automatic Updates > Download new updates when available"
                )
            elif check == "auto_install_macos":
                label = "Enable automatic macOS update installation"
                description = (
                    "To enable: System Settings > General > Software Update > "
                    "Automatic Updates > Install system data and security updates"
                )
            elif check == "critical_update":
                label = "Enable automatic critical update installation"
                description = (
                    "To enable: System Settings > General > Software Update > "
                    "Automatic Updates > Install system data and security updates. "
                    "This is critical for security."
                )
            elif check == "config_data":
                label = "Enable automatic configuration data updates"
                description = (
                    "To enable: System Settings > General > Software Update > "
                    "Automatic Updates > Install system data and security updates "
                    "(includes XProtect, Gatekeeper data)"
                )
            elif check == "app_store_auto":
                label = "Enable App Store automatic updates"
                description = (
                    "To enable: System Settings > General > Software Update > "
                    "Automatic Updates > Automatically update apps from the App Store"
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

    def _read_defaults(self, domain: str, key: str) -> str:
        """Read a macOS defaults value. Returns '1', '0', or '' if not found."""
        try:
            result = subprocess.run(
                ["defaults", "read", domain, key],
                capture_output=True,
                text=True,
            )
            output = result.stdout.strip()
            # defaults read returns "1" or "0" for boolean values
            return output
        except OSError:
            return ""
