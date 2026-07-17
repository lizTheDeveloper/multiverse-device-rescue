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
                    title="Automatic software update check is disabled",
                    description=(
                        "The system is not configured to automatically check for "
                        "software updates. This can delay important security patches."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
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
                    title="Automatic software update download is disabled",
                    description=(
                        "The system is not configured to automatically download "
                        "available updates. This delays the installation of security patches."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
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
                    title="Automatic macOS updates are disabled",
                    description=(
                        "The system is not configured to automatically install macOS "
                        "updates. Regular macOS updates are critical for security."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
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
                    title="Automatic critical update installation is disabled",
                    description=(
                        "The system is not configured to automatically install critical "
                        "security updates. This is a significant security risk."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
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
                    title="Automatic configuration data updates are disabled",
                    description=(
                        "The system is not configured to automatically install "
                        "configuration data updates (XProtect, Gatekeeper data). "
                        "This impacts security threat detection."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
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
                    title="App Store automatic updates are disabled",
                    description=(
                        "The system is not configured to automatically update apps "
                        "from the App Store. This can delay security patches for "
                        "installed applications."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
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
