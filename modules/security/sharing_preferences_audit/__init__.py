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
    name = "sharing_preferences_audit"
    category = "security"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "5s"

    emits_codes = [
        "security.sharing_preferences_audit.screen_sharing",
        "security.sharing_preferences_audit.file_sharing",
        "security.sharing_preferences_audit.remote_login",
        "security.sharing_preferences_audit.remote_management",
        "security.sharing_preferences_audit.printer_sharing",
        "security.sharing_preferences_audit.airdrop_everyone",
        "security.sharing_preferences_audit.config_secure",
        "security.sharing_preferences_audit.config_summary",
    ]

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []
        enabled_services = []

        # Check Screen Sharing
        if self._is_screen_sharing_enabled():
            enabled_services.append("Screen Sharing")
            findings.append(
                Finding(
                    title="Screen Sharing is enabled on your Mac",
                    description=(
                        "Screen Sharing allows someone to see your screen and control "
                        "your mouse and keyboard from another device. If this is on, anyone "
                        "with the right password or access to your network could take "
                        "over your Mac. Most people do not need this feature turned on.\n\n"
                        "If you think someone close to you set this up to monitor you, "
                        "removing it can alert them. Talk to an advocate first (US National "
                        "Domestic Violence Hotline: 1-800-799-7233, or text START to 88788).\n\n"
                        "What to do: Open System Settings > General > Sharing and turn "
                        "off the Screen Sharing switch."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.sharing_preferences_audit.screen_sharing",
                    data={"service": "screen_sharing"},
                )
            )

        # Check File Sharing (SMB)
        if self._is_file_sharing_enabled():
            enabled_services.append("File Sharing")
            findings.append(
                Finding(
                    title="File Sharing is enabled on your Mac",
                    description=(
                        "File Sharing lets other devices on your network see and access "
                        "folders on your Mac. This is useful for sharing files with family, "
                        "but if left on, it can expose your personal documents to others "
                        "on the same Wi-Fi.\n\n"
                        "What to do: Open System Settings > General > Sharing and turn "
                        "off the File Sharing switch."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.sharing_preferences_audit.file_sharing",
                    data={"service": "file_sharing"},
                )
            )

        # Check Remote Login (SSH)
        if self._is_remote_login_enabled():
            enabled_services.append("Remote Login (SSH)")
            findings.append(
                Finding(
                    title="Remote Login is enabled on your Mac",
                    description=(
                        "Remote Login lets people connect to your Mac from anywhere to "
                        "run commands and manage files. This is a powerful tool for IT "
                        "support, but if enabled, it can be a major security risk if your "
                        "password is weak or your network is public.\n\n"
                        "If you think someone close to you set this up to monitor you, "
                        "removing it can alert them. Talk to an advocate first (US National "
                        "Domestic Violence Hotline: 1-800-799-7233, or text START to 88788).\n\n"
                        "What to do: Open System Settings > General > Sharing and turn "
                        "off the Remote Login switch."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.sharing_preferences_audit.remote_login",
                    data={"service": "remote_login"},
                )
            )

        # Check Remote Management (ARD)
        if self._is_remote_management_enabled():
            enabled_services.append("Remote Management (ARD)")
            findings.append(
                Finding(
                    title="Remote Management is enabled on your Mac",
                    description=(
                        "Remote Management allows a remote user to fully control your "
                        "Mac, including installing software and changing settings. This "
                        "is often used by IT departments, but if you don't work for a "
                        "company that manages your device, it should be off.\n\n"
                        "If you think someone close to you set this up to monitor you, "
                        "removing it can alert them. Talk to an advocate first (US National "
                        "Domestic Violence Hotline: 1-800-799-7233, or text START to 88788).\n\n"
                        "What to do: Open System Settings > General > Sharing and turn "
                        "off the Remote Management switch."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.sharing_preferences_audit.remote_management",
                    data={"service": "remote_management"},
                )
            )

        # Check Printer Sharing
        if self._is_printer_sharing_enabled():
            enabled_services.append("Printer Sharing")
            findings.append(
                Finding(
                    title="Printer Sharing is enabled on your Mac",
                    description=(
                        "Printer Sharing allows other devices on your network to print "
                        "to your printer. While usually harmless, it can sometimes be "
                        "used to probe your network for other vulnerabilities.\n\n"
                        "What to do: If you don't share your printer with others, open "
                        "System Settings > General > Sharing and turn off the Printer "
                        "Sharing switch."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.sharing_preferences_audit.printer_sharing",
                    data={"service": "printer_sharing"},
                )
            )

        # Check AirDrop discoverability
        airdrop_mode = self._get_airdrop_mode()
        if airdrop_mode == "Everyone":
            enabled_services.append("AirDrop (Everyone)")
            findings.append(
                Finding(
                    title="AirDrop is set to accept files from Everyone",
                    description=(
                        "Your AirDrop is currently set to 'Everyone,' which means strangers "
                        "nearby can send you files. This is a common way for unwanted "
                        "files or malware to reach your device in public places.\n\n"
                        "What to do: Open System Settings > General > AirDrop & Handoff and change "
                        "the setting to 'Contacts Only' or 'No One'."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.sharing_preferences_audit.airdrop_everyone",
                    data={"service": "airdrop"},
                )
            )
        elif airdrop_mode == "ContactsOnly":
            enabled_services.append("AirDrop (Contacts Only)")

        # Add INFO summary if no security issues found, or if some services are enabled
        if not findings:
            findings.append(
                Finding(
                    title="Sharing services are properly disabled",
                    description=(
                        "Screen Sharing, File Sharing, Remote Login, Remote Management, "
                        "Printer Sharing are all disabled. AirDrop is set to a safe mode. "
                        "This is a secure configuration for most users."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.sharing_preferences_audit.config_secure",
                    data={"config": "secure"},
                )
            )
        else:
            # Add summary of enabled services
            summary = f"Enabled sharing services: {', '.join(enabled_services)}"
            findings.append(
                Finding(
                    title="Your sharing settings",
                    description=(
                        f"{summary}. "
                        "Review these services and disable any that are not needed. "
                        "Sharing services should only be enabled on secure, trusted networks."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.sharing_preferences_audit.config_summary",
                    data={"config": "summary", "services": enabled_services},
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            service = finding.data.get("service")
            config = finding.data.get("config")

            if service == "screen_sharing":
                actions.append(
                    Action(
                        title="Disable Screen Sharing",
                        description=(
                            "To disable Screen Sharing, open System Settings > General > Sharing, "
                            "find 'Screen Sharing' and toggle it off. "
                            "Alternatively, run: sudo launchctl unload -w "
                            "/System/Library/LaunchDaemons/com.apple.screensharing.plist"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )
            elif service == "file_sharing":
                actions.append(
                    Action(
                        title="Disable File Sharing",
                        description=(
                            "To disable File Sharing, open System Settings > General > Sharing, "
                            "find 'File Sharing' and toggle it off. "
                            "Alternatively, run: sudo launchctl unload -w "
                            "/System/Library/LaunchDaemons/com.apple.smbd.plist"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )
            elif service == "remote_login":
                actions.append(
                    Action(
                        title="Disable Remote Login (SSH)",
                        description=(
                            "To disable Remote Login, open System Settings > General > Sharing, "
                            "find 'Remote Login' and toggle it off. "
                            "Alternatively, run: sudo systemsetup -setremotelogin off"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )
            elif service == "remote_management":
                actions.append(
                    Action(
                        title="Disable Remote Management",
                        description=(
                            "To disable Remote Management, open System Settings > General > Sharing, "
                            "find 'Remote Management' and toggle it off. "
                            "Alternatively, run: sudo launchctl unload -w "
                            "/System/Library/LaunchDaemons/com.apple.ARDAgent.plist"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )
            elif service == "printer_sharing":
                actions.append(
                    Action(
                        title="Disable Printer Sharing",
                        description=(
                            "To disable Printer Sharing, open System Settings > General > Sharing, "
                            "find 'Printer Sharing' and toggle it off. "
                            "Alternatively, run: cupsctl --no-share-printers"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )
            elif service == "airdrop":
                actions.append(
                    Action(
                        title="Restrict AirDrop to Contacts Only",
                        description=(
                            "To restrict AirDrop, open System Settings > General > AirDrop, "
                            "and set it to 'Contacts Only' instead of 'Everyone'. "
                            "This prevents strangers from sending files to your Mac."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )
            elif config == "summary":
                # For summary findings, no action needed
                continue
            elif config == "secure":
                # For secure findings, no action needed
                continue

        return FixResult(module_name=self.name, actions=actions)

    def _is_screen_sharing_enabled(self) -> bool:
        """Check if Screen Sharing is enabled via launchctl."""
        try:
            result = subprocess.run(
                ["launchctl", "list"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                return "com.apple.screensharing" in result.stdout
            return False
        except (OSError, subprocess.TimeoutExpired):
            return False

    def _is_file_sharing_enabled(self) -> bool:
        """Check if File Sharing (SMB) is enabled via launchctl."""
        try:
            result = subprocess.run(
                ["launchctl", "list"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                return "com.apple.smbd" in result.stdout
            return False
        except (OSError, subprocess.TimeoutExpired):
            return False

    def _is_remote_login_enabled(self) -> bool:
        """Check if Remote Login (SSH) is enabled via systemsetup."""
        try:
            result = subprocess.run(
                ["systemsetup", "-getremotelogin"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                return "on" in result.stdout.lower()
            return False
        except (OSError, subprocess.TimeoutExpired):
            return False

    def _is_remote_management_enabled(self) -> bool:
        """Check if Remote Management (ARD) is enabled via launchctl."""
        try:
            result = subprocess.run(
                ["launchctl", "list"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                return "com.apple.ARDAgent" in result.stdout
            return False
        except (OSError, subprocess.TimeoutExpired):
            return False

    def _is_printer_sharing_enabled(self) -> bool:
        """Check if Printer Sharing is enabled via cupsctl."""
        try:
            result = subprocess.run(
                ["cupsctl"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                return "_share_printers=1" in result.stdout
            return False
        except (OSError, subprocess.TimeoutExpired):
            return False

    def _get_airdrop_mode(self) -> str | None:
        """Get AirDrop discoverability mode.

        Returns 'Everyone', 'ContactsOnly', 'No One', or None if unable to determine.
        """
        try:
            result = subprocess.run(
                ["defaults", "read", "com.apple.sharingd", "DiscoverableMode"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                mode = result.stdout.strip()
                if "Everyone" in mode:
                    return "Everyone"
                elif "ContactsOnly" in mode or "Contacts" in mode:
                    return "ContactsOnly"
                elif "No" in mode or "Off" in mode:
                    return "Off"
            return None
        except (OSError, subprocess.TimeoutExpired):
            return None
