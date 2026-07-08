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

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []
        enabled_services = []

        # Check Screen Sharing
        if self._is_screen_sharing_enabled():
            enabled_services.append("Screen Sharing")
            findings.append(
                Finding(
                    title="Screen Sharing is enabled",
                    description=(
                        "Screen Sharing (VNC) allows remote users to view and control your display. "
                        "This is a significant security risk, especially on public networks. "
                        "Most users don't need this service."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"service": "screen_sharing"},
                )
            )

        # Check File Sharing (SMB)
        if self._is_file_sharing_enabled():
            enabled_services.append("File Sharing")
            findings.append(
                Finding(
                    title="File Sharing is enabled",
                    description=(
                        "File Sharing (SMB) allows remote users to access files on your Mac. "
                        "This is a security risk if not properly secured. "
                        "Ensure firewall rules restrict access appropriately."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"service": "file_sharing"},
                )
            )

        # Check Remote Login (SSH)
        if self._is_remote_login_enabled():
            enabled_services.append("Remote Login (SSH)")
            findings.append(
                Finding(
                    title="Remote Login (SSH) is enabled",
                    description=(
                        "Remote Login allows remote users to log in via SSH and execute commands. "
                        "This is a high-risk setting on machines accessible from untrusted networks."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"service": "remote_login"},
                )
            )

        # Check Remote Management (ARD)
        if self._is_remote_management_enabled():
            enabled_services.append("Remote Management (ARD)")
            findings.append(
                Finding(
                    title="Remote Management is enabled",
                    description=(
                        "Remote Management (Apple Remote Desktop) allows remote administration. "
                        "This is a security risk if the Mac is on an untrusted network."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"service": "remote_management"},
                )
            )

        # Check Printer Sharing
        if self._is_printer_sharing_enabled():
            enabled_services.append("Printer Sharing")
            findings.append(
                Finding(
                    title="Printer Sharing is enabled",
                    description=(
                        "Printer Sharing allows network access to your printers. "
                        "This could expose your network to unauthorized access."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"service": "printer_sharing"},
                )
            )

        # Check AirDrop discoverability
        airdrop_mode = self._get_airdrop_mode()
        if airdrop_mode == "Everyone":
            enabled_services.append("AirDrop (Everyone)")
            findings.append(
                Finding(
                    title="AirDrop is discoverable by Everyone",
                    description=(
                        "AirDrop is set to accept files from 'Everyone'. "
                        "This allows strangers to send files to your Mac. "
                        "Consider limiting AirDrop to 'Contacts Only' or 'No One'."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
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
                    data={"config": "secure"},
                )
            )
        else:
            # Add summary of enabled services
            summary = f"Enabled sharing services: {', '.join(enabled_services)}"
            findings.append(
                Finding(
                    title="Sharing configuration summary",
                    description=(
                        f"{summary}. "
                        "Review these services and disable any that are not needed. "
                        "Sharing services should only be enabled on secure, trusted networks."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
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
