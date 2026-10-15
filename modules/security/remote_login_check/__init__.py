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
    name = "remote_login_check"
    category = "security"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "10s"

    emits_codes = [
        "security.remote_login_check.ssh_enabled",
        "security.remote_login_check.screen_sharing_enabled",
        "security.remote_login_check.remote_management_enabled",
        "security.remote_login_check.remote_apple_events_enabled",
        "security.remote_login_check.all_disabled",
    ]

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Check SSH (Remote Login)
        if self._is_ssh_enabled():
            findings.append(
                Finding(
                    title="Remote Login is turned on",
                    description=(
                        "Your Mac allows people to connect to it from another computer "
                        "using a program called SSH. This is a powerful tool that lets "
                        "someone type commands into your computer from a distance. Most "
                        "people do not use this for everyday tasks. If you did not turn "
                        "this on yourself, it is a good idea to check who has access to "
                        "your Mac.\n\n"
                        "If you think someone close to you set this up to monitor you, "
                        "removing it can alert them. Talk to an advocate first (US National "
                        "Domestic Violence Hotline: 1-800-799-7233, or text START to 88788).\n\n"
                        "What to do: Open System Settings, click General, then Sharing. "
                        "Turn off the switch next to Remote Login."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.remote_login_check.ssh_enabled",
                    data={"service": "ssh"},
                )
            )

        # Check Screen Sharing (VNC)
        if self._is_screen_sharing_enabled():
            findings.append(
                Finding(
                    title="Screen Sharing is turned on",
                    description=(
                        "Your Mac is set up to let other people see your screen and control "
                        "your mouse and keyboard from another computer. This is often "
                        "used for tech support, but it is not needed for normal use. If "
                        "you did not enable this, it is a good idea to check who has access "
                        "to your Mac.\n\n"
                        "If you think someone close to you set this up to monitor you, "
                        "removing it can alert them. Talk to an advocate first (US National "
                        "Domestic Violence Hotline: 1-800-799-7233, or text START to 88788).\n\n"
                        "What to do: Open System Settings, click General, then Sharing. "
                        "Turn off the switch next to Screen Sharing."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.remote_login_check.screen_sharing_enabled",
                    data={"service": "screen_sharing"},
                )
            )

        # Check Remote Management (ARD)
        if self._is_remote_management_enabled():
            findings.append(
                Finding(
                    title="Remote Management is turned on",
                    description=(
                        "Your Mac is set up to let other people manage your computer from "
                        "a distance. This is a feature usually used by IT departments "
                        "in offices, not by people at home. If you did not enable this, "
                        "it is a good idea to check who has access to your Mac.\n\n"
                        "If you think someone close to you set this up to monitor you, "
                        "removing it can alert them. Talk to an advocate first (US National "
                        "Domestic Violence Hotline: 1-800-799-7233, or text START to 88788).\n\n"
                        "What to do: Open System Settings, click General, then Sharing. "
                        "Turn off the switch next to Remote Management."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.remote_login_check.remote_management_enabled",
                    data={"service": "remote_management"},
                )
            )

        # Check Remote Apple Events
        if self._is_remote_apple_events_enabled():
            findings.append(
                Finding(
                    title="Remote Apple Events is turned on",
                    description=(
                        "Your Mac is set up to let other computers send commands to your "
                        "apps from a distance. This is a technical feature that most people "
                        "do not use. If you did not enable this, it is a good idea to "
                        "check who has access to your Mac.\n\n"
                        "If you think someone close to you set this up to monitor you, "
                        "removing it can alert them. Talk to an advocate first (US National "
                        "Domestic Violence Hotline: 1-800-799-7233, or text START to 88788).\n\n"
                        "What to do: Open System Settings, click General, then Sharing. "
                        "Turn off the switch next to Remote Apple Events."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.remote_login_check.remote_apple_events_enabled",
                    data={"service": "remote_apple_events"},
                )
            )

        # If no remote services are enabled, add an INFO finding
        if not findings:
            findings.append(
                Finding(
                    title="All remote access services are disabled",
                    description=(
                        "SSH, Screen Sharing, Remote Management, and Remote Apple Events "
                        "are all disabled. This is a secure configuration for a home Mac."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.remote_login_check.all_disabled",
                    data={"secure": True},
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            service = finding.data.get("service")
            if service == "ssh":
                title = "Disable Remote Login (SSH)"
                description = (
                    "To disable Remote Login, open System Settings > General > Sharing, "
                    "find 'Remote Login' and uncheck it. "
                    "Alternatively, run: sudo systemsetup -setremotelogin off"
                )
            elif service == "screen_sharing":
                title = "Disable Screen Sharing (VNC)"
                description = (
                    "To disable Screen Sharing, open System Settings > General > Sharing, "
                    "find 'Screen Sharing' and uncheck it."
                )
            elif service == "remote_management":
                title = "Disable Remote Management (ARD)"
                description = (
                    "To disable Remote Management, open System Settings > General > Sharing, "
                    "find 'Remote Management' and uncheck it."
                )
            elif service == "remote_apple_events":
                title = "Disable Remote Apple Events"
                description = (
                    "To disable Remote Apple Events, open System Settings > General > Sharing, "
                    "find 'Remote Apple Events' and uncheck it. "
                    "Alternatively, run: sudo systemsetup -setremoteappleevents off"
                )
            else:
                # INFO findings (all secure) - skip actions
                continue

            actions.append(
                Action(
                    title=title,
                    description=description,
                    risk_level=RiskLevel.SAFE,
                    success=True,
                    error=None,
                )
            )
        return FixResult(module_name=self.name, actions=actions)

    def _is_ssh_enabled(self) -> bool:
        """Check if SSH (Remote Login) is enabled via systemsetup."""
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

    def _is_screen_sharing_enabled(self) -> bool:
        """Check if Screen Sharing (VNC) is enabled via defaults."""
        try:
            result = subprocess.run(
                [
                    "defaults",
                    "read",
                    "/Library/Preferences/com.apple.RemoteManagement",
                    "ARD_AllLocalUsers",
                ],
                capture_output=True,
                text=True,
                timeout=5,
            )
            # If the key exists, screen sharing is enabled
            if result.returncode == 0:
                return True
            return False
        except (OSError, subprocess.TimeoutExpired):
            return False

    def _is_remote_management_enabled(self) -> bool:
        """Check if Remote Management (ARD) is enabled via defaults."""
        try:
            result = subprocess.run(
                [
                    "defaults",
                    "read",
                    "/Library/Preferences/com.apple.RemoteDesktop",
                ],
                capture_output=True,
                text=True,
                timeout=5,
            )
            # If the file exists and can be read, remote management was configured
            if result.returncode == 0:
                return True
            return False
        except (OSError, subprocess.TimeoutExpired):
            return False

    def _is_remote_apple_events_enabled(self) -> bool:
        """Check if Remote Apple Events is enabled via systemsetup."""
        try:
            result = subprocess.run(
                ["systemsetup", "-getremoteappleevents"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                return "on" in result.stdout.lower()
            return False
        except (OSError, subprocess.TimeoutExpired):
            return False
