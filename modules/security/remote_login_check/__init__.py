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
from rescue.macos_launchd import REMOTE_LOGIN, SCREEN_SHARING, parse_result
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
        "security.remote_login_check.remote_access_unknown",
    ]

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []
        # True (on) / False (off) / None (couldn't tell). systemsetup needs
        # admin; without it Remote Login used to read as "off" -- the miss
        # direction for a security check.
        ssh_state = self._is_ssh_enabled()
        apple_events_state = self._is_remote_apple_events_enabled()
        unknown = [
            label for state, label in (
                (ssh_state, "Remote Login (SSH)"),
                (apple_events_state, "Remote Apple Events"),
            ) if state is None
        ]

        # Check SSH (Remote Login)
        if ssh_state is True:
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
        if self._is_screen_sharing_enabled() or self._screen_sharing_daemon_loaded():
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
        if apple_events_state is True:
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

        if unknown:
            findings.append(
                Finding(
                    title="Couldn't check some remote access settings",
                    description=(
                        "Device Rescue couldn't read whether these are on: "
                        + ", ".join(unknown)
                        + ". This is not a sign that anything is wrong. To see for "
                        "yourself, open System Settings > General > Sharing."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.remote_login_check.remote_access_unknown",
                    data={"check": "remote_access_unknown", "services": unknown},
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

    def _is_ssh_enabled(self) -> bool | None:
        """Is Remote Login on? `launchctl print system/com.openssh.sshd` answers
        without admin; systemsetup (admin only) is the fallback. None if
        neither could tell."""
        try:
            result = subprocess.run(
                ["launchctl", "print", "system/com.openssh.sshd"],
                capture_output=True,
                text=True,
                timeout=5,
            )
        except (OSError, subprocess.SubprocessError):
            result = None
        state = parse_result(REMOTE_LOGIN, result)
        if state is not None:
            return state
        return self._systemsetup_on_off(["systemsetup", "-getremotelogin"], "Remote Login")

    @staticmethod
    def _systemsetup_on_off(cmd: list[str], label: str) -> bool | None:
        """'<label>: On/Off' from systemsetup; None for the admin refusal etc."""
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        except (OSError, subprocess.SubprocessError):
            return None
        out = result.stdout if isinstance(result.stdout, str) else ""
        match = re.search(rf"{re.escape(label)}:\s*(On|Off)\b", out)
        if result.returncode != 0 or not match:
            return None
        return match.group(1) == "On"

    def _screen_sharing_daemon_loaded(self) -> bool:
        try:
            result = subprocess.run(
                ["launchctl", "print", "system/com.apple.screensharing"],
                capture_output=True,
                text=True,
                timeout=5,
            )
        except (OSError, subprocess.SubprocessError):
            return False
        return parse_result(SCREEN_SHARING, result) is True

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

    def _is_remote_apple_events_enabled(self) -> bool | None:
        """Is Remote Apple Events on? The AEServer daemon is loaded only while it
        is; systemsetup (admin only) is the fallback."""
        try:
            result = subprocess.run(
                ["launchctl", "print", "system/com.apple.AEServer"],
                capture_output=True,
                text=True,
                timeout=5,
            )
        except (OSError, subprocess.SubprocessError):
            result = None
        state = parse_result("com.apple.AEServer", result)
        if state is not None:
            return state
        return self._systemsetup_on_off(
            ["systemsetup", "-getremoteappleevents"], "Remote Apple Events")
