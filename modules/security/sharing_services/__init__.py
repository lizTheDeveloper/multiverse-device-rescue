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
from rescue.macos_launchd import (
    FILE_SHARING,
    REMOTE_LOGIN,
    SCREEN_SHARING,
    parse_result,
)
from rescue.module_base import ModuleBase


class Module(ModuleBase):
    name = "sharing_services"
    category = "security"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "10s"

    emits_codes = [
        "security.sharing_services.screen_sharing",
        "security.sharing_services.file_sharing",
        "security.sharing_services.remote_login",
        "security.sharing_services.remote_management",
        "security.sharing_services.printer_sharing",
        "security.sharing_services.sharing_unknown",
    ]

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []
        # Each service reads as True (on), False (off) or None (couldn't tell).
        # None is listed in one info "couldn't check" finding, never as "off".
        unknown: list[str] = []
        screen_sharing = self._screen_sharing_state()
        file_sharing = self._file_sharing_state()
        remote_login = self._remote_login_state()
        printer_sharing = self._is_printer_sharing_enabled()
        for state, label in (
            (screen_sharing, "Screen Sharing"),
            (file_sharing, "File Sharing"),
            (remote_login, "Remote Login"),
            (printer_sharing, "Printer Sharing"),
        ):
            if state is None:
                unknown.append(label)

        # Check Screen Sharing (com.apple.screensharing)
        if screen_sharing is True:
            findings.append(
                Finding(
                    title="Screen Sharing is enabled on your Mac",
                    description=(
                        "Your Mac is set up to let other people see and control your screen "
                        "from another device. This is a powerful tool that most people "
                        "don't need for daily use. If you didn't turn this on, it could "
                        "allow someone else to watch what you are doing.\n\n"
                        "If you think someone close to you set this up to monitor you, "
                        "removing it can alert them. Talk to an advocate first (US National "
                        "Domestic Violence Hotline: 1-800-799-7233, or text START to 88788).\n\n"
                        "What to do: Open System Settings, go to General > Sharing, and "
                        "turn off the switch next to 'Screen Sharing'."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.sharing_services.screen_sharing",
                    data={"service": "screen_sharing"},
                )
            )

        # Check File Sharing / SMB (com.apple.smbd)
        if file_sharing is True:
            findings.append(
                Finding(
                    title="File Sharing is enabled on your Mac",
                    description=(
                        "Your Mac is allowing other devices on your network to access "
                        "your files. This is useful if you share folders with family, "
                        "but most people don't need it on. If you didn't turn this on, "
                        "it could let someone browse your documents.\n\n"
                        "What to do: Open System Settings, go to General > Sharing, and "
                        "turn off the switch next to 'File Sharing'."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.sharing_services.file_sharing",
                    data={"service": "file_sharing"},
                )
            )

        # Check Remote Login / SSH (com.apple.sshd)
        if remote_login is True:
            findings.append(
                Finding(
                    title="Remote Login is enabled on your Mac",
                    description=(
                        "Your Mac is allowing people to log in from another computer and "
                        "run commands. This is a technical feature that most home users "
                        "do not need. If you didn't turn this on, it could let someone "
                        "access your system from outside your home.\n\n"
                        "If you think someone close to you set this up to monitor you, "
                        "removing it can alert them. Talk to an advocate first (US National "
                        "Domestic Violence Hotline: 1-800-799-7233, or text START to 88788).\n\n"
                        "What to do: Open System Settings, go to General > Sharing, and "
                        "turn off the switch next to 'Remote Login'."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.sharing_services.remote_login",
                    data={"service": "remote_login"},
                )
            )

        # Check Remote Management / ARD (com.apple.RemoteDesktop.agent)
        if self._is_service_enabled("com.apple.RemoteDesktop.agent"):
            findings.append(
                Finding(
                    title="Remote Management is enabled on your Mac",
                    description=(
                        "Your Mac is allowing remote administration, which lets someone "
                        "manage your computer from afar. This is a very powerful setting "
                        "usually reserved for IT support. If you didn't turn this on, "
                        "it could let someone control your Mac without you knowing.\n\n"
                        "If you think someone close to you set this up to monitor you, "
                        "removing it can alert them. Talk to an advocate first (US National "
                        "Domestic Violence Hotline: 1-800-799-7233, or text START to 88788).\n\n"
                        "What to do: Open System Settings, go to General > Sharing, and "
                        "turn off the switch next to 'Remote Management'."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.sharing_services.remote_management",
                    data={"service": "remote_management"},
                )
            )

        # Check Printer Sharing
        if printer_sharing is True:
            findings.append(
                Finding(
                    title="Printer Sharing is enabled on your Mac",
                    description=(
                        "Your Mac is allowing other devices on your network to print to "
                        "your printers. This is usually safe, but if you didn't turn it "
                        "on, it means your Mac is open to other devices on your Wi-Fi. "
                        "Most people don't need this if they only print from their own "
                        "devices.\n\n"
                        "What to do: Open System Settings, go to General > Sharing, and "
                        "turn off the switch next to 'Printer Sharing'."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.sharing_services.printer_sharing",
                    data={"service": "printer_sharing"},
                )
            )

        if unknown:
            findings.append(
                Finding(
                    title="Couldn't check some sharing settings",
                    description=(
                        "Device Rescue couldn't read whether these are on: "
                        + ", ".join(unknown)
                        + ". This is not a sign that anything is wrong. To see for "
                        "yourself, open System Settings > General > Sharing."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.sharing_services.sharing_unknown",
                    data={"check": "sharing_unknown", "services": unknown},
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            service = finding.data.get("service")
            if service == "screen_sharing":
                title = "Disable Screen Sharing"
                description = (
                    "To disable Screen Sharing, open System Settings > General > Sharing, "
                    "find 'Screen Sharing' and uncheck it."
                )
            elif service == "file_sharing":
                title = "Disable File Sharing (SMB)"
                description = (
                    "To disable File Sharing, open System Settings > General > Sharing, "
                    "find 'File Sharing' and uncheck it."
                )
            elif service == "remote_login":
                title = "Disable Remote Login (SSH)"
                description = (
                    "To disable Remote Login, open System Settings > General > Sharing, "
                    "find 'Remote Login' and uncheck it. "
                    "Alternatively, run: sudo systemsetup -setremotelogin off"
                )
            elif service == "remote_management":
                title = "Disable Remote Management (ARD)"
                description = (
                    "To disable Remote Management, open System Settings > General > Sharing, "
                    "find 'Remote Management' and uncheck it."
                )
            elif service == "printer_sharing":
                title = "Disable Printer Sharing"
                description = (
                    "To disable Printer Sharing, open System Settings > General > Sharing, "
                    "find 'Printer Sharing' and uncheck it."
                )
            else:
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

    def _is_service_enabled(self, service_name: str) -> bool:
        """Check if a service is enabled via launchctl list."""
        try:
            result = subprocess.run(
                ["launchctl", "list"],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                # launchctl list shows services with a dash if they're loaded
                # Format is: PID  Status  Label
                for line in result.stdout.splitlines():
                    parts = line.split()
                    # Exact label: a substring test also matched per-user
                    # helpers such as com.apple.screensharing.agent.
                    if parts and parts[-1] == service_name and parts[0] != "-":
                        return True
                return False
            return False
        except OSError:
            return False

    # Screen Sharing, File Sharing and Remote Login are system daemons that
    # launchd loads only while the switch is on. A user's `launchctl list`
    # never shows them, and `systemsetup -getremotelogin` needs admin, so
    # both used to report "off" for a service that was on.
    # `launchctl print system/<label>` answers without admin.

    def _screen_sharing_state(self) -> bool | None:
        return parse_result(SCREEN_SHARING, self._safe(lambda: subprocess.run(
            ["launchctl", "print", "system/com.apple.screensharing"], capture_output=True, text=True, timeout=5)))

    def _file_sharing_state(self) -> bool | None:
        return parse_result(FILE_SHARING, self._safe(lambda: subprocess.run(
            ["launchctl", "print", "system/com.apple.smbd"], capture_output=True, text=True, timeout=5)))

    def _remote_login_state(self) -> bool | None:
        return parse_result(REMOTE_LOGIN, self._safe(lambda: subprocess.run(
            ["launchctl", "print", "system/com.openssh.sshd"], capture_output=True, text=True, timeout=5)))

    @staticmethod
    def _safe(call):
        """``call()`` (a subprocess.run written out in full, so docs/commands.md
        lists it), or None if it couldn't run."""
        try:
            return call()
        except (OSError, subprocess.SubprocessError):
            return None

    def _is_printer_sharing_enabled(self) -> bool | None:
        """Check if Printer Sharing is on: ``cupsctl`` prints ``_share_printers=1``.

        This used to read the AFP file server's preferences
        (/Library/Preferences/com.apple.AppleFileServer), which exist on most
        Macs and have nothing to do with printers, and reported "Printer
        Sharing is enabled" whenever that file existed.
        """
        try:
            result = subprocess.run(
                ["cupsctl"],
                capture_output=True,
                text=True,
                timeout=10,
            )
        except (OSError, subprocess.SubprocessError):
            return None  # couldn't run cupsctl: unknown, not off
        if result.returncode != 0 or not isinstance(result.stdout, str):
            return None
        if "_share_printers=1" in result.stdout:
            return True
        if "_share_printers=0" in result.stdout:
            return False
        return None
