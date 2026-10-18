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
    ]

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Check Screen Sharing (com.apple.screensharing)
        if self._is_service_enabled("com.apple.screensharing"):
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
        if self._is_service_enabled("com.apple.smbd"):
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
        if self._is_ssh_enabled():
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
        if self._is_printer_sharing_enabled():
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

    def _is_ssh_enabled(self) -> bool:
        """Check if SSH (Remote Login) is enabled via systemsetup."""
        try:
            result = subprocess.run(
                ["systemsetup", "-getremotelogin"],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                return "on" in result.stdout.lower()
            # Fallback: check launchctl
            return self._is_service_enabled("com.apple.sshd")
        except OSError:
            # Fallback to launchctl check
            return self._is_service_enabled("com.apple.sshd")

    def _is_printer_sharing_enabled(self) -> bool:
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
            return False
        if result.returncode != 0 or not isinstance(result.stdout, str):
            return False
        return "_share_printers=1" in result.stdout
