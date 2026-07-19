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
                    title="Screen Sharing is enabled",
                    description=(
                        "Screen Sharing (VNC) is enabled on this Mac. "
                        "Most home users don't need this service. "
                        "It allows remote users to see and control your display."
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
                    title="File Sharing (SMB) is enabled",
                    description=(
                        "SMB file sharing is enabled on this Mac. "
                        "Most home users don't need this service. "
                        "It allows remote users to access files via network shares."
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
                    title="Remote Login (SSH) is enabled",
                    description=(
                        "Remote Login (SSH) is enabled on this Mac. "
                        "Most home users don't need this service. "
                        "It allows remote users to log in and execute commands."
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
                    title="Remote Management (ARD) is enabled",
                    description=(
                        "Remote Management (Apple Remote Desktop) is enabled. "
                        "Most home users don't need this service. "
                        "It allows remote users to manage your Mac."
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
                    title="Printer Sharing is enabled",
                    description=(
                        "Printer Sharing is enabled on this Mac. "
                        "Most home users don't need this service. "
                        "It allows remote users to access shared printers."
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
                    if service_name in line:
                        # If the line contains the service name and doesn't start with "-",
                        # it's likely running
                        parts = line.split()
                        if parts and parts[0] != "-":
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
        """Check if Printer Sharing is enabled via defaults."""
        try:
            result = subprocess.run(
                [
                    "defaults",
                    "read",
                    "/Library/Preferences/com.apple.AppleFileServer",
                    "guestAccess",
                ],
                capture_output=True,
                text=True,
            )
            # If the key exists and is 1, printer sharing is enabled
            if result.returncode == 0:
                return "1" in result.stdout
            # Also check if there are any shared printers
            result2 = subprocess.run(
                [
                    "defaults",
                    "read",
                    "/Library/Preferences/com.apple.AppleFileServer",
                ],
                capture_output=True,
                text=True,
            )
            if result2.returncode == 0:
                # If the file exists, it means printer sharing was configured
                return True
            return False
        except OSError:
            return False
