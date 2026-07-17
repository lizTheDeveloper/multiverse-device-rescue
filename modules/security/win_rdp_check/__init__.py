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
    name = "win_rdp_check"
    category = "security"
    platforms = [Platform.WIN32]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "5s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Check if RDP is enabled
        rdp_enabled = self._is_rdp_enabled()
        rdp_port = self._get_rdp_port()
        nla_enabled = self._is_nla_enabled()

        if rdp_enabled:
            # RDP is enabled - check NLA status
            if not nla_enabled:
                # RDP enabled without NLA is a critical security risk (brute force vulnerable)
                findings.append(
                    Finding(
                        title="RDP enabled without Network Level Authentication (NLA)",
                        description=(
                            "Remote Desktop Protocol (RDP) is enabled but Network Level "
                            "Authentication is not required. This allows attackers to attempt "
                            "brute force attacks on the RDP port. NLA should be enabled to "
                            "require authentication before a full RDP session is established."
                        ),
                        severity=Severity.CRITICAL,
                        category=self.category,
                        data={
                            "rdp_enabled": True,
                            "nla_enabled": False,
                            "rdp_port": rdp_port,
                        },
                    )
                )
            else:
                # RDP is enabled with NLA - still warn since it's usually unnecessary on home PCs
                findings.append(
                    Finding(
                        title="RDP is enabled",
                        description=(
                            "Remote Desktop Protocol (RDP) is enabled on this system. "
                            "While RDP is secured with Network Level Authentication, "
                            "RDP is often unnecessary on personal computers and increases "
                            "the attack surface. Consider disabling RDP if remote access "
                            "is not required."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={
                            "rdp_enabled": True,
                            "nla_enabled": True,
                            "rdp_port": rdp_port,
                        },
                    )
                )
        else:
            # RDP is disabled - this is secure
            findings.append(
                Finding(
                    title="RDP is disabled",
                    description=(
                        "Remote Desktop Protocol (RDP) is disabled. "
                        "This is the secure default configuration."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "rdp_enabled": False,
                        "nla_enabled": nla_enabled,
                        "rdp_port": rdp_port,
                    },
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        for finding in findings.findings:
            rdp_enabled = finding.data.get("rdp_enabled", False)
            nla_enabled = finding.data.get("nla_enabled", False)

            if rdp_enabled and not nla_enabled:
                # Suggest enabling NLA
                actions.append(
                    Action(
                        title="Enable Network Level Authentication (NLA) for RDP",
                        description=(
                            "To secure RDP, Network Level Authentication should be enabled. "
                            "This requires authentication before a full RDP session is established. "
                            "Run: reg add "
                            '"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp" '
                            '/v UserAuthentication /t REG_DWORD /d 1 /f'
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )
            elif rdp_enabled and nla_enabled:
                # Suggest disabling RDP
                actions.append(
                    Action(
                        title="Disable Remote Desktop Protocol (RDP)",
                        description=(
                            "If RDP is not needed, it should be disabled to reduce the attack surface. "
                            "Run: reg add "
                            '"HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server" '
                            '/v fDenyTSConnections /t REG_DWORD /d 1 /f'
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )
            else:
                # RDP is already disabled - no action needed
                actions.append(
                    Action(
                        title="RDP is already disabled",
                        description="No action required; RDP is already in the secure state.",
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _is_rdp_enabled(self) -> bool:
        """Check if RDP is enabled via fDenyTSConnections registry value.

        fDenyTSConnections = 0 means RDP is ENABLED
        fDenyTSConnections = 1 means RDP is DISABLED
        """
        try:
            result = subprocess.run(
                [
                    "reg", "query",
                    "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server",
                    "/v", "fDenyTSConnections"
                ],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                return False

            # Parse output to find the REG_DWORD value
            for line in result.stdout.splitlines():
                if "fDenyTSConnections" in line and "REG_DWORD" in line:
                    # Format: "    fDenyTSConnections    REG_DWORD    0x0"
                    parts = line.split()
                    if len(parts) >= 3:
                        value_str = parts[-1]
                        try:
                            value = int(value_str, 16)
                            return value == 0  # 0 means enabled
                        except (ValueError, IndexError):
                            pass
            return False
        except (OSError, subprocess.SubprocessError):
            return False

    def _is_nla_enabled(self) -> bool:
        """Check if Network Level Authentication (NLA) is required.

        UserAuthentication = 1 means NLA is ENABLED
        UserAuthentication = 0 means NLA is DISABLED
        """
        try:
            result = subprocess.run(
                [
                    "reg", "query",
                    "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp",
                    "/v", "UserAuthentication"
                ],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                return False

            # Parse output to find the REG_DWORD value
            for line in result.stdout.splitlines():
                if "UserAuthentication" in line and "REG_DWORD" in line:
                    # Format: "    UserAuthentication    REG_DWORD    0x1"
                    parts = line.split()
                    if len(parts) >= 3:
                        value_str = parts[-1]
                        try:
                            value = int(value_str, 16)
                            return value == 1  # 1 means enabled
                        except (ValueError, IndexError):
                            pass
            return False
        except (OSError, subprocess.SubprocessError):
            return False

    def _get_rdp_port(self) -> int:
        """Get the RDP port number (default is 3389)."""
        try:
            result = subprocess.run(
                [
                    "reg", "query",
                    "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp",
                    "/v", "PortNumber"
                ],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                return 3389

            # Parse output to find the REG_DWORD value
            for line in result.stdout.splitlines():
                if "PortNumber" in line and "REG_DWORD" in line:
                    # Format: "    PortNumber    REG_DWORD    0xd3d" (which is 3389 in decimal)
                    parts = line.split()
                    if len(parts) >= 3:
                        value_str = parts[-1]
                        try:
                            value = int(value_str, 16)
                            return value
                        except (ValueError, IndexError):
                            pass
            return 3389
        except (OSError, subprocess.SubprocessError):
            return 3389
