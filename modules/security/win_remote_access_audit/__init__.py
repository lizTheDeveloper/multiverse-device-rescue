"""Windows' built-in Remote Desktop (RDP): is it on?

Remote Desktop lets someone sign in to this computer over the network. It is
often left on after a support session. This check reads one registry value,
``fDenyTSConnections``: 0 means connections are allowed.

Third-party remote-access tools (TeamViewer, AnyDesk, VNC, LogMeIn, Chrome
Remote Desktop and the rest) are ``remote_access_tools``' job, so each tool is
reported once, with the evidence about when it arrived and whether it's used.
The ``no_tools_found`` code is kept for compatibility; it now means "RDP is
off". A setting that couldn't be read is an error, never "off".
"""

from rescue.command import run
from rescue.models import (
    Action,
    ActionKind,
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

_RDP_KEY = r"HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server"
_TIMEOUT = 10


class Module(ModuleBase):
    name = "win_remote_access_audit"
    category = "security"
    platforms = [Platform.WIN32]
    risk_level = RiskLevel.SAFE
    priority = 55
    depends_on = []
    estimated_duration = "2s"

    emits_codes = [
        "security.win_remote_access_audit.rdp_enabled",
        "security.win_remote_access_audit.no_tools_found",
    ]

    def check(self, profile: SystemProfile) -> CheckResult:
        rdp_enabled = self._check_rdp_enabled()
        if rdp_enabled is None:
            return CheckResult(
                module_name=self.name,
                error="Couldn't read whether Remote Desktop is on (the registry value couldn't be read).",
            )
        if rdp_enabled:
            finding = Finding(
                title="Remote Desktop (RDP) is turned on",
                description=(
                    "Your computer's Remote Desktop feature is on. It lets someone sign in to this "
                    "computer over a network. It is often left on after a support session. If you don't "
                    "use it, it's safer to turn it off.\n\n"
                    "What to do: Open Windows Settings > System > Remote Desktop. If you don't use it, "
                    "set it to Off."
                ),
                severity=Severity.WARNING,
                category=self.category,
                code="security.win_remote_access_audit.rdp_enabled",
                data={"check": "rdp_enabled"},
            )
        else:
            finding = Finding(
                title="RDP is off",
                description=(
                    "Windows' Remote Desktop is turned off, so nobody can sign in to this computer with it. "
                    "Other remote-access tools are checked separately."
                ),
                severity=Severity.INFO,
                category=self.category,
                code="security.win_remote_access_audit.no_tools_found",
                data={"check": "no_tools_found"},
            )
        return CheckResult(module_name=self.name, findings=[finding])

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            if finding.data.get("check") == "rdp_enabled":
                actions.append(
                    Action(
                        title="Turn off Remote Desktop if you don't use it",
                        description=(
                            "Open Settings > System > Remote Desktop and set it to Off. If you do use it, "
                            "keep \"Require devices to use Network Level Authentication\" on, use a strong "
                            "password, and only allow it from networks you trust."
                        ),
                        risk_level=RiskLevel.SAFE,
                        kind=ActionKind.GUIDANCE,
                        success=True,
                    )
                )
        return FixResult(module_name=self.name, actions=actions)

    def _check_rdp_enabled(self) -> bool | None:
        """True when RDP is on, False when off, None when the value couldn't be read."""
        result = run(["reg", "query", _RDP_KEY, "/v", "fDenyTSConnections"], timeout=_TIMEOUT)
        if not result.ok:
            return None
        for line in result.stdout.splitlines():
            if "fDenyTSConnections" not in line:
                continue
            value = line.split()[-1].lower()
            # 0x0: connections are not denied, so RDP is on.
            if value in ("0x0", "0"):
                return True
            if value in ("0x1", "1"):
                return False
        return None
