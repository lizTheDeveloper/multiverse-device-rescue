import subprocess

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

# Maps the profile name reported by `netsh advfirewall show allprofiles`
# to the keyword netsh expects when targeting that profile with `set`.
PROFILE_KEYWORDS = {
    "Domain Profile": "domainprofile",
    "Private Profile": "privateprofile",
    "Public Profile": "publicprofile",
}


class Module(ModuleBase):
    name = "win_firewall"
    category = "security"
    platforms = [Platform.WIN32]
    risk_level = RiskLevel.MODERATE
    priority = 60
    depends_on = []
    estimated_duration = "5s"

    emits_codes = [
        "security.win_firewall.public_profile_disabled",
        "security.win_firewall.private_domain_profile_disabled",
    ]

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []
        output = self._run_netsh_show()
        for profile_name, state in _parse_advfirewall_output(output).items():
            if state == "OFF":
                is_public = profile_name == "Public Profile"
                severity = Severity.CRITICAL if is_public else Severity.WARNING
                if is_public:
                    code = "security.win_firewall.public_profile_disabled"
                else:
                    code = "security.win_firewall.private_domain_profile_disabled"
                findings.append(
                    Finding(
                        title=f"{profile_name} firewall is disabled",
                        description=(
                            f"The Windows Firewall {profile_name} is currently "
                            "off. This leaves the system open to unsolicited "
                            "inbound connections while using that network profile."
                        ),
                        severity=severity,
                        category=self.category,
                        code=code,
                        data={"profile_name": profile_name},
                    )
                )
        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            profile_name = finding.data.get("profile_name", "")
            keyword = PROFILE_KEYWORDS.get(profile_name)
            if keyword is None:
                continue
            try:
                result = subprocess.run(
                    ["netsh", "advfirewall", "set", keyword, "state", "on"],
                    capture_output=True,
                    text=True,
                )
                success = result.returncode == 0
                error = None if success else (
                    result.stderr.strip()
                    or "netsh command failed (may require Administrator privileges)"
                )
            except OSError as e:
                success = False
                error = str(e)
            actions.append(
                Action(
                title=f"Enable {profile_name} firewall",
                description=f"Ran `netsh advfirewall set {keyword} state on`.",
                risk_level=RiskLevel.MODERATE,
                kind=ActionKind.MUTATION,
                executed=True,
                success=success,
                    error=error,
                )
            )
        return FixResult(module_name=self.name, actions=actions)

    def _run_netsh_show(self) -> str:
        try:
            result = subprocess.run(
                ["netsh", "advfirewall", "show", "allprofiles"],
                capture_output=True,
                text=True,
            )
            return result.stdout
        except (OSError, subprocess.SubprocessError):
            return ""


def _parse_advfirewall_output(output: str) -> dict[str, str]:
    """Parse `netsh advfirewall show allprofiles` output.

    Example::

        Domain Profile Settings:
        ----------------------------------------------------------------------
        State                                 ON
        Firewall Policy                       BlockInbound,AllowOutbound

        Private Profile Settings:
        ----------------------------------------------------------------------
        State                                 ON

        Public Profile Settings:
        ----------------------------------------------------------------------
        State                                 OFF
    """
    states: dict[str, str] = {}
    current_profile = None
    for line in output.splitlines():
        stripped = line.strip()
        if stripped.endswith("Profile Settings:"):
            current_profile = stripped[: -len(" Settings:")]
        elif stripped.startswith("State") and current_profile:
            parts = stripped.split()
            if len(parts) >= 2:
                states[current_profile] = parts[-1].upper()
            current_profile = None
    return states
