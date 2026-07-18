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

SOCKETFILTERFW = "/usr/libexec/ApplicationFirewall/socketfilterfw"


class Module(ModuleBase):
    name = "firewall_audit"
    category = "security"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.MODERATE
    priority = 60
    depends_on = []
    estimated_duration = "5s"

    emits_codes = [
        "security.firewall_audit.global_state",
        "security.firewall_audit.stealth_mode",
    ]

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        global_state = self._run_socketfilterfw("--getglobalstate")
        if "disabled" in global_state.lower():
            findings.append(
                Finding(
                    title="Firewall is disabled",
                    description=(
                        "The macOS Application Firewall is currently disabled. "
                        "This leaves the system open to unsolicited incoming "
                        "connections."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
                    code="security.firewall_audit.global_state",
                    data={"check": "global_state"},
                )
            )

        stealth_state = self._run_socketfilterfw("--getstealthmode")
        if "disabled" in stealth_state.lower():
            findings.append(
                Finding(
                    title="Stealth mode is disabled",
                    description=(
                        "Stealth mode is off, so this Mac responds to network "
                        "probes (e.g. ping) that could reveal it to attackers "
                        "scanning the network."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.firewall_audit.stealth_mode",
                    data={"check": "stealth_mode"},
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            check = finding.data.get("check")
            if check == "global_state":
                flag, label = "--setglobalstate", "Enable firewall"
            elif check == "stealth_mode":
                flag, label = "--setstealthmode", "Enable stealth mode"
            else:
                continue
            try:
                result = subprocess.run(
                    [SOCKETFILTERFW, flag, "on"],
                    capture_output=True,
                    text=True,
                )
                success = result.returncode == 0
                error = None if success else (
                    result.stderr.strip()
                    or "socketfilterfw command failed (may require sudo)"
                )
            except OSError as e:
                success = False
                error = str(e)
            actions.append(
                Action(
                    title=label,
                    description=f"Ran `socketfilterfw {flag} on`.",
                    risk_level=RiskLevel.MODERATE,
                    kind=ActionKind.MUTATION,
                    executed=True,
                    success=success,
                    error=error,
                )
            )
        return FixResult(module_name=self.name, actions=actions)

    def _run_socketfilterfw(self, flag: str) -> str:
        result = subprocess.run(
            [SOCKETFILTERFW, flag],
            capture_output=True,
            text=True,
        )
        return result.stdout
