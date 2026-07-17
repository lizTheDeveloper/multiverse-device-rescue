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
    name = "sip_gatekeeper"
    category = "security"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 55
    depends_on = []
    estimated_duration = "3s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Check SIP status
        sip_enabled = self._check_sip_status()
        if sip_enabled is False:
            findings.append(
                Finding(
                    title="System Integrity Protection (SIP) is disabled",
                    description=(
                        "SIP is disabled on this machine. This is common on older "
                        "hackintosh or development machines, but leaves the system "
                        "vulnerable to unauthorized modifications to critical system files."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "sip_status"},
                )
            )

        # Check Gatekeeper status
        gatekeeper_enabled = self._check_gatekeeper_status()
        if gatekeeper_enabled is False:
            findings.append(
                Finding(
                    title="Gatekeeper is disabled",
                    description=(
                        "Gatekeeper assessments are disabled. This is common on "
                        "machines running unsigned or self-signed applications, but "
                        "reduces protection against running malicious code."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "gatekeeper_status"},
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        """
        Provide informational guidance on how to re-enable SIP and Gatekeeper.
        Does not actually modify the system.
        """
        actions = []

        for finding in findings.findings:
            check = finding.data.get("check")

            if check == "sip_status":
                actions.append(
                    Action(
                        title="Re-enable System Integrity Protection (SIP)",
                        description=(
                            "Reboot into Recovery Mode (Cmd+R during startup), open Terminal, "
                            "and run: csrutil enable\n"
                            "Then reboot normally. Note: SIP protects critical system files "
                            "from modification."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "gatekeeper_status":
                actions.append(
                    Action(
                        title="Re-enable Gatekeeper",
                        description=(
                            "Run: sudo spctl --master-enable\n"
                            "This will re-enable Gatekeeper's code signature verification. "
                            "If you have unsigned apps you need to run, you can allow them "
                            "individually instead of disabling Gatekeeper globally."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _check_sip_status(self) -> bool | None:
        """
        Check SIP status by running: csrutil status
        Returns: True if enabled, False if disabled, None if unable to determine
        """
        try:
            result = subprocess.run(
                ["/usr/bin/csrutil", "status"],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                return None
            output = result.stdout.lower()
            return "enabled" in output
        except (OSError, subprocess.SubprocessError):
            return None

    def _check_gatekeeper_status(self) -> bool | None:
        """
        Check Gatekeeper status by running: spctl --status
        Returns: True if enabled (assessments enabled), False if disabled, None if unable to determine
        """
        try:
            result = subprocess.run(
                ["/usr/sbin/spctl", "--status"],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                return None
            output = result.stdout.lower()
            return "enabled" in output
        except (OSError, subprocess.SubprocessError):
            return None
