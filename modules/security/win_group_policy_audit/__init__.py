import subprocess
import re

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
    name = "win_group_policy_audit"
    category = "security"
    platforms = [Platform.WIN32]
    risk_level = RiskLevel.SAFE
    priority = 55
    depends_on = []
    estimated_duration = "10s"

    emits_codes = [
        "security.win_group_policy_audit.stale_domain_policies",
        "security.win_group_policy_audit.restrictive_policy",
        "security.win_group_policy_audit.weak_password_policy",
        "security.win_group_policy_audit.applocker_configured",
        "security.win_group_policy_audit.status_report",
    ]

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Check domain status
        is_domain_joined = self._is_domain_joined()

        # Get applied GPOs
        computer_gpos = self._get_applied_gpos("computer")
        user_gpos = self._get_applied_gpos("user")

        # Check for stale domain policies on non-domain machine
        if not is_domain_joined and (computer_gpos or user_gpos):
            findings.append(
                Finding(
                    title="Stale domain Group Policies detected on non-domain machine",
                    description=(
                        "Group Policies from a domain are still applied to this machine, "
                        "but it's no longer domain-joined. These stale policies may cause "
                        "mysterious restrictions and should be cleaned up."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.win_group_policy_audit.stale_domain_policies",
                    data={
                        "computer_gpos": computer_gpos,
                        "user_gpos": user_gpos,
                        "is_domain_joined": is_domain_joined,
                    },
                )
            )

        # Check for restrictive policies
        restrictive_findings = self._check_restrictive_policies()
        findings.extend(restrictive_findings)

        # Check password policy
        password_findings = self._check_password_policy()
        findings.extend(password_findings)

        # Check audit policy
        audit_policy = self._get_audit_policy()

        # Check for AppLocker or software restriction policies
        applocker_findings = self._check_applocker()
        findings.extend(applocker_findings)

        # Add informational findings
        if computer_gpos or user_gpos or is_domain_joined:
            findings.append(
                Finding(
                    title="Group Policy status report",
                    description=(
                        f"Domain status: {'joined' if is_domain_joined else 'not joined'}. "
                        f"Computer GPOs: {len(computer_gpos)}. "
                        f"User GPOs: {len(user_gpos)}."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.win_group_policy_audit.status_report",
                    data={
                        "is_domain_joined": is_domain_joined,
                        "computer_gpos_count": len(computer_gpos),
                        "user_gpos_count": len(user_gpos),
                        "audit_policy_present": bool(audit_policy),
                    },
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            if finding.severity == Severity.WARNING:
                if "Stale domain Group Policies" in finding.title:
                    actions.append(
                        Action(
                            title="Remove stale Group Policies",
                            description=(
                                "Run `gpupdate /force` to refresh policies, or manually remove "
                                "stale GPO links in HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Group Policy\\History"
                            ),
                            risk_level=RiskLevel.MODERATE,
                            success=False,
                            error="Manual intervention required",
                            data={"gpos": finding.data},
                        )
                    )
                elif "disabled by policy" in finding.title:
                    actions.append(
                        Action(
                            title=f"Review or remove restrictive policy",
                            description=(
                                "This feature is disabled by Group Policy. Run `gpupdate /force` "
                                "after removing the GPO, or use 'Edit Group Policy' (gpedit.msc) "
                                "to modify the policy directly."
                            ),
                            risk_level=RiskLevel.MODERATE,
                            success=False,
                            error="Manual intervention required",
                            data=finding.data,
                        )
                    )
                elif "minimum length" in finding.title:
                    actions.append(
                        Action(
                            title="Increase password minimum length",
                            description=(
                                "Run `net accounts /minpwlen:<length>` (e.g., /minpwlen:14) "
                                "to set a stronger password policy."
                            ),
                            risk_level=RiskLevel.MODERATE,
                            success=False,
                            error="Manual intervention required",
                            data=finding.data,
                        )
                    )

        return FixResult(module_name=self.name, actions=actions)

    def _is_domain_joined(self) -> bool:
        """Check if the machine is domain-joined via WMI."""
        try:
            result = subprocess.run(
                [
                    "powershell",
                    "-NoProfile",
                    "-Command",
                    "(Get-WmiObject Win32_ComputerSystem).PartOfDomain",
                ],
                capture_output=True,
                text=True,
                timeout=5,
            )
            output = result.stdout.strip().lower()
            return output == "true"
        except (OSError, subprocess.SubprocessError, subprocess.TimeoutExpired):
            return False

    def _get_applied_gpos(self, scope: str) -> list[str]:
        """Get list of applied GPOs via gpresult."""
        try:
            result = subprocess.run(
                ["gpresult", "/r", f"/scope:{scope}"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            gpos = []
            for line in result.stdout.splitlines():
                # Look for lines with GPO names (usually indented and after "Applied")
                if "Applied Group Policy Objects" in line:
                    # Start capturing GPOs
                    lines = result.stdout.split("Applied Group Policy Objects")[1].split(
                        "The following"
                    )[0].splitlines()
                    for gpo_line in lines:
                        gpo = gpo_line.strip()
                        if gpo and not gpo.startswith("-"):
                            gpos.append(gpo)
            return gpos
        except (OSError, subprocess.SubprocessError, subprocess.TimeoutExpired):
            return []

    def _check_restrictive_policies(self) -> list[Finding]:
        """Check for restrictive policies that may indicate malware or issues."""
        findings = []
        restrictive_checks = [
            ("DisableCMD", "Command Prompt disabled by policy"),
            ("DisableTaskMgr", "Task Manager disabled by policy"),
            ("DisableRegistryTools", "Registry Editor disabled by policy"),
            ("NoControlPanel", "Control Panel disabled by policy"),
        ]

        for reg_name, policy_name in restrictive_checks:
            if self._check_registry_policy(reg_name):
                findings.append(
                    Finding(
                        title=f"{policy_name}",
                        description=(
                            f"{policy_name}. This may be a legitimate organizational policy "
                            "or a sign of malware/unauthorized changes. If unexpected, "
                            "investigate the Group Policy source."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        code="security.win_group_policy_audit.restrictive_policy",
                        data={"policy_name": policy_name, "registry_key": reg_name},
                    )
                )

        return findings

    def _check_registry_policy(self, policy_key: str) -> bool:
        """Check if a specific registry policy is set via PowerShell."""
        try:
            # Check both HKLM paths where these policies might be set
            paths = [
                f"HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System",
                f"HKLM:\\Software\\Policies\\Microsoft\\Windows\\System",
            ]
            for path in paths:
                result = subprocess.run(
                    [
                        "powershell",
                        "-NoProfile",
                        "-Command",
                        f"(Get-ItemProperty -Path '{path}' -Name '{policy_key}' -ErrorAction SilentlyContinue).{policy_key}",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                if result.stdout.strip() == "1":
                    return True
            return False
        except (OSError, subprocess.SubprocessError, subprocess.TimeoutExpired):
            return False

    def _check_password_policy(self) -> list[Finding]:
        """Check password policy via net accounts."""
        findings = []
        try:
            result = subprocess.run(
                ["net", "accounts"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            output = result.stdout

            # Parse minimum password length
            min_length = 0
            for line in output.splitlines():
                if "Minimum password length" in line:
                    parts = line.split()
                    if parts:
                        try:
                            min_length = int(parts[-1])
                        except ValueError:
                            pass

            # Flag if minimum length is less than 8
            if 0 < min_length < 8:
                findings.append(
                    Finding(
                        title=f"Weak password minimum length ({min_length} characters)",
                        description=(
                            f"Password minimum length is set to {min_length} characters. "
                            "Microsoft recommends at least 8 characters for security."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        code="security.win_group_policy_audit.weak_password_policy",
                        data={"min_length": min_length},
                    )
                )
        except (OSError, subprocess.SubprocessError, subprocess.TimeoutExpired):
            pass

        return findings

    def _get_audit_policy(self) -> dict:
        """Get audit policy settings via auditpol."""
        try:
            result = subprocess.run(
                ["auditpol", "/get", "/category:*"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            return {"present": result.returncode == 0, "output": result.stdout}
        except (OSError, subprocess.SubprocessError, subprocess.TimeoutExpired):
            return {"present": False, "output": ""}

    def _check_applocker(self) -> list[Finding]:
        """Check for AppLocker or software restriction policies."""
        findings = []
        try:
            result = subprocess.run(
                [
                    "powershell",
                    "-NoProfile",
                    "-Command",
                    "Get-AppLockerPolicy -Effective -Xml 2>/dev/null | Select-Object -ExpandProperty RuleCollections | Measure-Object | Select-Object -ExpandProperty Count",
                ],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.stdout.strip() and int(result.stdout.strip()) > 0:
                findings.append(
                    Finding(
                        title="AppLocker policies configured",
                        description=(
                            "This system has AppLocker policies configured. These may restrict "
                            "which applications can run. Check AppLocker event logs if issues arise."
                        ),
                        severity=Severity.INFO,
                        category=self.category,
                        code="security.win_group_policy_audit.applocker_configured",
                        data={"policy_type": "AppLocker"},
                    )
                )
        except (OSError, subprocess.SubprocessError, subprocess.TimeoutExpired, ValueError):
            pass

        return findings
