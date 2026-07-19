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
    name = "win_firewall_rules_audit"
    category = "security"
    platforms = [Platform.WIN32]
    risk_level = RiskLevel.SAFE
    priority = 65
    depends_on = []
    estimated_duration = "10s"

    emits_codes = [
        "security.win_firewall_rules_audit.default_inbound_allow",
        "security.win_firewall_rules_audit.rule_allows_all_programs",
        "security.win_firewall_rules_audit.rule_allows_all_ports",
        "security.win_firewall_rules_audit.excessive_rules",
        "security.win_firewall_rules_audit.summary",
    ]

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Get firewall profile status
        profile_output = self._run_powershell_profile_status()
        profiles = _parse_profile_status(profile_output)

        # Check for dangerous default inbound action
        for profile_name, settings in profiles.items():
            if settings.get("DefaultInboundAction") == "Allow":
                findings.append(
                    Finding(
                        title=f"{profile_name}: DefaultInboundAction set to Allow",
                        description=(
                            f"The {profile_name} has DefaultInboundAction set to Allow. "
                            "This is extremely dangerous and allows all unsolicited "
                            "inbound connections by default."
                        ),
                        severity=Severity.CRITICAL,
                        category=self.category,
                        code="security.win_firewall_rules_audit.default_inbound_allow",
                        data={
                            "profile_name": profile_name,
                            "setting_type": "default_inbound_action",
                        },
                    )
                )

        # Get inbound allow rules
        rules_output = self._run_powershell_inbound_rules()
        rules = _parse_inbound_rules(rules_output)

        # Check for overly permissive rules and count rules
        allow_all_program_rules = []
        allow_all_port_rules = []
        total_enabled_rules = len(rules)

        for rule in rules:
            rule_name = rule.get("DisplayName", "Unknown")
            program = rule.get("Program", "")
            ports = rule.get("LocalPort", "")

            # Check for rules allowing all programs
            if program and program.lower() == "any":
                allow_all_program_rules.append(rule_name)
                findings.append(
                    Finding(
                        title=f"Firewall rule allows all programs: {rule_name}",
                        description=(
                            f"The rule '{rule_name}' allows inbound traffic from any program. "
                            "This is overly permissive and could allow malware or unauthorized "
                            "applications to accept inbound connections."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        code="security.win_firewall_rules_audit.rule_allows_all_programs",
                        data={
                            "rule_name": rule_name,
                            "issue_type": "allow_all_programs",
                            "profile": rule.get("Profile", "Unknown"),
                        },
                    )
                )

            # Check for rules allowing all ports
            if ports and ports.lower() == "any":
                allow_all_port_rules.append(rule_name)
                if rule_name not in allow_all_program_rules:  # Avoid duplicate if both are "any"
                    findings.append(
                        Finding(
                            title=f"Firewall rule allows all ports: {rule_name}",
                            description=(
                                f"The rule '{rule_name}' allows inbound traffic on any port. "
                                "This is overly permissive and could expose multiple services "
                                "to unsolicited access."
                            ),
                            severity=Severity.WARNING,
                            category=self.category,
                            code="security.win_firewall_rules_audit.rule_allows_all_ports",
                            data={
                                "rule_name": rule_name,
                                "issue_type": "allow_all_ports",
                                "profile": rule.get("Profile", "Unknown"),
                            },
                        )
                    )

        # Check if total enabled inbound allow rules is excessive
        if total_enabled_rules > 100:
            findings.append(
                Finding(
                    title=f"Excessive enabled inbound allow rules ({total_enabled_rules})",
                    description=(
                        f"Found {total_enabled_rules} enabled inbound allow rules. "
                        "This is excessive and makes it difficult to audit which rules are necessary. "
                        "Review and consolidate rules where possible."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.win_firewall_rules_audit.excessive_rules",
                    data={
                        "rule_count": total_enabled_rules,
                        "issue_type": "excessive_rules",
                    },
                )
            )

        # Add informational finding with summary
        profile_summary = _format_profile_summary(profiles)
        rule_summary = (
            f"Total enabled inbound allow rules: {total_enabled_rules}. "
            f"Rules allowing all programs: {len(allow_all_program_rules)}. "
            f"Rules allowing all ports: {len(allow_all_port_rules)}."
        )
        findings.append(
            Finding(
                title="Windows Firewall Rules Audit Summary",
                description=f"{profile_summary}\n\n{rule_summary}",
                severity=Severity.INFO,
                category=self.category,
                code="security.win_firewall_rules_audit.summary",
                data={
                    "firewall_profiles": profiles,
                    "total_rules": total_enabled_rules,
                    "allow_all_program_count": len(allow_all_program_rules),
                    "allow_all_port_count": len(allow_all_port_rules),
                },
            )
        )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            if finding.severity == Severity.CRITICAL:
                actions.append(
                    Action(
                        title=f"Review dangerous firewall setting: {finding.title}",
                        description=(
                            "Open Windows Firewall with Advanced Security (wf.msc) and review "
                            "the firewall profile settings. Change DefaultInboundAction to Block "
                            "to prevent unsolicited inbound connections."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        data={"finding_data": finding.data},
                    )
                )
            elif finding.severity == Severity.WARNING:
                issue_type = finding.data.get("issue_type")
                if issue_type == "allow_all_programs":
                    actions.append(
                        Action(
                            title=f"Review and restrict rule: {finding.data.get('rule_name')}",
                            description=(
                                "Open Windows Firewall with Advanced Security (wf.msc). "
                                "Edit this rule to restrict it to specific programs or remove it "
                                "if no longer needed."
                            ),
                            risk_level=RiskLevel.SAFE,
                            success=True,
                            data={"rule_name": finding.data.get("rule_name")},
                        )
                    )
                elif issue_type == "allow_all_ports":
                    actions.append(
                        Action(
                            title=f"Review and restrict ports for rule: {finding.data.get('rule_name')}",
                            description=(
                                "Open Windows Firewall with Advanced Security (wf.msc). "
                                "Edit this rule to restrict it to specific ports or remove it "
                                "if no longer needed."
                            ),
                            risk_level=RiskLevel.SAFE,
                            success=True,
                            data={"rule_name": finding.data.get("rule_name")},
                        )
                    )
                elif issue_type == "excessive_rules":
                    actions.append(
                        Action(
                            title="Review and consolidate excessive inbound allow rules",
                            description=(
                                f"Found {finding.data.get('rule_count')} enabled inbound allow rules. "
                                "Open Windows Firewall with Advanced Security (wf.msc) and review "
                                "all rules. Consolidate or remove rules that are no longer needed. "
                                "Keep only rules that are actively in use."
                            ),
                            risk_level=RiskLevel.SAFE,
                            success=True,
                            data={"rule_count": finding.data.get("rule_count")},
                        )
                    )

        return FixResult(module_name=self.name, actions=actions)

    def _run_powershell_profile_status(self) -> str:
        """Get firewall profile status via PowerShell."""
        try:
            result = subprocess.run(
                [
                    "powershell",
                    "-NoProfile",
                    "-Command",
                    "Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction | ConvertTo-Json",
                ],
                capture_output=True,
                text=True,
            )
            return result.stdout
        except (OSError, subprocess.SubprocessError):
            return ""

    def _run_powershell_inbound_rules(self) -> str:
        """Get inbound allow rules via PowerShell."""
        try:
            result = subprocess.run(
                [
                    "powershell",
                    "-NoProfile",
                    "-Command",
                    "Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True | Select-Object DisplayName, Profile, Program | ConvertTo-Json",
                ],
                capture_output=True,
                text=True,
            )
            return result.stdout
        except (OSError, subprocess.SubprocessError):
            return ""


def _parse_profile_status(json_output: str) -> dict[str, dict[str, str]]:
    """Parse PowerShell JSON output for firewall profiles.

    Expected format (array of profile objects):
    [
        {
            "Name": "Domain",
            "Enabled": true,
            "DefaultInboundAction": "Block",
            "DefaultOutboundAction": "Allow"
        },
        ...
    ]
    """
    import json

    profiles = {}
    if not json_output.strip():
        return profiles

    try:
        data = json.loads(json_output)
        # Handle both single object and array of objects
        if isinstance(data, dict):
            data = [data]
        elif not isinstance(data, list):
            return profiles

        for profile in data:
            name = profile.get("Name", "Unknown")
            profiles[name] = {
                "Enabled": profile.get("Enabled", False),
                "DefaultInboundAction": profile.get("DefaultInboundAction", "Unknown"),
                "DefaultOutboundAction": profile.get("DefaultOutboundAction", "Unknown"),
            }
    except (json.JSONDecodeError, ValueError):
        pass

    return profiles


def _parse_inbound_rules(json_output: str) -> list[dict[str, str]]:
    """Parse PowerShell JSON output for inbound rules.

    Expected format (array of rule objects):
    [
        {
            "DisplayName": "Rule Name",
            "Profile": "Domain",
            "Program": "C:\\Program Files\\App\\app.exe" or "Any"
        },
        ...
    ]
    """
    import json

    rules = []
    if not json_output.strip():
        return rules

    try:
        data = json.loads(json_output)
        # Handle both single object and array of objects
        if isinstance(data, dict):
            data = [data]
        elif not isinstance(data, list):
            return rules

        for rule in data:
            rules.append(
                {
                    "DisplayName": rule.get("DisplayName", "Unknown"),
                    "Profile": rule.get("Profile", "Unknown"),
                    "Program": rule.get("Program", ""),
                    "LocalPort": rule.get("LocalPort", ""),
                }
            )
    except (json.JSONDecodeError, ValueError):
        pass

    return rules


def _format_profile_summary(profiles: dict[str, dict[str, str]]) -> str:
    """Format firewall profile status for display."""
    if not profiles:
        return "No firewall profile information available."

    lines = ["Firewall Profile Status:"]
    for name, settings in profiles.items():
        enabled = settings.get("Enabled", False)
        inbound = settings.get("DefaultInboundAction", "Unknown")
        outbound = settings.get("DefaultOutboundAction", "Unknown")
        status = "Enabled" if enabled else "Disabled"
        lines.append(
            f"  {name}: {status} | DefaultInbound: {inbound} | DefaultOutbound: {outbound}"
        )

    return "\n".join(lines)
