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

# Sensitive service keywords to detect Generic-type credentials to sensitive services
SENSITIVE_SERVICES = {
    "microsoft.com",
    "office.com",
    "outlook.com",
    "onedrive",
    "teams",
    "sharepoint",
    "azure",
    "github.com",
    "gitlab.com",
    "bitbucket.org",
    "aws.amazon.com",
    "console.aws.amazon.com",
    "gcp",
    "cloud.google.com",
    "dropbox",
    "box.com",
    "vault",
    "lastpass",
    "1password",
    "ssh",
    "vpn",
}


class Module(ModuleBase):
    name = "win_credential_manager_audit"
    category = "security"
    platforms = [Platform.WIN32]
    risk_level = RiskLevel.SAFE
    priority = 55
    depends_on = []
    estimated_duration = "5s"

    emits_codes = [
        "security.win_credential_manager_audit.credential_sprawl",
        "security.win_credential_manager_audit.domain_credentials_non_domain_joined",
        "security.win_credential_manager_audit.generic_credentials_sensitive_services",
        "security.win_credential_manager_audit.inventory_summary",
    ]

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Get stored credentials
        creds_output = self._run_cmdkey_list()
        credentials = _parse_cmdkey_output(creds_output)

        # Check if domain joined
        is_domain_joined = self._is_domain_joined()

        # Analyze credentials
        total_count = len(credentials)
        cred_types = {}
        generic_sensitive_creds = []
        domain_type_creds = []
        service_summary = {}

        for cred in credentials:
            cred_type = cred.get("type", "Unknown")
            target = cred.get("target", "")

            # Count by type
            cred_types[cred_type] = cred_types.get(cred_type, 0) + 1

            # Extract service name for summary
            service = self._extract_service_name(target)
            if service:
                service_summary[service] = service_summary.get(service, 0) + 1

            # Check for generic credentials to sensitive services
            if cred_type == "Generic" and self._is_sensitive_service(target):
                generic_sensitive_creds.append(
                    {
                        "target": target,
                        "user": cred.get("user", "Unknown"),
                    }
                )

            # Check for domain password credentials
            if cred_type == "Domain Password":
                domain_type_creds.append(
                    {
                        "target": target,
                        "user": cred.get("user", "Unknown"),
                    }
                )

        # WARNING: Total credential count > 50 (credential sprawl)
        if total_count > 50:
            findings.append(
                Finding(
                    title="Excessive stored credentials (credential sprawl)",
                    description=(
                        f"Found {total_count} stored credentials in Windows Credential Manager. "
                        "This suggests credential sprawl where old credentials accumulate over time. "
                        "Old or unused credentials should be regularly reviewed and deleted to reduce "
                        "the attack surface."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.win_credential_manager_audit.credential_sprawl",
                    data={"credential_count": total_count},
                )
            )

        # WARNING: Domain credentials on non-domain-joined machine
        if domain_type_creds and not is_domain_joined:
            findings.append(
                Finding(
                    title="Domain credentials on non-domain-joined machine",
                    description=(
                        f"Found {len(domain_type_creds)} cached domain credentials on a machine that is not "
                        "currently domain-joined. These are likely stale credentials from a previous domain "
                        "membership or cached from a remote session. They should be reviewed and removed if no "
                        "longer needed."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.win_credential_manager_audit.domain_credentials_non_domain_joined",
                    data={
                        "domain_credential_count": len(domain_type_creds),
                        "domain_credentials": domain_type_creds,
                    },
                )
            )

        # WARNING: Generic credentials to sensitive services
        if generic_sensitive_creds:
            findings.append(
                Finding(
                    title="Generic credentials stored for sensitive services",
                    description=(
                        f"Found {len(generic_sensitive_creds)} credentials stored as Generic type for "
                        "sensitive services. Generic type credentials are less secure than Domain Password "
                        "type credentials. Consider migrating to more secure credential types where possible, "
                        "or using credential managers with better encryption."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.win_credential_manager_audit.generic_credentials_sensitive_services",
                    data={
                        "generic_sensitive_count": len(generic_sensitive_creds),
                        "credentials": generic_sensitive_creds,
                    },
                )
            )

        # INFO: Summary of credential inventory
        inventory_summary = self._format_inventory_summary(
            total_count, cred_types, service_summary, is_domain_joined
        )
        findings.append(
            Finding(
                title="Windows Credential Manager Inventory Summary",
                description=inventory_summary,
                severity=Severity.INFO,
                category=self.category,
                code="security.win_credential_manager_audit.inventory_summary",
                data={
                    "total_credentials": total_count,
                    "by_type": cred_types,
                    "by_service": service_summary,
                    "is_domain_joined": is_domain_joined,
                },
            )
        )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            if finding.severity == Severity.WARNING:
                title = finding.title
                if "credential sprawl" in title.lower():
                    actions.append(
                        Action(
                            title="Review and clean up stored credentials",
                            description=(
                                f"Found {finding.data.get('credential_count', '?')} stored credentials. "
                                "Open Credential Manager (Win+R, then 'credential manager') and review all "
                                "stored credentials. Delete any credentials for services no longer in use, "
                                "old accounts, or archived projects. Keep the system clean by regularly "
                                "removing stale credentials."
                            ),
                            risk_level=RiskLevel.SAFE,
                            success=True,
                            data={"issue_type": "credential_sprawl"},
                        )
                    )
                elif "domain credentials" in title.lower():
                    actions.append(
                        Action(
                            title="Review cached domain credentials",
                            description=(
                                f"Found {finding.data.get('domain_credential_count', '?')} cached domain credentials "
                                "on a machine that is not domain-joined. Open Credential Manager and review these "
                                "credentials. Delete domain credentials from previous domain memberships or "
                                "archived infrastructure that is no longer in use."
                            ),
                            risk_level=RiskLevel.SAFE,
                            success=True,
                            data={"issue_type": "domain_credentials"},
                        )
                    )
                elif "generic credentials" in title.lower():
                    actions.append(
                        Action(
                            title="Review and secure generic credentials",
                            description=(
                                f"Found {finding.data.get('generic_sensitive_count', '?')} credentials stored as "
                                "Generic type for sensitive services. Open Credential Manager and review these "
                                "credentials. Where possible, upgrade to Domain Password type credentials or "
                                "use application-specific tokens/API keys instead of generic credentials for "
                                "sensitive services."
                            ),
                            risk_level=RiskLevel.SAFE,
                            success=True,
                            data={"issue_type": "generic_credentials"},
                        )
                    )

        return FixResult(module_name=self.name, actions=actions)

    def _run_cmdkey_list(self) -> str:
        """Get stored credentials via cmdkey /list."""
        try:
            result = subprocess.run(
                ["cmdkey", "/list"],
                capture_output=True,
                text=True,
            )
            return result.stdout
        except (OSError, subprocess.SubprocessError):
            return ""

    def _is_domain_joined(self) -> bool:
        """Check if machine is domain-joined via wmic."""
        try:
            result = subprocess.run(
                ["wmic", "computersystem", "get", "partofdomain"],
                capture_output=True,
                text=True,
            )
            output = result.stdout.strip()
            # Output looks like "PartOfDomain\nTRUE" or "PartOfDomain\nFALSE"
            lines = output.splitlines()
            if len(lines) > 1:
                return lines[1].strip().upper() == "TRUE"
            return False
        except (OSError, subprocess.SubprocessError):
            return False

    def _extract_service_name(self, target: str) -> str:
        """Extract service name from target string."""
        # Remove prefixes like "Domain:target=" or "LegacyGeneric:target="
        if ":target=" in target:
            target = target.split(":target=", 1)[1]

        # Extract domain or service name
        if target.startswith("http"):
            # Extract domain from URL
            try:
                from urllib.parse import urlparse

                parsed = urlparse(target)
                return parsed.netloc or target
            except (ImportError, ValueError):
                return target
        elif "@" in target:
            # Extract domain from email
            return target.split("@")[1]
        else:
            # Return first part before slash or domain
            return target.split("/")[0]

    def _is_sensitive_service(self, target: str) -> bool:
        """Check if target contains a sensitive service keyword."""
        target_lower = target.lower()
        return any(service in target_lower for service in SENSITIVE_SERVICES)

    def _format_inventory_summary(
        self, total: int, by_type: dict, by_service: dict, is_domain_joined: bool
    ) -> str:
        """Format credential inventory for display."""
        lines = [
            f"Total stored credentials: {total}",
            f"Domain-joined: {'Yes' if is_domain_joined else 'No'}",
            "",
            "Credentials by type:",
        ]

        for cred_type, count in sorted(by_type.items()):
            lines.append(f"  {cred_type}: {count}")

        if by_service:
            lines.append("")
            lines.append("Credentials by service (top services):")
            # Show top 10 services by count
            top_services = sorted(by_service.items(), key=lambda x: x[1], reverse=True)[
                :10
            ]
            for service, count in top_services:
                lines.append(f"  {service}: {count}")
            if len(by_service) > 10:
                lines.append(f"  ... and {len(by_service) - 10} more services")

        return "\n".join(lines)


def _parse_cmdkey_output(output: str) -> list[dict[str, str]]:
    """Parse `cmdkey /list` output.

    Example output::

        Currently stored credentials:

        Target: Domain:target=example.com
        Type: Domain Password
        User: DOMAIN\\username

        Target: LegacyGeneric:target=https://github.com
        Type: Generic
        User: github_user

        Target: WindowsLive:target=https://outlook.com
        Type: Generic
        User: user@outlook.com
    """
    credentials = []
    current_cred = {}

    for line in output.splitlines():
        stripped = line.strip()

        if not stripped or stripped == "Currently stored credentials:":
            # Save previous credential if exists
            if current_cred.get("target") and current_cred.get("type"):
                credentials.append(current_cred)
            current_cred = {}
            continue

        if stripped.startswith("Target:"):
            if current_cred.get("target") and current_cred.get("type"):
                credentials.append(current_cred)
            current_cred = {}
            current_cred["target"] = stripped[len("Target:") :].strip()

        elif stripped.startswith("Type:"):
            current_cred["type"] = stripped[len("Type:") :].strip()

        elif stripped.startswith("User:"):
            current_cred["user"] = stripped[len("User:") :].strip()

    # Don't forget the last credential
    if current_cred.get("target") and current_cred.get("type"):
        credentials.append(current_cred)

    return credentials
