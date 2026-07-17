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

# Security/banking domains that should not be redirected
SECURITY_BANKING_DOMAINS = {
    "microsoft.com",
    "windows.com",
    "google.com",
    "paypal.com",
    "apple.com",
    "amazon.com",
    "facebook.com",
    "twitter.com",
    "linkedin.com",
    "github.com",
    "chase.com",
    "wellsfargo.com",
    "bankofamerica.com",
}

# Localhost IPs - safe redirects
LOCALHOST_IPS = {"127.0.0.1", "::1", "localhost", "0.0.0.0"}


class Module(ModuleBase):
    name = "win_hosts_file"
    category = "security"
    platforms = [Platform.WIN32]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "3s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []
        hosts_content = self._read_hosts_file()
        if not hosts_content:
            return CheckResult(module_name=self.name, findings=findings)

        entries = _parse_hosts_file(hosts_content)
        if not entries:
            return CheckResult(module_name=self.name, findings=findings)

        # Check for banking/security domain redirects to non-localhost
        critical_redirects = _find_security_domain_redirects(entries)
        if critical_redirects:
            findings.append(
                Finding(
                    title="Security/banking domains redirected in hosts file",
                    description=(
                        f"The following security or banking domains are redirected "
                        f"to non-localhost IPs in the hosts file: {', '.join(critical_redirects)}. "
                        f"This may indicate malware attempting to redirect financial "
                        f"transactions or security services."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
                    data={"redirects": critical_redirects},
                )
            )

        # Check for excessive entries
        if len(entries) > 50:
            findings.append(
                Finding(
                    title=f"Hosts file has {len(entries)} entries (possible adware)",
                    description=(
                        f"The hosts file contains {len(entries)} entries. "
                        f"A large number of custom entries may indicate adware or "
                        f"ad-blocking software in conflict, or a malware infection."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"entry_count": len(entries)},
                )
            )

        # Info: report entry count and custom entries
        custom_entries = _get_custom_entries(entries)
        if custom_entries or entries:
            findings.append(
                Finding(
                    title=f"Hosts file contains {len(entries)} entries",
                    description=(
                        f"The hosts file has {len(entries)} total entries. "
                        f"Review any custom entries to ensure they are intentional."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "entry_count": len(entries),
                        "custom_entries": custom_entries[:10],  # Limit to first 10 for display
                    },
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            if finding.severity == Severity.CRITICAL:
                title = "Review and clean hosts file for malware"
                description = (
                    "Manually review the hosts file at "
                    "C:\\Windows\\System32\\drivers\\etc\\hosts and remove any "
                    "suspicious entries. Redirect to non-localhost IPs for security "
                    "or banking domains is a common malware tactic."
                )
            elif finding.severity == Severity.WARNING:
                title = "Review hosts file for excessive entries"
                description = (
                    "The hosts file has a large number of entries. Review "
                    "C:\\Windows\\System32\\drivers\\etc\\hosts and remove any "
                    "unnecessary entries. Use caution when removing entries for "
                    "known ad-blocking services."
                )
            elif finding.severity == Severity.INFO:
                title = "Review hosts file entries"
                description = (
                    "Review the hosts file at "
                    "C:\\Windows\\System32\\drivers\\etc\\hosts to ensure all "
                    "entries are intentional."
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

    def _read_hosts_file(self) -> str:
        try:
            result = subprocess.run(
                [
                    "powershell",
                    "-NoProfile",
                    "-Command",
                    "Get-Content $env:windir\\System32\\drivers\\etc\\hosts",
                ],
                capture_output=True,
                text=True,
            )
            return result.stdout
        except (OSError, subprocess.SubprocessError):
            return ""


def _parse_hosts_file(content: str) -> list[dict]:
    """Parse hosts file content into IP/domain pairs.

    Args:
        content: Raw content of hosts file

    Returns:
        List of dicts with 'ip' and 'domains' keys
    """
    entries = []
    for line in content.splitlines():
        line = line.strip()
        # Skip empty lines and comments
        if not line or line.startswith("#"):
            continue

        parts = line.split()
        if len(parts) < 2:
            continue

        ip = parts[0]
        domains = parts[1:]

        entries.append({"ip": ip, "domains": domains})

    return entries


def _find_security_domain_redirects(entries: list[dict]) -> list[str]:
    """Find security/banking domains redirected to non-localhost IPs.

    Args:
        entries: List of hosts file entries

    Returns:
        List of security/banking domains that are redirected suspiciously
    """
    redirects = []
    for entry in entries:
        ip = entry["ip"].lower()
        # Skip localhost IPs
        if ip in LOCALHOST_IPS or ip.startswith("::1") or ip.startswith("127."):
            continue

        domains = entry["domains"]
        for domain in domains:
            domain_lower = domain.lower()
            # Check if domain or its base matches security/banking domains
            if domain_lower in SECURITY_BANKING_DOMAINS:
                redirects.append(domain)
            # Check for domain variations (subdomains)
            for sec_domain in SECURITY_BANKING_DOMAINS:
                if domain_lower == sec_domain or domain_lower.endswith("." + sec_domain):
                    if domain not in redirects:
                        redirects.append(domain)
                    break

    return redirects


def _get_custom_entries(entries: list[dict]) -> list[str]:
    """Get custom hosts file entries (non-localhost).

    Args:
        entries: List of hosts file entries

    Returns:
        List of custom entries as formatted strings
    """
    custom = []
    for entry in entries:
        ip = entry["ip"].lower()
        # Only report non-localhost entries
        if ip not in LOCALHOST_IPS and not ip.startswith("::1") and not ip.startswith("127."):
            for domain in entry["domains"]:
                custom.append(f"{entry['ip']} -> {domain}")

    return custom
