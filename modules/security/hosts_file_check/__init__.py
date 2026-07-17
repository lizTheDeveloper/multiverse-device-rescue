from pathlib import Path
from collections import defaultdict

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


# Well-known domains that should point to legitimate IPs
WELL_KNOWN_DOMAINS = {
    "google.com",
    "gmail.com",
    "youtube.com",
    "facebook.com",
    "instagram.com",
    "twitter.com",
    "linkedin.com",
    "github.com",
    "amazon.com",
    "apple.com",
    "microsoft.com",
    "paypal.com",
    "bank.com",
    "banking.com",
}

# Bank domains (sensitive)
BANK_DOMAINS = {
    "paypal.com",
    "banking.com",
    "bank.com",
    "chase.com",
    "bofa.com",
    "wellsfargo.com",
    "citibank.com",
    "bankofamerica.com",
}

# Safe redirection IPs
SAFE_REDIRECT_IPS = {"127.0.0.1", "0.0.0.0", "::1"}


class Module(ModuleBase):
    name = "hosts_file_check"
    category = "security"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "1s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        try:
            hosts_path = Path("/etc/hosts")
            if not hosts_path.exists():
                return CheckResult(module_name=self.name, findings=[])

            content = hosts_path.read_text()
        except (OSError, PermissionError):
            return CheckResult(module_name=self.name, findings=[])

        entries = self._parse_hosts_file(content)

        if not entries:
            findings.append(
                Finding(
                    title="Hosts file is clean",
                    description="The /etc/hosts file contains only default localhost and broadcasthost entries.",
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "clean_hosts"},
                )
            )
            return CheckResult(module_name=self.name, findings=findings)

        # Check for suspicious IPs (not loopback or safe redirects)
        suspicious_entries = []
        for entry in entries:
            ip = entry["ip"]
            if ip not in SAFE_REDIRECT_IPS:
                suspicious_entries.append(entry)

        # Flag if many custom entries (could be ad-blocker but worth noting)
        if len(entries) > 20:
            findings.append(
                Finding(
                    title=f"Large number of custom hosts entries ({len(entries)})",
                    description=(
                        f"The /etc/hosts file contains {len(entries)} custom entries. "
                        f"While this could be an ad-blocker configuration, a large number of entries "
                        f"could indicate malware or system compromise."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "check": "large_hosts_count",
                        "count": len(entries),
                    },
                )
            )

        # Flag suspicious IP redirections
        if suspicious_entries:
            findings.append(
                Finding(
                    title=f"Found {len(suspicious_entries)} entries redirecting to non-standard IPs",
                    description=(
                        f"The hosts file contains entries redirecting to IPs other than 127.0.0.1 or 0.0.0.0. "
                        f"This is suspicious and could indicate malware redirecting traffic. "
                        f"Entries: {', '.join([e['hostname'] for e in suspicious_entries[:5]])}"
                        f"{'...' if len(suspicious_entries) > 5 else ''}"
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "check": "suspicious_ip_redirect",
                        "count": len(suspicious_entries),
                        "entries": suspicious_entries,
                    },
                )
            )

        # Check for well-known domains with suspicious redirects
        wellknown_redirects = [
            e
            for e in suspicious_entries
            if e["hostname"] in WELL_KNOWN_DOMAINS or any(
                e["hostname"].endswith("." + d) for d in WELL_KNOWN_DOMAINS
            )
        ]

        if wellknown_redirects:
            findings.append(
                Finding(
                    title=f"Well-known domains redirected to suspicious IPs",
                    description=(
                        f"Found {len(wellknown_redirects)} well-known domains "
                        f"(e.g., google.com, facebook.com) redirected to non-standard IPs. "
                        f"This could indicate malware: {', '.join([e['hostname'] for e in wellknown_redirects[:3]])}"
                        f"{'...' if len(wellknown_redirects) > 3 else ''}"
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "check": "wellknown_domain_redirect",
                        "count": len(wellknown_redirects),
                        "entries": wellknown_redirects,
                    },
                )
            )

        # Check for bank domains redirected
        bank_redirects = [
            e
            for e in suspicious_entries
            if e["hostname"] in BANK_DOMAINS or any(
                e["hostname"].endswith("." + d) for d in BANK_DOMAINS
            )
        ]

        if bank_redirects:
            findings.append(
                Finding(
                    title="Banking websites redirected to suspicious IPs",
                    description=(
                        f"Found {len(bank_redirects)} banking domain(s) redirected to non-standard IPs. "
                        f"This is a critical security issue: {', '.join([e['hostname'] for e in bank_redirects])}"
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
                    data={
                        "check": "bank_domain_redirect",
                        "count": len(bank_redirects),
                        "entries": bank_redirects,
                    },
                )
            )

        # List all custom entries as info
        if entries:
            findings.append(
                Finding(
                    title=f"Custom hosts entries found ({len(entries)})",
                    description=(
                        f"The hosts file contains {len(entries)} custom entries. "
                        f"First few: {', '.join([e['hostname'] for e in entries[:5]])}"
                        f"{'...' if len(entries) > 5 else ''}"
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "check": "custom_entries_list",
                        "count": len(entries),
                        "entries": entries,
                    },
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        """Provide guidance on reviewing and cleaning hosts file (informational only)."""
        actions = []

        for finding in findings.findings:
            check_type = finding.data.get("check")

            if check_type == "clean_hosts":
                # No action needed for clean hosts
                continue
            elif check_type == "large_hosts_count":
                count = finding.data.get("count")
                actions.append(
                    Action(
                        title="Review large hosts file",
                        description=(
                            f"Your hosts file contains {count} custom entries. "
                            f"Review /etc/hosts to ensure these are legitimate (e.g., ad-blocker rules) "
                            f"and not malware entries. Use: sudo nano /etc/hosts"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif check_type == "suspicious_ip_redirect":
                count = finding.data.get("count")
                entries = finding.data.get("entries", [])
                actions.append(
                    Action(
                        title="Review suspicious IP redirections",
                        description=(
                            f"Found {count} entries redirecting to non-standard IPs. "
                            f"Example IPs: {set(e['ip'] for e in entries[:3])}. "
                            f"Review and remove any entries not matching 127.0.0.1 or 0.0.0.0 unless intentional. "
                            f"Edit: sudo nano /etc/hosts"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif check_type == "wellknown_domain_redirect":
                count = finding.data.get("count")
                entries = finding.data.get("entries", [])
                domains = [e["hostname"] for e in entries[:5]]
                actions.append(
                    Action(
                        title="Remove well-known domain redirections",
                        description=(
                            f"Found {count} well-known domains redirected to suspicious IPs: {', '.join(domains)}. "
                            f"These entries are likely malicious. Remove them from /etc/hosts. "
                            f"Edit: sudo nano /etc/hosts"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif check_type == "bank_domain_redirect":
                count = finding.data.get("count")
                entries = finding.data.get("entries", [])
                domains = [e["hostname"] for e in entries]
                actions.append(
                    Action(
                        title="URGENT: Remove banking domain redirections",
                        description=(
                            f"CRITICAL: Found {count} banking domain(s) redirected to suspicious IPs: {', '.join(domains)}. "
                            f"This is a phishing/hijacking attempt. Remove immediately from /etc/hosts. "
                            f"Edit: sudo nano /etc/hosts"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif check_type == "custom_entries_list":
                # Already covered by other findings
                continue

        return FixResult(module_name=self.name, actions=actions)

    def _parse_hosts_file(self, content: str) -> list[dict]:
        """Parse /etc/hosts file, return list of custom entries (non-default)."""
        entries = []
        default_hosts = {"localhost", "broadcasthost", "localhost.localdomain"}

        for line in content.split("\n"):
            # Remove comments
            if "#" in line:
                line = line[: line.index("#")]

            line = line.strip()
            if not line:
                continue

            parts = line.split()
            if len(parts) < 2:
                continue

            ip = parts[0]
            hostnames = parts[1:]

            for hostname in hostnames:
                # Skip default entries
                if hostname in default_hosts:
                    continue

                entries.append(
                    {
                        "ip": ip,
                        "hostname": hostname,
                    }
                )

        return entries
