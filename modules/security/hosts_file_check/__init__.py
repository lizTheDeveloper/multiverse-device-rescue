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

    emits_codes = [
        "security.hosts_file_check.clean_hosts",
        "security.hosts_file_check.large_hosts_count",
        "security.hosts_file_check.suspicious_ip_redirect",
        "security.hosts_file_check.wellknown_domain_redirect",
        "security.hosts_file_check.bank_domain_redirect",
        "security.hosts_file_check.custom_entries_list",
    ]

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
                    code="security.hosts_file_check.clean_hosts",
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
                    title=f"Your computer has {len(entries)} extra website address overrides",
                    description=(
                        "Your computer's address book (a file called /etc/hosts) has "
                        f"{len(entries)} extra entries. This file usually only has a few "
                        "lines. A large number of entries often comes from ad-blocking "
                        "apps, but it can also be a sign that something is blocking or "
                        "redirecting your internet traffic. This is not proof of a problem, "
                        "but it is worth checking.\n\n"
                        "What to do: Open the file in a text editor to see what is listed. "
                        "On Mac, open Terminal and type: cat /etc/hosts. If you see names "
                        "of apps you installed (like ad blockers), it is likely fine. "
                        "If you see names you don't recognize, especially for banking "
                        "or email, ask for help."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.hosts_file_check.large_hosts_count",
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
                    title=(
                        "1 website name is being redirected to an unusual address"
                        if len(suspicious_entries) == 1
                        else f"{len(suspicious_entries)} website names are being redirected "
                        "to unusual addresses"
                    ),
                    description=(
                        "Your computer's address book (/etc/hosts) has entries that send "
                        "website names to addresses other than your own computer. "
                        + ("Here it is: " if len(suspicious_entries) == 1 else f"Here are {min(len(suspicious_entries), 5)} of them: ")
                        + f"{', '.join(e['ip'] + ' ' + e['hostname'] for e in suspicious_entries[:5])}{'...' if len(suspicious_entries) > 5 else ''}. "
                        "Many apps (like VPNs, Adobe, or ad blockers) do this automatically, "
                        "so this is not proof of spying or malware. However, if you see "
                        "a bank, email, or software update site here that you did not "
                        "add, it is a warning sign.\n\n"
                        "What to do: Check the list above. If you recognize the apps, "
                        "you can ignore this. If you see a site you don't recognize, "
                        "especially for banking or email, back up your data and ask a "
                        "trusted tech person to help you remove the entry."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.hosts_file_check.suspicious_ip_redirect",
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
                    title=(
                        f"Major websites like {', '.join([e['hostname'] for e in wellknown_redirects[:3]])} "
                        "are being redirected"
                    ),
                    description=(
                        f"We found {len(wellknown_redirects)} entries in your address "
                        f"book that redirect major websites (like {', '.join([e['hostname'] for e in wellknown_redirects[:3]])}{'...' if len(wellknown_redirects) > 3 else ''}) "
                        "to unusual addresses. This is more concerning than a simple "
                        "ad-blocker. It could mean an app is trying to block these sites, "
                        "or it could be a sign of malware. It is not proof of a hack, "
                        "but you should check it.\n\n"
                        "What to do: Open the file /etc/hosts in a text editor. Look "
                        "for the names listed above. If you don't recognize why they "
                        "are there, back up your data and ask a trusted tech person to "
                        "help you remove those specific lines."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.hosts_file_check.wellknown_domain_redirect",
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
                    title=(
                        f"Banking sites like {', '.join([e['hostname'] for e in bank_redirects])} "
                        "are being redirected"
                    ),
                    description=(
                        f"We found {len(bank_redirects)} entries in your address book "
                        f"that redirect banking websites ({', '.join([e['hostname'] for e in bank_redirects])}) "
                        "to unusual addresses. This is a serious warning sign. It could "
                        "mean an app is blocking your bank, or it could be malware trying "
                        "to trick you into entering your password on a fake site. Do "
                        "not ignore this.\n\n"
                        "What to do: Stop using your bank website on this computer until "
                        "you check it. Open the file /etc/hosts in a text editor and "
                        "look for these names. If you did not add them, back up your "
                        "data and ask a trusted tech person to help you remove them immediately."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
                    code="security.hosts_file_check.bank_domain_redirect",
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
                    title=(
                        "A custom hosts entry found"
                        if len(entries) == 1
                        else f"{len(entries)} custom hosts entries found"
                    ),
                    description=(
                        f"The hosts file contains {len(entries)} custom entries. "
                        f"First few: {', '.join([e['hostname'] for e in entries[:5]])}"
                        f"{'...' if len(entries) > 5 else ''}"
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.hosts_file_check.custom_entries_list",
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
