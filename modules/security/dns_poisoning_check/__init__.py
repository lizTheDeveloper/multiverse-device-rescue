import subprocess
import re
from typing import Optional

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


# Known legitimate/standard public DNS servers
KNOWN_GOOD_DNS = {
    "8.8.8.8": "Google DNS",
    "8.8.4.4": "Google DNS",
    "1.1.1.1": "Cloudflare DNS",
    "1.0.0.1": "Cloudflare DNS",
    "9.9.9.9": "Quad9 DNS",
    "149.112.112.112": "Quad9 DNS",
    "208.67.222.222": "OpenDNS",
    "208.67.220.220": "OpenDNS",
}

# Known malicious/sinkhole DNS servers
MALICIOUS_DNS = {
    "0.0.0.0": "Null route",
    "127.0.0.1": "Localhost sinkhole",
}

# Expected IP ranges for major domains (simplified - just check they're not obviously wrong)
EXPECTED_DOMAINS = {
    "apple.com": ["17.", "104."],  # Apple IP blocks
    "google.com": ["142.", "172.", "216."],  # Google IP blocks
    "microsoft.com": ["13.", "40.", "204."],  # Microsoft IP blocks
}


class Module(ModuleBase):
    name = "dns_poisoning_check"
    category = "security"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "3s"

    emits_codes = [
        "security.dns_poisoning_check.malicious_dns",
        "security.dns_poisoning_check.suspicious_dns",
        "security.dns_poisoning_check.dns_resolution_issue",
        "security.dns_poisoning_check.dns_config",
        "security.dns_poisoning_check.dns_over_https",
    ]

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Check 1: Get configured DNS servers
        dns_servers = self._get_configured_dns()

        if dns_servers:
            findings.extend(self._check_dns_servers(dns_servers))
        else:
            findings.append(
                Finding(
                    title="DNS configuration check",
                    description="Could not retrieve DNS configuration from system.",
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.dns_poisoning_check.dns_config",
                    data={"check": "dns_config", "dns_servers": []},
                )
            )

        # Check 2: Verify DNS resolution for known domains
        resolution_issues = self._check_dns_resolution()
        findings.extend(resolution_issues)

        # Check 3: Check for DNS-over-HTTPS
        doh_info = self._check_dns_over_https()
        if doh_info:
            findings.append(doh_info)

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        for finding in findings.findings:
            check = finding.data.get("check")

            if check == "malicious_dns":
                servers = finding.data.get("servers", [])
                actions.append(
                    Action(
                        title="Reset DNS to automatic/default",
                        description=(
                            f"Malicious DNS servers detected: {', '.join(servers)}.\n"
                            "To reset DNS to automatic configuration:\n"
                            "1. Open System Settings > Network\n"
                            "2. Select your Wi-Fi network and click Details\n"
                            "3. Go to DNS tab\n"
                            "4. Click the minus (-) button to remove custom DNS entries\n"
                            "5. Set DNS to 'Automatic' or leave empty for DHCP defaults"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )

            elif check == "suspicious_dns":
                servers = finding.data.get("servers", [])
                actions.append(
                    Action(
                        title="Review and reset suspicious DNS servers",
                        description=(
                            f"Suspicious non-standard DNS servers configured: {', '.join(servers)}.\n"
                            "Review if these are intentional. To reset:\n"
                            "1. Open System Settings > Network\n"
                            "2. Select your network and click Details\n"
                            "3. Go to DNS tab\n"
                            "4. Remove custom entries or verify they're from a trusted source\n"
                            "Consider using known-good DNS like 8.8.8.8 or 1.1.1.1 if needed"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )

            elif check == "dns_resolution_issue":
                domain = finding.data.get("domain", "")
                actions.append(
                    Action(
                        title=f"Investigate unexpected resolution for {domain}",
                        description=(
                            f"Domain {domain} resolved to an unexpected IP address.\n"
                            "This could indicate DNS hijacking or redirection.\n"
                            "Try:\n"
                            "1. Test resolution with: dig {domain} @8.8.8.8\n"
                            "2. Check your DNS settings in System Settings > Network\n"
                            "3. If issue persists, reset DNS to automatic\n"
                            "4. Flush DNS cache: sudo dscacheutil -flushcache"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )

            elif check == "dns_config":
                actions.append(
                    Action(
                        title="Manual DNS configuration review",
                        description=(
                            "Could not automatically retrieve DNS configuration.\n"
                            "To review DNS settings:\n"
                            "1. Open System Settings > Network\n"
                            "2. Select your network and click Details\n"
                            "3. Check the DNS tab for configured servers\n"
                            "4. Verify they are from a trusted source\n"
                            "5. For command-line check: scutil --dns"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _get_configured_dns(self) -> list[str]:
        """Get DNS servers from network configuration.

        Returns list of configured DNS server IPs.
        Returns empty list on any failure.
        """
        dns_servers = []

        # Try scutil --dns first (more reliable)
        try:
            result = subprocess.run(
                ["scutil", "--dns"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                # Parse scutil output for nameserver entries
                for line in result.stdout.split("\n"):
                    if "nameserver" in line.lower():
                        # Extract IP from lines like "  nameserver[0] : 192.168.1.1"
                        parts = line.split(":")
                        if len(parts) >= 2:
                            ip = parts[1].strip()
                            if ip and ip not in dns_servers:
                                dns_servers.append(ip)
        except Exception:
            pass

        # Fallback: try networksetup
        if not dns_servers:
            try:
                result = subprocess.run(
                    ["networksetup", "-getdnsservers", "Wi-Fi"],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                if result.returncode == 0 and result.stdout.strip() != "There aren't any DNS Servers set on Wi-Fi.":
                    for line in result.stdout.strip().split("\n"):
                        ip = line.strip()
                        if ip and ip not in dns_servers:
                            dns_servers.append(ip)
            except Exception:
                pass

        return dns_servers

    def _check_dns_servers(self, dns_servers: list[str]) -> list[Finding]:
        """Check configured DNS servers for malicious/suspicious entries.

        Returns list of findings.
        """
        findings = []
        malicious = []
        suspicious = []

        for server in dns_servers:
            # Check for malicious servers
            if server in MALICIOUS_DNS:
                malicious.append(server)
            # Check if it's not a known-good server
            elif server not in KNOWN_GOOD_DNS:
                # Check if it looks like a valid IP (not ISP DNS, localhost, etc)
                if not self._is_isp_dns(server) and server not in ["127.0.0.1", "::1"]:
                    suspicious.append(server)

        if malicious:
            findings.append(
                Finding(
                    title=f"CRITICAL: Malicious DNS server(s) detected",
                    description=(
                        f"The following malicious/sinkhole DNS servers are configured: {', '.join(malicious)}. "
                        "This is a strong indicator of DNS poisoning/hijacking. "
                        "Your traffic may be being redirected through attacker-controlled servers. "
                        "Reset DNS to automatic or use a known-good public DNS immediately."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
                    code="security.dns_poisoning_check.malicious_dns",
                    data={"check": "malicious_dns", "servers": malicious},
                )
            )

        if suspicious:
            findings.append(
                Finding(
                    title=f"WARNING: Non-standard DNS server(s) configured",
                    description=(
                        f"Non-standard DNS servers are configured: {', '.join(suspicious)}. "
                        "These do not appear to be from known public DNS providers. "
                        "Verify these are from a trusted source and not from malware."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.dns_poisoning_check.suspicious_dns",
                    data={"check": "suspicious_dns", "servers": suspicious},
                )
            )

        if not malicious and not suspicious:
            findings.append(
                Finding(
                    title="DNS servers configuration",
                    description=(
                        f"Configured DNS servers: {', '.join(dns_servers)}. "
                        "All servers appear to be from known-good public DNS providers or legitimate ISP DNS."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.dns_poisoning_check.dns_config",
                    data={"check": "dns_config", "dns_servers": dns_servers},
                )
            )

        return findings

    def _check_dns_resolution(self) -> list[Finding]:
        """Test DNS resolution for known major domains.

        Returns list of findings for resolution issues.
        """
        findings = []

        for domain, expected_prefixes in EXPECTED_DOMAINS.items():
            ip = self._resolve_domain(domain)
            if ip:
                # Check if resolved IP matches expected ranges
                matches_expected = any(ip.startswith(prefix) for prefix in expected_prefixes)
                if not matches_expected:
                    findings.append(
                        Finding(
                            title=f"WARNING: Unexpected DNS resolution for {domain}",
                            description=(
                                f"Domain {domain} resolved to {ip}, which is not in the expected IP ranges. "
                                "This could indicate DNS redirection/poisoning. "
                                "Verify the domain resolves correctly and check your DNS settings."
                            ),
                            severity=Severity.WARNING,
                            category=self.category,
                            code="security.dns_poisoning_check.dns_resolution_issue",
                            data={"check": "dns_resolution_issue", "domain": domain, "resolved_ip": ip},
                        )
                    )
            # If we can't resolve, just skip (network might be offline)

        return findings

    def _resolve_domain(self, domain: str) -> Optional[str]:
        """Resolve a domain to its IP address using dig.

        Returns the first A record IP or None.
        """
        try:
            result = subprocess.run(
                ["dig", "+short", domain],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                lines = result.stdout.strip().split("\n")
                for line in lines:
                    line = line.strip()
                    # Check if it looks like an IPv4 address (4 dotted octets)
                    if line and all(c.isdigit() or c == "." for c in line):
                        parts = line.split(".")
                        if len(parts) == 4:
                            try:
                                for part in parts:
                                    int(part)  # Validate numeric
                                return line
                            except ValueError:
                                continue
            return None
        except Exception:
            return None

    def _check_dns_over_https(self) -> Optional[Finding]:
        """Check if DNS-over-HTTPS (DoH) is configured.

        Returns INFO finding if DoH is configured, None otherwise.
        """
        try:
            result = subprocess.run(
                ["defaults", "read", "/Library/Preferences/com.apple.networkd", "DNSSettings"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0 and "doh" in result.stdout.lower():
                return Finding(
                    title="DNS-over-HTTPS (DoH) is configured",
                    description=(
                        "Your system has DNS-over-HTTPS enabled. "
                        "This adds an extra layer of privacy/security by encrypting DNS queries. "
                        "This is a positive security feature."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.dns_poisoning_check.dns_over_https",
                    data={"check": "dns_over_https", "enabled": True},
                )
        except Exception:
            pass

        return None

    def _is_isp_dns(self, ip: str) -> bool:
        """Check if IP looks like a typical ISP DNS server.

        ISP DNS are usually in private/regional ranges like:
        192.168.x.x, 10.x.x.x, 172.16-31.x.x
        or specific ISP ranges.
        """
        # Private IP ranges
        if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172."):
            return True

        # Common ISP DNS prefixes (examples)
        isp_prefixes = ["24.", "68.", "75.", "75.", "80.", "81.", "88.", "205."]
        if any(ip.startswith(p) for p in isp_prefixes):
            return True

        return False
