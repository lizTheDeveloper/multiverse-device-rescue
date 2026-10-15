import ipaddress
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

# Well-known public DNS provider networks (privacy / filtering resolvers are
# common and intentional: NextDNS, Mullvad, Control D, AdGuard, ...)
KNOWN_DNS_NETWORKS = [
    ("NextDNS", "45.90.28.0/24"),
    ("NextDNS", "45.90.30.0/24"),
    ("NextDNS", "2a07:a8c0::/32"),
    ("NextDNS", "2a07:a8c1::/32"),
    ("Mullvad DNS", "194.242.2.0/24"),
    ("Mullvad DNS", "2a07:e340::/32"),
    ("Control D", "76.76.2.0/24"),
    ("Control D", "76.76.10.0/24"),
    ("AdGuard DNS", "94.140.14.0/24"),
    ("AdGuard DNS", "94.140.15.0/24"),
    ("AdGuard DNS", "2a10:50c0::/32"),
    ("Quad9", "9.9.9.0/24"),
    ("Quad9", "149.112.112.0/24"),
    ("Quad9", "2620:fe::/48"),
    ("OpenDNS", "208.67.222.0/24"),
    ("OpenDNS", "208.67.220.0/24"),
    ("OpenDNS", "2620:119::/48"),
    ("Cloudflare DNS", "1.1.1.0/24"),
    ("Cloudflare DNS", "1.0.0.0/24"),
    ("Cloudflare DNS", "2606:4700:4700::/48"),
    ("Google DNS", "8.8.8.0/24"),
    ("Google DNS", "8.8.4.0/24"),
    ("Google DNS", "2001:4860:4860::/48"),
]
_KNOWN_DNS_PARSED = [(n, ipaddress.ip_network(c)) for n, c in KNOWN_DNS_NETWORKS]

# Domains whose public DNS answer should never be a private/internal address.
# We deliberately do not hard-code "expected" IP ranges: CDN-backed sites move
# between networks all the time. A public name resolving to a private,
# loopback, link-local or otherwise non-routable address is the real signal.
CANARY_DOMAINS = ["apple.com", "google.com", "microsoft.com"]


# Addresses a home/office router or local network hands out as DNS
_LOCAL_NETWORKS = [
    ipaddress.ip_network(n)
    for n in (
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16",
        "100.64.0.0/10", "fc00::/7", "fe80::/10",
    )
]


def _known_dns_provider(server: str) -> Optional[str]:
    """Return a friendly name if server is a known provider or a local/router address."""
    try:
        addr = ipaddress.ip_address(server.split("%")[0])
    except ValueError:
        return None
    if addr.is_loopback or addr.is_unspecified:
        return None  # handled separately (sinkhole list)
    if any(addr.version == n.version and addr in n for n in _LOCAL_NETWORKS):
        return "your router"
    for name, net in _KNOWN_DNS_PARSED:
        if addr.version == net.version and addr in net:
            return name
    return None


def _is_bogon(ip: str) -> bool:
    """True if ip is not a publicly routable address."""
    try:
        return not ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


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
                    title="Your DNS settings",
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
                        # partition (not split) so IPv6 addresses keep their colons
                        _, sep, rest = line.partition(":")
                        if sep:
                            ip = rest.strip()
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
        local_other = []
        gateway = None
        gateway_read = False

        for server in dns_servers:
            # Check for malicious servers
            if server in MALICIOUS_DNS:
                malicious.append(server)
            elif server in KNOWN_GOOD_DNS:
                continue
            elif _known_dns_provider(server) == "your router" or server.startswith(
                ("192.168.", "10.")
            ):
                # A private address is only "your router" if it IS the router.
                # Any device on the network (including one someone else runs)
                # can answer DNS, so anything else stays listed, not skipped.
                if not gateway_read:
                    gateway, gateway_read = self._default_gateway(), True
                if gateway is None or server != gateway:
                    local_other.append(server)
            # Check if it's not a known-good server
            elif not _known_dns_provider(server):
                # Check if it looks like a valid IP (not ISP DNS, localhost, etc)
                if not self._is_isp_dns(server) and server not in ["127.0.0.1", "::1"]:
                    suspicious.append(server)

        if local_other:
            findings.append(
                Finding(
                    title="DNS is set to a device on your local network",
                    description=(
                        f"Your computer is set to ask {', '.join(local_other)} for DNS "
                        "(the phone book for websites). That is usual when it is your "
                        "router, but any device on your network can act as a DNS server, "
                        "and this tool could not confirm that this address is your "
                        "router. If you do not recognize it, check System Settings > "
                        "Network > DNS, or ask whoever set up your network."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.dns_poisoning_check.suspicious_dns",
                    data={"check": "local_dns_server", "servers": local_other},
                )
            )

        if malicious:
            findings.append(
                Finding(
                    title="Your computer looks up websites through a known bad server",
                    description=(
                        "Your computer is set to use a DNS server that's on a list of "
                        f"malicious or blocked servers: {', '.join(malicious)}. DNS turns "
                        "website names into addresses, so whoever runs it can send you "
                        "to fake copies of real sites, including your bank.\n\n"
                        "If you think someone close to you set this up to monitor you, "
                        "changing it can alert them. Talk to an advocate first (US National "
                        "Domestic Violence Hotline: 1-800-799-7233, or text START to "
                        "88788).\n\n"
                        "What to do: Don't sign in to anything important on this computer "
                        "until it's fixed. Then follow the steps below to set DNS back "
                        "to automatic."
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
                    title="Your computer uses a DNS server we don't recognize",
                    description=(
                        "Your computer is set to use DNS servers we don't recognize: "
                        f"{', '.join(suspicious)}. DNS is the phone book your computer "
                        "uses to find websites. Some people choose a custom one on purpose "
                        "(for privacy, ad blocking or work), and some internet providers "
                        "and routers set one for you.\n\n"
                        "What to do: If you don't remember choosing this, check System "
                        "Settings > Network, choose your connection, click Details > "
                        "DNS, or ask whoever set up your network."
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
                    title="Your DNS servers",
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

        for domain in CANARY_DOMAINS:
            ip = self._resolve_domain(domain)
            if ip:
                if _is_bogon(ip):
                    findings.append(
                        Finding(
                            title=f"{domain} pointed somewhere it shouldn't",
                            description=(
                                f"When we looked up {domain}, the answer was {ip}, a private "
                                "address that real public websites never use. That can "
                                "mean something is redirecting your web traffic, or just "
                                "a filtering tool or a hotel or café sign-in page on "
                                "your network.\n\n"
                                "What to do: If you're on public Wi-Fi with a sign-in "
                                "page, sign in and run the checkup again. Otherwise, "
                                "follow the steps below to check your DNS settings."
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
                    title="Encrypted DNS is turned on",
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

    @staticmethod
    def _default_gateway() -> Optional[str]:
        """The default gateway as reported by the routing table (read-only)."""
        try:
            result = subprocess.run(
                ["route", "-n", "get", "default"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            out = result.stdout
            if result.returncode != 0 or not isinstance(out, str):
                return None
            m = re.search(r"^\s*gateway:\s*(\S+)", out, re.MULTILINE)
            return m.group(1) if m else None
        except Exception:
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
