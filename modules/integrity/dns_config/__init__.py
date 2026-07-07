import socket
import subprocess
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


class Module(ModuleBase):
    name = "dns_config"
    category = "integrity"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "5s"

    # Well-known DNS providers
    WELL_KNOWN_DNS = {
        "8.8.8.8": "Google DNS",
        "8.8.4.4": "Google DNS",
        "1.1.1.1": "Cloudflare DNS",
        "1.0.0.1": "Cloudflare DNS",
        "208.67.222.222": "OpenDNS",
        "208.67.220.220": "OpenDNS",
        "9.9.9.9": "Quad9 DNS",
    }

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Get DNS servers from scutil
        dns_servers = self._get_dns_servers()

        # Get per-interface DNS
        interface_dns = self._get_interface_dns()

        # Check for suspicious DNS
        suspicious = self._check_suspicious_dns(dns_servers)
        if suspicious:
            findings.extend(suspicious)

        # Info finding with current DNS servers
        dns_info = self._create_dns_info_finding(dns_servers, interface_dns)
        if dns_info:
            findings.append(dns_info)

        # Check DNS server reachability
        unreachable = self._check_dns_reachability(dns_servers)
        if unreachable:
            findings.append(unreachable)

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            check_type = finding.data.get("check_type")
            if check_type == "suspicious_dns":
                actions.append(
                    Action(
                        title="Suspicious DNS servers detected",
                        description=(
                            "Your system is using DNS servers that are not from well-known providers. "
                            "This could indicate DNS hijacking or misconfiguration. "
                            "To change DNS settings: Go to System Settings > Network > Wi-Fi (or Ethernet) > Details > DNS. "
                            "Consider using public DNS: "
                            "Google (8.8.8.8, 8.8.4.4), "
                            "Cloudflare (1.1.1.1, 1.0.0.1), "
                            "OpenDNS (208.67.222.222, 208.67.220.220), or "
                            "Quad9 (9.9.9.9)."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif check_type == "dns_info":
                actions.append(
                    Action(
                        title="Current DNS configuration",
                        description=(
                            "Your system is using the DNS servers shown above. "
                            "If you experience issues resolving websites, try changing to a public DNS server "
                            "or restarting your network interface."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif check_type == "unreachable_dns":
                actions.append(
                    Action(
                        title="DNS servers are unreachable",
                        description=(
                            "The configured DNS servers are not responding to queries. "
                            "Check your internet connection and network settings. "
                            "Try: (1) restarting your router, "
                            "(2) toggling Wi-Fi off and on, "
                            "(3) changing to a public DNS server, "
                            "(4) checking if your ISP is having issues."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
        return FixResult(module_name=self.name, actions=actions)

    def _get_dns_servers(self) -> list[str]:
        """Get current DNS servers via scutil --dns."""
        try:
            result = subprocess.run(
                ["scutil", "--dns"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode != 0:
                return []

            dns_servers = []
            for line in result.stdout.split("\n"):
                if "nameserver" in line.lower():
                    # Extract IP from lines like "nameserver[0] : 192.168.1.1"
                    parts = line.split(":")
                    if len(parts) > 1:
                        ip = parts[1].strip()
                        if ip and ip not in dns_servers:
                            dns_servers.append(ip)

            return dns_servers
        except (subprocess.TimeoutExpired, OSError):
            return []

    def _get_interface_dns(self) -> dict[str, list[str]]:
        """Get per-interface DNS configuration."""
        interface_dns = {}
        interfaces = ["Wi-Fi", "Ethernet"]

        for interface in interfaces:
            try:
                result = subprocess.run(
                    ["networksetup", "-getdnsservers", interface],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                if result.returncode == 0:
                    dns_list = []
                    for line in result.stdout.split("\n"):
                        line = line.strip()
                        if line and not line.startswith("DNS"):
                            dns_list.append(line)
                    if dns_list:
                        interface_dns[interface] = dns_list
            except (subprocess.TimeoutExpired, OSError):
                pass

        return interface_dns

    def _check_suspicious_dns(self, dns_servers: list[str]) -> list[Finding]:
        """Check if DNS servers are from suspicious/unknown sources."""
        findings = []
        suspicious = []

        for server in dns_servers:
            if server not in self.WELL_KNOWN_DNS and server not in ["127.0.0.1"]:
                suspicious.append(server)

        if suspicious:
            findings.append(
                Finding(
                    title="Unknown/suspicious DNS servers detected",
                    description=(
                        f"Your system is using DNS servers that are not from well-known providers: {', '.join(suspicious)}. "
                        "This could indicate DNS hijacking, ISP-provided DNS, or misconfiguration."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "check_type": "suspicious_dns",
                        "servers": suspicious,
                    },
                )
            )

        return findings

    def _create_dns_info_finding(
        self, dns_servers: list[str], interface_dns: dict[str, list[str]]
    ) -> Optional[Finding]:
        """Create an info finding with current DNS configuration."""
        if not dns_servers and not interface_dns:
            return None

        # Build description
        lines = []
        if dns_servers:
            lines.append(f"System DNS servers: {', '.join(dns_servers)}")
        for interface, servers in interface_dns.items():
            lines.append(f"{interface} DNS: {', '.join(servers)}")

        # Check if using well-known DNS
        well_known = [s for s in dns_servers if s in self.WELL_KNOWN_DNS]
        if well_known:
            lines.append(f"Using well-known providers: {', '.join([self.WELL_KNOWN_DNS[s] for s in well_known])}")

        return Finding(
            title="DNS configuration",
            description="\n".join(lines),
            severity=Severity.INFO,
            category=self.category,
            data={
                "check_type": "dns_info",
                "dns_servers": dns_servers,
                "interface_dns": interface_dns,
            },
        )

    def _check_dns_reachability(self, dns_servers: list[str]) -> Optional[Finding]:
        """Check if DNS servers are reachable by resolving a known domain."""
        if not dns_servers:
            return None

        try:
            # Try to resolve a known domain
            socket.getaddrinfo("google.com", 80)
            return None  # DNS works
        except (socket.gaierror, OSError):
            # DNS resolution failed
            return Finding(
                title="DNS servers are unreachable",
                description=(
                    f"Cannot resolve google.com using configured DNS servers: {', '.join(dns_servers)}. "
                    "Your DNS servers may be offline or blocking requests."
                ),
                severity=Severity.WARNING,
                category=self.category,
                data={
                    "check_type": "unreachable_dns",
                    "servers": dns_servers,
                },
            )
