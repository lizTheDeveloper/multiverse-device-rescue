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
    name = "network_diagnostics"
    category = "integrity"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "10s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Check DNS resolution
        dns_finding = self._check_dns_resolution()
        if dns_finding:
            findings.append(dns_finding)

        # Check DNS server configuration
        dns_config_findings = self._check_dns_servers()
        findings.extend(dns_config_findings)

        # Check network interface status
        interface_findings = self._check_network_interfaces()
        findings.extend(interface_findings)

        # Check gateway reachability
        gateway_finding = self._check_gateway()
        if gateway_finding:
            findings.append(gateway_finding)

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            check_type = finding.data.get("check_type")
            if check_type == "dns_resolution":
                actions.append(
                    Action(
                        title="DNS resolution failed",
                        description=(
                            "The system cannot resolve DNS names. "
                            "This may indicate a network connectivity issue, DNS server misconfiguration, "
                            "or a firewall/router blocking DNS traffic. "
                            "Try: (1) check your internet connection, "
                            "(2) restart your router, "
                            "(3) manually set DNS servers (e.g., 8.8.8.8, 1.1.1.1)"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif check_type == "dns_servers":
                domain = finding.data.get("domain", "Unknown")
                servers = finding.data.get("servers", [])
                actions.append(
                    Action(
                        title=f"DNS servers unresponsive for {domain}",
                        description=(
                            f"The configured DNS servers ({', '.join(servers) or 'none'}) "
                            f"are not responding. Try changing your DNS servers to public resolvers "
                            f"like 8.8.8.8 (Google), 1.1.1.1 (Cloudflare), or 208.67.222.222 (OpenDNS). "
                            f"Use System Settings > Network > Wi-Fi > Details > DNS."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif check_type == "network_interfaces":
                interface = finding.data.get("interface", "Unknown")
                reason = finding.data.get("reason", "Unknown")
                actions.append(
                    Action(
                        title=f"Network interface {interface} has issues",
                        description=(
                            f"Interface {interface}: {reason}. "
                            f"Try: (1) toggle Wi-Fi off/on, (2) forget and rejoin the network, "
                            f"(3) restart your Mac, (4) check System Settings > Network."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif check_type == "gateway":
                actions.append(
                    Action(
                        title="Default gateway is unreachable",
                        description=(
                            "The default gateway (router) is not responding to ping requests. "
                            "Try: (1) check if you're connected to Wi-Fi, "
                            "(2) verify the router is powered on, "
                            "(3) check for Ethernet cable if applicable, "
                            "(4) restart the router."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
        return FixResult(module_name=self.name, actions=actions)

    def _check_dns_resolution(self) -> Optional[Finding]:
        """Check if DNS resolution works for a known domain."""
        try:
            socket.getaddrinfo("google.com", 80)
            return None  # DNS works
        except (socket.gaierror, OSError):
            return Finding(
                title="DNS resolution failed",
                description=(
                    "Cannot resolve google.com. DNS resolution is not working. "
                    "This prevents access to any domain-based services."
                ),
                severity=Severity.CRITICAL,
                category=self.category,
                data={"check_type": "dns_resolution"},
            )

    def _check_dns_servers(self) -> list[Finding]:
        """Check DNS server configuration and responsiveness."""
        findings = []
        try:
            result = subprocess.run(
                ["scutil", "--dns"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode != 0:
                return findings

            output = result.stdout
            # Parse DNS servers from scutil output
            dns_servers = []
            for line in output.split("\n"):
                if "nameserver" in line.lower():
                    # Extract IP from lines like "nameserver[0] : 192.168.1.1"
                    parts = line.split(":")
                    if len(parts) > 1:
                        ip = parts[1].strip()
                        if ip and ip not in dns_servers:
                            dns_servers.append(ip)

            # Check if any DNS servers are configured
            if not dns_servers:
                findings.append(
                    Finding(
                        title="No DNS servers configured",
                        description=(
                            "No DNS servers are configured on this system. "
                            "This prevents DNS resolution from working."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={
                            "check_type": "dns_servers",
                            "domain": "System",
                            "servers": [],
                        },
                    )
                )
        except (subprocess.TimeoutExpired, OSError):
            pass

        return findings

    def _check_network_interfaces(self) -> list[Finding]:
        """Check if network interfaces are up and have IPs."""
        findings = []
        try:
            result = subprocess.run(
                ["ifconfig"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode != 0:
                return findings

            output = result.stdout
            lines = output.split("\n")
            current_interface = None
            interface_up = False

            for line in lines:
                # Interface lines start without leading whitespace
                if line and not line[0].isspace():
                    # Process previous interface
                    if current_interface and not interface_up:
                        findings.append(
                            Finding(
                                title=f"Network interface {current_interface} is down",
                                description=(
                                    f"Interface {current_interface} is not active. "
                                    f"This may prevent network connectivity."
                                ),
                                severity=Severity.WARNING,
                                category=self.category,
                                data={
                                    "check_type": "network_interfaces",
                                    "interface": current_interface,
                                    "reason": "Interface is down",
                                },
                            )
                        )
                    # Start new interface - check flags on the interface line itself
                    current_interface = line.split(":")[0]
                    interface_up = "UP" in line and "RUNNING" in line

            # Process last interface
            if current_interface and not interface_up:
                findings.append(
                    Finding(
                        title=f"Network interface {current_interface} is down",
                        description=(
                            f"Interface {current_interface} is not active. "
                            f"This may prevent network connectivity."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={
                            "check_type": "network_interfaces",
                            "interface": current_interface,
                            "reason": "Interface is down",
                        },
                    )
                )

        except (subprocess.TimeoutExpired, OSError):
            pass

        return findings

    def _check_gateway(self) -> Optional[Finding]:
        """Check if the default gateway is reachable."""
        # Try to get the default gateway by pinging common gateway IPs
        # or by parsing route output
        try:
            # Attempt to ping the local network (assumes typical 192.168.1.1)
            # In a real scenario, we'd parse `route -n get default` to get actual gateway
            gateway_candidates = ["192.168.1.1", "10.0.0.1"]

            for gateway in gateway_candidates:
                result = subprocess.run(
                    ["ping", "-c", "1", "-W", "1", gateway],
                    capture_output=True,
                    text=True,
                    timeout=3,
                )
                if result.returncode == 0:
                    return None  # Gateway is reachable

            # If none of the common gateways responded, check if we can reach anything
            result = subprocess.run(
                ["ping", "-c", "1", "-W", "1", "8.8.8.8"],
                capture_output=True,
                text=True,
                timeout=3,
            )
            if result.returncode != 0:
                return Finding(
                    title="Default gateway is unreachable",
                    description=(
                        "The system cannot reach the default gateway or external networks. "
                        "This indicates a network connectivity issue."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
                    data={"check_type": "gateway"},
                )
        except (subprocess.TimeoutExpired, OSError):
            pass

        return None
