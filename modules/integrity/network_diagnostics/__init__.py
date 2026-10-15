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
                title="Your Mac can't translate website names to addresses",
                description=(
                    "We tried to look up the address for google.com, but your Mac couldn't "
                    "find it. "
                    "This usually means your internet connection is having trouble. "
                    "It prevents you from opening websites until it's fixed.\n\n"
                    "What to do: Restart your router (unplug it for 30 seconds, then plug "
                    "it back in). "
                    "If that doesn't work, check System Settings > Network to make sure "
                    "you're connected."
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
                        title="No internet address book is set up",
                        description=(
                            "Your Mac doesn't have any instructions for translating website "
                            "names into numbers. "
                                                        "It means you probably can't load websites right now.\n\n"
                            "What to do: Make sure you're connected to Wi-Fi or a network "
                            "cable. If you are and websites still won't load, restart "
                            "your router."
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
                                title=f"Your {current_interface} connection is off",
                                description=(
                                    f"The {current_interface} port on your Mac is currently "
                                    "turned off. "
                                    "This is normal if you aren't using that connection "
                                    "right now. "
                                    "It isn't a security risk, but it means that specific "
                                    "connection won't work.\n\n"
                                    f"What to do: Nothing to fix if you aren't using {current_interface}. "
                                    "If you expected it to be on, check System Settings "
                                    "> Network to turn it back on."
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
                        title=f"Your {current_interface} connection is off",
                        description=(
                            f"The {current_interface} port on your Mac is currently turned off. "
                            "This is normal if you aren't using that connection right now. "
                            "It isn't a security risk, but it means that specific connection "
                            "won't work.\n\n"
                            f"What to do: Nothing to fix if you aren't using {current_interface}. "
                            "If you expected it to be on, check System Settings > Network "
                            "to turn it back on."
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
                    title="Your Mac can't reach your router",
                    description=(
                        "We tried to contact your home router, but it didn't respond. "
                        "This usually means your Wi-Fi or internet connection is down, "
                        "not that your Mac is compromised. "
                        "You likely won't be able to browse the web until this is fixed.\n\n"
                        "What to do: Check that your router is powered on and that your "
                        "Mac is connected to Wi-Fi. "
                        "Try restarting your router and your Mac."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
                    data={"check_type": "gateway"},
                )
        except (subprocess.TimeoutExpired, OSError):
            pass

        return None
