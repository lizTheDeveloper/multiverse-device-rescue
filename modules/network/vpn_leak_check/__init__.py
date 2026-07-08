import re
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
    name = "vpn_leak_check"
    category = "network"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "5s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Get list of all VPN configurations
        vpn_list = self._get_vpn_list()

        if not vpn_list:
            # No VPNs configured - this is normal for most users
            findings.append(
                Finding(
                    title="No VPN configurations detected",
                    description="No VPN services are configured on this system.",
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "no_vpns_configured"},
                )
            )
            return CheckResult(module_name=self.name, findings=findings)

        # Check each VPN's connection status
        vpn_details = {}
        vpn_connected = None

        for vpn_name in vpn_list:
            status = self._get_vpn_status(vpn_name)
            vpn_type = self._get_vpn_type(vpn_name)
            vpn_details[vpn_name] = {
                "connected": status,
                "type": vpn_type
            }

            if status:
                vpn_connected = vpn_name

        # Add INFO finding with VPN configuration summary
        vpn_summary = []
        for vpn_name, details in vpn_details.items():
            status_str = "Connected" if details["connected"] else "Not connected"
            vpn_type = details["type"] or "Unknown"
            vpn_summary.append(f"{vpn_name}: {status_str} ({vpn_type})")

        findings.append(
            Finding(
                title="VPN configurations detected",
                description=(
                    "The following VPN configurations are available:\n" +
                    "\n".join(vpn_summary)
                ),
                severity=Severity.INFO,
                category=self.category,
                data={
                    "check": "vpn_config_summary",
                    "vpn_configs": list(vpn_details.keys()),
                    "vpn_connected": vpn_connected,
                },
            )
        )

        # If a VPN is connected, perform leak checks
        if vpn_connected:
            # Check DNS configuration
            dns_leak_status = self._check_dns_leak(vpn_connected)
            if dns_leak_status["has_leak"]:
                findings.append(
                    Finding(
                        title="Potential DNS leak detected while VPN is connected",
                        description=(
                            f"While VPN '{vpn_connected}' is connected, the system DNS configuration "
                            f"includes non-VPN DNS servers: {', '.join(dns_leak_status['non_vpn_servers'])}. "
                            f"This indicates a DNS leak where DNS queries may bypass the VPN tunnel. "
                            f"DNS leaks compromise privacy. Ensure your VPN has DNS leak protection enabled."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={
                            "check": "dns_leak",
                            "vpn_name": vpn_connected,
                            "non_vpn_servers": dns_leak_status['non_vpn_servers'],
                            "all_servers": dns_leak_status['all_servers'],
                        },
                    )
                )

            # Check for split tunneling
            split_tunnel_status = self._check_split_tunneling(vpn_connected)
            if split_tunnel_status["has_split_tunnel"]:
                findings.append(
                    Finding(
                        title="Potential split tunneling leak detected",
                        description=(
                            f"While VPN '{vpn_connected}' is connected, multiple default routes exist: "
                            f"{', '.join(split_tunnel_status['default_routes'])}. "
                            f"This indicates split tunneling where some traffic bypasses the VPN tunnel. "
                            f"If unintended, disable split tunneling in your VPN settings to ensure all traffic "
                            f"is encrypted through the VPN."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={
                            "check": "split_tunneling",
                            "vpn_name": vpn_connected,
                            "default_routes": split_tunnel_status['default_routes'],
                        },
                    )
                )
        else:
            # VPN is configured but not connected
            findings.append(
                Finding(
                    title="VPN configured but not connected",
                    description=(
                        "One or more VPN configurations are available but currently not connected. "
                        "If privacy is a concern, consider connecting to a VPN."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "check": "vpn_not_connected",
                        "vpn_configs": list(vpn_details.keys()),
                    },
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        """Provide informational guidance on VPN configuration and DNS leak protection."""
        actions = []

        for finding in findings.findings:
            check_type = finding.data.get("check")

            if check_type == "dns_leak":
                vpn_name = finding.data.get("vpn_name")
                title = f"Enable DNS leak protection in {vpn_name}"
                description = (
                    f"To enable DNS leak protection for {vpn_name}:\n"
                    f"1. Open System Settings > Network\n"
                    f"2. Select {vpn_name} and click 'Details...'\n"
                    f"3. Look for DNS or Privacy settings\n"
                    f"4. Verify that DNS leak protection is enabled\n"
                    f"5. Some VPN providers offer custom DNS servers that route through the VPN tunnel\n"
                    f"\n"
                    f"If your VPN provider doesn't have built-in DNS leak protection, consider:\n"
                    f"- Switching to a VPN provider with strong privacy features\n"
                    f"- Manually configuring DNS to use the VPN provider's DNS servers\n"
                    f"- Testing for DNS leaks at tools like dnsleaktest.com"
                )

            elif check_type == "split_tunneling":
                vpn_name = finding.data.get("vpn_name")
                title = f"Disable split tunneling in {vpn_name}"
                description = (
                    f"To disable split tunneling for {vpn_name}:\n"
                    f"1. Open System Settings > Network\n"
                    f"2. Select {vpn_name} and click 'Details...'\n"
                    f"3. Look for 'Split tunneling' or 'Route all traffic' options\n"
                    f"4. Ensure 'Route all traffic through VPN' is enabled\n"
                    f"5. Disable any selective routing or split tunneling settings\n"
                    f"\n"
                    f"Note: Some applications or network requirements may necessitate split tunneling. "
                    f"Only disable if not required for your workflow."
                )

            elif check_type == "vpn_not_connected":
                title = "Connect to VPN for privacy"
                description = (
                    "To connect to a VPN:\n"
                    "1. Open System Settings > Network\n"
                    "2. Locate your VPN configuration in the list\n"
                    "3. Click the VPN and select 'Connect'\n"
                    "4. Verify the VPN status shows 'Connected'\n"
                    "\n"
                    "Note: VPNs are valuable for privacy, especially on public networks. "
                    "Ensure you trust the VPN provider, as they can see all your network traffic."
                )

            elif check_type in ("vpn_config_summary", "no_vpns_configured"):
                # No action needed for informational findings
                continue

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

    def _get_vpn_list(self) -> list[str]:
        """Get list of all VPN configurations via scutil."""
        try:
            result = subprocess.run(
                ["scutil", "--nc", "list"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode != 0:
                return []

            vpn_configs = []
            # Parse output: each VPN line starts with "  " and contains service name
            for line in result.stdout.split('\n'):
                line = line.strip()
                if line and not line.startswith("*"):
                    # Skip header and format lines
                    if ":" in line:
                        # Extract service name (usually between quotes or before first space)
                        parts = line.split()
                        if parts:
                            service_name = parts[0].strip("'\"()")
                            if service_name and service_name not in vpn_configs:
                                vpn_configs.append(service_name)

            return vpn_configs
        except (subprocess.SubprocessError, Exception):
            return []

    def _get_vpn_status(self, vpn_name: str) -> bool:
        """Check if a specific VPN is currently connected."""
        try:
            result = subprocess.run(
                ["scutil", "--nc", "status", vpn_name],
                capture_output=True,
                text=True,
                timeout=5
            )
            # Check for connected status - must be exact line match
            # "Connected" on its own line or "Status : Connected"
            for line in result.stdout.split('\n'):
                line = line.strip()
                if line == "Connected" or "Status : Connected" in line:
                    return True
            return False
        except (subprocess.SubprocessError, Exception):
            return False

    def _get_vpn_type(self, vpn_name: str) -> str | None:
        """Identify VPN type from configuration."""
        try:
            # Try to get VPN config details
            result = subprocess.run(
                ["scutil", "--nc", "status", vpn_name],
                capture_output=True,
                text=True,
                timeout=5
            )

            output = result.stdout.lower()

            # Check for common VPN types
            if "ikev2" in output:
                return "IKEv2"
            elif "l2tp" in output:
                return "L2TP"
            elif "ipsec" in output:
                return "IPSec"
            elif "openvpn" in output or "openvpn" in vpn_name.lower():
                return "OpenVPN"
            elif "wireguard" in output or "wireguard" in vpn_name.lower():
                return "WireGuard"
            elif "pptp" in output:
                return "PPTP"
            else:
                return "Unknown"
        except (subprocess.SubprocessError, Exception):
            return None

    def _check_dns_leak(self, vpn_name: str) -> dict:
        """Check if DNS configuration shows a leak while VPN is connected."""
        try:
            result = subprocess.run(
                ["scutil", "--dns"],
                capture_output=True,
                text=True,
                timeout=5
            )

            dns_servers = []
            for line in result.stdout.split('\n'):
                if "nameserver[" in line:
                    # Extract IP address
                    match = re.search(r':\s*([\d.]+|[a-f0-9:]+)', line)
                    if match:
                        dns_servers.append(match.group(1))

            # Remove duplicates while preserving order
            seen = set()
            unique_servers = []
            for server in dns_servers:
                if server not in seen:
                    seen.add(server)
                    unique_servers.append(server)

            # Common VPN-provided DNS servers and public DNS
            known_vpn_dns = {
                # NordVPN
                "103.86.96.100", "103.86.99.100",
                # ExpressVPN
                "35.243.86.165", "35.203.174.191",
                # SurfShark
                "89.163.128.29", "89.45.90.27",
                # ProtonVPN
                "185.217.116.16", "185.217.117.16",
                # Mullvad
                "194.126.29.24", "194.126.29.25",
                # Windscribe
                "143.244.33.44", "143.244.34.44",
                # Cyberghost
                "89.45.90.27", "89.45.91.27",
            }

            public_dns = {
                # Google
                "8.8.8.8", "8.8.4.4", "2001:4860:4860::8888", "2001:4860:4860::8844",
                # Cloudflare
                "1.1.1.1", "1.0.0.1", "2606:4700:4700::1111", "2606:4700:4700::1001",
                # Quad9
                "9.9.9.9", "149.112.112.112",
                # OpenDNS
                "208.67.222.222", "208.67.220.220",
            }

            # Local/private DNS
            private_ranges = [
                "127.0.0.1", "::1",  # localhost
                "192.168.",
                "10.",
                "172.16.", "172.17.", "172.18.", "172.19.", "172.20.", "172.21.",
                "172.22.", "172.23.", "172.24.", "172.25.", "172.26.", "172.27.",
                "172.28.", "172.29.", "172.30.", "172.31.",
                "fd00:", "fc00:",  # IPv6 private
            ]

            non_vpn_servers = []
            for server in unique_servers:
                # Check if it's a known VPN DNS
                if server in known_vpn_dns:
                    continue

                # Check if it's a public/well-known DNS
                if server in public_dns:
                    non_vpn_servers.append(f"{server} (public DNS)")
                    continue

                # Check if it's private/local
                is_private = False
                for private_range in private_ranges:
                    if server.startswith(private_range):
                        is_private = True
                        break

                if is_private:
                    non_vpn_servers.append(f"{server} (private)")
                else:
                    # Unknown server - potential leak
                    non_vpn_servers.append(f"{server} (unknown)")

            return {
                "has_leak": len(non_vpn_servers) > 0,
                "non_vpn_servers": non_vpn_servers,
                "all_servers": unique_servers,
            }
        except (subprocess.SubprocessError, Exception):
            return {
                "has_leak": False,
                "non_vpn_servers": [],
                "all_servers": [],
            }

    def _check_split_tunneling(self, vpn_name: str) -> dict:
        """Check for split tunneling by examining routing table."""
        try:
            result = subprocess.run(
                ["netstat", "-rn"],
                capture_output=True,
                text=True,
                timeout=5
            )

            default_routes = []

            for line in result.stdout.split('\n'):
                line = line.strip()
                if not line:
                    continue

                parts = line.split()
                # Look for default route (0.0.0.0 or ::/0 as destination)
                if len(parts) >= 2:
                    destination = parts[0]
                    if destination in ("0.0.0.0", "default", "::/0"):
                        # Extract gateway and interface
                        if len(parts) >= 3:
                            gateway = parts[1]
                            if len(parts) >= 4:
                                interface = parts[3]
                                default_routes.append(f"{destination} via {gateway} ({interface})")
                            else:
                                default_routes.append(f"{destination} via {gateway}")

            # Multiple default routes indicate split tunneling
            return {
                "has_split_tunnel": len(default_routes) > 1,
                "default_routes": default_routes,
            }
        except (subprocess.SubprocessError, Exception):
            return {
                "has_split_tunnel": False,
                "default_routes": [],
            }
