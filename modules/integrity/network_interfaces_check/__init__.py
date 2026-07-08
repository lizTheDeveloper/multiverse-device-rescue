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


class Module(ModuleBase):
    name = "network_interfaces_check"
    category = "integrity"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "5s"

    # DNS servers that are potentially problematic or censoring
    PROBLEMATIC_DNS = [
        "0.0.0.0",
        "127.0.0.1",
        "127.0.0.53",
    ]

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Get all network services
        services = self._get_network_services()
        if not services:
            findings.append(
                Finding(
                    title="Could not retrieve network services",
                    description="Unable to list network services. Network configuration may be inaccessible.",
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "services_retrieval"},
                )
            )
            return CheckResult(module_name=self.name, findings=findings)

        # Get service order
        service_order = self._get_service_order()

        # Check each service's configuration
        self_assigned_ips = []
        vpn_interfaces = []
        ipv6_disabled = []
        non_standard_mtu = []
        problematic_dns_found = []
        all_interfaces_info = []

        for service in services:
            config = self._get_service_config(service)
            if not config:
                continue

            interface_info = {
                "service": service,
                "interface": config.get("interface"),
                "ipv4": config.get("ipv4"),
                "ipv6": config.get("ipv6"),
                "dhcp": config.get("dhcp", False),
                "dns": config.get("dns", []),
                "gateway": config.get("gateway"),
                "mtu": config.get("mtu"),
                "type": config.get("type", "unknown"),
            }
            all_interfaces_info.append(interface_info)

            # Check for self-assigned IP (DHCP failure)
            if config.get("ipv4") and self._is_self_assigned_ip(config.get("ipv4")):
                self_assigned_ips.append(service)

            # Check for VPN interface
            if self._is_vpn_interface(service, config):
                vpn_interfaces.append(service)

            # Check IPv6 status
            if config.get("ipv6") is False:
                ipv6_disabled.append(service)

            # Check for non-standard MTU
            mtu = config.get("mtu")
            if mtu and mtu != 1500:
                non_standard_mtu.append((service, mtu))

            # Check for problematic DNS
            dns_servers = config.get("dns", [])
            for dns in dns_servers:
                if dns in self.PROBLEMATIC_DNS:
                    problematic_dns_found.append((service, dns))

        # Create findings based on issues found

        # CRITICAL: Self-assigned IPs indicate DHCP failure
        if self_assigned_ips:
            findings.append(
                Finding(
                    title="Self-assigned IP address detected (DHCP failure)",
                    description=(
                        f"The following network services have self-assigned IP addresses (169.254.x.x), "
                        f"indicating DHCP has failed: {', '.join(self_assigned_ips)}. "
                        f"This means the device could not obtain an IP address from the DHCP server."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
                    data={"check": "self_assigned_ip", "services": self_assigned_ips},
                )
            )

        # WARNING: Problematic DNS
        if problematic_dns_found:
            dns_text = ", ".join([f"{s}: {d}" for s, d in problematic_dns_found])
            findings.append(
                Finding(
                    title="Potentially problematic DNS servers configured",
                    description=(
                        f"The following services have potentially problematic DNS servers configured: {dns_text}. "
                        f"This may block internet access or indicate a network misconfiguration."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "check": "problematic_dns",
                        "problematic_dns": problematic_dns_found,
                    },
                )
            )

        # WARNING: VPN interfaces that might be routing all traffic when VPN is down
        if vpn_interfaces:
            findings.append(
                Finding(
                    title=f"VPN interface(s) detected: {', '.join(vpn_interfaces)}",
                    description=(
                        f"The following VPN interfaces are present: {', '.join(vpn_interfaces)}. "
                        f"If the VPN is down but configured to route all traffic, "
                        f"internet access may be blocked."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "vpn_interface", "services": vpn_interfaces},
                )
            )

        # INFO: Non-standard MTU
        if non_standard_mtu:
            mtu_text = ", ".join([f"{s}: {m}" for s, m in non_standard_mtu])
            findings.append(
                Finding(
                    title="Non-standard MTU settings detected",
                    description=(
                        f"The following services have non-standard MTU settings: {mtu_text}. "
                        f"Standard MTU is 1500 bytes. Non-standard values may cause connectivity issues."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "check": "non_standard_mtu",
                        "mtu_settings": non_standard_mtu,
                    },
                )
            )

        # INFO: IPv6 disabled
        if ipv6_disabled:
            findings.append(
                Finding(
                    title="IPv6 disabled on some interfaces",
                    description=(
                        f"IPv6 is disabled on the following services: {', '.join(ipv6_disabled)}. "
                        f"This is informational; IPv6 may be intentionally disabled."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "ipv6_disabled", "services": ipv6_disabled},
                )
            )

        # INFO: List all interfaces with their configuration
        if all_interfaces_info:
            interface_summary = self._format_interface_summary(all_interfaces_info)
            findings.append(
                Finding(
                    title="Network interfaces configuration summary",
                    description=interface_summary,
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "check": "interface_summary",
                        "interfaces": all_interfaces_info,
                    },
                )
            )

        # If no issues found, still provide informational summary
        if not findings and all_interfaces_info:
            interface_summary = self._format_interface_summary(all_interfaces_info)
            findings.append(
                Finding(
                    title="All network interfaces are properly configured",
                    description=interface_summary,
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "check": "interface_summary",
                        "interfaces": all_interfaces_info,
                    },
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            check_type = finding.data.get("check")

            if check_type == "self_assigned_ip":
                services = finding.data.get("services", [])
                for service in services:
                    actions.append(
                        Action(
                            title=f"Renew DHCP for {service}",
                            description=(
                                f"The {service} service has a self-assigned IP address, indicating DHCP has failed. "
                                f"To fix this: (1) Open System Settings > Network > {service}, "
                                f"(2) Click 'Advanced...' and select the TCP/IP tab, "
                                f"(3) Click 'Renew DHCP Lease', "
                                f"(4) If the issue persists, try 'Remove Configuration' and reconnect, "
                                f"(5) Restart your Mac if the problem continues."
                            ),
                            risk_level=RiskLevel.SAFE,
                            success=True,
                        )
                    )

            elif check_type == "problematic_dns":
                problematic_dns = finding.data.get("problematic_dns", [])
                for service, dns in problematic_dns:
                    actions.append(
                        Action(
                            title=f"Fix DNS configuration for {service}",
                            description=(
                                f"The {service} service is using DNS server {dns}, which is problematic. "
                                f"To fix this: (1) Open System Settings > Network > {service} > Advanced, "
                                f"(2) Select the DNS tab, (3) Remove {dns} from the DNS servers list, "
                                f"(4) Add a reliable DNS server like 8.8.8.8 (Google) or 1.1.1.1 (Cloudflare), "
                                f"(5) Click OK and apply the changes."
                            ),
                            risk_level=RiskLevel.SAFE,
                            success=True,
                        )
                    )

            elif check_type == "vpn_interface":
                services = finding.data.get("services", [])
                actions.append(
                    Action(
                        title="Check VPN configuration",
                        description=(
                            f"VPN interface(s) detected: {', '.join(services)}. "
                            f"To troubleshoot: (1) Check if the VPN is currently connected in System Settings > Network, "
                            f"(2) If the VPN is down but configured to route all traffic, disable 'Send all traffic over VPN' in VPN settings, "
                            f"(3) Restart the VPN connection, "
                            f"(4) If you no longer use the VPN, remove it from Network settings."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check_type == "non_standard_mtu":
                mtu_settings = finding.data.get("mtu_settings", [])
                for service, mtu in mtu_settings:
                    actions.append(
                        Action(
                            title=f"Reset MTU for {service} to standard 1500",
                            description=(
                                f"The {service} service has non-standard MTU setting of {mtu}. "
                                f"To fix this: (1) Open Terminal, "
                                f"(2) Run: networksetup -setMTU {service} 1500, "
                                f"(3) Verify with: networksetup -getMTU {service}, "
                                f"(4) Restart the network service or your Mac."
                            ),
                            risk_level=RiskLevel.SAFE,
                            success=True,
                        )
                    )

            elif check_type == "ipv6_disabled":
                actions.append(
                    Action(
                        title="IPv6 disabled on some interfaces",
                        description=(
                            "IPv6 is disabled on some network interfaces. This is informational and may be intentional. "
                            "If you want to enable IPv6: (1) Open System Settings > Network > Advanced, "
                            "(2) Select the TCP/IP tab, (3) Change 'Configure IPv6' from 'Off' to 'Automatic', "
                            "(4) Click OK and apply the changes."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check_type == "interface_summary":
                actions.append(
                    Action(
                        title="Network interfaces are configured",
                        description="Network interfaces have been analyzed. Review the interface summary for current configuration details.",
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _get_network_services(self) -> list[str]:
        """Get list of all network services.

        Returns list of service names like: Wi-Fi, Ethernet, VPN, etc.
        """
        try:
            result = subprocess.run(
                ["networksetup", "-listallnetworkservices"],
                capture_output=True,
                text=True,
                timeout=5,
            )

            if result.returncode != 0:
                return []

            services = []
            for line in result.stdout.strip().split("\n"):
                line = line.strip()
                if line and not line.startswith("*"):
                    services.append(line)

            return services

        except (subprocess.TimeoutExpired, OSError, FileNotFoundError):
            return []

    def _get_service_order(self) -> list[str]:
        """Get the order of network services.

        Returns list of service names in priority order.
        """
        try:
            result = subprocess.run(
                ["networksetup", "-listnetworkserviceorder"],
                capture_output=True,
                text=True,
                timeout=5,
            )

            if result.returncode != 0:
                return []

            services = []
            for line in result.stdout.strip().split("\n"):
                # Format is: (1) Service Name (Interface Name)
                match = re.match(r"\(\d+\)\s+([^(]+)\s+\(", line)
                if match:
                    service = match.group(1).strip()
                    services.append(service)

            return services

        except (subprocess.TimeoutExpired, OSError, FileNotFoundError):
            return []

    def _get_service_config(self, service: str) -> Optional[dict]:
        """Get configuration for a specific network service.

        Returns dict with: interface, ipv4, ipv6, dhcp, dns, gateway, mtu, type
        """
        config = {
            "interface": None,
            "ipv4": None,
            "ipv6": None,
            "dhcp": False,
            "dns": [],
            "gateway": None,
            "mtu": None,
            "type": "unknown",
        }

        try:
            # Get interface name
            result = subprocess.run(
                ["networksetup", "-getinfo", service],
                capture_output=True,
                text=True,
                timeout=5,
            )

            if result.returncode == 0:
                output = result.stdout
                for line in output.split("\n"):
                    line_lower = line.lower()
                    if "ip address:" in line_lower:
                        ip = line.split(":", 1)[1].strip()
                        if ip:
                            config["ipv4"] = ip
                    elif "ipv6 address:" in line_lower:
                        ip = line.split(":", 1)[1].strip()
                        if ip and ip != ":":
                            config["ipv6"] = ip
                    elif "dhcp configuration:" in line_lower:
                        config["dhcp"] = "enabled" in line_lower
                    elif "router:" in line_lower:
                        router = line.split(":", 1)[1].strip()
                        if router:
                            config["gateway"] = router
                    elif "interface name:" in line_lower:
                        interface = line.split(":", 1)[1].strip()
                        if interface:
                            config["interface"] = interface

            # Get DNS servers
            try:
                result = subprocess.run(
                    ["networksetup", "-getdnsservers", service],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                if result.returncode == 0 and result.stdout.strip():
                    dns_list = result.stdout.strip().split("\n")
                    config["dns"] = [d.strip() for d in dns_list if d.strip()]
            except (subprocess.TimeoutExpired, OSError, FileNotFoundError):
                pass

            # Get IPv6 configuration
            try:
                result = subprocess.run(
                    ["networksetup", "-getipv6", service],
                    capture_output=True,
                    text=True,
                    timeout=5,
                )
                if result.returncode == 0:
                    if "off" in result.stdout.lower():
                        config["ipv6"] = False
            except (subprocess.TimeoutExpired, OSError, FileNotFoundError):
                pass

            # Determine interface type
            interface_name = (config.get("interface") or "").lower()
            if "vpn" in interface_name or service.lower() == "vpn":
                config["type"] = "VPN"
            elif "wifi" in interface_name or "en1" in interface_name:
                config["type"] = "Wi-Fi"
            elif "eth" in interface_name or "en0" in interface_name:
                config["type"] = "Ethernet"
            elif "ppp" in interface_name:
                config["type"] = "PPP"
            elif "utun" in interface_name:
                config["type"] = "VPN (TUN)"

            return config

        except (subprocess.TimeoutExpired, OSError, FileNotFoundError):
            return None

    def _is_self_assigned_ip(self, ip: str) -> bool:
        """Check if IP is a self-assigned address (169.254.x.x)."""
        try:
            parts = ip.split(".")
            if len(parts) == 4:
                return parts[0] == "169" and parts[1] == "254"
        except (IndexError, ValueError):
            pass
        return False

    def _is_vpn_interface(self, service: str, config: dict) -> bool:
        """Check if service is a VPN interface."""
        service_lower = service.lower()
        interface = (config.get("interface") or "").lower()

        return (
            "vpn" in service_lower
            or "vpn" in interface
            or "utun" in interface
            or "ppp" in interface
        )

    def _format_interface_summary(self, interfaces: list[dict]) -> str:
        """Format a readable summary of all network interfaces."""
        lines = []
        for iface in interfaces:
            service = iface.get("service", "unknown")
            type_ = iface.get("type", "unknown")
            ipv4 = iface.get("ipv4", "not configured")
            ipv6 = iface.get("ipv6", "not configured")
            dhcp = "enabled" if iface.get("dhcp") else "disabled"
            dns = ", ".join(iface.get("dns", ["automatic"]))
            gateway = iface.get("gateway", "none")
            mtu = iface.get("mtu", 1500)

            summary = (
                f"{service} ({type_}): "
                f"IPv4={ipv4}, IPv6={ipv6}, "
                f"DHCP={dhcp}, DNS=[{dns}], "
                f"Gateway={gateway}, MTU={mtu}"
            )
            lines.append(summary)

        return "\n".join(lines) if lines else "No network interfaces found."
