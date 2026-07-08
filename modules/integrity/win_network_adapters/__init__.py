import json
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
    name = "win_network_adapters"
    category = "integrity"
    platforms = [Platform.WIN32]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "15s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Get network adapters
        adapters_info = self._get_network_adapters()
        if not adapters_info:
            findings.append(
                Finding(
                    title="Could not retrieve network adapter information",
                    description=(
                        "Failed to query network adapters. You may not have Administrator privileges. "
                        "Try running PowerShell as Administrator."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "adapter_query_failed"},
                )
            )
            return CheckResult(module_name=self.name, findings=findings)

        # Get IP configuration
        ip_config = self._get_ip_configuration()

        # Get DNS configuration
        dns_config = self._get_dns_configuration()

        # Track disconnected adapters and issues
        disconnected_adapters = []
        self_assigned_ips = []
        default_gateways = []

        # Check each adapter
        adapters = adapters_info.get("adapters", [])
        for adapter in adapters:
            adapter_name = adapter.get("name", "Unknown")
            status = adapter.get("status", "Unknown")
            link_speed = adapter.get("link_speed", "Unknown")
            mac_address = adapter.get("mac_address", "Unknown")

            findings.append(
                Finding(
                    title=f"Network adapter: {adapter_name}",
                    description=(
                        f"Status: {status}. Link Speed: {link_speed}. MAC Address: {mac_address}"
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "check": "adapter_info",
                        "adapter_name": adapter_name,
                        "status": status,
                        "link_speed": link_speed,
                    },
                )
            )

            # Flag warning if adapter is disconnected
            if status.lower() == "disconnected":
                disconnected_adapters.append(adapter_name)
                findings.append(
                    Finding(
                        title=f"Network adapter disconnected: {adapter_name}",
                        description=(
                            f"Network adapter '{adapter_name}' is disconnected. "
                            "Check the cable connection, enable the adapter in Device Manager, "
                            "or check if WiFi needs to be connected."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={
                            "check": "adapter_disconnected",
                            "adapter_name": adapter_name,
                        },
                    )
                )

        # Check IP configuration
        if ip_config:
            ip_configs = ip_config.get("interfaces", [])
            for iface in ip_configs:
                iface_name = iface.get("interface", "Unknown")
                ipv4_addr = iface.get("ipv4_address", "")
                ipv4_gateway = iface.get("ipv4_gateway", "")
                ipv6_addr = iface.get("ipv6_address", "")

                # Check for self-assigned IP (169.254.x.x indicates DHCP failure)
                if ipv4_addr and ipv4_addr.startswith("169.254."):
                    self_assigned_ips.append(iface_name)
                    findings.append(
                        Finding(
                            title=f"Self-assigned IP on {iface_name}",
                            description=(
                                f"Network adapter '{iface_name}' has a self-assigned IP ({ipv4_addr}). "
                                "This indicates DHCP configuration failed. The adapter may not be "
                                "able to reach the gateway. Try releasing and renewing the IP address "
                                "using 'ipconfig /release' and 'ipconfig /renew'."
                            ),
                            severity=Severity.CRITICAL,
                            category=self.category,
                            data={
                                "check": "self_assigned_ip",
                                "adapter_name": iface_name,
                                "ip_address": ipv4_addr,
                            },
                        )
                    )

                # Track default gateways
                if ipv4_gateway:
                    default_gateways.append(
                        {"interface": iface_name, "gateway": ipv4_gateway}
                    )

                if ipv4_addr or ipv6_addr:
                    findings.append(
                        Finding(
                            title=f"IP configuration for {iface_name}",
                            description=(
                                f"IPv4: {ipv4_addr or 'None'}. "
                                f"Gateway: {ipv4_gateway or 'None'}. "
                                f"IPv6: {ipv6_addr or 'None'}"
                            ),
                            severity=Severity.INFO,
                            category=self.category,
                            data={
                                "check": "ip_config_info",
                                "adapter_name": iface_name,
                                "ipv4": ipv4_addr,
                                "gateway": ipv4_gateway,
                            },
                        )
                    )

        # Check for multiple default gateways (routing conflicts)
        if len(default_gateways) > 1:
            unique_gateways = set(gw.get("gateway") for gw in default_gateways)
            if len(unique_gateways) > 1:
                gateway_list = ", ".join(unique_gateways)
                findings.append(
                    Finding(
                        title="Multiple default gateways detected",
                        description=(
                            f"Multiple network interfaces have different default gateways ({gateway_list}). "
                            "This may cause routing conflicts. Ensure only one active network adapter "
                            "is configured, or verify your network configuration is intentional."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={
                            "check": "multiple_gateways",
                            "gateway_count": len(unique_gateways),
                        },
                    )
                )

        # Check DNS configuration
        if dns_config:
            dns_servers = dns_config.get("servers", [])
            if dns_servers:
                findings.append(
                    Finding(
                        title="DNS servers configured",
                        description=(
                            f"Configured DNS servers: {', '.join(dns_servers)}"
                        ),
                        severity=Severity.INFO,
                        category=self.category,
                        data={
                            "check": "dns_config",
                            "dns_servers": dns_servers,
                        },
                    )
                )
            else:
                findings.append(
                    Finding(
                        title="No DNS servers configured",
                        description=(
                            "No DNS servers are configured. This may prevent name resolution. "
                            "Check your network adapter settings or DHCP configuration."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={"check": "no_dns"},
                    )
                )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        for finding in findings.findings:
            check = finding.data.get("check")

            if check == "adapter_query_failed":
                actions.append(
                    Action(
                        title="Unable to query network adapters",
                        description=(
                            "Could not retrieve network adapter information. "
                            "Ensure you have Administrator privileges. "
                            "Try running PowerShell as Administrator and running: "
                            "Get-NetAdapter | Select-Object Name, Status, LinkSpeed"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "adapter_disconnected":
                adapter_name = finding.data.get("adapter_name", "Unknown")
                actions.append(
                    Action(
                        title=f"Enable disconnected adapter '{adapter_name}'",
                        description=(
                            f"Network adapter '{adapter_name}' is disconnected. "
                            "Try the following: (1) Check physical cable connections. "
                            "(2) In Device Manager, find the adapter and right-click to enable. "
                            "(3) For WiFi adapters, ensure they're enabled in Settings > Network & internet. "
                            "(4) Restart the adapter or network service."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "self_assigned_ip":
                adapter_name = finding.data.get("adapter_name", "Unknown")
                ip_address = finding.data.get("ip_address", "Unknown")
                actions.append(
                    Action(
                        title=f"Renew IP address for '{adapter_name}'",
                        description=(
                            f"Network adapter '{adapter_name}' has a self-assigned IP ({ip_address}), "
                            "indicating DHCP failed. Try these steps: "
                            "(1) Open PowerShell as Administrator. "
                            "(2) Run 'ipconfig /release' to release the current IP. "
                            "(3) Run 'ipconfig /renew' to request a new DHCP lease. "
                            "(4) Wait 10 seconds and check with 'ipconfig /all'. "
                            "(5) If still self-assigned, check DHCP server and adapter settings. "
                            "(6) Restart the adapter or network service."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "multiple_gateways":
                actions.append(
                    Action(
                        title="Multiple default gateways detected",
                        description=(
                            "Multiple network interfaces have different default gateways, which can cause "
                            "routing conflicts. Try these steps: "
                            "(1) Open PowerShell as Administrator. "
                            "(2) Run 'route print' to view all routes. "
                            "(3) Disable unused network adapters in Device Manager or Settings. "
                            "(4) Or, use 'route delete 0.0.0.0' and 'route add' to configure explicit routes. "
                            "(5) Ensure only primary adapter has a default gateway (0.0.0.0/0)."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "no_dns":
                actions.append(
                    Action(
                        title="Configure DNS servers",
                        description=(
                            "No DNS servers are configured. This prevents name resolution. "
                            "Try these steps: (1) In Settings > Network & internet > Change adapter options, "
                            "right-click your adapter and select Properties. "
                            "(2) Click 'Internet Protocol Version 4 (TCP/IPv4)' and Properties. "
                            "(3) Select 'Use the following DNS server addresses'. "
                            "(4) Enter primary DNS (8.8.8.8) and secondary (8.8.4.4). "
                            "(5) Or run 'ipconfig /renew' to get DNS from DHCP. "
                            "(6) Verify with 'ipconfig /all' that DNS servers are present."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "adapter_info":
                adapter_name = finding.data.get("adapter_name", "Unknown")
                status = finding.data.get("status", "Unknown")
                actions.append(
                    Action(
                        title=f"Network adapter '{adapter_name}' is functional",
                        description=(
                            f"Adapter '{adapter_name}' is connected with status '{status}'. "
                            "No action needed at this time."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "ip_config_info":
                adapter_name = finding.data.get("adapter_name", "Unknown")
                actions.append(
                    Action(
                        title=f"IP configuration for '{adapter_name}'",
                        description=(
                            f"Adapter '{adapter_name}' is configured with IP settings. "
                            "No action needed at this time."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "dns_config":
                actions.append(
                    Action(
                        title="DNS servers are configured",
                        description=(
                            "DNS servers are properly configured. Name resolution should work. "
                            "No action needed at this time."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _get_network_adapters(self) -> Optional[dict]:
        """Get network adapter information from PowerShell."""
        try:
            ps_cmd = (
                "Get-NetAdapter | Select-Object Name, InterfaceDescription, Status, LinkSpeed, MacAddress | "
                "ConvertTo-Json"
            )
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                return None

            return _parse_adapter_info(result.stdout)
        except (OSError, subprocess.SubprocessError, TimeoutError):
            return None

    def _get_ip_configuration(self) -> Optional[dict]:
        """Get IP configuration from PowerShell."""
        try:
            ps_cmd = (
                "Get-NetIPConfiguration | Select-Object InterfaceAlias, IPv4Address, IPv4DefaultGateway, "
                "IPv6Address | ConvertTo-Json"
            )
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                return None

            return _parse_ip_config(result.stdout)
        except (OSError, subprocess.SubprocessError, TimeoutError):
            return None

    def _get_dns_configuration(self) -> Optional[dict]:
        """Get DNS configuration from PowerShell."""
        try:
            ps_cmd = (
                "Get-DnsClientServerAddress | Select-Object ServerAddresses | "
                "ConvertTo-Json"
            )
            result = subprocess.run(
                ["powershell", "-NoProfile", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                return None

            return _parse_dns_config(result.stdout)
        except (OSError, subprocess.SubprocessError, TimeoutError):
            return None


def _parse_adapter_info(json_output: str) -> dict:
    """Parse PowerShell JSON output from Get-NetAdapter."""
    info = {"adapters": []}

    if not json_output.strip():
        return info

    try:
        # Handle both single object and array
        data = json.loads(json_output)
        if not isinstance(data, list):
            data = [data]

        for adapter in data:
            name = adapter.get("Name", "Unknown")
            description = adapter.get("InterfaceDescription", "Unknown")
            status = adapter.get("Status", "Unknown")
            link_speed = adapter.get("LinkSpeed", "Unknown")
            mac_address = adapter.get("MacAddress", "Unknown")

            info["adapters"].append(
                {
                    "name": name,
                    "description": description,
                    "status": status,
                    "link_speed": link_speed,
                    "mac_address": mac_address,
                }
            )

        return info
    except (json.JSONDecodeError, ValueError, KeyError, TypeError):
        return info


def _parse_ip_config(json_output: str) -> dict:
    """Parse PowerShell JSON output from Get-NetIPConfiguration."""
    info = {"interfaces": []}

    if not json_output.strip():
        return info

    try:
        # Handle both single object and array
        data = json.loads(json_output)
        if not isinstance(data, list):
            data = [data]

        for iface in data:
            interface_alias = iface.get("InterfaceAlias", "Unknown")

            # Extract IPv4 address
            ipv4_addr = ""
            ipv4_obj = iface.get("IPv4Address")
            if ipv4_obj:
                if isinstance(ipv4_obj, dict):
                    ipv4_addr = ipv4_obj.get("IPAddress", "")
                elif isinstance(ipv4_obj, list) and ipv4_obj:
                    ipv4_addr = ipv4_obj[0].get("IPAddress", "") if isinstance(ipv4_obj[0], dict) else str(ipv4_obj[0])

            # Extract IPv4 gateway
            ipv4_gateway = ""
            ipv4_gw_obj = iface.get("IPv4DefaultGateway")
            if ipv4_gw_obj:
                if isinstance(ipv4_gw_obj, dict):
                    ipv4_gateway = ipv4_gw_obj.get("NextHop", "")
                elif isinstance(ipv4_gw_obj, list) and ipv4_gw_obj:
                    ipv4_gateway = ipv4_gw_obj[0].get("NextHop", "") if isinstance(ipv4_gw_obj[0], dict) else str(ipv4_gw_obj[0])

            # Extract IPv6 address
            ipv6_addr = ""
            ipv6_obj = iface.get("IPv6Address")
            if ipv6_obj:
                if isinstance(ipv6_obj, dict):
                    ipv6_addr = ipv6_obj.get("IPAddress", "")
                elif isinstance(ipv6_obj, list) and ipv6_obj:
                    ipv6_addr = ipv6_obj[0].get("IPAddress", "") if isinstance(ipv6_obj[0], dict) else str(ipv6_obj[0])

            info["interfaces"].append(
                {
                    "interface": interface_alias,
                    "ipv4_address": ipv4_addr,
                    "ipv4_gateway": ipv4_gateway,
                    "ipv6_address": ipv6_addr,
                }
            )

        return info
    except (json.JSONDecodeError, ValueError, KeyError, TypeError):
        return info


def _parse_dns_config(json_output: str) -> dict:
    """Parse PowerShell JSON output from Get-DnsClientServerAddress."""
    info = {"servers": []}

    if not json_output.strip():
        return info

    try:
        # Handle both single object and array
        data = json.loads(json_output)
        if not isinstance(data, list):
            data = [data]

        for item in data:
            servers = item.get("ServerAddresses", [])
            if isinstance(servers, list):
                info["servers"].extend(servers)

        # Remove duplicates while preserving order
        seen = set()
        unique_servers = []
        for server in info["servers"]:
            if server not in seen:
                seen.add(server)
                unique_servers.append(server)
        info["servers"] = unique_servers

        return info
    except (json.JSONDecodeError, ValueError, KeyError, TypeError):
        return info
