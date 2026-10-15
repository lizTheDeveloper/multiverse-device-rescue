import re
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
    name = "network_interface_audit"
    category = "integrity"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "5s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Get all network interfaces and their info
        interfaces_data = self._get_interfaces_and_ips()
        if not interfaces_data:
            return CheckResult(module_name=self.name, findings=findings)

        # Check for self-assigned IPs (DHCP failure)
        dhcp_findings = self._check_self_assigned_ips(interfaces_data)
        findings.extend(dhcp_findings)

        # Check for duplicate IPs
        duplicate_findings = self._check_duplicate_ips(interfaces_data)
        findings.extend(duplicate_findings)

        # Check interface priority
        priority_finding = self._check_wifi_priority()
        if priority_finding:
            findings.append(priority_finding)

        # Add INFO finding with all interfaces status
        info_finding = self._list_all_interfaces(interfaces_data)
        if info_finding:
            findings.append(info_finding)

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            check_type = finding.data.get("check_type")
            if check_type == "self_assigned_ip":
                interface = finding.data.get("interface", "Unknown")
                ip = finding.data.get("ip", "Unknown")
                actions.append(
                    Action(
                        title=f"Interface {interface} has self-assigned IP {ip}",
                        description=(
                            f"Interface {interface} is using a self-assigned IP address ({ip}), "
                            f"which indicates a DHCP failure. The interface cannot reach a DHCP server "
                            f"and has automatically assigned itself a non-routable IP. "
                            f"Try: (1) toggle Wi-Fi/Ethernet off and on, "
                            f"(2) forget and rejoin the network, "
                            f"(3) restart the router and wait for reconnection, "
                            f"(4) use System Settings > Network to manually assign a static IP."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif check_type == "duplicate_ip":
                ip = finding.data.get("ip", "Unknown")
                interfaces = finding.data.get("interfaces", [])
                actions.append(
                    Action(
                        title=f"Duplicate IP address {ip} on multiple interfaces",
                        description=(
                            f"Multiple network interfaces are assigned the same IP address {ip}: "
                            f"{', '.join(interfaces)}. This creates IP conflicts and network confusion. "
                            f"Try: (1) check System Settings > Network for each interface, "
                            f"(2) ensure only one interface is set to use the same IP, "
                            f"(3) use unique DHCP-assigned IPs for active interfaces, "
                            f"(4) disable or unpair unused network interfaces."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif check_type == "wifi_priority":
                actions.append(
                    Action(
                        title="Wi-Fi is not the top priority network service",
                        description=(
                            "Wi-Fi is not the highest priority network service, which may cause "
                            "the system to prefer other network interfaces unexpectedly. "
                            "Try: (1) System Settings > Network > Wi-Fi, "
                            "(2) Ethernet (if using), and other services, "
                            "(3) or use networksetup -ordernetworkservices to reorder manually. "
                            "(4) Consider disabling unused network services like Bluetooth or VPN "
                            "if they are interfering."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif check_type == "interfaces_list":
                actions.append(
                    Action(
                        title="Network interfaces status",
                        description=finding.data.get("description", ""),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
        return FixResult(module_name=self.name, actions=actions)

    def _get_interfaces_and_ips(self) -> dict:
        """Get all network interfaces and their IP addresses."""
        interfaces_data = {}
        try:
            # Get list of all network services
            result = subprocess.run(
                ["networksetup", "-listallnetworkservices"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode != 0:
                return interfaces_data

            services = [
                s.strip()
                for s in result.stdout.split("\n")
                if s.strip() and not s.startswith("*")
            ]

            # Get info for each service
            for service in services:
                try:
                    info_result = subprocess.run(
                        ["networksetup", "-getinfo", service],
                        capture_output=True,
                        text=True,
                        timeout=5,
                    )
                    if info_result.returncode == 0:
                        interfaces_data[service] = self._parse_network_info(
                            info_result.stdout
                        )
                except (subprocess.TimeoutExpired, OSError):
                    pass

        except (subprocess.TimeoutExpired, OSError):
            pass

        return interfaces_data

    def _parse_network_info(self, output: str) -> dict:
        """Parse networksetup -getinfo output."""
        info = {
            "ip": None,
            "subnet": None,
            "router": None,
            "status": "Unknown",
        }
        for line in output.split("\n"):
            line = line.strip()
            if line.startswith("IP Address:"):
                info["ip"] = line.split(":", 1)[1].strip()
            elif line.startswith("Subnet Mask:"):
                info["subnet"] = line.split(":", 1)[1].strip()
            elif line.startswith("Router:"):
                info["router"] = line.split(":", 1)[1].strip()
        return info

    def _check_self_assigned_ips(self, interfaces_data: dict) -> list[Finding]:
        """Check for self-assigned IPs (169.254.x.x), indicating DHCP failure."""
        findings = []
        for service, info in interfaces_data.items():
            ip = info.get("ip")
            if ip and ip.startswith("169.254."):
                findings.append(
                    Finding(
                        title=(
                            f"Your {service} connection is using a temporary address ({ip})"
                        ),
                        description=(
                            f"Your {service} connection is using a temporary address ({ip}) "
                            "instead of a normal one. This usually happens when your "
                            "computer can't reach the router to get a proper address. "
                            "You likely won't be able to use the internet on this connection "
                            "until it is fixed.\n\n"
                            "What to do: Restart your Wi-Fi or Ethernet connection, or "
                            "restart your router. If it persists, check that your router "
                            "is working."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={
                            "check_type": "self_assigned_ip",
                            "interface": service,
                            "ip": ip,
                        },
                    )
                )
        return findings

    def _check_duplicate_ips(self, interfaces_data: dict) -> list[Finding]:
        """Check for duplicate IP addresses across interfaces."""
        findings = []
        ip_to_services = {}

        for service, info in interfaces_data.items():
            ip = info.get("ip")
            if ip and ip != "":
                if ip not in ip_to_services:
                    ip_to_services[ip] = []
                ip_to_services[ip].append(service)

        # Find duplicates
        for ip, services in ip_to_services.items():
            if len(services) > 1:
                findings.append(
                    Finding(
                        title=f"Two connections are using the same address ({ip})",
                        description=(
                            f"Your computer has two connections ({', '.join(services)}) "
                            f"using the same address ({ip}). This can cause your internet "
                            "to be slow or unstable because the computer gets confused "
                            "about which connection to use.\n\n"
                            "What to do: Turn off the connection you don't need (like "
                            "Bluetooth or a USB network adapter) in System Settings > "
                            "Network. If you need both, a network professional can help "
                            "assign them different addresses."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={
                            "check_type": "duplicate_ip",
                            "ip": ip,
                            "interfaces": services,
                        },
                    )
                )
        return findings

    def _check_wifi_priority(self) -> Optional[Finding]:
        """Check if Wi-Fi is the top priority network service."""
        try:
            result = subprocess.run(
                ["networksetup", "-listnetworkserviceorder"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode != 0:
                return None

            output = result.stdout
            # Parse the order output - Wi-Fi should ideally be first or high priority
            lines = output.split("\n")
            for line in lines:
                if "Wi-Fi" in line and "1)" in line:
                    # Wi-Fi is first, which is good
                    return None
                elif "Wi-Fi" in line:
                    # Wi-Fi exists but is not first
                    return Finding(
                        title="Wi-Fi is not your top priority connection",
                        description=(
                            "Your computer is set to use other connections (like Ethernet "
                            "or Bluetooth) before Wi-Fi. This might cause unexpected behavior "
                            "if you have multiple connections active at once.\n\n"
                            "What to do: If you mostly use Wi-Fi, you can change the order "
                            "in System Settings > Network: click the ... button below the "
                            "list, choose Set Service Order, and drag Wi-Fi to the top."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={"check_type": "wifi_priority"},
                    )

        except (subprocess.TimeoutExpired, OSError):
            pass

        return None

    def _list_all_interfaces(self, interfaces_data: dict) -> Optional[Finding]:
        """Create an INFO finding listing all interfaces and their status."""
        if not interfaces_data:
            return None

        interface_lines = []
        for service, info in interfaces_data.items():
            ip = info.get("ip") or "Not assigned"
            subnet = info.get("subnet") or "N/A"
            router = info.get("router") or "N/A"
            interface_lines.append(
                f"  - {service}: IP={ip}, Subnet={subnet}, Router={router}"
            )

        description = "Configured network interfaces:\n" + "\n".join(
            interface_lines
        )

        return Finding(
            title="Network interfaces configuration",
            description=description,
            severity=Severity.INFO,
            category=self.category,
            data={
                "check_type": "interfaces_list",
                "description": description,
            },
        )
