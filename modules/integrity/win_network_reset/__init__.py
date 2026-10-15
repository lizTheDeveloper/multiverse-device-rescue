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
    name = "win_network_reset"
    category = "integrity"
    platforms = [Platform.WIN32]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "15s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Check Winsock catalog integrity
        winsock_finding = self._check_winsock_catalog()
        if winsock_finding:
            findings.append(winsock_finding)

        # Check TCP/IP parameters
        tcp_findings = self._check_tcp_ip_parameters()
        findings.extend(tcp_findings)

        # Check for residual LSP entries
        lsp_finding = self._check_lsp_entries()
        if lsp_finding:
            findings.append(lsp_finding)

        # Check DNS client service
        dns_finding = self._check_dns_service()
        if dns_finding:
            findings.append(dns_finding)

        # Check DHCP client service
        dhcp_finding = self._check_dhcp_service()
        if dhcp_finding:
            findings.append(dhcp_finding)

        # Add summary info about network stack health
        summary_finding = self._network_stack_summary(len(findings))
        if summary_finding:
            findings.append(summary_finding)

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            check_type = finding.data.get("check_type")

            if check_type == "winsock_catalog":
                actions.append(
                    Action(
                        title="Winsock catalog has unusual provider count",
                        description=(
                            "The Winsock catalog contains an unusual number of providers, "
                            "which may indicate Layered Service Provider (LSP) contamination from old software or malware. "
                            "To reset the Winsock catalog, open Command Prompt as Administrator and run: "
                            "netsh winsock reset catalog"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif check_type == "tcp_ip_params":
                actions.append(
                    Action(
                        title="TCP/IP parameters have unusual modifications",
                        description=(
                            f"{finding.description} "
                            "These unusual settings may cause network stack problems. "
                            "To reset TCP/IP parameters, open Command Prompt as Administrator and run: "
                            "netsh int ip reset"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif check_type == "lsp_entries":
                actions.append(
                    Action(
                        title="Residual LSP entries detected",
                        description=(
                            "Layered Service Provider (LSP) entries were found in the registry. "
                            "These may be left over from old software or malware. "
                            "To clean up LSP entries, open Command Prompt as Administrator and run: "
                            "netsh winsock reset catalog"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif check_type == "dns_service":
                actions.append(
                    Action(
                        title="DNS Client service is not running",
                        description=(
                            "The DNS Client (Dnscache) service is stopped. "
                            "This service is required for DNS name resolution. "
                            "To restart it, open Services and set 'DNS Client' to running, "
                            "or use: net start Dnscache"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif check_type == "dhcp_service":
                actions.append(
                    Action(
                        title="DHCP Client service is not running",
                        description=(
                            "The DHCP Client service is stopped. "
                            "This service is required for automatic IP configuration. "
                            "To restart it, open Services and set 'DHCP Client' to running, "
                            "or use: net start Dhcp"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _check_winsock_catalog(self) -> Optional[Finding]:
        """Check Winsock catalog integrity and provider count."""
        try:
            result = subprocess.run(
                ["netsh", "winsock", "show", "catalog"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                return None

            output = result.stdout
            # Count provider entries in the output
            provider_count = output.count("Item : ")

            # More than 30 providers suggests LSP contamination
            if provider_count > 30:
                return Finding(
                    title=f"Your network settings have {provider_count} extra components",
                    description=(
                        "Your computer's network system usually has about 30 components. "
                        f"Yours has {provider_count}. This often happens when old software "
                        "(old VPNs, antivirus or other networking tools) leaves behind extra parts that slow down your "
                        "internet.\n\n"
                        "What to do: This usually fixes itself with a system reset. If "
                        "your internet is acting up, use Settings > Network & internet > "
                        "Advanced network settings > Network reset."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "check_type": "winsock_catalog",
                        "provider_count": provider_count,
                    },
                )

            return Finding(
                title=f"Winsock catalog has {provider_count} providers (normal)",
                description=(
                    f"The Winsock catalog contains {provider_count} providers. "
                    "This is a normal count for a healthy network stack."
                ),
                severity=Severity.INFO,
                category=self.category,
                data={
                    "check_type": "winsock_catalog_info",
                    "provider_count": provider_count,
                },
            )
        except (subprocess.TimeoutExpired, OSError):
            return None

    def _check_tcp_ip_parameters(self) -> list[Finding]:
        """Check TCP/IP parameters via registry query."""
        findings = []
        try:
            result = subprocess.run(
                ["reg", "query", r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                return findings

            output = result.stdout
            unusual_params = []

            # Check for unusual TCP/IP parameters that suggest corruption
            if "KeepAliveTime" in output:
                unusual_params.append("KeepAliveTime (manually modified)")
            if "TcpTimedWaitDelay" in output:
                unusual_params.append("TcpTimedWaitDelay (manually modified)")
            if "TcpMaxDataRetransmissions" in output:
                unusual_params.append("TcpMaxDataRetransmissions (manually modified)")

            if unusual_params:
                findings.append(
                    Finding(
                        title="Some network settings were changed manually",
                        description=(
                            f"We found manual changes to your network settings: {', '.join(unusual_params)}. "
                            "People sometimes change these to try and fix slow internet, "
                            "but it can backfire and cause errors.\n\n"
                            "What to do: If your internet is working well, leave it alone. "
                            "If you are having trouble, use Settings > Network & internet > "
                            "Advanced network settings > Network reset."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={
                            "check_type": "tcp_ip_params",
                            "unusual_params": unusual_params,
                        },
                    )
                )
            else:
                findings.append(
                    Finding(
                        title="TCP/IP parameters appear normal",
                        description=(
                            "TCP/IP parameters are at their default values, indicating a healthy configuration."
                        ),
                        severity=Severity.INFO,
                        category=self.category,
                        data={"check_type": "tcp_ip_params_info"},
                    )
                )

        except (subprocess.TimeoutExpired, OSError):
            pass

        return findings

    def _check_lsp_entries(self) -> Optional[Finding]:
        """Check for residual Layered Service Provider (LSP) entries."""
        try:
            result = subprocess.run(
                ["reg", "query", r"HKLM\SYSTEM\CurrentControlSet\Services\Winsock2\Parameters\Protocol_Catalog9\Catalog_Entries"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                return None

            output = result.stdout
            # Count protocol entries (each entry is typically named Entry_NNN)
            entry_count = output.count("Entry_")

            # Large number of entries may indicate LSP remnants
            if entry_count > 20:
                return Finding(
                    title=f"Found {entry_count} leftover network rules",
                    description=(
                        f"Your system has {entry_count} leftover rules for how it handles "
                        "internet traffic. This is higher than normal and usually means "
                        "old networking software didn't clean up properly. These "
                        "leftovers can cause slow or unstable connections.\n\n"
                        "What to do: If your internet is working fine, you can ignore "
                        "this. If you have connection issues, use Settings > Network & "
                        "internet > Advanced network settings > Network reset."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "check_type": "lsp_entries",
                        "entry_count": entry_count,
                    },
                )

            return None
        except (subprocess.TimeoutExpired, OSError):
            return None

    def _check_dns_service(self) -> Optional[Finding]:
        """Check DNS Client (Dnscache) service status."""
        try:
            result = subprocess.run(
                ["powershell", "-Command", "Get-Service Dnscache | Select-Object Status"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                output = result.stdout.lower()
                if "running" not in output:
                    return Finding(
                        title="Your computer's name-lookup service is off",
                        description=(
                            "A service that translates website names into addresses is "
                            "currently stopped. Without it, your computer might struggle "
                            "to open websites or connect to online services.\n\n"
                            "What to do: Search for 'Services' in the Start menu, find "
                            "'DNS Client', right-click it, and select 'Start'."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={"check_type": "dns_service"},
                    )
                else:
                    return Finding(
                        title="DNS Client service is running",
                        description="The DNS Client (Dnscache) service is running normally.",
                        severity=Severity.INFO,
                        category=self.category,
                        data={"check_type": "dns_service_info"},
                    )

        except (subprocess.TimeoutExpired, OSError):
            return None

        return None

    def _check_dhcp_service(self) -> Optional[Finding]:
        """Check DHCP Client service status."""
        try:
            result = subprocess.run(
                ["powershell", "-Command", "Get-Service Dhcp | Select-Object Status"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                output = result.stdout.lower()
                if "running" not in output:
                    return Finding(
                        title="Your computer's address-assignment service is off",
                        description=(
                            "A service that automatically gives your computer an internet "
                            "address is currently stopped. This can prevent you from connecting "
                            "to Wi-Fi or the internet at all.\n\n"
                            "What to do: Search for 'Services' in the Start menu, find "
                            "'DHCP Client', right-click it, and select 'Start'."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={"check_type": "dhcp_service"},
                    )
                else:
                    return Finding(
                        title="DHCP Client service is running",
                        description="The DHCP Client service is running normally.",
                        severity=Severity.INFO,
                        category=self.category,
                        data={"check_type": "dhcp_service_info"},
                    )

        except (subprocess.TimeoutExpired, OSError):
            return None

        return None

    def _network_stack_summary(self, issue_count: int) -> Optional[Finding]:
        """Generate a summary finding about network stack health."""
        warning_count = 0
        if issue_count > 0:
            # In a real scenario, we'd track warnings vs info
            # For now, just provide summary
            return Finding(
                title="Network stack health check complete",
                description=(
                    f"Network stack integrity check found {issue_count} item(s) to review. "
                    "A healthy network stack is essential for internet connectivity. "
                    "If internet connectivity is failing despite basic checks passing, "
                    "network stack corruption may be the cause."
                ),
                severity=Severity.INFO,
                category=self.category,
                data={
                    "check_type": "network_summary",
                    "total_items": issue_count,
                },
            )
        return None
