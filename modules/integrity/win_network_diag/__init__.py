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
    name = "win_network_diag"
    category = "integrity"
    platforms = [Platform.WIN32]
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

        # Check IP configuration
        ip_findings = self._check_ip_configuration()
        findings.extend(ip_findings)

        # Check network connectivity
        connectivity_finding = self._check_network_connectivity()
        if connectivity_finding:
            findings.append(connectivity_finding)

        # Check proxy settings
        proxy_findings = self._check_proxy_settings()
        findings.extend(proxy_findings)

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
                            "or a firewall blocking DNS traffic. "
                            "Try: (1) check your internet connection, "
                            "(2) restart your router, "
                            "(3) manually set DNS servers (e.g., 8.8.8.8, 1.1.1.1) in Network Settings"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif check_type == "ip_configuration":
                reason = finding.data.get("reason", "Unknown")
                actions.append(
                    Action(
                        title=f"IP configuration issue: {reason}",
                        description=(
                            f"{reason}. "
                            f"Try: (1) run 'ipconfig /renew' in Command Prompt as Administrator, "
                            f"(2) disable and re-enable the network adapter, "
                            f"(3) restart your computer, "
                            f"(4) check Device Manager for network adapter drivers."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif check_type == "network_connectivity":
                actions.append(
                    Action(
                        title="Network connectivity check failed",
                        description=(
                            "The system cannot reach external networks. "
                            "This indicates a network connectivity issue. "
                            "Try: (1) check your internet connection, "
                            "(2) verify the network adapter is connected, "
                            "(3) restart your router and modem, "
                            "(4) check Windows Firewall settings."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif check_type == "proxy_settings":
                actions.append(
                    Action(
                        title="Proxy settings detected",
                        description=(
                            "A proxy is configured on this system. "
                            "If you don't need a proxy, consider disabling it. "
                            "Go to Settings > Network & Internet > Proxy to review or change settings."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
        return FixResult(module_name=self.name, actions=actions)

    def _check_dns_resolution(self) -> Optional[Finding]:
        """Check if DNS resolution works for a known domain."""
        try:
            result = subprocess.run(
                ["nslookup", "google.com"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                return None  # DNS works
            else:
                return Finding(
                    title="DNS resolution failed",
                    description=(
                        "Cannot resolve google.com via nslookup. DNS resolution is not working. "
                        "This prevents access to any domain-based services."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check_type": "dns_resolution"},
                )
        except (subprocess.TimeoutExpired, OSError):
            return Finding(
                title="DNS resolution check failed",
                description=(
                    "Could not run nslookup command. DNS resolution check could not complete."
                ),
                severity=Severity.WARNING,
                category=self.category,
                data={"check_type": "dns_resolution"},
            )

    def _check_ip_configuration(self) -> list[Finding]:
        """Check IP configuration via ipconfig /all."""
        findings = []
        try:
            result = subprocess.run(
                ["ipconfig", "/all"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode != 0:
                return findings

            output = result.stdout
            # Parse IP configuration from ipconfig output
            has_ipv4 = False
            has_dns_servers = False
            dns_servers = []

            for line in output.split("\n"):
                # Check for IPv4 address
                if "IPv4 Address" in line:
                    has_ipv4 = True
                # Check for DNS servers
                if "DNS Servers" in line or "nameserver" in line.lower():
                    has_dns_servers = True
                    # Extract DNS server IPs
                    parts = line.split(":")
                    if len(parts) > 1:
                        ip = parts[1].strip()
                        if ip and ip not in dns_servers:
                            dns_servers.append(ip)

            # Flag if no IPv4 address is configured
            if not has_ipv4:
                findings.append(
                    Finding(
                        title="No IPv4 address configured",
                        description=(
                            "No IPv4 address is configured on this system. "
                            "This prevents network connectivity."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={
                            "check_type": "ip_configuration",
                            "reason": "No IPv4 address found",
                        },
                    )
                )

            # Flag if no DNS servers are configured
            if not has_dns_servers:
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
                            "check_type": "ip_configuration",
                            "reason": "No DNS servers found",
                        },
                    )
                )

        except (subprocess.TimeoutExpired, OSError):
            pass

        return findings

    def _check_network_connectivity(self) -> Optional[Finding]:
        """Check network connectivity via ping to 8.8.8.8."""
        try:
            result = subprocess.run(
                ["ping", "-n", "1", "8.8.8.8"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                return None  # Network is reachable
            else:
                return Finding(
                    title="No network connectivity",
                    description=(
                        "Cannot ping external server (8.8.8.8). "
                        "This indicates a network connectivity issue."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check_type": "network_connectivity"},
                )
        except (subprocess.TimeoutExpired, OSError):
            return Finding(
                title="Network connectivity check failed",
                description=(
                    "Could not run ping command. Network connectivity check could not complete."
                ),
                severity=Severity.WARNING,
                category=self.category,
                data={"check_type": "network_connectivity"},
            )

    def _check_proxy_settings(self) -> list[Finding]:
        """Check for proxy settings via netsh winhttp show proxy."""
        findings = []
        try:
            result = subprocess.run(
                ["netsh", "winhttp", "show", "proxy"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode == 0:
                output = result.stdout
                # Check if a proxy is configured (look for proxy server setting)
                if "Direct access" not in output and (":" in output and "//" not in output):
                    # Likely has a proxy configured
                    findings.append(
                        Finding(
                            title="Proxy settings detected",
                            description=(
                                "A proxy is configured on this system via WinHTTP settings. "
                                "This may affect network connectivity if not properly configured."
                            ),
                            severity=Severity.INFO,
                            category=self.category,
                            data={"check_type": "proxy_settings"},
                        )
                    )
        except (subprocess.TimeoutExpired, OSError):
            pass

        return findings
