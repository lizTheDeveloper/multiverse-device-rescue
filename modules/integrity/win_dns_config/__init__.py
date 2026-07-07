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
    name = "win_dns_config"
    category = "integrity"
    platforms = [Platform.WIN32]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "5s"

    # Well-known public DNS servers
    WELL_KNOWN_DNS = {
        "8.8.8.8": "Google",
        "8.8.4.4": "Google",
        "1.1.1.1": "Cloudflare",
        "1.0.0.1": "Cloudflare",
        "9.9.9.9": "Quad9",
        "149.112.112.112": "Quad9",
    }

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Check DNS server configuration
        dns_config_finding = self._check_dns_servers()
        if dns_config_finding:
            findings.extend(dns_config_finding)

        # Check DNS resolution speed
        resolution_finding = self._check_dns_resolution()
        if resolution_finding:
            findings.append(resolution_finding)

        # Check DNS cache size
        cache_finding = self._check_dns_cache()
        if cache_finding:
            findings.append(cache_finding)

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            check_type = finding.data.get("check_type")
            if check_type == "isp_dns":
                dns_servers = finding.data.get("dns_servers", [])
                actions.append(
                    Action(
                        title="Using ISP default DNS servers",
                        description=(
                            f"Current DNS servers: {', '.join(dns_servers)}. "
                            "ISP DNS servers are often slow or unreliable. "
                            "Consider switching to public DNS alternatives: "
                            "1.1.1.1 (Cloudflare), 8.8.8.8 (Google), or 9.9.9.9 (Quad9). "
                            "To change: Settings > Network & Internet > Advanced network settings > "
                            "DNS server administration > Edit > Set to 'Manual' and enter the preferred DNS IPs."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif check_type == "dns_resolution":
                actions.append(
                    Action(
                        title="DNS resolution issue detected",
                        description=(
                            "DNS resolution is slow or failing. "
                            "Try: (1) restart your router and modem, "
                            "(2) change to a faster public DNS provider (8.8.8.8 or 1.1.1.1), "
                            "(3) clear DNS cache with: 'ipconfig /flushdns' in Command Prompt as Administrator, "
                            "(4) run 'ipconfig /registerdns' to re-register DNS entries."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif check_type == "dns_cache_large":
                actions.append(
                    Action(
                        title="DNS cache is large",
                        description=(
                            "The DNS cache has grown large. "
                            "This can impact performance. "
                            "To clear the DNS cache, run 'ipconfig /flushdns' in Command Prompt as Administrator."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif check_type == "dns_info":
                dns_servers = finding.data.get("dns_servers", [])
                is_automatic = finding.data.get("is_automatic", False)
                actions.append(
                    Action(
                        title="DNS configuration information",
                        description=(
                            f"Configured DNS servers: {', '.join(dns_servers)}. "
                            f"Configuration type: {'Automatic (DHCP)' if is_automatic else 'Manual'}. "
                            "DNS is working properly and is configured with a recognized provider."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _check_dns_servers(self) -> Optional[list[Finding]]:
        """Check configured DNS servers via PowerShell Get-DnsClientServerAddress."""
        findings = []
        try:
            result = subprocess.run(
                [
                    "powershell",
                    "-NoProfile",
                    "-Command",
                    "Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object -ExpandProperty ServerAddresses",
                ],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode != 0:
                return findings

            output = result.stdout.strip()
            if not output:
                return findings

            dns_servers = [ip.strip() for ip in output.split("\n") if ip.strip()]
            if not dns_servers:
                return findings

            # Check if using ISP/default DNS (not well-known public DNS)
            using_isp_dns = all(ip not in self.WELL_KNOWN_DNS for ip in dns_servers)

            if using_isp_dns:
                findings.append(
                    Finding(
                        title="Using ISP default DNS servers",
                        description=(
                            f"Detected DNS servers: {', '.join(dns_servers)}. "
                            "These appear to be ISP-provided DNS servers, which can be slow or unreliable. "
                            "Consider switching to public DNS: 1.1.1.1 (Cloudflare), "
                            "8.8.8.8 (Google), or 9.9.9.9 (Quad9)."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={"check_type": "isp_dns", "dns_servers": dns_servers},
                    )
                )
            else:
                # Report using well-known DNS
                dns_providers = [
                    self.WELL_KNOWN_DNS.get(ip, ip) for ip in dns_servers
                ]
                findings.append(
                    Finding(
                        title="DNS configuration is optimal",
                        description=(
                            f"Using DNS servers from {', '.join(set(dns_providers))}: "
                            f"{', '.join(dns_servers)}. DNS configuration is good."
                        ),
                        severity=Severity.INFO,
                        category=self.category,
                        data={
                            "check_type": "dns_info",
                            "dns_servers": dns_servers,
                            "is_automatic": False,
                        },
                    )
                )

        except (subprocess.TimeoutExpired, OSError):
            pass

        return findings if findings else None

    def _check_dns_resolution(self) -> Optional[Finding]:
        """Test DNS resolution speed via PowerShell Resolve-DnsName."""
        try:
            result = subprocess.run(
                [
                    "powershell",
                    "-NoProfile",
                    "-Command",
                    "Measure-Command { Resolve-DnsName google.com } | Select-Object -ExpandProperty TotalMilliseconds",
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                return Finding(
                    title="DNS resolution test failed",
                    description=(
                        "Could not complete DNS resolution test. "
                        "This may indicate DNS servers are unreachable or unresponsive."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check_type": "dns_resolution"},
                )

            output = result.stdout.strip()
            if output:
                try:
                    time_ms = float(output)
                    # Flag if resolution is slow (>500ms)
                    if time_ms > 500:
                        return Finding(
                            title="DNS resolution is slow",
                            description=(
                                f"DNS resolution took {time_ms:.0f}ms (threshold: 500ms). "
                                "Slow DNS resolution can impact browsing and web application performance. "
                                "Consider switching to a faster DNS provider or checking network connectivity."
                            ),
                            severity=Severity.WARNING,
                            category=self.category,
                            data={"check_type": "dns_resolution", "time_ms": time_ms},
                        )
                except ValueError:
                    pass

        except (subprocess.TimeoutExpired, OSError):
            return Finding(
                title="DNS resolution check timed out",
                description=(
                    "DNS resolution test timed out. "
                    "This indicates DNS servers may be unresponsive."
                ),
                severity=Severity.WARNING,
                category=self.category,
                data={"check_type": "dns_resolution"},
            )

        return None

    def _check_dns_cache(self) -> Optional[Finding]:
        """Check DNS cache size via PowerShell Get-DnsClientCache."""
        try:
            result = subprocess.run(
                [
                    "powershell",
                    "-NoProfile",
                    "-Command",
                    "Get-DnsClientCache | Measure-Object | Select-Object -ExpandProperty Count",
                ],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode != 0:
                return None

            output = result.stdout.strip()
            if output:
                try:
                    cache_count = int(output)
                    # Flag if cache is very large (>5000 entries)
                    if cache_count > 5000:
                        return Finding(
                            title="DNS cache is large",
                            description=(
                                f"DNS cache contains {cache_count} entries. "
                                "A large cache can impact system performance. "
                                "Clear the cache with: ipconfig /flushdns (in Command Prompt as Administrator)."
                            ),
                            severity=Severity.INFO,
                            category=self.category,
                            data={"check_type": "dns_cache_large", "cache_count": cache_count},
                        )
                except ValueError:
                    pass

        except (subprocess.TimeoutExpired, OSError):
            pass

        return None
