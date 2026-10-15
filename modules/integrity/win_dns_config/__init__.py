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
                        title=(
                            "Your computer uses your internet provider's name lookup "
                            f"({', '.join(dns_servers)})"
                        ),
                        description=(
                            "Your computer is using DNS servers provided by your internet "
                            f"service provider: {', '.join(dns_servers)}. DNS is the system "
                            "that turns website names into addresses. Using your provider's "
                            "servers is normal, but they can sometimes be slower or less "
                            "private than public options.\n\n"
                            "What to do: If you want faster or more private browsing, "
                            "open Settings > Network & internet > DNS settings. You can "
                            "manually set the DNS to 1.1.1.1 (Cloudflare) or 8.8.8.8 "
                            "(Google)."
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
                    title="We could not test your internet name lookup",
                    description=(
                        "We tried to check if your computer can translate website names "
                        "into addresses, but the test failed. This usually means your "
                        "internet connection is currently unstable or your DNS settings "
                        "are misconfigured.\n\n"
                        "What to do: Check that your Wi-Fi or Ethernet cable is connected. "
                        "If you are online, restart your router. If the problem persists, "
                        "open Settings > Network & internet > DNS settings to ensure they "
                        "are set to 'Automatic'."
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
                            title=f"Your internet name lookup is slow ({time_ms:.0f}ms)",
                            description=(
                                f"Translating website names into addresses took {time_ms:.0f} "
                                "milliseconds. This is slower than ideal (under 500ms) "
                                "and might make web pages load a bit slower.\n\n"
                                "What to do: Check your internet connection stability. "
                                "If it's consistently slow, open Settings > Network & "
                                "internet > DNS settings and try switching to a public "
                                "DNS like 1.1.1.1 or 8.8.8.8."
                            ),
                            severity=Severity.WARNING,
                            category=self.category,
                            data={"check_type": "dns_resolution", "time_ms": time_ms},
                        )
                except ValueError:
                    pass

        except (subprocess.TimeoutExpired, OSError):
            return Finding(
                title="Your internet name lookup took too long",
                description=(
                    "The test to check your internet connection took longer than expected "
                    "to finish. This suggests your DNS servers (which translate website "
                    "names into addresses) are slow or unresponsive right now.\n\n"
                    "What to do: Try restarting your router. If the slowness continues, "
                    "open Settings > Network & internet > DNS settings and consider switching "
                    "to a public DNS provider like 1.1.1.1 or 8.8.8.8 for better speed."
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
