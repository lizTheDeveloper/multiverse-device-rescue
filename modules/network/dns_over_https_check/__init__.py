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
    name = "dns_over_https_check"
    category = "network"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "5s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Get DNS configuration from system
        dns_servers = self._get_dns_servers()
        profile_status = self._check_encrypted_dns_profiles()
        local_resolver = self._check_local_resolver()
        doh_status = self._check_doh_configuration()

        # Analyze DNS servers
        if dns_servers:
            encryption_info = self._analyze_dns_encryption(dns_servers)

            # Add finding about DNS servers and encryption status
            findings.append(
                Finding(
                    title="DNS server configuration detected",
                    description=(
                        f"System DNS servers: {', '.join(dns_servers)}\n"
                        f"Encryption status: {encryption_info['status']}\n"
                        f"Configuration source: {encryption_info['source']}"
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "check": "dns_configuration",
                        "servers": dns_servers,
                        "encryption_status": encryption_info["status"],
                        "is_encrypted": encryption_info["is_encrypted"],
                        "provider": encryption_info.get("provider_name"),
                        "source": encryption_info["source"],
                    },
                )
            )

            # Warn if using ISP DNS (unencrypted)
            if not encryption_info["is_encrypted"]:
                findings.append(
                    Finding(
                        title="Unencrypted DNS detected - ISP can monitor queries",
                        description=(
                            "Your system is using unencrypted DNS (likely ISP-provided). "
                            "This exposes all your browsing activity to your ISP and network attackers. "
                            "Anyone on the network can see which websites you visit. "
                            "Consider switching to encrypted DNS (DoH/DoT) or a privacy-focused provider."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={
                            "check": "unencrypted_dns",
                            "servers": dns_servers,
                        },
                    )
                )
            elif encryption_info["is_known_provider"]:
                # Using known encrypted provider
                findings.append(
                    Finding(
                        title="Known encrypted DNS provider in use",
                        description=(
                            f"Detected use of {encryption_info['provider_name']} DNS. "
                            "This provider supports encryption, but system-level DNS-over-HTTPS "
                            "or DNS-over-TLS may not be configured."
                        ),
                        severity=Severity.INFO,
                        category=self.category,
                        data={
                            "check": "encrypted_dns_provider",
                            "provider": encryption_info["provider_name"],
                            "servers": dns_servers,
                        },
                    )
                )
        else:
            findings.append(
                Finding(
                    title="Unable to determine DNS configuration",
                    description="Could not read system DNS settings.",
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "no_dns_found"},
                )
            )

        # Check for encrypted DNS profiles
        if profile_status["has_profile"]:
            findings.append(
                Finding(
                    title="Encrypted DNS profile installed",
                    description=(
                        "An encrypted DNS configuration profile is installed. "
                        f"Profile details: {profile_status.get('profile_info', 'Unknown')}"
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "check": "encrypted_dns_profile",
                        "profile_info": profile_status.get("profile_info"),
                    },
                )
            )

        # Check for local DNS resolver
        if local_resolver["running"]:
            findings.append(
                Finding(
                    title="Local DNS resolver detected",
                    description=(
                        f"Local DNS resolver '{local_resolver['process']}' is running. "
                        "This can provide encryption for DNS queries if properly configured."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "check": "local_dns_resolver",
                        "process": local_resolver["process"],
                    },
                )
            )

        # Check for DNS-over-HTTPS/TLS configuration
        if doh_status["configured"]:
            findings.append(
                Finding(
                    title="DNS-over-HTTPS/TLS configuration found",
                    description=(
                        "System has DNS-over-HTTPS or DNS-over-TLS configuration. "
                        f"Details: {doh_status.get('details', 'Unknown')}"
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "check": "doh_tls_configured",
                        "details": doh_status.get("details"),
                    },
                )
            )

        # Warn if no encryption is configured at all
        if (
            dns_servers
            and not profile_status["has_profile"]
            and not local_resolver["running"]
            and not doh_status["configured"]
        ):
            if not self._is_known_encrypted_provider(dns_servers):
                findings.append(
                    Finding(
                        title="No DNS encryption configuration detected",
                        description=(
                            "No encrypted DNS (DoH/DoT) profiles, local resolvers, or "
                            "known encrypted DNS providers are configured. "
                            "Your DNS queries may be exposed to monitoring."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={"check": "no_encryption_configured"},
                    )
                )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        """Provide informational guidance on configuring encrypted DNS."""
        actions = []

        for finding in findings.findings:
            check_type = finding.data.get("check")

            if check_type == "unencrypted_dns":
                title = "Configure encrypted DNS"
                description = (
                    "To enable DNS-over-HTTPS on macOS:\n"
                    "1. Open System Settings > Network\n"
                    "2. Select your active network connection\n"
                    "3. Click 'Details...'\n"
                    "4. Go to 'DNS' tab\n"
                    "5. Click '+' to add DNS servers\n"
                    "6. Add Cloudflare (1.1.1.1, 1.0.0.1), Google (8.8.8.8, 8.8.4.4), or Quad9 (9.9.9.9, 149.112.112.112)\n"
                    "7. macOS will automatically use DoH for compatible providers\n"
                    "\n"
                    "Alternatively, install a configuration profile for encrypted DNS:\n"
                    "- Check your DNS provider's website for a macOS profile\n"
                    "- Import the profile in System Settings > General > Profiles\n"
                    "- Restart your computer for changes to take effect"
                )

            elif check_type == "encrypted_dns_provider":
                provider = finding.data.get("provider", "the provider")
                title = f"Verify {provider} DoH/DoT configuration"
                description = (
                    f"Your system is using {provider} DNS. To ensure DNS-over-HTTPS/TLS is active:\n"
                    "1. Verify in System Settings > Network > DNS settings\n"
                    "2. Check that the connection uses DoH/DoT (look for lock icon)\n"
                    "3. Some applications override system DNS - check app-specific settings\n"
                    "4. Test DNS encryption at: https://1.1.1.1/help or similar tools"
                )

            elif check_type == "no_encryption_configured":
                title = "Install encrypted DNS configuration"
                description = (
                    "To add encrypted DNS protection:\n"
                    "\n"
                    "Option 1: Change system DNS\n"
                    "1. Open System Settings > Network\n"
                    "2. Select your network and click 'Details...'\n"
                    "3. Go to 'DNS' tab\n"
                    "4. Add Cloudflare (1.1.1.1), Google (8.8.8.8), or Quad9 (9.9.9.9)\n"
                    "\n"
                    "Option 2: Install a DNS profile\n"
                    "1. Visit providers like Cloudflare, NextDNS, or AdGuard\n"
                    "2. Download their macOS configuration profile\n"
                    "3. Double-click to install\n"
                    "4. Approve in System Settings > General > Profiles\n"
                    "\n"
                    "Option 3: Install a local DNS resolver\n"
                    "1. Install dnscrypt-proxy or stubby via Homebrew\n"
                    "2. Configure for your preferred encrypted DNS provider\n"
                    "3. Set system DNS to 127.0.0.1 to route through the resolver"
                )

            elif check_type in (
                "encrypted_dns_profile",
                "local_dns_resolver",
                "doh_tls_configured",
                "dns_configuration",
            ):
                # No action needed for these informational findings
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

    def _get_dns_servers(self) -> list[str]:
        """Get DNS servers from system configuration via scutil --dns."""
        try:
            result = subprocess.run(
                ["scutil", "--dns"],
                capture_output=True,
                text=True,
                timeout=5,
            )

            if result.returncode != 0:
                return []

            servers = []
            for line in result.stdout.split("\n"):
                if "nameserver[" in line:
                    # Extract IP address: look for pattern "nameserver[n]: x.x.x.x"
                    match = re.search(r":\s*([\d.]+|[a-f0-9:]+)", line)
                    if match:
                        server = match.group(1)
                        if server not in servers:
                            servers.append(server)

            return servers
        except (subprocess.SubprocessError, Exception):
            return []

    def _analyze_dns_encryption(self, servers: list[str]) -> dict:
        """Analyze if DNS servers support encryption."""
        if not servers:
            return {
                "status": "No DNS servers found",
                "is_encrypted": False,
                "is_known_provider": False,
                "provider_name": None,
                "source": "Unknown",
            }

        # Known encrypted DNS providers
        encrypted_providers = {
            "Cloudflare": ["1.1.1.1", "1.0.0.1"],
            "Google": ["8.8.8.8", "8.8.4.4"],
            "Quad9": ["9.9.9.9", "149.112.112.112"],
            "NextDNS": [],  # Multiple IPs, checked by domain/config
            "OpenDNS": ["208.67.222.222", "208.67.220.220"],
            "AdGuard": ["94.140.14.14", "94.140.15.15"],
        }

        # Check if any server is a known encrypted provider
        provider_found = None
        for provider, provider_ips in encrypted_providers.items():
            if any(server in provider_ips for server in servers):
                provider_found = provider
                break

        # Check for ISP DNS (common patterns)
        isp_patterns = ["127.0.0.1", "192.168.", "10.", "172.16."]
        is_isp_dns = any(
            server.startswith(pattern) for server in servers for pattern in isp_patterns
        )

        if provider_found:
            return {
                "status": f"Known encrypted DNS provider: {provider_found}",
                "is_encrypted": True,
                "is_known_provider": True,
                "provider_name": provider_found,
                "source": "System DNS configuration",
            }
        elif is_isp_dns:
            return {
                "status": "ISP DNS (likely unencrypted)",
                "is_encrypted": False,
                "is_known_provider": False,
                "provider_name": None,
                "source": "System DNS configuration",
            }
        else:
            return {
                "status": "Unknown DNS provider",
                "is_encrypted": False,
                "is_known_provider": False,
                "provider_name": None,
                "source": "System DNS configuration",
            }

    def _check_encrypted_dns_profiles(self) -> dict:
        """Check if encrypted DNS profiles are installed."""
        try:
            result = subprocess.run(
                ["profiles", "list"],
                capture_output=True,
                text=True,
                timeout=5,
            )

            if result.returncode != 0:
                return {"has_profile": False, "profile_info": None}

            # Look for DNSSettings in profile output
            output_lower = result.stdout.lower()
            if "dnssettings" in output_lower or "dns" in output_lower:
                # Try to extract more info
                profile_info = None
                for line in result.stdout.split("\n"):
                    if "dns" in line.lower():
                        profile_info = line.strip()
                        break

                return {"has_profile": True, "profile_info": profile_info}

            return {"has_profile": False, "profile_info": None}
        except (subprocess.SubprocessError, Exception):
            return {"has_profile": False, "profile_info": None}

    def _check_local_resolver(self) -> dict:
        """Check if local DNS resolver (dnscrypt-proxy or stubby) is running."""
        try:
            result = subprocess.run(
                ["ps", "aux"],
                capture_output=True,
                text=True,
                timeout=5,
            )

            if result.returncode != 0:
                return {"running": False, "process": None}

            # Check for common local DNS resolvers
            resolvers = ["dnscrypt-proxy", "stubby"]

            for line in result.stdout.split("\n"):
                for resolver in resolvers:
                    if resolver in line and not line.strip().startswith("#"):
                        return {"running": True, "process": resolver}

            return {"running": False, "process": None}
        except (subprocess.SubprocessError, Exception):
            return {"running": False, "process": None}

    def _check_doh_configuration(self) -> dict:
        """Check if DNS-over-HTTPS or DNS-over-TLS is configured."""
        try:
            # Check /etc/resolv.conf for DoH/DoT nameservers
            with open("/etc/resolv.conf", "r") as f:
                content = f.read()

                # Look for DoH/DoT indicators
                if "https://" in content or "tls://" in content:
                    return {
                        "configured": True,
                        "details": "DoH/DoT found in resolver configuration",
                    }

        except (FileNotFoundError, OSError, Exception):
            pass

        # Check for profiles with DoH/DoT configuration
        try:
            result = subprocess.run(
                ["profiles", "list"],
                capture_output=True,
                text=True,
                timeout=5,
            )

            if result.returncode == 0:
                output_lower = result.stdout.lower()
                if "https" in output_lower or "tls" in output_lower:
                    return {
                        "configured": True,
                        "details": "DoH/DoT profile detected",
                    }
        except (subprocess.SubprocessError, Exception):
            pass

        return {"configured": False, "details": None}

    def _is_known_encrypted_provider(self, servers: list[str]) -> bool:
        """Check if any server is from a known encrypted DNS provider."""
        encrypted_providers = {
            "Cloudflare": ["1.1.1.1", "1.0.0.1"],
            "Google": ["8.8.8.8", "8.8.4.4"],
            "Quad9": ["9.9.9.9", "149.112.112.112"],
            "OpenDNS": ["208.67.222.222", "208.67.220.220"],
            "AdGuard": ["94.140.14.14", "94.140.15.15"],
        }

        for provider_ips in encrypted_providers.values():
            if any(server in provider_ips for server in servers):
                return True

        return False
