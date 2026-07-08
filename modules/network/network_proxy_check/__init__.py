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
    name = "network_proxy_check"
    category = "network"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "3s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Get list of all network services
        interfaces = self._get_network_services()
        if not interfaces:
            return CheckResult(module_name=self.name, findings=[
                Finding(
                    title="Unable to retrieve network services",
                    description="Could not query network services using networksetup.",
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "network_query_failed"},
                )
            ])

        proxy_configs_found = {}

        for interface in interfaces:
            proxy_config = self._get_proxy_config(interface)
            if proxy_config is None:
                # Interface not available or command failed
                continue

            proxy_configs_found[interface] = proxy_config

            # Check for PAC URL - this is CRITICAL if it's a remote URL
            if proxy_config.get("pac_url"):
                pac_url = proxy_config["pac_url"]
                is_remote = self._is_remote_url(pac_url)

                if is_remote:
                    findings.append(
                        Finding(
                            title=f"Remote PAC URL configured on {interface} (CRITICAL)",
                            description=(
                                f"A remote Proxy Auto-Configuration (PAC) file URL is configured on {interface}: "
                                f"{pac_url}. Remote PAC files are a major malware indicator and commonly used "
                                f"by adware/malware to intercept network traffic. This is highly suspicious "
                                f"and should be removed immediately."
                            ),
                            severity=Severity.CRITICAL,
                            category=self.category,
                            data={
                                "check": "remote_pac_url",
                                "interface": interface,
                                "pac_url": pac_url,
                            },
                        )
                    )
                else:
                    # Local PAC URL - less critical but still suspicious
                    findings.append(
                        Finding(
                            title=f"PAC URL configured on {interface}",
                            description=(
                                f"A Proxy Auto-Configuration (PAC) file URL is configured on {interface}: "
                                f"{pac_url}. PAC files are typically used in corporate environments. "
                                f"On home machines, this may indicate misconfiguration or malware."
                            ),
                            severity=Severity.WARNING,
                            category=self.category,
                            data={
                                "check": "pac_url_detected",
                                "interface": interface,
                                "pac_url": pac_url,
                            },
                        )
                    )

            # Check for any enabled proxies
            enabled_proxies = []
            suspicious_localhost_proxies = []

            if proxy_config.get("http_enabled"):
                enabled_proxies.append("HTTP")
                if proxy_config.get("http_server"):
                    if self._is_suspicious_localhost(proxy_config["http_server"]):
                        suspicious_localhost_proxies.append(f"HTTP: {proxy_config['http_server']}")

            if proxy_config.get("https_enabled"):
                enabled_proxies.append("HTTPS")
                if proxy_config.get("https_server"):
                    if self._is_suspicious_localhost(proxy_config["https_server"]):
                        suspicious_localhost_proxies.append(f"HTTPS: {proxy_config['https_server']}")

            if proxy_config.get("socks_enabled"):
                enabled_proxies.append("SOCKS")
                if proxy_config.get("socks_server"):
                    if self._is_suspicious_localhost(proxy_config["socks_server"]):
                        suspicious_localhost_proxies.append(f"SOCKS: {proxy_config['socks_server']}")

            # Flag suspicious localhost proxies (malware indicator)
            if suspicious_localhost_proxies:
                findings.append(
                    Finding(
                        title=f"Local proxy server(s) configured on {interface}",
                        description=(
                            f"Proxy server(s) pointing to localhost with unusual port(s) are configured on {interface}: "
                            f"{', '.join(suspicious_localhost_proxies)}. This is often used by local proxy malware "
                            f"to intercept traffic while remaining hidden. Review and remove if unexpected."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={
                            "check": "suspicious_localhost_proxy",
                            "interface": interface,
                            "proxies": suspicious_localhost_proxies,
                        },
                    )
                )
            elif enabled_proxies:
                # Any enabled proxy is at least a warning
                findings.append(
                    Finding(
                        title=f"Proxy server(s) configured on {interface}",
                        description=(
                            f"The following proxy server(s) are enabled on {interface}: {', '.join(enabled_proxies)}. "
                            f"Proxies can be a malware vector. Corporate machines legitimately use proxies, "
                            f"but home machines should typically not have proxies configured. "
                            f"Review and disable if unexpected."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={
                            "check": "proxy_enabled",
                            "interface": interface,
                            "enabled_proxies": enabled_proxies,
                            "http_server": proxy_config.get("http_server"),
                            "https_server": proxy_config.get("https_server"),
                            "socks_server": proxy_config.get("socks_server"),
                        },
                    )
                )

            # Check proxy bypass domains if any proxies are configured
            if enabled_proxies or proxy_config.get("pac_url"):
                bypass_domains = proxy_config.get("bypass_domains", [])
                if bypass_domains:
                    findings.append(
                        Finding(
                            title=f"Proxy bypass domains configured on {interface}",
                            description=(
                                f"Proxy bypass domains are configured on {interface}: {', '.join(bypass_domains)}. "
                                f"This defines which domains bypass the proxy configuration."
                            ),
                            severity=Severity.INFO,
                            category=self.category,
                            data={
                                "check": "proxy_bypass_domains",
                                "interface": interface,
                                "bypass_domains": bypass_domains,
                            },
                        )
                    )

        # Add INFO finding with summary of all proxy configurations
        if proxy_configs_found:
            config_summary = []
            for iface, config in proxy_configs_found.items():
                if config.get("http_enabled") or config.get("https_enabled") or \
                   config.get("socks_enabled") or config.get("pac_url"):
                    config_summary.append(f"{iface}: {self._format_config(config)}")

            if config_summary:
                findings.append(
                    Finding(
                        title="Network proxy configuration summary",
                        description=(
                            f"Proxy configuration found on the following interfaces:\n" +
                            "\n".join(config_summary)
                        ),
                        severity=Severity.INFO,
                        category=self.category,
                        data={
                            "check": "proxy_config_summary",
                            "interfaces": list(proxy_configs_found.keys()),
                        },
                    )
                )

        # If no issues found, add informational finding
        if not findings:
            findings.append(
                Finding(
                    title="No network proxies configured",
                    description=(
                        "No proxy servers are configured on any network interfaces. "
                        "This is normal for home machines."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "no_proxies"},
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        """Provide informational guidance on removing proxies (never modifies settings)."""
        actions = []

        for finding in findings.findings:
            check_type = finding.data.get("check")

            if check_type == "remote_pac_url":
                interface = finding.data.get("interface")
                title = f"Remove remote PAC URL from {interface}"
                description = (
                    f"To remove the remote PAC file URL from {interface}:\n"
                    f"1. Open System Settings > Network\n"
                    f"2. Select {interface} and click 'Details...'\n"
                    f"3. Go to 'Proxies' tab\n"
                    f"4. Uncheck 'Automatic Proxy Configuration'\n"
                    f"5. Click 'OK' and apply changes\n"
                    f"\n"
                    f"If you did not intentionally configure this PAC URL, it may have been added by malware."
                )

            elif check_type == "pac_url_detected":
                interface = finding.data.get("interface")
                title = f"Review PAC URL on {interface}"
                description = (
                    f"To remove or review the PAC file URL on {interface}:\n"
                    f"1. Open System Settings > Network\n"
                    f"2. Select {interface} and click 'Details...'\n"
                    f"3. Go to 'Proxies' tab\n"
                    f"4. Review the 'Automatic Proxy Configuration' URL\n"
                    f"5. Uncheck if not needed for your organization\n"
                    f"6. Click 'OK' and apply changes"
                )

            elif check_type == "suspicious_localhost_proxy":
                interface = finding.data.get("interface")
                proxies = finding.data.get("proxies", [])
                title = f"Remove suspicious local proxy from {interface}"
                description = (
                    f"To remove the local proxy configuration from {interface}:\n"
                    f"1. Open System Settings > Network\n"
                    f"2. Select {interface} and click 'Details...'\n"
                    f"3. Go to 'Proxies' tab\n"
                    f"4. Uncheck: {', '.join(proxies)}\n"
                    f"5. Click 'OK' and apply changes\n"
                    f"\n"
                    f"If you did not configure these proxies, they may have been added by malware."
                )

            elif check_type == "proxy_enabled":
                interface = finding.data.get("interface")
                enabled_proxies = finding.data.get("enabled_proxies", [])
                title = f"Review proxies on {interface}"
                description = (
                    f"To review or remove the configured proxies from {interface}:\n"
                    f"1. Open System Settings > Network\n"
                    f"2. Select {interface} and click 'Details...'\n"
                    f"3. Go to 'Proxies' tab\n"
                    f"4. Review enabled proxies: {', '.join(enabled_proxies)}\n"
                    f"5. Uncheck if not required by your organization\n"
                    f"6. Click 'OK' and apply changes"
                )

            elif check_type in ("proxy_bypass_domains", "proxy_config_summary", "no_proxies", "network_query_failed"):
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

    def _get_network_services(self) -> list[str]:
        """Get list of all network services."""
        try:
            result = subprocess.run(
                ["networksetup", "-listallnetworkservices"],
                capture_output=True,
                text=True,
                timeout=5
            )
            if result.returncode != 0:
                return []

            lines = result.stdout.strip().split('\n')
            # Filter out "An asterisk (*) denotes that a network service is disabled."
            services = [line.strip() for line in lines if line.strip() and not line.startswith("An asterisk")]
            return services
        except (subprocess.SubprocessError, Exception):
            return []

    def _get_proxy_config(self, interface: str) -> dict | None:
        """Get proxy configuration for an interface."""
        config = {
            "http_enabled": False,
            "https_enabled": False,
            "socks_enabled": False,
            "http_server": None,
            "https_server": None,
            "socks_server": None,
            "pac_url": None,
            "bypass_domains": [],
        }

        try:
            # Check HTTP proxy
            http_output = self._run_networksetup(["networksetup", "-getwebproxy", interface])
            if http_output and "Enabled: Yes" in http_output:
                config["http_enabled"] = True
                server = self._extract_server_with_port(http_output)
                if server:
                    config["http_server"] = server

            # Check HTTPS proxy
            https_output = self._run_networksetup(["networksetup", "-getsecurewebproxy", interface])
            if https_output and "Enabled: Yes" in https_output:
                config["https_enabled"] = True
                server = self._extract_server_with_port(https_output)
                if server:
                    config["https_server"] = server

            # Check SOCKS proxy
            socks_output = self._run_networksetup(["networksetup", "-getsocksfirewallproxy", interface])
            if socks_output and "Enabled: Yes" in socks_output:
                config["socks_enabled"] = True
                server = self._extract_server_with_port(socks_output)
                if server:
                    config["socks_server"] = server

            # Check PAC file URL
            pac_output = self._run_networksetup(["networksetup", "-getautoproxyurl", interface])
            if pac_output:
                pac_url = self._extract_pac_url(pac_output)
                if pac_url:
                    config["pac_url"] = pac_url

            # Check proxy bypass domains
            bypass_output = self._run_networksetup(["networksetup", "-getproxybypassdomains", interface])
            if bypass_output:
                bypass_domains = self._extract_bypass_domains(bypass_output)
                if bypass_domains:
                    config["bypass_domains"] = bypass_domains

            return config

        except Exception:
            # Interface might not exist or networksetup might fail
            return None

    def _run_networksetup(self, cmd: list) -> str:
        """Run a networksetup command and return output."""
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            return result.stdout
        except (subprocess.SubprocessError, Exception):
            return ""

    def _extract_server(self, output: str) -> str | None:
        """Extract server address from networksetup output."""
        for line in output.split("\n"):
            if "Server:" in line:
                parts = line.split("Server:", 1)
                if len(parts) > 1:
                    return parts[1].strip()
        return None

    def _extract_server_with_port(self, output: str) -> str | None:
        """Extract server address with port from networksetup output."""
        server = None
        port = None

        for line in output.split("\n"):
            if "Server:" in line:
                parts = line.split("Server:", 1)
                if len(parts) > 1:
                    server = parts[1].strip()
            elif "Port:" in line:
                parts = line.split("Port:", 1)
                if len(parts) > 1:
                    port = parts[1].strip()

        if server:
            if port:
                return f"{server}:{port}"
            return server

        return None

    def _extract_pac_url(self, output: str) -> str | None:
        """Extract PAC URL from networksetup output."""
        for line in output.split("\n"):
            if "URL:" in line:
                parts = line.split("URL:", 1)
                if len(parts) > 1:
                    url = parts[1].strip()
                    # Only return if it's not empty or just whitespace
                    if url and url.lower() != "(null)":
                        return url
        return None

    def _extract_bypass_domains(self, output: str) -> list[str]:
        """Extract proxy bypass domains from networksetup output."""
        domains = []
        for line in output.split("\n"):
            line = line.strip()
            if line and line.lower() != "(null)":
                domains.append(line)
        return domains

    def _is_remote_url(self, url: str) -> bool:
        """Check if URL is remote (not localhost or file://)."""
        if not url:
            return False
        url_lower = url.lower()
        return not (url_lower.startswith("localhost") or
                   url_lower.startswith("127.0.0.1") or
                   url_lower.startswith("file://"))

    def _is_suspicious_localhost(self, server: str) -> bool:
        """Check if server is localhost with unusual port (malware indicator)."""
        if not server:
            return False

        # Check if it's localhost
        if not (server.startswith("localhost") or server.startswith("127.0.0.1") or
                server.startswith("::1")):
            return False

        # Extract port if present
        if ":" in server:
            try:
                port_str = server.split(":")[-1]
                port = int(port_str)
                # Standard proxy ports: 80, 443, 3128, 8080, 8888, 9090
                standard_ports = {80, 443, 3128, 8080, 8888, 9090, 1080}
                return port not in standard_ports
            except (ValueError, IndexError):
                return False

        # If no port specified, it's less suspicious
        return False

    def _format_config(self, config: dict) -> str:
        """Format proxy config for display."""
        parts = []
        if config.get("http_enabled"):
            parts.append(f"HTTP={config.get('http_server', 'unknown')}")
        if config.get("https_enabled"):
            parts.append(f"HTTPS={config.get('https_server', 'unknown')}")
        if config.get("socks_enabled"):
            parts.append(f"SOCKS={config.get('socks_server', 'unknown')}")
        if config.get("pac_url"):
            parts.append(f"PAC={config.get('pac_url')}")
        return ", ".join(parts) if parts else "No proxies"
