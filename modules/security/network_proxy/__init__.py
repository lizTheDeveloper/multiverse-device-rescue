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
    name = "network_proxy"
    category = "security"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "2s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Check both Wi-Fi and Ethernet interfaces
        interfaces = ["Wi-Fi", "Ethernet"]

        for interface in interfaces:
            proxy_config = self._get_proxy_config(interface)
            if proxy_config is None:
                # Interface not available or command failed
                continue

            # Check for any enabled proxies
            enabled_proxies = []
            if proxy_config.get("http_enabled"):
                enabled_proxies.append("HTTP")
            if proxy_config.get("https_enabled"):
                enabled_proxies.append("HTTPS")
            if proxy_config.get("socks_enabled"):
                enabled_proxies.append("SOCKS")
            if proxy_config.get("auto_discovery_enabled"):
                enabled_proxies.append("Auto Proxy Discovery")

            # Check for PAC file (very suspicious)
            if proxy_config.get("pac_url"):
                findings.append(
                    Finding(
                        title=f"Proxy Auto-Configuration (PAC) URL detected on {interface}",
                        description=(
                            f"A Proxy Auto-Configuration (PAC) file URL is configured on {interface}: "
                            f"{proxy_config['pac_url']}. This is very suspicious on home machines and may "
                            f"indicate malware attempting to hijack network traffic. PAC files are typically "
                            f"used in corporate environments. On home machines, this is a malware red flag."
                        ),
                        severity=Severity.CRITICAL,
                        category=self.category,
                        data={
                            "check": "pac_url_detected",
                            "interface": interface,
                            "pac_url": proxy_config["pac_url"],
                        },
                    )
                )

            # Flag if any proxy is enabled (excluding PAC discovery)
            if enabled_proxies:
                findings.append(
                    Finding(
                        title=f"Proxy server(s) configured on {interface}",
                        description=(
                            f"The following proxy server(s) are enabled on {interface}: {', '.join(enabled_proxies)}. "
                            f"Unexpected proxies can be a malware vector used to hijack traffic. "
                            f"Corporate machines legitimately use proxies, but home machines should typically not. "
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

        # If no issues found, add informational finding
        if not findings:
            findings.append(
                Finding(
                    title="No proxies configured",
                    description=(
                        "No proxy servers are configured on Wi-Fi or Ethernet interfaces. "
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

            if check_type == "pac_url_detected":
                pac_url = finding.data.get("pac_url")
                interface = finding.data.get("interface")
                title = f"Remove PAC URL from {interface}"
                description = (
                    f"To remove the PAC file URL from {interface}:\n"
                    f"1. Open System Preferences > Network\n"
                    f"2. Select {interface} and click 'Advanced...'\n"
                    f"3. Go to 'Proxies' tab\n"
                    f"4. Uncheck 'Automatic Proxy Configuration'\n"
                    f"5. Click 'OK' and 'Apply'\n"
                    f"\n"
                    f"Current PAC URL: {pac_url}"
                )

            elif check_type == "proxy_enabled":
                interface = finding.data.get("interface")
                enabled_proxies = finding.data.get("enabled_proxies", [])
                title = f"Remove proxies from {interface}"
                description = (
                    f"To remove the configured proxies from {interface}:\n"
                    f"1. Open System Preferences > Network\n"
                    f"2. Select {interface} and click 'Advanced...'\n"
                    f"3. Go to 'Proxies' tab\n"
                    f"4. Uncheck: {', '.join(enabled_proxies)}\n"
                    f"5. Click 'OK' and 'Apply'\n"
                    f"\n"
                    f"If these proxies are required by your organization, consult your IT department."
                )

            elif check_type == "no_proxies":
                # No action needed for clean systems
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

    def _get_proxy_config(self, interface: str) -> dict | None:
        """Get proxy configuration for an interface."""
        config = {
            "http_enabled": False,
            "https_enabled": False,
            "socks_enabled": False,
            "auto_discovery_enabled": False,
            "http_server": None,
            "https_server": None,
            "socks_server": None,
            "pac_url": None,
        }

        try:
            # Check HTTP proxy
            http_output = self._run_networksetup(["networksetup", "-getwebproxy", interface])
            if "Enabled: Yes" in http_output:
                config["http_enabled"] = True
                server = self._extract_server(http_output)
                if server:
                    config["http_server"] = server

            # Check HTTPS proxy
            https_output = self._run_networksetup(["networksetup", "-getsecurewebproxy", interface])
            if "Enabled: Yes" in https_output:
                config["https_enabled"] = True
                server = self._extract_server(https_output)
                if server:
                    config["https_server"] = server

            # Check SOCKS proxy
            socks_output = self._run_networksetup(["networksetup", "-getsocksfirewallproxy", interface])
            if "Enabled: Yes" in socks_output:
                config["socks_enabled"] = True
                server = self._extract_server(socks_output)
                if server:
                    config["socks_server"] = server

            # Check Auto Proxy Discovery
            autodiscovery_output = self._run_networksetup(
                ["networksetup", "-getproxyautodiscovery", interface]
            )
            if "Enabled: Yes" in autodiscovery_output:
                config["auto_discovery_enabled"] = True

            # Check PAC file URL
            pac_output = self._run_networksetup(
                ["networksetup", "-getautoproxyurl", interface]
            )
            pac_url = self._extract_pac_url(pac_output)
            if pac_url:
                config["pac_url"] = pac_url

            return config

        except Exception:
            # Interface might not exist or networksetup might fail
            return None

    def _run_networksetup(self, cmd: list) -> str:
        """Run a networksetup command and return output."""
        result = subprocess.run(cmd, capture_output=True, text=True)
        return result.stdout

    def _extract_server(self, output: str) -> str | None:
        """Extract server address from networksetup output."""
        for line in output.split("\n"):
            if "Server:" in line:
                parts = line.split("Server:", 1)
                if len(parts) > 1:
                    return parts[1].strip()
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
