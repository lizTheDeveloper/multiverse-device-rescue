import os
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
    name = "network_proxy_detect"
    category = "integrity"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "2s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Check environment variables
        env_proxies = self._check_environment_proxies()
        if env_proxies:
            findings.append(
                Finding(
                    title="Proxy environment variables detected",
                    description=(
                        f"The following proxy environment variables are set: {', '.join(env_proxies)}. "
                        f"Environment variable proxies can override system settings and break connectivity. "
                        f"This is unexpected on home machines and may indicate malware or leftover corporate settings."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "check": "env_proxy_detected",
                        "env_proxies": env_proxies,
                    },
                )
            )

        # Check networksetup proxies on Wi-Fi interface
        proxy_config = self._get_proxy_config("Wi-Fi")
        if proxy_config is not None:
            # Check for PAC file (most suspicious)
            if proxy_config.get("pac_url"):
                findings.append(
                    Finding(
                        title="Proxy Auto-Configuration (PAC) URL detected on Wi-Fi",
                        description=(
                            f"A Proxy Auto-Configuration (PAC) file URL is configured on Wi-Fi: "
                            f"{proxy_config['pac_url']}. PAC files can intercept and modify traffic, "
                            f"making them a malware vector. This is very suspicious on home machines."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={
                            "check": "pac_url_detected",
                            "pac_url": proxy_config["pac_url"],
                        },
                    )
                )

            # Check for enabled proxies (HTTP, HTTPS, SOCKS)
            enabled_proxies = []
            if proxy_config.get("http_enabled"):
                enabled_proxies.append("HTTP")
            if proxy_config.get("https_enabled"):
                enabled_proxies.append("HTTPS")
            if proxy_config.get("socks_enabled"):
                enabled_proxies.append("SOCKS")

            if enabled_proxies:
                findings.append(
                    Finding(
                        title=f"Proxy server(s) configured on Wi-Fi: {', '.join(enabled_proxies)}",
                        description=(
                            f"The following proxy server(s) are enabled on Wi-Fi: {', '.join(enabled_proxies)}. "
                            f"Unexpected proxies on home machines can break connectivity and may be a malware vector. "
                            f"Corporate machines may legitimately use proxies, but home machines should typically not."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={
                            "check": "proxy_enabled",
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
                    title="No unexpected proxies detected",
                    description=(
                        "No proxy environment variables are set, and no proxies are configured via networksetup. "
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

            if check_type == "env_proxy_detected":
                env_proxies = finding.data.get("env_proxies", [])
                title = "Remove proxy environment variables"
                description = (
                    f"The following environment variables are set: {', '.join(env_proxies)}\n\n"
                    f"To remove proxy environment variables:\n"
                    f"1. Edit your shell configuration file (~/.bash_profile, ~/.zshrc, or ~/.bashrc)\n"
                    f"2. Remove or comment out lines like:\n"
                    f"   export HTTP_PROXY=...\n"
                    f"   export HTTPS_PROXY=...\n"
                    f"   export ALL_PROXY=...\n"
                    f"3. Save and close the file\n"
                    f"4. Open a new terminal or run: source ~/.zshrc (or ~/.bash_profile)\n"
                    f"\n"
                    f"To verify removal, run: env | grep -i proxy"
                )

            elif check_type == "pac_url_detected":
                pac_url = finding.data.get("pac_url")
                title = "Remove PAC URL from Wi-Fi"
                description = (
                    f"A PAC file is configured: {pac_url}\n\n"
                    f"To remove the PAC file URL from Wi-Fi:\n"
                    f"1. Open System Preferences > Network\n"
                    f"2. Select Wi-Fi and click 'Advanced...'\n"
                    f"3. Go to 'Proxies' tab\n"
                    f"4. Uncheck 'Automatic Proxy Configuration'\n"
                    f"5. Click 'OK' and 'Apply'\n"
                    f"\n"
                    f"Current PAC URL: {pac_url}"
                )

            elif check_type == "proxy_enabled":
                enabled_proxies = finding.data.get("enabled_proxies", [])
                title = "Remove proxies from Wi-Fi"
                description = (
                    f"To remove the configured proxies from Wi-Fi:\n"
                    f"1. Open System Preferences > Network\n"
                    f"2. Select Wi-Fi and click 'Advanced...'\n"
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

    def _check_environment_proxies(self) -> list[str]:
        """Check for proxy environment variables."""
        proxy_vars = ["HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY"]
        found_proxies = []

        for var in proxy_vars:
            # Check both uppercase and lowercase versions
            if os.environ.get(var.upper()) or os.environ.get(var.lower()):
                found_proxies.append(var)

        return found_proxies

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

            # Check PAC file URL
            pac_output = self._run_networksetup(["networksetup", "-getautoproxyurl", interface])
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
