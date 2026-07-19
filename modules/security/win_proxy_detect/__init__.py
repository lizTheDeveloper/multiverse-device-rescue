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
    name = "win_proxy_detect"
    category = "security"
    platforms = [Platform.WIN32]
    risk_level = RiskLevel.SAFE
    priority = 70
    depends_on = []
    estimated_duration = "5s"

    emits_codes = [
        "security.win_proxy_detect.localhost_suspicious",
        "security.win_proxy_detect.ie_proxy_enabled",
        "security.win_proxy_detect.pac_configured",
        "security.win_proxy_detect.system_proxy",
        "security.win_proxy_detect.no_proxies",
    ]

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Check IE/Edge proxy settings
        ie_proxy_enabled = self._get_ie_proxy_enabled()
        ie_proxy_server = self._get_ie_proxy_server()
        ie_pac_url = self._get_ie_pac_url()
        netsh_proxy = self._get_netsh_proxy()

        # Flag CRITICAL if proxy points to localhost on unusual port (malware intercepting)
        if ie_proxy_server:
            is_localhost_suspicious = _is_suspicious_localhost_proxy(ie_proxy_server)
            if is_localhost_suspicious:
                findings.append(
                    Finding(
                        title="Proxy points to localhost on unusual port (potential malware)",
                        description=(
                            f"The proxy server is set to {ie_proxy_server}, which points to localhost "
                            "on an unusual port. This is a common malware/adware tactic to intercept "
                            "traffic. Verify this is intentional immediately."
                        ),
                        severity=Severity.CRITICAL,
                        category=self.category,
                        code="security.win_proxy_detect.localhost_suspicious",
                        data={"proxy_server": ie_proxy_server, "type": "localhost_suspicious"},
                    )
                )

        # Flag WARNING if any proxy is enabled (unexpected on most home PCs)
        if ie_proxy_enabled and ie_proxy_server:
            findings.append(
                Finding(
                    title="Internet Explorer/Edge proxy is enabled",
                    description=(
                        f"Proxy server is enabled and set to {ie_proxy_server}. "
                        "Most home PCs do not require proxy settings. Verify this is "
                        "intentional (common in corporate environments or with VPN)."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.win_proxy_detect.ie_proxy_enabled",
                    data={"proxy_server": ie_proxy_server, "type": "ie_proxy_enabled"},
                )
            )

        # Flag WARNING if PAC URL is configured
        if ie_pac_url:
            findings.append(
                Finding(
                    title="Auto-config (PAC) URL is configured",
                    description=(
                        f"Proxy auto-config URL is set to {ie_pac_url}. "
                        "Verify this is intentional. Malware may use PAC files to redirect traffic."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    code="security.win_proxy_detect.pac_configured",
                    data={"pac_url": ie_pac_url, "type": "pac_configured"},
                )
            )

        # Report on system-wide proxy
        if netsh_proxy:
            findings.append(
                Finding(
                    title="System-wide proxy detected",
                    description=(
                        f"System-wide HTTP proxy is configured: {netsh_proxy}. "
                        "Verify this is intentional."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.win_proxy_detect.system_proxy",
                    data={"netsh_proxy": netsh_proxy, "type": "system_proxy"},
                )
            )

        # Flag INFO if no proxies configured (normal)
        if not findings:
            findings.append(
                Finding(
                    title="No proxies configured",
                    description=(
                        "No proxy settings detected. This is the normal state for most systems."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="security.win_proxy_detect.no_proxies",
                    data={"type": "no_proxies"},
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            finding_type = finding.data.get("type", "")

            if finding_type == "localhost_suspicious":
                proxy_server = finding.data.get("proxy_server", "")
                actions.append(
                    Action(
                        title=f"Remove suspicious proxy: {proxy_server}",
                        description=(
                            "This proxy configuration appears to be malware/adware intercepting traffic. "
                            "To remove it:\n"
                            "1. Open Settings > Network & Internet > Proxy\n"
                            "2. Under 'Manual proxy setup', turn OFF 'Use a proxy server'\n"
                            "3. Restart your browser and consider running a malware scan"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )
            elif finding_type == "ie_proxy_enabled":
                proxy_server = finding.data.get("proxy_server", "")
                actions.append(
                    Action(
                        title=f"Review proxy: {proxy_server}",
                        description=(
                            "Proxy server is enabled. If this is not intentional (not in a corporate "
                            "environment or using VPN), remove it:\n"
                            "1. Open Settings > Network & Internet > Proxy\n"
                            "2. Under 'Manual proxy setup', turn OFF 'Use a proxy server'"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )
            elif finding_type == "pac_configured":
                pac_url = finding.data.get("pac_url", "")
                actions.append(
                    Action(
                        title=f"Review PAC URL: {pac_url}",
                        description=(
                            "Proxy auto-config (PAC) URL is configured. If this is not intentional, "
                            "remove it:\n"
                            "1. Open Settings > Network & Internet > Proxy\n"
                            "2. Under 'Automatic proxy setup', turn OFF 'Use automatic proxy setup'"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                        error=None,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _get_ie_proxy_enabled(self) -> bool:
        """Check if IE/Edge proxy is enabled via registry."""
        try:
            result = subprocess.run(
                [
                    "reg",
                    "query",
                    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
                    "/v",
                    "ProxyEnable",
                ],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                return False
            # Output contains "0x1" for enabled, "0x0" for disabled
            return "0x1" in result.stdout
        except (OSError, subprocess.SubprocessError):
            return False

    def _get_ie_proxy_server(self) -> str | None:
        """Get IE/Edge proxy server address."""
        try:
            result = subprocess.run(
                [
                    "reg",
                    "query",
                    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
                    "/v",
                    "ProxyServer",
                ],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                return None
            # Parse registry output to extract value
            return _extract_registry_value(result.stdout)
        except (OSError, subprocess.SubprocessError):
            return None

    def _get_ie_pac_url(self) -> str | None:
        """Check for PAC (auto-config) URL."""
        try:
            result = subprocess.run(
                [
                    "reg",
                    "query",
                    r"HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
                    "/v",
                    "AutoConfigURL",
                ],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                return None
            # Parse registry output to extract value
            return _extract_registry_value(result.stdout)
        except (OSError, subprocess.SubprocessError):
            return None

    def _get_netsh_proxy(self) -> str | None:
        """Check system-wide proxy via netsh."""
        try:
            result = subprocess.run(
                ["netsh", "winhttp", "show", "proxy"],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                return None
            # Parse netsh output
            return _parse_netsh_proxy_output(result.stdout)
        except (OSError, subprocess.SubprocessError):
            return None


def _extract_registry_value(output: str) -> str | None:
    r"""Extract the value from registry query output.

    Example output:
    HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Internet Settings
        ProxyServer    REG_SZ    proxy.example.com:8080
    """
    for line in output.splitlines():
        line = line.strip()
        if not line or "ProxyServer" not in line and "AutoConfigURL" not in line:
            continue
        # The value is typically the last whitespace-separated field
        parts = line.split()
        if len(parts) >= 3:
            return parts[-1].strip()
    return None


def _parse_netsh_proxy_output(output: str) -> str | None:
    """Parse netsh winhttp show proxy output.

    Example output:
    Current WinHTTP proxy settings:
        Direct access (no proxy server).

    Or with proxy:
    Current WinHTTP proxy settings:
        Proxy Server(s) :  proxy.example.com:8080
        Bypass List     :  local
    """
    for line in output.splitlines():
        line = line.strip()
        if "Proxy Server(s)" in line and ":" in line:
            parts = line.split(":", 1)
            if len(parts) == 2:
                value = parts[1].strip()
                if value and value.lower() != "(none)":
                    return value
    return None


def _is_suspicious_localhost_proxy(proxy_server: str) -> bool:
    """Check if proxy points to localhost on an unusual port (malware indicator).

    Args:
        proxy_server: Proxy server string (e.g., "127.0.0.1:8080")

    Returns:
        True if it looks like suspicious localhost proxy, False otherwise
    """
    if not proxy_server:
        return False

    proxy_lower = proxy_server.lower()

    # Check for localhost patterns
    localhost_patterns = ["127.0.0.1", "localhost", "127."]

    for pattern in localhost_patterns:
        if pattern in proxy_lower:
            # Check if it's on an unusual port (not standard proxy ports)
            # Standard ports: 3128, 8080, 8888, 9090, 80, 443, 8000, 8001, 8002, 8003
            standard_ports = ["80", "443", "3128", "8000", "8001", "8002", "8003", "8080", "8888", "9090"]

            # Extract port if present
            port_part = ""
            if ":" in proxy_lower:
                port_part = proxy_lower.split(":")[-1]

            # If we have a port and it's not standard, flag as suspicious
            if port_part and not any(port in port_part for port in standard_ports):
                return True

    return False
