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
    name = "win_winsock_check"
    category = "integrity"
    platforms = [Platform.WIN32]
    risk_level = RiskLevel.SAFE
    priority = 55
    depends_on = []
    estimated_duration = "20s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Check Winsock catalog
        catalog_info = self._get_winsock_catalog()
        if catalog_info is None:
            findings.append(
                Finding(
                    title="Could not retrieve Winsock catalog",
                    description=(
                        "Failed to run 'netsh winsock show catalog'. "
                        "Winsock configuration cannot be assessed."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "winsock_catalog_failed"},
                )
            )
        else:
            # Check for excessive catalog entries
            entry_count = catalog_info.get("entry_count", 0)
            if entry_count > 30:
                findings.append(
                    Finding(
                        title=f"Excessive Winsock catalog entries ({entry_count})",
                        description=(
                            f"Winsock catalog contains {entry_count} entries (normal: <30). "
                            "This may indicate corruption or unclean software removal. "
                            "Consider running 'netsh winsock reset' from admin command prompt."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={
                            "check": "excessive_winsock_entries",
                            "entry_count": entry_count,
                        },
                    )
                )

            # Check for suspicious LSPs
            lsps = catalog_info.get("lsps", [])
            if lsps:
                suspicious_lsps = self._check_suspicious_lsps(lsps)
                if suspicious_lsps:
                    findings.append(
                        Finding(
                            title=f"Suspicious LSP (Layered Service Provider) detected",
                            description=(
                                f"Found {len(suspicious_lsps)} potentially problematic LSPs: "
                                f"{', '.join(suspicious_lsps)}. "
                                "LSPs can intercept network traffic. "
                                "These are often remnants of old antivirus/adware. "
                                "Consider removing if not actively used."
                            ),
                            severity=Severity.WARNING,
                            category=self.category,
                            data={
                                "check": "suspicious_lsps",
                                "lsps": suspicious_lsps,
                            },
                        )
                    )

            # Add info about healthy catalog if no issues found
            if entry_count <= 30 and not lsps:
                findings.append(
                    Finding(
                        title="Winsock catalog healthy",
                        description=(
                            f"Winsock catalog is healthy with {entry_count} entries. "
                            "No excessive entries or suspicious LSPs detected."
                        ),
                        severity=Severity.INFO,
                        category=self.category,
                        data={
                            "check": "winsock_healthy",
                            "entry_count": entry_count,
                        },
                    )
                )

        # Check TCP/IP parameters
        tcpip_info = self._get_tcpip_parameters()
        if tcpip_info is None:
            findings.append(
                Finding(
                    title="Could not retrieve TCP/IP parameters",
                    description=(
                        "Failed to query TCP/IP registry parameters. "
                        "TCP/IP configuration cannot be assessed."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "tcpip_query_failed"},
                )
            )
        else:
            # Check for unusual TCP/IP values
            unusual_params = self._check_unusual_tcpip_params(tcpip_info)
            if unusual_params:
                findings.append(
                    Finding(
                        title="Unusual TCP/IP parameters detected",
                        description=(
                            f"Found {len(unusual_params)} unusual TCP/IP parameters: "
                            f"{', '.join(unusual_params)}. "
                            "These may indicate network problems, optimization attempts, "
                            "or malware modifications."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={
                            "check": "unusual_tcpip_params",
                            "parameters": unusual_params,
                        },
                    )
                )

            # Check IPv4/IPv6 configuration
            ipv4_enabled = tcpip_info.get("ipv4_enabled", True)
            ipv6_enabled = tcpip_info.get("ipv6_enabled", False)

            if not ipv4_enabled:
                findings.append(
                    Finding(
                        title="IPv4 appears to be disabled",
                        description=(
                            "IPv4 may be disabled in TCP/IP parameters. "
                            "This could cause networking problems if IPv6 is not properly configured."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={"check": "ipv4_disabled"},
                    )
                )

            # Add info about TCP/IP configuration
            if not unusual_params and ipv4_enabled:
                config_summary = (
                    f"IPv4 enabled, IPv6 {'enabled' if ipv6_enabled else 'disabled'}"
                )
                findings.append(
                    Finding(
                        title="TCP/IP configuration normal",
                        description=(
                            f"TCP/IP stack appears healthy. Configuration: {config_summary}. "
                            "No unusual parameters detected."
                        ),
                        severity=Severity.INFO,
                        category=self.category,
                        data={
                            "check": "tcpip_normal",
                            "ipv4_enabled": ipv4_enabled,
                            "ipv6_enabled": ipv6_enabled,
                        },
                    )
                )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        for finding in findings.findings:
            check = finding.data.get("check")

            if check == "winsock_catalog_failed":
                actions.append(
                    Action(
                        title="Unable to assess Winsock catalog",
                        description=(
                            "The Winsock catalog query failed. "
                            "Ensure you have Administrator privileges. "
                            "You can manually check Winsock with: "
                            "netsh winsock show catalog"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "excessive_winsock_entries":
                entry_count = finding.data.get("entry_count", 0)
                actions.append(
                    Action(
                        title=f"Reset Winsock catalog ({entry_count} entries)",
                        description=(
                            f"Winsock catalog contains {entry_count} entries (normal: <30). "
                            "To reset the Winsock catalog: (1) Open Command Prompt as Administrator. "
                            "(2) Run: netsh winsock reset catalog (3) Run: ipconfig /all to verify. "
                            "(4) Restart your computer if issues persist."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "suspicious_lsps":
                lsps = finding.data.get("lsps", [])
                actions.append(
                    Action(
                        title=f"Remove suspicious LSPs ({len(lsps)} found)",
                        description=(
                            f"Found suspicious LSPs: {', '.join(lsps)}. "
                            "Layered Service Providers can intercept network traffic. "
                            "To remove an LSP: (1) Open Command Prompt as Administrator. "
                            "(2) Run: netsh winsock remove provider <GUID> "
                            "(3) Restart your computer. "
                            "If you don't recognize the LSP, it's likely safe to remove."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "unusual_tcpip_params":
                params = finding.data.get("parameters", [])
                actions.append(
                    Action(
                        title=f"Review unusual TCP/IP parameters ({len(params)} found)",
                        description=(
                            f"Found unusual parameters: {', '.join(params)}. "
                            "Recommendations: (1) Document current values with: "
                            "reg query HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters "
                            "(2) If values were added by software, uninstall the software. "
                            "(3) If values are unknown, consider resetting with: netsh int ip reset. "
                            "(4) Only reset if you're comfortable with network changes."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "ipv4_disabled":
                actions.append(
                    Action(
                        title="Re-enable IPv4",
                        description=(
                            "IPv4 appears to be disabled. "
                            "To re-enable IPv4: (1) Open Settings > Network & Internet > Advanced network settings. "
                            "(2) Scroll to 'More settings' and select 'Advanced options'. "
                            "(3) Find IPv4 and ensure it's enabled. "
                            "(4) Or use Command Prompt: netsh int ipv4 set interface <interface> disabled=0"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "winsock_healthy":
                actions.append(
                    Action(
                        title="Winsock catalog is healthy",
                        description=(
                            "Winsock catalog is in good condition with no excessive entries "
                            "or suspicious providers. Network stack should function normally."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "tcpip_normal":
                actions.append(
                    Action(
                        title="TCP/IP configuration is normal",
                        description=(
                            "TCP/IP stack is properly configured. "
                            "No unusual parameters or problematic settings detected. "
                            "Network connectivity should work as expected."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "tcpip_query_failed":
                actions.append(
                    Action(
                        title="Unable to assess TCP/IP parameters",
                        description=(
                            "TCP/IP parameter query failed. "
                            "Ensure you have Administrator privileges and run the diagnostic again. "
                            "You can manually check TCP/IP with: "
                            "reg query HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _get_winsock_catalog(self) -> Optional[dict]:
        """Get Winsock catalog information."""
        try:
            result = subprocess.run(
                ["netsh", "winsock", "show", "catalog"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                return None

            return _parse_winsock_catalog(result.stdout)
        except (OSError, subprocess.SubprocessError, TimeoutError):
            return None

    def _get_tcpip_parameters(self) -> Optional[dict]:
        """Get TCP/IP parameters from registry."""
        try:
            result = subprocess.run(
                [
                    "reg",
                    "query",
                    r"HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters",
                ],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                return None

            return _parse_tcpip_parameters(result.stdout)
        except (OSError, subprocess.SubprocessError, TimeoutError):
            return None

    def _check_suspicious_lsps(self, lsps: list[str]) -> list[str]:
        """Check for known problematic LSPs."""
        suspicious_keywords = [
            "norton",
            "mcafee",
            "kaspersky",
            "symantec",
            "trend micro",
            "avast",
            "avira",
            "bitdefender",
            "baidu",
            "qq",
            "deepl",
            "vpn",
            "proxy",
            "webroot",
            "pctools",
        ]

        suspicious = []
        for lsp in lsps:
            lsp_lower = lsp.lower()
            for keyword in suspicious_keywords:
                if keyword in lsp_lower:
                    suspicious.append(lsp)
                    break

        return suspicious

    def _check_unusual_tcpip_params(self, params: dict) -> list[str]:
        """Check for unusual TCP/IP parameter values."""
        unusual = []

        # Check DefaultTTL (should be 64 or 128, not <32 or >255)
        ttl = params.get("DefaultTTL")
        if ttl is not None:
            try:
                # Handle hex values
                if isinstance(ttl, str) and ttl.startswith("0x"):
                    ttl_val = int(ttl, 16)
                else:
                    ttl_val = int(ttl)
                if ttl_val < 32 or ttl_val > 255:
                    unusual.append(f"DefaultTTL={ttl}")
            except ValueError:
                pass

        # Check for disabled TCP features
        tcp_disabled_params = [
            "DisabledComponents",
            "TcpWindowSize",
            "SynAttackProtect",
        ]
        for param in tcp_disabled_params:
            if param in params:
                val = params[param]
                # These should not be present or should have normal values
                try:
                    # Handle hex values
                    if isinstance(val, str) and val.startswith("0x"):
                        val_int = int(val, 16)
                    else:
                        val_int = int(val)
                    # DisabledComponents with high values indicate disabled features
                    if param == "DisabledComponents" and val_int > 0:
                        unusual.append(f"{param}={val} (features may be disabled)")
                except ValueError:
                    pass

        # Check for KeepAliveTime (too low = excessive traffic)
        keep_alive = params.get("KeepAliveTime")
        if keep_alive is not None:
            try:
                # Handle hex values
                if isinstance(keep_alive, str) and keep_alive.startswith("0x"):
                    ka_val = int(keep_alive, 16)
                else:
                    ka_val = int(keep_alive)
                if ka_val < 60000:  # Less than 1 minute is unusual
                    unusual.append(f"KeepAliveTime={keep_alive}ms (very aggressive)")
            except ValueError:
                pass

        return unusual


def _parse_winsock_catalog(output: str) -> dict:
    """Parse Winsock catalog output from netsh."""
    info = {"entry_count": 0, "lsps": []}

    lines = output.split("\n")
    for line in lines:
        # Count catalog entries (look for "Entry" lines)
        if "Entry" in line and ":" in line:
            info["entry_count"] += 1

        # Look for LSP (Layered Service Provider) entries
        if "Layered Service Provider" in line:
            # Extract provider name if present (format: Layered Service Provider = Name)
            if "=" in line:
                parts = line.split("=", 1)
                if len(parts) > 1:
                    provider = parts[1].strip()
                    if provider and provider not in info["lsps"]:
                        info["lsps"].append(provider)

    return info


def _parse_tcpip_parameters(output: str) -> dict:
    """Parse TCP/IP parameters from registry output."""
    params = {"ipv4_enabled": True, "ipv6_enabled": False}

    lines = output.split("\n")
    for line in lines:
        # Skip empty lines and header lines
        if not line.strip() or "HKEY_LOCAL_MACHINE" in line:
            continue

        # Parse registry values with format: KeyName    REG_TYPE    Value
        parts = line.split()
        if len(parts) < 3:
            continue

        key = parts[0]
        # Value is typically the last part (after REG_DWORD or REG_SZ, etc.)
        value = parts[-1]

        # Store parameter
        params[key] = value

        # Check for IPv4 disabled
        if key == "DisabledComponents":
            try:
                # Handle hex values like 0x20
                if value.startswith("0x"):
                    val = int(value, 16)
                else:
                    val = int(value)
                # If bit 5 is set, IPv4 is disabled
                if val & 0x20:
                    params["ipv4_enabled"] = False
            except (ValueError, IndexError):
                pass

        # Check for IPv6 enabled
        if key == "DisabledComponents":
            try:
                # Handle hex values like 0x20
                if value.startswith("0x"):
                    val = int(value, 16)
                else:
                    val = int(value)
                # If bit 4 is not set, IPv6 is enabled
                if not (val & 0x10):
                    params["ipv6_enabled"] = True
            except (ValueError, IndexError):
                pass

    return params
