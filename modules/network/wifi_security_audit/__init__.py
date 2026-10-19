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


# Marks "system_profiler not read yet in this check" (None means "read, failed").
_UNREAD = object()


class Module(ModuleBase):
    name = "wifi_security_audit"
    category = "network"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "5s"
    emits_codes = [
        "network.wifi_security_audit.wep_connected",
        "network.wifi_security_audit.open_network_connected",
        "network.wifi_security_audit.wpa2_only",
        "network.wifi_security_audit.hidden_network",
        "network.wifi_security_audit.wep_saved",
        "network.wifi_security_audit.open_saved",
        "network.wifi_security_audit.wifi_summary",
        "network.wifi_security_audit.security_unknown",
    ]

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []
        # `system_profiler SPAirPortDataType` takes about 5 seconds. It used to
        # run once per saved network, so a Mac that remembers 200 networks
        # spent over 15 minutes here and the check timed out. One report per
        # check is enough: every lookup below reads the same text.
        self._airport_report = _UNREAD

        # Get current Wi-Fi connection info
        current_network = self._get_current_network()
        if current_network:
            findings.extend(self._check_current_connection(current_network))

        # Get saved/preferred networks
        saved_networks = self._get_saved_networks()
        if saved_networks:
            findings.extend(self._check_saved_networks(saved_networks))

        # Add overall summary
        summary = self._get_summary(current_network, saved_networks)
        if summary:
            findings.append(summary)

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        """Provide informational guidance on Wi-Fi security improvements."""
        actions = []

        for finding in findings.findings:
            check_type = finding.data.get("check")

            if check_type == "wep_connected":
                title = "Immediately disconnect from WEP network"
                description = (
                    "WEP (Wired Equivalent Privacy) is completely broken and provides NO security.\n"
                    "Your traffic can be intercepted in seconds. Immediately:\n"
                    "1. Open System Settings > Wi-Fi\n"
                    "2. Click 'Wi-Fi Details' for your current network\n"
                    "3. Select 'Forget This Network'\n"
                    "4. Contact your network administrator to upgrade to WPA2/WPA3\n"
                    "\n"
                    "Do NOT transmit sensitive data on this network."
                )

            elif check_type == "open_network_connected":
                title = "Disconnect from open/unencrypted network"
                description = (
                    "You are connected to an open (unencrypted) Wi-Fi network. "
                    "Anyone can monitor your traffic.\n"
                    "1. Open System Settings > Wi-Fi\n"
                    "2. Select a different network or disconnect\n"
                    "3. If you must use this network, enable VPN before accessing sensitive data\n"
                    "4. Never access banking, email, or passwords on open networks"
                )

            elif check_type == "wep_saved":
                title = "Remove WEP networks from saved list"
                description = (
                    "WEP networks are saved on your computer. "
                    "Your Mac may auto-connect to these compromised networks.\n"
                    "1. Open System Settings > Wi-Fi\n"
                    "2. Click 'Wi-Fi Details'\n"
                    "3. Select WEP networks and click the '-' button to remove them\n"
                    "4. Ask network owner to upgrade routers to WPA2/WPA3"
                )

            elif check_type == "open_saved":
                title = "Remove open networks from saved list"
                description = (
                    "Open (unencrypted) Wi-Fi networks are saved. "
                    "Your Mac may auto-connect to these.\n"
                    "1. Open System Settings > Wi-Fi\n"
                    "2. Click 'Wi-Fi Details'\n"
                    "3. Select open networks and click '-' to remove them\n"
                    "4. Prefer WPA2/WPA3-secured networks instead"
                )

            elif check_type == "wpa2_only":
                title = "Upgrade to WPA3 if hardware supports it"
                description = (
                    "Your network uses WPA2, which is secure but older. "
                    "WPA3 is recommended for newer hardware.\n"
                    "1. Check if your Wi-Fi hardware supports WPA3\n"
                    "2. On newer Macs (2018+), WPA3 is typically available\n"
                    "3. Ask your network administrator to enable WPA3\n"
                    "4. To verify WPA3 support:\n"
                    "   - Click Wi-Fi menu > 'Wi-Fi Details'\n"
                    "   - Look for 'Security' field\n"
                    "   - Modern hardware should show WPA3 option"
                )

            elif check_type == "wifi_summary":
                # Informational - no action needed
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

    def _get_current_network(self) -> Optional[dict]:
        """Get current Wi-Fi network information."""
        try:
            # Get current network name
            result = subprocess.run(
                ["networksetup", "-getairportnetwork", "en0"],
                capture_output=True,
                text=True,
                timeout=5,
            )

            if result.returncode != 0:
                return None

            # Parse output: "Current Wi-Fi Network: NetworkName" or "Wi-Fi is off."
            output = result.stdout.strip()
            if "off" in output.lower():
                return None

            # Extract network name
            if ":" in output:
                network_name = output.split(":", 1)[1].strip()
                if network_name:
                    # Get security info for current network
                    security_info = self._get_network_security_info(network_name)
                    return {
                        "name": network_name,
                        "security": security_info.get("security", "Unknown"),
                        "is_hidden": security_info.get("is_hidden", False),
                    }

            return None
        except (subprocess.SubprocessError, Exception):
            return None

    def _airport_text(self) -> Optional[str]:
        """The Wi-Fi report from system_profiler, read at most once per check.

        None when it could not be read (failed or timed out); callers then
        report the security as Unknown, never as fine.
        """
        cached = getattr(self, "_airport_report", _UNREAD)
        if cached is not _UNREAD:
            return cached
        text: Optional[str] = None
        try:
            result = subprocess.run(
                ["system_profiler", "SPAirPortDataType"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode == 0:
                text = result.stdout
        except (subprocess.SubprocessError, Exception):
            text = None
        self._airport_report = text
        return text

    def _get_network_security_info(self, network_name: str) -> dict:
        """Get security info for a specific network via system_profiler."""
        try:
            output = self._airport_text()
            if output is None:
                return {"security": "Unknown", "is_hidden": False}
            is_hidden = False
            security = "Unknown"

            # Look for the current network section
            lines = output.split("\n")
            in_current_network = False
            for i, line in enumerate(lines):
                if "Current Network Information:" in line:
                    in_current_network = True
                elif in_current_network:
                    if "SSID:" in line or "Network Name:" in line:
                        if network_name in line:
                            # Found the network, look for security and other info
                            for j in range(i, min(i + 20, len(lines))):
                                if "Security:" in lines[j]:
                                    security = lines[j].split(":", 1)[1].strip()
                                elif "PHY Mode:" in lines[j]:
                                    # Continue searching
                                    pass
                    elif line.strip() and not line.startswith(" "):
                        # Left the network section
                        in_current_network = False

            # Simple heuristic: hidden networks don't show SSID broadcast
            if "<hidden>" in output.lower() or "hidden" in output.lower():
                is_hidden = True

            return {"security": security, "is_hidden": is_hidden}
        except (subprocess.SubprocessError, Exception):
            return {"security": "Unknown", "is_hidden": False}

    def _get_saved_networks(self) -> list[dict]:
        """Get list of saved/preferred Wi-Fi networks."""
        try:
            result = subprocess.run(
                ["networksetup", "-listpreferredwirelessnetworks", "en0"],
                capture_output=True,
                text=True,
                timeout=5,
            )

            if result.returncode != 0:
                return []

            networks = []
            for line in result.stdout.split("\n"):
                line = line.strip()
                if line and not line.startswith("Preferred networks"):
                    networks.append({"name": line})

            return networks
        except (subprocess.SubprocessError, Exception):
            return []

    def _check_current_connection(self, current_network: dict) -> list[Finding]:
        """Check security of current Wi-Fi connection."""
        findings = []
        security = current_network.get("security", "Unknown").lower()
        network_name = current_network.get("name", "Unknown")

        # Check for WEP
        if "wep" in security:
            findings.append(
                Finding(
                    code="network.wifi_security_audit.wep_connected",
                    title=f"Your Wi-Fi '{network_name}' uses WEP, which is easy to break",
                    description=(
                        f"Your Mac is connected to '{network_name}', which uses WEP. WEP "
                        "is an old security type that is easily broken. "
                        "This means people nearby can read your internet traffic, including "
                        "passwords and messages.\n\n"
                        "What to do: Open System Settings > Wi-Fi, select your current "
                        "network, and click 'Forget This Network'. "
                        "Connect to a different, secure network instead. Do not use this "
                        "one for sensitive tasks."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
                    data={
                        "check": "wep_connected",
                        "network": network_name,
                        "security": security,
                    },
                )
            )

        # Check for open/none security
        elif security == "unknown":
            findings.append(
                Finding(
                    title="Couldn't read your Wi-Fi's security type",
                    description=(
                        f"Your Mac is connected to '{network_name}', but Device Rescue "
                        "could not read what kind of security it uses. The security "
                        "type was not checked, so this result does not say whether the "
                        "network is protected or not.\n\n"
                        "What to do: Open System Settings > Wi-Fi and look at the "
                        "network's details to see its security type yourself."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    code="network.wifi_security_audit.security_unknown",
                    data={
                        "check": "security_unknown",
                        "network": network_name,
                    },
                )
            )

        # Check for open/none security
        elif "none" in security or "open" in security:
            findings.append(
                Finding(
                    code="network.wifi_security_audit.open_network_connected",
                    title=f"You are connected to an open Wi-Fi network: '{network_name}'",
                    description=(
                        f"Your Mac is connected to '{network_name}', which has no encryption. "
                        "This means anyone on the same Wi-Fi can see your internet traffic, "
                        "including passwords and messages.\n\n"
                        "What to do: Open System Settings > Wi-Fi and connect to a different, "
                        "secure network. "
                        "If you must use this one, turn on a VPN before doing anything sensitive."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
                    data={
                        "check": "open_network_connected",
                        "network": network_name,
                        "security": security,
                    },
                )
            )

        # Check for WPA2 (warn to upgrade to WPA3)
        elif "wpa2" in security and "wpa3" not in security:
            findings.append(
                Finding(
                    code="network.wifi_security_audit.wpa2_only",
                    title="Your Wi-Fi uses WPA2, which is secure but older",
                    description=(
                        f"You are connected to '{network_name}' using WPA2. This is a "
                        "secure standard, but it is older. "
                        "Newer Wi-Fi uses WPA3, which is harder to break. This is not "
                        "an emergency, but an upgrade is better.\n\n"
                        "What to do: Nothing urgent. If you control the Wi-Fi router, "
                        "you can ask your provider or IT to enable WPA3."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "check": "wpa2_only",
                        "network": network_name,
                        "security": security,
                    },
                )
            )

        # Check for hidden network
        if current_network.get("is_hidden"):
            findings.append(
                Finding(
                    code="network.wifi_security_audit.hidden_network",
                    title=f"Connected to hidden network: {network_name}",
                    description=(
                        f"'{network_name}' is a hidden network (SSID not broadcast). "
                        "Hidden networks offer only marginal additional security and may complicate troubleshooting."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "check": "hidden_network",
                        "network": network_name,
                    },
                )
            )

        return findings

    def _check_saved_networks(self, saved_networks: list[dict]) -> list[Finding]:
        """Check for weak security in saved networks."""
        findings = []
        weak_networks = {"wep": [], "open": []}

        for network in saved_networks:
            network_name = network.get("name", "")
            security_info = self._get_network_security_info(network_name)
            security = security_info.get("security", "Unknown").lower()

            if "wep" in security:
                weak_networks["wep"].append(network_name)
            elif "none" in security or "open" in security:
                weak_networks["open"].append(network_name)

        # Report WEP networks in saved list
        if weak_networks["wep"]:
            findings.append(
                Finding(
                    code="network.wifi_security_audit.wep_saved",
                    title=(
                        f"Your Mac remembers {len(weak_networks['wep'])} Wi-Fi networks with weak WEP"
                    ),
                    description=(
                        f"Your Mac has saved {len(weak_networks['wep'])} networks that "
                        f"use WEP: {', '.join(weak_networks['wep'])}. "
                        "WEP is easily broken, so your Mac might automatically connect "
                        "to these unsafe networks when it sees them.\n\n"
                        "What to do: Open System Settings > Wi-Fi, click 'Wi-Fi Details', "
                        "select these networks, and click the '-' button to remove them."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "check": "wep_saved",
                        "networks": weak_networks["wep"],
                    },
                )
            )

        # Report open networks in saved list
        if weak_networks["open"]:
            findings.append(
                Finding(
                    code="network.wifi_security_audit.open_saved",
                    title=(
                        f"Your Mac remembers {len(weak_networks['open'])} open Wi-Fi networks"
                    ),
                    description=(
                        f"Your Mac has saved {len(weak_networks['open'])} networks with "
                        f"no password: {', '.join(weak_networks['open'])}. "
                        "Because they are open, people nearby can see your internet traffic. "
                        "Your Mac might connect to them automatically.\n\n"
                        "What to do: Open System Settings > Wi-Fi, click 'Wi-Fi Details', "
                        "select these networks, and click the '-' button to remove them."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "check": "open_saved",
                        "networks": weak_networks["open"],
                    },
                )
            )

        return findings

    def _get_summary(
        self, current_network: Optional[dict], saved_networks: list[dict]
    ) -> Optional[Finding]:
        """Generate informational summary of Wi-Fi security configuration."""
        if not current_network and not saved_networks:
            return None

        summary_parts = []

        if current_network:
            security = current_network.get("security", "Unknown")
            summary_parts.append(f"Currently connected to: {current_network['name']} ({security})")

        saved_count = len(saved_networks)
        summary_parts.append(f"Saved networks: {saved_count}")

        description = "\n".join(summary_parts)

        return Finding(
            code="network.wifi_security_audit.wifi_summary",
            title="Your Wi-Fi security settings",
            description=description,
            severity=Severity.INFO,
            category=self.category,
            data={
                "check": "wifi_summary",
                "current_network": current_network["name"] if current_network else None,
                "saved_networks_count": saved_count,
            },
        )
