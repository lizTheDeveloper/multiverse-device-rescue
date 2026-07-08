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
    name = "wifi_security_audit"
    category = "network"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "5s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

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

    def _get_network_security_info(self, network_name: str) -> dict:
        """Get security info for a specific network via system_profiler."""
        try:
            result = subprocess.run(
                ["system_profiler", "SPAirPortDataType"],
                capture_output=True,
                text=True,
                timeout=10,
            )

            if result.returncode != 0:
                return {"security": "Unknown", "is_hidden": False}

            output = result.stdout
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
                if line and not line.startswith("Preferred networks:"):
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
                    title="CRITICAL: Currently connected via WEP network",
                    description=(
                        f"Your Mac is connected to '{network_name}' which uses WEP (Wired Equivalent Privacy). "
                        "WEP is completely broken and provides no security. "
                        "All your network traffic can be intercepted and decrypted in seconds. "
                        "This is a critical security risk. Immediately disconnect and connect to a secure network."
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
        elif "none" in security or "open" in security or security == "unknown":
            findings.append(
                Finding(
                    title="CRITICAL: Connected to open/unencrypted network",
                    description=(
                        f"Your Mac is connected to '{network_name}' which has no encryption. "
                        "Anyone on this network can monitor your traffic, intercept passwords, and steal data. "
                        "If you must use this network, enable VPN before accessing any sensitive information."
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
                    title="WARNING: Using WPA2 (consider upgrading to WPA3)",
                    description=(
                        f"Connected to '{network_name}' using WPA2 encryption. "
                        "WPA2 is secure but older. WPA3 provides stronger protection against brute-force attacks. "
                        "If your hardware supports it, ask your network administrator to enable WPA3."
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
                    title="INFO: Connected to hidden network",
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
                    title=f"WARNING: {len(weak_networks['wep'])} WEP network(s) in saved list",
                    description=(
                        f"Your Mac has saved these WEP networks: {', '.join(weak_networks['wep'])}. "
                        "WEP is broken encryption. Your Mac may auto-connect to these vulnerable networks. "
                        "Remove them from your saved networks list immediately and ask the network owner to upgrade."
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
                    title=f"WARNING: {len(weak_networks['open'])} open/unencrypted network(s) in saved list",
                    description=(
                        f"Your Mac has saved these unencrypted networks: {', '.join(weak_networks['open'])}. "
                        "Without encryption, anyone can monitor your traffic. "
                        "Remove these from saved networks and prefer WPA2/WPA3-protected networks instead."
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
            title="Wi-Fi security configuration summary",
            description=description,
            severity=Severity.INFO,
            category=self.category,
            data={
                "check": "wifi_summary",
                "current_network": current_network["name"] if current_network else None,
                "saved_networks_count": saved_count,
            },
        )
