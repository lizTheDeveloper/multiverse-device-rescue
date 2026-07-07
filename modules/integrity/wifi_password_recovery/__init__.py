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
    name = "wifi_password_recovery"
    category = "integrity"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 45
    depends_on = []
    estimated_duration = "3s"

    # Threshold for warning about too many saved networks
    MAX_RECOMMENDED_NETWORKS = 30

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Get list of saved Wi-Fi networks
        saved_networks = self._get_saved_networks()

        if saved_networks is None:
            findings.append(
                Finding(
                    title="Unable to retrieve saved Wi-Fi networks",
                    description=(
                        "Could not query saved Wi-Fi networks using networksetup. "
                        "This may indicate a permission issue or system configuration problem."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "unable_to_query"},
                )
            )
            return CheckResult(module_name=self.name, findings=findings)

        # Get currently connected network
        current_network = self._get_current_network()

        # Add informational finding about saved networks
        if saved_networks:
            network_list = self._format_network_list(saved_networks)
            findings.append(
                Finding(
                    title=f"Saved Wi-Fi networks ({len(saved_networks)} total)",
                    description=(
                        f"Saved/preferred Wi-Fi networks on this system:\n{network_list}"
                        f"\n\nCurrently connected: {current_network if current_network else '(not connected)'}"
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "check": "saved_networks_info",
                        "network_count": len(saved_networks),
                        "networks": saved_networks,
                        "current_network": current_network,
                    },
                )
            )

            # Warn if too many saved networks (can slow down Wi-Fi scanning)
            if len(saved_networks) > self.MAX_RECOMMENDED_NETWORKS:
                findings.append(
                    Finding(
                        title=f"Too many saved Wi-Fi networks ({len(saved_networks)})",
                        description=(
                            f"This system has {len(saved_networks)} saved Wi-Fi networks, "
                            f"which exceeds the recommended limit of {self.MAX_RECOMMENDED_NETWORKS}. "
                            f"Having too many saved networks can slow down Wi-Fi scanning and may cause "
                            f"connection issues. Consider removing networks you no longer use via System Settings > Wi-Fi > Known Networks."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={
                            "check": "too_many_networks",
                            "network_count": len(saved_networks),
                            "threshold": self.MAX_RECOMMENDED_NETWORKS,
                        },
                    )
                )

            # Check if current network is in preferred list
            if current_network and current_network not in saved_networks:
                findings.append(
                    Finding(
                        title=f"Currently connected network '{current_network}' not in preferred list",
                        description=(
                            f"Your Mac is currently connected to '{current_network}', but this network "
                            f"is not in the list of saved/preferred networks. This is unusual and may indicate "
                            f"the network was manually connected or the preference list is out of sync."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={
                            "check": "current_not_in_preferred",
                            "current_network": current_network,
                        },
                    )
                )

        else:
            findings.append(
                Finding(
                    title="No saved Wi-Fi networks found",
                    description=(
                        "This system has no saved or preferred Wi-Fi networks. "
                        "Networks will be requested as you connect to them."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "check": "no_saved_networks",
                        "network_count": 0,
                        "current_network": current_network,
                    },
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        for finding in findings.findings:
            check = finding.data.get("check")

            if check == "unable_to_query":
                actions.append(
                    Action(
                        title="Unable to query Wi-Fi networks",
                        description=(
                            "The system could not retrieve your saved Wi-Fi networks. This is usually not "
                            "a critical issue. You can still manage Wi-Fi networks via System Settings > Wi-Fi > Known Networks. "
                            "If this error persists, try restarting your Mac or checking Wi-Fi permissions in System Settings > Privacy & Security."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "saved_networks_info":
                networks = finding.data.get("networks", [])
                current = finding.data.get("current_network")
                actions.append(
                    Action(
                        title=f"Saved Wi-Fi networks ({len(networks)} total)",
                        description=(
                            "Your Mac has remembered these Wi-Fi networks. To find the password for any of them, "
                            "open Keychain Access (Applications > Utilities > Keychain Access), search for the network name "
                            "in the search box, double-click the entry, check 'Show password', and authenticate with your Mac password. "
                            "Note: This app does NOT extract passwords for security reasons — you must retrieve them manually via Keychain Access."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "too_many_networks":
                count = finding.data.get("network_count", 0)
                threshold = finding.data.get("threshold", 30)
                actions.append(
                    Action(
                        title=f"Remove old Wi-Fi networks ({count} saved, {threshold} recommended)",
                        description=(
                            f"You have {count} saved Wi-Fi networks, which can slow down Wi-Fi scanning. "
                            f"To remove old networks: (1) Open System Settings > Wi-Fi > Known Networks; "
                            f"(2) Review the list and identify networks you no longer use (old offices, previous homes, etc.); "
                            f"(3) Click the minus (-) button next to each network to remove it; "
                            f"(4) Keep only networks you actively use (typically 5-10). Removing old networks will improve Wi-Fi scanning speed."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "current_not_in_preferred":
                current = finding.data.get("current_network", "unknown")
                actions.append(
                    Action(
                        title=f"Currently connected to non-preferred network: {current}",
                        description=(
                            f"Your Mac is connected to '{current}', which is not in the saved networks list. "
                            "This may happen if: (1) The network was manually connected without saving; "
                            "(2) The saved preference list became out of sync. "
                            "This is informational only. Your connection should work normally. "
                            "To add this network to saved networks for next time, disconnect and reconnect, "
                            "then check 'Remember this network' when prompted."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

            elif check == "no_saved_networks":
                actions.append(
                    Action(
                        title="No saved Wi-Fi networks",
                        description=(
                            "Your Mac has no saved Wi-Fi networks. This is normal for a fresh or newly reset system. "
                            "When you connect to a Wi-Fi network, your Mac will offer to save it for future use. "
                            "To manually view and manage networks, open System Settings > Wi-Fi > Known Networks."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _get_saved_networks(self) -> Optional[list[str]]:
        """Get list of saved Wi-Fi networks via networksetup.

        Returns a list of network names, or None if the command fails.
        """
        try:
            result = subprocess.run(
                ["networksetup", "-listpreferredwirelessnetworks", "en0"],
                capture_output=True,
                text=True,
                timeout=5,
            )

            if result.returncode != 0:
                return None

            output = result.stdout.strip()
            if not output:
                return []

            # Parse the output: first line is header "Preferred networks on en0:",
            # followed by network names, one per line, with a leading space
            networks = []
            lines = output.split("\n")
            for line in lines:
                line = line.strip()
                # Skip the header line and empty lines
                if line and not line.startswith("Preferred networks"):
                    networks.append(line)

            return networks

        except (subprocess.TimeoutExpired, OSError, FileNotFoundError):
            return None

    def _get_current_network(self) -> Optional[str]:
        """Get the currently connected Wi-Fi network name via airport command.

        Returns the SSID or None if not connected or command fails.
        """
        airport_path = (
            "/System/Library/PrivateFrameworks/Apple80211.framework/"
            "Versions/Current/Resources/airport"
        )

        try:
            result = subprocess.run(
                [airport_path, "-I"],
                capture_output=True,
                text=True,
                timeout=5,
            )

            if result.returncode != 0:
                return None

            output = result.stdout
            for line in output.split("\n"):
                line = line.strip()
                if line.startswith("SSID:"):
                    ssid = line.split(":", 1)[1].strip()
                    # Handle "SSID: <none>" case
                    if ssid and ssid.lower() != "<none>":
                        return ssid
                    return None

            return None

        except (subprocess.TimeoutExpired, OSError, FileNotFoundError):
            return None

    def _format_network_list(self, networks: list[str]) -> str:
        """Format network list for display in findings."""
        if not networks:
            return "  (no networks)"

        lines = ["  Saved networks:"]
        for network in networks:
            lines.append(f"    - {network}")

        return "\n".join(lines)
