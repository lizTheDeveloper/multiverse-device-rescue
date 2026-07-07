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
    name = "vpn_config"
    category = "security"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "3s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # List all VPN configurations
        vpn_configs = self._list_vpn_configs()

        if not vpn_configs:
            # No VPN configured
            findings.append(
                Finding(
                    title="No VPN configured",
                    description=(
                        "No VPN configurations are currently set up on this Mac. "
                        "For enhanced privacy and security, especially on public Wi-Fi networks, "
                        "consider configuring a VPN. VPNs encrypt your traffic and mask your IP address."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "no_vpn"},
                )
            )
        else:
            # Analyze each VPN configuration
            has_pptp = False
            vpn_list = []

            for vpn_name, vpn_type in vpn_configs.items():
                status = self._check_vpn_status(vpn_name)
                vpn_list.append({
                    "name": vpn_name,
                    "type": vpn_type,
                    "status": status,
                })

                # Flag PPTP as deprecated and insecure
                if vpn_type.upper() == "PPTP":
                    has_pptp = True
                    findings.append(
                        Finding(
                            title=f"PPTP VPN detected: {vpn_name}",
                            description=(
                                f"PPTP (Point-to-Point Tunneling Protocol) is deprecated and has known security "
                                f"vulnerabilities. It should not be used for security-sensitive communications. "
                                f"Consider replacing it with IKEv2, L2TP/IPSec, or a modern OpenVPN setup."
                            ),
                            severity=Severity.WARNING,
                            category=self.category,
                            data={
                                "check": "pptp_detected",
                                "vpn_name": vpn_name,
                                "vpn_type": vpn_type,
                            },
                        )
                    )

            # Add informational finding with all VPN configurations
            findings.append(
                Finding(
                    title=f"VPN configuration found ({len(vpn_configs)} configured)",
                    description=(
                        f"Found {len(vpn_configs)} VPN configuration(s) on this Mac:\n" +
                        "\n".join([
                            f"  - {v['name']}: {v['type']} ({v['status']})"
                            for v in vpn_list
                        ])
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "check": "vpn_list",
                        "vpn_count": len(vpn_configs),
                        "vpn_list": vpn_list,
                    },
                )
            )

        # Check for third-party VPN apps
        third_party_vpns = self._check_third_party_vpns()
        if third_party_vpns:
            findings.append(
                Finding(
                    title=f"Third-party VPN app(s) detected ({len(third_party_vpns)})",
                    description=(
                        f"Found {len(third_party_vpns)} third-party VPN application(s) with "
                        f"network extensions installed:\n" +
                        "\n".join([f"  - {app}" for app in third_party_vpns])
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "check": "third_party_vpns",
                        "app_count": len(third_party_vpns),
                        "apps": third_party_vpns,
                    },
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        """Provide informational guidance on VPN setup (never modifies settings)."""
        actions = []

        for finding in findings.findings:
            check_type = finding.data.get("check")

            if check_type == "no_vpn":
                title = "Set up a VPN"
                description = (
                    "To set up a VPN on macOS:\n"
                    "1. Open System Preferences > Network\n"
                    "2. Click the '+' button at the bottom left to add a new network service\n"
                    "3. Select the VPN type from the dropdown (IKEv2, L2TP, or PPP)\n"
                    "4. Give it a descriptive name\n"
                    "5. Enter the VPN server details provided by your VPN service\n"
                    "6. Configure authentication credentials\n"
                    "7. Click 'Create' and then 'Connect' to establish the VPN connection\n"
                    "\n"
                    "Alternatively, many third-party VPN providers offer dedicated macOS apps "
                    "that are easier to set up and use (e.g., Mullvad, Proton VPN, ExpressVPN)."
                )

            elif check_type == "pptp_detected":
                vpn_name = finding.data.get("vpn_name")
                title = f"Replace PPTP VPN: {vpn_name}"
                description = (
                    f"PPTP is insecure and should be replaced. To remove the PPTP VPN '{vpn_name}':\n"
                    f"1. Open System Preferences > Network\n"
                    f"2. Select the VPN service in the left panel\n"
                    f"3. Click the '-' button to remove it\n"
                    f"\n"
                    f"Then set up a more secure VPN (IKEv2, L2TP/IPSec, or a modern provider app)."
                )

            elif check_type == "vpn_list":
                vpn_list = finding.data.get("vpn_list", [])
                title = f"Review configured VPNs ({len(vpn_list)})"
                description = (
                    "Review your VPN configurations to ensure they are:\n"
                    "- Using secure protocols (IKEv2, L2TP/IPSec, or OpenVPN)\n"
                    "- Properly configured with correct server addresses\n"
                    "- Connecting successfully when needed\n"
                    "- Not accumulating unused or duplicate entries\n"
                    "\n"
                    "Current VPN configurations:\n" +
                    "\n".join([
                        f"  - {v['name']}: {v['type']} ({v['status']})"
                        for v in vpn_list
                    ])
                )

            elif check_type == "third_party_vpns":
                apps = finding.data.get("apps", [])
                title = f"Verify third-party VPN app(s) ({len(apps)})"
                description = (
                    "Third-party VPN apps are installed with network extensions. "
                    "Verify that these are trusted applications:\n" +
                    "\n".join([f"  - {app}" for app in apps]) +
                    "\n\n"
                    "To remove or manage these apps:\n"
                    "1. Open System Preferences > Security & Privacy > Extensions\n"
                    "2. Review network extensions from unknown or untrusted developers\n"
                    "3. If an app is unwanted, remove it from Applications and uninstall its extensions"
                )

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

    def _list_vpn_configs(self) -> dict[str, str]:
        """List all VPN configurations using scutil."""
        vpn_configs = {}
        try:
            result = subprocess.run(
                ["scutil", "--nc", "list"],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                return vpn_configs

            # Parse output looking for VPN entries
            lines = result.stdout.split("\n")
            for line in lines:
                line = line.strip()
                # Skip empty lines and headers
                if not line or line.startswith("*"):
                    continue

                # Lines with VPN configs look like: "x. ServiceName : IPv4, IPv6, DNS, WINS"
                # But we care about the ones that mention VPN types
                if "IKEv2" in line or "L2TP" in line or "PPTP" in line or "OpenVPN" in line:
                    vpn_name = self._extract_vpn_name(line)
                    vpn_type = self._extract_vpn_type(line)
                    if vpn_name and vpn_type:
                        vpn_configs[vpn_name] = vpn_type

            return vpn_configs
        except Exception:
            return vpn_configs

    def _extract_vpn_name(self, line: str) -> str | None:
        """Extract VPN name from a scutil line."""
        # Format: "x. ServiceName : ..."
        if ":" not in line:
            return None
        parts = line.split(":")
        if not parts or not parts[0]:
            return None
        # Remove numbering if present
        name_part = parts[0].strip()
        # Remove leading number and dot
        if name_part and name_part[0].isdigit():
            name_part = name_part[1:].lstrip(". ")
        return name_part.strip() if name_part else None

    def _extract_vpn_type(self, line: str) -> str | None:
        """Extract VPN type from a scutil line."""
        if "IKEv2" in line:
            return "IKEv2"
        elif "L2TP" in line:
            return "L2TP"
        elif "PPTP" in line:
            return "PPTP"
        elif "OpenVPN" in line:
            return "OpenVPN"
        return None

    def _check_vpn_status(self, vpn_name: str) -> str:
        """Check if a VPN is currently connected."""
        try:
            result = subprocess.run(
                ["scutil", "--nc", "status", vpn_name],
                capture_output=True,
                text=True,
            )
            if result.returncode == 0:
                output = result.stdout.lower()
                if "connected" in output or "established" in output:
                    return "Connected"
                elif "connecting" in output:
                    return "Connecting"
                else:
                    return "Disconnected"
            return "Unknown"
        except Exception:
            return "Unknown"

    def _check_third_party_vpns(self) -> list[str]:
        """Check for third-party VPN apps by looking at network extensions."""
        third_party_vpns = []
        try:
            # Use systemextensionsctl to list network extensions
            result = subprocess.run(
                ["systemextensionsctl", "list"],
                capture_output=True,
                text=True,
            )
            if result.returncode != 0:
                return third_party_vpns

            # Look for VPN-related extensions
            vpn_keywords = ["vpn", "wireguard", "openvpn", "mullvad", "proton", "expressvpn"]
            lines = result.stdout.split("\n")
            for line in lines:
                line_lower = line.lower()
                if any(keyword in line_lower for keyword in vpn_keywords):
                    # Extract app name from the extension line
                    if line.strip():
                        # Try to extract bundle identifier or app name
                        parts = line.split()
                        if parts:
                            app_name = parts[0] if parts else "Unknown"
                            if app_name not in third_party_vpns:
                                third_party_vpns.append(app_name)
            return third_party_vpns
        except Exception:
            return third_party_vpns
