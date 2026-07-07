import subprocess
from typing import Optional
from collections import Counter

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
    name = "airport_wifi_scan"
    category = "integrity"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "5s"

    # Path to macOS airport utility
    AIRPORT_PATH = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"

    # SNR threshold (Signal-to-Noise Ratio in dB)
    SNR_POOR_THRESHOLD = 25  # Below this is considered poor

    # Channel congestion threshold
    CONGESTION_THRESHOLD = 5  # More than this many networks on a channel is congested

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Get current Wi-Fi connection info
        current_wifi = self._get_current_wifi_info()

        if current_wifi is None:
            findings.append(
                Finding(
                    title="Wi-Fi not connected",
                    description="Wi-Fi is not connected. Cannot scan for channel congestion.",
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "wifi_not_connected"},
                )
            )
            return CheckResult(module_name=self.name, findings=findings)

        # Scan nearby networks
        nearby_networks = self._scan_networks()

        if nearby_networks is None:
            findings.append(
                Finding(
                    title="Could not scan Wi-Fi networks",
                    description="Failed to scan nearby Wi-Fi networks. Airport command may not be available.",
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "scan_failed"},
                )
            )
            return CheckResult(module_name=self.name, findings=findings)

        # Extract current channel
        current_channel = current_wifi.get("channel")
        current_ssid = current_wifi.get("ssid")

        # Count networks per channel
        channel_counts = Counter()
        for network in nearby_networks:
            channel = network.get("channel")
            if channel:
                channel_counts[channel] += 1

        # Remove current network from congestion count (looking for other networks)
        if current_channel and current_ssid:
            # We count "other networks" on the same channel
            networks_on_current = [
                n for n in nearby_networks
                if n.get("channel") == current_channel and n.get("ssid") != current_ssid
            ]
            other_networks_count = len(networks_on_current)
        else:
            other_networks_count = 0

        # Check SNR (Signal-to-Noise Ratio)
        snr = current_wifi.get("snr")

        # Build findings
        # Check for channel congestion
        if other_networks_count > self.CONGESTION_THRESHOLD:
            findings.append(
                Finding(
                    title=f"Channel congestion detected",
                    description=(
                        f"Your current Wi-Fi channel ({current_channel}) has {other_networks_count} other networks nearby. "
                        f"This may cause interference and reduced speeds. Consider switching to a less congested channel."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "check": "channel_congestion",
                        "current_channel": current_channel,
                        "networks_on_channel": other_networks_count,
                    },
                )
            )

        # Check SNR
        if snr is not None and snr < self.SNR_POOR_THRESHOLD:
            findings.append(
                Finding(
                    title=f"Poor signal-to-noise ratio",
                    description=(
                        f"Your signal-to-noise ratio is poor ({snr} dB). This indicates weak signal relative to noise. "
                        f"This may cause slow speeds or intermittent connectivity."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "poor_snr", "snr": snr},
                )
            )

        # Generate channel congestion map and recommendations
        if channel_counts:
            # Find least congested channels
            sorted_channels = sorted(channel_counts.items(), key=lambda x: x[1])
            least_congested = sorted_channels[:3]  # Top 3 least congested

            congestion_map = ", ".join(
                f"Ch{ch}: {count} networks" for ch, count in sorted(channel_counts.items())
            )

            recommendations = ", ".join(
                f"Channel {ch} ({count} networks)"
                for ch, count in least_congested
            )

            findings.append(
                Finding(
                    title="Wi-Fi channel congestion map",
                    description=(
                        f"Current channel: {current_channel}\n"
                        f"Channel congestion: {congestion_map}\n"
                        f"Recommended alternatives: {recommendations}"
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={
                        "check": "channel_map",
                        "current_channel": current_channel,
                        "channel_counts": dict(channel_counts),
                        "recommendations": [ch for ch, _ in least_congested],
                    },
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []

        for finding in findings.findings:
            check_type = finding.data.get("check")

            if check_type == "wifi_not_connected":
                actions.append(
                    Action(
                        title="Connect to Wi-Fi network",
                        description=(
                            "Your Mac is not connected to any Wi-Fi network. "
                            "Click the Wi-Fi icon in the menu bar and select your network to connect."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif check_type == "scan_failed":
                actions.append(
                    Action(
                        title="Airport utility unavailable",
                        description=(
                            "The airport utility could not be accessed. "
                            "This is typically not a user-fixable issue. "
                            "If Wi-Fi is working normally, you can ignore this warning."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif check_type == "channel_congestion":
                current_channel = finding.data.get("current_channel")
                recommendations = finding.data.get("recommendations", [])
                if recommendations:
                    rec_str = ", ".join(str(ch) for ch in recommendations[:3])
                else:
                    rec_str = "a less congested channel"

                actions.append(
                    Action(
                        title=f"Switch from channel {current_channel} to reduce congestion",
                        description=(
                            f"Your current channel ({current_channel}) has many other networks nearby. "
                            f"To improve your Wi-Fi speed: "
                            f"1. Open System Settings > Wi-Fi > Options "
                            f"2. Look for 'Preferred Networks' "
                            f"3. Edit your network and try forcing it to use preferred channels "
                            f"4. Recommended channels: {rec_str} "
                            f"Note: Not all routers allow manual channel selection. Check your router settings."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif check_type == "poor_snr":
                actions.append(
                    Action(
                        title="Improve signal-to-noise ratio",
                        description=(
                            "Your signal-to-noise ratio is poor, indicating weak signal or high noise. "
                            "To improve: "
                            "1. Move closer to your router "
                            "2. Remove obstacles (walls, metal) between your Mac and router "
                            "3. Reduce interference from other devices (microwaves, cordless phones) "
                            "4. Try moving your router to a more central location "
                            "5. If available, switch to a 5GHz or Wi-Fi 6 network which may have better SNR"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _get_current_wifi_info(self) -> Optional[dict]:
        """Get current Wi-Fi connection info using airport -I command.

        Returns dict with keys: ssid, channel, rssi, noise, snr
        Returns None if not connected or airport command fails.
        """
        try:
            result = subprocess.run(
                [self.AIRPORT_PATH, "-I"],
                capture_output=True,
                text=True,
                timeout=5,
            )

            if result.returncode != 0:
                return None

            output = result.stdout
            if not output or not output.strip():
                return None

            return self._parse_airport_info(output)

        except (subprocess.TimeoutExpired, OSError, FileNotFoundError):
            return None

    def _scan_networks(self) -> Optional[list]:
        """Scan nearby Wi-Fi networks using airport -s command.

        Returns list of dicts with keys: ssid, channel, rssi, security
        Returns None if airport command fails.
        """
        try:
            result = subprocess.run(
                [self.AIRPORT_PATH, "-s"],
                capture_output=True,
                text=True,
                timeout=10,
            )

            if result.returncode != 0:
                return None

            output = result.stdout
            if not output or not output.strip():
                return None

            return self._parse_airport_scan(output)

        except (subprocess.TimeoutExpired, OSError, FileNotFoundError):
            return None

    def _parse_airport_info(self, output: str) -> dict:
        """Parse airport -I output and extract Wi-Fi information."""
        info = {
            "ssid": None,
            "channel": None,
            "rssi": None,
            "noise": None,
            "snr": None,
        }

        lines = output.split("\n")
        for line in lines:
            line = line.strip()
            if not line:
                continue

            if line.startswith("SSID:"):
                info["ssid"] = line.split(":", 1)[1].strip()
            elif line.startswith("channel:"):
                channel = line.split(":", 1)[1].strip()
                # Format: "149,80" means channel 149 with 80MHz width
                if "," in channel:
                    channel = channel.split(",")[0]
                try:
                    info["channel"] = int(channel)
                except ValueError:
                    pass
            elif line.startswith("agrctlrssi:"):
                try:
                    rssi = int(line.split(":", 1)[1].strip())
                    info["rssi"] = rssi
                except ValueError:
                    pass
            elif line.startswith("agrctlnoise:"):
                try:
                    noise = int(line.split(":", 1)[1].strip())
                    info["noise"] = noise
                except ValueError:
                    pass

        # Calculate SNR if we have both RSSI and noise
        if info["rssi"] is not None and info["noise"] is not None:
            # SNR = RSSI - Noise (in dB)
            info["snr"] = info["rssi"] - info["noise"]

        return info

    def _parse_airport_scan(self, output: str) -> list:
        """Parse airport -s output and extract nearby network information."""
        networks = []

        lines = output.split("\n")
        for line in lines:
            line = line.strip()
            if not line:
                continue

            # Skip header line
            if "SSID" in line and "BSSID" in line:
                continue

            # Parse network line: SSID BSSID RSSI CHANNEL HT CC SECURITY
            # Example: MyNetwork 00:11:22:33:44:55 -45 6 Y -- WPA2(PSK/FT/AES/AES)
            parts = line.split()
            if len(parts) < 7:
                continue

            try:
                # SSID is parts[0], BSSID is parts[1], RSSI is parts[2], Channel is parts[3]
                ssid = parts[0]
                bssid = parts[1]
                rssi = int(parts[2])
                channel = int(parts[3])

                networks.append(
                    {
                        "ssid": ssid,
                        "bssid": bssid,
                        "rssi": rssi,
                        "channel": channel,
                    }
                )
            except (ValueError, IndexError):
                # Skip lines that don't parse correctly
                continue

        return networks
