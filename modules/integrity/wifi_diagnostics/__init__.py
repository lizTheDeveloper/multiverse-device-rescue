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
    name = "wifi_diagnostics"
    category = "integrity"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "5s"

    # Path to macOS airport utility
    AIRPORT_PATH = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"

    # RSSI thresholds in dBm (more negative = weaker)
    RSSI_WEAK_THRESHOLD = -70  # Below this is considered weak
    RSSI_VERY_WEAK_THRESHOLD = -80  # Below this is very weak

    # TX rate (MCS index) thresholds
    TX_RATE_LOW_THRESHOLD = 2  # Below this is considered low

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Check Wi-Fi status and information
        wifi_info = self._get_wifi_info()

        if wifi_info is None:
            # Wi-Fi is not available
            findings.append(
                Finding(
                    title="Wi-Fi is off or unavailable",
                    description="Wi-Fi is not currently available on this system.",
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "wifi_status"},
                )
            )
        else:
            # Check connection status
            if not wifi_info.get("connected"):
                findings.append(
                    Finding(
                        title="Wi-Fi is not connected",
                        description=(
                            f"Wi-Fi interface is not connected to any network. "
                            f"Current state: {wifi_info.get('state', 'unknown')}."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={"check": "connection_status"},
                    )
                )
            else:
                # Check signal strength
                rssi = wifi_info.get("rssi")
                if rssi is not None:
                    signal_finding = self._check_signal_strength(rssi)
                    if signal_finding:
                        findings.append(signal_finding)

                # Check TX rate
                mcs = wifi_info.get("mcs")
                if mcs is not None:
                    tx_finding = self._check_tx_rate(mcs)
                    if tx_finding:
                        findings.append(tx_finding)

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            check_type = finding.data.get("check")

            if check_type == "wifi_status":
                actions.append(
                    Action(
                        title="Wi-Fi is off or unavailable",
                        description=(
                            "Wi-Fi is not enabled on this Mac. Enable Wi-Fi by clicking the Wi-Fi icon "
                            "in the menu bar and selecting a network, or use System Settings > Network > Wi-Fi. "
                            "If you see 'Wi-Fi: No hardware found', the Wi-Fi hardware may need service."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif check_type == "connection_status":
                actions.append(
                    Action(
                        title="Not connected to Wi-Fi network",
                        description=(
                            "Your Mac has Wi-Fi enabled but is not connected to any network. "
                            "Try: (1) click the Wi-Fi icon in the menu bar and select your network, "
                            "(2) if your network is not visible, use 'Other Networks' and enter details manually, "
                            "(3) forget the network and rejoin it, "
                            "(4) restart your Mac."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif check_type == "signal_strength":
                rssi = finding.data.get("rssi")
                actions.append(
                    Action(
                        title=f"Weak Wi-Fi signal (RSSI: {rssi} dBm)",
                        description=(
                            f"Your Wi-Fi signal is weak ({rssi} dBm). This may cause slow speeds or disconnections. "
                            f"Try: (1) move closer to your router, (2) remove obstacles between your Mac and router, "
                            f"(3) check if your router is in a central location, (4) reduce interference from other devices "
                            f"(microwaves, cordless phones), (5) consider upgrading to a 5GHz or Wi-Fi 6 network if available."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif check_type == "tx_rate":
                mcs = finding.data.get("mcs")
                actions.append(
                    Action(
                        title=f"Low Wi-Fi transmit rate (MCS index: {mcs})",
                        description=(
                            f"Your Wi-Fi transmit rate is low (MCS index {mcs}). This indicates a weak connection or interference. "
                            f"Try: (1) check your signal strength (see other diagnostics), "
                            f"(2) avoid using old Wi-Fi standards (802.11b), switch to 5GHz if available, "
                            f"(3) check for interference from other Wi-Fi networks using a Wi-Fi analyzer app, "
                            f"(4) ensure your router is using the latest firmware, "
                            f"(5) temporarily disable 2.4GHz band if 5GHz is available."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _get_wifi_info(self) -> Optional[dict]:
        """Get Wi-Fi information using airport command.

        Returns dict with keys: connected, state, ssid, rssi, channel, mcs, band, snr
        Returns None if Wi-Fi is off or airport command fails.
        """
        try:
            result = subprocess.run(
                [self.AIRPORT_PATH, "-I"],
                capture_output=True,
                text=True,
                timeout=5,
            )

            if result.returncode != 0:
                # Wi-Fi is off or airport command failed
                return None

            output = result.stdout
            if not output or not output.strip():
                return None

            wifi_info = self._parse_airport_output(output)
            return wifi_info

        except (subprocess.TimeoutExpired, OSError, FileNotFoundError):
            return None

    def _parse_airport_output(self, output: str) -> dict:
        """Parse airport -I output and extract Wi-Fi information."""
        info = {
            "connected": False,
            "state": None,
            "ssid": None,
            "bssid": None,
            "rssi": None,
            "channel": None,
            "mcs": None,
            "band": None,
            "snr": None,
        }

        lines = output.split("\n")
        for line in lines:
            line = line.strip()
            if not line:
                continue

            # Parse each field
            if line.startswith("SSID:"):
                info["ssid"] = line.split(":", 1)[1].strip()
            elif line.startswith("BSSID:"):
                info["bssid"] = line.split(":", 1)[1].strip()
            elif line.startswith("state:"):
                state = line.split(":", 1)[1].strip()
                info["state"] = state
                info["connected"] = state == "running"
            elif line.startswith("agrctlrssi:"):
                try:
                    rssi = int(line.split(":", 1)[1].strip())
                    info["rssi"] = rssi
                except ValueError:
                    pass
            elif line.startswith("RSSI:"):
                try:
                    rssi = int(line.split(":", 1)[1].strip())
                    info["rssi"] = rssi
                except ValueError:
                    pass
            elif line.startswith("channel:"):
                channel = line.split(":", 1)[1].strip()
                info["channel"] = channel
                # Determine band from channel
                if "," in channel:
                    # Format: "149,80" means channel 149 with 80MHz width
                    channel_num = int(channel.split(",")[0])
                else:
                    try:
                        channel_num = int(channel)
                    except ValueError:
                        channel_num = None

                if channel_num:
                    # 2.4GHz channels: 1-14
                    # 5GHz channels: 36-165
                    # 6GHz channels: 1-233
                    if 1 <= channel_num <= 14:
                        info["band"] = "2.4GHz"
                    elif 36 <= channel_num <= 165:
                        info["band"] = "5GHz"
                    elif channel_num >= 1:
                        info["band"] = "6GHz"

            elif line.startswith("MCS index:"):
                try:
                    mcs = int(line.split(":", 1)[1].strip())
                    info["mcs"] = mcs
                except ValueError:
                    pass
            elif line.startswith("MCS:"):
                try:
                    mcs = int(line.split(":", 1)[1].strip())
                    info["mcs"] = mcs
                except ValueError:
                    pass
            elif line.startswith("agrctlnoise:"):
                try:
                    noise = int(line.split(":", 1)[1].strip())
                    if info.get("rssi") is not None:
                        # SNR = RSSI - Noise (in dB)
                        info["snr"] = info["rssi"] - noise
                except ValueError:
                    pass

        return info

    def _check_signal_strength(self, rssi: int) -> Optional[Finding]:
        """Check if Wi-Fi signal strength is adequate.

        RSSI is in dBm, more negative values indicate weaker signal.
        Typical ranges:
        -30 to -50: Excellent
        -50 to -60: Good
        -60 to -70: Fair
        -70 to -80: Weak
        -80+: Very weak
        """
        if rssi < self.RSSI_WEAK_THRESHOLD:
            severity = (
                Severity.WARNING if rssi > self.RSSI_VERY_WEAK_THRESHOLD else Severity.CRITICAL
            )
            return Finding(
                title=f"Weak Wi-Fi signal detected (RSSI: {rssi} dBm)",
                description=(
                    f"Your Wi-Fi signal strength is weak ({rssi} dBm). "
                    f"This may result in slow speeds, intermittent connectivity, or frequent disconnections. "
                    f"Ideal RSSI is above -60 dBm."
                ),
                severity=severity,
                category=self.category,
                data={"check": "signal_strength", "rssi": rssi},
            )
        return None

    def _check_tx_rate(self, mcs: int) -> Optional[Finding]:
        """Check if Wi-Fi transmit rate is adequate.

        MCS (Modulation and Coding Scheme) index:
        0-7: 802.11n (20MHz)
        Higher values indicate better data rates
        MCS index 0 uses the most basic coding and is very slow
        """
        if mcs < self.TX_RATE_LOW_THRESHOLD:
            return Finding(
                title=f"Low Wi-Fi transmit rate (MCS index: {mcs})",
                description=(
                    f"Your Wi-Fi transmit rate is low (MCS index {mcs}). "
                    f"This indicates either weak signal, interference, or compatibility issues. "
                    f"Your connection speed will be significantly reduced."
                ),
                severity=Severity.WARNING,
                category=self.category,
                data={"check": "tx_rate", "mcs": mcs},
            )
        return None
