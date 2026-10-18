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
            # Neither the airport tool (removed in macOS 14.4) nor
            # system_profiler gave an answer: that is "couldn't check", not
            # "Wi-Fi is off".
            findings.append(
                Finding(
                    title="Couldn't check your Wi-Fi",
                    description=(
                        "Device Rescue couldn't read your Mac's Wi-Fi status, so it "
                        "doesn't know whether Wi-Fi is on. This is not a sign that "
                        "anything is wrong."
                    ),
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "wifi_unknown"},
                )
            )
        elif wifi_info.get("power") is False:
            # Wi-Fi is off
            findings.append(
                Finding(
                    title="Wi-Fi is off or unavailable",
                    description=(
                        "Your Mac's Wi-Fi is currently turned off or not working.\n\n"
                        "What to do: Click the Wi-Fi icon in the menu bar and turn it "
                        "on, or restart your Mac if it stays off."
                    ),
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
                        title="Wi-Fi is not connected to a network",
                        description=(
                            "Your Wi-Fi is on, but it is not connected to any network. "
                            f"Current state: {wifi_info.get('state', 'unknown')}.\n\n"
                            "What to do: Click the Wi-Fi icon in the menu bar and select "
                            "your home network to reconnect."
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
        """Get Wi-Fi information.

        Returns dict with keys: power, connected, state, ssid, rssi, channel,
        mcs, band, snr. ``power`` is False when Wi-Fi is switched off.
        Returns None if nothing could be read.

        The ``airport`` tool was removed in macOS 14.4, so on current macOS
        this falls back to ``system_profiler SPAirPortDataType``. Treating the
        missing tool as "Wi-Fi is off" reported a connected Mac as offline.
        """
        try:
            result = subprocess.run(
                [self.AIRPORT_PATH, "-I"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            output = result.stdout if result.returncode == 0 else ""
            if isinstance(output, str) and output.strip():
                if re.search(r"AirPort:\s*Off", output):
                    return {"power": False, "connected": False, "state": "off"}
                wifi_info = self._parse_airport_output(output)
                wifi_info.setdefault("power", True)
                return wifi_info
        except (subprocess.TimeoutExpired, OSError, FileNotFoundError):
            pass

        try:
            result = subprocess.run(
                ["system_profiler", "SPAirPortDataType"],
                capture_output=True,
                text=True,
                timeout=30,
            )
        except (subprocess.SubprocessError, OSError):
            return None
        if result.returncode != 0 or not isinstance(result.stdout, str):
            return None
        return self._parse_system_profiler_output(result.stdout)

    @staticmethod
    def _parse_system_profiler_output(output: str) -> Optional[dict]:
        """Parse the first Wi-Fi interface in ``system_profiler SPAirPortDataType``."""
        status = re.search(r"^\s*Status:\s*(.+?)\s*$", output, re.MULTILINE)
        if not status:
            return None
        state = status.group(1)
        lowered = state.lower()
        if lowered == "off":
            return {"power": False, "connected": False, "state": "off"}
        info: dict = {"power": True, "state": state, "connected": lowered == "connected"}
        if not info["connected"]:
            return info
        current = output.split("Current Network Information:", 1)
        section = current[1].split("Other Local Wi-Fi Networks:", 1)[0] if len(current) > 1 else ""
        sn = re.search(r"Signal / Noise:\s*(-?\d+)\s*dBm\s*/\s*(-?\d+)\s*dBm", section)
        if sn:
            info["rssi"] = int(sn.group(1))
            info["snr"] = int(sn.group(1)) - int(sn.group(2))
        mcs = re.search(r"MCS Index:\s*(\d+)", section)
        if mcs:
            info["mcs"] = int(mcs.group(1))
        channel = re.search(r"Channel:\s*(\d+)\s*\((\d)GHz", section)
        if channel:
            info["channel"] = int(channel.group(1))
            info["band"] = {"2": "2.4GHz", "5": "5GHz", "6": "6GHz"}.get(channel.group(2))
        return info

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
                title=f"Weak Wi-Fi signal ({rssi} dBm)",
                description=(
                    f"Your Wi-Fi signal is weak right now ({rssi} dBm). A stronger signal "
                    "is usually above -60 dBm. This often causes slow speeds or dropped "
                    "connections.\n\n"
                    "What to do: Try moving closer to your router or removing obstacles "
                    "between your Mac and the router."
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
                title=f"Low Wi-Fi speed setting (MCS {mcs})",
                description=(
                    f"Your Mac is using a basic Wi-Fi speed setting (MCS index {mcs}). "
                    "This usually happens when the signal is weak or there is interference. "
                    "It makes your connection slower.\n\n"
                    "What to do: Move closer to your router to improve the signal, or "
                    "check if other devices are using the same network heavily."
                ),
                severity=Severity.WARNING,
                category=self.category,
                data={"check": "tx_rate", "mcs": mcs},
            )
        return None
