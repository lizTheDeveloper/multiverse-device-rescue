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
    name = "win_wifi_diagnostics"
    category = "integrity"
    platforms = [Platform.WIN32]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "10s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Check Wi-Fi connection status and details
        connection_findings = self._check_wifi_connection()
        findings.extend(connection_findings)

        # Check saved Wi-Fi profiles
        profile_finding = self._check_wifi_profiles()
        if profile_finding:
            findings.append(profile_finding)

        # Check Wi-Fi driver info
        driver_finding = self._check_wifi_driver()
        if driver_finding:
            findings.append(driver_finding)

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            check_type = finding.data.get("check_type")
            if check_type == "low_signal":
                actions.append(
                    Action(
                        title="Low Wi-Fi signal strength detected",
                        description=(
                            "Signal strength is below 50%. This can cause internet dropping and instability. "
                            "Try: (1) move closer to the router, "
                            "(2) reduce obstacles between device and router, "
                            "(3) check if other devices are using the 2.4GHz band heavily, "
                            "(4) consider moving to a less congested location."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif check_type == "congested_channel":
                actions.append(
                    Action(
                        title="Connected to congested Wi-Fi channel",
                        description=(
                            "Connected on a congested 2.4GHz channel (1, 6, or 11). "
                            "This can cause interference and dropping connections. "
                            "Try: (1) open router admin panel, "
                            "(2) scan for other networks and choose a less crowded channel, "
                            "(3) consider switching to 5GHz band if your device supports it, "
                            "(4) if on 2.4GHz, try channels 1, 6, or 11 that are further from neighbors."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif check_type == "old_driver":
                actions.append(
                    Action(
                        title="Wi-Fi driver is outdated",
                        description=(
                            "The Wi-Fi driver has not been updated recently. Outdated drivers can cause connection issues. "
                            "Try: (1) open Device Manager, "
                            "(2) find your network adapter under 'Network adapters', "
                            "(3) right-click and select 'Update driver', "
                            "(4) choose 'Search automatically for updated driver software', "
                            "(5) alternatively, visit your device/network adapter manufacturer's website for the latest driver."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif check_type == "too_many_profiles":
                actions.append(
                    Action(
                        title="Too many saved Wi-Fi profiles",
                        description=(
                            "More than 30 saved Wi-Fi profiles can slow down network scanning. "
                            "Try: (1) open Settings > Network & Internet > Wi-Fi > Manage known networks, "
                            "(2) remove Wi-Fi networks you no longer use, "
                            "(3) keep only active networks to improve connection speed."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif check_type == "connection_info":
                # Info findings don't need actions
                pass

        return FixResult(module_name=self.name, actions=actions)

    def _check_wifi_connection(self) -> list[Finding]:
        """Check current Wi-Fi connection status, signal strength, and channel."""
        findings = []
        try:
            result = subprocess.run(
                ["netsh", "wlan", "show", "interfaces"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode != 0:
                return findings

            output = result.stdout
            interface_data = self._parse_netsh_interface_output(output)

            if not interface_data:
                return findings

            # Extract connection info
            ssid = interface_data.get("SSID")
            signal = interface_data.get("Signal")
            channel = interface_data.get("Channel")
            band = interface_data.get("Band")
            speed = interface_data.get("Transmit Rate (Mbps)")

            # Flag INFO: Report connection details
            if ssid and ssid != "":
                description = f"Connected to: {ssid}"
                if signal:
                    description += f", Signal strength: {signal}"
                if channel:
                    description += f", Channel: {channel}"
                if band:
                    description += f", Band: {band}"
                if speed:
                    description += f", Speed: {speed} Mbps"

                findings.append(
                    Finding(
                        title="Wi-Fi connection information",
                        description=description,
                        severity=Severity.INFO,
                        category=self.category,
                        data={
                            "check_type": "connection_info",
                            "ssid": ssid,
                            "signal": signal,
                            "channel": channel,
                            "band": band,
                            "speed": speed,
                        },
                    )
                )

                # Flag WARNING: Signal strength below 50%
                if signal:
                    signal_percent = self._parse_signal_percentage(signal)
                    if signal_percent is not None and signal_percent < 50:
                        findings.append(
                            Finding(
                                title=f"Weak Wi-Fi signal ({signal})",
                                description=(
                                    f"Your connection to the Wi-Fi router is weak ({signal}). "
                                    "This usually means you are far from the router or "
                                    "there are walls in between. It can cause slow speeds "
                                    "or dropped connections.\n\n"
                                    "What to do: Try moving closer to your router. If "
                                    "the problem persists, you may need a Wi-Fi extender "
                                    "or a mesh system to improve coverage in that room."
                                ),
                                severity=Severity.WARNING,
                                category=self.category,
                                data={
                                    "check_type": "low_signal",
                                    "signal": signal,
                                    "signal_percent": signal_percent,
                                },
                            )
                        )

                # Flag WARNING: Connected on congested channel (1, 6, 11 on 2.4GHz)
                if channel and band and "2.4" in band:
                    try:
                        channel_num = int(channel)
                        if channel_num in [1, 6, 11]:
                            findings.append(
                                Finding(
                                    title=f"Connected to a busy Wi-Fi channel ({channel})",
                                    description=(
                                        f"Your router is using channel {channel} on the "
                                        "2.4GHz band. This is a very common channel, "
                                        "so it might be crowded with neighbors' networks, "
                                        "causing slower speeds.\n\n"
                                        "What to do: If your internet feels slow, log "
                                        "in to your router's admin page (usually 192.168.1.1 "
                                        "or 192.168.0.1) and change the Wi-Fi channel "
                                        "to a less crowded one, or switch to the 5GHz "
                                        "band if your router supports it."
                                    ),
                                    severity=Severity.WARNING,
                                    category=self.category,
                                    data={
                                        "check_type": "congested_channel",
                                        "channel": channel,
                                        "band": band,
                                    },
                                )
                            )
                    except (ValueError, TypeError):
                        pass

        except (subprocess.TimeoutExpired, OSError):
            pass

        return findings

    def _check_wifi_profiles(self) -> Optional[Finding]:
        """Check the number of saved Wi-Fi profiles."""
        try:
            result = subprocess.run(
                ["netsh", "wlan", "show", "profiles"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode != 0:
                return None

            output = result.stdout
            # Count profiles - look for lines starting with "All User Profile"
            profile_count = 0
            for line in output.split("\n"):
                if "All User Profile" in line or "User Profile" in line:
                    # Lines containing profile names have the pattern "All User Profile : name"
                    if ":" in line:
                        profile_count += 1

            # Flag WARNING: Too many profiles (>30)
            if profile_count > 30:
                return Finding(
                    title=f"Many saved Wi-Fi networks ({profile_count})",
                    description=(
                        f"Your computer remembers {profile_count} Wi-Fi networks. It is "
                        "likely just a list of places you have visited in the past.\n\n"
                        "What to do: You can ignore this. If you want to clean up, go "
                        "to Settings > Network & internet > Wi-Fi > Known networks and "
                        "remove networks you no longer use."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "check_type": "too_many_profiles",
                        "profile_count": profile_count,
                    },
                )

        except (subprocess.TimeoutExpired, OSError):
            pass

        return None

    def _check_wifi_driver(self) -> Optional[Finding]:
        """Check Wi-Fi driver information."""
        try:
            result = subprocess.run(
                ["netsh", "wlan", "show", "drivers"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode != 0:
                return None

            output = result.stdout
            driver_info = self._parse_netsh_driver_output(output)

            if not driver_info:
                return None

            # Check driver version and date
            driver_version = driver_info.get("Driver Version")
            driver_date = driver_info.get("Driver Date")

            # Simple heuristic: if driver version contains old patterns or date is very old
            # For now, flag if driver date is not recent (this is a simplified check)
            if driver_date:
                # Try to identify very old dates (before 2020)
                if any(year in driver_date for year in ["2015", "2016", "2017", "2018", "2019"]):
                    return Finding(
                        title=f"Your Wi-Fi driver is old (from {driver_date})",
                        description=(
                            "Your computer's Wi-Fi software (driver) was last updated "
                            f"on {driver_date} (version {driver_version}). Old drivers "
                            "can cause slow speeds or random disconnects.\n\n"
                            "What to do: Go to Settings > Windows Update and check for "
                            "updates. If an update is available, install it. If not, "
                            "check your computer manufacturer's website for a newer Wi-Fi "
                            "driver."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={
                            "check_type": "old_driver",
                            "driver_version": driver_version,
                            "driver_date": driver_date,
                        },
                    )

        except (subprocess.TimeoutExpired, OSError):
            pass

        return None

    def _parse_netsh_interface_output(self, output: str) -> dict[str, str]:
        """Parse netsh wlan show interfaces output."""
        data = {}
        for line in output.split("\n"):
            line = line.strip()
            if ":" in line:
                parts = line.split(":", 1)
                if len(parts) == 2:
                    key = parts[0].strip()
                    value = parts[1].strip()
                    if key and value:
                        data[key] = value
        return data

    def _parse_netsh_driver_output(self, output: str) -> dict[str, str]:
        """Parse netsh wlan show drivers output."""
        data = {}
        for line in output.split("\n"):
            line = line.strip()
            if ":" in line:
                parts = line.split(":", 1)
                if len(parts) == 2:
                    key = parts[0].strip()
                    value = parts[1].strip()
                    if key and value:
                        data[key] = value
        return data

    def _parse_signal_percentage(self, signal_str: str) -> Optional[int]:
        """Extract signal percentage from signal string like '75 %'."""
        if not signal_str:
            return None
        # Look for pattern like "75 %" or "75%"
        match = re.search(r"(\d+)\s*%", signal_str)
        if match:
            try:
                return int(match.group(1))
            except (ValueError, IndexError):
                return None
        return None
