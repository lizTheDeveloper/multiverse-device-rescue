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
    name = "network_speed_test"
    category = "integrity"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "15s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Get gateway IP and test local network latency
        gateway_latency = self._check_gateway_latency()
        if gateway_latency is not None:
            if gateway_latency["latency_ms"] > 10:
                findings.append(
                    Finding(
                        title="High local network latency",
                        description=(
                            f"Gateway latency is {gateway_latency['latency_ms']:.1f}ms (threshold: 10ms). "
                            "This indicates a problem with your local network connection."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={
                            "check_type": "gateway_latency",
                            "latency_ms": gateway_latency["latency_ms"],
                            "gateway_ip": gateway_latency.get("gateway_ip"),
                        },
                    )
                )
            else:
                findings.append(
                    Finding(
                        title="Local network latency",
                        description=(
                            f"Gateway latency: {gateway_latency['latency_ms']:.1f}ms (healthy)"
                        ),
                        severity=Severity.INFO,
                        category=self.category,
                        data={
                            "check_type": "gateway_latency_info",
                            "latency_ms": gateway_latency["latency_ms"],
                        },
                    )
                )

        # Test internet latency
        internet_latency = self._check_internet_latency()
        if internet_latency is not None:
            if internet_latency["latency_ms"] > 100:
                findings.append(
                    Finding(
                        title="High internet latency",
                        description=(
                            f"Internet latency is {internet_latency['latency_ms']:.1f}ms (threshold: 100ms). "
                            "Your internet connection quality may be degraded."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={
                            "check_type": "internet_latency",
                            "latency_ms": internet_latency["latency_ms"],
                        },
                    )
                )
            else:
                findings.append(
                    Finding(
                        title="Internet latency",
                        description=(
                            f"Internet latency: {internet_latency['latency_ms']:.1f}ms (healthy)"
                        ),
                        severity=Severity.INFO,
                        category=self.category,
                        data={
                            "check_type": "internet_latency_info",
                            "latency_ms": internet_latency["latency_ms"],
                        },
                    )
                )

        # Check DNS resolution time
        dns_time = self._check_dns_resolution_time()
        if dns_time is not None:
            if dns_time["time_ms"] > 500:
                findings.append(
                    Finding(
                        title="Slow DNS resolution",
                        description=(
                            f"DNS resolution time: {dns_time['time_ms']:.1f}ms (threshold: 500ms). "
                            "Your DNS servers may be slow or unresponsive."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={
                            "check_type": "dns_resolution_time",
                            "time_ms": dns_time["time_ms"],
                        },
                    )
                )
            else:
                findings.append(
                    Finding(
                        title="DNS resolution time",
                        description=(
                            f"DNS resolution time: {dns_time['time_ms']:.1f}ms (healthy)"
                        ),
                        severity=Severity.INFO,
                        category=self.category,
                        data={
                            "check_type": "dns_resolution_time_info",
                            "time_ms": dns_time["time_ms"],
                        },
                    )
                )

        # Check Wi-Fi link speed
        wifi_speed = self._check_wifi_link_speed()
        if wifi_speed is not None:
            if wifi_speed["speed_mbps"] < 50:
                findings.append(
                    Finding(
                        title="Low Wi-Fi link speed",
                        description=(
                            f"Wi-Fi link speed: {wifi_speed['speed_mbps']:.0f} Mbps (threshold: 50 Mbps). "
                            "Your Wi-Fi connection speed is very low. "
                            "This may be due to signal strength, interference, or router issues."
                        ),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={
                            "check_type": "wifi_speed",
                            "speed_mbps": wifi_speed["speed_mbps"],
                        },
                    )
                )
            else:
                findings.append(
                    Finding(
                        title="Wi-Fi link speed",
                        description=(
                            f"Wi-Fi link speed: {wifi_speed['speed_mbps']:.0f} Mbps (healthy)"
                        ),
                        severity=Severity.INFO,
                        category=self.category,
                        data={
                            "check_type": "wifi_speed_info",
                            "speed_mbps": wifi_speed["speed_mbps"],
                        },
                    )
                )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            check_type = finding.data.get("check_type")
            if check_type == "gateway_latency":
                actions.append(
                    Action(
                        title="High local network latency",
                        description=(
                            "High latency to your local gateway indicates a problem with your local network. "
                            "Try: (1) move closer to the router, (2) restart your router, "
                            "(3) check for Wi-Fi interference from other devices, "
                            "(4) switch to a less congested Wi-Fi channel (use System Settings > Network > Wi-Fi > Advanced)"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif check_type == "internet_latency":
                actions.append(
                    Action(
                        title="High internet latency",
                        description=(
                            "High latency to the internet suggests poor connection quality. "
                            "Try: (1) restart your router, (2) check your internet service quality, "
                            "(3) close bandwidth-heavy applications, (4) contact your ISP if the problem persists"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif check_type == "dns_resolution_time":
                actions.append(
                    Action(
                        title="Slow DNS resolution",
                        description=(
                            "Your DNS servers are responding slowly. "
                            "Try: (1) switch to a faster DNS provider (e.g., 8.8.8.8, 1.1.1.1), "
                            "(2) restart your router, (3) use System Settings > Network > Wi-Fi > Advanced > DNS "
                            "to change your DNS servers manually"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif check_type == "wifi_speed":
                actions.append(
                    Action(
                        title="Low Wi-Fi link speed",
                        description=(
                            "Your Wi-Fi connection speed is very low. "
                            "Try: (1) move closer to the router, (2) restart the router, "
                            "(3) switch to the 5GHz band if available (System Settings > Network > Wi-Fi > Advanced), "
                            "(4) check for Wi-Fi interference from other devices, "
                            "(5) change the Wi-Fi channel to reduce interference"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
        return FixResult(module_name=self.name, actions=actions)

    def _check_gateway_latency(self) -> Optional[dict]:
        """Check latency to the local gateway."""
        try:
            # Get the default gateway IP
            result = subprocess.run(
                ["route", "-n", "get", "default"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if result.returncode != 0:
                return None

            # Parse gateway IP from output like "gateway: 192.168.1.1"
            gateway_ip = None
            for line in result.stdout.split("\n"):
                if "gateway:" in line:
                    parts = line.split()
                    if len(parts) >= 2:
                        gateway_ip = parts[-1]
                        break

            if not gateway_ip:
                return None

            # Ping the gateway
            ping_result = subprocess.run(
                ["ping", "-c", "5", gateway_ip],
                capture_output=True,
                text=True,
                timeout=10,
            )

            if ping_result.returncode != 0:
                return None

            # Parse average latency from ping output
            avg_latency = self._parse_ping_latency(ping_result.stdout)
            if avg_latency is not None:
                return {"latency_ms": avg_latency, "gateway_ip": gateway_ip}

        except (subprocess.TimeoutExpired, OSError, ValueError):
            pass

        return None

    def _check_internet_latency(self) -> Optional[dict]:
        """Check latency to external DNS (8.8.8.8)."""
        try:
            result = subprocess.run(
                ["ping", "-c", "5", "8.8.8.8"],
                capture_output=True,
                text=True,
                timeout=10,
            )

            if result.returncode != 0:
                return None

            avg_latency = self._parse_ping_latency(result.stdout)
            if avg_latency is not None:
                return {"latency_ms": avg_latency}

        except (subprocess.TimeoutExpired, OSError, ValueError):
            pass

        return None

    def _check_dns_resolution_time(self) -> Optional[dict]:
        """Check DNS resolution time using dig."""
        try:
            result = subprocess.run(
                ["dig", "google.com", "+stats"],
                capture_output=True,
                text=True,
                timeout=10,
            )

            if result.returncode != 0:
                return None

            # Parse Query time from dig output like "Query time: 45 msec"
            for line in result.stdout.split("\n"):
                if "Query time:" in line:
                    # Extract milliseconds from "Query time: 45 msec"
                    match = re.search(r"Query time:\s*(\d+)\s*msec", line)
                    if match:
                        return {"time_ms": float(match.group(1))}

        except (subprocess.TimeoutExpired, OSError, ValueError):
            pass

        return None

    def _check_wifi_link_speed(self) -> Optional[dict]:
        """Check Wi-Fi link speed using system_profiler."""
        try:
            result = subprocess.run(
                ["system_profiler", "SPAirPortDataType"],
                capture_output=True,
                text=True,
                timeout=10,
            )

            if result.returncode != 0:
                return None

            # Look for patterns like "PHY Mode: 802.11ax (Wi-Fi 6)"
            # or "Transmit Rate: 867 Mbps"
            for line in result.stdout.split("\n"):
                if "Transmit Rate:" in line:
                    # Extract speed from "Transmit Rate: 867 Mbps"
                    match = re.search(r"Transmit Rate:\s*(\d+)\s*Mbps", line)
                    if match:
                        return {"speed_mbps": float(match.group(1))}

        except (subprocess.TimeoutExpired, OSError, ValueError):
            pass

        return None

    def _parse_ping_latency(self, ping_output: str) -> Optional[float]:
        """Extract average latency from ping output."""
        # Look for lines like "round-trip min/avg/max/stddev = 1.234/5.678/9.012/1.234 ms"
        for line in ping_output.split("\n"):
            if "round-trip" in line and "avg" in line:
                # Extract the average value (second number)
                match = re.search(r"min/avg/max/stddev\s*=\s*[\d.]+/([\d.]+)/", line)
                if match:
                    return float(match.group(1))
        return None
