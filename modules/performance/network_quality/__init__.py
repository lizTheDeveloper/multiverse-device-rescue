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
    name = "network_quality"
    category = "performance"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "30s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Try networkQuality first (macOS 12+)
        speed_info = self._run_network_quality()

        # Fall back to ping if networkQuality failed
        if not speed_info:
            speed_info = self._run_ping_test()

        if not speed_info:
            # No way to test network quality
            return CheckResult(module_name=self.name, findings=findings)

        # Extract metrics
        download_mbps = speed_info.get("download_mbps", 0)
        upload_mbps = speed_info.get("upload_mbps", 0)
        rpm = speed_info.get("rpm", 0)
        latency_ms = speed_info.get("latency_ms", 0)

        # INFO: Report network speeds and latency
        if download_mbps > 0 or upload_mbps > 0 or latency_ms > 0 or rpm > 0:
            speed_desc = ""
            if download_mbps > 0:
                speed_desc += f"Download: {download_mbps:.1f} Mbps, "
            if upload_mbps > 0:
                speed_desc += f"Upload: {upload_mbps:.1f} Mbps, "
            if rpm > 0:
                speed_desc += f"Responsiveness (RPM): {rpm:.0f}"
            if latency_ms > 0 and rpm == 0:
                # Only add latency if we didn't already get RPM
                speed_desc += f"Latency: {latency_ms:.1f} ms"

            if speed_desc:
                findings.append(
                    Finding(
                        title="Network quality measured",
                        description=speed_desc.rstrip(", "),
                        severity=Severity.INFO,
                        category=self.category,
                        data={
                            "check": "network_speed",
                            "download_mbps": download_mbps,
                            "upload_mbps": upload_mbps,
                            "rpm": rpm,
                            "latency_ms": latency_ms,
                        },
                    )
                )

        # WARNING: Download speed below 10 Mbps
        if download_mbps > 0 and download_mbps < 10:
            findings.append(
                Finding(
                    title="Your internet download speed is slow",
                    description=(
                        f"Your download speed is {download_mbps:.1f} Mbps. For smooth "
                        "video calls and quick updates, most people need at least 10 "
                        "Mbps.\n\n"
                        "It just means your internet connection is slower than usual, "
                        "which might make videos buffer or files take longer to download.\n\n"
                        "What to do: Try restarting your router. If the speed stays low, "
                        "contact your internet provider to check if there is a problem "
                        "with your plan or local lines."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "check": "low_download_speed",
                        "download_mbps": download_mbps,
                    },
                )
            )

        # WARNING: Poor responsiveness (RPM below 50)
        if rpm > 0 and rpm < 50:
            findings.append(
                Finding(
                    title="Your internet connection feels laggy",
                    description=(
                        f"Your network responsiveness score is {rpm:.0f} (higher is "
                        "better; a few hundred or less feels laggy). It measures how quickly "
                        "your connection answers while it's busy.\n\n"
                        "It usually means your connection is busy or unstable. You might "
                        "notice delays in video calls or online games.\n\n"
                        "What to do: Restart your router. If the lag continues, try connecting "
                        "to a different Wi-Fi network or using a wired connection if "
                        "possible to see if the speed improves."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "check": "poor_responsiveness",
                        "rpm": rpm,
                    },
                )
            )

        # WARNING: High latency (if we got it from ping test)
        if latency_ms > 0 and latency_ms > 100:
            findings.append(
                Finding(
                    title="Your internet connection has high delay",
                    description=(
                        f"Your network latency is {latency_ms:.0f} milliseconds. Latency "
                        "is the time it takes for data to travel between your device "
                        "and the internet. Under 50ms is ideal.\n\n"
                        "It just means your connection is slow to react. You might notice "
                        "delays when typing in chat apps, playing online games, or using "
                        "video calls.\n\n"
                        "What to do: Restart your router. If the delay stays high, check "
                        "if other devices on your Wi-Fi are using a lot of data, or contact "
                        "your internet provider."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "check": "high_latency",
                        "latency_ms": latency_ms,
                    },
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            check = finding.data.get("check")
            if check == "low_download_speed":
                actions.append(
                    Action(
                        title="Improve download speed",
                        description=(
                            "Your download speed is below recommended levels. Try:\n"
                            "1. Move closer to your Wi-Fi router\n"
                            "2. Switch to a 5GHz Wi-Fi band if available\n"
                            "3. Check for interference from other devices\n"
                            "4. Restart your router and modem\n"
                            "5. Contact your ISP to check service quality\n"
                            "6. Consider upgrading your internet plan"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif check == "poor_responsiveness":
                actions.append(
                    Action(
                        title="Improve network responsiveness",
                        description=(
                            "Your network responsiveness is poor. Try:\n"
                            "1. Reduce interference: move closer to router, change Wi-Fi channel\n"
                            "2. Reduce network load: close other devices/applications using internet\n"
                            "3. Use Ethernet cable for critical applications\n"
                            "4. Check for background applications consuming bandwidth\n"
                            "5. Restart your router\n"
                            "6. Update router firmware"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif check == "high_latency":
                actions.append(
                    Action(
                        title="Reduce network latency",
                        description=(
                            "Your network latency is high. Try:\n"
                            "1. Check your internet connection stability\n"
                            "2. Close applications consuming bandwidth\n"
                            "3. Use a wired Ethernet connection if possible\n"
                            "4. Check if your router is overloaded\n"
                            "5. Restart your router and modem\n"
                            "6. Contact your ISP about latency issues"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif check == "network_speed":
                # Informational only
                actions.append(
                    Action(
                        title="Network speed information",
                        description=(
                            "Your network speed has been measured. Good speeds are:\n"
                            "- Download: 10+ Mbps (minimum for streaming)\n"
                            "- Upload: 1+ Mbps (minimum for video calls)\n"
                            "- Responsiveness (RPM): 50+ (higher is better)\n"
                            "Run this check periodically to monitor your network quality."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _run_network_quality(self) -> Optional[dict]:
        """Run macOS networkQuality command (macOS 12+)."""
        try:
            result = subprocess.run(
                ["networkQuality", "-s", "-v"],
                capture_output=True,
                text=True,
                timeout=30,
            )
            if result.returncode != 0:
                return None

            # Parse output to extract speeds and responsiveness
            # Example output includes lines like:
            # Downlink: 100.0 Mbps
            # Uplink: 50.0 Mbps
            # Responsiveness: 100 RPM
            info = {}

            # Look for download speed
            match = re.search(r"Downlink:\s+([\d.]+)\s*Mbps", result.stdout)
            if match:
                info["download_mbps"] = float(match.group(1))

            # Look for upload speed
            match = re.search(r"Uplink:\s+([\d.]+)\s*Mbps", result.stdout)
            if match:
                info["upload_mbps"] = float(match.group(1))

            # Look for responsiveness (RPM)
            match = re.search(r"Responsiveness:\s+([\d.]+)\s*(?:RPM)?", result.stdout)
            if match:
                info["rpm"] = float(match.group(1))

            return info if info else None
        except (subprocess.TimeoutExpired, FileNotFoundError, OSError):
            return None

    def _run_ping_test(self) -> Optional[dict]:
        """Fall back to ping test to 8.8.8.8 if networkQuality is not available."""
        try:
            # Ping Google DNS (8.8.8.8) 4 times with 2 second timeout
            result = subprocess.run(
                ["ping", "-c", "4", "-W", "2000", "8.8.8.8"],
                capture_output=True,
                text=True,
                timeout=10,
            )

            if result.returncode != 0:
                return None

            # Parse ping output to get average latency
            # Example: "round-trip min/avg/max/stddev = 10.234/15.432/20.123/3.456 ms"
            match = re.search(
                r"min/avg/max/(?:stddev|std)\s*=\s*([\d.]+)/([\d.]+)/([\d.]+)/?([\d.]+)?",
                result.stdout,
            )
            if match:
                latency_ms = float(match.group(2))  # Average latency
                # Convert ping latency to a rough RPM estimate
                # Assuming < 30ms is excellent (RPM ~100), > 100ms is poor (RPM ~50)
                rpm = max(0, 100 - (latency_ms - 10) / 0.9)
                rpm = min(100, rpm)

                return {
                    "latency_ms": latency_ms,
                    "rpm": rpm,
                    "download_mbps": 0,  # Not available from ping
                    "upload_mbps": 0,  # Not available from ping
                }

            return None
        except (subprocess.TimeoutExpired, OSError):
            return None
