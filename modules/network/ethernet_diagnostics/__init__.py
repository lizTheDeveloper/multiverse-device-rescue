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
    name = "ethernet_diagnostics"
    category = "network"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "10s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        # Get Ethernet interfaces
        interfaces = self._get_ethernet_interfaces()
        if not interfaces:
            findings.append(
                Finding(
                    title="No Ethernet interfaces found",
                    description="No Ethernet adapters detected on this system.",
                    severity=Severity.INFO,
                    category=self.category,
                    data={"check": "no_ethernet"},
                )
            )
            return CheckResult(module_name=self.name, findings=findings)

        # Check each Ethernet interface
        for iface in interfaces:
            findings.extend(self._check_interface(iface))

        # Add summary if we found any interfaces
        if interfaces:
            summary = self._get_summary(interfaces)
            if summary:
                findings.append(summary)

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        """Provide informational guidance on Ethernet connectivity issues."""
        actions = []

        for finding in findings.findings:
            check_type = finding.data.get("check")

            if check_type == "self_assigned_ip":
                title = "DHCP failure detected - no valid IP address"
                description = (
                    "Your Ethernet interface has a self-assigned IP (169.254.x.x), "
                    "which means DHCP failed to assign a valid address.\n"
                    "Steps to resolve:\n"
                    "1. Check that your Ethernet cable is firmly connected\n"
                    "2. Verify the cable works (try different cable or port)\n"
                    "3. Restart your Mac: Apple menu > Restart\n"
                    "4. If using a dock/adapter, try a different USB-C/Thunderbolt port\n"
                    "5. Reset DHCP: System Settings > Network > Ethernet > Advanced > TCP/IP > Renew DHCP Lease\n"
                    "6. If problem persists, the adapter may be faulty - try a different adapter\n"
                    "\n"
                    "This is a CRITICAL issue - your Ethernet has no network connectivity."
                )

            elif check_type == "link_speed_mismatch":
                title = "Link speed mismatch - poor cable or switch port"
                description = (
                    "Your Ethernet is negotiated at 100 Mbps on a gigabit-capable adapter. "
                    "This typically indicates a bad cable, bad switch port, or driver issue.\n"
                    "Steps to resolve:\n"
                    "1. Try a different Ethernet cable (especially if it's old or coiled tightly)\n"
                    "2. Connect to a different port on your switch/hub/router\n"
                    "3. Verify the cable is not damaged or bent\n"
                    "4. For USB-C docks: try a different dock or USB-C port on your Mac\n"
                    "5. Check if your switch port is set to auto-negotiate (not forced to 100 Mbps)\n"
                    "6. Update your Mac's drivers/firmware\n"
                    "\n"
                    "A gigabit connection should negotiate at 1000 Mbps. "
                    "100 Mbps limits bandwidth significantly."
                )

            elif check_type == "high_packet_errors":
                title = "High packet error rate - cable or hardware issue"
                description = (
                    "Your Ethernet interface is reporting packet errors above 1%. "
                    "This indicates a hardware or cable problem.\n"
                    "Steps to resolve:\n"
                    "1. Replace the Ethernet cable (try a different cable first)\n"
                    "2. Connect to a different port on your switch/router\n"
                    "3. For docking stations/adapters:\n"
                    "   - Try the adapter in a different USB-C port\n"
                    "   - Try a different docking station\n"
                    "   - Update the adapter's firmware if available\n"
                    "4. Check your router/switch for issues\n"
                    "5. If errors persist, the adapter may be faulty\n"
                    "\n"
                    "High error rates cause slowdowns and connection drops."
                )

            elif check_type == "non_standard_mtu":
                title = "Non-standard MTU setting"
                description = (
                    "Your Ethernet MTU (Maximum Transmission Unit) is not 1500, "
                    "which is the standard for Ethernet.\n"
                    "This may cause compatibility issues or reduced performance.\n"
                    "Steps to resolve:\n"
                    "1. Open System Settings > Network > Ethernet > Advanced > Hardware\n"
                    "2. Check the MTU setting (should be 1500)\n"
                    "3. If it's not 1500, change it back to 1500\n"
                    "4. Click OK and reconnect\n"
                    "\n"
                    "Only change MTU if you specifically know your network requires it."
                )

            elif check_type == "interface_inactive":
                title = "Ethernet interface is inactive"
                description = (
                    "Your Ethernet interface is not active (no link detected).\n"
                    "Steps to resolve:\n"
                    "1. Check that your Ethernet cable is firmly connected\n"
                    "2. Verify the cable is not damaged\n"
                    "3. Try connecting to a different port on your switch/router\n"
                    "4. Try a different Ethernet cable\n"
                    "5. For USB-C docks: try a different USB-C port on your Mac\n"
                    "6. Restart your Mac\n"
                    "7. If the interface still doesn't activate, the adapter may be faulty\n"
                    "\n"
                    "No link means the physical connection is not established."
                )

            elif check_type == "ethernet_summary":
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

    def _get_ethernet_interfaces(self) -> list[str]:
        """Get list of Ethernet interfaces from networksetup."""
        try:
            result = subprocess.run(
                ["networksetup", "-listallhardwareports"],
                capture_output=True,
                text=True,
                timeout=5,
            )

            if result.returncode != 0:
                return []

            interfaces = []
            lines = result.stdout.split("\n")
            i = 0
            while i < len(lines):
                line = lines[i].strip()
                # Look for Ethernet entries
                if "Ethernet" in line:
                    # Next line should be "Device: ..."
                    if i + 1 < len(lines):
                        device_line = lines[i + 1].strip()
                        if device_line.startswith("Device:"):
                            device = device_line.split(":", 1)[1].strip()
                            interfaces.append(device)
                i += 1

            return interfaces
        except (subprocess.SubprocessError, Exception):
            return []

    def _check_interface(self, interface: str) -> list[Finding]:
        """Check a single Ethernet interface for issues."""
        findings = []

        # Get interface info via ifconfig
        iface_info = self._get_interface_info(interface)
        if not iface_info:
            return findings

        # Check link status
        is_active = iface_info.get("is_active", False)
        if not is_active:
            findings.append(
                Finding(
                    title=f"Ethernet interface {interface} is inactive",
                    description=(
                        f"Interface {interface} has no active link. "
                        "This means the physical connection is not established."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "check": "interface_inactive",
                        "interface": interface,
                    },
                )
            )
            return findings

        # Get IP info
        ip_addr = iface_info.get("ip_address", "")

        # Check for self-assigned IP
        if ip_addr.startswith("169.254."):
            findings.append(
                Finding(
                    title=f"Ethernet {interface}: Self-assigned IP detected",
                    description=(
                        f"Interface {interface} has self-assigned IP {ip_addr}. "
                        "DHCP failed to assign a valid address. "
                        "No network connectivity available."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
                    data={
                        "check": "self_assigned_ip",
                        "interface": interface,
                        "ip_address": ip_addr,
                    },
                )
            )

        # Get link speed
        speed_info = self._get_link_speed(interface)
        if speed_info:
            speed = speed_info.get("speed", "")
            findings.extend(self._check_link_speed(interface, speed))

        # Check MTU
        mtu = iface_info.get("mtu", 0)
        if mtu > 0 and mtu != 1500:
            findings.append(
                Finding(
                    title=f"Ethernet {interface}: Non-standard MTU ({mtu})",
                    description=(
                        f"Interface {interface} has MTU of {mtu}. "
                        "Standard Ethernet MTU is 1500. "
                        "Non-standard MTU may cause compatibility issues."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "check": "non_standard_mtu",
                        "interface": interface,
                        "mtu": mtu,
                    },
                )
            )

        # Check packet errors
        errors = self._get_packet_errors(interface)
        if errors is not None:
            findings.extend(self._check_packet_errors(interface, errors))

        return findings

    def _get_interface_info(self, interface: str) -> dict:
        """Get interface information via ifconfig."""
        try:
            result = subprocess.run(
                ["ifconfig", interface],
                capture_output=True,
                text=True,
                timeout=5,
            )

            if result.returncode != 0:
                return {}

            info = {"is_active": False, "ip_address": "", "mtu": 0}
            output = result.stdout

            # Check if interface is up
            if "status: active" in output.lower():
                info["is_active"] = True
            elif "UP," in output or "UP\n" in output:
                info["is_active"] = True

            # Extract IP address
            for line in output.split("\n"):
                if "inet " in line:
                    parts = line.strip().split()
                    if len(parts) > 1:
                        info["ip_address"] = parts[1]

                # Extract MTU
                if "mtu " in line.lower():
                    match = re.search(r"mtu (\d+)", line, re.IGNORECASE)
                    if match:
                        info["mtu"] = int(match.group(1))

            return info
        except (subprocess.SubprocessError, Exception):
            return {}

    def _get_link_speed(self, interface: str) -> dict:
        """Get link speed via system_profiler."""
        try:
            result = subprocess.run(
                ["system_profiler", "SPEthernetDataType"],
                capture_output=True,
                text=True,
                timeout=10,
            )

            if result.returncode != 0:
                return {}

            output = result.stdout
            speed_info = {}

            # Parse output for link speed
            lines = output.split("\n")
            for i, line in enumerate(lines):
                if interface in line or "Ethernet" in line:
                    # Look for speed info nearby
                    for j in range(max(0, i - 5), min(len(lines), i + 20)):
                        if "Link Speed:" in lines[j]:
                            speed = lines[j].split(":", 1)[1].strip()
                            speed_info["speed"] = speed
                            return speed_info

            return speed_info
        except (subprocess.SubprocessError, Exception):
            return {}

    def _check_link_speed(self, interface: str, speed: str) -> list[Finding]:
        """Check if link speed is appropriate."""
        findings = []

        # Check for 100 Mbps on gigabit adapter
        if "100" in speed and "Mbps" in speed:
            # This might be a speed mismatch (gigabit adapter running at 100)
            findings.append(
                Finding(
                    title=f"Ethernet {interface}: Link speed is 100 Mbps (possible degradation)",
                    description=(
                        f"Interface {interface} is negotiated at {speed}. "
                        "If this is a gigabit adapter, it should be 1000 Mbps. "
                        "This indicates a bad cable, bad switch port, or poor connection quality."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "check": "link_speed_mismatch",
                        "interface": interface,
                        "speed": speed,
                    },
                )
            )

        return findings

    def _get_packet_errors(self, interface: str) -> Optional[dict]:
        """Get packet error stats via netstat."""
        try:
            result = subprocess.run(
                ["netstat", "-i"],
                capture_output=True,
                text=True,
                timeout=5,
            )

            if result.returncode != 0:
                return None

            output = result.stdout
            lines = output.split("\n")

            for line in lines:
                if interface in line:
                    # Parse netstat output
                    parts = line.split()
                    # netstat -i format: Name Mtu Network Address Ipkts Ierrs Idrop Opkts Oerrs Coll
                    if len(parts) >= 10:
                        try:
                            # Typically column indices vary, but look for errors
                            # Standard: Name Mtu Network Address Ipkts Ierrs Idrop Opkts Oerrs Coll
                            ierrs = int(parts[5]) if parts[5] != "-" else 0
                            oerrs = int(parts[8]) if parts[8] != "-" else 0
                            ipkts = int(parts[4]) if parts[4] != "-" else 1  # Avoid division by zero
                            opkts = int(parts[7]) if parts[7] != "-" else 1

                            return {
                                "input_errors": ierrs,
                                "output_errors": oerrs,
                                "input_packets": ipkts,
                                "output_packets": opkts,
                            }
                        except (ValueError, IndexError):
                            pass

            return None
        except (subprocess.SubprocessError, Exception):
            return None

    def _check_packet_errors(self, interface: str, errors: dict) -> list[Finding]:
        """Check if packet error rate is acceptable."""
        findings = []

        ierrs = errors.get("input_errors", 0)
        oerrs = errors.get("output_errors", 0)
        ipkts = errors.get("input_packets", 1)
        opkts = errors.get("output_packets", 1)

        # Calculate error rates
        ierr_rate = (ierrs / ipkts * 100) if ipkts > 0 else 0
        oerr_rate = (oerrs / opkts * 100) if opkts > 0 else 0

        # Flag if error rate > 1%
        if ierr_rate > 1.0 or oerr_rate > 1.0:
            findings.append(
                Finding(
                    title=f"Ethernet {interface}: High packet error rate",
                    description=(
                        f"Interface {interface} reports high error rate: "
                        f"Input errors: {ierrs} ({ierr_rate:.2f}%), "
                        f"Output errors: {oerrs} ({oerr_rate:.2f}%). "
                        "This indicates a hardware or cable problem."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "check": "high_packet_errors",
                        "interface": interface,
                        "input_error_rate": ierr_rate,
                        "output_error_rate": oerr_rate,
                        "input_errors": ierrs,
                        "output_errors": oerrs,
                    },
                )
            )

        return findings

    def _get_summary(self, interfaces: list[str]) -> Optional[Finding]:
        """Generate informational summary of Ethernet configuration."""
        summary_parts = []

        for iface in interfaces:
            info = self._get_interface_info(iface)
            status = "active" if info.get("is_active") else "inactive"
            ip = info.get("ip_address", "no IP")
            mtu = info.get("mtu", 0)

            summary_parts.append(
                f"{iface}: {status} (IP: {ip}, MTU: {mtu})"
            )

        if not summary_parts:
            return None

        description = "\n".join(summary_parts)

        return Finding(
            title="Ethernet configuration summary",
            description=description,
            severity=Severity.INFO,
            category=self.category,
            data={
                "check": "ethernet_summary",
                "interfaces": interfaces,
            },
        )
