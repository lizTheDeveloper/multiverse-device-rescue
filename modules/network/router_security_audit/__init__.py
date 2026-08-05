"""Audit the home router's exposed surface, and give the reclaim procedure.

When someone has got onto a home network, the router is both the most likely
way in and the thing that has to be fixed first — a spotless laptop rejoins a
compromised network and is compromised again. Yet the router is usually the
one device nobody has ever logged into, still running its factory admin
password and 2019 firmware.

This module checks the router from the inside of the network: which
administrative services it is offering to every device on the Wi-Fi, and
whether UPnP is enabled (which lets any program on the network open a hole in
the firewall without being asked). It touches only the default gateway — the
user's own router — with short, bounded TCP connections, and never attempts to
authenticate to it.
"""

import socket

from rescue.models import (
    Action,
    ActionKind,
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
from rescue.runtime import load_content_module

_NEIGHBORS_KEY = "rescue_lan_common_neighbors"

_CONNECT_TIMEOUT = 1.0
_SSDP_TIMEOUT = 2.0

_SSDP_ADDRESS = ("239.255.255.250", 1900)
_SSDP_DISCOVER = (
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    'MAN: "ssdp:discover"\r\n'
    "MX: 1\r\n"
    "ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n"
    "\r\n"
)

# Administrative services checked on the gateway. Each entry says what the
# service is and how much it matters that it is reachable from the Wi-Fi.
_ADMIN_PORTS = [
    {
        "port": 23,
        "service": "Telnet",
        "severity": Severity.CRITICAL,
        "why": (
            "Telnet sends the admin password across the network in plain text, and "
            "is the single most common way home routers are taken over by botnets. "
            "No modern router needs it."
        ),
    },
    {
        "port": 21,
        "service": "FTP",
        "severity": Severity.WARNING,
        "why": (
            "FTP is unencrypted. If the router shares a USB drive this way, anyone "
            "on the Wi-Fi can read it and capture the password."
        ),
    },
    {
        "port": 22,
        "service": "SSH",
        "severity": Severity.WARNING,
        "why": (
            "SSH access to the router is encrypted but is still a login prompt "
            "offered to every device on the network. Disable it unless it is "
            "deliberately used."
        ),
    },
    {
        "port": 7547,
        "service": "TR-069 remote management (CWMP)",
        "severity": Severity.WARNING,
        "why": (
            "TR-069 lets the internet provider reconfigure the router remotely. "
            "Vulnerabilities in it have been used to compromise millions of home "
            "routers, and it should not be reachable from inside the network."
        ),
    },
    {
        "port": 80,
        "service": "Router admin page (unencrypted HTTP)",
        "severity": Severity.INFO,
        "why": (
            "The admin page is served without encryption, so the admin password is "
            "sent in the clear across the Wi-Fi every time it is used. Prefer the "
            "HTTPS admin page if the router offers one."
        ),
    },
    {
        "port": 8080,
        "service": "Alternate admin page (unencrypted HTTP)",
        "severity": Severity.INFO,
        "why": "A second unencrypted administration interface is reachable.",
    },
    {
        "port": 443,
        "service": "Router admin page (HTTPS)",
        "severity": Severity.INFO,
        "why": "This is the expected, encrypted way to administer the router.",
    },
    {
        "port": 8443,
        "service": "Alternate admin page (HTTPS)",
        "severity": Severity.INFO,
        "why": "A second encrypted administration interface is reachable.",
    },
]


def _neighbors_module():
    return load_content_module("modules/network/lan_common/neighbors.py", _NEIGHBORS_KEY)


class Module(ModuleBase):
    name = "router_security_audit"
    category = "network"
    platforms = [Platform.DARWIN, Platform.WIN32, Platform.LINUX]
    risk_level = RiskLevel.SAFE
    priority = 70
    depends_on = []
    estimated_duration = "15s"

    def check(self, profile: SystemProfile) -> CheckResult:
        neighbors = _neighbors_module()
        if neighbors is None:
            return CheckResult(
                module_name=self.name,
                error="Local-network helper data could not be loaded.",
            )

        gateways = neighbors.read_gateways(profile.platform.value)
        gateway_ips = [gw.ip for gw in gateways if gw.ip]
        if not gateway_ips:
            return CheckResult(
                module_name=self.name,
                error=(
                    "No default gateway is configured, so there is no router to audit. "
                    "Check that this machine is connected to the network."
                ),
            )

        gateway_ip = gateway_ips[0]
        findings = self._check_admin_ports(gateway_ip)
        findings.extend(self._check_upnp(gateway_ip))
        findings.append(self._reminder_finding(gateway_ip))
        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        """Guidance only — the toolkit never logs in to or reconfigures a router."""
        actions: list[Action] = []
        if not findings.findings:
            return FixResult(module_name=self.name, actions=actions)

        gateway_ip = next(
            (
                f.data.get("gateway_ip")
                for f in findings.findings
                if f.data.get("gateway_ip")
            ),
            "your router",
        )

        exposed = [
            f for f in findings.findings if f.data.get("check") == "admin_service_open"
        ]
        for finding in exposed:
            if finding.severity == Severity.INFO:
                continue
            service = finding.data.get("service", "the service")
            port = finding.data.get("port")
            actions.append(
                Action(
                    title=f"Turn off {service} on the router",
                    description=(
                        f"{finding.description}\n\n"
                        f"Sign in to the router at http://{gateway_ip}/ and look under "
                        "Administration, Management, or Advanced settings for the "
                        f"option controlling {service} (port {port}). Turn it off, save, "
                        "and re-run this check to confirm it is closed."
                    ),
                    risk_level=RiskLevel.MODERATE,
                    kind=ActionKind.GUIDANCE,
                    success=True,
                    data={"port": port, "service": service},
                )
            )

        if any(f.data.get("check") == "upnp_enabled" for f in findings.findings):
            actions.append(
                Action(
                    title="Consider turning off UPnP",
                    description=(
                        "UPnP lets any program on the network tell the router to open "
                        "a port to the internet, with no password and no prompt. "
                        "Malware uses it to make an infected machine reachable from "
                        "outside.\n\n"
                        "Turning it off is a real trade-off: games consoles, some "
                        "video-call software, and torrent clients rely on it and may "
                        "warn about a 'strict NAT' afterwards. If you turn it off, "
                        "first check the router's port-forwarding list and delete any "
                        "rule you did not create — those are the holes UPnP already "
                        "opened."
                    ),
                    risk_level=RiskLevel.MODERATE,
                    kind=ActionKind.GUIDANCE,
                    success=True,
                )
            )

        actions.append(
            Action(
                title="Take the router back: the full reclaim procedure",
                description=(
                    "If someone has been on this network, assume they have also been "
                    "on the router. Work through this in order, ideally on a computer "
                    "plugged in by cable:\n"
                    f"1. Sign in at http://{gateway_ip}/. If the password is still the "
                    "one printed on the router, assume the router is already "
                    "compromised.\n"
                    "2. Update the firmware first — later steps are pointless if a "
                    "known vulnerability is still present.\n"
                    "3. Set a new admin password, different from the Wi-Fi password.\n"
                    "4. Set a new Wi-Fi passphrase, and set security to WPA3 (or "
                    "WPA2-AES if WPA3 is not offered). Never WEP, never WPA/TKIP, "
                    "never open.\n"
                    "5. Turn off WPS. It allows joining with an 8-digit PIN that can "
                    "be guessed offline, and it defeats a strong Wi-Fi password.\n"
                    "6. Turn off remote/internet administration and 'cloud' management.\n"
                    "7. Check the DNS servers on the router's WAN or Internet page. If "
                    "they are not your provider's or a resolver you chose (for example "
                    "1.1.1.1 or 9.9.9.9), someone redirected the whole household's "
                    "browsing; reset them.\n"
                    "8. Delete port-forwarding rules and any 'DMZ host' you did not "
                    "create.\n"
                    "9. Check the guest network — leaving it open with no password is "
                    "an unlocked back door onto the same hardware.\n"
                    "10. Reboot the router, then re-run this check.\n\n"
                    "If the settings will not stick, or unwanted settings reappear, "
                    "factory reset the router (hold the reset pin for 30 seconds) and "
                    "set it up again from scratch — do not restore a saved "
                    "configuration backup, which would restore the attacker's changes "
                    "too."
                ),
                risk_level=RiskLevel.MODERATE,
                kind=ActionKind.GUIDANCE,
                success=True,
            )
        )
        return FixResult(module_name=self.name, actions=actions)

    # ---------------- checks ----------------

    def _check_admin_ports(self, gateway_ip: str) -> list[Finding]:
        findings = []
        for entry in _ADMIN_PORTS:
            if not _tcp_open(gateway_ip, entry["port"]):
                continue
            findings.append(
                Finding(
                    title=f"Router offers {entry['service']} to every device on the network",
                    description=(
                        f"The router at {gateway_ip} accepts connections on port "
                        f"{entry['port']} ({entry['service']}). {entry['why']}"
                    ),
                    severity=entry["severity"],
                    category=self.category,
                    data={
                        "check": "admin_service_open",
                        "gateway_ip": gateway_ip,
                        "port": entry["port"],
                        "service": entry["service"],
                        "confidence": "high",
                    },
                )
            )
        return findings

    def _check_upnp(self, gateway_ip: str) -> list[Finding]:
        response = _ssdp_discover()
        if not response:
            return []
        return [
            Finding(
                title="UPnP is enabled on the router",
                description=(
                    "The router answered a UPnP discovery request, which means any "
                    "program on this network can ask it to open a port to the "
                    "internet without a password and without telling anyone. That is "
                    "convenient for games consoles and a well-used route for malware "
                    "to make an infected machine reachable from outside.\n\n"
                    "Check the router's port-forwarding list for rules you did not "
                    "create."
                ),
                severity=Severity.WARNING,
                category=self.category,
                data={
                    "check": "upnp_enabled",
                    "gateway_ip": gateway_ip,
                    "confidence": "high",
                },
            )
        ]

    def _reminder_finding(self, gateway_ip: str) -> Finding:
        return Finding(
            title="Router settings that this check cannot see",
            description=(
                f"Your router is at {gateway_ip}. Several of the settings that decide "
                "whether someone can get back onto this network can only be seen by "
                "signing in to it: the admin password, the Wi-Fi passphrase and "
                "security mode, WPS, remote administration, the DNS servers it hands "
                "out, port-forwarding rules, and the firmware version.\n\n"
                "The remediation steps for this check walk through each of them in "
                "order."
            ),
            severity=Severity.INFO,
            category=self.category,
            data={
                "check": "router_manual_review",
                "gateway_ip": gateway_ip,
                "confidence": "high",
            },
        )


# ---------------- helpers ----------------


def _tcp_open(host: str, port: int) -> bool:
    """Return True if a TCP connection to host:port is accepted."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(_CONNECT_TIMEOUT)
            return sock.connect_ex((host, port)) == 0
    except OSError:
        return False


def _ssdp_discover() -> str:
    """Send one SSDP discovery request and return the first response."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(_SSDP_TIMEOUT)
            sock.sendto(_SSDP_DISCOVER.encode("ascii"), _SSDP_ADDRESS)
            data, _ = sock.recvfrom(2048)
            return data.decode("utf-8", errors="replace")
    except OSError:
        return ""
