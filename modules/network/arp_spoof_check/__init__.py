"""Detect ARP spoofing — someone on the network intercepting your traffic.

Getting onto a Wi-Fi network is the first step; the reason to bother is
usually the second one, which is to sit between you and the router and read
what you send. That attack (ARP spoofing, ARP poisoning, "man in the middle")
leaves a specific fingerprint in the neighbour table: the attacker's hardware
address starts answering for IP addresses that are not theirs, most often the
router's.

This module compares the machine's own view of the network against what a
healthy network looks like. It cannot see attacks that leave no local trace,
so a clean result means "nothing visible from here", not "nobody is watching".
"""

from collections import defaultdict

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
from rescue.runtime import content_directory, load_content_module

_LAN_COMMON_DIR = content_directory("modules/network/lan_common")
_NEIGHBORS_KEY = "rescue_lan_common_neighbors"

# One hardware address answering for several IPs is normal for a router doing
# proxy ARP or a host with several addresses; it becomes interesting at three.
_DUPLICATE_IP_THRESHOLD = 3

_CLEAN_RESULT_CAVEAT = (
    "A clean result here means no interception is visible from this computer. "
    "An attacker who only targets other devices on the network, or who "
    "intercepts traffic at the router itself, would not show up in this check."
)


def _neighbors_module():
    return load_content_module("modules/network/lan_common/neighbors.py", _NEIGHBORS_KEY)


class Module(ModuleBase):
    name = "arp_spoof_check"
    category = "network"
    platforms = [Platform.DARWIN, Platform.WIN32, Platform.LINUX]
    risk_level = RiskLevel.SAFE
    priority = 80
    depends_on = []
    estimated_duration = "10s"

    def check(self, profile: SystemProfile) -> CheckResult:
        neighbors = _neighbors_module()
        if neighbors is None:
            return CheckResult(
                module_name=self.name,
                error="Local-network helper data could not be loaded.",
            )

        platform = profile.platform.value
        entries = neighbors.read_neighbors(platform)
        gateways = neighbors.read_gateways(platform)

        if not entries:
            return CheckResult(
                module_name=self.name,
                error=(
                    "The neighbour table could not be read, or is empty. Check that "
                    "this machine is connected to the network."
                ),
            )

        gateway_ips = {gw.ip for gw in gateways}
        by_mac: dict[str, list[str]] = defaultdict(list)
        for entry in entries:
            if entry.ip not in by_mac[entry.mac]:
                by_mac[entry.mac].append(entry.ip)

        findings: list[Finding] = []
        findings.extend(self._check_gateway_impersonation(by_mac, gateway_ips))
        findings.extend(self._check_duplicate_macs(by_mac, gateway_ips))
        findings.extend(self._check_gateway_mac(entries, gateway_ips, neighbors))
        findings.extend(self._check_multiple_gateways(gateways))
        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        """Guidance only. Interception is an emergency, not a cleanup task."""
        actions: list[Action] = []
        if not findings.findings:
            return FixResult(module_name=self.name, actions=actions)

        interception = [
            f
            for f in findings.findings
            if f.data.get("check")
            in {"gateway_impersonation", "duplicate_mac", "multiple_gateways"}
        ]

        if interception:
            actions.append(
                Action(
                    title="Stop using this network for anything sensitive right now",
                    description=(
                        "Something on this network is answering for addresses that are "
                        "not its own, which is how traffic gets intercepted. Until it "
                        "is resolved:\n"
                        "- Do not sign in to anything, and do not change any passwords "
                        "while connected to this network.\n"
                        "- Switch to a phone's mobile hotspot for anything that "
                        "matters. Mobile data is not on the compromised network.\n"
                        "- If you must stay connected, a VPN encrypts what an "
                        "interceptor can read, but it does not remove them from the "
                        "network."
                    ),
                    risk_level=RiskLevel.SAFE,
                    kind=ActionKind.GUIDANCE,
                    success=True,
                )
            )
            actions.append(
                Action(
                    title="Confirm the router's real hardware address",
                    description=(
                        "Look at the label on the underside of the router, or its "
                        "admin page, and compare the hardware (MAC) address printed "
                        "there with the address reported above. If they differ, "
                        "another device is impersonating the router and everything "
                        "you send is passing through it first.\n\n"
                        "One caution: some mesh systems and Wi-Fi extenders legitimately "
                        "answer for the router. If the address belongs to your own "
                        "extender, that explains the result."
                    ),
                    risk_level=RiskLevel.SAFE,
                    kind=ActionKind.GUIDANCE,
                    success=True,
                )
            )
            actions.append(
                Action(
                    title="Evict the intruder and rebuild the network's credentials",
                    description=(
                        "An interceptor is already on the network, so the Wi-Fi "
                        "password is compromised. In this order:\n"
                        "1. Connect a computer to the router by cable if you can, so "
                        "the next steps do not go over the air.\n"
                        "2. Change the router's admin password.\n"
                        "3. Change the Wi-Fi password to a new long passphrase and set "
                        "the security mode to WPA3, or WPA2-AES if WPA3 is unavailable.\n"
                        "4. Turn off WPS — it lets a device join without the password.\n"
                        "5. Install any pending router firmware update.\n"
                        "6. Reconnect your devices and re-run this check.\n\n"
                        "Then change the passwords of accounts you used while the "
                        "interception was active, starting with email. Do that from a "
                        "device on a different network."
                    ),
                    risk_level=RiskLevel.MODERATE,
                    kind=ActionKind.GUIDANCE,
                    success=True,
                )
            )
        else:
            actions.append(
                Action(
                    title="Review the flagged hardware address",
                    description=(
                        "The result above is unusual but has innocent explanations — "
                        "mesh nodes, powerline adapters, and virtual machines can all "
                        "produce it. Identify the device before treating it as an "
                        f"attack. {_CLEAN_RESULT_CAVEAT}"
                    ),
                    risk_level=RiskLevel.SAFE,
                    kind=ActionKind.GUIDANCE,
                    success=True,
                )
            )

        return FixResult(module_name=self.name, actions=actions)

    # ---------------- checks ----------------

    def _check_gateway_impersonation(
        self, by_mac: dict[str, list[str]], gateway_ips: set[str]
    ) -> list[Finding]:
        """The strongest signal: the router's MAC also answering for other IPs."""
        findings = []
        for mac, ips in by_mac.items():
            gateway_matches = [ip for ip in ips if ip in gateway_ips]
            others = [ip for ip in ips if ip not in gateway_ips]
            if not gateway_matches or not others:
                continue
            findings.append(
                Finding(
                    title="Your router's hardware address is answering for other devices",
                    description=(
                        f"The hardware address {mac} belongs to your router "
                        f"({', '.join(gateway_matches)}) but is also claiming to be "
                        f"{', '.join(others[:8])}. On a healthy network each device has "
                        "its own address. This pattern is what traffic interception "
                        "looks like: one machine has positioned itself between you and "
                        "everything else so it can read what you send.\n\n"
                        "A Wi-Fi extender or mesh node repeating the network can produce "
                        "the same pattern legitimately — confirm which it is before "
                        "acting."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
                    data={
                        "check": "gateway_impersonation",
                        "mac": mac,
                        "gateway_ips": gateway_matches,
                        "other_ips": others,
                        "confidence": "medium",
                    },
                )
            )
        return findings

    def _check_duplicate_macs(
        self, by_mac: dict[str, list[str]], gateway_ips: set[str]
    ) -> list[Finding]:
        findings = []
        for mac, ips in by_mac.items():
            if any(ip in gateway_ips for ip in ips):
                continue  # already reported, with more context, above
            if len(ips) < _DUPLICATE_IP_THRESHOLD:
                continue
            findings.append(
                Finding(
                    title=f"One device is answering for {len(ips)} addresses",
                    description=(
                        f"The hardware address {mac} is claiming {len(ips)} different "
                        f"IP addresses ({', '.join(ips[:8])}). A single device "
                        "answering for many addresses is how an interceptor makes "
                        "other devices' traffic come to it. Virtual machines, "
                        "container hosts, and some network gear do this legitimately, "
                        "so identify the device before concluding anything."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "check": "duplicate_mac",
                        "mac": mac,
                        "ips": ips,
                        "confidence": "low",
                    },
                )
            )
        return findings

    def _check_gateway_mac(
        self, entries: list, gateway_ips: set[str], neighbors
    ) -> list[Finding]:
        """A router with a software-invented hardware address is suspicious."""
        findings = []
        reported: set[str] = set()
        for entry in entries:
            if entry.ip not in gateway_ips or entry.mac in reported:
                continue
            if not entry.is_locally_administered:
                continue
            reported.add(entry.mac)
            findings.append(
                Finding(
                    title="The router's hardware address looks software-generated",
                    description=(
                        f"The gateway at {entry.ip} reports the hardware address "
                        f"{entry.mac}. That address is marked as locally administered, "
                        "meaning it was chosen by software rather than assigned to the "
                        "hardware by its manufacturer. Real routers use a "
                        "manufacturer-assigned address; a made-up one suggests "
                        "something is impersonating the router.\n\n"
                        "Virtual networks, some corporate equipment, and a few mesh "
                        "systems also use locally administered addresses, so check the "
                        "address on the router's label before acting."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "check": "locally_administered_gateway",
                        "mac": entry.mac,
                        "ip": entry.ip,
                        "confidence": "low",
                    },
                )
            )
        return findings

    def _check_multiple_gateways(self, gateways: list) -> list[Finding]:
        unique = {gw.ip for gw in gateways if gw.ip}
        if len(unique) < 2:
            return []
        return [
            Finding(
                title=f"This machine has {len(unique)} default gateways configured",
                description=(
                    "More than one default route is configured: "
                    f"{', '.join(sorted(unique))}. Traffic can leave through either, "
                    "so a rogue router or a rogue DHCP server on the network can take "
                    "over part of your traffic without anything appearing to break. "
                    "A VPN client or a virtual machine bridge can also add a second "
                    "gateway legitimately."
                ),
                severity=Severity.WARNING,
                category=self.category,
                data={
                    "check": "multiple_gateways",
                    "gateways": sorted(unique),
                    "confidence": "medium",
                },
            )
        ]
