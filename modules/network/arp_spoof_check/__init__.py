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
                    title="Your router's ID is being used by other devices",
                    description=(
                        f"The hardware address {mac} belongs to your router ({', '.join(gateway_matches)}) "
                        f"but is also claiming to be {', '.join(others[:8])}. Normally, "
                        "every device has a unique ID. When one ID appears for multiple "
                        "devices, it can mean a Wi-Fi extender is working as intended, "
                        "or it can mean a device is hiding behind your router's identity "
                        "to read your internet traffic.\n\n"
                        "If you think someone close to you set this up to monitor you, "
                        "removing it can alert them. Talk to an advocate first (US National "
                        "Domestic Violence Hotline: 1-800-799-7233, or text START to "
                        "88788).\n\n"
                        "What to do: Check if you have a Wi-Fi extender or mesh system. "
                        "If not, restart your router and run this check again."
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
                    title=f"One device is pretending to be {len(ips)} different computers",
                    description=(
                        f"The hardware address {mac} is claiming {len(ips)} different "
                        f"IP addresses ({', '.join(ips[:8])}). A single device answering "
                        "for many addresses is a common trick used to intercept traffic "
                        "from other devices on your network. However, virtual machines "
                        "and some network gear do this legitimately.\n\n"
                        "If you think someone close to you set this up to monitor you, "
                        "removing it can alert them. Talk to an advocate first (US National "
                        "Domestic Violence Hotline: 1-800-799-7233, or text START to "
                        "88788).\n\n"
                        "What to do: Identify which device this is. If you don't recognize "
                        "it, unplug it from your network."
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
                    title="Your router's ID looks fake",
                    description=(
                        f"The router at {entry.ip} reports the hardware address {entry.mac}. "
                        "This address is marked as 'locally administered,' meaning software "
                        "chose it rather than the manufacturer. Real routers usually "
                        "have a permanent ID assigned by the factory. A fake ID suggests "
                        "something is impersonating your router.\n\n"
                        "Virtual networks and some mesh systems also use these addresses, "
                        "so this might be normal for your setup.\n\n"
                        "What to do: Check the label on your physical router. If the "
                        f"address on the label doesn't match {entry.mac}, investigate "
                        "further."
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
                title=f"Your computer is set to send traffic through {len(unique)} routers",
                description=(
                    f"Your computer has {len(unique)} default routes configured: {', '.join(sorted(unique))}. "
                    "This means your internet traffic can leave through either path. "
                    "While a VPN or virtual machine often causes this, it can also happen "
                    "if a stranger on your Wi-Fi tricks your computer into sending data "
                    "to their device instead of your real router.\n\n"
                    "If you are not using a VPN or virtual machine, this is a sign that "
                    "someone might be trying to intercept your traffic.\n\n"
                    "What to do: If you are not using a VPN, restart your router and "
                    "your computer. If this persists, check your Wi-Fi password to ensure "
                    "it hasn't been shared."
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
