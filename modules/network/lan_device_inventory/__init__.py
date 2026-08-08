"""List every device currently visible on the local network.

When someone has got onto a home Wi-Fi network, the first question is always
"who is actually on it?" — and the honest answer is that most people have
never looked. This module reads the machine's ARP/neighbour table, labels each
hardware address with the vendor that registered it, and presents the result
as a list to be reconciled device by device.

It deliberately does not scan or probe: it reports only devices that have
already exchanged traffic with this machine. That means the list can be
incomplete (a quiet device may not appear), which the findings say plainly
rather than implying the network has been fully enumerated.
"""

from typing import Any

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

# Devices listed individually in the finding description before it is
# truncated; the complete list always stays in the finding's data.
_MAX_LISTED_DEVICES = 40

_INCOMPLETE_LIST_CAVEAT = (
    "This list only includes devices that have exchanged traffic with this "
    "computer recently, so a device that stays quiet can be missing from it. "
    "The router's own admin page has the authoritative list of everything "
    "connected."
)


def _neighbors_module():
    return load_content_module("modules/network/lan_common/neighbors.py", _NEIGHBORS_KEY)


class Module(ModuleBase):
    name = "lan_device_inventory"
    category = "network"
    platforms = [Platform.DARWIN, Platform.WIN32, Platform.LINUX]
    risk_level = RiskLevel.SAFE
    priority = 55
    depends_on = []
    estimated_duration = "10s"

    def __init__(self) -> None:
        self._expected_device_count: int | None = None
        self._known_macs: set[str] = set()

    def configure(self, config: dict[str, Any]) -> None:
        """Accept an expected device count and a list of already-known MACs.

        Both come from a profile's ``module_config``. Without them the module
        still produces the inventory; with them it can point at the specific
        devices the household has not accounted for.
        """
        expected = config.get("expected_device_count")
        if isinstance(expected, int) and expected >= 0:
            self._expected_device_count = expected

        known = config.get("known_macs")
        if isinstance(known, (list, tuple)):
            neighbors = _neighbors_module()
            self._known_macs = {
                neighbors.normalise_mac(str(mac)) if neighbors else str(mac).lower()
                for mac in known
            }

    def check(self, profile: SystemProfile) -> CheckResult:
        neighbors = _neighbors_module()
        if neighbors is None:
            return CheckResult(
                module_name=self.name,
                error="Local-network helper data could not be loaded.",
            )

        entries = neighbors.read_neighbors(profile.platform.value)
        if not entries:
            return CheckResult(
                module_name=self.name,
                error=(
                    "The neighbour table could not be read, or is empty. Check that "
                    "this machine is connected to the network."
                ),
            )

        gateway_ips = {gw.ip for gw in neighbors.read_gateways(profile.platform.value)}
        vendors = neighbors.load_oui_vendors(_LAN_COMMON_DIR)

        devices = self._describe_devices(entries, gateway_ips, vendors, neighbors)
        findings = [self._inventory_finding(devices)]
        findings.extend(self._unaccounted_findings(devices))
        findings.extend(self._count_findings(devices))
        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        """Guidance only — identifying a device is something only its owner can do."""
        actions: list[Action] = []
        if not findings.findings:
            return FixResult(module_name=self.name, actions=actions)

        actions.append(
            Action(
                title="Account for every device on the list",
                description=(
                    "Go through the list one device at a time and name it out loud: "
                    "phone, laptop, TV, printer, thermostat, games console, doorbell. "
                    "Anything left over at the end is the thing to worry about.\n\n"
                    "Two tips that save time:\n"
                    "- Turn a device off and re-run this check. The entry that "
                    "disappears is that device.\n"
                    "- Modern phones use a different, randomised hardware address for "
                    "each network, so a phone will not match the address printed on "
                    "the box. That is normal privacy behaviour, not an intruder.\n\n"
                    f"{_INCOMPLETE_LIST_CAVEAT}"
                ),
                risk_level=RiskLevel.SAFE,
                kind=ActionKind.GUIDANCE,
                success=True,
            )
        )
        actions.append(
            Action(
                title="Remove unknown devices by changing the Wi-Fi password",
                description=(
                    "Blocking one device by its hardware address does not work — an "
                    "address can be changed in seconds. The reliable way to remove "
                    "everyone you have not authorised is:\n"
                    "1. Change the Wi-Fi password on the router to a new, long "
                    "passphrase.\n"
                    "2. Change the router's admin password too, and make it different "
                    "from the Wi-Fi password.\n"
                    "3. Reconnect your own devices with the new password.\n"
                    "4. Re-run this check — anything still present after the change "
                    "either has the new password or is connected by cable.\n\n"
                    "If unknown devices come back after a password change, the router "
                    "itself is compromised. Factory reset it, update its firmware, and "
                    "set it up again from scratch."
                ),
                risk_level=RiskLevel.MODERATE,
                kind=ActionKind.GUIDANCE,
                success=True,
            )
        )
        return FixResult(module_name=self.name, actions=actions)

    # ---------------- internals ----------------

    def _describe_devices(
        self,
        entries: list,
        gateway_ips: set[str],
        vendors: dict[str, str],
        neighbors,
    ) -> list[dict]:
        """Collapse the neighbour table into one record per hardware address."""
        by_mac: dict[str, dict] = {}
        for entry in entries:
            record = by_mac.get(entry.mac)
            if record is None:
                record = {
                    "mac": entry.mac,
                    "ips": [],
                    "interface": entry.interface,
                    "vendor": neighbors.vendor_for(entry.mac, vendors),
                    "is_gateway": False,
                    "randomised_mac": entry.is_locally_administered,
                }
                by_mac[entry.mac] = record
            if entry.ip not in record["ips"]:
                record["ips"].append(entry.ip)
            if entry.ip in gateway_ips:
                record["is_gateway"] = True
        return sorted(by_mac.values(), key=lambda r: _ip_sort_key(r["ips"][0]))

    def _inventory_finding(self, devices: list[dict]) -> Finding:
        lines = []
        for device in devices[:_MAX_LISTED_DEVICES]:
            label = device["vendor"] or (
                "unknown vendor (randomised address)"
                if device["randomised_mac"]
                else "unknown vendor"
            )
            role = " — your router" if device["is_gateway"] else ""
            lines.append(f"  {device['ips'][0]}  {device['mac']}  {label}{role}")
        if len(devices) > _MAX_LISTED_DEVICES:
            lines.append(f"  … and {len(devices) - _MAX_LISTED_DEVICES} more")

        return Finding(
            title=f"{len(devices)} device(s) visible on the local network",
            description=(
                "These devices have recently communicated with this computer over "
                "the local network:\n" + "\n".join(lines) + "\n\n"
                f"{_INCOMPLETE_LIST_CAVEAT}"
            ),
            severity=Severity.INFO,
            category=self.category,
            data={
                "check": "lan_inventory",
                "device_count": len(devices),
                "devices": devices,
                "confidence": "high",
            },
        )

    def _unaccounted_findings(self, devices: list[dict]) -> list[Finding]:
        if not self._known_macs:
            return []
        findings = []
        for device in devices:
            if device["mac"] in self._known_macs or device["is_gateway"]:
                continue
            vendor = device["vendor"] or "an unidentified vendor"
            findings.append(
                Finding(
                    title=f"Unrecognised device on the network: {device['ips'][0]}",
                    description=(
                        f"The device at {device['ips'][0]} ({device['mac']}, {vendor}) "
                        "is not in the list of devices this household has accounted "
                        "for. Identify it before assuming the worst — a new phone, a "
                        "guest, or a smart plug all look like this — but do not leave "
                        "it unexplained."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "check": "unrecognised_device",
                        "ip": device["ips"][0],
                        "mac": device["mac"],
                        "vendor": device["vendor"],
                        "confidence": "medium",
                    },
                )
            )
        return findings

    def _count_findings(self, devices: list[dict]) -> list[Finding]:
        expected = self._expected_device_count
        if expected is None or len(devices) <= expected:
            return []
        return [
            Finding(
                title=(
                    f"More devices on the network than expected "
                    f"({len(devices)} seen, {expected} expected)"
                ),
                description=(
                    f"{len(devices)} devices are visible but only {expected} were "
                    "expected. Work through the inventory above and identify the "
                    "extras. Remember that phones, tablets, TVs, speakers, and smart "
                    "home gadgets each count as one device, so the real number is "
                    "usually higher than people guess."
                ),
                severity=Severity.WARNING,
                category=self.category,
                data={
                    "check": "device_count_exceeded",
                    "device_count": len(devices),
                    "expected_device_count": expected,
                    "confidence": "medium",
                },
            )
        ]


def _ip_sort_key(ip: str) -> tuple:
    try:
        return tuple(int(part) for part in ip.split("."))
    except ValueError:
        return (999, 999, 999, 999)
