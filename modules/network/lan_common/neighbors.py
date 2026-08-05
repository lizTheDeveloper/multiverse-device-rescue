"""Read the local machine's view of its network neighbours.

Every device that has recently talked to this machine leaves an entry in the
ARP/neighbour table: an IP address and the hardware (MAC) address behind it.
That table is the only view of "who else is on this Wi-Fi" available without
scanning, and it is what both the LAN inventory and the ARP-spoofing check are
built on.

Read-only, bounded, and platform-aware. Every command has a timeout and every
parse failure degrades to an empty result rather than raising.
"""

from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

_COMMAND_TIMEOUT = 15

# A table larger than this on a home network means something is wrong with the
# parse, not that 512 devices are present; cap it either way.
_MAX_NEIGHBORS = 512

_MAC_PATTERN = re.compile(r"\b([0-9a-fA-F]{1,2}(?:[:-][0-9a-fA-F]{1,2}){5})\b")
_IPV4_PATTERN = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")

# Placeholder entries the OS keeps for unresolved or broadcast addresses.
_IGNORED_MACS = {
    "00:00:00:00:00:00",
    "ff:ff:ff:ff:ff:ff",
}


@dataclass(frozen=True)
class Neighbor:
    ip: str
    mac: str
    interface: str

    @property
    def is_multicast(self) -> bool:
        """True for IPv4 multicast/broadcast MAC mappings, which are not devices."""
        return self.mac.startswith("01:00:5e") or self.mac.startswith("33:33")

    @property
    def is_locally_administered(self) -> bool:
        """True when the MAC's 'locally administered' bit is set.

        Phones set this bit deliberately for Wi-Fi privacy (randomised MACs),
        so on its own it is normal. On a *router's* MAC it is not: routers ship
        with a vendor-assigned address, and a locally administered one there
        suggests the address was made up by software.
        """
        try:
            first_octet = int(self.mac.split(":")[0], 16)
        except (ValueError, IndexError):
            return False
        return bool(first_octet & 0b10)


@dataclass(frozen=True)
class Gateway:
    ip: str
    interface: str


def read_neighbors(platform: str) -> list[Neighbor]:
    """Return the ARP/neighbour table, normalised across platforms."""
    if platform == "linux":
        output = _run(["ip", "neigh", "show"])
        neighbors = _parse_ip_neigh(output)
        if neighbors:
            return neighbors
        return _parse_bsd_arp(_run(["arp", "-an"]))
    if platform == "darwin":
        return _parse_bsd_arp(_run(["arp", "-a", "-n"]))
    if platform == "win32":
        return _parse_windows_arp(_run(["arp", "-a"]))
    return []


def read_gateways(platform: str) -> list[Gateway]:
    """Return the configured default gateway(s)."""
    if platform == "linux":
        return _parse_ip_route(_run(["ip", "route", "show", "default"]))
    if platform == "darwin":
        return _parse_darwin_route(_run(["route", "-n", "get", "default"]))
    if platform == "win32":
        return _parse_windows_route(_run(["route", "print", "-4"]))
    return []


def normalise_mac(value: str) -> str:
    """Return a lower-case colon-separated MAC with zero-padded octets.

    BSD `arp` prints `0:1c:42:0:0:8`, Windows prints `00-1C-42-00-00-08`, and
    Linux prints `00:1c:42:00:00:08`; all three must compare equal.
    """
    parts = re.split(r"[:-]", value.strip())
    if len(parts) != 6:
        return value.strip().lower()
    try:
        return ":".join(f"{int(part, 16):02x}" for part in parts)
    except ValueError:
        return value.strip().lower()


def load_oui_vendors(data_dir: Path | None = None) -> dict[str, str]:
    """Return a mapping of OUI prefix (``aa:bb:cc``) to vendor name."""
    if data_dir is None:
        data_dir = Path(__file__).parent
    path = data_dir / "oui_vendors.json"
    try:
        if not path.exists():
            return {}
        with open(path, "r") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return {}
    entries = data.get("entries", {})
    if not isinstance(entries, dict):
        return {}
    return {str(k).lower(): str(v) for k, v in entries.items()}


def vendor_for(mac: str, vendors: dict[str, str]) -> str | None:
    """Return the vendor that registered this MAC's prefix, if known."""
    prefix = ":".join(mac.split(":")[:3]).lower()
    return vendors.get(prefix)


# ---------------- parsers ----------------


def _parse_ip_neigh(output: str) -> list[Neighbor]:
    neighbors: list[Neighbor] = []
    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 2 or "lladdr" not in parts:
            continue
        ip = parts[0]
        if not _IPV4_PATTERN.fullmatch(ip):
            continue
        mac = normalise_mac(parts[parts.index("lladdr") + 1])
        interface = parts[parts.index("dev") + 1] if "dev" in parts else ""
        neighbors.append(Neighbor(ip=ip, mac=mac, interface=interface))
        if len(neighbors) >= _MAX_NEIGHBORS:
            break
    return [n for n in neighbors if _is_real(n)]


def _parse_bsd_arp(output: str) -> list[Neighbor]:
    """Parse `? (192.168.1.1) at 0:1c:42:0:0:8 on en0 ifscope [ethernet]`."""
    neighbors: list[Neighbor] = []
    for line in output.splitlines():
        ip_match = re.search(r"\((\d{1,3}(?:\.\d{1,3}){3})\)", line)
        mac_match = _MAC_PATTERN.search(line)
        if ip_match is None or mac_match is None:
            continue
        interface_match = re.search(r"\bon\s+(\S+)", line)
        neighbors.append(
            Neighbor(
                ip=ip_match.group(1),
                mac=normalise_mac(mac_match.group(1)),
                interface=interface_match.group(1) if interface_match else "",
            )
        )
        if len(neighbors) >= _MAX_NEIGHBORS:
            break
    return [n for n in neighbors if _is_real(n)]


def _parse_windows_arp(output: str) -> list[Neighbor]:
    """Parse `arp -a`, which groups rows under `Interface: <ip> --- 0x5`."""
    neighbors: list[Neighbor] = []
    interface = ""
    for line in output.splitlines():
        stripped = line.strip()
        if stripped.lower().startswith("interface:"):
            match = _IPV4_PATTERN.search(stripped)
            interface = match.group(1) if match else ""
            continue
        ip_match = _IPV4_PATTERN.search(stripped)
        mac_match = _MAC_PATTERN.search(stripped)
        if ip_match is None or mac_match is None:
            continue
        neighbors.append(
            Neighbor(
                ip=ip_match.group(1),
                mac=normalise_mac(mac_match.group(1)),
                interface=interface,
            )
        )
        if len(neighbors) >= _MAX_NEIGHBORS:
            break
    return [n for n in neighbors if _is_real(n)]


def _parse_ip_route(output: str) -> list[Gateway]:
    gateways: list[Gateway] = []
    for line in output.splitlines():
        parts = line.split()
        if "via" not in parts:
            continue
        ip = parts[parts.index("via") + 1]
        interface = parts[parts.index("dev") + 1] if "dev" in parts else ""
        gateways.append(Gateway(ip=ip, interface=interface))
    return gateways


def _parse_darwin_route(output: str) -> list[Gateway]:
    gateway_ip = ""
    interface = ""
    for line in output.splitlines():
        stripped = line.strip()
        if stripped.startswith("gateway:"):
            gateway_ip = stripped.split(":", 1)[1].strip()
        elif stripped.startswith("interface:"):
            interface = stripped.split(":", 1)[1].strip()
    return [Gateway(ip=gateway_ip, interface=interface)] if gateway_ip else []


def _parse_windows_route(output: str) -> list[Gateway]:
    """Parse the IPv4 default routes out of `route print -4`."""
    gateways: list[Gateway] = []
    seen: set[str] = set()
    for line in output.splitlines():
        parts = line.split()
        if len(parts) < 4 or parts[0] != "0.0.0.0" or parts[1] != "0.0.0.0":
            continue
        gateway_ip = parts[2]
        if not _IPV4_PATTERN.fullmatch(gateway_ip) or gateway_ip in seen:
            continue
        seen.add(gateway_ip)
        gateways.append(Gateway(ip=gateway_ip, interface=parts[3]))
    return gateways


def _is_real(neighbor: Neighbor) -> bool:
    return neighbor.mac not in _IGNORED_MACS and not neighbor.is_multicast


def _run(command: list[str]) -> str:
    try:
        result = subprocess.run(
            command, capture_output=True, text=True, timeout=_COMMAND_TIMEOUT
        )
    except (OSError, subprocess.SubprocessError):
        return ""
    return result.stdout or ""
