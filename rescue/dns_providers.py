"""Public DNS providers a person may have chosen on purpose.

Shared public resolvers (Cloudflare, Quad9, Google, Mullvad, AdGuard's public
addresses, OpenDNS, and NextDNS / Control D's generic addresses) are common
and intentional, so a check never calls them unrecognised. One table for every
DNS check.

A *profile* address is different: NextDNS, Control D and AdGuard give each
account its own addresses, and the account's owner can see every website name
looked up through it. Someone can point another person's DNS at their own
profile to read their browsing, so a profile address is never silently
trusted: ``provider_info`` says it is one, and the check reports it (with the
profile id when the address carries it) for the person to confirm it's theirs.

``provider_info(server)`` -> {"name", "profile": bool, "profile_id"} | None
``provider_name(server)`` -> a shared provider's name, ROUTER for a local
address, or None (unknown, or a profile address).
"""
from __future__ import annotations

import ipaddress

KNOWN_DNS_NETWORKS = [
    ("NextDNS", "45.90.28.0/24"),
    ("NextDNS", "45.90.30.0/24"),
    ("NextDNS", "2a07:a8c0::/32"),
    ("NextDNS", "2a07:a8c1::/32"),
    ("Mullvad DNS", "194.242.2.0/24"),
    ("Mullvad DNS", "2a07:e340::/32"),
    ("Control D", "76.76.2.0/24"),
    ("Control D", "76.76.10.0/24"),
    ("Control D", "2606:1a40::/32"),
    ("AdGuard DNS", "94.140.14.0/24"),
    ("AdGuard DNS", "94.140.15.0/24"),
    ("AdGuard DNS", "2a10:50c0::/32"),
    ("Quad9", "9.9.9.0/24"),
    ("Quad9", "149.112.112.0/24"),
    ("Quad9", "2620:fe::/48"),
    ("OpenDNS", "208.67.222.0/24"),
    ("OpenDNS", "208.67.220.0/24"),
    ("OpenDNS", "2620:119::/48"),
    ("Cloudflare DNS", "1.1.1.0/24"),
    ("Cloudflare DNS", "1.0.0.0/24"),
    ("Cloudflare DNS", "2606:4700:4700::/48"),
    ("Google DNS", "8.8.8.0/24"),
    ("Google DNS", "8.8.4.0/24"),
    ("Google DNS", "2001:4860:4860::/48"),
]
KNOWN_DNS_PARSED = [(n, ipaddress.ip_network(c)) for n, c in KNOWN_DNS_NETWORKS]

# Addresses a home/office router or local network hands out as DNS.
LOCAL_NETWORKS = [
    ipaddress.ip_network(n)
    for n in (
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16",
        "100.64.0.0/10", "fc00::/7", "fe80::/10",
    )
]

ROUTER = "your router"

# Providers that hand out per-account addresses inside their ranges, and the
# addresses in those ranges that are shared (no account, no profile log).
PROFILE_PROVIDERS = {"NextDNS", "Control D", "AdGuard DNS"}
_SHARED_IN_PROFILE_RANGES = {ipaddress.ip_address(a) for a in (
    # NextDNS anycast without a profile.
    "45.90.28.0", "45.90.30.0", "2a07:a8c0::", "2a07:a8c1::",
    # Control D free resolvers (unfiltered and the preset filters).
    *(f"76.76.2.{i}" for i in range(6)), *(f"76.76.10.{i}" for i in range(6)),
    *(f"2606:1a40::{i}" for i in ("", "1", "2", "3", "4", "5")),
    *(f"2606:1a40:1::{i}" for i in ("", "1", "2", "3", "4", "5")),
    # AdGuard public DNS (default, non-filtering, family).
    "94.140.14.14", "94.140.15.15", "94.140.14.140", "94.140.14.141", "94.140.14.15", "94.140.15.16",
    "2a10:50c0::ad1:ff", "2a10:50c0::ad2:ff", "2a10:50c0::1:ff", "2a10:50c0::2:ff",
    "2a10:50c0::bad1:ff", "2a10:50c0::bad2:ff",
)}


def _profile_id(name: str, addr) -> str | None:
    """The profile id an address carries, when it does (NextDNS IPv6: the last
    two groups, e.g. 2a07:a8c0::ab:cd12 -> abcd12)."""
    if name == "NextDNS" and addr.version == 6:
        groups = addr.exploded.split(":")
        pid = (groups[-2].lstrip("0") + groups[-1].rjust(4, "0")).lstrip("0")
        return pid or None
    return None


def provider_info(server: str) -> dict | None:
    """{"name", "profile", "profile_id"} for a known provider's address,
    {"name": ROUTER, ...} for a local one, or None."""
    try:
        addr = ipaddress.ip_address(str(server).split("%")[0])
    except ValueError:
        return None
    if addr.is_loopback or addr.is_unspecified:
        return None
    if any(addr.version == n.version and addr in n for n in LOCAL_NETWORKS):
        return {"name": ROUTER, "profile": False, "profile_id": None}
    for name, net in KNOWN_DNS_PARSED:
        if addr.version == net.version and addr in net:
            profile = name in PROFILE_PROVIDERS and addr not in _SHARED_IN_PROFILE_RANGES
            return {"name": name, "profile": profile, "profile_id": _profile_id(name, addr) if profile else None}
    return None


def provider_name(server: str) -> str | None:
    """A shared provider's name, ROUTER for a local address, or None: unknown,
    or a per-account profile address (never trusted silently)."""
    info = provider_info(server)
    if info is None or info["profile"]:
        return None
    return info["name"]


def profile_servers(servers) -> list[dict]:
    """The profile addresses among ``servers``: [{server, provider, profile_id}]."""
    out = []
    for server in servers or []:
        info = provider_info(server)
        if info and info["profile"]:
            out.append({"server": str(server), "provider": info["name"], "profile_id": info["profile_id"]})
    return out
