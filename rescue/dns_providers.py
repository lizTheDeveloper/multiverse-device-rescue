"""Public DNS providers a person may have chosen on purpose.

Privacy and filtering resolvers (NextDNS, Mullvad, Control D, AdGuard, Quad9,
Cloudflare, Google, OpenDNS) are common and intentional, so a check never calls
them unrecognised. One table for every DNS check.

``provider_name(server)`` -> "NextDNS" / "your router" / None (not known).
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


def provider_name(server: str) -> str | None:
    """A known provider's name, ROUTER for a local address, or None."""
    try:
        addr = ipaddress.ip_address(str(server).split("%")[0])
    except ValueError:
        return None
    if addr.is_loopback or addr.is_unspecified:
        return None
    if any(addr.version == n.version and addr in n for n in LOCAL_NETWORKS):
        return ROUTER
    for name, net in KNOWN_DNS_PARSED:
        if addr.version == net.version and addr in net:
            return name
    return None
