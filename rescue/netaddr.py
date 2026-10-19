"""Which addresses are on the internet, and which are this computer or its network.

Shared by the connection watch (which lists destinations) and the lookups of
who runs an address (which only ever ask about public ones).
"""

from __future__ import annotations

import ipaddress

# Shared address space used by carrier-grade NAT; not a destination on the internet.
_CGNAT = ipaddress.ip_network("100.64.0.0/10")

# The well-known NAT64 prefix only. In the local-use 64:ff9b:1::/48 the
# prefix length (and so where the IPv4 address sits) varies (RFC 6052 / 8215),
# so those addresses are left as they are and count as public: fail closed.
_NAT64_WKP = ipaddress.ip_network("64:ff9b::/96")

_PRIVATE_NETWORKS = tuple(
    ipaddress.ip_network(n)
    for n in (
        "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",  # RFC 1918
        "127.0.0.0/8", "::1/128",                          # loopback
        "169.254.0.0/16", "fe80::/10",                     # link-local
        "fc00::/7",                                        # unique local (ULA)
    )
)


def parse_ip(addr: str | None):
    """The address, with an IPv4 address carried inside IPv6 unwrapped."""
    try:
        ip = ipaddress.ip_address((addr or "").split("%")[0])
    except ValueError:
        return None
    if ip.version == 6:
        if ip.ipv4_mapped is not None:
            return ip.ipv4_mapped
        if ip in _NAT64_WKP:
            # The well-known NAT64 prefix carries the IPv4 address in the last
            # 32 bits, so classify by that address.
            return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    return ip


def is_loopback(addr: str | None) -> bool:
    ip = parse_ip(addr)
    return ip is not None and ip.is_loopback


def is_public(addr: str | None) -> bool:
    """True only for an address that is clearly not on this computer or network."""
    ip = parse_ip(addr)
    if ip is None or ip.is_multicast or ip.is_unspecified:
        return False
    # IPv4 "reserved" is 240.0.0.0/4 and broadcast. IPv6's is_reserved covers
    # whole unassigned ranges, which says nothing about where a connection goes.
    if ip.version == 4 and (ip.is_reserved or ip in _CGNAT):
        return False
    return not any(ip in net for net in _PRIVATE_NETWORKS if net.version == ip.version)


def address_key(addr) -> str:
    """One spelling per address: ::ffff:8.8.8.8 and 8.8.8.8 give the same key."""
    ip = parse_ip(addr)
    return str(ip) if ip is not None else str(addr)
