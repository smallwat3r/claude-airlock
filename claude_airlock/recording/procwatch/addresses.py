"""Addresses as the records write them, the same to the watcher and to
the launcher, which reads them from a capture, from gVisor and from the
logs of its proxies: one of IPv4 inside IPv6 as the IPv4 address it is,
the session's own loopback, and the address of docker's resolver."""

from __future__ import annotations

import ipaddress

# Where docker's own resolver waits in every container, not the session's
RESOLVER = "127.0.0.11"


def unmapped(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> str:
    """An address as text, one of IPv4 inside IPv6 (::ffff:203.0.113.9)
    as the IPv4 address it is, as it goes over the wire: a socket of IPv6
    that takes both says so of what comes over IPv4."""
    mapped = getattr(address, "ipv4_mapped", None)
    return str(mapped or address)


def is_loopback(address: str) -> bool:
    """Whether an address, as text, is the session's own loopback, which
    nothing else reaches and no capture has."""
    return address.startswith("127.") or address == "::1"
