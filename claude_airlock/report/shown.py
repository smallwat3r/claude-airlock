"""How what a session reached is shown, in a trace and in the digest of a
session: an amount of bytes, a protocol and a destination."""

from __future__ import annotations

import functools
import socket

from ..events import clean
from ..recording.pcap import Capture

PORT_USES = {
    22: "ssh",
    53: "dns",
    80: "http",
    443: "https",
    1883: "mqtt",
    2375: "docker",
    3128: "proxy",
    3306: "mysql",
    5432: "postgres",
    6379: "redis",
    27017: "mongodb",
}


def size(count: int) -> str:
    """A number of bytes as shown: 950 B, 1 kB, 2.3 GB."""
    left = float(count)
    for unit in ("B", "kB", "MB"):
        if left < 1000:
            return f"{left:.0f} {unit}"
        left /= 1000
    return f"{left:.1f} GB"


@functools.cache
def over(transport: str, port: int) -> str:
    """How a connection was made and, going by its port, what for:
    tcp/https, proxy/ssh, plain tcp for a port without a known use. The
    usual ones are named here, a host need not have a services file."""
    if port in PORT_USES:
        return f"{transport}/{PORT_USES[port]}"
    try:
        named_for = "udp" if transport == "udp" else "tcp"
        return f"{transport}/{socket.getservbyport(port, named_for)}"
    except (OSError, OverflowError):
        return transport


def verdict(denied: bool) -> str:
    return "DENIED" if denied else "allowed"


def reached(capture: Capture, address: str, port: int, transport: str = "tcp") -> str:
    """A destination as shown: tcp/https name (address):port, the name
    left out when the capture has none for the address, the port for a
    protocol without ports. An IPv6 address is in brackets ahead of one."""
    known = capture.names.get(address)
    if port:
        literal = f"[{address}]" if ":" in address else address
        where = f"{known} ({address}):{port}" if known else f"{literal}:{port}"
    else:
        where = f"{known} ({address})" if known else address
    return clean(f"{over(transport, port)} {where}")
