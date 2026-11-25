"""How what a session reached is shown, in a trace and in the digest of a
session: an amount of bytes, a protocol and a destination."""

from __future__ import annotations

import functools
import socket

from ..events import flat
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


# What is said of a capture that stopped before its session did, see
# CaptureSidecar.stopped_early
STOPPED = "its capture is INCOMPLETE, a recorder ended before the session did: {}"
# What is said of a capture some of whose packets were not taken, see
# dropped_packets of capture.py
DROPPED = (
    "its capture is INCOMPLETE, {} packets came faster than they were"
    " taken: what they told of is missing"
)
# What is said of the egress proxy's log when it begins after a session
# that asked it did, see Recorded.log_begins
LOG_SHORT = (
    "the egress proxy's log is INCOMPLETE, it goes back to {:%H:%M:%S}"
    " only: what was asked before is missing"
)
# What is said of a record of processes whose watcher was slowed, with
# the most its looks came apart and for how long in all, see Slowed of
# processes.py. From a second on: under load a look comes a little late
# all the time, and what is missed then lived for an instant.
SLOWED = (
    "the record of its processes has GAPS, its watcher was slowed: its"
    " looks came up to {:.1f}s apart, for {:.0f}s in all, what ran for"
    " less then may be missing"
)
SLOWED_FROM = 1.0
# What is said of a record of processes whose watcher ended or hung
# before its session did, with when it was last heard, see
# ProcessRecord.silent_from
SILENT = (
    "the record of its processes is INCOMPLETE, its watcher said nothing"
    " after {:%H:%M:%S}: what ran later is missing"
)


def verdict(denied: bool) -> str:
    return "DENIED" if denied else "allowed"


def reached(
    capture: Capture,
    address: str,
    port: int,
    transport: str = "tcp",
    when: float | None = None,
) -> str:
    """A destination as shown: tcp/https name (address):port, the name
    left out when the capture has none for the address, the port for a
    protocol without ports. An IPv6 address is in brackets ahead of one.
    The name is the one the address had when the destination was reached,
    see Capture.name_of."""
    known = capture.name_of(address, when)
    if port:
        literal = f"[{address}]" if ":" in address else address
        where = f"{known} ({address}):{port}" if known else f"{literal}:{port}"
    else:
        where = f"{known} ({address})" if known else address
    # On one line: a name is the session's to choose, a line break in one
    # would start a line of its own
    return flat(f"{over(transport, port)} {where}")
