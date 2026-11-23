"""A captured frame as the packet it carries: who sent it to whom, over
which protocol, and what it holds. Over IPv4 and IPv6.

A frame is what a session put on the wire: one that is not what it is read
as raises NotThis, and is passed over."""

from __future__ import annotations

import enum
import socket
from dataclasses import dataclass

from ..reader import Cursor, NotThis

# Where docker's own resolver waits, in every container
RESOLVER = "127.0.0.11"
# In a cooked frame, the packet type of one the machine sent
COOKED_SENT = 4


class LinkType(enum.IntEnum):
    """What the frames of a capture file are, as its header says
    (tcpdump.org/linktypes). tcpdump's "any" device gives Linux cooked
    frames, version 1 or 2 depending on its age: both carry whether the
    machine sent the packet, at a different place."""

    ETHERNET = 1
    COOKED = 113
    COOKED_2 = 276


class EtherType(enum.IntEnum):
    """What a frame carries, of that the two that are read."""

    IPV4 = 0x0800
    IPV6 = 0x86DD


class Protocol(enum.IntEnum):
    """What IP carries, by its number there. TCP and UDP are read into,
    of any other transport just where it went and how much. The headers
    IPv6 can have ahead of the transport's are numbered the same way."""

    HOP_BY_HOP_OPTIONS = 0
    ICMP = 1
    TCP = 6
    UDP = 17
    DCCP = 33
    ROUTING = 43
    FRAGMENT = 44
    GRE = 47
    ICMP6 = 58
    DESTINATION_OPTIONS = 60
    SCTP = 132
    UDPLITE = 136


# The part of an IPv4 header's fragment field that says where in the
# datagram a fragment goes: other than 0, it has no transport header
IPV4_FRAGMENT_OFFSET = 0x1FFF
IPV6_HEADER = 40
# The headers that can come between the IPv6 header and the transport's
# and say their own length. The fragment header, which says where a
# fragment goes, is of a fixed one.
IPV6_OPTION_HEADERS = (
    Protocol.HOP_BY_HOP_OPTIONS,
    Protocol.ROUTING,
    Protocol.DESTINATION_OPTIONS,
)
IPV6_FRAGMENT_OFFSET = 0xFFF8
# A packet cannot have more of them than this, a longer walk is not one
IPV6_MOST_HEADERS = 8
UDP_HEADER = 8
# What is not TCP is named by its number over IP, the usual ones by name
TRANSPORT_NAMES: dict[int, str] = {
    Protocol.ICMP: "icmp",
    Protocol.UDP: "udp",
    Protocol.DCCP: "dccp",
    Protocol.GRE: "gre",
    Protocol.ICMP6: "icmp6",
    Protocol.SCTP: "sctp",
    Protocol.UDPLITE: "udplite",
}
# Of those, the ones that start with the two ports
PORTED_TRANSPORTS = (Protocol.UDP, Protocol.DCCP, Protocol.SCTP, Protocol.UDPLITE)
# The type of an echo request, by the ICMP it is of: the one message of
# either a session without capabilities can send (a ping), the others are
# the kernel's own
ICMP_ECHO: dict[int, int] = {Protocol.ICMP: 8, Protocol.ICMP6: 128}


class TcpFlag(enum.IntFlag):
    """The flags of a TCP packet that tell how a connection starts and
    ends."""

    FIN = 0x01
    SYN = 0x02
    RST = 0x04
    ACK = 0x10


@dataclass(frozen=True)
class Packet:
    """A captured packet over IPv4 or IPv6."""

    when: float
    # By the session, as opposed to received by it
    sent: bool
    # Its number over IP, see Protocol and TRANSPORT_NAMES
    protocol: int
    source: str
    destination: str
    # Both 0 for a protocol without ports, and for a fragment that is not
    # the first of its datagram
    source_port: int
    port: int
    # None of them unless TCP
    tcp_flags: TcpFlag
    # As far as it was captured: of TCP and UDP what they carry, of
    # another protocol all that IP carries
    payload: bytes
    # Of a TCP packet: its sequence and acknowledgement numbers
    sequence: int = 0
    acknowledgement: int = 0
    # How long it was, captured or not: of TCP its payload, of another
    # protocol what IP carried
    length: int = 0


def is_loopback(address: str) -> bool:
    return address.startswith("127.") or address == "::1"


def ip_in_frame(link_type: int, frame: bytes) -> tuple[bytes, bool, int]:
    """The IP packet a captured frame carries, whether the session sent it
    and the version of IP it is, 4 or 6. Raises NotThis for a frame that
    carries something else. An Ethernet frame does not say who sent it, it
    counts as sent."""
    reader = Cursor(frame)
    match link_type:
        case LinkType.COOKED_2:
            ethertype = reader.number(2)
            reader.skip(8)  # reserved, interface, hardware type
            sent = reader.number(1) == COOKED_SENT
            reader.skip(9)  # address length and address
        case LinkType.COOKED:
            sent = reader.number(2) == COOKED_SENT
            reader.skip(12)  # hardware type, address length and address
            ethertype = reader.number(2)
        case LinkType.ETHERNET:
            reader.skip(12)  # the two addresses
            ethertype, sent = reader.number(2), True
        case _:
            raise NotThis
    if ethertype == EtherType.IPV4:
        return reader.rest(), sent, 4
    if ethertype == EtherType.IPV6:
        return reader.rest(), sent, 6
    raise NotThis


@dataclass(frozen=True)
class IpHeader:
    """What the IP header of a packet says, of either version."""

    protocol: int
    source: str
    destination: str
    # Where in the packet what IP carries starts
    transport_at: int
    # How long that is, captured or not, None when the header does not
    # say: a packet the kernel has yet to split says 0 there
    length: int | None
    # A fragment that is not the first of its datagram, which has no
    # transport header
    later_fragment: bool


def ipv4_header(datagram: bytes) -> IpHeader:
    ip = Cursor(datagram)
    header_length = (ip.number(1) & 0x0F) * 4
    ip.skip(1)  # service
    total_length = ip.number(2)
    ip.skip(2)  # id
    later = bool(ip.number(2) & IPV4_FRAGMENT_OFFSET)
    ip.skip(1)  # time to live
    protocol = ip.number(1)
    ip.skip(2)  # checksum
    source, destination = (socket.inet_ntoa(ip.take(4)) for _ in range(2))
    length = max(total_length - header_length, 0) if total_length else None
    return IpHeader(protocol, source, destination, header_length, length, later)


def ipv6_header(datagram: bytes) -> IpHeader:
    """The IPv6 header, and the headers after it that come ahead of the
    transport's: a session can put those there, and what it sends must
    not go unread for it."""
    ip = Cursor(datagram)
    ip.skip(4)  # version, class, flow
    payload_length = ip.number(2)
    protocol = ip.number(1)
    ip.skip(1)  # hop limit
    source, destination = (
        socket.inet_ntop(socket.AF_INET6, ip.take(16)) for _ in range(2)
    )
    at, later = IPV6_HEADER, False
    for _ in range(IPV6_MOST_HEADERS):
        extension = Cursor(datagram, at)
        if protocol in IPV6_OPTION_HEADERS:
            protocol = extension.number(1)
            at += (extension.number(1) + 1) * 8
        elif protocol == Protocol.FRAGMENT:
            protocol = extension.number(1)
            extension.skip(1)  # reserved
            later = bool(extension.number(2) & IPV6_FRAGMENT_OFFSET)
            at += 8
        else:
            break
        if later:
            break
    else:
        raise NotThis
    carried = payload_length - (at - IPV6_HEADER)
    length = max(carried, 0) if payload_length else None
    return IpHeader(protocol, source, destination, at, length, later)


def parse_packet(when: float, link_type: int, frame: bytes) -> Packet:
    """A captured frame as a packet. Raises NotThis unless it is IPv4 or
    IPv6, whole as far as its headers go."""
    datagram, sent, version = ip_in_frame(link_type, frame)
    ip = ipv4_header(datagram) if version == 4 else ipv6_header(datagram)
    carried = datagram[ip.transport_at :]
    length = len(carried) if ip.length is None else ip.length
    source_port = port = sequence = acknowledgement = 0
    tcp_flags = TcpFlag(0)
    payload = carried
    transport = Cursor(carried)
    if ip.protocol == Protocol.TCP:
        if ip.later_fragment:
            raise NotThis
        source_port, port = transport.number(2), transport.number(2)
        sequence, acknowledgement = transport.number(4), transport.number(4)
        tcp_header_length = (transport.number(1) >> 4) * 4
        # The flags that are not read are dropped
        tcp_flags = TcpFlag(transport.number(1) & sum(TcpFlag))
        payload = carried[tcp_header_length:]
        # As the IP header has it, the capture cuts a long payload short
        length = (
            len(payload) if ip.length is None else max(length - tcp_header_length, 0)
        )
    elif ip.later_fragment:
        payload = b""
    elif ip.protocol in PORTED_TRANSPORTS:
        source_port, port = transport.number(2), transport.number(2)
        if ip.protocol == Protocol.UDP:
            payload = carried[UDP_HEADER:]
    return Packet(
        when,
        sent,
        ip.protocol,
        ip.source,
        ip.destination,
        source_port,
        port,
        tcp_flags,
        payload,
        sequence,
        acknowledgement,
        length,
    )
