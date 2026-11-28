"""A captured frame as the packet it carries: who sent it to whom, over
which protocol, and what it holds. Over IPv4 and IPv6.

A frame is what a session put on the wire: one that is not what it is read
as raises NotThis, and is passed over."""

from __future__ import annotations

import enum
import functools
import socket
import struct
from typing import NamedTuple

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


# The flags of a packet as they are read, by the byte of the header that
# has them: the others are dropped. Worked out once, a capture has up to
# hundreds of thousands of packets.
_TCP_FLAGS = tuple(
    TcpFlag(byte & (TcpFlag.FIN | TcpFlag.SYN | TcpFlag.RST | TcpFlag.ACK))
    for byte in range(256)
)
_NO_FLAGS = _TCP_FLAGS[0]

# Where the sequence numbers of TCP start over: they are of 32 bits
SEQUENCE_SPACE = 1 << 32

# What a connection is known by: the session's port, and the address and
# the port of the other end
type Key = tuple[int, str, int]


class Packet(NamedTuple):
    """A captured packet over IPv4 or IPv6. A named tuple, which is
    quicker to make than an object of a class: a capture can have
    hundreds of thousands."""

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

    @property
    def key(self) -> Key:
        """The connection it is of, see Key: by where it went of one the
        session sent, by where it came from of one it was sent."""
        if self.sent:
            return (self.source_port, self.destination, self.port)
        return (self.port, self.source, self.source_port)

    @property
    def carried_from(self) -> int:
        """Where in its stream what a TCP packet carries starts: at its
        sequence number, or the one after for a SYN, which takes one of
        its own (what it carries is the first of the stream, TCP Fast
        Open)."""
        syn = 1 if TcpFlag.SYN in self.tcp_flags else 0
        return (self.sequence + syn) % SEQUENCE_SPACE

    @property
    def carried_to(self) -> int:
        """Where what the next packet of the stream carries starts, as
        far as this one tells: past what it carried."""
        return (self.carried_from + self.length) % SEQUENCE_SPACE


def is_loopback(address: str) -> bool:
    return address.startswith("127.") or address == "::1"


# The headers that are read, by where their fields are, each read in one
# go: a cooked frame of either version and an Ethernet one, the headers of
# IPv4 and IPv6, and of TCP its ports, numbers and flags
_COOKED_2 = struct.Struct("!H8xB9x")
_COOKED = struct.Struct("!H12xH")
_ETHERNET = struct.Struct("!12xH")
_IPV4 = struct.Struct("!BxHxxHxBxx4s4s")
_IPV6 = struct.Struct("!4xHBx16s16s")
_TCP = struct.Struct("!HHIIBB")
_PORTS = struct.Struct("!HH")
# How many addresses are known as text at a time: a capture reaches few as
# a rule, and a session that reaches many has them worked out again
MOST_ADDRESSES_KNOWN = 4096


@functools.lru_cache(maxsize=MOST_ADDRESSES_KNOWN)
def _ipv4_text(raw: bytes) -> str:
    return socket.inet_ntoa(raw)


@functools.lru_cache(maxsize=MOST_ADDRESSES_KNOWN)
def _ipv6_text(raw: bytes) -> str:
    return socket.inet_ntop(socket.AF_INET6, raw)


def _ip_in_frame(link_type: int, frame: bytes) -> tuple[int, bool, int]:
    """Where in a captured frame the IP packet it carries starts, whether
    the session sent it and the version of IP it is, 4 or 6. Raises
    NotThis for a frame that carries something else, and struct.error
    for one cut short of its header, see parse_packet. An Ethernet frame
    does not say who sent it, it counts as sent."""
    match link_type:
        case LinkType.COOKED_2:
            ethertype, kind = _COOKED_2.unpack_from(frame)
            at, sent = _COOKED_2.size, kind == COOKED_SENT
        case LinkType.COOKED:
            kind, ethertype = _COOKED.unpack_from(frame)
            at, sent = _COOKED.size, kind == COOKED_SENT
        case LinkType.ETHERNET:
            (ethertype,) = _ETHERNET.unpack_from(frame)
            at, sent = _ETHERNET.size, True
        case _:
            raise NotThis
    if ethertype == EtherType.IPV4:
        return at, sent, 4
    if ethertype == EtherType.IPV6:
        return at, sent, 6
    raise NotThis


class IpHeader(NamedTuple):
    """What the IP header of a packet says, of either version."""

    protocol: int
    source: str
    destination: str
    # Where in the frame what IP carries starts
    transport_at: int
    # How long that is, captured or not, None when the header does not
    # say: a packet the kernel has yet to split says 0 there
    length: int | None
    # A fragment that is not the first of its datagram, which has no
    # transport header
    later_fragment: bool


def _ipv4_header(frame: bytes, at: int) -> IpHeader:
    """The IPv4 header that starts at a place in a frame. Raises
    struct.error for one cut short, see parse_packet."""
    first, total_length, fragment, protocol, source, destination = _IPV4.unpack_from(
        frame, at
    )
    header_length = (first & 0x0F) * 4
    length = max(total_length - header_length, 0) if total_length else None
    return IpHeader(
        protocol,
        _ipv4_text(source),
        _ipv4_text(destination),
        at + header_length,
        length,
        bool(fragment & IPV4_FRAGMENT_OFFSET),
    )


def _ipv6_header(frame: bytes, start: int) -> IpHeader:
    """The IPv6 header that starts at a place in a frame, and the headers
    after it that come ahead of the transport's: a session can put those
    there, and what it sends must not go unread for it. Raises
    struct.error for a header cut short, see parse_packet, and NotThis
    for headers that go on too long or past the frame."""
    payload_length, protocol, source, destination = _IPV6.unpack_from(frame, start)
    at, later = start + IPV6_HEADER, False
    for _ in range(IPV6_MOST_HEADERS):
        extension = Cursor(frame, at)
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
    carried = payload_length - (at - start - IPV6_HEADER)
    length = max(carried, 0) if payload_length else None
    return IpHeader(
        protocol, _ipv6_text(source), _ipv6_text(destination), at, length, later
    )


def parse_packet(when: float, link_type: int, frame: bytes) -> Packet:
    """A captured frame as a packet. Raises NotThis unless it is IPv4 or
    IPv6, whole as far as its headers go: a header cut short is found
    where it is read, as struct.error, which is told as that here for
    them all."""
    try:
        at, sent, version = _ip_in_frame(link_type, frame)
        ip = _ipv4_header(frame, at) if version == 4 else _ipv6_header(frame, at)
        transport_at = ip.transport_at
        captured = max(len(frame) - transport_at, 0)
        length = captured if ip.length is None else ip.length
        source_port = port = sequence = acknowledgement = 0
        tcp_flags = _NO_FLAGS
        if ip.protocol == Protocol.TCP:
            if ip.later_fragment:
                raise NotThis
            source_port, port, sequence, acknowledgement, offset, flags = (
                _TCP.unpack_from(frame, transport_at)
            )
            tcp_header_length = (offset >> 4) * 4
            # The flags that are not read are dropped
            tcp_flags = _TCP_FLAGS[flags]
            payload = frame[transport_at + tcp_header_length :]
            # As the IP header has it, the capture cuts a long payload short
            length = (
                len(payload)
                if ip.length is None
                else max(length - tcp_header_length, 0)
            )
        elif ip.later_fragment:
            payload = b""
        elif ip.protocol in PORTED_TRANSPORTS:
            source_port, port = _PORTS.unpack_from(frame, transport_at)
            skipped = UDP_HEADER if ip.protocol == Protocol.UDP else 0
            payload = frame[transport_at + skipped :]
        else:
            payload = frame[transport_at:]
    except struct.error:
        raise NotThis from None
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
