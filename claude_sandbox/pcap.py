"""Reading a capture (pcap, as tcpdump writes it) for what it says a
session reached: each TCP connection and how it went, what it sent by
anything else (UDP, a ping), the answers of the resolver, the server name
of a TLS hello and the request of plain HTTP. Over IPv4 and IPv6.

Nothing here runs docker, see capture.py for the sidecar that writes the
file. What is read is what a session put on the wire, so none of it is
trusted: a message that is not what it was read as ends the read of that
message, nothing more."""

from __future__ import annotations

import enum
import socket
import struct
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path

from .network import EGRESS_PORT

# The methods a plain HTTP request starts with, by their first four bytes
HTTP_METHODS = ("GET", "POST", "HEAD", "PUT", "DELETE", "PATCH", "OPTIONS", "CONNECT")
# A pcap file starts with one of these, which gives its byte order and what
# its timestamps count in: microseconds or nanoseconds
PCAP_FORMATS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1e6),
    b"\x4d\x3c\xb2\xa1": ("<", 1e9),
    b"\xa1\xb2\xc3\xd4": (">", 1e6),
    b"\xa1\xb2\x3c\x4d": (">", 1e9),
}
PCAP_HEADER = 24
PCAP_RECORD_HEADER = 16
PCAP_READ_SIZE = 1 << 16
# The longest frame tcpdump writes, a longer one means a damaged file
PCAP_LONGEST_FRAME = 262144
# In a cooked frame, the packet type of one the machine sent
COOKED_SENT = 4
ETHERTYPE_IPV4 = 0x0800
ETHERTYPE_IPV6 = 0x86DD
# The part of an IPv4 header's fragment field that says where in the
# datagram a fragment goes: other than 0, it has no transport header
IPV4_FRAGMENT_OFFSET = 0x1FFF
IPV6_HEADER = 40
# The headers that can come between the IPv6 header and the transport's:
# hop-by-hop options, routing and destination options, which say their
# own length, and the fragment header, which says where a fragment goes
IPV6_OPTION_HEADERS = (0, 43, 60)
IPV6_FRAGMENT_HEADER = 44
IPV6_FRAGMENT_OFFSET = 0xFFF8
# A packet cannot have more of them than this, a longer walk is not one
IPV6_MOST_HEADERS = 8
UDP_HEADER = 8
# What is not TCP is named by its number over IP, the usual ones by name
TRANSPORT_NAMES = {
    1: "icmp",
    17: "udp",
    33: "dccp",
    47: "gre",
    58: "icmp6",
    132: "sctp",
    136: "udplite",
}
# Of those, the ones that start with the two ports
PORTED_TRANSPORTS = (17, 33, 132, 136)
# The type of an echo request, by the ICMP it is of: the one message of
# either a session without capabilities can send (a ping), the others are
# the kernel's own
ICMP_ECHO = {1: 8, 58: 128}
DNS_IS_RESPONSE = 0x8000
DNS_ERROR_CODE = 0x000F
# The two top bits of a length that is a pointer to the rest of a name
DNS_POINTER = 0xC0
# The kinds of record that are named, the others show as their number,
# and of those the two that hold an address
DNS_RECORDS = {
    1: "A",
    5: "CNAME",
    12: "PTR",
    15: "MX",
    16: "TXT",
    28: "AAAA",
    33: "SRV",
    65: "HTTPS",
}
DNS_ADDRESS_FAMILIES = {1: socket.AF_INET, 28: socket.AF_INET6}
# What a resolver says went wrong, by the code in its answer
DNS_ERRORS = {
    1: "malformed query",
    2: "server failure",
    3: "no such name",
    5: "refused",
}
# A name cannot have more labels than this, a longer walk is a loop
DNS_MOST_LABELS = 127
# What a lookup is flagged for: a name or one label of it longer than
# names are, or this many different names under one parent. Data can be
# carried out in the names asked for, a resolver passes them on, and it
# takes long names or many of them.
DNS_LONG_NAME = 100
DNS_LONG_LABEL = 40
DNS_MANY_NAMES = 30
TLS_HANDSHAKE = 0x16
TLS_CLIENT_HELLO = 0x01
TLS_SERVER_NAME = 0
# Retransmitted connection attempts closer than this count as one
RETRY_SECONDS = 5.0


class LinkType(enum.IntEnum):
    """What the frames of a capture file are, as its header says
    (tcpdump.org/linktypes). tcpdump's "any" device gives Linux cooked
    frames, version 1 or 2 depending on its age: both carry whether the
    machine sent the packet, at a different place."""

    ETHERNET = 1
    COOKED = 113
    COOKED_2 = 276


class Protocol(enum.IntEnum):
    """The protocols over IP that are read into, by their number there.
    Of any other just where it went and how much."""

    TCP = 6
    UDP = 17


class TcpFlag(enum.IntFlag):
    """The flags of a TCP packet that tell how a connection starts and
    ends."""

    FIN = 0x01
    SYN = 0x02
    RST = 0x04
    ACK = 0x10


class NotThis(Exception):
    """The bytes are not the kind of message they were read as."""


class Cursor:
    """Reads a message front to back, in network byte order. Reading past
    its end raises NotThis: a truncated or foreign message ends the read
    of that message, nothing more."""

    def __init__(self, data: bytes, at: int = 0) -> None:
        self.data = data
        self.at = at

    def take(self, count: int) -> bytes:
        taken = self.data[self.at : self.at + count]
        if count < 0 or len(taken) < count:
            raise NotThis
        self.at += count
        return taken

    def number(self, size: int) -> int:
        return int.from_bytes(self.take(size), "big")

    def skip(self, count: int) -> None:
        self.take(count)

    def rest(self) -> bytes:
        return self.data[self.at :]


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


@dataclass
class Connection:
    """A TCP connection the session opened, and how it went as far as the
    capture tells."""

    when: float
    address: str
    port: int
    source_port: int
    # The sequence number it started from, and the one the other end
    # started from when it answered
    sequence: int
    answer_sequence: int | None = None
    # When it was last attempted. An attempt sent again got no answer in
    # the second or so the kernel waits for one.
    attempted: float = 0.0
    retried: bool = False
    refused: bool = False
    ended: float | None = None
    # Bytes each way, known once it is closed in the usual way
    sent: int | None = None
    received: int | None = None

    @property
    def answered(self) -> bool:
        return self.answer_sequence is not None

    @property
    def outcome(self) -> str:
        """refused, closed, open, no answer, or empty when the capture
        does not tell."""
        if self.refused:
            return "refused"
        if self.ended is not None:
            return "closed"
        if self.answered:
            return "open"
        return "no answer" if self.retried else ""

    @property
    def failed(self) -> bool:
        return self.outcome in ("refused", "no answer")

    @property
    def seconds(self) -> float | None:
        """How long it was open, once it has ended."""
        return None if self.ended is None else round(self.ended - self.when, 3)


@dataclass
class Flow:
    """What the session sent to one place by something other than TCP:
    UDP, a ping, any other protocol over IP. Nothing there says where a
    conversation starts or ends, so it is one per destination, with how
    much went out to it."""

    when: float
    protocol: int
    address: str
    # 0 for a protocol without ports
    port: int
    packets: int = 0
    sent: int = 0

    @property
    def transport(self) -> str:
        return TRANSPORT_NAMES.get(self.protocol, f"ip-{self.protocol}")


@dataclass(frozen=True)
class Lookup:
    """An answer of the resolver: for which name and kind of record it
    was asked, the addresses it gave, and what it said went wrong."""

    when: float
    name: str
    kind: str
    addresses: tuple[str, ...]
    error: str


@dataclass(frozen=True)
class Request:
    """A plain HTTP request the session sent: to where, and its method,
    target and Host header as it wrote them."""

    when: float
    address: str
    port: int
    method: str
    target: str
    host: str

    @property
    def url(self) -> str:
        """What was asked for as one URL, when the target is a path."""
        if not self.target.startswith("/"):
            return self.target
        return f"http://{self.host or self.address}{self.target}"


def tcp_span(end: int, start: int) -> int | None:
    """The bytes sent between two sequence numbers of one direction, the
    first being where it started. None for a count that cannot be right,
    numbers that do not belong together."""
    count = (end - start - 1) & 0xFFFFFFFF
    return count if count < 1 << 31 else None


@dataclass
class Capture:
    """What a capture says a session reached."""

    # Each TCP connection it opened
    connections: list[Connection] = field(default_factory=list)
    # What became of them, in the order it did: when, what (no answer,
    # refused or closed) and the connection. For a reader that follows.
    endings: list[tuple[float, str, Connection]] = field(default_factory=list)
    # The name an address was looked up under, else the one the TLS hello
    # to it asked for. Both are the session's doing: the address is what
    # it reached, the name what it says it was after.
    names: dict[str, str] = field(default_factory=dict)
    # Each answer of the resolver
    lookups: list[Lookup] = field(default_factory=list)
    # The lookups that stand out, each with what for, see DNS_MANY_NAMES
    flagged: list[tuple[str, Lookup]] = field(default_factory=list)
    # Each plain HTTP request
    requests: list[Request] = field(default_factory=list)
    # Each place something was sent to by another protocol than TCP
    flows: list[Flow] = field(default_factory=list)
    packets: int = 0
    # The connections that have not ended, by source port, address and port
    _open: dict[tuple[int, str, int], Connection] = field(
        default_factory=dict, repr=False
    )
    _flows: dict[tuple[int, str, int], Flow] = field(default_factory=dict, repr=False)
    # The names that were looked up, and how many under each parent
    _looked_up: set[str] = field(default_factory=set, repr=False)
    _under: dict[str, int] = field(default_factory=dict, repr=False)

    def marks(self) -> tuple[int, int, int, int, int, int]:
        """How much of each kind there is, for a reader that follows to
        tell what came since."""
        return (
            len(self.connections),
            len(self.endings),
            len(self.lookups),
            len(self.requests),
            len(self.flows),
            len(self.flagged),
        )

    def add(self, packet: Packet) -> None:
        """Take in what one packet tells."""
        if packet.protocol != Protocol.TCP:
            if packet.protocol == Protocol.UDP:
                self._add_dns_answer(packet)
            self._add_to_flow(packet)
            return
        # A connection is known by the session's port and the other end
        if packet.sent:
            key = (packet.source_port, packet.destination, packet.port)
        else:
            key = (packet.port, packet.source, packet.source_port)
        if is_loopback(key[1]):
            # What the session does within itself
            return
        flags = packet.tcp_flags
        if TcpFlag.SYN in flags:
            # The start of a connection has SYN alone, the answer to it
            # SYN and ACK. Those of connections made to the session are
            # the other way around, and passed over.
            if packet.sent and TcpFlag.ACK not in flags:
                self._add_connection(packet, key)
            elif not packet.sent and TcpFlag.ACK in flags and key in self._open:
                answered = self._open[key]
                if not answered.answered:
                    answered.answer_sequence = packet.sequence
        elif flags & (TcpFlag.FIN | TcpFlag.RST):
            if key in self._open:
                self._end_connection(packet, self._open.pop(key))
        elif packet.sent:
            self._add_server_name(packet)
            self._add_request(packet)

    def _add_dns_answer(self, packet: Packet) -> None:
        # An answer comes in, or from the resolver on loopback. What the
        # session sends out in the shape of one is not an answer to it.
        if packet.sent and not is_loopback(packet.source):
            return
        try:
            lookup = dns_answer(packet.when, packet.payload)
        except NotThis:
            return
        self.lookups.append(lookup)
        self._flag(lookup)
        if lookup.kind in ("A", "AAAA"):
            self.names.update(dict.fromkeys(lookup.addresses, lookup.name))

    def _flag(self, lookup: Lookup) -> None:
        """Note a lookup that stands out, a name once however often it is
        asked for: one longer than names are, and the one that makes it
        DNS_MANY_NAMES under the same parent."""
        name = lookup.name.lower().rstrip(".")
        if name in self._looked_up:
            return
        self._looked_up.add(name)
        labels = name.split(".")
        if len(name) > DNS_LONG_NAME or max(map(len, labels)) > DNS_LONG_LABEL:
            self.flagged.append(("an unusually long name", lookup))
        # Under a parent of two labels or more, not under com
        if len(labels) < 3:
            return
        parent = ".".join(labels[1:])
        count = self._under[parent] = self._under.get(parent, 0) + 1
        if count == DNS_MANY_NAMES:
            self.flagged.append((f"{count} names looked up under {parent}", lookup))

    def _add_to_flow(self, packet: Packet) -> None:
        """Count a packet that is not TCP towards where the session sent
        it. Not what it sent to itself, and of ICMP only a ping: the rest
        is the kernel's, and says nothing the session chose."""
        if not packet.sent or is_loopback(packet.destination):
            return
        echo = ICMP_ECHO.get(packet.protocol)
        if echo is not None and packet.payload[:1] != bytes([echo]):
            return
        key = (packet.protocol, packet.destination, packet.port)
        flow = self._flows.get(key)
        if flow is None:
            flow = Flow(packet.when, *key)
            self._flows[key] = flow
            self.flows.append(flow)
        flow.packets += 1
        flow.sent += packet.length

    def _add_connection(self, packet: Packet, key: tuple[int, str, int]) -> None:
        known = self._open.get(key)
        if known and packet.when - known.attempted < RETRY_SECONDS:
            known.attempted = packet.when
            if not known.answered and not known.retried:
                known.retried = True
                self.endings.append((packet.when, "no answer", known))
            return
        connection = Connection(
            packet.when,
            packet.destination,
            packet.port,
            packet.source_port,
            packet.sequence,
            attempted=packet.when,
        )
        self.connections.append(connection)
        self._open[key] = connection

    def _end_connection(self, packet: Packet, connection: Connection) -> None:
        """A connection ends with the first FIN or RST of either side. A
        RST from the other end in place of an answer is a refusal. A FIN
        says how much its sender sent, and acknowledges how much it got."""
        connection.ended = packet.when
        closing = TcpFlag.FIN in packet.tcp_flags
        if not connection.answered and not closing and not packet.sent:
            connection.refused = True
            self.endings.append((packet.when, "refused", connection))
            return
        if closing and connection.answer_sequence is not None:
            # Where the sender of the packet started from, then the other
            starts = [connection.sequence, connection.answer_sequence]
            if not packet.sent:
                starts.reverse()
            said = tcp_span(packet.sequence + packet.length, starts[0])
            got = (
                tcp_span(packet.acknowledgement, starts[1])
                if TcpFlag.ACK in packet.tcp_flags
                else None
            )
            connection.sent, connection.received = (
                (said, got) if packet.sent else (got, said)
            )
        self.endings.append((packet.when, "closed", connection))

    def _add_server_name(self, packet: Packet) -> None:
        name = tls_server_name(packet.payload)
        if name:
            # What the resolver said, if anything, comes first
            self.names.setdefault(packet.destination, name)

    def _add_request(self, packet: Packet) -> None:
        # What goes to the egress proxy is in the proxy's log, with whether
        # it was allowed
        if packet.port == EGRESS_PORT:
            return
        found = http_request(packet.payload)
        if found:
            self.requests.append(
                Request(packet.when, packet.destination, packet.port, *found)
            )


def is_loopback(address: str) -> bool:
    return address.startswith("127.") or address == "::1"


def dns_name(message: bytes, at: Cursor) -> str:
    """The name at a cursor in a DNS message, the cursor left after it.
    A name can end in a pointer to the rest of it, elsewhere in the
    message, which is followed without moving the cursor further."""
    labels: list[str] = []
    reader = at
    for _ in range(DNS_MOST_LABELS):
        length = reader.number(1)
        if length & DNS_POINTER == DNS_POINTER:
            target = (length & ~DNS_POINTER) << 8 | reader.number(1)
            reader = Cursor(message, target)
        elif length == 0:
            return ".".join(labels)
        else:
            labels.append(reader.take(length).decode("ascii", "replace"))
    raise NotThis


def dns_answer(when: float, message: bytes) -> Lookup:
    """A DNS response as a lookup: the name and kind of record it is
    about, the addresses it gives and the error it reports. Raises NotThis
    for anything else."""
    reader = Cursor(message)
    reader.skip(2)  # the id of the query
    flags, questions, answers = (reader.number(2) for _ in range(3))
    reader.skip(4)  # the counts of the two other sections
    if not flags & DNS_IS_RESPONSE or questions != 1:
        raise NotThis
    name = dns_name(message, reader)
    asked = reader.number(2)
    reader.skip(2)  # the class asked for
    addresses = []
    for _ in range(answers):
        dns_name(message, reader)
        kind = reader.number(2)
        reader.skip(6)  # class, time to live
        data = reader.take(reader.number(2))
        family = DNS_ADDRESS_FAMILIES.get(kind)
        if family is not None:
            try:
                addresses.append(socket.inet_ntop(family, data))
            except (OSError, ValueError):
                continue
    if not name:
        raise NotThis
    code = flags & DNS_ERROR_CODE
    error = DNS_ERRORS.get(code, f"error {code}") if code else ""
    kind_asked = DNS_RECORDS.get(asked, f"type {asked}")
    return Lookup(when, name, kind_asked, tuple(addresses), error)


def http_request(payload: bytes) -> tuple[str, str, str] | None:
    """The method, target and Host header of a plain HTTP request, none
    for a payload that does not start as one."""
    lines = payload.split(b"\r\n")
    start = lines[0].split(b" ")
    if len(start) != 3 or not start[2].startswith(b"HTTP/"):
        return None
    method, target = (part.decode("ascii", "replace") for part in start[:2])
    if method not in HTTP_METHODS:
        return None
    host = ""
    for line in lines[1:]:
        name, _, value = line.partition(b":")
        if name.lower() == b"host":
            host = value.strip().decode("ascii", "replace")
            break
    return method, target, host


def tls_server_name(record: bytes) -> str:
    """The server name a TLS client hello asks for. Empty for anything
    else, and for a hello without one or longer than what was captured."""
    try:
        hello = Cursor(record)
        if hello.number(1) != TLS_HANDSHAKE:
            return ""
        hello.skip(4)  # record version and length
        if hello.number(1) != TLS_CLIENT_HELLO:
            return ""
        hello.skip(3 + 2 + 32)  # handshake length, version, random
        hello.skip(hello.number(1))  # session id
        hello.skip(hello.number(2))  # cipher suites
        hello.skip(hello.number(1))  # compression methods
        hello.skip(2)  # length of the extensions
        while True:
            kind, length = hello.number(2), hello.number(2)
            if kind == TLS_SERVER_NAME:
                hello.skip(3)  # list length, name type
                return hello.take(hello.number(2)).decode("ascii", "replace")
            hello.skip(length)
    except NotThis:
        return ""


def ip_in_frame(link_type: int, frame: bytes) -> tuple[bytes, bool, int]:
    """The IP packet a captured frame carries, whether the session sent it
    and the version of IP it is, 4 or 6. Raises NotThis for a frame that
    carries something else. An Ethernet frame does not say who sent it, it
    counts as sent."""
    reader = Cursor(frame)
    if link_type == LinkType.COOKED_2:
        ethertype = reader.number(2)
        reader.skip(8)  # reserved, interface, hardware type
        sent = reader.number(1) == COOKED_SENT
        reader.skip(9)  # address length and address
    elif link_type == LinkType.COOKED:
        sent = reader.number(2) == COOKED_SENT
        reader.skip(12)  # hardware type, address length and address
        ethertype = reader.number(2)
    elif link_type == LinkType.ETHERNET:
        reader.skip(12)  # the two addresses
        ethertype, sent = reader.number(2), True
    else:
        raise NotThis
    if ethertype == ETHERTYPE_IPV4:
        return reader.rest(), sent, 4
    if ethertype == ETHERTYPE_IPV6:
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
        elif protocol == IPV6_FRAGMENT_HEADER:
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


class PcapReader:
    """Reads a capture (pcap, as tcpdump writes it) piece by piece, as a
    file read in one go or one still being written. Ends at the first thing
    that is not as it should be, what is fed after that is dropped."""

    def __init__(self) -> None:
        self._pending = bytearray()
        # Byte order, timestamp units per second and link type, from the
        # header of the file
        self._format: tuple[str, float, int] | None = None
        self._ended = False

    def feed(self, data: bytes) -> Iterator[tuple[float, int, bytes]]:
        """Take in the next bytes of the capture and give the frames they
        complete: when each was captured, the link type of the file and
        the frame. A frame cut off at the end waits for the rest of it."""
        if self._ended:
            return
        self._pending += data
        if self._format is None:
            if len(self._pending) < PCAP_HEADER:
                return
            start = bytes(self._pending[:PCAP_HEADER])
            del self._pending[:PCAP_HEADER]
            if start[:4] not in PCAP_FORMATS:
                self._end()
                return
            byte_order, per_second = PCAP_FORMATS[start[:4]]
            (link_type,) = struct.unpack_from(byte_order + "I", start, 20)
            self._format = (byte_order, per_second, link_type)
        byte_order, per_second, link_type = self._format
        at = 0
        while len(self._pending) - at >= PCAP_RECORD_HEADER:
            seconds, fraction, length, _ = struct.unpack_from(
                byte_order + "IIII", self._pending, at
            )
            if length > PCAP_LONGEST_FRAME:
                self._end()
                return
            end = at + PCAP_RECORD_HEADER + length
            if len(self._pending) < end:
                break
            frame = bytes(self._pending[at + PCAP_RECORD_HEADER : end])
            at = end
            yield seconds + fraction / per_second, link_type, frame
        del self._pending[:at]

    def _end(self) -> None:
        self._ended = True
        self._pending.clear()


def pcap_frames(path: Path) -> Iterator[tuple[float, int, bytes]]:
    """The frames of a capture file: when each was captured, the link type
    of the file and the frame. Ends at the first thing that is not as it
    should be, as a file cut off by a stopped tcpdump is. Raises OSError
    when the file cannot be read."""
    reader = PcapReader()
    with open(path, "rb") as file:
        while True:
            data = file.read(PCAP_READ_SIZE)
            if not data:
                return
            yield from reader.feed(data)


def take_frames(capture: Capture, frames: Iterable[tuple[float, int, bytes]]) -> None:
    """Add what captured frames tell to a capture. A packet that cannot be
    made sense of is counted and passed over."""
    for when, link_type, frame in frames:
        capture.packets += 1
        try:
            capture.add(parse_packet(when, link_type, frame))
        except NotThis:
            continue


def read_capture(path: Path) -> Capture:
    """What a capture file says a session reached. Raises OSError when the
    file cannot be read."""
    capture = Capture()
    take_frames(capture, pcap_frames(path))
    return capture
