"""Reading a capture (pcap, as tcpdump writes it) for what it says a
session reached: each TCP connection and how it went, the answers of the
resolver, the server name of a TLS hello and the request of plain HTTP.

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
UDP_HEADER = 8
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
    """The protocols over IPv4 that are read, by their number there."""

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
    """A captured TCP or UDP packet over IPv4."""

    when: float
    # By the session, as opposed to received by it
    sent: bool
    protocol: Protocol
    source: str
    destination: str
    source_port: int
    port: int
    # None of them for UDP
    tcp_flags: TcpFlag
    # As far as it was captured
    payload: bytes
    # Of a TCP packet: its sequence and acknowledgement numbers, and how
    # long its payload was, captured or not
    sequence: int = 0
    acknowledgement: int = 0
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
    # Each plain HTTP request
    requests: list[Request] = field(default_factory=list)
    packets: int = 0
    # The connections that have not ended, by source port, address and port
    _open: dict[tuple[int, str, int], Connection] = field(
        default_factory=dict, repr=False
    )

    def marks(self) -> tuple[int, int, int, int]:
        """How much of each kind there is, for a reader that follows to
        tell what came since."""
        return (
            len(self.connections),
            len(self.endings),
            len(self.lookups),
            len(self.requests),
        )

    def add(self, packet: Packet) -> None:
        """Take in what one packet tells."""
        if packet.protocol is Protocol.UDP:
            self._add_dns_answer(packet)
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
        if lookup.kind == "A":
            self.names.update(dict.fromkeys(lookup.addresses, lookup.name))

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
    return address.startswith("127.")


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


def ipv4_in_frame(link_type: int, frame: bytes) -> tuple[bytes, bool]:
    """The IPv4 packet a captured frame carries and whether the session
    sent it. Raises NotThis for a frame that carries something else. An
    Ethernet frame does not say who sent it, it counts as sent."""
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
    if ethertype != ETHERTYPE_IPV4:
        raise NotThis
    return reader.rest(), sent


def parse_packet(when: float, link_type: int, frame: bytes) -> Packet:
    """A captured frame as a packet. Raises NotThis unless it is TCP or
    UDP over IPv4, whole as far as its headers go."""
    datagram, sent = ipv4_in_frame(link_type, frame)
    ip = Cursor(datagram)
    header_length = (ip.number(1) & 0x0F) * 4
    ip.skip(1)  # service
    total_length = ip.number(2)
    ip.skip(5)  # id, fragment, time to live
    try:
        protocol = Protocol(ip.number(1))
    except ValueError:
        raise NotThis from None
    ip.skip(2)  # checksum
    source, destination = (socket.inet_ntoa(ip.take(4)) for _ in range(2))

    transport = Cursor(datagram, header_length)
    source_port, port = transport.number(2), transport.number(2)
    tcp_flags = TcpFlag(0)
    sequence = acknowledgement = length = 0
    if protocol is Protocol.TCP:
        sequence, acknowledgement = transport.number(4), transport.number(4)
        tcp_header_length = (transport.number(1) >> 4) * 4
        # The flags that are not read are dropped
        tcp_flags = TcpFlag(transport.number(1) & sum(TcpFlag))
        payload = datagram[header_length + tcp_header_length :]
        # As the IP header has it, the capture cuts a long payload short.
        # A packet the kernel has yet to split says 0 there.
        headers = header_length + tcp_header_length
        length = max(total_length - headers, 0) if total_length else len(payload)
    else:
        payload = datagram[header_length + UDP_HEADER :]
    return Packet(
        when,
        sent,
        protocol,
        source,
        destination,
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
