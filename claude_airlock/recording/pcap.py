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

from ..reader import Cursor, NotThis
from ..settings import EGRESS_PORT

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
# What a lookup says that was asked and never answered
NO_ANSWER = "no answer"
# A name cannot have more labels than this, a longer walk is a loop
DNS_MOST_LABELS = 127
# What a lookup is flagged for: a name or one label of it longer than
# names are, or this many different names under one parent. Data can be
# carried out in the names asked for, a resolver passes them on, and it
# takes long names or many of them.
DNS_LONG_NAME = 100
DNS_LONG_LABEL = 40
DNS_MANY_NAMES = 30
# The embedded resolver of docker, in every container, and the port of DNS
RESOLVER = "127.0.0.11"
DNS_PORT = 53
# A query that has no answer after this many seconds of the capture is
# recorded as one, an answer later than that is still taken for it
DNS_WAIT = 10.0
# No more queries are kept to be matched with an answer than this
DNS_MOST_PENDING = 2000
TLS_HANDSHAKE = 0x16
TLS_CLIENT_HELLO = 0x01
TLS_SERVER_NAME = 0


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


class Went:
    """What became of a connection, as its outcome is named."""

    REFUSED = "refused"
    CLOSED = "closed"
    # Answered, and not seen to end
    OPEN = "open"
    # Asked for again, and never answered
    NO_ANSWER = "no answer"
    # The capture does not tell
    UNKNOWN = ""
    # Those of a connection that was not made
    WRONG = (REFUSED, NO_ANSWER)


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
    retried: bool = False
    refused: bool = False
    ended: float | None = None
    # Bytes each way, as far as the packet that ended it tells
    sent: int | None = None
    received: int | None = None

    @property
    def answered(self) -> bool:
        return self.answer_sequence is not None

    @property
    def outcome(self) -> str:
        """What became of it, see Went: UNKNOWN when the capture does
        not tell."""
        if self.refused:
            return Went.REFUSED
        if self.ended is not None:
            return Went.CLOSED
        if self.answered:
            return Went.OPEN
        return Went.NO_ANSWER if self.retried else Went.UNKNOWN

    @property
    def failed(self) -> bool:
        return self.outcome in Went.WRONG

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
    # Each answer of the resolver
    lookups: list[Lookup] = field(default_factory=list)
    # The lookups that stand out, each with what for, see DNS_MANY_NAMES
    flagged: list[tuple[str, Lookup]] = field(default_factory=list)
    # Each plain HTTP request
    requests: list[Request] = field(default_factory=list)
    # Each place something was sent to by another protocol than TCP
    flows: list[Flow] = field(default_factory=list)
    packets: int = 0
    # How many each part of the capture had, by its name: each has a
    # packet limit of its own
    part_packets: dict[str, int] = field(default_factory=dict)
    # The connections that have not ended, by source port, address and port
    _open: dict[tuple[int, str, int], Connection] = field(
        default_factory=dict, repr=False
    )
    _flows: dict[tuple[int, str, int], Flow] = field(default_factory=dict, repr=False)
    # The names that were looked up, and how many under each parent
    _looked_up: set[str] = field(default_factory=set, repr=False)
    _under: dict[str, int] = field(default_factory=dict, repr=False)
    # What each address was looked up under, with when the answer came, and
    # the server name the first TLS hello to it asked for. Both are the
    # session's doing: the address is what it reached, the name what it
    # says it was after.
    _answered: dict[str, list[tuple[float, str]]] = field(
        default_factory=dict, repr=False
    )
    _hello: dict[str, str] = field(default_factory=dict, repr=False)
    # The queries the session sent to a resolver that have not been
    # answered, by the key of their answer, with when each was sent, and
    # those of them said to have had none
    _pending: dict[tuple[int, str, int], float] = field(
        default_factory=dict, repr=False
    )
    _silent: set[tuple[int, str, int]] = field(default_factory=set, repr=False)
    _expired_at: float = field(default=0.0, repr=False)

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
                self._add_dns(packet, packet.payload)
            self._add_to_flow(packet)
            return
        if packet.payload and self._is_dns(packet):
            # Over TCP a message comes after its length
            length = int.from_bytes(packet.payload[:2], "big")
            self._add_dns(packet, packet.payload[2 : 2 + length])
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

    @staticmethod
    def _is_dns(packet: Packet) -> bool:
        """Whether a packet is to or from a resolver: by its port, or by
        its address, which is the one place docker's own is reached at
        another port than DNS's. A packet that only says it is DNS, from
        anywhere else on loopback, is the session's own."""
        return DNS_PORT in (packet.port, packet.source_port) or RESOLVER in (
            packet.source,
            packet.destination,
        )

    def _add_dns(self, packet: Packet, message: bytes) -> None:
        """Take in a DNS message. A query the session sent is kept until
        it is answered. An answer counts when it comes from a resolver
        (docker's, or a server it reached) and is the answer to one of
        those: one that was not asked for, or that came from anywhere else
        on loopback, is nothing the resolver said."""
        if not self._is_dns(packet):
            return
        try:
            found = dns_message(packet.when, message)
        except NotThis:
            return
        self._expire(packet.when)
        key = (found.id, found.lookup.name.lower(), found.asked)
        if not found.response:
            # On loopback a capture has each packet once, as one that came
            # in: what goes to the resolver there is the session's query
            if packet.sent or packet.destination == RESOLVER:
                self._ask(key, packet.when)
            return
        from_resolver = packet.source == RESOLVER or (
            not packet.sent and not is_loopback(packet.source)
        )
        if not from_resolver or key not in self._pending:
            return
        del self._pending[key]
        self._silent.discard(key)
        self._take_lookup(found.lookup)

    def _ask(self, key: tuple[int, str, int], when: float) -> None:
        """Keep a query to match its answer with. Past DNS_MOST_PENDING the
        oldest goes: queries that are never answered must not keep the
        later ones, and their answers, from being taken."""
        if key in self._pending:
            return
        while len(self._pending) >= DNS_MOST_PENDING:
            oldest = next(iter(self._pending))
            if oldest not in self._silent:
                self._take_lookup(unanswered(self._pending[oldest], oldest))
            self._silent.discard(oldest)
            del self._pending[oldest]
        self._pending[key] = when

    def _take_lookup(self, lookup: Lookup) -> None:
        self.lookups.append(lookup)
        self._flag(lookup)
        if lookup.kind in ("A", "AAAA"):
            for address in lookup.addresses:
                self._answered.setdefault(address, []).append(
                    (lookup.when, lookup.name)
                )

    def _expire(self, now: float) -> None:
        """Record the queries that have waited longer than DNS_WAIT for an
        answer as lookups that had none, once for each. Looked at once a
        second of the capture at most."""
        if now - self._expired_at < 1.0:
            return
        self._expired_at = now
        for key, asked in self._pending.items():
            if now - asked > DNS_WAIT and key not in self._silent:
                self._silent.add(key)
                self._take_lookup(unanswered(asked, key))

    def finish(self) -> None:
        """Say of what was asked and never answered, of a capture that
        ended, that it was not. Not for one that is still growing."""
        for key, asked in self._pending.items():
            if key not in self._silent:
                self._silent.add(key)
                self._take_lookup(unanswered(asked, key))

    @property
    def names(self) -> dict[str, str]:
        """The name each address is known by as of the end of the capture,
        see name_of."""
        known = {address: said[-1][1] for address, said in self._answered.items()}
        return {**self._hello, **known}

    def name_of(self, address: str, when: float | None = None) -> str | None:
        """The name an address was looked up under, as of a time: the last
        answer that came before it, so that what the session had looked up
        later does not rename what it reached earlier. Else the name the
        first TLS hello to it asked for. None when there is neither."""
        said = self._answered.get(address, [])
        if when is None and said:
            return said[-1][1]
        earlier = [name for at, name in said if when is not None and at <= when]
        return earlier[-1] if earlier else self._hello.get(address)

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
        # The same attempt sent again, which starts from the same number:
        # it got no answer in the time the kernel waits for one, a second
        # at first and twice as long each time after
        if known and packet.sequence == known.sequence:
            if not known.answered and not known.retried:
                known.retried = True
                self.endings.append((packet.when, Went.NO_ANSWER, known))
            return
        connection = Connection(
            packet.when,
            packet.destination,
            packet.port,
            packet.source_port,
            packet.sequence,
        )
        self.connections.append(connection)
        self._open[key] = connection

    def _end_connection(self, packet: Packet, connection: Connection) -> None:
        """A connection ends with the first FIN or RST of either side. A
        RST from the other end in place of an answer is a refusal. Either
        says how much its sender had sent by then, and when it also
        acknowledges, how much it had got: of a connection that is reset
        the count is known too, as far as the packet tells."""
        connection.ended = packet.when
        closing = TcpFlag.FIN in packet.tcp_flags
        if not connection.answered and not closing and not packet.sent:
            connection.refused = True
            self.endings.append((packet.when, Went.REFUSED, connection))
            return
        if connection.answer_sequence is not None:
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
        self.endings.append((packet.when, Went.CLOSED, connection))

    def _add_server_name(self, packet: Packet) -> None:
        name = tls_server_name(packet.payload)
        if name:
            # What the resolver said, if anything, is looked at first
            self._hello.setdefault(packet.destination, name)

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


@dataclass(frozen=True)
class DnsMessage:
    """A DNS message as it is read: its id, whether it is a response, the
    kind of record it is about (by number) and the lookup it makes, with
    the addresses a response gives and the error it reports."""

    id: int
    response: bool
    asked: int
    lookup: Lookup


def dns_message(when: float, message: bytes) -> DnsMessage:
    """A DNS query or response as a lookup: the name and kind of record it
    is about, and of a response the addresses it gives and the error it
    reports. A response that was captured only in part, as one longer than
    the capture takes is, gives the addresses that came before the cut.
    Raises NotThis for anything that is not about exactly one name."""
    reader = Cursor(message)
    ident = reader.number(2)
    flags, questions, answers = (reader.number(2) for _ in range(3))
    reader.skip(4)  # the counts of the two other sections
    if questions != 1:
        raise NotThis
    name = dns_name(message, reader)
    asked = reader.number(2)
    reader.skip(2)  # the class asked for
    if not name:
        raise NotThis
    response = bool(flags & DNS_IS_RESPONSE)
    addresses = []
    try:
        for _ in range(answers if response else 0):
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
    except NotThis:
        pass
    code = flags & DNS_ERROR_CODE if response else 0
    error = DNS_ERRORS.get(code, f"error {code}") if code else ""
    kind_asked = DNS_RECORDS.get(asked, f"type {asked}")
    lookup = Lookup(when, name, kind_asked, tuple(addresses), error)
    return DnsMessage(ident, response, asked, lookup)


def dns_answer(when: float, message: bytes) -> Lookup:
    """A DNS response as a lookup, see dns_message. Raises NotThis for
    anything else, a query too."""
    found = dns_message(when, message)
    if not found.response:
        raise NotThis
    return found.lookup


def unanswered(asked: float, key: tuple[int, str, int]) -> Lookup:
    """The lookup of a query that never had an answer: when it was sent,
    for which name and kind of record."""
    _, name, kind = key
    return Lookup(asked, name, DNS_RECORDS.get(kind, f"type {kind}"), (), NO_ANSWER)


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


def take_frames(
    capture: Capture,
    frames: Iterable[tuple[float, int, bytes]],
    part: str = "tcp",
) -> None:
    """Add what captured frames tell to a capture, those of the part of it
    that is named. A packet that cannot be made sense of is counted and
    passed over."""
    for when, link_type, frame in frames:
        capture.packets += 1
        capture.part_packets[part] = capture.part_packets.get(part, 0) + 1
        try:
            capture.add(parse_packet(when, link_type, frame))
        except NotThis:
            continue


def read_capture(path: Path, others: Iterable[Path] = ()) -> Capture:
    """What a capture file says a session reached, with the files of the
    other parts of the capture that are there. Raises OSError when the
    first cannot be read, and passes over one of the others that cannot."""
    capture = Capture()
    take_frames(capture, pcap_frames(path))
    for other in others:
        try:
            take_frames(capture, pcap_frames(other), other.suffix.lstrip("."))
        except OSError:
            continue
    capture.finish()
    return capture
