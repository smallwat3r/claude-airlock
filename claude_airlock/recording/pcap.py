"""Reading a capture for what it says a session reached: each TCP
connection and how it went, what it sent by anything else (UDP, a ping),
the answers of the resolver, the server name of a TLS hello and the request
of plain HTTP. Over IPv4 and IPv6.

Nothing here runs docker, see capture.py for the sidecar that writes the
files. The file is read by pcap_file.py, a packet by packets.py and what it
carries by payloads.py. What is read is what a session put on the wire, so
none of it is trusted: a message that is not what it was read as ends the
read of that message, nothing more."""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

from ..reader import NotThis
from ..settings import EGRESS_PORT
from .packets import (
    ICMP_ECHO,
    RESOLVER,
    TRANSPORT_NAMES,
    Packet,
    Protocol,
    TcpFlag,
    is_loopback,
    parse_packet,
)
from .payloads import (
    Lookup,
    dns_message,
    http_request,
    tls_server_name,
    unanswered,
)
from .pcap_file import pcap_frames

# What a lookup is flagged for: a name or one label of it longer than
# names are, or this many different names under one parent. Data can be
# carried out in the names asked for, a resolver passes them on, and it
# takes long names or many of them.
DNS_LONG_NAME = 100
DNS_LONG_LABEL = 40
DNS_MANY_NAMES = 30
# The port of DNS
DNS_PORT = 53
# A query that has no answer after this many seconds of the capture is
# recorded as one, an answer later than that is still taken for it
DNS_WAIT = 10.0
# No more queries are kept to be matched with an answer than this
DNS_MOST_PENDING = 2000


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
