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

import bisect
import enum
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
from .uploads import ELSEWHERE_PART, UPLOADS_PART, Key, Uploads

# What a lookup is flagged for: a name or one label of it longer than
# names are, or this many different names under one parent. Data can be
# carried out in the names asked for, a resolver passes them on, and it
# takes long names or many of them. The names are counted under the
# domain they are of too, whatever is between: a.1.evil.test and
# a.2.evil.test have no parent in common and are both evil.test's. More
# of them there before it is said, a provider has many hosts under its
# own (s3.eu-west-1.amazonaws.com).
DNS_LONG_NAME = 100
DNS_LONG_LABEL = 40
DNS_MANY_NAMES = 30
DNS_MANY_UNDER_DOMAIN = 100
# What stands under a country in the place of com, org and the like
# (co.uk, com.au): a domain there has a label more. Not all of them, a
# list of those is long and changes: the common ones, by their first label
DNS_SECOND_LEVEL = frozenset(
    {"ac", "co", "com", "edu", "gov", "mil", "ne", "net", "nom", "or", "org"}
)
COUNTRY_LENGTH = 2
# The port of DNS
DNS_PORT = 53
# A query that has no answer after this many seconds of the capture is
# recorded as one, an answer later than that is still taken for it
DNS_WAIT = 10.0
# No more queries are kept to be matched with an answer than this
DNS_MOST_PENDING = 2000
# Over TCP a message comes after its length, in as many packets as its
# sender likes: of no more streams than this is the start of one kept
# until the rest comes, and no more of it than so many bytes
DNS_MOST_HELD = 1000
DNS_HELD_BYTES = 4096
DNS_LENGTH = 2
# No more lookups than this are kept of a capture, the DNS messages past
# them are counted and not read. Each part of a capture has a packet
# limit, which bounds what a packet a lookup would: over TCP one packet
# can hold dozens of messages, and a session can send any number of them
# to a port of its own.
MOST_LOOKUPS = 100_000
# Nor are more DNS messages read than this, whatever comes of them: one
# that is none, an answer nobody asked for and a query asked again leave
# no lookup to count, and over TCP a packet can hold hundreds, each as
# short as it says it is, down to the two bytes of its length alone. A
# lookup takes two messages, so this is twice what MOST_LOOKUPS of them
# take. Past it the messages are counted and not read, the same.
MOST_DNS_READ = 4 * MOST_LOOKUPS
# A connection that one side has ended is followed until the other has
# too, for what went over it meanwhile: no more of them than this, a
# session can leave any number half open
MOST_CLOSING = 10_000
SEQUENCE_SPACE = 1 << 32


class Went(enum.StrEnum):
    """What became of a connection, as its outcome is named."""

    REFUSED = "refused"
    CLOSED = "closed"
    # Answered, and not seen to end
    OPEN = "open"
    # Asked for again, and never answered
    NO_ANSWER = "no answer"
    # The capture does not tell
    UNKNOWN = ""

    @property
    def wrong(self) -> bool:
        """Whether it is that of a connection that was not made."""
        return self in (Went.REFUSED, Went.NO_ANSWER)


@dataclass
class Stream:
    """What one end of a connection sent, counted from the sequence
    numbers of its packets and from what the other end acknowledged. A
    number says where in the stream a packet is, and starts over every
    four gigabytes: it is taken as so much further than the last one
    seen, which holds as long as two that are seen are less than half
    of that apart. The capture takes a packet of every gigabyte for it,
    see capture.py."""

    # The number it started from
    start: int
    # How far past that it got, the start itself counted in
    reached: int = 0
    # Whether anything told how far, and whether it said it was done
    known: bool = False
    closed: bool = False

    def reach(self, sequence: int) -> None:
        """Take a sequence number that it got to. One that is behind is
        a packet sent again, or out of its turn."""
        ahead = (sequence - self.start - self.reached) % SEQUENCE_SPACE
        if ahead < SEQUENCE_SPACE // 2:
            self.reached += ahead
        self.known = True

    @property
    def count(self) -> int | None:
        """The bytes it sent as far as was seen, none when nothing told."""
        return max(0, self.reached - 1) if self.known else None


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
    # Bytes each way, as far as the packets that ended it tell: none
    # while it has not ended
    sent: int | None = None
    received: int | None = None
    # What each end sent, the other end's once it answered
    outgoing: Stream | None = field(default=None, repr=False)
    incoming: Stream | None = field(default=None, repr=False)

    def __post_init__(self) -> None:
        self.outgoing = Stream(self.sequence)

    def answer(self, sequence: int) -> None:
        """The other end answered, starting from a sequence number."""
        if self.answer_sequence is None:
            self.answer_sequence = sequence
            self.incoming = Stream(sequence)

    def count(self, packet: Packet) -> None:
        """Take in how far a packet of it says each end got: its sender
        by where the packet ends, the other end by what the packet
        acknowledges. Neither past the end of what it sent, once it said
        it was done: the end takes a number of its own, which what comes
        after it and what acknowledges it count in."""
        if self.outgoing is None or self.incoming is None:
            return
        flags = packet.tcp_flags
        sender, other = self.outgoing, self.incoming
        if not packet.sent:
            sender, other = other, sender
        if not sender.closed:
            sender.reach(packet.sequence + packet.length)
            sender.closed = TcpFlag.FIN in flags
        if TcpFlag.ACK in flags and not other.closed:
            other.reach(packet.acknowledgement)
        if self.ended is not None:
            self.sent, self.received = self.outgoing.count, self.incoming.count

    @property
    def done(self) -> bool:
        """Whether both ends said they had sent all they would."""
        return bool(
            self.outgoing
            and self.incoming
            and self.outgoing.closed
            and self.incoming.closed
        )

    @property
    def answered(self) -> bool:
        return self.answer_sequence is not None

    @property
    def outcome(self) -> Went:
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
        return self.outcome.wrong

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


def _domain_of(labels: list[str]) -> str:
    """The domain a name is of, by its labels: its last two, or three
    under a country that has com, co and the like of its own (see
    DNS_SECOND_LEVEL)."""
    under_country = (
        len(labels) > 2
        and len(labels[-1]) == COUNTRY_LENGTH
        and labels[-2] in DNS_SECOND_LEVEL
    )
    return ".".join(labels[-3:] if under_country else labels[-2:])


@dataclass
class Answers:
    """The names an address was looked up under, by when each answer
    came, the earliest first: found by the time without going through
    them all, a session can have any number of answers give one address."""

    times: list[float] = field(default_factory=list)
    names: list[str] = field(default_factory=list)

    def add(self, when: float, name: str) -> None:
        # After those of the same time. At the end as a rule, the answers
        # of a capture come in the order of their times
        at = bisect.bisect_right(self.times, when)
        self.times.insert(at, when)
        self.names.insert(at, name)

    def as_of(self, when: float) -> str | None:
        """The name of the last answer that came by a time."""
        at = bisect.bisect_right(self.times, when)
        return self.names[at - 1] if at else None


@dataclass
class Capture:
    """What a capture says a session reached."""

    # Each TCP connection it opened
    connections: list[Connection] = field(default_factory=list)
    # What became of them, in the order it did: when, what (no answer,
    # refused or closed) and the connection. For a reader that follows.
    endings: list[tuple[float, Went, Connection]] = field(default_factory=list)
    # Each answer of the resolver
    lookups: list[Lookup] = field(default_factory=list)
    # The lookups that stand out, each with what for, see DNS_MANY_NAMES
    flagged: list[tuple[str, Lookup]] = field(default_factory=list)
    # The DNS messages that were not read, past MOST_LOOKUPS or
    # MOST_DNS_READ: of a packet over TCP that was not looked into, one
    dns_unread: int = 0
    # Each plain HTTP request
    requests: list[Request] = field(default_factory=list)
    # Each place something was sent to by another protocol than TCP
    flows: list[Flow] = field(default_factory=list)
    # What was sent to the model's API, a run of packets at a time, and
    # what was sent anywhere else, when the capture took those parts, see
    # uploads.py
    uploads: Uploads = field(default_factory=Uploads)
    elsewhere: Uploads = field(default_factory=Uploads)
    packets: int = 0
    # How many each part of the capture had, by its name: each has a
    # packet limit of its own
    part_packets: dict[str, int] = field(default_factory=dict)
    # The connections that have not ended, by source port, address and port
    _open: dict[tuple[int, str, int], Connection] = field(
        default_factory=dict, repr=False
    )
    # Those one side has ended and the other may not have, see MOST_CLOSING
    _closing: dict[tuple[int, str, int], Connection] = field(
        default_factory=dict, repr=False
    )
    # The start of a DNS message over TCP whose rest has not come, by
    # where it is from and where it goes, see DNS_MOST_HELD
    _dns_held: dict[tuple[str, int, str, int], bytes] = field(
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
    _answered: dict[str, Answers] = field(default_factory=dict, repr=False)
    _hello: dict[str, str] = field(default_factory=dict, repr=False)
    # The queries the session sent to a resolver that have not been
    # answered, by the key of their answer, with when each was sent, and
    # those of them said to have had none
    _pending: dict[tuple[int, str, int], float] = field(
        default_factory=dict, repr=False
    )
    _silent: set[tuple[int, str, int]] = field(default_factory=set, repr=False)
    _expired_at: float = field(default=0.0, repr=False)
    # How many DNS messages were read, see MOST_DNS_READ
    _dns_read: int = field(default=0, repr=False)

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
            for message in self._dns_over_tcp(packet):
                self._add_dns(packet, message)
        self._add_tcp(packet)

    def _add_tcp(self, packet: Packet) -> None:
        """Take in what a packet tells of the TCP connection it is of."""
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
                self._open[key].answer(packet.sequence)
        elif flags & (TcpFlag.FIN | TcpFlag.RST):
            if key in self._open:
                self._end_connection(packet, key, self._open.pop(key))
            elif key in self._closing:
                self._end_other_side(packet, key)
        else:
            # A packet of what it carries, taken for how far it got
            known = self._open.get(key) or self._closing.get(key)
            if known:
                known.count(packet)
        # Whatever else the packet is: the one that starts a connection
        # can carry its first bytes, and the one that ends it its last, a
        # request sent whole with the end of the connection it is on
        if packet.sent and packet.payload:
            self._add_server_name(packet)
            self._add_request(packet)

    def _dns_left(self) -> int:
        """How many more DNS messages are read: none once MOST_LOOKUPS
        are kept, else what is left of MOST_DNS_READ."""
        if len(self.lookups) >= MOST_LOOKUPS:
            return 0
        return max(MOST_DNS_READ - self._dns_read, 0)

    def _dns_over_tcp(self, packet: Packet) -> list[bytes]:
        """The DNS messages a packet of TCP completes. Over TCP a message
        comes after its length, and the two need not come together: the
        length in a packet of its own, a message in several. What is
        left without its end is kept for the next packet of the same
        stream. A packet that was not captured whole gives what there is
        of its last message, and nothing is kept: where the next one
        starts is not known. No more messages than are still read, see
        _dns_left: what is left of the packet then counts as one that was
        not, and is not looked into."""
        left = self._dns_left()
        stream = (packet.source, packet.source_port, packet.destination, packet.port)
        data = self._dns_held.pop(stream, b"") + packet.payload
        messages: list[bytes] = []
        at = 0
        while len(data) - at >= DNS_LENGTH and len(messages) < left:
            end = at + DNS_LENGTH + int.from_bytes(data[at : at + DNS_LENGTH], "big")
            if len(data) < end:
                break
            messages.append(data[at + DNS_LENGTH : end])
            at = end
        data = data[at:]
        if data and len(messages) >= left:
            self.dns_unread += 1
            return messages
        if len(packet.payload) < packet.length:
            return [*messages, data[DNS_LENGTH:]] if data[DNS_LENGTH:] else messages
        if data and len(data) <= DNS_HELD_BYTES:
            while len(self._dns_held) >= DNS_MOST_HELD:
                del self._dns_held[next(iter(self._dns_held))]
            self._dns_held[stream] = data
        return messages

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
        if not self._dns_left():
            self.dns_unread += 1
            return
        self._dns_read += 1
        try:
            # Its question alone at first, see dns_message
            found = dns_message(packet.when, message, answered=False)
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
        self._take_lookup(dns_message(packet.when, message).lookup)

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
        if len(self.lookups) >= MOST_LOOKUPS:
            # Of the queries still waiting when the last one was kept
            self.dns_unread += 1
            return
        self.lookups.append(lookup)
        self._flag(lookup)
        if lookup.kind in ("A", "AAAA"):
            for address in lookup.addresses:
                self._answered.setdefault(address, Answers()).add(
                    lookup.when, lookup.name
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
        known = {address: said.names[-1] for address, said in self._answered.items()}
        return {**self._hello, **known}

    def connection_of(self, key: Key, when: float) -> Connection | None:
        """The connection something was sent on at a time, by the
        session's port and the other end: the last one from that port
        opened by then. None when the capture has none, it began later
        or its part ran into its packet limit."""
        for connection in reversed(self.connections):
            known = (connection.source_port, connection.address, connection.port)
            if known == key and connection.when <= when:
                return connection
        return None

    def name_of(self, address: str, when: float | None = None) -> str | None:
        """The name an address was looked up under, as of a time: the last
        answer that came before it, so that what the session had looked up
        later does not rename what it reached earlier. Else the name the
        first TLS hello to it asked for. None when there is neither."""
        said = self._answered.get(address)
        if said and when is None:
            return said.names[-1]
        earlier = said.as_of(when) if said and when is not None else None
        return earlier or self._hello.get(address)

    def _flag(self, lookup: Lookup) -> None:
        """Note a lookup that stands out, a name once however often it is
        asked for: one longer than names are, the one that makes it
        DNS_MANY_NAMES under the same parent, and the one that makes it
        DNS_MANY_UNDER_DOMAIN under the same domain, whatever labels are
        between the two."""
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
        parent, domain = ".".join(labels[1:]), _domain_of(labels)
        count = self._under[parent] = self._under.get(parent, 0) + 1
        if count == DNS_MANY_NAMES:
            self.flagged.append((f"{count} names looked up under {parent}", lookup))
        if domain in (parent, name):
            return
        # By a key no name is: a parent is counted by its own
        within = f"{domain}."
        count = self._under[within] = self._under.get(within, 0) + 1
        if count == DNS_MANY_UNDER_DOMAIN:
            self.flagged.append((f"{count} names looked up under {domain}", lookup))

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
        # The one before it from the same port, if it was half ended
        self._closing.pop(key, None)

    def _end_connection(
        self, packet: Packet, key: tuple[int, str, int], connection: Connection
    ) -> None:
        """A connection ends with the first FIN or RST of either side. A
        RST from the other end in place of an answer is a refusal. Either
        says how much its sender had sent by then, and when it also
        acknowledges, how much it had got: of a connection that is reset
        the count is known too, as far as the packet tells. One side that
        ends it with a FIN leaves the other free to send on, a server that
        has nothing to say does so before an upload: it is followed until
        that side has ended it too, see _end_other_side."""
        connection.ended = packet.when
        closing = TcpFlag.FIN in packet.tcp_flags
        if not connection.answered and not closing and not packet.sent:
            connection.refused = True
            self.endings.append((packet.when, Went.REFUSED, connection))
            return
        connection.count(packet)
        self.endings.append((packet.when, Went.CLOSED, connection))
        if closing and connection.answered:
            while len(self._closing) >= MOST_CLOSING:
                del self._closing[next(iter(self._closing))]
            self._closing[key] = connection

    def _end_other_side(self, packet: Packet, key: tuple[int, str, int]) -> None:
        """A FIN or RST of a connection one side had ended: how much went
        each way is as this one tells, and it ended now. With a RST, or
        once both sides have sent their FIN, nothing more comes of it."""
        connection = self._closing[key]
        connection.ended = packet.when
        connection.count(packet)
        if TcpFlag.RST in packet.tcp_flags or connection.done:
            del self._closing[key]

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
    # Those of the uploads are counted alone: the part of the TCP has what
    # starts and ends their connections, and its own count of each
    uploads = {UPLOADS_PART: capture.uploads, ELSEWHERE_PART: capture.elsewhere}
    take = uploads[part].add if part in uploads else capture.add
    for when, link_type, frame in frames:
        capture.packets += 1
        capture.part_packets[part] = capture.part_packets.get(part, 0) + 1
        try:
            take(parse_packet(when, link_type, frame))
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
