"""Reading a capture for what it says a session reached: each TCP
connection and how it went, what it sent by anything else (UDP, a ping),
the answers of the resolver, the server name of a TLS hello and the request
of plain HTTP. Over IPv4 and IPv6. And for who reached the session: each
connection made to it from outside.

Of a connection the session made, three things more are read from what it
sent first: what it asked a proxy to connect it to (CONNECT), whether its
hello asks for the name it was reached by, and whether what it speaks is
what its port says. The last two are noted when they are not (see
Capture.noticed): the bytes are the session's own, so this tells what is
not as it looks, not what was made to look right.

Nothing here runs docker, see capture.py for the sidecar that writes the
files. The file is read by pcap_file.py, a packet by packets.py and what it
carries by payloads.py. What is read is what a session put on the wire, so
none of it is trusted: a message that is not what it was read as ends the
read of that message, nothing more."""

from __future__ import annotations

import bisect
import enum
import math
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import NamedTuple

from ..reader import NotThis
from ..settings import EGRESS_PORT
from .answers import ANSWERS_PART, DOWNLOADS_PART, Answers
from .lookups import Lookups
from .packets import (
    ICMP_ECHO,
    TRANSPORT_NAMES,
    Packet,
    Protocol,
    TcpFlag,
    is_loopback,
    parse_packet,
)
from .payloads import (
    HTTP,
    SSH,
    TLS,
    Hello,
    http_request,
    spoken,
    tls_hello,
)
from .pcap_file import pcap_frames
from .uploads import ELSEWHERE_PART, UPLOADS_PART, Key, Uploads

# A connection that one side has ended is followed until the other has
# too, for what went over it meanwhile: no more of them than this, a
# session can leave any number half open
MOST_CLOSING = 10_000
SEQUENCE_SPACE = 1 << 32
# What is spoken on the ports whose use is not in doubt, as spoken of
# payloads.py tells it: a connection there that begins as something else
# is noted. And how each is written.
SPOKEN_ON = {22: SSH, 80: HTTP, 443: TLS}
SPOKEN_NAMES = {SSH: "SSH", HTTP: "HTTP", TLS: "TLS"}
HTTPS_PORT = 443
# What is kept of what a connection asked a proxy for, the session's to
# make as long as a packet
ASKED_LENGTH = 255
# No more is noted of the connections of a capture than this
MOST_NOTICED = 10_000
# No more of what was sent on a connection that is not read yet is kept
# to be looked at again than this, and no more often than so many times
MOST_UNPLACED = 256
LATE_TRIES = 2


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
    # When the last packet that told how far was sent
    told_at: float = -math.inf

    def reach(self, sequence: int, when: float) -> None:
        """Take a sequence number that it got to by a time. One that is
        behind is a packet sent again, or out of its turn. And one from
        before the last that was taken tells nothing: the parts of a
        capture are read one after the other, each from its start, and
        a number is only good to compare with the ones around it in
        time. Held against one from gigabytes later, an early packet
        would read as four gigabytes further on."""
        if when < self.told_at:
            return
        self.told_at = when
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
    capture tells. Or one that was made to the session from outside
    (inbound): its address is then that of whoever made it, its port the
    one of the session it was made to, and its source port theirs."""

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
    # Whether it was made to the session, not by it
    inbound: bool = False
    # What its first bytes asked a proxy to connect it to (host:port),
    # empty when they asked for no such thing: the session's word, which
    # a proxy takes or refuses
    asked: str = ""
    # The hello of TLS it sent, none when it sent none
    hello: Hello | None = None
    # What it speaks, by the first bytes the session sent on it, see
    # spoken of payloads.py: empty while that is not known
    speaks: str = ""

    def __post_init__(self) -> None:
        first = Stream(self.sequence)
        if self.inbound:
            self.incoming = first
        else:
            self.outgoing = first

    @property
    def key(self) -> Key:
        """What it is known by: the session's port, then the address and
        the port of the other end."""
        if self.inbound:
            return (self.port, self.address, self.source_port)
        return (self.source_port, self.address, self.port)

    def answer(self, sequence: int) -> None:
        """The other end answered, starting from a sequence number. Of
        one made to the session, the session did."""
        if self.answer_sequence is None:
            self.answer_sequence = sequence
            if self.inbound:
                self.outgoing = Stream(sequence)
            else:
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
            sender.reach(packet.sequence + packet.length, packet.when)
            sender.closed = TcpFlag.FIN in flags
        if TcpFlag.ACK in flags and not other.closed:
            other.reach(packet.acknowledgement, packet.when)
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

    @property
    def so_far(self) -> tuple[int | None, int | None]:
        """The bytes each way as far as any packet of it told, out then
        in: of one that has not ended, what is known of it by now. Of
        what the session sent every packet tells, when the capture took
        those. Of what came in, as the capture samples it: every packet
        from the model's API, one of every 16 MB from anywhere else (see
        capture.py)."""
        out = self.outgoing.count if self.outgoing else None
        back = self.incoming.count if self.incoming else None
        return out, back


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


class Marks(NamedTuple):
    """How much of each kind a capture has, for a reader that follows it
    to tell what came since, and to say how far it shows."""

    connections: int = 0
    endings: int = 0
    lookups: int = 0
    requests: int = 0
    flows: int = 0
    flagged: int = 0
    inbound: int = 0
    noticed: int = 0


@dataclass
class Capture:
    """What a capture says a session reached, and who reached it."""

    # Each TCP connection it opened
    connections: list[Connection] = field(default_factory=list)
    # Each one that was made to it from outside
    inbound: list[Connection] = field(default_factory=list)
    # What became of them, in the order it did: when, what (no answer,
    # refused or closed) and the connection. For a reader that follows.
    endings: list[tuple[float, Went, Connection]] = field(default_factory=list)
    # What stands out of the connections it opened, in the order it was
    # found: when, what, and the connection. See look_at_hellos and
    # _take_first.
    noticed: list[tuple[float, str, Connection]] = field(default_factory=list)
    # What was asked of resolvers and what they said, see lookups.py
    dns: Lookups = field(default_factory=Lookups)
    # Each plain HTTP request
    requests: list[Request] = field(default_factory=list)
    # Each place something was sent to by another protocol than TCP
    flows: list[Flow] = field(default_factory=list)
    # What was sent to the model's API, a run of packets at a time, and
    # what was sent anywhere else, when the capture took those parts, see
    # uploads.py
    uploads: Uploads = field(default_factory=Uploads)
    elsewhere: Uploads = field(default_factory=Uploads)
    # What came back from the model's API after each thing sent there,
    # when the capture took that part, see answers.py
    answers: Answers = field(default_factory=Answers)
    packets: int = 0
    # Whether the lookups are all there, as far as whoever reads the
    # capture knows: not when the part that has them stopped at its
    # packet limit, or its recorder ended or lost packets. A hello is
    # then held against no name, see _reached_otherwise.
    lookups_whole: bool = True
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
    # Every connection by what it is known by, see Connection.key, those
    # of one key in the order they were made: a port is used again
    _by_key: dict[Key, list[Connection]] = field(default_factory=dict, repr=False)
    _flows: dict[tuple[int, str, int], Flow] = field(default_factory=dict, repr=False)
    # The server name the first TLS hello to each address asked for, what
    # the session says it was after, see dns for what it looked up
    _hello: dict[str, str] = field(default_factory=dict, repr=False)
    # The connections whose hello is still to be held against what was
    # looked up, each with when it sent it, see look_at_hellos
    _hellos: list[tuple[float, Connection]] = field(default_factory=list, repr=False)
    # What the session sent on a connection whose start was not read
    # yet, each with how often it was looked for again, see sent_too
    _unplaced: list[tuple[Packet, int]] = field(default_factory=list, repr=False)

    def marks(self) -> Marks:
        """How much of each kind there is, for a reader that follows to
        tell what came since."""
        return Marks(
            len(self.connections),
            len(self.endings),
            len(self.dns.lookups),
            len(self.requests),
            len(self.flows),
            len(self.dns.flagged),
            len(self.inbound),
            len(self.noticed),
        )

    def add(self, packet: Packet) -> None:
        """Take in what one packet tells."""
        self.dns.add(packet)
        if packet.protocol != Protocol.TCP:
            self._add_to_flow(packet)
            return
        self._add_tcp(packet)

    def _add_tcp(self, packet: Packet) -> None:
        """Take in what a packet tells of the TCP connection it is of."""
        # A connection is known by the session's port and the other end
        if packet.sent:
            key = (packet.source_port, packet.destination, packet.port)
        else:
            key = (packet.port, packet.source, packet.source_port)
        if is_loopback(key[1]) or packet.source == packet.destination:
            # What the session does within itself, at its own address too
            return
        flags = packet.tcp_flags
        if TcpFlag.SYN in flags:
            # The start of a connection has SYN alone, the answer to it
            # SYN and ACK. One the session sends is a connection it
            # makes, one that comes in is made to it from outside, and
            # the answer comes from the other side than the start.
            known = self._open.get(key)
            if TcpFlag.ACK not in flags:
                self._add_connection(packet, key)
            elif known and packet.sent == known.inbound:
                known.answer(packet.sequence)
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
            self._read_sent(packet, key)
            self._add_request(packet)

    @property
    def names(self) -> dict[str, str]:
        """The name each address is known by as of the end of the capture,
        see name_of."""
        known = {address: said.names[-1] for address, said in self.dns.answered.items()}
        return {**self._hello, **known}

    def still_open(self) -> list[Connection]:
        """The connections that were answered and have not ended."""
        return [found for found in self._open.values() if found.answered]

    def carried(self) -> tuple[int, int]:
        """How much the session sent and got over TCP so far, on the
        connections it made and on those made to it, as far as the
        capture tells: of one that ended, by what ended it, of any other
        by the packets of it there are, see Connection.so_far."""
        out = back = 0
        for found in (*self.connections, *self.inbound):
            sent, received = found.so_far
            out += (sent if found.sent is None else found.sent) or 0
            back += (received if found.received is None else found.received) or 0
        return out, back

    def connection_at(self, key: Key, when: float) -> Connection | None:
        """The connection a packet of a time is of, by the session's
        port and the other end: the last one of that key made by then,
        whoever made it. None when the capture has none, it began later
        or its part ran into its packet limit."""
        known = self._by_key.get(key)
        if not known:
            return None
        at = bisect.bisect_right(known, when, key=lambda connection: connection.when)
        return known[at - 1] if at else None

    def connection_of(self, key: Key, when: float) -> Connection | None:
        """The connection something was sent on at a time, see
        connection_at: one the session made, none for any other."""
        found = self.connection_at(key, when)
        return found if found and not found.inbound else None

    def sent_too(self, packet: Packet) -> None:
        """Take in a packet of the parts that have all the session
        sends, which are read for the uploads (see uploads.py): how far
        its connection got by it, while that is open, and what the
        connection speaks when it is the first of it."""
        if not packet.sent or not packet.length:
            return
        if not self._sent_on(packet) and len(self._unplaced) < MOST_UNPLACED:
            # Its connection is not known: while a capture grows, the
            # part this packet is in is read a moment after the part
            # that has what starts a connection, and can be ahead of it
            self._unplaced.append((packet, 0))

    def _sent_on(self, packet: Packet) -> bool:
        """Take in what a packet the session sent tells of its
        connection, one it made or one made to it. Whether it has one."""
        key = (packet.source_port, packet.destination, packet.port)
        connection = self.connection_at(key, packet.when)
        if connection is None:
            return False
        if not connection.inbound:
            self._take_first(connection, packet)
        if connection.ended is None:
            connection.count(packet)
        return True

    def _place_late(self) -> None:
        """Look again for the connections of what was sent before its
        connection was read, see sent_too: twice, the start of one comes
        with the next reading of its part at the latest."""
        late, self._unplaced = self._unplaced, []
        for packet, tries in late:
            if not self._sent_on(packet) and tries < LATE_TRIES:
                self._unplaced.append((packet, tries + 1))

    def received_too(self, packet: Packet) -> None:
        """Take in a packet of the parts that have some of what comes
        in (see answers.py): how far its connection got by it, while
        that is open."""
        if packet.sent or not packet.length:
            return
        key = (packet.port, packet.source, packet.source_port)
        connection = self.connection_at(key, packet.when)
        if connection and connection.ended is None:
            connection.count(packet)

    def name_of(self, address: str, when: float | None = None) -> str | None:
        """The name an address was looked up under, as of a time: the last
        answer that came before it, so that what the session had looked up
        later does not rename what it reached earlier. Else the name the
        first TLS hello to it asked for. None when there is neither."""
        said = self.dns.answered.get(address)
        if said and when is None:
            return said.names[-1]
        earlier = said.as_of(when) if said and when is not None else None
        return earlier or self._hello.get(address)

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
        """Take in the start of a connection: one the session makes when
        it sent the packet, one made to it when the packet came in."""
        known = self._open.get(key)
        inbound = not packet.sent
        # The same attempt sent again, which starts from the same number:
        # it got no answer in the time the kernel waits for one, a second
        # at first and twice as long each time after
        if known and packet.sequence == known.sequence and known.inbound == inbound:
            if not known.answered and not known.retried:
                known.retried = True
                self.endings.append((packet.when, Went.NO_ANSWER, known))
            return
        if inbound:
            connection = Connection(
                packet.when,
                packet.source,
                packet.port,
                packet.source_port,
                packet.sequence,
                inbound=True,
            )
            self.inbound.append(connection)
        else:
            connection = Connection(
                packet.when,
                packet.destination,
                packet.port,
                packet.source_port,
                packet.sequence,
            )
            self.connections.append(connection)
        self._by_key.setdefault(key, []).append(connection)
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
        # From the side that was asked, the session's of one made to it
        refusing = packet.sent == connection.inbound
        if not connection.answered and not closing and refusing:
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

    def _read_sent(self, packet: Packet, key: Key) -> None:
        """Read what a packet the session sent carries, for what it
        tells of its connection: the hello of TLS, and when it is the
        first the connection sent, what is spoken there and what a
        proxy was asked for."""
        connection = self.connection_of(key, packet.when)
        if connection:
            self._take_first(connection, packet)
        hello = tls_hello(packet.payload)
        # Not the hello of a tunnel, which names what is behind the proxy
        # the address is of
        if hello and hello.name and not (connection and connection.asked):
            # What the resolver said, if anything, is looked at first
            self._hello.setdefault(packet.destination, hello.name)
        if connection is None:
            return
        if hello and connection.hello is None:
            connection.hello = hello
            self._hellos.append((packet.when, connection))

    def _notice(self, when: float, what: str, connection: Connection) -> None:
        if len(self.noticed) < MOST_NOTICED:
            self.noticed.append((when, what, connection))

    def _take_first(self, connection: Connection, packet: Packet) -> None:
        """Take in the first bytes a connection sent, when the packet
        holds them: what they say is spoken there, noted when the port
        is one that speaks something else, and what they ask a proxy to
        connect to. Later bytes are not looked at for either: within a
        tunnel they are the session's to make read as anything."""
        first = (connection.sequence + 1) % SEQUENCE_SPACE
        if connection.speaks or packet.sequence != first:
            return
        connection.speaks = spoken(packet.payload)
        if connection.speaks == HTTP:
            asked = http_request(packet.payload)
            if asked and asked[0] == "CONNECT":
                connection.asked = asked[1][:ASKED_LENGTH]
        usual = SPOKEN_ON.get(connection.port)
        if not usual or connection.speaks in ("", usual):
            return
        said = SPOKEN_NAMES.get(connection.speaks)
        self._notice(
            packet.when,
            f"speaks {said}, not {SPOKEN_NAMES[usual]}"
            if said
            else f"does not speak {SPOKEN_NAMES[usual]}",
            connection,
        )

    def _reached_otherwise(self, connection: Connection, name: str, when: float) -> str:
        """The name a connection was reached by, when that is not the
        name its hello asks for, in small letters: the host it asked a
        proxy for, else the one its address was looked up under last by
        a time, when the address was given no such name by then. Empty
        when the hello asks for a name it was reached by, and when that
        cannot be told: the address was not looked up, the lookups are
        not all there, or it goes to the egress proxy and what it asked
        of it was not seen."""
        if connection.asked:
            host = connection.asked.rpartition(":")[0] or connection.asked
            host = host.strip("[]").lower()
            return "" if name == host else host
        said = self.dns.answered.get(connection.address)
        whole = self.lookups_whole and self.dns.whole
        if not said or not whole or connection.port == EGRESS_PORT:
            return ""
        return "" if said.had(name, when) else (said.as_of(when) or "").lower()

    def look_at_hellos(self) -> None:
        """Hold the hellos that came since the last time against the
        names their connections were reached by, see _look_at_hello.
        Once every part of the capture is read as far as it goes: the
        lookups are in another part than the hellos, and a name that was
        looked up a moment before a hello is to be known by then. What
        was sent on a connection that was not read yet is looked at
        again then too."""
        self._place_late()
        for when, connection in self._hellos:
            if connection.hello:
                self._look_at_hello(connection, connection.hello, when)
        self._hellos.clear()

    def _look_at_hello(self, connection: Connection, hello: Hello, when: float) -> None:
        """Note the hello of TLS of a connection that does not ask for
        the name the connection was reached by: the server is then told
        another name than the session looked up, or asked its proxy for,
        which is how one host is reached in the place of another behind
        the same address. Nothing of an address that was not looked up
        at all, whose hello is all that names it. A hello without a name
        is noted on the port of HTTPS alone, elsewhere clients leave it
        out, and not one that was cut short, which may name its server
        past the cut."""
        name = hello.name.lower().rstrip(".")
        reached = self._reached_otherwise(connection, name, when)
        if not reached:
            return
        if name:
            what = f"its hello asks for {hello.name}"
        elif hello.whole and connection.port == HTTPS_PORT:
            what = "its hello names no server"
        else:
            return
        self._notice(when, f"{what}, it was reached as {reached}", connection)

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


def _taken_by(capture: Capture, part: str) -> Callable[[Packet], None]:
    """What takes in the packets of a part of a capture. Those of what
    the session sent and of what came back are counted on their own: the
    part of the TCP has what starts and ends their connections, and its
    own count of each."""
    uploads = {UPLOADS_PART: capture.uploads, ELSEWHERE_PART: capture.elsewhere}
    if part in uploads:

        def sent(packet: Packet) -> None:
            uploads[part].add(packet)
            capture.sent_too(packet)

        return sent
    if part == ANSWERS_PART:

        def answered(packet: Packet) -> None:
            # Of the connection it came in on, by when that was made: a
            # port is used again, and what went over the one before it
            # is not what this is the answer to
            key = (packet.port, packet.source, packet.source_port)
            found = capture.connection_at(key, packet.when)
            since = found.when if found else -math.inf
            capture.answers.add(packet, capture.uploads, since)
            capture.received_too(packet)

        return answered
    return capture.received_too if part == DOWNLOADS_PART else capture.add


def take_frames(
    capture: Capture,
    frames: Iterable[tuple[float, int, bytes]],
    part: str = "tcp",
) -> None:
    """Add what captured frames tell to a capture, those of the part of it
    that is named. A packet that cannot be made sense of is counted and
    passed over."""
    take = _taken_by(capture, part)
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
    first cannot be read, and passes over one of the others that cannot.
    The hellos are not held against the lookups here, see
    Capture.look_at_hellos: whoever reads a capture knows whether its
    lookups are all there, see read_parts of capture.py."""
    capture = Capture()
    take_frames(capture, pcap_frames(path))
    for other in others:
        try:
            take_frames(capture, pcap_frames(other), other.suffix.lstrip("."))
        except OSError:
            continue
    capture.dns.finish()
    return capture
