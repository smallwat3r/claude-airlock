"""Reading a capture for what it says a session reached: each TCP
connection and how it went, what it sent by anything else (UDP, a ping),
the answers of the resolver, the server name of a TLS hello and the request
of plain HTTP. Over IPv4 and IPv6. And for who reached the session: each
connection made to it from outside.

Of a connection the session made, three things more are read from what it
sent first: what it asked a proxy to connect it to (CONNECT), whether its
hello asks for the name it was reached by, and whether what it speaks is
what its port says. The last two are noted when they are not, and the
first when the egress proxy was asked for what could not be read (see
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
import ipaddress
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
    SEQUENCE_SPACE,
    TRANSPORT_NAMES,
    Key,
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
    TLS_HANDSHAKE,
    Hello,
    http_request,
    spoken,
    tls_hello,
)
from .pcap_file import pcap_frames
from .uploads import ELSEWHERE_PART, UPLOADS_PART, Uploads

# A connection that one side has ended is followed until the other has
# too, for what went over it meanwhile: no more of them than this, a
# session can leave any number half open
MOST_CLOSING = 10_000
# What is spoken on the ports whose use is not in doubt, as spoken of
# payloads.py tells it: a connection there that begins as something else
# is noted. And how each is written.
SPOKEN_ON = {22: SSH, 80: HTTP, 443: TLS}
SPOKEN_NAMES = {SSH: "SSH", HTTP: "HTTP", TLS: "TLS"}
HTTPS_PORT = 443
# What is kept of what a connection asked a proxy for, the session's to
# make as long as a packet
ASKED_LENGTH = 255
# How a request that asks a proxy to connect it begins, the line it asks
# that on ends, and the request does
CONNECTING = b"CONNECT "
LINE_END = b"\r\n"
REQUEST_END = b"\r\n\r\n"
# No more of the first bytes of a connection are held than this, while
# what they say is read: what it speaks, and of a request to a proxy what
# it asks for and where it ends. Far more than a client's, a session can
# send them a few at a time, and a target past this is not read.
OPENING_MOST = 1024
# Nor more of a hello of TLS than this, while it is read from the packets
# it came in, see Connection.read_hello. Its server name is near its
# start, well within this.
HELLO_MOST = 4096
# What a packet carries of a connection at the least where a link of the
# smallest size IPv6 allows was filled: of a hello begun in one as long,
# what goes on past it is a client's hello longer than a packet, see
# Connection.read_hello
FULL_SEGMENT = 1200
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


class _Opening:
    """The first bytes a connection sent, read as they come for what they
    tell: what is spoken (see spoken of payloads.py), and of a request to
    a proxy to connect it what it asks for, where it ends, and when what
    goes through the tunnel begins. As many packets as it takes, the start
    too when it carries some (TCP Fast Open): a session can send its first
    bytes a few at a time. Held by its connection until it is done."""

    def __init__(self, sequence: int) -> None:
        # Where in the stream they start, after the start of the
        # connection, which takes a number of its own
        self._starts_at = sequence + 1
        # Whether they are still read, those read so far, and how many
        # tell something once they no longer are: of a request to a
        # proxy, up to its end where that was found
        self._reading = True
        self._read = b""
        self._read_to = 0
        # Whether something was sent past a request to a proxy, see through
        self._through = False
        self.speaks = ""
        self.asked = ""
        # Whether they are a request to a proxy to connect it, whatever it
        # asked for
        self.connecting = False

    @property
    def done(self) -> bool:
        """Whether nothing more is to be read of them: they tell what they
        could, and of a request to a proxy what goes through it began."""
        return not self._reading and (self._through or not self.connecting)

    def read_on(self, packet: Packet) -> bool:
        """Add what a packet carries past them while they are read, and
        tell what they say. Whether they grew. A packet that does not go
        on from where they got, one out of its turn, adds nothing, and one
        sent again what it has past them alone: a part of the capture can
        have the start of a packet that another has more of."""
        if not self._reading or not packet.payload:
            return False
        goes_on_at = (self._starts_at + len(self._read)) % SEQUENCE_SPACE
        skipped = (goes_on_at - packet.carried_from) % SEQUENCE_SPACE
        if skipped >= len(packet.payload):
            return False
        room = OPENING_MOST - len(self._read)
        self._read += packet.payload[skipped : skipped + room]
        self.speaks = self.speaks or spoken(self._read)
        if not self.speaks:
            return True
        self.connecting = self.speaks == HTTP and self._read.startswith(CONNECTING)
        if not self.connecting:
            self._read_up(len(self._read))
            return True
        if not self.asked and LINE_END in self._read:
            asked = http_request(self._read)
            self.asked = asked[1][:ASKED_LENGTH] if asked else ""
        end = self._read.find(REQUEST_END)
        if end >= 0 or len(self._read) >= OPENING_MOST:
            self._read_up(end + len(REQUEST_END) if end >= 0 else len(self._read))
        return True

    def _read_up(self, length: int) -> None:
        """Stop reading them, so many of which told something."""
        self._reading, self._read, self._read_to = False, b"", length

    def through(self, packet: Packet) -> bool:
        """Whether a packet is the first to carry something past a request
        to a proxy to connect it, or past what was read of it while it is
        read: what goes through the tunnel, or what may, where the request
        cannot be read to its end. Never of what is no such request."""
        if not self.connecting or self._through:
            return False
        read = len(self._read) if self._reading else self._read_to
        read_to = (self._starts_at + read) % SEQUENCE_SPACE
        past = (packet.carried_to - read_to) % SEQUENCE_SPACE
        self._through = 0 < past < SEQUENCE_SPACE // 2
        return self._through


class _Greeting:
    """A hello of TLS as it is read from the packets it came in, from the
    one that starts it: what came so far, and where the next packet goes
    on from. A hello can come in as many packets as its sender likes."""

    def __init__(self, packet: Packet) -> None:
        self._held = b""
        self._goes_on_at = packet.carried_from

    def goes_on(self, packet: Packet) -> bool:
        """Whether a packet goes on from where it got."""
        return packet.carried_from == self._goes_on_at

    def read_on(self, packet: Packet) -> Hello | None:
        """Add a packet that goes on with it, and read it as far as it came,
        see tls_hello of payloads.py: none while that reads as no hello."""
        self._held += packet.payload[: HELLO_MOST - len(self._held)]
        self._goes_on_at = packet.carried_to
        return tls_hello(self._held)

    def ended_by(self, packet: Packet, hello: Hello | None) -> bool:
        """Whether nothing more is read of it after a packet: one that was
        not captured whole, past HELLO_MOST of it, or once it is read
        whole or names its server."""
        cut = len(packet.payload) < packet.length or len(self._held) >= HELLO_MOST
        return cut or bool(hello and hello.told)


@dataclass(eq=False)
class Connection:
    """A TCP connection the session opened, and how it went as far as the
    capture tells. Or one that was made to the session from outside
    (inbound): its address is then that of whoever made it, its port the
    one of the session it was made to, and its source port theirs. Known
    by itself, not by what it holds: two can go the same way."""

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
    # The hello of TLS it sent, none when it sent none, as far as it was
    # read: of one in several packets, as many as the capture has
    hello: Hello | None = None
    # What it speaks, by the first bytes the session sent on it, see
    # spoken of payloads.py: empty while that is not known
    speaks: str = ""
    # Its first bytes while they are read, see read_on: none once they
    # are done, and of one made to the session, whose are not read
    opening: _Opening | None = field(default=None, repr=False)
    # Its hello while it is read from more than one packet, see read_hello
    greeting: _Greeting | None = field(default=None, repr=False)
    # How long the packet was that its hello began in, see
    # longer_than_kept
    greeting_first: int = field(default=0, repr=False)
    # Of a hello longer than the capture keeps, the name the connection
    # was reached by, which the hello may or may not ask for: said, not
    # flagged, see Capture._look_at_hello
    hello_unread: str = ""
    # Whether how far the session got on it is told by its own packets
    # alone: the capture has all it sends, see count
    own_told: bool = field(default=False, repr=False)

    def __post_init__(self) -> None:
        first = Stream(self.sequence)
        if self.inbound:
            self.incoming = first
        else:
            self.outgoing = first
            self.opening = _Opening(self.sequence)

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
        after it and what acknowledges it count in. Each end that is
        known, the other end's is not before it answered. What the other
        end acknowledges of the session's is its word, which a server the
        session runs makes what it likes: it is not taken where the
        session's own packets tell, see own_told."""
        flags = packet.tcp_flags
        sender, other = self.outgoing, self.incoming
        if not packet.sent:
            sender, other = other, sender
        if sender is not None and not sender.closed:
            sender.reach(packet.carried_to, packet.when)
            sender.closed = TcpFlag.FIN in flags
        told = packet.sent or not self.own_told
        if other is not None and not other.closed and TcpFlag.ACK in flags and told:
            other.reach(packet.acknowledgement, packet.when)
        if self.ended is not None:
            self.sent, self.received = self.so_far

    def read_on(self, packet: Packet) -> bool:
        """Add to its first bytes what a packet of it carries past them,
        while they are read, see _Opening. Whether they grew. What they
        tell is kept here, they are let go of once done."""
        opening = self.opening
        if opening is None or not opening.read_on(packet):
            return False
        self.speaks, self.asked = opening.speaks, opening.asked
        self._done_with(opening)
        return True

    def through_tunnel(self, packet: Packet) -> bool:
        """Whether a packet it sent is the first to go through the tunnel
        its first bytes asked a proxy for, or may, see _Opening.through."""
        opening = self.opening
        if opening is None or not opening.through(packet):
            return False
        self._done_with(opening)
        return True

    def _done_with(self, opening: _Opening) -> None:
        """Let go of its first bytes once nothing more is read of them."""
        if opening.done:
            self.opening = None

    def read_hello(self, packet: Packet) -> bool:
        """Read the hello of TLS a packet it sent starts or goes on with,
        see tls_hello of payloads.py. Whether it has one by then, which
        may say no more than the start of it. Of one the capture has the
        start of in a packet that is whole, what comes next is read with
        it, as long as it goes on from there, see _Greeting. How long the
        packet it began in was is kept, see longer_than_kept."""
        greeting = self.greeting
        if greeting is None or not greeting.goes_on(packet):
            if self.hello is not None or packet.payload[:1] != bytes([TLS_HANDSHAKE]):
                return self.hello is not None
            # The first that starts as a record of TLS, or the next of
            # them when the one before read as no hello
            greeting = _Greeting(packet)
            self.greeting_first = packet.length
        hello = greeting.read_on(packet)
        self.hello = hello or self.hello
        self.greeting = None if greeting.ended_by(packet, hello) else greeting
        return self.hello is not None

    @property
    def longer_than_kept(self) -> bool:
        """Whether its hello, not read as far as its name, is one longer
        than the capture keeps, as a client's: it began in a packet as
        long as a link carries, and the rest is past what the part of
        what starts a connection takes, or past what it keeps of one.
        Not one sent a few bytes at a time, which no client does."""
        told = self.hello is not None and self.hello.told
        return not told and self.greeting_first >= FULL_SEGMENT

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


class _Waiting(NamedTuple):
    """What a connection sent that is still to be looked at, see
    Capture.look_at_hellos: when it was sent, the connection, and how
    many looks came before."""

    when: float
    connection: Connection
    looks: int


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
    # Whether it has the parts with all the session sends over TCP, see
    # uploads.py: how far the session got on a connection is then told by
    # its own packets alone, see Connection.count. Not of a capture made
    # before there were such parts.
    sends_known: bool = True
    # The connections that have not ended, by source port, address and port
    _open: dict[Key, Connection] = field(default_factory=dict, repr=False)
    # Those one side has ended and the other may not have, see MOST_CLOSING
    _closing: dict[Key, Connection] = field(default_factory=dict, repr=False)
    # Every connection by what it is known by, see Connection.key, those
    # of one key in the order they were made: a port is used again
    _by_key: dict[Key, list[Connection]] = field(default_factory=dict, repr=False)
    _flows: dict[tuple[int, str, int], Flow] = field(default_factory=dict, repr=False)
    # The server name the first TLS hello to each address asked for, what
    # the session says it was after, see dns for what it looked up
    _hello: dict[str, str] = field(default_factory=dict, repr=False)
    # The connections whose hello is still to be held against what was
    # looked up, and those whose request to the egress proxy is still to
    # be looked at, see look_at_hellos
    _hellos: list[_Waiting] = field(default_factory=list, repr=False)
    _asking: list[_Waiting] = field(default_factory=list, repr=False)
    _looks: int = field(default=0, repr=False)
    # The connections whose hello, and whose request to the egress proxy,
    # were given to be looked at: once for each
    _hello_given: set[Connection] = field(default_factory=set, repr=False)
    _asked_given: set[Connection] = field(default_factory=set, repr=False)
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
        key = packet.key
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
        connection, one it made or one made to it. Whether it has one.
        Counted also once the connection is taken to have ended: a reset
        the session's kernel did not take (one that is not at the number
        it waits for), and a connection that is no longer followed for
        being one of too many half ended (see MOST_CLOSING), go on as far
        as the session likes. What comes after its own FIN is not, see
        Connection.count."""
        connection = self.connection_at(packet.key, packet.when)
        if connection is None:
            return False
        self._take_first(connection, packet)
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
        in (see answers.py): how far its connection got by it, also once
        it is taken to have ended, as of what is sent (see _sent_on)."""
        if packet.sent or not packet.length:
            return
        connection = self.connection_at(packet.key, packet.when)
        if connection:
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

    def _add_connection(self, packet: Packet, key: Key) -> None:
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
                own_told=self.sends_known,
            )
            self.inbound.append(connection)
        else:
            connection = Connection(
                packet.when,
                packet.destination,
                packet.port,
                packet.source_port,
                packet.sequence,
                own_told=self.sends_known,
            )
            self.connections.append(connection)
        self._by_key.setdefault(key, []).append(connection)
        self._open[key] = connection
        # The one before it from the same port, if it was half ended
        self._closing.pop(key, None)

    def _end_connection(self, packet: Packet, key: Key, connection: Connection) -> None:
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

    def _end_other_side(self, packet: Packet, key: Key) -> None:
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
        tells of its connection: the hello of TLS, and when it is of the
        first the connection sent, what is spoken there and what a
        proxy was asked for."""
        connection = self.connection_of(key, packet.when)
        if connection is None:
            hello = tls_hello(packet.payload)
            if hello and hello.name:
                self._hello.setdefault(packet.destination, hello.name)
            return
        self._take_first(connection, packet)
        if connection.read_hello(packet):
            hello = connection.hello
            # Not the hello of a tunnel, which names what is behind the
            # proxy the address is of
            if hello and hello.name and not connection.asked:
                # What the resolver said, if anything, is looked at first
                self._hello.setdefault(packet.destination, hello.name)
            self._hello_due(connection, packet.when)

    def _notice(self, when: float, what: str, connection: Connection) -> None:
        if len(self.noticed) < MOST_NOTICED:
            self.noticed.append((when, what, connection))

    def _take_first(self, connection: Connection, packet: Packet) -> None:
        """Take in the first bytes a connection sent, see
        Connection.read_on, none of one made to the session. Once they
        tell what is spoken, that is noted when the port is one that
        speaks something else, and of TLS its hello is to be looked at,
        also where the capture has none of it. A request to the egress
        proxy to connect it is looked at, for whether what it asks for
        could be read, and the hello of the tunnel once the session sends
        through it, past the request: whether or not the capture has that
        hello, one the proxy refused carries nothing. Later bytes are not
        looked at for either: within a tunnel they are the session's to
        make read as anything."""
        opening = connection.opening
        if opening is None:
            return
        told = connection.speaks
        grew = connection.read_on(packet)
        if connection.through_tunnel(packet):
            self._hello_due(connection, packet.when)
        if not grew:
            return
        proxied = opening.connecting and connection.port == EGRESS_PORT
        if proxied and connection not in self._asked_given:
            self._asked_given.add(connection)
            self._asking.append(_Waiting(packet.when, connection, self._looks))
        if told or not connection.speaks:
            return
        if connection.speaks == TLS:
            self._hello_due(connection, packet.when)
        usual = SPOKEN_ON.get(connection.port)
        if not usual or connection.speaks == usual:
            return
        said = SPOKEN_NAMES.get(connection.speaks)
        self._notice(
            packet.when,
            f"speaks {said}, not {SPOKEN_NAMES[usual]}"
            if said
            else f"does not speak {SPOKEN_NAMES[usual]}",
            connection,
        )

    def _hello_due(self, connection: Connection, when: float) -> None:
        """Have the hello of a connection looked at, once, see
        look_at_hellos: by when it was sent."""
        if connection not in self._hello_given:
            self._hello_given.add(connection)
            self._hellos.append(_Waiting(when, connection, self._looks))

    def _reached_otherwise(self, connection: Connection, name: str, when: float) -> str:
        """The name a connection was reached by, when that is not the
        name its hello asks for, in small letters: the host it asked a
        proxy for, else the one its address was looked up under last by
        a time, when the address was given no such name by then. Empty
        when the hello asks for a name it was reached by, and when that
        cannot be told: the address was not looked up, the lookups up to
        that time are not all there (see whole_by of lookups.py), or it
        goes to the egress proxy and what it asked of it was not seen."""
        if connection.asked:
            host = _asked_host(connection.asked)
            return "" if name == host else host
        said = self.dns.answered.get(connection.address)
        # A lookup that went unread after the hello says nothing of it
        whole = self.lookups_whole and self.dns.whole_by(when)
        if not said or not whole or connection.port == EGRESS_PORT:
            return ""
        return "" if said.had(name, when) else (said.as_of(when) or "").lower()

    def look_at_hellos(self, over: bool = False) -> None:
        """Hold the hellos that came since the last time against the
        names their connections were reached by, see _look_at_hello,
        and note a request to the egress proxy whose target could not be
        read. Once every part of the capture is read as far as it goes:
        the lookups are in another part than the hellos, and a name that
        was looked up a moment before a hello is to be known by then. What
        was sent on a connection that was not read yet is looked at again
        then too. Of a hello that does not say all it could yet, and of a
        request whose target was not read, what came by the next look is
        waited for: while a capture grows, the part of what starts a
        connection is read ahead of those of all that is sent, and a
        packet can come to one before the other. Nothing is waited for of
        a capture that is over, nothing more comes."""
        self._place_late()
        self._hellos = [
            waiting
            for waiting in self._hellos
            if not self._looked_at(
                waiting,
                over,
                lambda connection: bool(connection.hello and connection.hello.told),
                self._look_at_hello,
            )
        ]
        self._asking = [
            waiting
            for waiting in self._asking
            if not self._looked_at(waiting, over, _asked_told, self._look_at_asked)
        ]
        self._looks += 1

    def _looked_at(
        self,
        waiting: _Waiting,
        over: bool,
        told: Callable[[Connection], bool],
        look: Callable[[Connection, float], None],
    ) -> bool:
        """Look at what a connection sent, see look_at_hellos, once it
        tells all it could, it waited for a look or the capture is over.
        Whether it was."""
        connection = waiting.connection
        if over or waiting.looks < self._looks or told(connection):
            look(connection, waiting.when)
            return True
        return False

    def _look_at_asked(self, connection: Connection, when: float) -> None:
        """Note a request to the egress proxy to connect a connection
        whose target could not be read: the hello of what goes through
        it is then held against nothing."""
        if not connection.asked:
            what = "what it asked the proxy for could not be read"
            self._notice(when, what, connection)

    def _look_at_hello(self, connection: Connection, when: float) -> None:
        """Note the hello of TLS of a connection that does not ask for
        the name the connection was reached by: the server is then told
        another name than the session looked up, or asked its proxy for,
        which is how one host is reached in the place of another behind
        the same address. Nothing of an address that was not looked up
        at all, whose hello is all that names it. A hello without a name
        is noted where HTTPS is spoken alone, to a name (see
        _to_named_https), elsewhere clients leave it out: one read whole,
        and one that could not be read as far as its name, or not at all,
        cut by the capture or sent a few bytes at a time."""
        hello = connection.hello
        name = hello.name.lower().rstrip(".") if hello else ""
        reached = self._reached_otherwise(connection, name, when)
        if not reached:
            return
        if hello and hello.name:
            what = f"its hello asks for {hello.name}"
        elif not _to_named_https(connection):
            return
        elif hello and hello.whole:
            what = "its hello names no server"
        elif connection.longer_than_kept:
            # As the hello of a browser is as often as not: said with
            # it, not flagged. A session that makes its own as long to
            # hide the name has an easier way, the name inside the
            # encryption, see the docs
            connection.hello_unread = reached
            return
        else:
            what = "its hello could not be read"
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


def _asked_host(asked: str) -> str:
    """The host a connection asked a proxy for, by what it asked
    (host:port), in small letters: an address of IPv6 without its
    brackets."""
    host = asked.rpartition(":")[0] or asked
    return host.strip("[]").lower()


def _asked_told(connection: Connection) -> bool:
    """Whether what a connection asked a proxy for was read."""
    return bool(connection.asked)


def _to_named_https(connection: Connection) -> bool:
    """Whether a connection is one HTTPS is spoken on to a name, whose
    hello names its server: on the port of HTTPS, or through a proxy it
    asked for that port of a host by its name. A client gives no name
    for an address, it has none to give."""
    if not connection.asked:
        return connection.port == HTTPS_PORT
    try:
        ipaddress.ip_address(_asked_host(connection.asked))
    except ValueError:
        return connection.asked.rpartition(":")[2] == str(HTTPS_PORT)
    return False


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
            found = capture.connection_at(packet.key, packet.when)
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
    others = list(others)
    sending = (f".{UPLOADS_PART}", f".{ELSEWHERE_PART}")
    capture = Capture(
        sends_known=any(other.suffix in sending and other.exists() for other in others)
    )
    take_frames(capture, pcap_frames(path))
    for other in others:
        try:
            take_frames(capture, pcap_frames(other), other.suffix.lstrip("."))
        except OSError:
            continue
    capture.dns.finish()
    return capture
