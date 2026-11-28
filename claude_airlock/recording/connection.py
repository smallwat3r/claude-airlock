"""One TCP connection of a capture, as it is read from its packets: how
far each end got on it, by their sequence numbers, what its first bytes
say (what is spoken there, and what a proxy was asked to connect it to),
and its hello of TLS, read from as many packets as it came in. What a
capture holds of all of them, and what is held against what was looked
up, is pcap.py's. What is read is what a session put on the wire, so none
of it is trusted: a message that is not what it was read as ends the read
of that message, nothing more."""

from __future__ import annotations

import enum
import math
from dataclasses import dataclass, field

from .packets import SEQUENCE_SPACE, Key, Packet, TcpFlag
from .payloads import HTTP, TLS_HANDSHAKE, Hello, http_request, spoken, tls_hello

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
    # flagged, see Capture._look_at_hello of pcap.py
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
