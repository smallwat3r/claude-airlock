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
files. The file is read by pcap_file.py, a packet by packets.py, what one
connection sent by connection.py and what it carries by payloads.py. What is read is what a session put on the wire, so
none of it is trusted: a message that is not what it was read as ends the
read of that message, nothing more."""

from __future__ import annotations

import bisect
import ipaddress
import math
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path
from typing import NamedTuple

from ..oldest import forget_oldest
from ..reader import NotThis
from ..settings import EGRESS_PORT
from .answers import ANSWERS_PART, DOWNLOADS_PART, Answers
from .connection import ASKED_LENGTH, Connection, Went
from .lookups import Lookups
from .packets import (
    ICMP_ECHO,
    TRANSPORT_NAMES,
    Key,
    Packet,
    Protocol,
    TcpFlag,
    parse_packet,
)
from .payloads import (
    HTTP,
    SSH,
    TLS,
    http_request,
    tls_hello,
)
from .pcap_file import pcap_frames
from .procwatch import is_loopback
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
# No more is noted of the connections of a capture than this
MOST_NOTICED = 10_000
# Nor more plain HTTP requests kept, each with no more than ASKED_LENGTH
# of its target and of its Host: a session can send one in every packet,
# each as long as the capture keeps of a packet. Those past them are
# counted, see Capture.unkept_requests
MOST_REQUESTS = 10_000
# No more of what was sent on a connection that is not read yet is kept
# to be looked at again than this, and no more often than so many times
MOST_UNPLACED = 256
LATE_TRIES = 2


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
    unkept_requests: int = 0


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
    # Each plain HTTP request, as far as MOST_REQUESTS, and of those past
    # them how many there were and when the first was sent
    requests: list[Request] = field(default_factory=list)
    unkept_requests: int = 0
    unkept_since: float = math.inf
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
            self.unkept_requests,
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
            # Room for the one put in next
            forget_oldest(self._closing, MOST_CLOSING - 1)
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
        """Keep the plain HTTP request a packet the session sent starts,
        see MOST_REQUESTS. Not one to the egress proxy, whose log has it
        with whether it was allowed."""
        if packet.port == EGRESS_PORT:
            return
        found = http_request(packet.payload)
        if not found:
            return
        if len(self.requests) >= MOST_REQUESTS:
            self.unkept_requests += 1
            self.unkept_since = min(self.unkept_since, packet.when)
            return
        method, target, host = found
        self.requests.append(
            Request(
                packet.when,
                packet.destination,
                packet.port,
                method,
                _kept(target),
                host[:ASKED_LENGTH],
            )
        )


def _kept(target: str) -> str:
    """The target of a plain HTTP request as it is kept: as long as what
    a connection asks a proxy for, with ... in the place of the rest."""
    return target[:ASKED_LENGTH] + "..." if len(target) > ASKED_LENGTH else target


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
