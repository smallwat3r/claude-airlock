"""The lookups of a capture: what the session asked resolvers, over UDP
and over TCP, and what they answered, matched query to answer, with the
lookups that stand out and what could not be read of them. Of what the
session reached, which address was looked up under which name by when,
for a connection to be named and its hello held against that, see
Capture of pcap.py."""

from __future__ import annotations

import bisect
import math
from dataclasses import dataclass, field
from typing import NamedTuple

from ..reader import NotThis
from .packets import Packet, Protocol, TcpFlag
from .payloads import DNS_HEADER, Lookup, Name, dns_message, unanswered
from .procwatch import RESOLVER, is_loopback

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
# to a port of its own. This and the two below are each of what goes to
# and comes from Docker's resolver on its own, and of what goes to port 53
# anywhere else on its own: a session can make all it likes of the second,
# which must not use up what the lookups it has the resolver make are read
# with, in whatever order the two are read.
MOST_LOOKUPS = 100_000
# Nor are more bytes of DNS messages read than this, whatever comes of
# them: one that is none, an answer nobody asked for and a query asked
# again leave no lookup to count, and over TCP a packet can hold dozens.
# By their bytes, which is what reading them takes, and not by their
# number: a session that sends many short ones uses no more of it than one
# that sends the same bytes in a few. Far more than MOST_LOOKUPS take, and
# most of what a part of the capture can hold (see capture.py), which is
# then said to have stopped. Past it the messages are counted and not
# read, the same.
MOST_DNS_BYTES = 64 * 1024 * 1024
# What a message is charged at the least of that: reading one takes its
# time whatever its length, and a session that sends the shortest there
# are, answers nobody asked for, would have each share take seconds
LEAST_CHARGED = 64
# Nor more addresses in all than this, in the lookups that are kept: one
# answer can give thousands, and each takes some 650 bytes once it is
# known by the name it was looked up under. Past it a lookup is counted
# and not kept, as one past MOST_LOOKUPS is.
MOST_ADDRESSES = 200_000


def _charged(length: int) -> int | None:
    """What a DNS message of a length is charged of what is read, see
    LEAST_CHARGED. None for what is shorter than a header: that is no
    message, and is neither read nor counted."""
    return max(length, LEAST_CHARGED) if length >= DNS_HEADER else None


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
class LookedUp:
    """The names an address was looked up under, by when each answer
    came, the earliest first: found by the time without going through
    them all, a session can have any number of answers give one address."""

    times: list[float] = field(default_factory=list)
    names: list[str] = field(default_factory=list)
    # When each name was first given it, in small letters
    _first: dict[str, float] = field(default_factory=dict, repr=False)

    def add(self, when: float, name: str) -> None:
        # After those of the same time. At the end as a rule, the answers
        # of a capture come in the order of their times
        at = bisect.bisect_right(self.times, when)
        self.times.insert(at, when)
        self.names.insert(at, name)
        known = name.lower().rstrip(".")
        self._first[known] = min(when, self._first.get(known, when))

    def as_of(self, when: float) -> str | None:
        """The name of the last answer that came by a time."""
        at = bisect.bisect_right(self.times, when)
        return self.names[at - 1] if at else None

    def had(self, name: str, when: float) -> bool:
        """Whether an answer gave it a name, in small letters, by a time."""
        return self._first.get(name, math.inf) <= when


def is_dns(packet: Packet) -> bool:
    """Whether a packet is to or from a resolver: by its port, or by
    its address, which is the one place docker's own is reached at
    another port than DNS's. A packet that only says it is DNS, from
    anywhere else on loopback, is the session's own."""
    return DNS_PORT in (packet.port, packet.source_port) or RESOLVER in (
        packet.source,
        packet.destination,
    )


class Stream(NamedTuple):
    """One way of a connection of TCP, by where it is from and where it
    goes."""

    source: str
    source_port: int
    destination: str
    port: int

    @classmethod
    def of(cls, packet: Packet) -> Stream:
        return cls(packet.source, packet.source_port, packet.destination, packet.port)

    @property
    def back(self) -> Stream:
        """The other way of the same connection."""
        return Stream(self.destination, self.port, self.source, self.source_port)


class Held(NamedTuple):
    """The start of a DNS message over TCP whose rest has not come, the
    sequence number the rest starts at, and when what it holds began to
    come."""

    data: bytes
    goes_on_at: int
    since: float


def at_resolver(packet: Packet) -> bool:
    """Whether a packet goes to or comes from Docker's resolver, which
    has its own share of what is read, see MOST_LOOKUPS."""
    return RESOLVER in (packet.source, packet.destination)


@dataclass
class _Share:
    """What was read and kept of one share of the DNS messages, see
    MOST_LOOKUPS: Docker's resolver's, or the rest. How many bytes of
    messages were read, how many lookups are kept, and how many addresses
    those give."""

    read: int = 0
    kept: int = 0
    addresses: int = 0

    def left(self) -> int:
        """How many more bytes of messages are read: none once
        MOST_LOOKUPS are kept, else what is left of MOST_DNS_BYTES."""
        if self.kept >= MOST_LOOKUPS:
            return 0
        return max(MOST_DNS_BYTES - self.read, 0)

    def room_for(self, lookup: Lookup) -> bool:
        """Whether a lookup can be kept, see MOST_ADDRESSES."""
        addresses = self.addresses + len(lookup.addresses)
        return self.kept < MOST_LOOKUPS and addresses <= MOST_ADDRESSES

    def keep(self, lookup: Lookup) -> None:
        self.kept += 1
        self.addresses += len(lookup.addresses)


# What a query and its answer are matched by: its id, its name in small
# letters and the kind of record it asks for (by number)
type _Question = tuple[int, str, int]


class _Pending(NamedTuple):
    """A query the session sent to a resolver that has not been answered:
    the lookup it asks for, its name as it was read and the share it is
    of."""

    query: Lookup
    named: Name
    share: _Share


@dataclass
class Lookups:
    """The DNS messages of a capture as they are taken in, a packet at a
    time, see add."""

    # Each answer of the resolver
    lookups: list[Lookup] = field(default_factory=list)
    # The lookups that stand out, each with what for, see DNS_MANY_NAMES
    flagged: list[tuple[str, Lookup]] = field(default_factory=list)
    # The DNS messages that were not read, past MOST_LOOKUPS or
    # MOST_DNS_BYTES: of a packet over TCP that was not looked into, one
    unread: int = 0
    # And how many times what was sent to a resolver over TCP could not
    # be read to its end, see _over_tcp: a query may have gone unseen
    # each time, which is the session's to arrange
    cut: int = 0
    # The start of a DNS message over TCP whose rest has not come, by
    # where it is from and where it goes, see DNS_MOST_HELD
    _held: dict[Stream, Held] = field(default_factory=dict, repr=False)
    # The names that were looked up, and how many under each parent
    _looked_up: set[str] = field(default_factory=set, repr=False)
    _under: dict[str, int] = field(default_factory=dict, repr=False)
    # What each address was looked up under, with when the answer came:
    # the session's doing, the address is what it reached
    answered: dict[str, LookedUp] = field(default_factory=dict)
    # The queries the session sent to a resolver that have not been
    # answered, by what their answer is matched by, and those of them said
    # to have had none
    _pending: dict[_Question, _Pending] = field(default_factory=dict, repr=False)
    _silent: set[_Question] = field(default_factory=set, repr=False)
    _expired_at: float = field(default=0.0, repr=False)
    # What was read and kept of what is Docker's resolver's, and of the
    # rest, apart, see MOST_LOOKUPS
    _shares: dict[bool, _Share] = field(
        default_factory=lambda: {True: _Share(), False: _Share()}, repr=False
    )
    # From when a message may have gone unread, see whole_by
    _missed_from: float = field(default=math.inf, repr=False)

    def whole_by(self, when: float) -> bool:
        """Whether every DNS message up to a time was read: none was
        found unread that was sent by then. A name an address was given
        by then is all there is to know of it at that time, whatever was
        not read later."""
        return when < self._missed_from

    def _missed(self, since: float) -> None:
        """Note that a message sent at a time, or later, went unread."""
        self._missed_from = min(self._missed_from, since)

    def _share(self, packet: Packet) -> _Share:
        """The share of what is read a packet is of, see MOST_LOOKUPS."""
        return self._shares[at_resolver(packet)]

    def add(self, packet: Packet) -> None:
        """Take in the DNS messages a packet carries, if any. Of TCP, a
        packet that ends its stream or starts another from the same port
        lets go of what was held of it, see _over_tcp."""
        if packet.protocol == Protocol.UDP:
            self._take(packet, packet.payload)
        elif packet.protocol == Protocol.TCP and is_dns(packet):
            # A start before what it carries, the first of its stream, an
            # end after what it carries, the last
            if TcpFlag.SYN in packet.tcp_flags:
                self._ended(packet)
            for message in self._over_tcp(packet) if packet.payload else ():
                self._take(packet, message)
            if packet.tcp_flags & (TcpFlag.FIN | TcpFlag.RST):
                self._ended(packet)

    def _over_tcp(self, packet: Packet) -> list[bytes]:
        """The DNS messages a packet of TCP completes. Over TCP a message
        comes after its length, and the two need not come together: the
        length in a packet of its own, a message in several. What is
        left without its end is kept for the next packet of the same
        stream. A packet that was not captured whole gives what there is
        of its last message, and nothing is kept: where the next one
        starts is not known. What is shorter than a header is passed
        over. No more bytes of messages than are still read, see
        _Share.left: what is left of the packet then counts as one
        message that was not, and is not looked into.

        Where a stream cannot be read to its end, that is counted (see
        cut), never passed over: a packet of the session's that is
        longer than the capture keeps, with whatever follows its first
        message out of sight, and the start of a message that is let go
        of, for being longer than is held or for more streams than are.
        A session chooses all three, a query sent behind padding or in
        a message of many kilobytes is otherwise in no lookup and in no
        count."""
        left = self._share(packet).left()
        stream = Stream.of(packet)
        held, since = self._held_before(stream, packet)
        data = held + packet.payload
        messages: list[bytes] = []
        at, over = 0, False
        while len(data) - at >= DNS_LENGTH:
            length = data[at] << 8 | data[at + 1]
            end = at + DNS_LENGTH + length
            if len(data) < end:
                break
            charged = _charged(length)
            if charged is not None:
                if charged > left:
                    over = True
                    break
                left -= charged
                messages.append(data[at + DNS_LENGTH : end])
            at = end
        data = data[at:]
        if over:
            self.unread += 1
            self._missed(since)
            return messages
        if len(packet.payload) < packet.length:
            self._lost(stream, since)
            return [*messages, data[DNS_LENGTH:]] if data[DNS_LENGTH:] else messages
        if len(data) > DNS_HELD_BYTES:
            self._lost(stream, since)
        elif data:
            while len(self._held) >= DNS_MOST_HELD:
                oldest = next(iter(self._held))
                self._lost(oldest, self._held.pop(oldest).since)
            self._held[stream] = Held(data, packet.carried_to, since)
        return messages

    def _held_before(self, stream: Stream, packet: Packet) -> tuple[bytes, float]:
        """What was held of a stream for a packet to go on from, with
        when it began to come, the packet's own time without any: none
        when the packet does not start where it goes on, which is then
        counted as lost (see _lost). A packet the capture did not have,
        one sent again or out of its turn, or another connection from
        the same port with the one before it reset: glued together, the
        two would read as other messages, the one sent in them as none."""
        held = self._held.pop(stream, None)
        if held is None:
            return b"", packet.when
        if held.goes_on_at != packet.carried_from:
            self._lost(stream, held.since)
            return b"", packet.when
        return held.data, held.since

    def _ended(self, packet: Packet) -> None:
        """Let go of what was held of the stream a packet ends, and of
        the stream back with a reset or a start: nothing comes after
        them on the same connection. What was held then is counted as
        lost, see _lost. A FIN ends what its sender sends alone, the
        other end can send on."""
        stream = Stream.of(packet)
        both = packet.tcp_flags & (TcpFlag.RST | TcpFlag.SYN)
        for ended in (stream, stream.back) if both else (stream,):
            held = self._held.pop(ended, None)
            if held is not None:
                self._lost(ended, held.since)

    def _lost(self, stream: Stream, since: float) -> None:
        """Count a stream of DNS over TCP that could not be read to its
        end, by where it is from and where it goes, see cut: one
        that goes to a resolver, with when what was not read began to
        come. What comes back cut short is the answer to a query that was
        seen, which is then a lookup without one."""
        if stream.destination == RESOLVER or stream.port == DNS_PORT:
            self.cut += 1
            self._missed(since)

    def _take(self, packet: Packet, message: bytes) -> None:
        """Take in a DNS message. A query the session sent is kept until
        it is answered. An answer counts when it comes from a resolver
        (docker's, or a server it reached) and is the answer to one of
        those: one that was not asked for, or that came from anywhere else
        on loopback, is nothing the resolver said. What is shorter than a
        header is no message."""
        charged = _charged(len(message))
        if charged is None or not is_dns(packet):
            return
        share = self._share(packet)
        if charged > share.left():
            self.unread += 1
            self._missed(packet.when)
            return
        share.read += charged
        try:
            # Its question alone at first, see dns_message
            found = dns_message(packet.when, message)
        except NotThis:
            return
        self._expire(packet.when)
        key = (found.id, found.lookup.name.lower(), found.asked)
        if not found.response:
            # On loopback a capture has each packet once, as one that came
            # in: what goes to the resolver there is the session's query
            if packet.sent or packet.destination == RESOLVER:
                self._ask(key, _Pending(found.lookup, found.named, share))
            return
        from_resolver = packet.source == RESOLVER or (
            not packet.sent and not is_loopback(packet.source)
        )
        if not from_resolver or key not in self._pending:
            return
        asked = self._pending.pop(key)
        self._silent.discard(key)
        self._keep(found.answered(), found.named, asked.share)

    def _ask(self, key: _Question, pending: _Pending) -> None:
        """Keep a query to match its answer with. Past DNS_MOST_PENDING
        the oldest goes: queries that are never answered must not keep
        the later ones, and their answers, from being taken."""
        if key in self._pending:
            return
        while len(self._pending) >= DNS_MOST_PENDING:
            oldest = next(iter(self._pending))
            self._give_up(oldest, self._pending.pop(oldest))
            self._silent.discard(oldest)
        self._pending[key] = pending

    def _give_up(self, key: _Question, pending: _Pending) -> None:
        """Keep a query that is not waited for any more as a lookup that
        had no answer, once for each."""
        if key not in self._silent:
            self._silent.add(key)
            self._keep(unanswered(pending.query), pending.named, pending.share)

    def _keep(self, lookup: Lookup, named: Name | None, share: _Share) -> None:
        """Keep a lookup of a share, as long as there is room for it, see
        MOST_LOOKUPS, and flag it when it stands out by its name as it was
        read, see _flag. That is not kept with it: its labels take as much
        again as its name, and are not needed once it is flagged."""
        if not share.room_for(lookup):
            # Of the queries still waiting when the last one was kept
            self.unread += 1
            if lookup.addresses:
                # One that gives none names no address either
                self._missed(lookup.when)
            return
        share.keep(lookup)
        self.lookups.append(lookup)
        if named is not None:
            self._flag(lookup, named)
        if lookup.kind in ("A", "AAAA"):
            for address in lookup.addresses:
                self.answered.setdefault(address, LookedUp()).add(
                    lookup.when, lookup.name
                )

    def _expire(self, now: float) -> None:
        """Record the queries that have waited longer than DNS_WAIT for an
        answer as lookups that had none, once for each. Looked at once a
        second of the capture at most."""
        if now - self._expired_at < 1.0:
            return
        self._expired_at = now
        for key, pending in self._pending.items():
            if now - pending.query.when > DNS_WAIT:
                self._give_up(key, pending)

    def finish(self) -> None:
        """Say of what was asked and never answered, of a capture that
        ended, that it was not, and count what is still held of a stream
        over TCP as not read to its end: its rest never came. Not for one
        that is still growing."""
        for key, pending in self._pending.items():
            self._give_up(key, pending)
        held, self._held = self._held, {}
        for stream, rest in held.items():
            self._lost(stream, rest.since)

    def _flag(self, lookup: Lookup, named: Name) -> None:
        """Note a lookup that stands out, a name once however often it is
        asked for: one longer than names are, one with bytes no host name
        has, the one that makes it DNS_MANY_NAMES under the same parent,
        and the one that makes it DNS_MANY_UNDER_DOMAIN under the same
        domain, whatever labels are between the two. A name is another
        by its case too, as it went: data can be carried in that as well,
        a resolver passes it on. Where it is counted goes by small letters,
        a domain is the same in any case. What the name is made of is as
        it was read, see Name of payloads.py: of one longer than names can
        be, its last labels, which are always long enough to flag."""
        if lookup.name in self._looked_up:
            return
        self._looked_up.add(lookup.name)
        labels = [label.lower() for label in named.labels]
        name = ".".join(labels)
        if named.length > DNS_LONG_NAME or named.longest > DNS_LONG_LABEL:
            self.flagged.append(("an unusually long name", lookup))
        if not named.plain:
            self.flagged.append(("a name with bytes no host name has", lookup))
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
