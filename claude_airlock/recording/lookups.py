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

from ..reader import NotThis
from .packets import RESOLVER, Packet, Protocol, is_loopback
from .payloads import Lookup, dns_message, unanswered

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


@dataclass
class Lookups:
    """The DNS messages of a capture as they are taken in, a packet at a
    time, see add."""

    # Each answer of the resolver
    lookups: list[Lookup] = field(default_factory=list)
    # The lookups that stand out, each with what for, see DNS_MANY_NAMES
    flagged: list[tuple[str, Lookup]] = field(default_factory=list)
    # The DNS messages that were not read, past MOST_LOOKUPS or
    # MOST_DNS_READ: of a packet over TCP that was not looked into, one
    unread: int = 0
    # And how many times what was sent to a resolver over TCP could not
    # be read to its end, see _over_tcp: a query may have gone unseen
    # each time, which is the session's to arrange
    cut: int = 0
    # The start of a DNS message over TCP whose rest has not come, by
    # where it is from and where it goes, see DNS_MOST_HELD
    _held: dict[tuple[str, int, str, int], bytes] = field(
        default_factory=dict, repr=False
    )
    # The names that were looked up, and how many under each parent
    _looked_up: set[str] = field(default_factory=set, repr=False)
    _under: dict[str, int] = field(default_factory=dict, repr=False)
    # What each address was looked up under, with when the answer came:
    # the session's doing, the address is what it reached
    answered: dict[str, LookedUp] = field(default_factory=dict)
    # The queries the session sent to a resolver that have not been
    # answered, by the key of their answer, with when each was sent, and
    # those of them said to have had none
    _pending: dict[tuple[int, str, int], float] = field(
        default_factory=dict, repr=False
    )
    _silent: set[tuple[int, str, int]] = field(default_factory=set, repr=False)
    _expired_at: float = field(default=0.0, repr=False)
    # How many DNS messages were read, see MOST_DNS_READ
    _read: int = field(default=0, repr=False)

    @property
    def whole(self) -> bool:
        """Whether every DNS message was read, see unread and cut."""
        return not self.unread and not self.cut

    def add(self, packet: Packet) -> None:
        """Take in the DNS messages a packet carries, if any."""
        if packet.protocol == Protocol.UDP:
            self._take(packet, packet.payload)
        elif packet.protocol == Protocol.TCP and packet.payload and is_dns(packet):
            for message in self._over_tcp(packet):
                self._take(packet, message)

    def _left(self) -> int:
        """How many more DNS messages are read: none once MOST_LOOKUPS
        are kept, else what is left of MOST_DNS_READ."""
        if len(self.lookups) >= MOST_LOOKUPS:
            return 0
        return max(MOST_DNS_READ - self._read, 0)

    def _over_tcp(self, packet: Packet) -> list[bytes]:
        """The DNS messages a packet of TCP completes. Over TCP a message
        comes after its length, and the two need not come together: the
        length in a packet of its own, a message in several. What is
        left without its end is kept for the next packet of the same
        stream. A packet that was not captured whole gives what there is
        of its last message, and nothing is kept: where the next one
        starts is not known. No more messages than are still read, see
        _left: what is left of the packet then counts as one that was
        not, and is not looked into.

        Where a stream cannot be read to its end, that is counted (see
        cut), never passed over: a packet of the session's that is
        longer than the capture keeps, with whatever follows its first
        message out of sight, and the start of a message that is let go
        of, for being longer than is held or for more streams than are.
        A session chooses all three, a query sent behind padding or in
        a message of many kilobytes is otherwise in no lookup and in no
        count."""
        left = self._left()
        stream = (packet.source, packet.source_port, packet.destination, packet.port)
        data = self._held.pop(stream, b"") + packet.payload
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
            self.unread += 1
            return messages
        if len(packet.payload) < packet.length:
            self._lost(stream)
            return [*messages, data[DNS_LENGTH:]] if data[DNS_LENGTH:] else messages
        if len(data) > DNS_HELD_BYTES:
            self._lost(stream)
        elif data:
            while len(self._held) >= DNS_MOST_HELD:
                oldest = next(iter(self._held))
                del self._held[oldest]
                self._lost(oldest)
            self._held[stream] = data
        return messages

    def _lost(self, stream: tuple[str, int, str, int]) -> None:
        """Count a stream of DNS over TCP that could not be read to its
        end, by where it is from and where it goes, see cut: one
        that goes to a resolver. What comes back cut short is the answer
        to a query that was seen, which is then a lookup without one."""
        _, _, destination, port = stream
        if destination == RESOLVER or port == DNS_PORT:
            self.cut += 1

    def _take(self, packet: Packet, message: bytes) -> None:
        """Take in a DNS message. A query the session sent is kept until
        it is answered. An answer counts when it comes from a resolver
        (docker's, or a server it reached) and is the answer to one of
        those: one that was not asked for, or that came from anywhere else
        on loopback, is nothing the resolver said."""
        if not is_dns(packet):
            return
        if not self._left():
            self.unread += 1
            return
        self._read += 1
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
        self._keep(dns_message(packet.when, message).lookup)

    def _ask(self, key: tuple[int, str, int], when: float) -> None:
        """Keep a query to match its answer with. Past DNS_MOST_PENDING the
        oldest goes: queries that are never answered must not keep the
        later ones, and their answers, from being taken."""
        if key in self._pending:
            return
        while len(self._pending) >= DNS_MOST_PENDING:
            oldest = next(iter(self._pending))
            if oldest not in self._silent:
                self._keep(unanswered(self._pending[oldest], oldest))
            self._silent.discard(oldest)
            del self._pending[oldest]
        self._pending[key] = when

    def _keep(self, lookup: Lookup) -> None:
        if len(self.lookups) >= MOST_LOOKUPS:
            # Of the queries still waiting when the last one was kept
            self.unread += 1
            return
        self.lookups.append(lookup)
        self._flag(lookup)
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
        for key, asked in self._pending.items():
            if now - asked > DNS_WAIT and key not in self._silent:
                self._silent.add(key)
                self._keep(unanswered(asked, key))

    def finish(self) -> None:
        """Say of what was asked and never answered, of a capture that
        ended, that it was not. Not for one that is still growing."""
        for key, asked in self._pending.items():
            if key not in self._silent:
                self._silent.add(key)
                self._keep(unanswered(asked, key))

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
