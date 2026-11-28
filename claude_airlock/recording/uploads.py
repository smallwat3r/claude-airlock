"""What a session sent as the capture saw it go, a connection at a time:
each run of packets it sent somewhere without a pause is an upload. A
request to the model is one, the conversation sent again, and so is a
push to a repository or a file sent anywhere. So they show from outside
the session, with the connection each went over and when, without
anything of what they hold: of these packets the capture keeps no more
than their start, the headers and where those are short some bytes after
them (see HEADERS_LENGTH of capture.py), which are not read here. What
goes to the model's API and what goes anywhere else are two parts of a
capture, each with its own packet limit (see capture.py): a session that
sends a lot somewhere does not use up what its requests to the model are
told by.

What a session says it asked the model is another record, its own word
(see api_log.py). The two are put side by side by report/wire.py.

How much an upload sent is counted from the sequence numbers of its
packets, as of a connection (see Stream of pcap.py): one sent again is
not counted twice, and one the capture missed is counted by the next.
Two requests sent at the same moment over one connection are one upload,
nothing on the wire tells them apart."""

from __future__ import annotations

import bisect
from dataclasses import dataclass, field

from .packets import SEQUENCE_SPACE, Key, Packet

# The names of the parts of a capture these packets are in, see
# capture.py: what is sent to the model's API, and what is sent anywhere
# else
UPLOADS_PART = "uploads"
ELSEWHERE_PART = "elsewhere"
# Seconds without a packet after which what is sent next is another
# upload. Longer than the pauses within one, when its sender waits for
# the other end to take what it has, and shorter than it takes the model
# to answer, which is what comes between two requests.
PAUSE = 0.5
# An upload of fewer bytes than this is not worth a line of its own:
# what keeps a connection going, its handshake, a request that asks for
# something and sends nothing
LEAST = 4096
# How far ahead of the last one a packet may be and still be the same
# stream going on, with what the capture missed between: past that the
# port was taken by another connection
MOST_MISSED = 1 << 24
# No more uploads than this are kept of a capture. Its part has a packet
# limit, and an upload is a packet at least
MOST_UPLOADS = 100_000


@dataclass
class Upload:
    """What a session sent on one connection without a pause."""

    key: Key
    began: float
    ended: float
    sent: int = 0
    # When it got long enough to be worth a line, none while it is not
    sized_at: float | None = None

    @property
    def seconds(self) -> float:
        return round(self.ended - self.began, 3)

    @property
    def sized(self) -> bool:
        """Whether it is long enough to be worth a line."""
        return self.sent >= LEAST


def _began(upload: Upload) -> float:
    """What uploads are in the order of."""
    return upload.began


def began_between(uploads: list[Upload], start: float, end: float) -> list[Upload]:
    """Of some uploads in the order they began, those that began between
    two times, the first first."""
    first = bisect.bisect_left(uploads, start, key=_began)
    last = bisect.bisect_right(uploads, end, key=_began)
    return uploads[first:last]


class Reached:
    """How far what each connection sent one way got, by the sequence
    numbers of its packets: what a packet adds to that."""

    def __init__(self) -> None:
        self._reached: dict[Key, int] = {}

    def adds(self, key: Key, packet: Packet) -> tuple[int, bool]:
        """How many bytes a packet adds to what its connection sent that
        way, none for one sent again or out of its turn, which was
        counted when it first came. And whether it is of another
        connection than the packets before it: neither the stream going
        on nor a part of it again, the port was taken by a new one."""
        end = packet.carried_to
        reached = self._reached.get(key)
        ahead, another = packet.length, False
        if reached is not None:
            ahead = (end - reached) % SEQUENCE_SPACE
            if not 0 < ahead <= packet.length + MOST_MISSED:
                if (reached - end) % SEQUENCE_SPACE <= MOST_MISSED:
                    return 0, False
                ahead, another = packet.length, True
        self._reached[key] = end
        return ahead, another


@dataclass
class Uploads:
    """The uploads of one part of a capture, in the order they began."""

    all: list[Upload] = field(default_factory=list)
    # The one each connection sent last, and how far its stream got
    _last: dict[Key, Upload] = field(default_factory=dict, repr=False)
    _reached: Reached = field(default_factory=Reached, repr=False)
    # Those of each connection that are long enough to be worth a line,
    # in the order they began: what came back after each is its answer,
    # see answers.py
    _sized: dict[Key, list[Upload]] = field(default_factory=dict, repr=False)

    def add(self, packet: Packet) -> None:
        """Take in a packet a session sent that carries something."""
        if not packet.sent or not packet.length:
            return
        key = packet.key
        ahead, another = self._reached.adds(key, packet)
        if not ahead:
            return
        if another:
            self._last.pop(key, None)
        last = self._last.get(key)
        if last is None or packet.when - last.ended > PAUSE:
            if len(self.all) >= MOST_UPLOADS:
                return
            last = self._last[key] = Upload(key, packet.when, packet.when)
            self.all.append(last)
        last.ended = max(last.ended, packet.when)
        last.sent += ahead
        if last.sized and last.sized_at is None:
            last.sized_at = packet.when
            self._sized.setdefault(key, []).append(last)

    def asked_by(self, key: Key, when: float, since: float) -> Upload | None:
        """The last upload from a port to a place that had got long
        enough to be worth a line by a time: the request what comes back
        then is the answer to. Not one that began before since, when the
        connection something came back on was made: a port is used
        again. None when there was none yet."""
        sized = self._sized.get(key)
        if not sized:
            return None
        at = bisect.bisect_right(sized, when, key=lambda upload: upload.sized_at or 0)
        found = sized[at - 1] if at else None
        return found if found and found.began >= since else None

    def place(self, upload: Upload, since: float) -> int:
        """Which of those sent over its connection an upload is, of the
        ones long enough to be worth a line: 1 for the first since the
        connection was made. None of them is 0, one that is too short
        or is of another part of the capture."""
        sized = self._sized.get(upload.key, [])
        first = bisect.bisect_left(sized, since, key=_began)
        at = bisect.bisect_left(sized, upload.began, key=_began)
        found = at < len(sized) and sized[at] is upload
        return at - first + 1 if found and at >= first else 0

    def sized_on(self, key: Key, start: float, end: float) -> int:
        """How many of one connection were long enough to be worth a
        line, by when it was opened and ended: of those it sent alone,
        however many others there are."""
        return len(began_between(self._sized.get(key, []), start, end))
