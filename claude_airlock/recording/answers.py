"""What came back to a session as its capture saw it, where the capture
takes that: from the model's API every packet, and from anywhere else one
packet of every 16 MB a connection brings in, of each no more than its
headers and a few bytes after them (see SEQUENCE_LENGTH of capture.py).
Two parts of a capture, each with its own packet limit.

From the first, what the model's API sent back after each thing the
session sent there is an answer: how long after the upload it began, how
much it was and for how long it came. So the answers of the model show
from outside the session, next to the requests they are to (see
uploads.py), without anything of what they hold. An answer is what came
in on the connection of an upload after the last of it was sent, until
the next one long enough to be a request was sent there. What comes in
while a request is still being sent is not its answer: on a connection
that was just made it is the other end's side of the handshake, which
the first request is sent right after. Two requests sent over one
connection at the same time have their answers come back together:
nothing on the wire tells them apart, they are one answer, to the later
of the two.

From the second, how far a connection that brings in a lot has got is
known while it is still open, to within the 16 MB: a download shows
before it is over.

Of a session behind the egress filter the first part has nothing, what
comes back to it all comes from the proxy."""

from __future__ import annotations

from dataclasses import dataclass, field

from .packets import Packet
from .uploads import Key, Reached, Upload, Uploads

# The names of the parts of a capture these packets are in, see
# capture.py: what comes back from the model's API, and a sample of what
# comes in from anywhere else
ANSWERS_PART = "answers"
DOWNLOADS_PART = "downloads"
# Seconds without a packet after which an answer is over. The model
# sends what it makes as it makes it, with pauses while it thinks: longer
# than those are as a rule. What comes after one is the rest of it, said
# as that.
OVER = 10.0
# No more answers than this are kept of a capture. Its part has a packet
# limit, and an answer is a packet at least
MOST_ANSWERS = 100_000


@dataclass
class Answer:
    """What came back on a connection after an upload, until the next."""

    # What it is the answer to
    upload: Upload
    began: float
    ended: float
    received: int = 0
    # Whether it is the rest of an answer that was quiet for longer than
    # OVER, and so was taken to be over
    rest: bool = False

    @property
    def key(self) -> Key:
        return self.upload.key

    @property
    def seconds(self) -> float:
        return round(self.ended - self.began, 3)

    @property
    def waited(self) -> float:
        """How long after the last of its upload it began, the time the
        other end took to start answering. Not less than none: an answer
        can begin while the upload it is to still goes on."""
        return round(max(self.began - self.upload.ended, 0.0), 3)


@dataclass
class Answers:
    """The answers of one capture, in the order they began."""

    all: list[Answer] = field(default_factory=list)
    # The one each connection got last, and how far what came in on it
    # has got
    _last: dict[Key, Answer] = field(default_factory=dict, repr=False)
    _reached: Reached = field(default_factory=Reached, repr=False)

    def add(self, packet: Packet, uploads: Uploads, since: float) -> None:
        """Take in a packet that came back to a session and carries
        something, given what the session sent and when the connection
        it came in on was made: it is of the answer to the last request
        sent on that connection by then. Nothing of what comes in before
        a request was sent whole: the handshake of the connection, and
        what the other end says while it is still being sent to."""
        if packet.sent or not packet.length:
            return
        key = (packet.port, packet.source, packet.source_port)
        ahead, another = self._reached.adds(key, packet)
        if not ahead:
            return
        if another:
            self._last.pop(key, None)
        upload = uploads.asked_by(key, packet.when, since)
        if upload is None or packet.when <= upload.ended:
            return
        last = self._last.get(key)
        going_on = last is not None and last.upload is upload
        if last is None or not going_on or packet.when - last.ended > OVER:
            if len(self.all) >= MOST_ANSWERS:
                return
            last = self._last[key] = Answer(
                upload, packet.when, packet.when, rest=going_on
            )
            self.all.append(last)
        last.ended = max(last.ended, packet.when)
        last.received += ahead

    def superseded(self, answer: Answer) -> bool:
        """Whether another answer began on the connection of one since:
        nothing more comes of it then."""
        return self._last.get(answer.key) is not answer
