"""The records --trace --follow reads as they grow, a tail for each: a
transcript of Claude Code's, the capture of a running session out of its
sidecar, what the watcher of its processes says, how the session is
doing, and the egress proxy's log. And what the sessions did on the
network since it was last asked, for a chat to say after each turn (see
Traffic). Each knows nothing of the others, see Follower of follow.py
for what puts them together."""

from __future__ import annotations

import dataclasses
import math
import os
import time
from collections.abc import Callable, Iterator, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Self

from ..events import Event, Kind, Stage, Who, flat
from ..files import LINE_LIMIT, line_entry, open_plain
from ..recording.answers import OVER, Answer
from ..recording.capture import (
    PARTS,
    CaptureSidecar,
    captured_since,
    cut_short,
    died_so_far,
    lookups_whole,
)
from ..recording.egress_log import logged_since
from ..recording.health import Ended, Sample
from ..recording.model_api import is_model_api
from ..recording.pcap import Capture, Connection, Marks, take_frames
from ..recording.pcap_file import PcapReader
from ..recording.processes import (
    SAID_AGAIN,
    SILENT_BEATS,
    ProcessRecord,
    Watcher,
    said_lines,
)
from ..recording.procwatch import HEALTH_EVERY as SAID_EVERY
from ..recording.uploads import PAUSE, Upload
from .digest import destination_key
from .entries import read_entries, title
from .links import Links
from .net_events import (
    capture_events,
    listener_events,
    name_container,
    proxy_event,
)
from .shown import over, reached, size
from .transcript import Walk, WalkOptions
from .wire import Sent, Wire, answer_event, tunnel_to_model, upload_event

# Seconds between two questions to a watcher on how its session is doing:
# it says so every 30 seconds, and at once when a limit is near
HEALTH_EVERY = 10.0
# Seconds between two looks at whether a tcpdump of a capture has died
DIED_EVERY = 5.0
# Seconds after its last packet that an upload is
# shown: twice the pause that ends one, for what the clock of the capture
# and this one are apart
UPLOAD_OVER = 2 * PAUSE
# And seconds after its last packet that an answer of the model is shown,
# the pause that ends one and a little more for the same
ANSWER_OVER = OVER + 2.0
# Seconds after it was made that a connection is shown: what tells of it
# comes a moment later, the process its watcher found to hold it, what it
# asked a proxy for, its hello. Sooner when it was read at an earlier
# look, the clock of a capture can be ahead of this one.
SETTLE = 0.5
# A connection that is still open says how much it has carried each time
# that is so many bytes more one way, no more often than every so many
# seconds: what comes in is known by a packet of every 16 MB, see
# capture.py
PROGRESS_STEP = 1 << 24
PROGRESS_EVERY = 10.0
# What is said next to a destination the project was not noted to reach
NEW = "NEW for this project"
# Seconds without a word on how a session is doing after which what says
# it is taken to have ended, or hung: it says so every SAID_EVERY
SILENT_AFTER = SILENT_BEATS * SAID_EVERY
READ_SIZE = 1 << 20
# Of what was read of a transcript, how much of its end is kept to find it
# there again: one emptied and written to past where it was read to has a
# size that says nothing, what is before that place does
KEPT_END = 64
# How much of a transcript one look takes in, once what it held when the
# following began is read: a session can write to it as fast as it is
# read, and whoever looks has more to do than that (a chat listens to
# claude and to Ctrl-C between two looks). What is left is read by the
# next look. A megabyte of the shortest entries is a quarter of a second
# to take in
MOST_POLLED = 1 << 20
# The looks in a row that leave some of a transcript unread before it is
# said to be late: a result with a picture in it takes a few
LATE_AFTER = 10
# And the looks in a row that find a transcript no file that can be read
# before that is said: one that is written anew is gone for a moment
UNREAD_AFTER = 3
# How much of the end of a transcript is looked at for what happened
# before the following began: the last few events are shown of it, and
# the calls still running are in it. A session can make its transcript as
# long as the disk, and every megabyte of small entries is a quarter of a
# second and a dozen megabytes to hold: all of it would keep whoever
# starts to follow waiting, a chat that resumes a session too.
MOST_HISTORY = 4 << 20
# And of its start for a title, when nothing that was followed gave one
TITLE_BYTES = 1 << 20


class TranscriptTail:
    """A transcript read as it grows, from a place in it onward. It is
    the session's to write: a line longer than LINE_LIMIT is dropped, not
    held in memory."""

    def __init__(
        self,
        path: Path,
        project_dir: str,
        options: WalkOptions,
        offset: int = 0,
        agents: Iterator[int] | None = None,
    ):
        self.path = path
        self._offset = offset
        # The start of a line whose end is not written yet
        self._partial = b""
        # Whether what is read is the rest of a line that was too long
        self._dropping = False
        # With agents, of a subagent: what it does says which it is of
        self._walk = Walk(project_dir, options, agents=agents)
        self._title: str | None = None
        # The looks in a row that left some of it unread, and whether
        # that was said, see newly_behind
        self._behind = 0
        self._said_behind = False
        # The looks in a row that found it no file that can be read, and
        # whether that was said, see newly_unread
        self._unread = 0
        self._said_unread = False
        # The file it is, by its device and inode, once it was opened, and
        # whether it was found written anew since that was said, see
        # newly_rewritten
        self._file: tuple[int, int] | None = None
        self._rewritten = False
        # The last bytes read of it, up to where it was read to
        self._read_end = b""
        # Whether it is read from within and not from its start, see
        # latest: what it holds before is not looked at
        self.cut = False

    @classmethod
    def latest(cls, path: Path, project_dir: str, options: WalkOptions) -> Self:
        """A transcript read from where its last MOST_HISTORY bytes
        begin, for what happened before it was followed. A call from
        before that is not known: its result is not shown when it comes,
        as of a transcript that is followed from where it ends."""
        tail = cls(path, project_dir, options)
        try:
            start = path.lstat().st_size - MOST_HISTORY
        except OSError:
            start = 0
        if start > 0:
            # From the byte before: what is read first is let go of up to
            # the end of its line, as the rest of one too long to hold is,
            # and a line that starts right there is whole
            tail._offset, tail._dropping, tail.cut = start - 1, True, True
        return tail

    @property
    def title(self) -> str:
        """The title of its session: the one an entry that was followed
        gave, else as the start of the transcript has it."""
        if self._title is None:
            self._title = title(read_entries(self.path, TITLE_BYTES))
        return self._title

    def poll(self, most: int | None = MOST_POLLED) -> list[Event]:
        """The events of what was written since the last time, of no
        more of it than most bytes: the rest is for the next time. With
        none, of all there was when the look began, for what a
        transcript held before it was followed."""
        events: list[Event] = []
        for line in self._new_lines(most):
            entry = line_entry(line)
            if entry:
                events += self._events(entry)
        return events

    def newly_behind(self) -> bool:
        """Whether LATE_AFTER looks in a row left some of it unread,
        said once until one reads it to its end again: it is written
        faster than it is read, and what is shown of it is late."""
        if self._behind < LATE_AFTER:
            self._said_behind = self._said_behind and bool(self._behind)
            return False
        said, self._said_behind = self._said_behind, True
        return not said

    def newly_rewritten(self) -> bool:
        """Whether it was found written anew since the last time it was
        asked: emptied or cut short, written to past where it was read to
        too, or another file put in its place. A session can do that to its own transcript, to have
        what it did taken out, and what is written after would be read
        from where the one before was read to. It is read again from its
        start, and that is not to pass for what it always held."""
        said, self._rewritten = self._rewritten, False
        return said

    def newly_unread(self) -> bool:
        """Whether UNREAD_AFTER looks in a row found it no file that can
        be read, said once until it can be again: it was moved, removed,
        or a link was put in its place, which is not followed (see
        open_plain). A session can do that to its own transcript and go
        on writing through the link: what it does from then on is in no
        line, and is not to pass for nothing done."""
        if self._unread < UNREAD_AFTER:
            self._said_unread = self._said_unread and bool(self._unread)
            return False
        said, self._said_unread = self._said_unread, True
        return not said

    def _new_lines(self, most: int | None) -> Iterator[bytes | None]:
        """The lines completed since the last time, none while it is not
        a plain file that can be read (see open_plain), which is counted
        for newly_unread. From the start again of one written anew, see
        newly_rewritten. None in the place of a line that was too long
        to hold. No further than the file went when it was opened, and
        than most bytes when there is a most: what is written meanwhile
        does not keep the look going."""
        file = open_plain(self.path)
        if file is None:
            self._unread += 1
            return
        self._unread = 0
        with file:
            about = os.fstat(file.fileno())
            size, this = about.st_size, (about.st_dev, about.st_ino)
            if self._written_anew(file, size, this):
                # From its start, and said, see newly_rewritten
                self._offset, self._partial, self._dropping = 0, b"", False
                self._rewritten, self.cut, self._read_end = True, False, b""
            self._file = this
            end = size if most is None else min(size, self._offset + most)
            self._behind = self._behind + 1 if end < size else 0
            file.seek(self._offset)
            while self._offset < end:
                data = file.read(min(READ_SIZE, end - self._offset))
                if not data:
                    return
                self._offset += len(data)
                self._read_end = (self._read_end + data)[-KEPT_END:]
                if self._dropping:
                    # The rest of the line that was too long, to its end:
                    # said once, and none of it kept
                    _, ended, data = data.partition(b"\n")
                    self._dropping = not ended
                *lines, self._partial = (self._partial + data).split(b"\n")
                yield from lines
                if len(self._partial) > LINE_LIMIT:
                    self._partial, self._dropping = b"", True
                    yield None

    def _written_anew(self, file: BinaryIO, size: int, this: tuple[int, int]) -> bool:
        """Whether the file at its path is not the one read so far: another
        one, one shorter than what was read of it, or one that no longer
        has what was read last where it was read."""
        if size < self._offset or self._file not in (None, this):
            return True
        if not self._read_end:
            return False
        file.seek(self._offset - len(self._read_end))
        return file.read(len(self._read_end)) != self._read_end

    def _events(self, entry: dict) -> list[Event]:
        if entry.get("type") == "ai-title":
            self._title = title([entry])
        return self._walk.take(entry)


@dataclass(frozen=True)
class Traffic:
    """What sessions did on the network in some time, summed: the
    connections they made and to how many places, those of them that
    were refused or not answered, the requests the egress filter
    refused, the connections made to them from outside, and the bytes
    each way, as far as the capture tells of those: of a connection
    still open to anywhere but the model's API, what came in is known to
    within 16 MB."""

    connections: int = 0
    hosts: int = 0
    failed: int = 0
    denied: int = 0
    inbound: int = 0
    sent: int = 0
    received: int = 0

    def __bool__(self) -> bool:
        return any(dataclasses.astuple(self))

    def __add__(self, other: Traffic) -> Traffic:
        both = zip(dataclasses.astuple(self), dataclasses.astuple(other), strict=True)
        return Traffic(*(mine + theirs for mine, theirs in both))

    @property
    def said(self) -> str:
        """As the line of a chat says it, empty when there was none."""
        parts = []
        if self.connections:
            made = (
                "1 connection"
                if self.connections == 1
                else f"{self.connections} connections"
            )
            hosts = "1 host" if self.hosts == 1 else f"{self.hosts} hosts"
            parts.append(f"{made} to {hosts}")
        if self.sent or self.received:
            parts.append(f"{size(self.sent)} out, {size(self.received)} in")
        if self.failed:
            parts.append(f"{self.failed} FAILED")
        if self.denied:
            parts.append(f"{self.denied} DENIED")
        if self.inbound:
            parts.append(f"{self.inbound} made to it from outside")
        return ", ".join(parts)


class NewlyOver[Item]:
    """Of a list that grows at its end, the items that are over since it
    was last asked: each is given once, when it is found to be over,
    whatever those before it are. One that goes on for long does not
    hold back those that began after it."""

    def __init__(self) -> None:
        # Those before this place were given, and of those from it on
        # the ones noted here, each by what it is
        self._before = 0
        self._given: set[int] = set()

    def of(self, items: Sequence[Item], over: Callable[[Item], bool]) -> list[Item]:
        found = []
        for item in items[self._before :]:
            if id(item) not in self._given and over(item):
                self._given.add(id(item))
                found.append(item)
        while self._before < len(items) and id(items[self._before]) in self._given:
            self._given.discard(id(items[self._before]))
            self._before += 1
        return found


def _read_from(file: Path, offset: int) -> bytes:
    """What a copy of a part of a capture holds past an offset, nothing
    for one that is not there: a part that wrote nothing is not copied.
    The launcher's own file, which a packet limit bounds."""
    try:
        with open(file, "rb") as copy:
            copy.seek(offset)
            return copy.read()
    except OSError:
        return b""


class CaptureTail:
    """The capture of a running session, read as it grows. With known,
    the destinations its project was noted to reach, for the ones that
    are new to be said, with filtered, whether the session is behind
    the egress filter, and with numbers, the count its connections are
    numbered by when other captures are too, see links.py."""

    def __init__(
        self,
        sidecar: str,
        verbose: bool,
        known: frozenset[str] | None = None,
        filtered: bool = False,
        numbers: Iterator[int] | None = None,
    ):
        self.sidecar = sidecar
        self.session = CaptureSidecar.session_of(sidecar)
        self._verbose = verbose
        # Where each part of the capture has been read to, and its reader
        self._offsets = {part.name: 0 for part in PARTS}
        self._readers = {part.name: PcapReader() for part in PARTS}
        # Which of the uploads were shown, those to the model's API and
        # those to anywhere else, and which of the answers
        self._uploads_told = {True: NewlyOver[Upload](), False: NewlyOver[Upload]()}
        self._answers_told = NewlyOver[Answer]()
        # What it has read so far, for what places a request on the wire
        self.capture = Capture()
        self.filtered = filtered
        # What its lines are tied by, and what it saw go to the model's
        # API as given out to the requests that are noted, see wire.py:
        # for as long as the capture is, whose uploads that knows by
        # what they are
        self.links = Links(numbers)
        self.wire = Wire()
        # How much of it was shown, and how much it held at the last
        # look: what was there then has had its moment, see SETTLE
        self._shown = Marks()
        self._read = Marks()
        # Of each connection said to be still open, how much it had
        # carried each way then, and when that was
        self._progress: dict[int, tuple[int, int, float]] = {}
        # The destinations known, and those said to be new
        self._known = known
        self._new: set[str] = set()
        # How much there was when what the session did was last summed
        self._summed = (0, 0, 0, 0)
        self._said_cut_short = False
        # The parts already said to have died, and when that was last asked
        self._said_died = ""
        self._asked_died = 0.0

    @property
    def seen(self) -> Sent:
        """What it saw the session send, told apart, see wire.py."""
        return Sent(self.capture, self.filtered, self.links)

    def poll(self) -> list[Event]:
        """What the capture has since the last time: the connections that
        opened, what became of the open ones, the plain HTTP requests, and
        with --verbose the lookups. Nothing while it cannot be read: it can
        again later, or its session has ended."""
        offsets = {part.file: self._offsets[part.name] for part in PARTS}
        read, whole = captured_since(self.sidecar, offsets)
        self._take(read, whole)
        return self._events(over=False)

    def last_look(self, copied: Path) -> list[Event]:
        """What the capture holds past where it was read to, out of the
        copy its launcher made of it as the session ended, see collect of
        sidecar.py: the last connections, uploads and answers of the
        session, which the sidecar, stopped, no longer gives. All of it,
        nothing more comes."""
        read = {}
        for part in PARTS:
            file = (
                copied
                if part is PARTS[0]
                else copied.with_name(copied.name + part.suffix)
            )
            read[part.file] = _read_from(file, self._offsets[part.name])
        self._take(read, whole=True)
        self.capture.dns.finish()
        return self._events(over=True)

    def _take(self, read: Mapping[str, bytes], whole: bool) -> None:
        """Take in what was read past where each part was read to."""
        for part in PARTS:
            data = read[part.file]
            if data:
                self._offsets[part.name] += len(data)
                frames = self._readers[part.name].feed(data)
                take_frames(self.capture, frames, part.name)
        if whole:
            # Once every part is read as far as it goes, and not against
            # lookups that are known to be missing
            self.capture.lookups_whole = not self._said_died and lookups_whole(
                self.capture
            )
            self.capture.look_at_hellos()

    def _events(self, over: bool) -> list[Event]:
        """What is to be shown of what was taken in: of a capture that is
        over, all of it, and no connection is still open."""
        upto = self.capture.marks() if over else self._settled()
        events = capture_events(
            self.capture, self._verbose, self._shown, upto, self.links
        )
        self._shown, self._read = upto, self.capture.marks()
        self._say_new(events)
        return [
            *events,
            *self._uploads_over(over),
            *self._answers_over(over),
            *([] if over else self._still_open()),
        ]

    def _settled(self) -> Marks:
        """How much of the capture is shown by now: all of it, but for
        the connections made less than SETTLE seconds ago and read at
        this look, with what became of them and what stands out of them.
        They are shown next time, with what came of them meanwhile."""
        now = self.capture.marks()
        fresh = time.time() - SETTLE
        held: set[int] = set()

        def settled(made: list[Connection], read: int, shown: int) -> int:
            """How many of some connections are shown: those shown
            before, those read at an earlier look, and of the rest the
            first that are old enough."""
            count = max(read, shown)
            while count < len(made) and made[count].when <= fresh:
                count += 1
            held.update(id(connection) for connection in made[count:])
            return count

        capture = self.capture
        made = settled(capture.connections, self._read.connections, self._shown[0])
        inbound = settled(capture.inbound, self._read.inbound, self._shown.inbound)
        endings = self._shown.endings
        while endings < now.endings and id(capture.endings[endings][2]) not in held:
            endings += 1
        noticed = self._shown.noticed
        while noticed < now.noticed and id(capture.noticed[noticed][2]) not in held:
            noticed += 1
        return now._replace(
            connections=made, inbound=inbound, endings=endings, noticed=noticed
        )

    def _say_new(self, events: list[Event]) -> None:
        """Say of each destination that is reached, and that no session
        of the project was noted to reach before, that it is new: once,
        where it is first reached. Nothing when the project has no
        record of them yet, all of them would be."""
        if self._known is None:
            return
        for event in events:
            fields = event.fields
            reaching = fields.get("stage") == Stage.OPEN and "transport" in fields
            if not reaching:
                continue
            key = destination_key(
                fields["transport"], fields["name"], fields["address"], fields["port"]
            )
            if key not in self._known and key not in self._new:
                self._new.add(key)
                fields["new"] = True
                event.notes.append(NEW)

    def _uploads_over(self, over: bool = False) -> list[Event]:
        """The uploads that are over since the last time, to the model's
        API and to anywhere else, those long enough to be worth a line,
        each as an event: one is over once nothing was sent on its
        connection for longer than the pause that ends it, by the clock
        of this side. Each when it is, see NewlyOver: one that goes on,
        a long push or a connection that is sent a little to all the
        time, does not keep the others from showing."""
        events = []
        seen = self.seen
        quiet = math.inf if over else time.time() - UPLOAD_OVER
        parts = ((True, self.capture.uploads), (False, self.capture.elsewhere))
        for to_model, part in parts:
            told = self._uploads_told[to_model]
            for upload in told.of(part.all, lambda sent: sent.ended < quiet):
                if upload.sized:
                    model = to_model or seen.to_model(upload)
                    events.append(
                        upload_event(self.capture, upload, model, links=self.links)
                    )
        return events

    def _answers_over(self, over: bool = False) -> list[Event]:
        """The answers of the model's API that are over since the last
        time, each as an event: one is over once another began on its
        connection, or nothing came on it for longer than the pause that
        ends one, by the clock of this side."""
        answers = self.capture.answers
        quiet = math.inf if over else time.time() - ANSWER_OVER
        ended = self._answers_told.of(
            answers.all,
            lambda answer: answers.superseded(answer) or answer.ended < quiet,
        )
        return [answer_event(self.capture, answer, self.links) for answer in ended]

    def _still_open(self) -> list[Event]:
        """The connections that are still open and have carried a lot
        more since it was last said, each as an event, see
        PROGRESS_STEP: a long download or upload is not quiet until it
        is over. Not those to the model's API, nor behind the egress
        filter a tunnel to its host: each thing sent there has a line of
        its own."""
        events = []
        now = time.monotonic()
        still = self.capture.still_open()
        there = {id(connection) for connection in still}
        self._progress = {
            known: said for known, said in self._progress.items() if known in there
        }
        for connection in still:
            to_model = is_model_api(connection.address) or (
                self.filtered and tunnel_to_model(connection.port, connection.asked)
            )
            if connection.inbound or to_model:
                continue
            out, back = (count or 0 for count in connection.so_far)
            said_out, said_back, said_at = self._progress.get(
                id(connection), (0, 0, -math.inf)
            )
            more = max(out - said_out, back - said_back) >= PROGRESS_STEP
            if more and now - said_at >= PROGRESS_EVERY:
                self._progress[id(connection)] = (out, back, now)
                events.append(
                    _progress_event(self.capture, connection, out, back, self.links)
                )
        return events

    def traffic(self) -> Traffic:
        """What the session did on the network since this was last
        asked, see Traffic. Not what its egress filter refused it, which
        the capture does not tell."""
        capture = self.capture
        made, inbound, was_out, was_back = self._summed
        new = capture.connections[made:]
        hosts = {
            connection.asked
            or capture.name_of(connection.address, connection.when)
            or connection.address
            for connection in new
        }
        out, back = capture.carried()
        self._summed = (len(capture.connections), len(capture.inbound), out, back)
        return Traffic(
            connections=len(new),
            hosts=len(hosts),
            failed=sum(connection.failed for connection in new),
            inbound=len(capture.inbound) - inbound,
            sent=max(out - was_out, 0),
            received=max(back - was_back, 0),
        )

    def newly_died(self) -> str:
        """The parts whose tcpdump is found to have died since the last
        time, empty as a rule. Asked every DIED_EVERY seconds: what such a
        part would have captured since is missing, and a session that goes
        on is not to look quiet for it."""
        now = time.monotonic()
        if now - self._asked_died < DIED_EVERY:
            return ""
        self._asked_died = now
        found = died_so_far(self.sidecar)
        if found == self._said_died:
            return ""
        self._said_died = found
        return found

    def newly_cut_short(self) -> bool:
        """Whether the capture ran into its packet limit, once."""
        if self._said_cut_short or not cut_short(self.capture):
            return False
        self._said_cut_short = True
        return True


def _progress_event(
    capture: Capture, connection: Connection, out: int, back: int, links: Links
) -> Event:
    """A connection that is still open, as an event of now: for how long
    it has been, and how much it has carried so far. Tied to the line
    that said it opened by its number."""
    address, port = connection.address, connection.port
    open_for = round(max(time.time() - connection.when, 0.0), 1)
    asked = f"  asked for {flat(connection.asked)}" if connection.asked else ""
    detail = (
        f"{reached(capture, address, port, 'tcp', connection.when)}{asked}"
        f"  still open after {open_for:.0f}s, {size(out)} out, {size(back)} in so far"
    )
    fields = {
        **({"asked": connection.asked} if connection.asked else {}),
        "protocol": over("tcp", port),
        "name": capture.name_of(address, connection.when),
        "address": address,
        "port": port,
        "source_port": connection.source_port,
        "stage": Stage.PROGRESS,
        "opened": connection.when,
        "seconds": open_for,
        "bytes_out": out,
        "bytes_in": back,
    }
    tied = links.of(connection)
    return Event(time.time(), Who.SANDBOX, Kind.NET, [detail], fields, tied)


class WatcherTail:
    """What the watcher of a running session says aloud, read as it says
    it: how the session is doing, each connection and each socket that
    waits for them with the processes that hold it, and those processes
    (see procwatch.py). Not the record of all that ran, which stays in
    the sidecar."""

    def __init__(self, watcher: str) -> None:
        self.watcher = watcher
        self.session = Watcher.session_of(watcher)
        # What it said so far, as a record of the session's processes
        # with only those in it that hold a socket
        self.record = ProcessRecord()
        # The lines of the last look: what it said then is asked for
        # again in part, see SAID_AGAIN
        self._last: set[str] = set()
        self._listeners = 0
        self._said_hushed = False

    def poll(self) -> list[Event]:
        """Take in what it said since the last time. The sockets that
        started to wait for connections since, as events."""
        since = max(self.record.last_line - SAID_AGAIN, 0.0)
        lines = said_lines(self.watcher, since)
        for line in lines:
            if line not in self._last:
                self.record.take(line)
        if lines:
            # Not after a look that gave nothing, it may not have been
            # answered: what it said before would be taken again
            self._last = set(lines)
        events = listener_events(self.record, self._listeners)
        self._listeners = len(self.record.listeners)
        return events

    def health_since(self, since: float) -> list[Sample | Ended]:
        """How the session was doing later than a time, as far as read."""
        said: list[Sample | Ended] = [*self.record.samples, *self.record.ended]
        return sorted(
            (one for one in said if one.when > since), key=lambda one: one.when
        )

    def newly_hushed(self) -> bool:
        """Whether it said that it says no more aloud of connections and
        their processes, once."""
        if self._said_hushed or self.record.hushed_at is None:
            return False
        self._said_hushed = True
        return True


# A function that returns a session's health readings later than a time
type SaidSince = Callable[[float], list[Sample | Ended]]


class HealthTail:
    """The health readings of one session, polled at intervals from the
    moment the following began. said_since returns the readings later
    than a given time, see Follower._health_sources."""

    def __init__(self, session: str, said_since: SaidSince) -> None:
        self.session = session
        self._said_since = said_since
        self._since = time.time()
        self._asked = 0.0
        # When a reading last came, and whether it was said that none
        # has for too long, see newly_silent
        self._heard = time.monotonic()
        self._said_silent = False

    def poll(self) -> list[Event]:
        now = time.monotonic()
        if now - self._asked < HEALTH_EVERY:
            return []
        self._asked = now
        found = self._said_since(self._since)
        if found:
            self._since = max(one.when for one in found)
            self._heard, self._said_silent = now, False
        return [one.event() for one in found]

    def newly_silent(self) -> float | None:
        """The seconds without a reading, once they are more than
        SILENT_AFTER, and again only after one came: what watches the
        session has ended or hung, and what it notes of the session, its
        processes too, is missing from then on. None as a rule."""
        silent = time.monotonic() - self._heard
        if self._said_silent or silent <= SILENT_AFTER:
            return None
        self._said_silent = True
        return silent


class ProxyTail:
    """The egress proxy's log, read as it grows from where it ended when
    the following began."""

    def __init__(self) -> None:
        self._offset: int | None = None

    def poll(self, addresses: dict[str, str], several: bool) -> list[Event]:
        """The requests logged since the last time that came from one of
        the addresses, each with the container that has the address (see
        name_container)."""
        found = logged_since(self._offset)
        if found is None:
            return []
        self._offset, requests = found
        events = []
        for request in requests:
            if request.address in addresses:
                event = proxy_event(request)
                name_container([event], addresses[request.address], several)
                events.append(event)
        return events
