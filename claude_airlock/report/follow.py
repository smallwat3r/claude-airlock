"""Watching sessions as they run (--trace --follow): the lines of --trace,
written as things happen and until interrupted.

Four records are read as they grow. The transcripts Claude Code keeps of
the project's sessions, every one that is written to, so a session started,
resumed or cleared while following is picked up, and those of the subagents
of each. The capture of each of the
project's running sessions, read out of its sidecar. For a filtered
session the egress proxy's log. And what the launcher notes of the use of
the SSH agent and the Docker socket (see doors.py). Not the record of the
processes, which stays in its sidecar until the session is over: of what
the watcher of the processes notes, what it says aloud, how the session
is doing (see health.py) and which process holds each connection and
each socket that waits for them (see procwatch.py).

Three things differ from the trace of a session that is over. A tool call
is shown when it is issued and its result when that comes, as an event of
its own, the two having the same number, those of a subagent after the
number of the subagent (see Walk). Of a prompt or a reply only the
first line is shown, whoever follows is after what the session does, what
it says is on its own screen. And a connection is shown half a second
after it was made, with what is known of it by then: the process that
made it, what it asked a proxy for, the name its hello gives an address
that was not looked up. What comes later than that is on the line of what
became of it. A tunnel through the egress proxy is logged when it closes,
so the proxy's line shows then, at the time it began.

Some things are only said of a session that runs. A destination no
session of the project was noted to reach before is NEW, by the record
the digest of a session keeps (see digest.py). A connection that is still
open says how much it has carried each time that is 16 MB more, no more
often than every ten seconds. And what the sessions did on the network
since it was last asked is summed, for a chat to say after each turn (see
Traffic).

Of what the latest transcript held before the following began, the last
few events are shown, and no more than its end is read for them (see
TranscriptTail.latest): a transcript is the session's to make as long as
the disk.

What is said in transcript.py of whom to trust holds here too: the transcript is
the session's own word, the capture and the proxy's log are the launcher's."""

from __future__ import annotations

import contextlib
import dataclasses
import itertools
import math
import os
import sys
import time
from collections.abc import Callable, Iterator, Sequence
from dataclasses import dataclass, field
from functools import partial
from pathlib import Path
from typing import Self

from ..docker import running_containers
from ..errors import Fatal
from ..events import Event, Kind, Stage, Who, clean, flat, labelled
from ..files import LINE_LIMIT, line_entry, open_plain
from ..projects import (
    MOST_SUBAGENTS,
    project_root,
    subagent_files,
    subagents_unread,
    transcript_files,
)
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
from ..recording.host_health import running_health, said_in
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
from ..recording.records import recorded_sessions
from ..recording.uploads import PAUSE, Upload
from ..settings import Host
from .digest import destination_key, known_destinations
from .entries import read_entries, session_files, title
from .layout import Layout, event_json
from .links import Links
from .net_events import (
    capture_events,
    listener_events,
    name_container,
    name_processes,
    proxy_event,
)
from .noted import NewlyNoted
from .shown import over, reached, size
from .stream import (
    EVERYTHING,
    Filter,
    Timeline,
    ordered,
    record_event,
    wants_record,
)
from .trace_args import USAGE, picked_session, trace_options
from .transcript import Walk, WalkOptions
from .wire import Sent, Wire, answer_event, tunnel_to_model, upload_event

# Seconds between two looks at what is followed
INTERVAL = 1.0
# Every so many of those, a look for what else there is to follow: new
# transcripts, sessions that started or ended
LOOK_EVERY = 3
# The events from before the start that are shown, as tail -f would
HISTORY = 10
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

    def _new_lines(self, most: int | None) -> Iterator[bytes | None]:
        """The lines completed since the last time, none while it is not
        a plain file that can be read (see open_plain). None in the place
        of a line that was too long to hold. No further than the file
        went when it was opened, and than most bytes when there is a
        most: what is written meanwhile does not keep the look going."""
        file = open_plain(self.path)
        if file is None:
            return
        with file:
            size = os.fstat(file.fileno()).st_size
            if size < self._offset:
                # Written anew and shorter: from where it ends now
                self._offset, self._partial, self._dropping = size, b"", False
            end = size if most is None else min(size, self._offset + most)
            self._behind = self._behind + 1 if end < size else 0
            file.seek(self._offset)
            while self._offset < end:
                data = file.read(min(READ_SIZE, end - self._offset))
                if not data:
                    return
                self._offset += len(data)
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
        upto = self._settled()
        events = capture_events(
            self.capture, self._verbose, self._shown, upto, self.links
        )
        self._shown, self._read = upto, self.capture.marks()
        self._say_new(events)
        return [
            *events,
            *self._uploads_over(),
            *self._answers_over(),
            *self._still_open(),
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

    def _uploads_over(self) -> list[Event]:
        """The uploads that are over since the last time, to the model's
        API and to anywhere else, those long enough to be worth a line,
        each as an event: one is over once nothing was sent on its
        connection for longer than the pause that ends it, by the clock
        of this side. Each when it is, see NewlyOver: one that goes on,
        a long push or a connection that is sent a little to all the
        time, does not keep the others from showing."""
        events = []
        seen = self.seen
        quiet = time.time() - UPLOAD_OVER
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

    def _answers_over(self) -> list[Event]:
        """The answers of the model's API that are over since the last
        time, each as an event: one is over once another began on its
        connection, or nothing came on it for longer than the pause that
        ends one, by the clock of this side."""
        answers = self.capture.answers
        quiet = time.time() - ANSWER_OVER
        over = self._answers_told.of(
            answers.all,
            lambda answer: answers.superseded(answer) or answer.ended < quiet,
        )
        return [answer_event(self.capture, answer, self.links) for answer in over]

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


@dataclass
class Round:
    """What one look at everything gave: lines to say, and events with the
    transcript each is from, none for one of the network."""

    notes: list[str] = field(default_factory=list)
    events: list[tuple[Path | None, Event]] = field(default_factory=list)


class Follower:
    """Follows the sessions of a project, or just the one of a transcript
    when only names it, and gives of what they do the events chosen. With
    container, of the network and the doors only what the session in the
    container of that name does, as a chat wants of its own. With steps,
    what each step of the model used is told without verbose too. Without
    lines, the events are for their values alone, see WalkOptions."""

    def __init__(
        self,
        host: Host,
        verbose: bool,
        only: Path | None = None,
        chosen: Filter = EVERYTHING,
        container: str | None = None,
        steps: bool = False,
        lines: bool = True,
    ):
        self._host = host
        self._verbose = verbose
        # How the transcripts are walked. With events left out a result
        # may come without its call, so it names it.
        self._walked = WalkOptions(
            verbose, live=True, name_results=bool(chosen), steps=steps, lines=lines
        )
        self._only = only
        self._chosen = chosen
        # The one session whose network and doors are followed, by the
        # name of its container, when not all of the project's are
        self._container = container
        self._tails: dict[Path, TranscriptTail] = {}
        # The transcript of each subagent that is followed, with that of
        # the session it is of
        self._subagents: dict[Path, tuple[Path, TranscriptTail]] = {}
        # How long each transcript without a tail was when last looked at,
        # and each of the subagents of one when the following began
        self._sizes: dict[Path, int] = {}
        self._subagent_sizes: dict[Path, int] = {}
        # The sessions said to have more subagents than are followed
        self._unfollowed: set[Path] = set()
        self._captures: dict[tuple[str, float], CaptureTail] = {}
        self._health: dict[tuple[str, float], HealthTail] = {}
        # What the watcher of each session says aloud
        self._watchers: dict[tuple[str, float], WatcherTail] = {}
        # The destinations the project was noted to reach before, for
        # those that are new to be said: as they were when the capture
        # of a session was last begun to be followed, a session notes
        # its own when it ends
        self._known: frozenset[str] | None = None
        # The requests the egress filter refused since it was last
        # asked, see traffic
        self._denied = 0
        self._proxy = ProxyTail()
        # Of the project's filtered sessions that are running, with the
        # name of the container each is of
        self._addresses: dict[str, str] = {}
        self._docker = True
        self._timeline = Timeline()
        self._rounds = 0
        # What the launchers note of the sessions, shown from now: how
        # the sandbox of one was started, the uses of the SSH agent and
        # the Docker socket, and what a chat found changed in what Claude
        # Code says
        self._noted = NewlyNoted(host, container)
        # What the connections of the captures are numbered by, all of
        # them by one count, and the subagents that are followed, each
        # when it first does something: a number is used once in what
        # is shown, see links.py and Walk
        self._numbers = itertools.count(1)
        self._agents = itertools.count(1)

    def title(self, path: Path) -> str:
        return self._tails[path].title

    def follow_only(self, path: Path) -> None:
        """Follow the session of another transcript from here on, and no
        longer the one before: a session that is cleared goes on in a new
        transcript."""
        if path != self._only:
            self._only = path
            self._tails.clear()
            self._subagents.clear()
            # The calls of the one before are not running in this one
            self._timeline.let_go()
            self._tail(path)

    def _ours(self, session: str) -> bool:
        return self._container in (None, session)

    def poll(self) -> Round:
        found = Round()
        if self._rounds % LOOK_EVERY == 0:
            self._look_for_transcripts(found)
            self._look_for_subagents(found)
            self._look_for_sessions(found)
        # At first all that the end of the latest transcript holds, for
        # the events before now (see TranscriptTail.latest): later no
        # more of any than a look is to take
        most = None if self._rounds == 0 else MOST_POLLED
        for tail in self._tails.values():
            found.events += [(tail.path, event) for event in tail.poll(most)]
            self._note_behind(tail, found)
        for session, tail in self._subagents.values():
            found.events += [(session, event) for event in tail.poll(most)]
            self._note_behind(tail, found)
        self._poll_network(found)
        self._poll_notes(found)
        found.events = ordered(
            found.events, lambda shown: shown[1], self._timeline, self._chosen
        )
        if self._rounds == 0:
            self._keep_latest(found)
        self._rounds += 1
        return found

    @staticmethod
    def _note_behind(tail: TranscriptTail, found: Round) -> None:
        """Say that a transcript is written faster than it is read, when
        a look first leaves some of it unread."""
        if tail.newly_behind():
            late = (
                f"{flat(tail.path.name)} is written faster than it is read,"
                " what is shown of it is LATE"
            )
            found.notes.append(labelled("transcript", late))

    def _tail(self, path: Path, offset: int | None = None) -> None:
        """Start to follow a transcript from a place in it, without one
        from where its latest events are, see TranscriptTail.latest."""
        project_dir = project_root(path, self._host)
        if offset is None:
            tail = TranscriptTail.latest(path, project_dir, self._walked)
        else:
            tail = TranscriptTail(path, project_dir, self._walked, offset)
        self._tails[path] = tail
        self._sizes.pop(path, None)

    def _look_for_transcripts(self, found: Round) -> None:
        """Start to follow the transcripts that were written to. At first
        the latest one from where its latest events are, for those
        before now, the others from where they end."""
        if self._only:
            if not self._tails:
                self._tail(self._only)
            return
        first = self._rounds == 0
        sizes = {}
        for path in transcript_files(self._host):
            try:
                sizes[path] = path.stat()
            except OSError:
                continue
        if first and sizes:
            self._tail(max(sizes, key=lambda path: sizes[path].st_mtime))
        elif first:
            found.notes.append("no session of this project yet, waiting for one")
        for path, about in sizes.items():
            size = about.st_size
            if path in self._tails:
                continue
            if first:
                self._sizes[path] = size
                self._note_subagents(path)
            elif size != self._sizes.get(path, 0):
                # Grown, or new and so read from its start
                self._tail(path, self._sizes.get(path, 0))

    def _look_for_subagents(self, found: Round) -> None:
        """Start to follow what the subagents of the followed sessions
        do. Claude Code keeps a transcript of each next to that of its
        session, in SESSION/subagents. At first from where they end, as
        of a session that is not the latest. Later from where they ended
        when the following began, as their session is, see
        _note_subagents: what a subagent did before that is not shown as
        done now. One that is new is read from its start. A session with
        more of them than are followed is said to have them, once."""
        for session in list(self._tails):
            theirs = subagent_files(session)
            # Only one that has as many as are given can have more
            if len(theirs) >= MOST_SUBAGENTS and session not in self._unfollowed:
                self._note_unfollowed(session, found)
            for path in theirs:
                if path in self._subagents:
                    continue
                try:
                    size = path.lstat().st_size
                except OSError:
                    continue
                noted = self._subagent_sizes.pop(path, 0)
                # A result always names its call: the calls of a subagent
                # are numbered on their own, after the number it is given
                tail = TranscriptTail(
                    path,
                    project_root(session, self._host),
                    dataclasses.replace(self._walked, name_results=True),
                    size if self._rounds == 0 else min(noted, size),
                    self._agents,
                )
                self._subagents[path] = (session, tail)

    def _note_unfollowed(self, session: Path, found: Round) -> None:
        """Say that a session has more transcripts of subagents than are
        followed, when it has: what those subagents do is in no line."""
        unread = subagents_unread(session)
        if not unread:
            return
        self._unfollowed.add(session)
        said = (
            f"NOT ALL FOLLOWED: {unread} transcripts of {flat(session.stem)}"
            f" past the first {MOST_SUBAGENTS}, what those subagents do is not"
            " shown"
        )
        found.notes.append(labelled("subagents", said))

    def _note_subagents(self, session: Path) -> None:
        """Note how long the transcripts of the subagents of a session
        are, one that is not followed yet."""
        for path in subagent_files(session):
            with contextlib.suppress(OSError):
                self._subagent_sizes[path] = path.lstat().st_size

    def _look_for_sessions(self, found: Round) -> None:
        """Start to follow the captures and the watchers of the project's
        sessions that started, let go of those that ended, and note the
        addresses of its filtered sessions that run."""
        if not self._docker:
            return
        try:
            running = [
                (sidecar, started)
                for sidecar, started in CaptureSidecar.running(self._host.project_dir)
                if self._ours(CaptureSidecar.session_of(sidecar))
            ]
            self._addresses = self._filtered_addresses()
            watched = self._health_sources()
        except Fatal:
            self._docker = False
            found.notes.append(
                labelled("network", "not followed, docker was not found")
            )
            return
        for sidecar, started in running:
            if (sidecar, started) not in self._captures:
                self._known = known_destinations(self._host)
                tail = CaptureTail(
                    sidecar, self._verbose, self._known, numbers=self._numbers
                )
                self._captures[(sidecar, started)] = tail
                # No call from before it was started runs in it
                self._timeline.began(tail.session, started)
                name = clean(tail.session)
                found.notes.append(
                    labelled("network", f"following the capture of {name}")
                )
        for key in set(self._captures) - set(running):
            name = clean(self._captures.pop(key).session)
            found.notes.append(labelled("network", f"the capture of {name} ended"))
        # Which of them are behind the egress filter is known once their
        # session is up, which is after its capture is
        filtered = set(self._addresses.values())
        for tail in self._captures.values():
            tail.filtered = tail.filtered or tail.session in filtered
        # How each is doing, without a word on the following of it,
        # unless what said so is gone and the session is not
        gone = [self._health.pop(key) for key in set(self._health) - set(watched)]
        left = running_containers() if gone else set()
        for health in gone:
            if health.session in left:
                found.notes.append(
                    labelled(
                        "processes",
                        f"the record of {clean(health.session)} is INCOMPLETE,"
                        " its watcher ended before the session did",
                    )
                )
        for key, (session, said) in watched.items():
            if key not in self._health:
                self._health[key] = HealthTail(session, said)
        if self._rounds == 0 and not running and not self._addresses:
            found.notes.append(
                labelled(
                    "network",
                    "no session of this project is recorded now"
                    " (none runs, CLAUDE_AIRLOCK_NET_LOG=0, or not sandboxed)",
                )
            )

    def _health_sources(self) -> dict[tuple[str, float], tuple[str, SaidSince]]:
        """The source of health readings for each running session of the
        project: its watcher sidecar, or the record its launcher writes
        when there is no watcher (see host_health.py). Each key is the
        watcher's name or the record's path, with the start time. Each
        value is the session's name and the function that reads it."""
        sources: dict[tuple[str, float], tuple[str, SaidSince]] = {}
        running = {
            (watcher, started)
            for watcher, started in Watcher.running(self._host.project_dir)
            if self._ours(Watcher.session_of(watcher))
        }
        for gone in set(self._watchers) - running:
            del self._watchers[gone]
        for key in running:
            tail = self._watchers.setdefault(key, WatcherTail(key[0]))
            sources[key] = (tail.session, tail.health_since)
        for record, session, started in running_health(self._host):
            sources[(record, started)] = (session, partial(said_in, record))
        return {key: asked for key, asked in sources.items() if self._ours(asked[0])}

    def _filtered_addresses(self) -> dict[str, str]:
        """The addresses of the project's filtered sessions that are
        running, the proxy's log tells its requests apart by them, each
        with the name of its session's container."""
        now = time.time()
        recorded = [
            session for session in recorded_sessions(self._host, now, now) if session.ip
        ]
        if not recorded:
            return {}
        # A filtered session has the address of its sidecar when it is
        # captured, either way it runs while a container of its name does
        running = running_containers()
        filtered = [
            session
            for session in recorded
            if session.name in running and self._ours(session.name)
        ]
        for session in filtered:
            # As of a captured one: no call from before it runs in it
            self._timeline.began(session.name, session.start)
        return {session.ip: session.name for session in filtered}

    def _several(self) -> bool:
        """Whether more than one of the project's sessions is followed on
        the network, so that each line has to say which it is of."""
        names = {capture.session for capture in self._captures.values()}
        names.update(health.session for health in self._health.values())
        return len(names.union(self._addresses.values())) > 1

    def _poll_network(self, found: Round) -> None:
        if not self._docker:
            return
        several = self._several()
        # What the watchers said first: which process made a connection
        # is said with the connection
        records: dict[str, ProcessRecord] = {}
        for watcher in self._watchers.values():
            events = watcher.poll()
            records[watcher.session] = watcher.record
            name_container(events, watcher.session, several)
            found.events += [(None, event) for event in events]
            if watcher.newly_hushed():
                found.notes.append(
                    labelled(
                        "processes",
                        "which process makes a connection is no longer said as"
                        f" {clean(watcher.session)} runs, its watcher said as much"
                        " as it says aloud: --trace has it once the session is over",
                    )
                )
        for capture in self._captures.values():
            events = capture.poll()
            if capture.session in records:
                name_processes(events, records[capture.session])
            name_container(events, capture.session, several)
            found.events += [(None, event) for event in events]
            dead = capture.newly_died()
            if dead:
                found.notes.append(
                    labelled(
                        "network",
                        f"the capture of {clean(capture.session)} is INCOMPLETE,"
                        f" a recorder ended before the session did: {flat(dead)}",
                    )
                )
            if capture.newly_cut_short():
                name = clean(capture.session)
                found.notes.append(
                    labelled(
                        "network",
                        f"the capture of {name} STOPPED at its packet limit,"
                        " what comes later is missing",
                    )
                )
        if self._addresses:
            requests = self._proxy.poll(self._addresses, several)
            self._denied += sum(bool(event.fields["denied"]) for event in requests)
            found.events += [(None, event) for event in requests]
        for health in self._health.values():
            events = health.poll()
            name_container(events, health.session, several)
            found.events += [(None, event) for event in events]
            silent = health.newly_silent()
            if silent is not None:
                found.notes.append(
                    labelled(
                        "processes",
                        f"the record of {clean(health.session)} is INCOMPLETE,"
                        f" its watcher said nothing for {silent:.0f}s",
                    )
                )

    def _poll_notes(self, found: Round) -> None:
        """What the launchers of the project's sessions noted since the
        last time: the starts, the uses of the doors, the changes chats
        found and the requests to the model, each of those with where
        the capture of its session saw it go."""
        noted = self._noted.poll()
        captures = {tail.session: tail for tail in self._captures.values()}
        for event in noted:
            tail = captures.get(str(event.fields.get("container")))
            if event.kind is Kind.REQUEST and tail:
                tail.wire.place(event, tail.seen)
        found.events += [(None, event) for event in noted]

    def traffic(self) -> Traffic:
        """What the followed sessions did on the network since this was
        last asked, as far as their captures and the egress proxy's log
        were read by now."""
        summed = Traffic(denied=self._denied)
        self._denied = 0
        for capture in self._captures.values():
            summed += capture.traffic()
        return summed

    def _keep_latest(self, found: Round) -> None:
        """Of what happened before the following began, the last few.
        Said too when not all of a transcript was looked at for them."""
        earlier = len(found.events) - HISTORY
        said = []
        if earlier > 0:
            del found.events[:earlier]
            said.append(f"{earlier} earlier events")
        if any(tail.cut for tail in self._tails.values()):
            size = f"{MOST_HISTORY >> 20} MB"
            said.append(f"what the transcript holds before its last {size}")
        if said:
            found.notes.append(f"{' and '.join(said)}, see claude-airlock --trace")


class Output:
    """Writes what is found, as the lines of --trace or as JSON Lines."""

    def __init__(self, follower: Follower, layout: Layout | None):
        self._follower = follower
        # None for JSON Lines
        self._layout = layout
        # The transcript of the event written last
        self._session: Path | None = None
        self._chosen = EVERYTHING

    def start(self, project_dir: str, chosen: Filter) -> None:
        self._chosen = chosen
        if self._layout:
            about = labelled("following", f"{flat(project_dir)}, until interrupted")
            self._say([about, *chosen.header(), self._layout.columns])

    def write(self, found: Round) -> None:
        self._say(found.notes)
        lines: list[str] = []
        # The events since the last line about their session
        together: list[Event] = []
        for path, event in found.events:
            if path and path != self._session:
                # Those of the session before, while it is still the one
                lines += self._shown(together)
                together = []
                self._session = path
                about = labelled(
                    "session", f"{flat(path.stem)}  {self._follower.title(path)}"
                )
                lines += self._layout.header([about]) if self._layout else []
            together.append(event)
        self._put(lines + self._shown(together))

    def _shown(self, events: list[Event]) -> list[str]:
        if self._layout:
            return [*self._layout.events(events)]
        # An event of the network is put with the session that wrote
        # last, as good a guess as the trace makes
        session = self._session.stem if self._session else ""
        return [event_json(session, event) for event in events]

    def _say(self, notes: list[str]) -> None:
        """Lines about the following itself and about the records it
        reads, in JSON Lines as an event of their own: among them is
        what says that a record is LATE, INCOMPLETE or STOPPED."""
        if self._layout:
            self._put(self._layout.header(notes))
        elif notes and wants_record(self._chosen):
            session = self._session.stem if self._session else ""
            self._put([event_json(session, record_event(time.time(), notes))])

    @staticmethod
    def _put(lines: Sequence[str]) -> None:
        if lines:
            sys.stdout.write("\n".join(lines) + "\n")
            sys.stdout.flush()


def follow(host: Host, args: list[str]) -> int:
    """Show what the sessions of this project do, as they do it and until
    interrupted. With the start of a session id only that session, with
    --json as JSON Lines, with --only and --failed the events they
    choose."""
    options, names, chosen = trace_options(args, ("--follow", "--verbose", "--json"))
    if names == ["list"]:
        raise Fatal(USAGE)
    as_json = "--json" in options
    only = picked_session(session_files(host), names[0]) if names else None
    verbose = as_json or "--verbose" in options
    follower = Follower(host, verbose, only, chosen, lines=not as_json)
    output = Output(follower, None if as_json else Layout.for_output(os.environ))
    try:
        output.start(host.project_dir, chosen)
        while True:
            output.write(follower.poll())
            time.sleep(INTERVAL)
    except KeyboardInterrupt:
        # How following ends, or with the reader leaving, see cli.py
        return 0
