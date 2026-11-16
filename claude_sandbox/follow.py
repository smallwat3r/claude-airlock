"""Watching sessions as they run (--trace --follow): the lines of --trace,
written as things happen and until interrupted.

Four records are read as they grow. The transcripts Claude Code keeps of
the project's sessions, every one that is written to, so a session started,
resumed or cleared while following is picked up. The capture of each of the
project's running sessions, read out of its sidecar. For a filtered
session the egress proxy's log. And what the launcher notes of the use of
the SSH agent and the Docker socket (see doors.py). Not the record of the
processes: which process made a connection is told by --trace of a
session that is over.

Three things differ from the trace of a session that is over. A tool call
is shown when it is issued and its result when that comes, as an event of
its own, the two having the same number. Of a prompt or a reply only the first line is shown, whoever
follows is after what the session does, what it says is on its own screen.
And a connection is shown with the name known when it was made: one
that only its TLS hello gives, to an address that was not looked up, comes
too late for the line. A tunnel through the egress proxy is logged when it
closes, so it shows then, at the time it began.

What is said in transcript.py of whom to trust holds here too: the transcript is
the session's own word, the capture and the proxy's log are the launcher's."""

from __future__ import annotations

import os
import sys
import time
from collections.abc import Iterator
from dataclasses import dataclass, field
from pathlib import Path

from .capture import CaptureSidecar, captured_since, cut_short, running_captures
from .docker import running_containers
from .door_events import use_event
from .doors import read_uses
from .egress_log import logged_since
from .events import Event, clean, flat
from .files import json_object, open_plain
from .pcap import Capture, PcapReader, take_frames
from .projects import project_root, transcript_files
from .records import recorded_sessions
from .settings import Fatal, Host
from .trace import (
    EVERYTHING,
    USAGE,
    Filter,
    Layout,
    Timeline,
    capture_events,
    event_json,
    picked_session,
    proxy_event,
    trace_options,
)
from .transcript import (
    Walk,
    read_entries,
    session_files,
    title,
)

# Seconds between two looks at what is followed
INTERVAL = 1.0
# Every so many of those, a look for what else there is to follow: new
# transcripts, sessions that started or ended
LOOK_EVERY = 3
# The events from before the start that are shown, as tail -f would
HISTORY = 10
READ_SIZE = 1 << 20
# A transcript is the session's to write: a line longer than this is
# dropped, not held in memory
LINE_LIMIT = 32 * READ_SIZE


class TranscriptTail:
    """A transcript read as it grows, from a place in it onward."""

    def __init__(
        self,
        path: Path,
        project_dir: str,
        verbose: bool,
        offset: int = 0,
        name_results: bool = False,
    ):
        self.path = path
        self._offset = offset
        # The start of a line whose end is not written yet
        self._partial = b""
        self._dropping = False
        self._walk = Walk(project_dir, verbose, live=True, name_results=name_results)
        self._title: str | None = None

    @property
    def title(self) -> str:
        if self._title is None:
            self._title = title(read_entries(self.path))
        return self._title

    def poll(self) -> list[Event]:
        """The events of what was written since the last time."""
        events: list[Event] = []
        for line in self._new_lines():
            entry = json_object(line)
            if entry:
                events += self._events(entry)
        return events

    def _new_lines(self) -> Iterator[bytes]:
        """The lines completed since the last time, none while it is not
        a plain file that can be read (see open_plain)."""
        file = open_plain(self.path)
        if file is None:
            return
        with file:
            size = os.fstat(file.fileno()).st_size
            if size < self._offset:
                # Written anew and shorter: from where it ends now
                self._offset, self._partial = size, b""
            file.seek(self._offset)
            while True:
                data = file.read(READ_SIZE)
                if not data:
                    return
                self._offset += len(data)
                *lines, self._partial = (self._partial + data).split(b"\n")
                if self._dropping and lines:
                    # The end of the line that was too long
                    del lines[0]
                    self._dropping = False
                if len(self._partial) > LINE_LIMIT:
                    self._partial, self._dropping = b"", True
                yield from lines

    def _events(self, entry: dict) -> list[Event]:
        if entry.get("type") == "ai-title":
            self._title = title([entry])
        return self._walk.take(entry)


class CaptureTail:
    """The capture of a running session, read as it grows."""

    def __init__(self, sidecar: str, verbose: bool):
        self.sidecar = sidecar
        self._verbose = verbose
        self._offset = 0
        self._reader = PcapReader()
        self._capture = Capture()
        self._said_cut_short = False

    def poll(self) -> list[Event]:
        """What the capture has since the last time: the connections that
        opened, what became of the open ones, the plain HTTP requests, and
        with --verbose the lookups. Nothing while it cannot be read: it can
        again later, or its session has ended."""
        data = captured_since(self.sidecar, self._offset)
        if not data:
            return []
        self._offset += len(data)
        past = self._capture.marks()
        take_frames(self._capture, self._reader.feed(data))
        return capture_events(self._capture, self._verbose, past)

    def newly_cut_short(self) -> bool:
        """Whether the capture ran into its packet limit, once."""
        if self._said_cut_short or not cut_short(self._capture):
            return False
        self._said_cut_short = True
        return True


class ProxyTail:
    """The egress proxy's log, read as it grows from where it ended when
    the following began."""

    def __init__(self) -> None:
        self._offset: int | None = None

    def poll(self, addresses: set[str]) -> list[Event]:
        """The requests logged since the last time that came from one of
        the addresses."""
        found = logged_since(self._offset)
        if found is None:
            return []
        self._offset, requests = found
        return [
            proxy_event(request) for request in requests if request.address in addresses
        ]


@dataclass
class Round:
    """What one look at everything gave: lines to say, and events with the
    transcript each is from, none for one of the network."""

    notes: list[str] = field(default_factory=list)
    events: list[tuple[Path | None, Event]] = field(default_factory=list)


class Follower:
    """Follows the sessions of a project, or just the one of a transcript
    when only names it, and gives of what they do the events chosen."""

    def __init__(
        self,
        host: Host,
        verbose: bool,
        only: Path | None = None,
        chosen: Filter = EVERYTHING,
    ):
        self._host = host
        self._verbose = verbose
        self._only = only
        self._chosen = chosen
        self._tails: dict[Path, TranscriptTail] = {}
        # How long each transcript without a tail was when last looked at
        self._sizes: dict[Path, int] = {}
        self._captures: dict[tuple[str, float], CaptureTail] = {}
        self._proxy = ProxyTail()
        # Of the project's filtered sessions that are running
        self._addresses: set[str] = set()
        self._docker = True
        self._timeline = Timeline()
        self._rounds = 0
        # The uses of the SSH agent and the Docker socket are shown from now:
        # the time of the one shown last, and how many of that very time
        # were shown, several can be noted in one moment
        self._doors_since = time.time()
        self._doors_shown = 0

    def title(self, path: Path) -> str:
        return self._tails[path].title

    def poll(self) -> Round:
        found = Round()
        if self._rounds % LOOK_EVERY == 0:
            self._look_for_transcripts(found)
            self._look_for_sessions(found)
        for tail in self._tails.values():
            found.events += [(tail.path, event) for event in tail.poll()]
        self._poll_network(found)
        self._poll_doors(found)
        # Stable, so what a transcript has at the same time keeps its order
        found.events.sort(key=lambda shown: shown[1].when)
        for _, event in found.events:
            self._timeline.take(event)
        found.events = [shown for shown in found.events if self._chosen.wants(shown[1])]
        if self._rounds == 0:
            self._keep_latest(found)
        self._rounds += 1
        return found

    def _tail(self, path: Path, offset: int = 0) -> None:
        project_dir = project_root(path, self._host)
        # With events left out a result may come without its call
        self._tails[path] = TranscriptTail(
            path, project_dir, self._verbose, offset, name_results=bool(self._chosen)
        )
        self._sizes.pop(path, None)

    def _look_for_transcripts(self, found: Round) -> None:
        """Start to follow the transcripts that were written to. At first
        the latest one from its start, for the events before now, the
        others from where they end."""
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
            elif size != self._sizes.get(path, 0):
                # Grown, or new and so read from its start
                self._tail(path, self._sizes.get(path, 0))

    def _look_for_sessions(self, found: Round) -> None:
        """Start to follow the captures of the project's sessions that
        started, let go of those that ended, and note the addresses of its
        filtered sessions that run."""
        if not self._docker:
            return
        try:
            running = running_captures(self._host.project_dir)
            self._addresses = self._filtered_addresses()
        except Fatal:
            self._docker = False
            found.notes.append("network     not followed, docker was not found")
            return
        for sidecar, started in running:
            if (sidecar, started) not in self._captures:
                self._captures[(sidecar, started)] = CaptureTail(sidecar, self._verbose)
                name = clean(CaptureSidecar.session_of(sidecar))
                found.notes.append(f"network     following the capture of {name}")
        for key in set(self._captures) - set(running):
            name = clean(CaptureSidecar.session_of(self._captures.pop(key).sidecar))
            found.notes.append(f"network     the capture of {name} ended")
        if self._rounds == 0 and not running and not self._addresses:
            found.notes.append(
                "network     no session of this project is recorded now"
                " (none runs, CLAUDE_DOCKER_NET_LOG=0, or not sandboxed)"
            )

    def _filtered_addresses(self) -> set[str]:
        """The addresses of the project's filtered sessions that are
        running, the proxy's log tells its requests apart by them."""
        now = time.time()
        recorded = [
            session for session in recorded_sessions(self._host, now, now) if session.ip
        ]
        if not recorded:
            return set()
        # A filtered session has the address of its sidecar when it is
        # captured, either way it runs while a container of its name does
        running = running_containers()
        return {session.ip for session in recorded if session.name in running}

    def _poll_network(self, found: Round) -> None:
        if not self._docker:
            return
        for capture in self._captures.values():
            found.events += [(None, event) for event in capture.poll()]
            if capture.newly_cut_short():
                name = clean(CaptureSidecar.session_of(capture.sidecar))
                found.notes.append(
                    f"network     the capture of {name} STOPPED at its packet"
                    " limit, what comes later is missing"
                )
        if self._addresses:
            requests = self._proxy.poll(self._addresses)
            found.events += [(None, event) for event in requests]

    def _poll_doors(self, found: Round) -> None:
        """The uses of the SSH agent and the Docker socket that the
        launchers of the project's sessions noted since the last time."""
        at_since = 0
        for use in read_uses(self._host, self._doors_since, float("inf")):
            when = float(use["t"])
            if when == self._doors_since:
                at_since += 1
                if at_since <= self._doors_shown:
                    continue
                self._doors_shown = at_since
            elif when > self._doors_since:
                self._doors_since, self._doors_shown, at_since = when, 1, 1
            # One noted out of order is shown, the place is kept
            event = use_event(use)
            if event:
                found.events.append((None, event))

    @staticmethod
    def _keep_latest(found: Round) -> None:
        """Of what happened before the following began, the last few."""
        earlier = len(found.events) - HISTORY
        if earlier > 0:
            del found.events[:earlier]
            found.notes.append(f"{earlier} earlier events, see claude-docker --trace")


class Output:
    """Writes what is found, as the lines of --trace or as JSON Lines."""

    def __init__(self, follower: Follower, layout: Layout | None):
        self._follower = follower
        # None for JSON Lines
        self._layout = layout
        # The transcript of the event written last
        self._session: Path | None = None

    def start(self, project_dir: str, chosen: Filter) -> None:
        if self._layout:
            about = f"following   {flat(project_dir)}, until interrupted"
            self._say([about, *chosen.header(), self._layout.columns])

    def write(self, found: Round) -> None:
        self._say(found.notes)
        lines: list[str] = []
        # The events since the last line about their session
        together: list[Event] = []
        for path, event in found.events:
            if path and path != self._session:
                self._session = path
                lines += self._shown(together)
                together = []
                about = f"session     {flat(path.stem)}  {self._follower.title(path)}"
                lines += self._layout.header([about]) if self._layout else []
            together.append(event)
        self._put(lines + self._shown(together))

    def _shown(self, events: list[Event]) -> list[str]:
        if self._layout:
            return self._layout.events(events)
        # An event of the network is put with the session that wrote
        # last, as good a guess as the trace makes
        session = self._session.stem if self._session else ""
        return [event_json(session, event) for event in events]

    def _say(self, notes: list[str]) -> None:
        """Lines about the following itself, which JSON Lines has no
        place for."""
        if self._layout:
            self._put(self._layout.header(notes))

    @staticmethod
    def _put(lines: list[str]) -> None:
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
    follower = Follower(host, as_json or "--verbose" in options, only, chosen)
    output = Output(follower, None if as_json else Layout.for_output(os.environ))
    try:
        output.start(host.project_dir, chosen)
        while True:
            output.write(follower.poll())
            time.sleep(INTERVAL)
    except KeyboardInterrupt:
        # How following ends, or with the reader leaving, see cli.py
        return 0
