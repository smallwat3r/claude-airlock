"""Watching sessions as they run (--trace --follow): the lines of --trace,
written as things happen and until interrupted.

Four records are read as they grow. The transcripts Claude Code keeps of
the project's sessions, every one that is written to, so a session started,
resumed or cleared while following is picked up, and those of the subagents
of each. The capture of each of the
project's running sessions, read out of its sidecar. For a filtered
session the egress proxy's log. And what the launcher notes of the use of
the SSH agent and the Docker socket (see doors.py). Not the record of the
processes: which process made a connection is told by --trace of a
session that is over. Of what the watcher of the processes notes, only
how the session is doing, which it says aloud (see health.py).

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

import contextlib
import dataclasses
import os
import sys
import time
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from functools import partial
from pathlib import Path

from ..docker import running_containers
from ..errors import Fatal
from ..events import Event, clean, flat, labelled
from ..files import LINE_LIMIT, line_entry, open_plain
from ..projects import project_root, subagent_files, transcript_files
from ..recording.capture import (
    PARTS,
    CaptureSidecar,
    captured_since,
    cut_short,
    died_so_far,
)
from ..recording.egress_log import logged_since
from ..recording.health import Ended, Sample
from ..recording.host_health import running_health, said_in
from ..recording.pcap import Capture, PcapReader, take_frames
from ..recording.processes import Watcher, said_since
from ..recording.records import recorded_sessions
from ..settings import Host
from .entries import read_entries, session_files, title
from .layout import Layout, event_json
from .net_events import capture_events, name_container, proxy_event
from .noted import NewlyNoted
from .stream import EVERYTHING, Filter, Timeline, ordered
from .trace_args import USAGE, picked_session, trace_options
from .transcript import Walk, WalkOptions

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
READ_SIZE = 1 << 20


class TranscriptTail:
    """A transcript read as it grows, from a place in it onward. It is
    the session's to write: a line longer than LINE_LIMIT is dropped, not
    held in memory."""

    def __init__(
        self, path: Path, project_dir: str, options: WalkOptions, offset: int = 0
    ):
        self.path = path
        self._offset = offset
        # The start of a line whose end is not written yet
        self._partial = b""
        # Whether what is read is the rest of a line that was too long
        self._dropping = False
        self._walk = Walk(project_dir, options)
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
            entry = line_entry(line)
            if entry:
                events += self._events(entry)
        return events

    def _new_lines(self) -> Iterator[bytes | None]:
        """The lines completed since the last time, none while it is not
        a plain file that can be read (see open_plain). None in the place
        of a line that was too long to hold."""
        file = open_plain(self.path)
        if file is None:
            return
        with file:
            size = os.fstat(file.fileno()).st_size
            if size < self._offset:
                # Written anew and shorter: from where it ends now
                self._offset, self._partial, self._dropping = size, b"", False
            file.seek(self._offset)
            while True:
                data = file.read(READ_SIZE)
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


class CaptureTail:
    """The capture of a running session, read as it grows."""

    def __init__(self, sidecar: str, verbose: bool):
        self.sidecar = sidecar
        self.session = CaptureSidecar.session_of(sidecar)
        self._verbose = verbose
        # Where each part of the capture has been read to, and its reader
        self._offsets = {part.name: 0 for part in PARTS}
        self._readers = {part.name: PcapReader() for part in PARTS}
        self._capture = Capture()
        self._said_cut_short = False
        # The parts already said to have died, and when that was last asked
        self._said_died = ""
        self._asked_died = 0.0

    def poll(self) -> list[Event]:
        """What the capture has since the last time: the connections that
        opened, what became of the open ones, the plain HTTP requests, and
        with --verbose the lookups. Nothing while it cannot be read: it can
        again later, or its session has ended."""
        past = self._capture.marks()
        for part in PARTS:
            data = captured_since(self.sidecar, self._offsets[part.name], part.file)
            if data:
                self._offsets[part.name] += len(data)
                frames = self._readers[part.name].feed(data)
                take_frames(self._capture, frames, part.name)
        return capture_events(self._capture, self._verbose, past)

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
        if self._said_cut_short or not cut_short(self._capture):
            return False
        self._said_cut_short = True
        return True


# A function that returns a session's health readings later than a time. The
# union is quoted, Python 3.9 cannot evaluate it when the module is loaded
SaidSince = Callable[[float], "list[Sample | Ended]"]


class HealthTail:
    """The health readings of one session, polled at intervals from the
    moment the following began. said_since returns the readings later
    than a given time, see Follower._health_sources."""

    def __init__(self, session: str, said_since: SaidSince) -> None:
        self.session = session
        self._said_since = said_since
        self._since = time.time()
        self._asked = 0.0

    def poll(self) -> list[Event]:
        now = time.monotonic()
        if now - self._asked < HEALTH_EVERY:
            return []
        self._asked = now
        found = self._said_since(self._since)
        if found:
            self._since = max(one.when for one in found)
        return [one.event() for one in found]


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
    what each step of the model used is told without verbose too."""

    def __init__(
        self,
        host: Host,
        verbose: bool,
        only: Path | None = None,
        chosen: Filter = EVERYTHING,
        container: str | None = None,
        steps: bool = False,
    ):
        self._host = host
        self._verbose = verbose
        # How the transcripts are walked. With events left out a result
        # may come without its call, so it names it.
        self._walked = WalkOptions(
            verbose, live=True, name_results=bool(chosen), steps=steps
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
        self._captures: dict[tuple[str, float], CaptureTail] = {}
        self._health: dict[tuple[str, float], HealthTail] = {}
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
            self._timeline = Timeline()
            self._tail(path)

    def _ours(self, session: str) -> bool:
        return self._container in (None, session)

    def poll(self) -> Round:
        found = Round()
        if self._rounds % LOOK_EVERY == 0:
            self._look_for_transcripts(found)
            self._look_for_subagents()
            self._look_for_sessions(found)
        for tail in self._tails.values():
            found.events += [(tail.path, event) for event in tail.poll()]
        for session, tail in self._subagents.values():
            found.events += [(session, event) for event in tail.poll()]
        self._poll_network(found)
        self._poll_notes(found)
        found.events = ordered(
            found.events, lambda shown: shown[1], self._timeline, self._chosen
        )
        if self._rounds == 0:
            self._keep_latest(found)
        self._rounds += 1
        return found

    def _tail(self, path: Path, offset: int = 0) -> None:
        project_dir = project_root(path, self._host)
        self._tails[path] = TranscriptTail(path, project_dir, self._walked, offset)
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
                self._note_subagents(path)
            elif size != self._sizes.get(path, 0):
                # Grown, or new and so read from its start
                self._tail(path, self._sizes.get(path, 0))

    def _look_for_subagents(self) -> None:
        """Start to follow what the subagents of the followed sessions
        do. Claude Code keeps a transcript of each next to that of its
        session, in SESSION/subagents. At first from where they end, as
        of a session that is not the latest. Later from where they ended
        when the following began, as their session is, see
        _note_subagents: what a subagent did before that is not shown as
        done now. One that is new is read from its start."""
        for session in list(self._tails):
            for path in subagent_files(session):
                if path in self._subagents:
                    continue
                try:
                    size = path.lstat().st_size
                except OSError:
                    continue
                noted = self._subagent_sizes.pop(path, 0)
                # A result always names its call: the calls of a subagent
                # are numbered on their own, as those of its session are
                tail = TranscriptTail(
                    path,
                    project_root(session, self._host),
                    dataclasses.replace(self._walked, name_results=True),
                    size if self._rounds == 0 else min(noted, size),
                )
                self._subagents[path] = (session, tail)

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
                tail = CaptureTail(sidecar, self._verbose)
                self._captures[(sidecar, started)] = tail
                name = clean(tail.session)
                found.notes.append(
                    labelled("network", f"following the capture of {name}")
                )
        for key in set(self._captures) - set(running):
            name = clean(self._captures.pop(key).session)
            found.notes.append(labelled("network", f"the capture of {name} ended"))
        # How each is doing, without a word on the following of it
        for key in set(self._health) - set(watched):
            del self._health[key]
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
        for watcher, started in Watcher.running(self._host.project_dir):
            session = Watcher.session_of(watcher)
            sources[(watcher, started)] = (session, partial(said_since, watcher))
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
        return {
            session.ip: session.name
            for session in recorded
            if session.name in running and self._ours(session.name)
        }

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
        for capture in self._captures.values():
            events = capture.poll()
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
            found.events += [(None, event) for event in requests]
        for health in self._health.values():
            events = health.poll()
            name_container(events, health.session, several)
            found.events += [(None, event) for event in events]

    def _poll_notes(self, found: Round) -> None:
        """What the launchers of the project's sessions noted since the
        last time: the starts, the uses of the doors, and the changes
        chats found."""
        found.events += [(None, event) for event in self._noted.poll()]

    @staticmethod
    def _keep_latest(found: Round) -> None:
        """Of what happened before the following began, the last few."""
        earlier = len(found.events) - HISTORY
        if earlier > 0:
            del found.events[:earlier]
            found.notes.append(f"{earlier} earlier events, see claude-airlock --trace")


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
