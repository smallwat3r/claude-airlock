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
Traffic of tails.py, where each record has the tail that reads it).

Of what the latest transcript held before the following began, the last
few events are shown, and no more than its end is read for them (see
TranscriptTail.latest of tails.py): a transcript is the session's to make as long as
the disk.

What is said in transcript.py of whom to trust holds here too: the transcript is
the session's own word, the capture and the proxy's log are the launcher's."""

from __future__ import annotations

import contextlib
import dataclasses
import itertools
import os
import sys
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
from functools import partial
from pathlib import Path

from ..docker import running_containers
from ..errors import Fatal
from ..events import Event, Kind, clean, flat, labelled
from ..projects import (
    MOST_SUBAGENTS,
    project_root,
    subagent_files,
    subagents_unread,
    transcript_files,
)
from ..recording.capture import (
    CaptureSidecar,
)
from ..recording.host_health import running_health, said_in
from ..recording.processes import (
    ProcessRecord,
    Watcher,
)
from ..recording.records import read_traced_sessions, recorded_sessions
from ..settings import Host
from .digest import known_destinations
from .entries import session_files
from .layout import Layout, event_json
from .net_events import (
    name_container,
    name_processes,
)
from .noted import NewlyNoted
from .stream import (
    EVERYTHING,
    Filter,
    Timeline,
    ordered,
    record_event,
    wants_record,
)
from .tails import (
    MOST_HISTORY,
    MOST_POLLED,
    CaptureTail,
    HealthTail,
    ProxyTail,
    SaidSince,
    Traffic,
    TranscriptTail,
    WatcherTail,
)
from .trace_args import USAGE, picked_session, trace_options
from .transcript import WalkOptions

# Seconds between two looks at what is followed
INTERVAL = 1.0
# Every so many of those, a look for what else there is to follow: new
# transcripts, sessions that started or ended
LOOK_EVERY = 3
# The events from before the start that are shown, as tail -f would
HISTORY = 10
# Seconds a capture whose session ended is waited for to be copied out of
# its sidecar, for a last look at what the sidecar no longer gives: its
# tcpdump is given 10 seconds to stop, then the copy is made
LAST_LOOK_WAIT = 30.0


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
        # Those whose session ended, until when the copy of each is waited
        # for, see _last_looks
        self._ending: dict[tuple[str, float], float] = {}
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
        a look first leaves some of it unread, that one was written anew,
        when it is found so, and that one can no longer be read at all,
        when it first cannot."""
        if tail.newly_behind():
            late = (
                f"{flat(tail.path.name)} is written faster than it is read,"
                " what is shown of it is LATE"
            )
            found.notes.append(labelled("transcript", late))
        if tail.newly_rewritten():
            anew = (
                f"{flat(tail.path.name)} was WRITTEN ANEW (emptied, cut short or"
                " replaced): it is read again from its start, --trace says what"
                " was taken out of it"
            )
            found.notes.append(labelled("transcript", anew))
        if tail.newly_unread():
            gone = (
                f"{flat(tail.path.name)} is no longer a file that can be read"
                " (moved, removed, or a link put in its place): what its"
                " session does from here on is NOT SHOWN"
            )
            found.notes.append(labelled("transcript", gone))

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
            listed = CaptureSidecar.running(self._host.project_dir)
            # Docker did not say: what is followed is kept as it is, it is
            # not taken to have ended, to be read again from its start
            running = (
                [key for key in self._captures if key not in self._ending]
                if listed is None
                else [
                    (sidecar, started)
                    for sidecar, started in listed
                    if self._ours(CaptureSidecar.session_of(sidecar))
                ]
            )
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
        now = time.monotonic()
        for key in running:
            self._ending.pop(key, None)
        for key in set(self._captures) - set(running) - set(self._ending):
            # Its launcher copies it out as the session ends, and notes
            # the copy once it is made
            self._ending[key] = now + LAST_LOOK_WAIT
        self._last_looks(found, now)
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

    def _last_looks(self, found: Round, now: float) -> None:
        """Let go of the captures whose session ended, each once the copy
        its launcher made of it is noted, with a last look at that copy
        for what the sidecar no longer gave (see CaptureTail.last_look),
        or once that was waited for LAST_LOOK_WAIT."""
        if not self._ending:
            return
        noted = {session.capture for session in read_traced_sessions(self._host)}
        for key, until in list(self._ending.items()):
            sidecar, started = key
            copy = f"{sidecar}-{int(started)}.{CaptureSidecar.EXTENSION}"
            if copy not in noted and now < until:
                continue
            del self._ending[key]
            tail = self._captures.pop(key)
            if copy in noted:
                events = tail.last_look(Path(self._host.captures_dir, copy))
                name_container(events, tail.session, self._several())
                found.events += [(None, event) for event in events]
            name = clean(tail.session)
            found.notes.append(labelled("network", f"the capture of {name} ended"))

    def _health_sources(self) -> dict[tuple[str, float], tuple[str, SaidSince]]:
        """The source of health readings for each running session of the
        project: its watcher sidecar, or the record its launcher writes
        when there is no watcher (see host_health.py). Each key is the
        watcher's name or the record's path, with the start time. Each
        value is the session's name and the function that reads it."""
        sources: dict[tuple[str, float], tuple[str, SaidSince]] = {}
        listed = Watcher.running(self._host.project_dir)
        # As for the captures, see _look_for_sessions
        running = (
            set(self._watchers)
            if listed is None
            else {
                (watcher, started)
                for watcher, started in listed
                if self._ours(Watcher.session_of(watcher))
            }
        )
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
        for key, capture in self._captures.items():
            if key in self._ending:
                # Stopped, its copy is waited for
                continue
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
