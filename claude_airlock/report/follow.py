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
each socket that waits for them (see procwatch/tables.py).

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

The transcripts are followed by a TranscriptFollower, the other records
by a NetworkFollower, and a Follower puts what the two give together.

What is said in transcript.py of whom to trust holds here too: the transcript is
the session's own word, the capture and the proxy's log are the launcher's."""

from __future__ import annotations

import contextlib
import dataclasses
import functools
import itertools
import os
import sys
import time
from collections.abc import Sequence
from dataclasses import dataclass, field
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
from ..recording.host_health import running_health
from ..recording.processes import (
    ProcessRecord,
    Watcher,
    aloud_path,
)
from ..recording.recorder import copy_rank
from ..recording.records import read_traced_sessions, recorded_sessions
from ..settings import Host
from .digest import known_destinations
from .entries import session_files
from .layout import Layout, event_json
from .net_events import (
    RepeatedHolders,
    name_container,
    name_processes,
)
from .noted import NewlyNoted
from .session_trace import traced_secrets
from .stream import (
    EVERYTHING,
    Filter,
    Timeline,
    ordered,
    record_event,
    wants_record,
)
from .tails import (
    LAST_OF_HISTORY,
    MOST_POLLED,
    UNSEEN,
    CaptureTail,
    HealthTail,
    ProcessTail,
    ProxyTail,
    RecordTail,
    SaidSince,
    Seen,
    Traffic,
    TranscriptTail,
    WatcherTail,
)
from .trace_args import ALL, LIST, STATS, USAGE, picked_session, trace_options
from .transcript import WalkOptions

# Seconds between two looks at what is followed
INTERVAL = 1.0
# Every so many of those, a look for what else there is to follow: new
# transcripts, sessions that started or ended
LOOK_EVERY = 3
# The events from before the start that are shown, as tail -f would
HISTORY = 10
# Of the transcripts that are written to, how many are followed: those of
# sessions, and those of their subagents, all of them together. A session
# can write any number into the directory Claude Code keeps them in, and
# each that is followed is read at every look.
MOST_FOLLOWED = 100
MOST_FOLLOWED_SUBAGENTS = 1000
# What a line starts with that says some of them are not followed
NOT_ALL_FOLLOWED = "NOT ALL FOLLOWED"
# Seconds a capture whose session ended is waited for to be copied out of
# its sidecar, for a last look at what the sidecar no longer gives: its
# tcpdump is given 10 seconds to stop, then the copy is made
LAST_LOOK_WAIT = 30.0

# A transcript that is followed, with that of the session it is of
type Followed = tuple[Path, TranscriptTail]
# What a running session is followed by on the network: the name of its
# sidecar, of its watcher or of the record of it, and when that started
type Started = tuple[str, float]


@dataclass
class Round:
    """What one look at everything gave: lines to say, and events with the
    transcript each is from, none for one of the network."""

    notes: list[str] = field(default_factory=list)
    events: list[tuple[Path | None, Event]] = field(default_factory=list)


class TranscriptFollower:
    """Follows the transcripts of the sessions of a project, or just the
    one of a transcript when only names it, and those of the subagents of
    each: which are followed and how long the others were when last
    looked at, what each gained since the last look, the turn each has
    in a look, and what is to be said of how they are read (see
    _note_behind and _note_once). Each walked as walked says."""

    def __init__(self, host: Host, walked: WalkOptions, only: Path | None = None):
        self._host = host
        self._walked = walked
        self._only = only
        # The transcript of each session that is followed
        self.tails: dict[Path, TranscriptTail] = {}
        # The transcript of each subagent that is followed, with that of
        # the session it is of
        self._subagents: dict[Path, Followed] = {}
        # How long each transcript without a tail was when last looked at,
        # and each of the subagents of one when the following began
        self._seen: dict[Path, Seen] = {}
        self._subagents_seen: dict[Path, Seen] = {}
        # What was said not to be followed, each once: of a session that
        # has more subagents than are followed, the path of its transcript,
        # and that more transcripts of sessions or of subagents are written
        # to than are followed (see MOST_FOLLOWED), by what they are of
        self._said_unfollowed: set[Path | str] = set()
        # Of the transcripts followed but the first, the one the next look
        # starts with, see _in_turn
        self._turn = 0
        # The subagents that are followed, each numbered when it first
        # does something: a number is used once in what is shown, see Walk
        self._agents = itertools.count(1)

    def title(self, path: Path) -> str:
        return self.tails[path].title

    @property
    def cut(self) -> bool:
        """Whether of a transcript followed, not all that it held when it
        was begun to be followed was looked at, see TranscriptTail.cut."""
        return any(tail.cut for tail in self.tails.values())

    def follow_only(self, path: Path) -> bool:
        """Follow the session of another transcript from here on, and no
        longer the one before: a session that is cleared goes on in a new
        transcript. Whether it is another."""
        if path == self._only:
            return False
        self._only = path
        self.tails.clear()
        self._subagents.clear()
        self._tail(path)
        return True

    def look(self, found: Round, first: bool) -> None:
        """Start to follow the transcripts that were written to, of the
        sessions and of their subagents, the first look at them as first
        says, see _look_for_transcripts and _look_for_subagents."""
        self._look_for_transcripts(found, first)
        self._look_for_subagents(found, first)

    def poll(self, found: Round, first: bool) -> None:
        """What the transcripts followed gained since the last look. At
        the first, all that the end of the latest one holds, for the
        events before now (see TranscriptTail.latest). Later no more of
        all of them together than a look is to take, in turn (see
        _in_turn): a session can write to as many as are followed, and
        one that is left some of is said to be late."""
        most = None if first else MOST_POLLED
        ahead, others, turn = self._in_turn()
        for session, tail in ahead:
            most = self._poll_one(session, tail, most, found)
        # The next look starts with the one after that which had the last
        # of it, unless that was the first: what that one left waits for
        # its turn
        self._turn = turn
        for place, (session, tail) in enumerate(others, 1):
            left = self._poll_one(session, tail, most, found)
            if most and not left:
                self._turn = turn + place
            most = left

    def _poll_one(
        self, session: Path, tail: TranscriptTail, most: int | None, found: Round
    ) -> int | None:
        """What a transcript followed gained since the last look, of no
        more than most bytes, and what is to be said of how it is read,
        see _note_behind. What is left of most for the others, none when
        there is no most."""
        found.events += [(session, event) for event in tail.poll(most)]
        self._note_behind(tail, found)
        return None if most is None else max(most - tail.polled, 0)

    def _in_turn(self) -> tuple[list[Followed], list[Followed], int]:
        """The transcripts followed, each with that of the session it is
        of, in the order a look reads them: first that of the session
        followed alone, or else of the session begun to be followed last.
        Then the others, from the one after that which the look before
        ran out of what it is to take with, so that each has its turn.
        And where that one is among them, in the order they were begun
        to be followed."""
        sessions = list(self.tails.values())
        first = [(tail.path, tail) for tail in sessions[-1:]]
        others = [(tail.path, tail) for tail in sessions[:-1]]
        others += self._subagents.values()
        turn = self._turn % len(others) if others else 0
        return first, others[turn:] + others[:turn], turn

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
            start = f"where {LAST_OF_HISTORY} begin" if tail.cut else "its start"
            anew = (
                f"{flat(tail.path.name)} was WRITTEN ANEW (emptied, cut short or"
                f" replaced): it is read again from {start},"
                " --trace says what was taken out of it"
            )
            found.notes.append(labelled("transcript", anew))
        if tail.newly_unread():
            gone = (
                f"{flat(tail.path.name)} is no longer a file that can be read"
                " (moved, removed, or a link put in its place): what its"
                " session does from here on is NOT SHOWN"
            )
            found.notes.append(labelled("transcript", gone))

    def _tail(self, path: Path, seen: Seen | None = None) -> None:
        """Start to follow a transcript from where it ended when it was
        seen, as the file it was then, without that from where its latest
        events are, see TranscriptTail.latest."""
        project_dir = project_root(path, self._host)
        if seen is None:
            tail = TranscriptTail.latest(path, project_dir, self._walked)
        else:
            tail = TranscriptTail(
                path, project_dir, self._walked, offset=seen.size, file=seen.file
            )
        self.tails[path] = tail
        self._seen.pop(path, None)

    def _look_for_transcripts(self, found: Round, first: bool) -> None:
        """Start to follow the transcripts that were written to. At the
        first look the latest one from where its latest events are, for
        those before now, the others from where they end, see
        _begin_with."""
        if self._only:
            if not self.tails:
                self._tail(self._only)
            return
        there = self._transcripts_there()
        if first:
            self._begin_with(there, found)
            return
        for path, about in there.items():
            seen = self._seen.get(path, UNSEEN)
            if path in self.tails or not seen.changed(Seen.of(about)):
                continue
            if len(self.tails) >= MOST_FOLLOWED:
                said = (
                    f"more than {MOST_FOLLOWED} were written to, what the"
                    " sessions of the others do is not shown"
                )
                self._note_once(found, "transcripts", "transcripts", said)
                continue
            # Grown, or another file put in its place, which is said to be
            # written anew, or new and so read from its start
            self._tail(path, seen)

    def _transcripts_there(self) -> dict[Path, os.stat_result]:
        """The project's transcripts, each as it is now, but those that
        are gone since they were listed."""
        there = {}
        for path in transcript_files(self._host):
            with contextlib.suppress(OSError):
                there[path] = path.stat()
        return there

    def _begin_with(self, there: dict[Path, os.stat_result], found: Round) -> None:
        """At the first look, follow the transcript of the latest session
        (see copy_rank of recorder.py), and note how long each of the
        others is and those of their subagents: each is followed from
        there once it is written to."""
        if not there:
            found.notes.append("no session of this project yet, waiting for one")
            return
        self._tail(max(there, key=functools.partial(copy_rank, self._host)))
        for path, about in there.items():
            if path not in self.tails:
                self._seen[path] = Seen.of(about)
                self._note_subagents(path)

    def _note_once(self, found: Round, key: Path | str, about: str, said: str) -> None:
        """Say that some transcripts are not followed, once for what key
        stands for: what is done in them is in no line."""
        if key not in self._said_unfollowed:
            self._said_unfollowed.add(key)
            found.notes.append(labelled(about, f"{NOT_ALL_FOLLOWED}: {said}"))

    def _look_for_subagents(self, found: Round, first: bool) -> None:
        """Start to follow what the subagents of the followed sessions
        do. Claude Code keeps a transcript of each next to that of its
        session, in SESSION/subagents. At the first look from where they
        end, as of a session that is not the latest. Later from where
        they ended when the following began, as the files they were then,
        as their session is, see _note_subagents: what a subagent did
        before that is not shown as done now. One that is new is read
        from its start. A session with more of them than are followed is
        said to have them, once, and so is that the sessions have more
        than MOST_FOLLOWED_SUBAGENTS."""
        for session in list(self.tails):
            theirs = subagent_files(session)
            # Only one that has as many as are given can have more
            if len(theirs) >= MOST_SUBAGENTS and session not in self._said_unfollowed:
                self._note_unfollowed(session, found)
            for path in theirs:
                if path in self._subagents:
                    continue
                if len(self._subagents) >= MOST_FOLLOWED_SUBAGENTS:
                    said = (
                        f"more than {MOST_FOLLOWED_SUBAGENTS} of the sessions"
                        " followed, what the subagents of the others do is not"
                        " shown"
                    )
                    self._note_once(found, "subagents", "subagents", said)
                    return
                try:
                    about = path.lstat()
                except OSError:
                    continue
                noted = self._subagents_seen.pop(path, UNSEEN)
                seen = Seen.of(about) if first else noted
                # A result always names its call: the calls of a subagent
                # are numbered on their own, after the number it is given
                tail = TranscriptTail(
                    path,
                    project_root(session, self._host),
                    dataclasses.replace(self._walked, name_results=True),
                    offset=seen.size,
                    agents=self._agents,
                    file=seen.file,
                )
                self._subagents[path] = (session, tail)

    def _note_unfollowed(self, session: Path, found: Round) -> None:
        """Say that a session has more transcripts of subagents than are
        followed, when it has: what those subagents do is in no line."""
        unread = subagents_unread(session)
        if not unread:
            return
        said = (
            f"{unread} transcripts of {flat(session.stem)} past the first"
            f" {MOST_SUBAGENTS}, what those subagents do is not shown"
        )
        self._note_once(found, session, "subagents", said)

    def _note_subagents(self, session: Path) -> None:
        """Note how long the transcripts of the subagents of a session
        are, one that is not followed yet."""
        for path in subagent_files(session):
            with contextlib.suppress(OSError):
                self._subagents_seen[path] = Seen.of(path.lstat())


class NetworkFollower:
    """Follows what the running sessions of a project do on the network
    and how they are doing: the capture of each, until a last look at the
    copy its launcher makes once it ended, what its watcher of the
    processes says or the record its launcher keeps of them from outside,
    the egress proxy's log for those that are filtered, and what the
    launchers note of them. With container, only what the session in the
    container of that name does. Where a session starts in timeline, no
    call from before it runs in it."""

    def __init__(
        self,
        host: Host,
        verbose: bool,
        timeline: Timeline,
        container: str | None = None,
    ):
        self._host = host
        self._verbose = verbose
        self._timeline = timeline
        # The one session whose network and doors are followed, by the
        # name of its container, when not all of the project's are
        self._container = container
        # What was said of the process behind each connection, not said
        # again of its later lines unless verbose
        self._holders = RepeatedHolders()
        self._captures: dict[Started, CaptureTail] = {}
        # Those whose session ended, until when the copy of each is waited
        # for, see _last_looks
        self._ending: dict[Started, float] = {}
        self._health: dict[Started, HealthTail] = {}
        # What the watcher of each session says aloud
        self._watchers: dict[Started, WatcherTail] = {}
        # The records the launchers write of the sessions they record from
        # outside, by their path and start time, see host_health.py
        self._records: dict[Started, RecordTail] = {}
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
        # What the launchers note of the sessions, shown from now: how
        # the sandbox of one was started, the uses of the SSH agent and
        # the Docker socket, and what a chat found changed in what Claude
        # Code says
        self._noted = NewlyNoted(host, container)
        # What the connections of the captures are numbered by, all of
        # them by one count: a number is used once in what is shown, see
        # links.py
        self._numbers = itertools.count(1)

    def ours(self, session: str) -> bool:
        """Whether what a session does on the network and with the
        doors is followed, by the name of its container."""
        return self._container in (None, session)

    def look(self, found: Round, first: bool) -> None:
        """Start to follow the captures and the watchers of the project's
        sessions that started, let go of those that ended, and note the
        addresses of its filtered sessions that run. At the first look,
        say so when none is recorded."""
        if not self._docker:
            return
        try:
            listed = CaptureSidecar.running(self._host.project_dir)
            self._addresses = self._filtered_addresses()
            watched = self._health_sources()
        except Fatal:
            self._docker = False
            found.notes.append(
                labelled("network", "not followed, docker was not found")
            )
            return
        running = self._follow_captures(listed, found)
        self._follow_health(watched, found)
        if first and not running and not self._addresses:
            found.notes.append(
                labelled(
                    "network",
                    "no session of this project is recorded now"
                    " (none runs, CLAUDE_AIRLOCK_NET_LOG=0, or not sandboxed)",
                )
            )

    def _follow_captures(
        self, listed: list[Started] | None, found: Round
    ) -> list[Started]:
        """Start to follow the captures of the project's sessions that
        are listed to run, let go of those that ended (see _last_looks),
        and note which are behind the egress filter. Which are running.
        With listed none, Docker did not say: what is followed is kept as
        it is, it is not taken to have ended, to be read again from its
        start."""
        running = (
            [key for key in self._captures if key not in self._ending]
            if listed is None
            else [key for key in listed if self.ours(CaptureSidecar.session_of(key[0]))]
        )
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
        return running

    def _follow_health(
        self, watched: dict[Started, tuple[str, SaidSince]], found: Round
    ) -> None:
        """Start to follow how each of the sessions watched is doing, and
        let go of those no longer watched: without a word on the
        following of it, unless what said so is gone and the session is
        not."""
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

    def _health_sources(self) -> dict[Started, tuple[str, SaidSince]]:
        """The source of health readings for each running session of the
        project: its watcher sidecar, or the record its launcher writes
        when there is no watcher (see host_health.py). Each key is the
        watcher's name or the record's path, with the start time. Each
        value is the session's name and the function that reads it."""
        sources: dict[Started, tuple[str, SaidSince]] = {}
        listed = Watcher.running(self._host.project_dir)
        # As for the captures, see _follow_captures
        running = (
            set(self._watchers)
            if listed is None
            else {
                (watcher, started)
                for watcher, started in listed
                if self.ours(Watcher.session_of(watcher))
            }
        )
        for gone in set(self._watchers) - running:
            del self._watchers[gone]
        for key in running:
            if key not in self._watchers:
                aloud = aloud_path(self._host, key[0])
                self._watchers[key] = WatcherTail(key[0], aloud)
            tail = self._watchers[key]
            sources[key] = (tail.session, tail.health_since)
        written = running_health(self._host)
        kept = {(record, started) for record, _, started in written}
        for gone in set(self._records) - kept:
            del self._records[gone]
        for record, session, started in written:
            read = self._records.setdefault(
                (record, started), RecordTail(record, session)
            )
            sources[(record, started)] = (session, read.health_since)
        return {key: asked for key, asked in sources.items() if self.ours(asked[0])}

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
            if session.name in running and self.ours(session.name)
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

    def poll(self, found: Round) -> None:
        """What the sessions followed did on the network since the last
        look, and how they are doing."""
        if not self._docker:
            return
        several = self._several()
        # What the watchers said first: which process made a connection
        # is said with the connection
        records = self._poll_processes(several, found)
        self._poll_captures(records, several, found)
        if self._addresses:
            requests = self._proxy.poll(self._addresses, several)
            self._denied += sum(bool(event.fields["denied"]) for event in requests)
            found.events += [(None, event) for event in requests]
        self._poll_health(several, found)

    def _poll_processes(self, several: bool, found: Round) -> dict[str, ProcessRecord]:
        """What was said of the processes of the sessions since the last
        look, by their watchers and in the records of those recorded from
        outside, and what each was said to run so far, by its session."""
        records: dict[str, ProcessRecord] = {}
        tails: list[ProcessTail] = [*self._watchers.values(), *self._records.values()]
        for tail in tails:
            events = tail.poll()
            records[tail.session] = tail.record
            name_container(events, tail.session, several)
            found.events += [(None, event) for event in events]
            if tail.newly_hushed():
                found.notes.append(
                    labelled(
                        "processes",
                        "which process makes a connection is no longer said as"
                        f" {clean(tail.session)} runs, its watcher said as much"
                        " as it says aloud: --trace has it once the session is over",
                    )
                )
        return records

    def _poll_captures(
        self, records: dict[str, ProcessRecord], several: bool, found: Round
    ) -> None:
        """What the captures of the running sessions took since the last
        look, each connection with the process its record says made it,
        and that one is INCOMPLETE or STOPPED, once it is found so."""
        for key, capture in self._captures.items():
            if key in self._ending:
                # Stopped, its copy is waited for
                continue
            events = capture.poll()
            brief = not self._verbose
            if capture.session in records:
                name_processes(events, records[capture.session], brief=brief)
            if brief:
                self._holders.drop(capture.session, events)
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

    def _poll_health(self, several: bool, found: Round) -> None:
        """How the sessions are doing, as far as was said since the last
        look, and that the record of one is INCOMPLETE, once nothing was
        said of it for too long (see HealthTail.newly_silent)."""
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

    def poll_notes(self, found: Round) -> None:
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


class Follower:
    """Follows the sessions of a project, or just the one of a transcript
    when only names it, and gives of what they do the events chosen: of
    their transcripts (see TranscriptFollower) and of the network (see
    NetworkFollower), together in the order they happened. With
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
        self._chosen = chosen
        # The calls running, of the transcripts, and when each session
        # began, of the network
        self._timeline = Timeline()
        self._rounds = 0
        # How the transcripts are walked. With events left out a result
        # may come without its call, so it names it. The files of secrets
        # are made once for every transcript followed, those of the
        # project alone: which directories a session has next to it is
        # not known when its transcript is first read.
        walked = WalkOptions(
            verbose,
            live=True,
            name_results=bool(chosen),
            steps=steps,
            lines=lines,
            secrets=traced_secrets(host),
        )
        # What is followed, in two parts that each are read on their own
        self.transcripts = TranscriptFollower(host, walked, only)
        self.network = NetworkFollower(host, verbose, self._timeline, container)

    def title(self, path: Path) -> str:
        return self.transcripts.title(path)

    def follow_only(self, path: Path) -> None:
        """Follow the session of another transcript from here on, and no
        longer the one before, see TranscriptFollower.follow_only."""
        if self.transcripts.follow_only(path):
            # The calls of the one before are not running in this one
            self._timeline.let_go()

    def poll(self) -> Round:
        found = Round()
        first = self._rounds == 0
        if self._rounds % LOOK_EVERY == 0:
            self.transcripts.look(found, first)
            self.network.look(found, first)
        self.transcripts.poll(found, first)
        self.network.poll(found)
        self.network.poll_notes(found)
        found.events = ordered(
            found.events, lambda shown: shown[1], self._timeline, self._chosen
        )
        if first:
            self._keep_latest(found)
        self._rounds += 1
        return found

    def traffic(self) -> Traffic:
        """What the followed sessions did on the network since this was
        last asked, see NetworkFollower.traffic."""
        return self.network.traffic()

    def _keep_latest(self, found: Round) -> None:
        """Of what happened before the following began, the last few.
        Said too when not all of a transcript was looked at for them."""
        earlier = len(found.events) - HISTORY
        said = []
        if earlier > 0:
            del found.events[:earlier]
            said.append(f"{earlier} earlier events")
        if self.transcripts.cut:
            said.append(f"what the transcript holds before {LAST_OF_HISTORY}")
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
    options, name, chosen, _ = trace_options(args, ("--follow", "--verbose", "--json"))
    if name in (LIST, ALL, STATS):
        raise Fatal(USAGE)
    as_json = "--json" in options
    only = picked_session(session_files(host), name) if name else None
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
