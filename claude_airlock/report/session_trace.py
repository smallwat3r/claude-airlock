"""The trace of a session, as --trace shows it and --trace stats sums it
up: the events of its transcript and of those of its subagents, with
those of what was taken out of them, and what the launcher recorded of
the sandboxes while it ran, in the order they happened, under a header
that says what to know of it before reading on. With what the header was
made of that the events do not hold, for what is made of traces: the
stats of several sessions, see stats.py.

How it is shown is trace.py's, the reading of a transcript is
transcript.py's and the network's side of a trace net_events.py's."""

from __future__ import annotations

import functools
import os
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from ..errors import Fatal
from ..events import Event, Kind, Wrong, flat, labelled
from ..projects import (
    MOST_SUBAGENTS,
    project_root,
    subagent_files,
    subagents_unread,
)
from ..recording.procwatch import Secrets
from ..recording.recorder import Compared, removed_subagents
from ..recording.secrets import session_secrets
from ..recording.started import Start, start_summary
from ..settings import Host, Settings, load_settings
from .api_events import place_calls
from .entries import entry_times, step_of, title
from .net_events import network
from .noted import noted_events
from .planted import INJECTION, read_said
from .recorded import ReadTranscript, Recorded
from .stream import EVERYTHING, Filter, Timeline, ordered
from .summary import (
    Figures,
    Flagged,
    flagged_shown,
    planted_shown,
    session_figures,
    summary,
)
from .transcript import WalkOptions, left_events, taken_out_events
from .unseen import mark_unseen, unseen_summary
from .wire import on_the_wire

# What an event of what was taken out of a transcript says of itself
REMOVED = "REMOVED FROM THE TRANSCRIPT"
# What the header says of the records of a session whose transcripts
# say nowhere when it ran
NO_TIME = (
    "NOT LOOKED AT, nor what was noted of the session: its transcript"
    " says nowhere when it ran"
)
# What follows a directory mounted read-only, as the start of a session
# notes it, see Start.of
READ_ONLY_NOTED = " (ro)"


@dataclass(frozen=True)
class SessionTrace:
    """The trace of a session: its header and its events, with the
    figures of the entries its transcripts are known to hold, those of
    its subagents too (see Figures), its title as its header names it,
    and how many of what it read show signs of being planted and of its
    calls were flagged."""

    header: list[str]
    events: list[Event]
    figures: Figures
    title: str
    planted: int
    flagged: Flagged


def removed_events(
    gone: list[dict], left: list[dict], project_dir: str, options: WalkOptions
) -> list[Event]:
    """The events of the entries the launcher copied and the transcript
    no longer has, each said to have been removed. Read next to what the
    transcript still has, see taken_out_events: a result that was taken
    out or altered while its call was left is one of them."""
    events = taken_out_events(gone, left, project_dir, options)
    for event in events:
        event.notes.append(REMOVED)
        event.fields["removed"] = True
        event.went_wrong(Wrong.THROUGHOUT)
    return events


def _subagents_header(compared: list[Compared]) -> list[str]:
    """The line that says how far the transcripts of a session's
    subagents are to be believed, none for a session without any."""
    if not compared:
        return []
    return functools.reduce(Compared.with_, compared).header(len(compared))


def _unread_header(unread: int) -> list[str]:
    """The line that says a session has more transcripts of subagents
    than are read, by how many (see subagents_unread), none when it has
    not: what those subagents ran is in no line below."""
    if not unread:
        return []
    said = (
        f"NOT ALL READ: {unread} transcripts past the first {MOST_SUBAGENTS},"
        " what those subagents did is not told"
    )
    return [labelled("subagents", said)]


def _taken_out_header(taken: Sequence[Event]) -> list[str]:
    """The line that says what went wrong in what was taken out of
    transcripts that are still there, none when nothing did: the counts
    of the header are of the transcripts as they are now, and a call
    whose failure was taken out of one would read as none there."""
    failed = sum(bool(event.fields.get("failed")) for event in taken)
    planted = sum(bool(event.fields.get(INJECTION)) for event in taken)
    said = [f"{failed} calls FAILED"] if failed else []
    said += [read_said(planted)] if planted else []
    if not said:
        return []
    among = f"among what is shown as REMOVED, {' and '.join(said)}: see --failed"
    return [labelled("transcript", among)]


def _session_header(
    own: ReadTranscript,
    subagents: list[ReadTranscript],
    named: str,
    unread: int = 0,
    taken: Sequence[Event] = (),
) -> list[str]:
    """The lines of the header that say which session it is, by its id
    and as it is named, and how far the transcripts of it and of its
    subagents are to be believed: unread is how many transcripts of
    subagents there are past those given, and taken the events of what
    was taken out of those that are still there. What to know of it
    before reading on comes next, see summary."""
    unreadable = sum(one.unreadable for one in (own, *subagents))
    cannot_be_read = labelled(
        "transcript",
        f"{unreadable} lines CANNOT BE READ, shown as UNREADABLE:"
        " what was done there is not told",
    )
    return [
        labelled("session", f"{flat(own.path.stem)}  {named}"),
        *own.compared.header(),
        *_subagents_header([of_one.compared for of_one in subagents]),
        *_unread_header(unread),
        *_taken_out_header(taken),
        *([cannot_be_read] if unreadable else []),
    ]


def _transcript_side(
    read: ReadTranscript, project_dir: str, options: WalkOptions
) -> tuple[list[Event], list[Event]]:
    """The events of a transcript, with those of what was taken out of
    it, and of them those of what it is known to hold (see
    ReadTranscript.known): the ones its header is about."""
    gone = read.compared.gone
    left = left_events(read.entries, gone, project_dir, options)
    removed = removed_events(gone, read.entries, project_dir, options)
    return left + removed, left if read.entries else removed


def _steps_told(read: Sequence[ReadTranscript], unread: int) -> set[str] | None:
    """The ids of the steps of the model that the transcripts of a
    session and of its subagents tell of, with what was taken out of
    them: what a request to the model is looked for among, see
    place_calls. None when they were not all read, a step that is not
    among them may then be in what was not: as the reading says, not as
    an entry does, which is the session's to write."""
    if unread or not all(of_one.whole for of_one in read):
        return None
    steps: set[str] = set()
    for of_one in read:
        for entry in (*of_one.entries, *of_one.compared.gone):
            step = step_of(entry)
            if step:
                steps.add(step)
    return steps


def traced_secrets(host: Host, mounted: Sequence[str] = ()) -> Secrets:
    """The files of secrets a call of a session that is traced or
    followed is flagged on (see secrets_of): the logins and keys under
    its home, the container's and the host's, and the files of a name
    hidden from it in the project and in the directories mounted next to
    it, each as the host and the session name it (see session_secrets),
    by the names the settings hide now. Made once for a trace, and for what is
    followed, of the settings as they are: settings that cannot be read
    hide no more than the defaults, and the trace is not stopped for
    them."""
    try:
        settings = load_settings(os.environ, os.path.join(host.user_conf, "config"))
    except Fatal:
        settings = Settings()
    return session_secrets(settings, host, [host.project_dir, *mounted])


def _mounted(noted: Sequence[Event]) -> list[str]:
    """The directories mounted next to the project of the sessions whose
    start the launcher noted, each by its path, see Start."""
    return [
        mounted.removesuffix(READ_ONLY_NOTED)
        for event in noted
        if event.kind is Kind.STARTED
        for mounted in Start.from_note(event.fields).dirs
    ]


def session_events(
    path: Path,
    host: Host,
    verbose: bool,
    chosen: Filter = EVERYTHING,
    lines: bool = True,
) -> tuple[list[str], list[Event]]:
    """The header lines of a session and its events, see traced_session."""
    traced = traced_session(path, host, verbose, chosen, lines)
    return traced.header, traced.events


def traced_session(
    path: Path,
    host: Host,
    verbose: bool,
    chosen: Filter = EVERYTHING,
    lines: bool = True,
) -> SessionTrace:
    """The trace of a session: the header lines and the events, those of
    the transcript and of the network record together, in the order they
    happened. The header is of the whole session, the events are the
    chosen ones. Without lines, the events are for their values alone,
    see WalkOptions."""
    own = ReadTranscript.read(host, path)
    project_dir = project_root(path, host)
    # What its subagents did is in a transcript of each, see subagent_files
    of_subagents = [*subagent_files(path), *removed_subagents(host, path)]
    subagents = [ReadTranscript.read(host, file) for file in of_subagents]
    theirs = [entry for of_one in subagents for entry in of_one.known]
    # With what was taken out: when the session ran is not what is left
    # of it. By the earliest and the latest, the order is the session's.
    times = [
        when.timestamp()
        for when in entry_times([*own.entries, *own.compared.gone, *theirs])
    ]
    net_lines: list[str] = []
    net_events: list[Event] = []
    # What the launchers noted of the sessions: how the sandbox of each
    # was started, the uses of the doors, and what a chat found changed
    # in what Claude Code says
    noted_rows: list[tuple[str, str]] = []
    noted: list[Event] = []
    recorded = Recorded.between(host, min(times), max(times)) if times else None
    if recorded is not None:
        # Over all of the sessions' stay, as the network is, see stay.
        # Ahead of the walk, which flags calls on files of secrets in
        # the directories they were started with.
        noted_rows, noted = noted_events(host, *recorded.stay)
    secrets = traced_secrets(host, _mounted(noted))
    walked = WalkOptions(verbose, lines=lines, secrets=secrets)
    sides = [_transcript_side(read, project_dir, walked) for read in (own, *subagents)]
    told = [event for events, _ in sides for event in events]
    # Counted from the events: what was read and called is looked
    # through once
    about = [event for _, known in sides for event in known]
    planted, flagged = planted_shown(about), flagged_shown(about)
    # What was taken out of a transcript that is still there comes after
    # what it is known to hold, see _transcript_side
    taken = [event for events, known in sides for event in events[len(known) :]]
    unread = subagents_unread(path)
    # Worked out once, for the header and for what is made of the trace
    entries = own.known + theirs
    figures = session_figures(entries, project_dir)
    named = title(own.known)
    if recorded is not None:
        net_lines, net_events = network(recorded, verbose)
        # The commands the record of the processes has nothing of
        net_lines += unseen_summary(mark_unseen(told, recorded.watched))
        # Each request to the model next to the steps the transcripts have,
        # and where the capture of its session saw it go
        place_calls(noted, path.stem, _steps_told([own, *subagents], unread))
        wire_rows, wire_events = on_the_wire(noted, recorded)
        noted_rows += wire_rows
        net_events += wire_events
    else:
        # The records are looked through for when the session ran: none
        # was, and a header without a word of them would read as if the
        # session had done nothing there
        net_lines = [labelled("network", NO_TIME)]
    header = [
        *_session_header(own, subagents, named, unread, taken),
        *summary(entries, project_dir, planted, flagged, figures),
        *(
            labelled("sandbox", start_summary(event))
            for event in noted
            if event.kind is Kind.STARTED
        ),
        *net_lines,
        *(labelled(about, said) for about, said in noted_rows),
        *chosen.header(),
    ]
    found = [*told, *net_events, *noted]
    events = ordered(found, lambda event: event, Timeline(), chosen)
    return SessionTrace(header, events, figures, named, planted, flagged)
