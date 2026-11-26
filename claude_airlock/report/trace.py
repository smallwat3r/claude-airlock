"""Reviewing what a session did: what it ran, where and why, what it wrote
and what it reached on the network, in the order it happened.

From the transcript Claude Code keeps of each session in ~/.claude/projects
(every prompt, reply, tool call and result), and from what the launcher
kept of the session's network use (see records.py, network.py and
capture.py). The reading of the transcript is in transcript.py and the
network's side of a trace in net_events.py, this is the two put together
and how it is shown.

The output is plain text, one event per line or lines. In a file or a pipe
each line starts with when, who and what, so any line grep finds says it
all. On a terminal an event says so once, on its first line, see Layout.
The header lines start with a #. With --json it is JSON Lines instead, an
object per event, for jq or a database.

The transcript is written from inside the sandbox, a session could rewrite
its own. The launcher copies it as it is written (see recorder.py), and
what the copy has that the transcript no longer does is shown as removed.
Nothing in a transcript is trusted here: control characters are dropped
before anything is printed. The network record, the record of processes
and that of the SSH agent and Docker socket are the launcher's own."""

from __future__ import annotations

import functools
import os
import pydoc
import sys
import time
from collections.abc import Sequence
from pathlib import Path

from ..errors import Fatal
from ..events import Event, Kind, Wrong, flat, labelled
from ..projects import (
    MOST_SUBAGENTS,
    project_root,
    subagent_files,
    subagents_unread,
)
from ..recording.recorder import (
    Compared,
    compare,
    last_written,
    removed_subagents,
    removed_transcripts,
)
from ..recording.started import start_summary
from ..settings import Host
from .api_events import place_calls
from .entries import (
    NOT_ALL_HELD,
    NOT_ALL_READ,
    entry_times,
    prompts,
    read_entries,
    session_files,
    short_id,
    step_of,
    title,
    tool_calls,
    unreadable_lines,
)
from .layout import Layout, event_json
from .net_events import network
from .noted import noted_events
from .planted import INJECTION, read_said
from .recorded import ReadTranscript, Recorded
from .stream import (
    EVERYTHING,
    Filter,
    Timeline,
    ordered,
    record_event,
    wants_record,
)
from .summary import planted_shown, summary
from .trace_args import picked_session, trace_options
from .transcript import WalkOptions, left_events, taken_out_events
from .unseen import mark_unseen, unseen_summary

# What an event of what was taken out of a transcript says of itself
REMOVED = "REMOVED FROM THE TRANSCRIPT"


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


def _traced_files(host: Host) -> list[Path]:
    """The transcripts a trace can be of, the latest session first: the
    project's, and those the launcher has a copy of that are no longer
    there, each by where it was. A session that removed its transcript is
    then still the session it was, with what the launcher copied of it."""
    removed = removed_transcripts(host)
    try:
        files = session_files(host)
    except Fatal:
        if not removed:
            raise
        files = []

    return sorted(
        [*files, *removed], key=functools.partial(last_written, host), reverse=True
    )


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
    project_dir: str,
    planted: int | None = None,
    unread: int = 0,
    taken: Sequence[Event] = (),
) -> list[str]:
    """The lines of the header that the transcripts of a session and of
    its subagents give: which session it is, how far they are to be
    believed, and what to know of it before reading on. planted is how
    many of what they read show signs of being written to instruct the
    session, as their events tell (see planted_shown), unread how many
    transcripts of subagents there are past those given, and taken the
    events of what was taken out of those that are still there."""
    theirs = [entry for of_one in subagents for entry in of_one.known]
    unreadable = own.unreadable + sum(
        unreadable_lines(of_one.known) for of_one in subagents
    )
    cannot_be_read = labelled(
        "transcript",
        f"{unreadable} lines CANNOT BE READ, shown as UNREADABLE:"
        " what was done there is not told",
    )
    return [
        labelled("session", f"{flat(own.path.stem)}  {title(own.known)}"),
        *own.compared.header(),
        *_subagents_header([of_one.compared for of_one in subagents]),
        *_unread_header(unread),
        *_taken_out_header(taken),
        *([cannot_be_read] if unreadable else []),
        *summary(own.known + theirs, project_dir, planted),
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
    among them may then be in what was not."""
    if unread:
        return None
    steps: set[str] = set()
    for of_one in read:
        for entry in (*of_one.entries, *of_one.compared.gone):
            if entry.get("text") in (NOT_ALL_READ, NOT_ALL_HELD):
                return None
            step = step_of(entry)
            if step:
                steps.add(step)
    return steps


def session_events(
    path: Path,
    host: Host,
    verbose: bool,
    chosen: Filter = EVERYTHING,
    lines: bool = True,
) -> tuple[list[str], list[Event]]:
    """The header lines of a session and its events, those of the
    transcript and of the network record together, in the order they
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
    walked = WalkOptions(verbose, lines=lines)
    sides = [_transcript_side(read, project_dir, walked) for read in (own, *subagents)]
    told = [event for events, _ in sides for event in events]
    # Counted from the events: what was read is looked through once
    planted = planted_shown(event for _, known in sides for event in known)
    # What was taken out of a transcript that is still there comes after
    # what it is known to hold, see _transcript_side
    taken = [event for events, known in sides for event in events[len(known) :]]
    unread = subagents_unread(path)
    if times:
        start, end = min(times), max(times)
        recorded = Recorded.between(host, start, end)
        net_lines, net_events = network(recorded, verbose)
        # The commands the record of the processes has nothing of
        net_lines += unseen_summary(mark_unseen(told, recorded.watched))
        # Over all of the sessions' stay, as the network is, see stay
        noted_rows, noted = noted_events(host, *recorded.stay)
        # Each request to the model next to the steps the transcripts have
        place_calls(noted, path.stem, _steps_told([own, *subagents], unread))
    header = [
        *_session_header(own, subagents, project_dir, planted, unread, taken),
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
    return header, ordered(found, lambda event: event, Timeline(), chosen)


def render(
    path: Path, host: Host, verbose: bool, layout: Layout, chosen: Filter = EVERYTHING
) -> str:
    """The trace as text: the header, then every event that is chosen."""
    header, events = session_events(path, host, verbose, chosen)
    lines = layout.header([*header, "", layout.columns])
    lines += layout.events(events)
    return "\n".join(lines) + "\n"


def render_json(path: Path, host: Host, chosen: Filter = EVERYTHING) -> str:
    """The trace as JSON Lines, an object per event, nothing shortened.
    Every line names its session, so the traces of several can go into one
    file or table. First what the text has above its events, see
    record_event."""
    header, events = session_events(
        path, host, verbose=True, chosen=chosen, lines=False
    )
    when = events[0].when if events else time.time()
    told = [record_event(when, header), *events] if wants_record(chosen) else events
    return "".join(event_json(path.stem, event) + "\n" for event in told)


def session_rows(files: list[Path], host: Host | None = None) -> list[tuple[Path, str]]:
    """Each session with the line that tells of it: when it last did
    something, the start of its id (enough to name it to --trace), its
    size and its title. In the order of that time, the latest first, and
    one that has no time last."""
    rows = []
    for path in files:
        entries = read_entries(path)
        removed = ""
        if not entries and host is not None:
            # No longer there: as the launcher copied it, and said so
            entries = compare(host, path).gone
            removed = "REMOVED  " if entries else ""
        times = entry_times(entries)
        last = max(times) if times else None
        when = f"{last:%Y-%m-%d %H:%M}" if last else ""
        line = (
            f"{when:16}  {short_id(path)}  {len(prompts(entries)):3d} prompts"
            f"  {len(tool_calls(entries)):4d} calls  {removed}{title(entries)}"
        )
        rows.append((last.timestamp() if last else 0.0, path, line))
    # Stable: the files come the last written first
    rows.sort(key=lambda row: row[0], reverse=True)
    return [(path, line) for _, path, line in rows]


def _list_sessions(files: list[Path], host: Host | None = None) -> str:
    """One line per session, see session_rows."""
    return "".join(line + "\n" for _, line in session_rows(files, host))


def _show(text: str, colour: bool = False) -> None:
    """Through the pager on a terminal, as it is when piped."""
    if sys.stdout.isatty():
        if colour and "R" not in os.environ.get("LESS", ""):
            # less shows colours only when told to
            os.environ["LESS"] = (os.environ.get("LESS", "") + " -R").strip()
        pydoc.pager(text)
    else:
        sys.stdout.write(text)


def trace(host: Host, args: list[str]) -> int:
    """Show what a session of this project did: the latest one, or the one
    whose id starts with the given text, as text or with --json as JSON
    Lines, all of it or what --only and --failed choose. "list" lists
    them instead."""
    options, names, chosen = trace_options(args, ("--verbose", "--json"))
    files = _traced_files(host)
    if names == ["list"]:
        _show(_list_sessions(files, host))
        return 0
    path = picked_session(files, names[0]) if names else files[0]
    if "--json" in options:
        _show(render_json(path, host, chosen))
    else:
        layout = Layout.for_output(os.environ)
        _show(render(path, host, "--verbose" in options, layout, chosen), layout.colour)
    return 0
