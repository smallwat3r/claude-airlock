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
from pathlib import Path

from ..errors import Fatal
from ..events import Event, Kind, Wrong, flat, labelled
from ..projects import project_root, subagent_files
from ..recording.recorder import (
    Compared,
    compare,
    last_written,
    removed_subagents,
    removed_transcripts,
)
from ..recording.started import start_summary
from ..settings import Host
from .entries import (
    entry_times,
    prompts,
    read_entries,
    session_files,
    short_id,
    title,
    tool_calls,
    unreadable_lines,
)
from .layout import Layout, event_json
from .net_events import network
from .noted import noted_events
from .recorded import ReadTranscript, Recorded
from .stream import EVERYTHING, Filter, Timeline, ordered
from .summary import planted_shown, summary
from .trace_args import picked_session, trace_options
from .transcript import transcript_events
from .unseen import mark_unseen, unseen_summary


def removed_events(gone: list[dict], project_dir: str, verbose: bool) -> list[Event]:
    """The events of the entries the launcher copied and the transcript
    no longer has, each said to have been removed."""
    events = transcript_events(gone, project_dir, verbose)
    for event in events:
        event.notes.append("REMOVED FROM THE TRANSCRIPT")
        event.fields["removed"] = True
        event.went_wrong(Wrong.THROUGHOUT)
    return events


def traced_files(host: Host) -> list[Path]:
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


def subagents_header(compared: list[Compared]) -> list[str]:
    """The line that says how far the transcripts of a session's
    subagents are to be believed, none for a session without any."""
    if not compared:
        return []
    return functools.reduce(Compared.with_, compared).header(len(compared))


def session_header(
    own: ReadTranscript,
    subagents: list[ReadTranscript],
    project_dir: str,
    planted: int | None = None,
) -> list[str]:
    """The lines of the header that the transcripts of a session and of
    its subagents give: which session it is, how far they are to be
    believed, and what to know of it before reading on. planted is how
    many of what they read show signs of being written to instruct the
    session, as their events tell (see planted_shown)."""
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
        *subagents_header([of_one.compared for of_one in subagents]),
        *([cannot_be_read] if unreadable else []),
        *summary(own.known + theirs, project_dir, planted),
    ]


def transcript_side(
    read: ReadTranscript, project_dir: str, verbose: bool
) -> tuple[list[Event], list[Event]]:
    """The events of a transcript, with those of what was taken out of
    it, and of them those of what it is known to hold (see
    ReadTranscript.known): the ones its header is about."""
    left = transcript_events(read.entries, project_dir, verbose)
    removed = removed_events(read.compared.gone, project_dir, verbose)
    return left + removed, left if read.entries else removed


def session_events(
    path: Path, host: Host, verbose: bool, chosen: Filter = EVERYTHING
) -> tuple[list[str], list[Event]]:
    """The header lines of a session and its events, those of the
    transcript and of the network record together, in the order they
    happened. The header is of the whole session, the events are the
    chosen ones."""
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
    sides = [transcript_side(read, project_dir, verbose) for read in (own, *subagents)]
    told = [event for events, _ in sides for event in events]
    # Counted from the events: what was read is looked through once
    planted = planted_shown(event for _, known in sides for event in known)
    if times:
        start, end = min(times), max(times)
        recorded = Recorded.between(host, start, end)
        net_lines, net_events = network(recorded, verbose)
        # The commands the record of the processes has nothing of
        net_lines += unseen_summary(mark_unseen(told, recorded.watched))
        noted_rows, noted = noted_events(host, start, end)
    header = [
        *session_header(own, subagents, project_dir, planted),
        *(
            labelled("sandbox", start_summary(event))
            for event in noted
            if event.what == Kind.STARTED
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
    file or table."""
    _, events = session_events(path, host, verbose=True, chosen=chosen)
    return "".join(event_json(path.stem, event) + "\n" for event in events)


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


def list_sessions(files: list[Path], host: Host | None = None) -> str:
    """One line per session, see session_rows."""
    return "".join(line + "\n" for _, line in session_rows(files, host))


def show(text: str, colour: bool = False) -> None:
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
    files = traced_files(host)
    if names == ["list"]:
        show(list_sessions(files, host))
        return 0
    path = picked_session(files, names[0]) if names else files[0]
    if "--json" in options:
        show(render_json(path, host, chosen))
    else:
        layout = Layout.for_output(os.environ)
        show(render(path, host, "--verbose" in options, layout, chosen), layout.colour)
    return 0
