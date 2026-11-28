"""Reviewing what a session did: what it ran, where and why, what it wrote
and what it reached on the network, in the order it happened.

From the transcript Claude Code keeps of each session in ~/.claude/projects
(every prompt, reply, tool call and result), and from what the launcher
kept of the session's network use (see records.py, network.py and
capture.py). The reading of the transcript is in transcript.py, the
network's side of a trace in net_events.py and the two put together in
session_trace.py. This is the command, and how what it shows is shown.

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
from collections.abc import Callable, Iterable, Iterator
from pathlib import Path

from ..errors import Fatal
from ..recording.recorder import copy_rank, last_written, removed_transcripts
from ..settings import Host
from .entries import session_files
from .layout import Layout, event_json
from .session_list import session_rows
from .session_trace import session_events, traced_session
from .stats import session_stats
from .stats_shown import stats_json, stats_lines
from .stream import EVERYTHING, Filter, record_event, wants_record
from .trace_args import (
    ALL,
    LIST,
    STATS,
    TraceArgs,
    picked_session,
    trace_options,
)


def _traced_files(host: Host) -> list[Path]:
    """The transcripts a trace can be of, the latest session first (see
    copy_rank): the project's, and those the launcher has a copy of
    that are no longer there, each by where it was. A session that
    removed its transcript is then still the session it was, with what
    the launcher copied of it."""
    removed = removed_transcripts(host)
    try:
        files = session_files(host)
    except Fatal:
        if not removed:
            raise
        files = []

    return sorted(
        [*files, *removed], key=functools.partial(copy_rank, host), reverse=True
    )


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


def _list_sessions(files: list[Path], host: Host, as_json: bool) -> str:
    """One line per session, see SessionRow, or one object."""
    rows = session_rows(files, host)
    return "".join((row.as_json() if as_json else row.line) + "\n" for row in rows)


def _every_trace(
    files: list[Path], host: Host, options: set[str], chosen: Filter
) -> Iterator[str]:
    """The trace of each session of the project, the earliest first: in
    the order the launcher copied them, which a session cannot set, see
    copy_rank. As JSON Lines, each starts with its record and every line
    names its session. As text, a blank line between two, each laid out
    on its own: at a terminal a day is said under its header, whatever
    the day the trace before it ended on."""
    for at, path in enumerate(reversed(files)):
        if "--json" in options:
            yield render_json(path, host, chosen)
            continue
        verbose = "--verbose" in options
        layout = Layout.for_output(os.environ)
        yield ("\n" if at else "") + render(path, host, verbose, layout, chosen)


def _show(text: str, colour: bool = False) -> None:
    """Through the pager on a terminal, as it is when piped."""
    if sys.stdout.isatty():
        if colour and "R" not in os.environ.get("LESS", ""):
            # less shows colours only when told to
            os.environ["LESS"] = (os.environ.get("LESS", "") + " -R").strip()
        pydoc.pager(text)
    else:
        sys.stdout.write(text)


def _show_each(parts: Iterable[str], colour: bool = False) -> None:
    """Through the pager on a terminal, all at once. Piped, each part as
    it is made: the traces of every session together can be more than is
    worth holding."""
    if sys.stdout.isatty():
        _show("".join(parts), colour)
        return
    for part in parts:
        sys.stdout.write(part)


def _show_list(files: list[Path], host: Host, given: TraceArgs) -> None:
    """The sessions, a line each, or with --json an object each."""
    _show(_list_sessions(files, host, "--json" in given.options))


def _show_all(files: list[Path], host: Host, given: TraceArgs) -> None:
    """The trace of every session, see _every_trace."""
    colour = "--json" not in given.options and Layout.for_output(os.environ).colour
    _show_each(_every_trace(files, host, given.options, given.chosen), colour)


def _show_stats(files: list[Path], host: Host, given: TraceArgs) -> None:
    """The sessions summed up (see stats.py), from the trace of each with
    every event: as the lines of a header, with --json as one object."""
    stats = session_stats(
        host.project_dir,
        files,
        given.since,
        lambda path: traced_session(path, host, verbose=True, lines=False),
    )
    if "--json" in given.options:
        _show(stats_json(stats))
        return
    layout = Layout.for_output(os.environ)
    _show("\n".join(layout.header(stats_lines(stats))) + "\n")


# What is shown of the sessions for each name --trace takes in the place
# of one, see trace_args.py
OF_EVERY_SESSION: dict[str, Callable[[list[Path], Host, TraceArgs], None]] = {
    LIST: _show_list,
    ALL: _show_all,
    STATS: _show_stats,
}


def trace(host: Host, args: list[str]) -> int:
    """Show what a session of this project did: the latest one, or the one
    whose id starts with the given text, as text or with --json as JSON
    Lines, all of it or what --only and --failed choose. Or what is shown
    of every session by the name given instead, see OF_EVERY_SESSION,
    with --since of those last written since then."""
    given = trace_options(args, ("--verbose", "--json"))
    files = _traced_files(host)
    if given.since is not None:
        files = [path for path in files if last_written(host, path) >= given.since]
    of_every = OF_EVERY_SESSION.get(given.name or "")
    if of_every is not None:
        of_every(files, host, given)
        return 0
    path = picked_session(files, given.name) if given.name else files[0]
    if "--json" in given.options:
        _show(render_json(path, host, given.chosen))
    else:
        layout = Layout.for_output(os.environ)
        verbose = "--verbose" in given.options
        _show(render(path, host, verbose, layout, given.chosen), layout.colour)
    return 0
