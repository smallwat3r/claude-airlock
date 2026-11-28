"""What the sessions of a project did, summed up for --trace stats: what
was asked and called and at what cost, the programs run, the files
written, where the sandboxes reached and what they sent there, what was
flagged, and each session on its own. How it is shown is stats_shown.py's.

What its transcripts give is counted as the header of a session's trace
counts it (see summary.py), each session once. What the launcher recorded
of the sandbox is in the trace of every session that ran at the time, a
transcript does not say which container wrote it (see name_container), so
each event of it is counted once, however many traces it is in.

Names, paths and commands are the sessions' to write, any number of them:
no more names of each kind are kept than MOST_KEPT, past which they are
counted in the totals and as left out."""

from __future__ import annotations

import operator
from collections import Counter
from collections.abc import Callable, Hashable
from dataclasses import astuple, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import NamedTuple
from urllib.parse import urlsplit

from ..events import Event, Kind, Who, Wrong
from .entries import entry_times, prompts, title
from .net_events import (
    made_connection,
    opened_secret,
    proxy_request,
    stands_out,
    taken_connection,
)
from .programs import programs
from .session_trace import SessionTrace
from .summary import (
    Tokens,
    call_outcomes,
    calls_by_tool,
    files_written,
    pages_fetched,
    session_cost,
    tokens_used,
)
from .told import told_from_outside
from .wire import is_upload, to_the_model

# Of each kind of thing counted by its name (a destination, a program, a
# path), how many names are kept
MOST_KEPT = 10_000
# The tool whose calls are commands, counted by the programs they run
COMMAND_TOOL = "Bash"
# Who what the transcripts give is of: the rest is what the launcher
# recorded, in the trace of every session that ran at the time
FROM_TRANSCRIPTS = frozenset({Who.USER, Who.CLAUDE, Who.AGENT})


# What names are put in order by, the highest first: what their counts
# come to, of one key, then of the next
type Rank = Callable[[Counter[str]], tuple[int, ...]]


def by(*keys: str) -> Rank:
    """Names ranked by the counts of those keys, in that order."""
    return lambda counts: tuple(counts[key] for key in keys)


class Tally[Name: Hashable]:
    """Counts by name, each name with counts of its own under keys (how
    often, how often it failed, how many bytes), and their totals. No
    more than MOST_KEPT names: what is added of another is in the totals,
    and counted as left out."""

    def __init__(self) -> None:
        self.counts: dict[Name, Counter[str]] = {}
        self.totals: Counter[str] = Counter()
        self.most_kept = MOST_KEPT
        self.left_out = 0

    def add(self, name: Name, **counts: int) -> None:
        """Add those counts to a name's, a flag as 1."""
        # An empty Counter would keep a flag as it is given
        added = {key: int(count) for key, count in counts.items()}
        self.totals.update(added)
        if name not in self.counts:
            if len(self.counts) >= self.most_kept:
                self.left_out += 1
                return
            self.counts[name] = Counter()
        self.counts[name].update(added)

    def most(self, rank: Rank) -> list[tuple[Name, Counter[str]]]:
        """Every name with its counts, those ranked highest first, then by
        name."""
        by_name = sorted(self.counts.items(), key=lambda item: str(item[0]))
        return sorted(by_name, key=lambda item: rank(item[1]), reverse=True)

    def __len__(self) -> int:
        return len(self.counts)


class Destination(NamedTuple):
    """Where a session reached: by what, which name (the address of one
    that has none) and which port."""

    protocol: str
    name: str
    port: int


class Opened(NamedTuple):
    """A file of secrets a process opened, and what the trace says it is."""

    path: str
    said: str


@dataclass(frozen=True)
class SessionLine:
    """A session on its own: its id, when it last did something, its
    prompts and calls, how many of them failed, what it cost when Claude
    Code says, how much of it was flagged, and its title."""

    session: str
    last: datetime | None
    prompts: int
    calls: int
    failed: int
    cost: float | None
    flagged: int
    title: str


@dataclass(frozen=True)
class Flags:
    """What was flagged, as the headers of the traces count it: what read
    as written to instruct a session, calls that acted outside the
    sandbox, calls of Claude Code's own tools on files of secrets, files
    written outside the project, and entries taken out of transcripts."""

    injections: int = 0
    outside_sandbox: int = 0
    secrets_calls: int = 0
    outside_project: int = 0
    removed: int = 0

    def __add__(self, other: Flags) -> Flags:
        return Flags(*map(operator.add, astuple(self), astuple(other)))

    def total(self) -> int:
        return sum(astuple(self))


@dataclass
class Network:
    """What the launcher recorded of the sandboxes: each destination with
    the connections to it, the requests through the egress proxy for it
    (a filtered session's way out), how many of those failed or were
    denied and the bytes either way, the connections made to a session,
    the requests to the model and the uploads elsewhere the capture saw,
    the connections and lookups that stand out, the processes seen to
    run, the files of secrets they opened, and the uses of the doors."""

    destinations: Tally[Destination] = field(default_factory=Tally)
    secrets: Tally[Opened] = field(default_factory=Tally)
    inbound: int = 0
    model_requests: int = 0
    uploads: int = 0
    uploaded: int = 0
    stand_out: int = 0
    processes: int = 0
    doors: Counter[str] = field(default_factory=Counter)
    # What tells apart each event counted, see _event_key. As many as the
    # records the launcher keeps hold, which are bounded: one left out
    # would be counted again from the next trace it is in.
    _counted: set[int] = field(default_factory=set)

    def add(self, event: Event) -> None:
        """An event the launcher recorded, the first time it is seen."""
        key = _event_key(event)
        if key in self._counted:
            return
        self._counted.add(key)
        values = event.fields
        self.stand_out += stands_out(event)
        if made_connection(event):
            self.destinations.add(
                _destination(values),
                connections=1,
                failed=event.wrong is not Wrong.NO,
                bytes_out=_count(values.get("bytes_out")),
                bytes_in=_count(values.get("bytes_in")),
            )
        elif proxy_request(event):
            # Over a connection to the proxy, which is counted as one
            self.destinations.add(
                _proxied_to(values),
                requests=1,
                denied=values.get("denied") is True,
                bytes_out=_count(values.get("bytes_out")),
                bytes_in=_count(values.get("bytes")),
            )
        elif taken_connection(event):
            self.inbound += 1
        elif is_upload(event):
            self._add_upload(event)
        elif opened_secret(event):
            self.secrets.add(Opened(str(values.get("path")), str(values.get("said"))))
        elif event.kind is Kind.EXEC:
            self.processes += 1
        elif event.kind in (Kind.SSH_AGENT, Kind.DOCKER):
            self.doors[event.what] += 1

    def _add_upload(self, event: Event) -> None:
        if to_the_model(event):
            self.model_requests += 1
        else:
            self.uploads += 1
            self.uploaded += _count(event.fields.get("bytes_out"))


@dataclass
class Stats:
    """The sums of the sessions added to it (see add): of a project, of
    the sessions last written since a time when one is given."""

    project: str
    since: float | None = None
    sessions: list[SessionLine] = field(default_factory=list)
    first: datetime | None = None
    last: datetime | None = None
    prompts: int = 0
    not_from_you: int = 0
    calls: Counter[str] = field(default_factory=Counter)
    failed: int = 0
    refused: int = 0
    tokens: Tokens = field(default_factory=Tokens)
    cost: float = 0.0
    costed: int = 0
    flags: Flags = field(default_factory=Flags)
    commands: Tally[str] = field(default_factory=Tally)
    files: Tally[str] = field(default_factory=Tally)
    pages: Tally[str] = field(default_factory=Tally)
    network: Network = field(default_factory=Network)

    def add(self, session: str, traced: SessionTrace) -> None:
        """Add the trace of a session: what its transcripts give as its
        header counts it, and what the launcher recorded that was not
        counted yet."""
        entries = traced.entries
        times = entry_times(entries)
        self.first = min([*times, *filter(None, [self.first])], default=None)
        self.last = max([*times, *filter(None, [self.last])], default=None)
        asked = len(prompts(entries))
        self.prompts += asked
        self.not_from_you += told_from_outside(entries).total()
        by_tool = calls_by_tool(entries)
        self.calls.update(by_tool)
        outcomes = call_outcomes(entries)
        self.failed += outcomes.failed
        self.refused += outcomes.refused
        self.tokens += tokens_used(entries)
        cost = session_cost(entries)
        if cost is not None:
            self.cost += cost
            self.costed += 1
        written = files_written(entries, traced.project_dir)
        for path, count in written.counts.items():
            self.files.add(path, writes=count, outside=path in written.outside)
        for host, count in pages_fetched(entries).items():
            self.pages.add(host, fetches=count)
        flags = Flags(
            injections=traced.planted,
            outside_sandbox=traced.flagged.outside,
            secrets_calls=traced.flagged.secrets,
            outside_project=len(written.outside),
            removed=sum(bool(event.fields.get("removed")) for event in traced.events),
        )
        self.flags += flags
        for event in traced.events:
            if event.who in FROM_TRANSCRIPTS:
                self._add_command(event)
            else:
                self.network.add(event)
        self.sessions.append(
            SessionLine(
                session,
                max(times, default=None),
                asked,
                by_tool.total(),
                outcomes.failed,
                cost,
                flags.total(),
                title(entries),
            )
        )

    def _add_command(self, event: Event) -> None:
        """A command, by the programs it runs (see programs.py), of the
        transcript as it is: what was taken out of it is flagged."""
        values = event.fields
        given = values.get("input")
        command = given.get("command") if isinstance(given, dict) else None
        if (
            not event.call
            or values.get("tool") != COMMAND_TOOL
            or values.get("removed")
            or not isinstance(command, str)
        ):
            return
        failed = values.get("failed") is True
        for program in dict.fromkeys(programs(command)):
            self.commands.add(program, calls=1, failed=failed)

    def latest_first(self) -> list[SessionLine]:
        """The sessions, the one that last did something first."""
        return sorted(
            self.sessions,
            key=lambda one: one.last.timestamp() if one.last else 0.0,
            reverse=True,
        )


def session_stats(
    project_dir: str,
    files: list[Path],
    since: float | None,
    traced: Callable[[Path], SessionTrace],
) -> Stats:
    """The stats of the sessions of a project's transcripts, each traced
    by traced, the earliest first: in the order the launcher copied them,
    see copy_rank."""
    stats = Stats(project_dir, since)
    for path in reversed(files):
        stats.add(path.stem, traced(path))
    return stats


def _event_key(event: Event) -> int:
    """What tells an event the launcher recorded from any other, in every
    trace it is in: what it is, when, of which container, from which port
    of it, and its first line, whose number (see links.py) is not. As a
    hash, of which a set holds the most."""
    values = event.fields
    first = event.details[0] if event.details else ""
    return hash(
        (
            event.what,
            event.when,
            str(values.get("container")),
            str(values.get("source_port")),
            first,
        )
    )


def _destination(values: dict) -> Destination:
    """Where a connection went."""
    return Destination(
        str(values.get("protocol")),
        str(values.get("name") or values.get("address")).lower(),
        _count(values.get("port")),
    )


def _proxied_to(values: dict) -> Destination:
    """Where a request to the egress proxy asked to go: the host of its
    URL, or the host it asked to be connected to."""
    url = str(values.get("url"))
    try:
        host = urlsplit(url if "//" in url else f"//{url}").hostname
    except ValueError:
        host = None
    return Destination(
        str(values.get("protocol")), (host or url).lower(), _count(values.get("port"))
    )


def _count(value: object) -> int:
    """A number the records give (bytes, a port), 0 for none."""
    return value if isinstance(value, int) and not isinstance(value, bool) else 0
