"""Reviewing what a session did: what it ran, where and why, what it wrote
and what it reached on the network, in the order it happened.

From the transcript Claude Code keeps of each session in ~/.claude/projects
(every prompt, reply, tool call and result), and from what the launcher
kept of the session's network use (see records.py, network.py and
capture.py). The reading of the transcript is in transcript.py, this is
the network's side of a trace, the two put together and how it is shown.

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
import subprocess
import sys
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from .capture import cut_short, session_capture
from .door_events import door_events
from .egress_log import ProxyRequest, logged_requests, requests_made
from .events import Event, Who, clean, flat, labelled
from .files import UNREADABLE
from .layout import Layout, event_json, shown_what, went_wrong
from .pcap import Capture, Connection, Flow, Lookup, Request
from .processes import ProcessRecord, session_record, shown_lineage
from .projects import project_root, subagent_files
from .recorder import (
    Compared,
    compare,
    copied_at,
    removed_subagents,
    removed_transcripts,
)
from .records import NetSession, recorded_sessions
from .settings import Fatal, Host
from .shown import over, reached, size, verdict
from .transcript import (
    call_label,
    entry_times,
    modified,
    prompts,
    read_entries,
    session_files,
    sessions_named,
    summary,
    title,
    tool_calls,
    transcript_events,
)

USAGE = (
    "usage: claude-docker --trace [list | SESSION] [--follow] [--verbose | --json]"
    " [--only KIND,...] [--failed]"
)
# Of the call a connection is said to be made during
DURING_WIDTH = 60
# Seconds for which the timeline remembers a call that has ended, for the
# events of the network that are read later than they happened
TIMELINE_SLACK = 30.0
# Of the command line of a process seen to run
PROCESS_WIDTH = 200


def proxy_summary(
    requests: list[ProxyRequest], sessions: list[NetSession]
) -> list[str]:
    """Each destination with its number of requests and bytes, the
    refused ones first, then the busiest."""
    lines = []
    if len(sessions) > 1:
        names = ", ".join(sorted({clean(session.name) for session in sessions}))
        lines.append(f"  from {names}, which ran in this time, each line says which")
    if not requests:
        lines.append("  no request in the egress proxy's log")
    count: Counter[tuple[bool, str]] = Counter()
    volume: Counter[tuple[bool, str]] = Counter()
    for request in requests:
        # What a session asked for is the session's to choose
        asked = (request.denied, clean(request.url))
        count[asked] += 1
        volume[asked] += request.size
    for denied, url in sorted(count, key=lambda to: (not to[0], -count[to], to[1])):
        total = size(volume[(denied, url)])
        lines.append(f"  {verdict(denied):<7}  {url} x{count[(denied, url)]}  {total}")
    return lines


def proxy_event(request: ProxyRequest) -> Event:
    """A request to the egress proxy as an event. Its method and URL are
    the session's to choose, so they are cleaned."""
    protocol = over("proxy", request.port)
    method, url = clean(request.method), clean(request.url)
    # What the session sent, where the proxy's log says so
    out = f" {size(request.sent)} out," if request.sent is not None else ""
    back = " in" if out else ""
    detail = (
        f"{protocol} {method} {url} {verdict(request.denied)}"
        f"{out} {size(request.size)}{back} {request.seconds:.1f}s"
    )
    fields = {
        "protocol": protocol,
        "method": method,
        "url": url,
        "port": request.port,
        "denied": request.denied,
        "bytes": request.size,
        "seconds": request.seconds,
        **({"bytes_out": request.sent} if request.sent is not None else {}),
    }
    return Event(request.began, Who.SANDBOX, "net", [detail], fields)


def name_container(events: list[Event], name: str, shown: bool) -> None:
    """Say of each event which container it is of, by the name the
    launcher gave it. A transcript does not say which container wrote it,
    so what the project's other sessions did at the same time is in its
    trace too: the name is what tells them apart. Always among the values
    of the event, in its line only when shown, which is when there is more
    than one to tell apart."""
    for event in events:
        event.fields["container"] = name
        if shown:
            event.details[0] = f"[{clean(name)}] {event.details[0]}"


def proxy_requests(
    sessions: list[NetSession], start: float, end: float, several: bool = False
) -> tuple[list[str], list[Event]]:
    """What filtered sessions asked the egress proxy for between start and
    end, as summary lines and as one event per request, each with the
    container it came from (see name_container)."""
    logged = logged_requests(stderr=subprocess.DEVNULL)
    if logged is None:
        return ["  the egress proxy's log cannot be read"], []
    requests, events = [], []
    for request, by in requests_made(logged, sessions, start, end):
        event = proxy_event(request)
        name_container([event], by.name, several)
        requests.append(request)
        events.append(event)
    return proxy_summary(requests, sessions), events


def how_it_went(connection: Connection, outcome: str) -> str:
    """An outcome of a connection as the words after its destination,
    none for no outcome: the capture does not always tell."""
    if outcome != "closed":
        return {"open": "left open"}.get(outcome, outcome.upper())
    went = f"closed after {connection.seconds:.1f}s"
    # Of a connection that was reset, one of the two may not be known
    for count, way in ((connection.sent, "out"), (connection.received, "in")):
        if count is not None:
            went += f", {size(count)} {way}"
    return went


def connection_event(
    capture: Capture,
    connection: Connection,
    live: bool = False,
    ending: tuple[float, str] | None = None,
) -> Event:
    """A connection as an event. Of a capture that is all there it says
    how the connection went. Live there are two or more: one as it opens,
    and one for each thing that became of it, ending being when and what
    (no answer, refused or closed)."""
    address, port = connection.address, connection.port
    fields: dict = {
        "protocol": over("tcp", port),
        "name": capture.names.get(address),
        "address": address,
        "port": port,
        "source_port": connection.source_port,
    }
    when, outcome = ending or (connection.when, "" if live else connection.outcome)
    if live:
        fields["stage"] = "outcome" if ending else "open"
    if outcome:
        fields["outcome"] = outcome
    if outcome == "closed":
        fields.update(
            seconds=connection.seconds,
            bytes_out=connection.sent,
            bytes_in=connection.received,
        )
    went = how_it_went(connection, outcome)
    detail = reached(capture, address, port) + (f"  {went}" if went else "")
    return Event(when, Who.SANDBOX, "net", [detail], fields)


def flow_event(capture: Capture, flow: Flow, live: bool = False) -> Event:
    """What was sent to one place by another protocol than TCP, as an
    event at the time of the first packet. Of a capture that is all there
    it says how much went out, live just that it started."""
    protocol = over(flow.transport, flow.port)
    fields: dict = {
        "protocol": protocol,
        "name": capture.names.get(flow.address),
        "address": flow.address,
        "port": flow.port,
    }
    detail = reached(capture, flow.address, flow.port, flow.transport)
    if live:
        fields["stage"] = "open"
    else:
        fields.update(packets=flow.packets, bytes_out=flow.sent)
        detail += f"  {sent_by(flow)}"
    return Event(flow.when, Who.SANDBOX, "net", [detail], fields)


def sent_by(flow: Flow) -> str:
    packets = f"{flow.packets} packet{'s' if flow.packets > 1 else ''}"
    return f"{packets}, {size(flow.sent)} out"


def flag_event(why: str, lookup: Lookup) -> Event:
    """A lookup that stands out, see pcap.py for what makes one."""
    fields = {"name": lookup.name, "type": lookup.kind, "flagged": why}
    detail = clean(f"lookup {lookup.name} {lookup.kind} FLAGGED: {why}")
    return Event(lookup.when, Who.SANDBOX, "dns", [detail], fields)


def request_event(request: Request) -> Event:
    """A plain HTTP request, which unlike one over TLS can be read."""
    fields = {
        "protocol": "http",
        "method": request.method,
        "url": request.url,
        "address": request.address,
        "port": request.port,
    }
    detail = clean(f"http {request.method} {request.url}")
    return Event(request.when, Who.SANDBOX, "net", [detail], fields)


def lookup_event(lookup: Lookup) -> Event:
    """An answer of the resolver: what was asked and what came back."""
    answer = ", ".join(lookup.addresses) or "nothing"
    said = f"FAILED: {lookup.error}" if lookup.error else f"-> {answer}"
    fields = {
        "name": lookup.name,
        "type": lookup.kind,
        "addresses": list(lookup.addresses),
        "error": lookup.error,
    }
    detail = clean(f"lookup {lookup.name} {lookup.kind} {said}")
    return Event(lookup.when, Who.SANDBOX, "dns", [detail], fields)


def capture_summary(capture: Capture, verbose: bool) -> list[str]:
    """Each destination with its number of connections, the busiest
    first, how many of them failed and how many names were looked up."""
    count = Counter(
        reached(capture, connection.address, connection.port)
        for connection in capture.connections
    )
    lines = [
        f"  {destination} x{count[destination]}"
        for destination in sorted(count, key=lambda to: (-count[to], to))
    ]
    lines += [
        f"  {reached(capture, flow.address, flow.port, flow.transport)}"
        f"  {sent_by(flow)}"
        for flow in sorted(capture.flows, key=lambda flow: -flow.sent)
    ]
    if not count and not capture.flows:
        lines.append("  no connection")
    failed = sum(connection.failed for connection in capture.connections)
    if failed:
        lines.append(f"  {failed} connections REFUSED or without an answer")
    if capture.requests:
        lines.append(f"  http {len(capture.requests)} requests in the clear")
    names = {lookup.name for lookup in capture.lookups}
    if names:
        hint = "" if verbose else ", each one shown with --verbose"
        lines.append(f"  dns {len(names)} names looked up{hint}")
    if capture.flagged:
        lines.append(f"  dns {len(capture.flagged)} lookups FLAGGED, see --failed")
    if cut_short(capture):
        lines.append("  STOPPED at its packet limit, what came later is missing")
    return lines


def capture_events(
    capture: Capture,
    verbose: bool,
    past: tuple[int, int, int, int, int, int] | None = None,
) -> list[Event]:
    """One event per connection, per place something was sent to by
    another protocol, per plain HTTP request and per lookup that stands
    out, with --verbose also per answer of the resolver. Of a capture that
    is all there, a connection says how it went. Of one read as it grows,
    past being its marks at the last reading, only what came since: a
    connection when it starts, and what became of it as an event of its
    own."""
    live = past is not None
    started, ended, looked_up, asked, sent, flagged = past or (0, 0, 0, 0, 0, 0)
    events = [
        connection_event(capture, connection, live)
        for connection in capture.connections[started:]
    ]
    if live:
        events += [
            connection_event(capture, connection, live, (when, what))
            for when, what, connection in capture.endings[ended:]
        ]
    events += [request_event(request) for request in capture.requests[asked:]]
    events += [flow_event(capture, flow, live) for flow in capture.flows[sent:]]
    events += [flag_event(why, lookup) for why, lookup in capture.flagged[flagged:]]
    if verbose:
        events += [lookup_event(lookup) for lookup in capture.lookups[looked_up:]]
    return events


def process_records(
    host: Host, watched: list[NetSession]
) -> list[tuple[NetSession, ProcessRecord]]:
    """The record of the processes of each session that has one, those
    that are still kept."""
    return [
        (session, record)
        for session in watched
        if (record := session_record(host, session)) is not None
    ]


def processes_of(
    session: NetSession, records: list[tuple[NetSession, ProcessRecord]]
) -> ProcessRecord | None:
    """The record of the processes of a session, none when there is no
    such record or it is no longer kept: the one of the same container
    that ran at the same time."""
    for noted, record in records:
        if (
            noted.name == session.name
            and noted.start <= session.until
            and noted.until >= session.start
        ):
            return record
    return None


def name_processes(events: list[Event], record: ProcessRecord) -> None:
    """Say of each connection which process made it, where one was noted
    to hold it: by its ports, so this is not a guess by the clock."""
    for event in events:
        fields = event.fields
        if event.what != "net" or "source_port" not in fields:
            continue
        lineage = record.holder(
            fields["source_port"], fields["address"], fields["port"], event.when
        )
        if not lineage:
            continue
        made_it = lineage[0]
        fields["process"] = {
            "pid": made_it.pid,
            "exe": made_it.program,
            "argv": list(made_it.argv),
            "parents": [parent.name for parent in lineage[1:]],
        }
        event.details[0] += f"  by: {clean(shown_lineage(lineage))}"


def process_events(record: ProcessRecord) -> list[Event]:
    """One event per process that was seen to run, or to become another
    program. What a process says it is, is its own to choose."""
    events = []
    for process in record.processes:
        parent = record.process(process.parent, process.when)
        details = [flat(f"[{process.pid}] {process.command}")[:PROCESS_WIDTH]]
        if process.program:
            details.append("exe: " + flat(process.program))
        if parent:
            details.append(flat(f"parent: [{parent.pid}] {parent.name}"))
        fields = {
            "pid": process.pid,
            "ppid": process.parent,
            "exe": process.program,
            "argv": list(process.argv),
        }
        events.append(Event(process.when, Who.SANDBOX, "exec", details, fields))
    return events


def process_summary(record: ProcessRecord, verbose: bool) -> list[str]:
    hint = "" if verbose else ", each one shown with --verbose"
    lines = [f"  processes {len(record.processes)} seen to run{hint}"]
    if record.full:
        lines.append("  the record of them STOPPED at its size limit")
    if record.unreadable:
        lines.append("  which process made a connection could not be seen")
    return lines


def captured_connections(
    host: Host,
    session: NetSession,
    verbose: bool,
    record: ProcessRecord | None,
    several: bool = False,
) -> tuple[list[str], list[Event]]:
    """What a captured session connected to, as summary lines and as
    events, each connection with the process that made it when a record
    of the session's processes tells. Of the container's whole stay, a
    capture is not tied to one transcript."""
    began = datetime.fromtimestamp(session.start)
    ended = datetime.fromtimestamp(session.until)
    name = clean(session.name)
    heading = f"  captured in {name} from {began:%H:%M:%S} to {ended:%H:%M:%S}"
    capture = session_capture(host, session)
    if capture is None:
        return [heading, "  its capture is no longer kept"], []
    events = capture_events(capture, verbose)
    if record:
        name_processes(events, record)
    name_container(events, session.name, several)
    return [heading, *capture_summary(capture, verbose)], events


def network(
    host: Host, start: float, end: float, verbose: bool
) -> tuple[list[str], list[Event]]:
    """What the session did on the network and what ran in it, from what
    the launcher kept: the egress proxy's log for a filtered session, a
    capture for one run without CLAUDE_DOCKER_NET_LOG=0, and the record
    of its processes for one run without CLAUDE_DOCKER_PROC_LOG=0, all
    of those between start and end."""
    sessions = recorded_sessions(host, start, end)
    filtered = [session for session in sessions if session.ip]
    captured = [session for session in sessions if session.capture]
    records = process_records(
        host, [session for session in sessions if session.processes]
    )
    # A session can have a line for each of its records, under one name
    several = len({session.name for session in sessions}) > 1
    found = [proxy_requests(filtered, start, end, several)] if filtered else []
    found += [
        captured_connections(
            host, session, verbose, processes_of(session, records), several
        )
        for session in captured
    ]
    lines = (
        ["network", *(line for some, _ in found for line in some)]
        if found
        else [
            labelled(
                "network", "not recorded (CLAUDE_DOCKER_NET_LOG=0, or not sandboxed)"
            )
        ]
    )
    events = [event for _, events in found for event in events]
    for session, record in records:
        lines += process_summary(record, verbose)
        ran = process_events(record) if verbose else []
        name_container(ran, session.name, several)
        events += ran
    return lines, events


@dataclass(frozen=True)
class Filter:
    """Which events are shown, all of them unless told otherwise: with
    --only those of the kinds named (what the what column says, bash or
    net), with --failed those that tell of something gone wrong."""

    only: frozenset[str] = frozenset()
    failed: bool = False

    def __bool__(self) -> bool:
        return bool(self.only) or self.failed

    def wants(self, event: Event) -> bool:
        if self.only and not {event.what, shown_what(event.what)} & self.only:
            return False
        return went_wrong(event) or not self.failed

    def header(self) -> list[str]:
        """The line that says what was left out, none when nothing was:
        a trace kept in a file must not pass for a whole one."""
        said = [f"only {', '.join(sorted(self.only))}"] if self.only else []
        said += ["only what went wrong"] if self.failed else []
        return [labelled("shown", ", ".join(said))] if said else []


# The filter that leaves nothing out
EVERYTHING = Filter()


@dataclass
class RunningCall:
    """A tool call as the timeline knows it: from when to when it ran,
    and what it is shown by."""

    started: float
    ended: float
    label: str


class Timeline:
    """Says of each thing on the network which tool call was running when
    it happened, from the events in the order they come. That is not proof
    the call did it, a connection is known by its container and not by the
    command that opened it, but a connection made while one command ran is
    as a rule that command's, and one made while none ran is Claude Code's
    own or that of something left running."""

    def __init__(self) -> None:
        self._calls: dict[str, RunningCall] = {}
        # The latest time seen, the events of the network can come late
        self._now = 0.0

    def take(self, event: Event) -> None:
        """Note a tool call or its result, or mark an event of the
        network with the calls running at its time."""
        fields = event.fields
        self._now = max(self._now, event.when)
        call = fields.get("id")
        if "tool" in fields and isinstance(call, str):
            self._note(event, call)
        elif event.what == "net" and fields.get("stage") != "outcome":
            self._mark(event)

    def _note(self, event: Event, call: str) -> None:
        fields = event.fields
        stage = fields.get("stage")
        if stage == "result":
            if call in self._calls:
                self._calls[call].ended = event.when
            return
        # Live a call runs until its result comes. In a transcript that
        # is all there it ran for as long as its result says, and one
        # without a result is not known to have run at all.
        seconds = fields.get("seconds")
        length = seconds if isinstance(seconds, (int, float)) else 0.0
        ended = float("inf") if stage == "call" else event.when + length
        label = (call_label(event) or fields["tool"])[:DURING_WIDTH]
        self._calls[call] = RunningCall(event.when, ended, label)

    def _mark(self, event: Event) -> None:
        if event.when < self._now - TIMELINE_SLACK:
            # Too long ago to tell: the calls of then are forgotten
            return
        forgotten = self._now - TIMELINE_SLACK
        for call in [c for c, ran in self._calls.items() if ran.ended < forgotten]:
            del self._calls[call]
        running = {
            call: ran
            for call, ran in self._calls.items()
            if ran.started <= event.when <= ran.ended
        }
        event.fields["during"] = list(running)
        if not running:
            event.details[0] += "  (no call running)"
            return
        # The one started last: the others are what it runs within, a
        # subagent for one
        latest = max(running.values(), key=lambda ran: ran.started)
        more = f" (+{len(running) - 1} more)" if len(running) > 1 else ""
        event.details[0] += f"  during: {latest.label}{more}"


def removed_events(gone: list[dict], project_dir: str, verbose: bool) -> list[Event]:
    """The events of the entries the launcher copied and the transcript
    no longer has, each said to have been removed."""
    events = transcript_events(gone, project_dir, verbose)
    for event in events:
        first = event.details[0] if event.details else ""
        event.details[:1] = [f"{first}  REMOVED FROM THE TRANSCRIPT".lstrip()]
        event.fields["removed"] = True
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

    def last_written(path: Path) -> float:
        return modified(path) or copied_at(host, path)

    return sorted([*files, *removed], key=last_written, reverse=True)


def subagents_header(compared: list[Compared]) -> list[str]:
    """The line that says how far the transcripts of a session's
    subagents are to be believed, none for a session without any."""
    if not compared:
        return []
    return functools.reduce(Compared.with_, compared).header(len(compared))


def session_events(
    path: Path, host: Host, verbose: bool, chosen: Filter = EVERYTHING
) -> tuple[list[str], list[Event]]:
    """The header lines of a session and its events, those of the
    transcript and of the network record together, in the order they
    happened. The header is of the whole session, the events are the
    chosen ones."""
    entries = read_entries(path)
    project_dir = project_root(path, host)
    compared = compare(host, path)
    # What its subagents did is in a transcript of each, see subagent_files
    of_subagents = [*subagent_files(path), *removed_subagents(host, path)]
    subagents = [(read_entries(f), compare(host, f)) for f in of_subagents]
    # What a transcript that is no longer there held, as it was copied
    entries_known = entries or compared.gone
    theirs = [entry for of_one, copied in subagents for entry in of_one or copied.gone]
    # With what was taken out: when the session ran is not what is left
    # of it. By the earliest and the latest, the order is the session's.
    times = [
        when.timestamp() for when in entry_times([*entries, *compared.gone, *theirs])
    ]
    unreadable = sum(e.get("type") == UNREADABLE for e in [*entries, *theirs])
    net_lines: list[str] = []
    net_events: list[Event] = []
    door_rows: list[tuple[str, str]] = []
    door_uses: list[Event] = []
    if times:
        start, end = min(times), max(times)
        net_lines, net_events = network(host, start, end, verbose)
        door_rows, door_uses = door_events(host, start, end)
    header = [
        labelled("session", f"{flat(path.stem)}  {title(entries_known)}"),
        *compared.header(),
        *subagents_header([copied for _, copied in subagents]),
        *(
            [
                labelled(
                    "transcript",
                    f"{unreadable} lines CANNOT BE READ, shown as UNREADABLE:"
                    " what was done there is not told",
                )
            ]
            if unreadable
            else []
        ),
        *summary(entries_known + theirs, project_dir),
        *net_lines,
        *(labelled(door, used) for door, used in door_rows),
        *chosen.header(),
    ]
    # Stable, so what the transcript has at the same time keeps its order
    events = sorted(
        transcript_events(entries, project_dir, verbose)
        + removed_events(compared.gone, project_dir, verbose)
        + [
            event
            for of_one, copied in subagents
            for event in transcript_events(of_one, project_dir, verbose)
            + removed_events(copied.gone, project_dir, verbose)
        ]
        + net_events
        + door_uses,
        key=lambda event: event.when,
    )
    timeline = Timeline()
    for event in events:
        timeline.take(event)
    return header, [event for event in events if chosen.wants(event)]


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
            f"{when:16}  {flat(path.stem)[:8]}  {len(prompts(entries)):3d} prompts"
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


def trace_options(
    args: list[str], known: tuple[str, ...]
) -> tuple[set[str], list[str], Filter]:
    """The arguments of --trace as the options among them, what is left,
    which is at most a name (a session, or list), and which events are
    asked for: --only takes its kinds after an = or as the next argument,
    separated by commas."""
    options: set[str] = set()
    names: list[str] = []
    only: set[str] = set()
    failed = False
    rest = iter(args)
    for arg in rest:
        option, has_value, value = arg.partition("=")
        if option == "--only":
            kinds = (value if has_value else next(rest, "")).lower().split(",")
            only |= {kind.strip() for kind in kinds if kind.strip()}
            if not only:
                raise Fatal(USAGE)
        elif arg == "--failed":
            failed = True
        elif arg in known:
            options.add(arg)
        else:
            names.append(arg)
    if len(names) > 1 or any(name.startswith("-") for name in names):
        raise Fatal(USAGE)
    if {"--verbose", "--json"} <= options:
        # JSON Lines has everything as it is
        raise Fatal(USAGE)
    return options, names, Filter(frozenset(only), failed)


def picked_session(files: list[Path], name: str) -> Path:
    """The one transcript whose session id starts with name."""
    found = sessions_named(files, name)
    if len(found) != 1:
        problem = "matches several sessions" if found else "matches no session"
        raise Fatal(f"{name} {problem}, see claude-docker --trace list")
    return found[0]


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
