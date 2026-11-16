"""Reviewing what a session did: what it ran, where and why, what it wrote
and what it reached on the network, in the order it happened.

From the transcript Claude Code keeps of each session in ~/.claude/projects
(every prompt, reply, tool call and result), and from what the launcher
kept of the session's network use (see records.py, network.py and
capture.py). The reading of the transcript is in transcript.py, this is
the network's side of a trace, the two put together and how it is shown.

The output is plain text, one event per line or lines, each line starting
with when, who and what, so it reads as well in a file or through grep as
on a terminal. The header lines start with a #. With --json it is JSON
Lines instead, an object per event, for jq or a database.

The transcript is written from inside the sandbox, so it is a convenience
for review and not an audit log, a session could rewrite its own. For the
same reason nothing in it is trusted here: control characters are dropped
before anything is printed. The network record is the launcher's own."""

from __future__ import annotations

import functools
import json
import math
import os
import pydoc
import socket
import subprocess
import sys
from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from .capture import cut_short
from .events import Event, Who, clean, flat
from .network import ProxyRequest, logged_requests
from .pcap import Capture, Connection, Lookup, Request, read_capture
from .records import NetSession, recorded_sessions
from .settings import Fatal, Host
from .transcript import (
    FILE_TOOLS,
    entry_times,
    project_root,
    prompts,
    read_entries,
    session_files,
    summary,
    title,
    tool_calls,
    transcript_events,
)

USAGE = "usage: claude-docker --trace [list | SESSION] [--follow] [--full | --json]"
# Of the call a connection is said to be made during
DURING_WIDTH = 60
# Seconds for which the timeline remembers a call that has ended, for the
# events of the network that are read later than they happened
TIMELINE_SLACK = 30.0
COLUMNS = "time                 who      what      details"
PORT_USES = {
    22: "ssh",
    53: "dns",
    80: "http",
    443: "https",
    1883: "mqtt",
    2375: "docker",
    3128: "proxy",
    3306: "mysql",
    5432: "postgres",
    6379: "redis",
    27017: "mongodb",
}

# How the lines are coloured on a terminal, as the parameters of an SGR
# escape. What a session did out of sight is what stands out: commands,
# writes and the network. The conversation, which its user saw anyway, and
# the lines about the trace itself are dimmed, the other tools are left
# as they are.
DIM = "2"
ALERT = "1;31"
STYLES = {
    "prompt": DIM,
    "reply": DIM,
    "bash": "33",
    "net": "36",
    "dns": "36",
    # The network too, asked for through a tool
    "webfetch": "34",
    "websearch": "34",
    **dict.fromkeys(map(str.lower, FILE_TOOLS), "35"),
}


def size(count: int) -> str:
    """A number of bytes as shown: 950 B, 1 kB, 2.3 GB."""
    left = float(count)
    for unit in ("B", "kB", "MB"):
        if left < 1000:
            return f"{left:.0f} {unit}"
        left /= 1000
    return f"{left:.1f} GB"


@functools.cache
def over(transport: str, port: int) -> str:
    """How a connection was made and, going by its port, what for:
    tcp/https, proxy/ssh, plain tcp for a port without a known use. The
    usual ones are named here, a host need not have a services file."""
    if port in PORT_USES:
        return f"{transport}/{PORT_USES[port]}"
    try:
        return f"{transport}/{socket.getservbyport(port, 'tcp')}"
    except (OSError, OverflowError):
        return transport


def verdict(denied: bool) -> str:
    return "DENIED" if denied else "allowed"


def made_by(
    request: ProxyRequest, session: NetSession, start: float, end: float
) -> bool:
    """Whether a session made a request between start and end: it came
    from the session's address and was open at some point of that time.
    The proxy logs a tunnel when it closes, which can be much later."""
    return (
        session.ip == request.address
        and request.ended >= max(start, session.start)
        and request.began <= min(end, session.until)
    )


def proxy_summary(
    requests: list[ProxyRequest], sessions: list[NetSession]
) -> list[str]:
    """Each destination with its number of requests and bytes, the
    refused ones first, then the busiest."""
    lines = []
    if len(sessions) > 1:
        names = ", ".join(sorted({clean(session.name) for session in sessions}))
        lines.append(f"  from {names}, which ran in this time and are not told apart")
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
    detail = (
        f"{protocol} {method} {url} {verdict(request.denied)}"
        f" {size(request.size)} {request.seconds:.1f}s"
    )
    fields = {
        "protocol": protocol,
        "method": method,
        "url": url,
        "port": request.port,
        "denied": request.denied,
        "bytes": request.size,
        "seconds": request.seconds,
    }
    return Event(request.began, Who.SANDBOX, "net", [detail], fields)


def proxy_requests(
    sessions: list[NetSession], start: float, end: float
) -> tuple[list[str], list[Event]]:
    """What filtered sessions asked the egress proxy for between start and
    end, as summary lines and as one event per request."""
    logged = logged_requests(stderr=subprocess.DEVNULL)
    if logged is None:
        return ["  the egress proxy is not running, its log cannot be read"], []
    requests = [
        request
        for request in logged
        if any(made_by(request, session, start, end) for session in sessions)
    ]
    return proxy_summary(requests, sessions), [proxy_event(r) for r in requests]


def reached(capture: Capture, address: str, port: int) -> str:
    """A destination as shown: tcp/https name (address):port, the name
    left out when the capture has none for the address."""
    known = capture.names.get(address)
    where = f"{known} ({address})" if known else address
    return clean(f"{over('tcp', port)} {where}:{port}")


def how_it_went(connection: Connection, outcome: str) -> str:
    """An outcome of a connection as the words after its destination,
    none for no outcome: the capture does not always tell."""
    if outcome != "closed":
        return {"open": "left open"}.get(outcome, outcome.upper())
    went = f"closed after {connection.seconds:.1f}s"
    if connection.sent is not None and connection.received is not None:
        went += f", {size(connection.sent)} out, {size(connection.received)} in"
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


def capture_summary(capture: Capture, full: bool) -> list[str]:
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
    if not count:
        lines.append("  no connection")
    failed = sum(connection.failed for connection in capture.connections)
    if failed:
        lines.append(f"  {failed} connections REFUSED or without an answer")
    if capture.requests:
        lines.append(f"  http {len(capture.requests)} requests in the clear")
    names = {lookup.name for lookup in capture.lookups}
    if names:
        hint = "" if full else ", each one shown with --full"
        lines.append(f"  dns {len(names)} names looked up{hint}")
    if cut_short(capture):
        lines.append("  STOPPED at its packet limit, what came later is missing")
    return lines


def capture_events(
    capture: Capture, full: bool, past: tuple[int, int, int, int] | None = None
) -> list[Event]:
    """One event per connection and per plain HTTP request, with --full
    also per answer of the resolver. Of a capture that is all there, a
    connection says how it went. Of one read as it grows, past being its
    marks at the last reading, only what came since: a connection when it
    starts, and what became of it as an event of its own."""
    live = past is not None
    started, ended, looked_up, asked = past or (0, 0, 0, 0)
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
    if full:
        events += [lookup_event(lookup) for lookup in capture.lookups[looked_up:]]
    return events


def captured_connections(
    host: Host, session: NetSession, full: bool
) -> tuple[list[str], list[Event]]:
    """What a captured session connected to, as summary lines and as
    events. Of the container's whole stay, a capture is not tied to one
    transcript."""
    began = datetime.fromtimestamp(session.start)
    ended = datetime.fromtimestamp(session.until)
    name = clean(session.name)
    heading = f"  captured in {name} from {began:%H:%M:%S} to {ended:%H:%M:%S}"
    try:
        capture = read_capture(Path(host.captures_dir, session.capture))
    except OSError:
        return [heading, "  its capture is no longer kept"], []
    return [heading, *capture_summary(capture, full)], capture_events(capture, full)


def network(
    host: Host, entries: list[dict], full: bool
) -> tuple[list[str], list[Event]]:
    """What the session did on the network, from what the launcher kept of
    it: the egress proxy's log for a filtered session, a capture for one
    run without CLAUDE_DOCKER_NET_LOG=0."""
    times = [when.timestamp() for when in entry_times(entries)]
    if not times:
        return [], []
    start, end = times[0], times[-1]
    sessions = recorded_sessions(host, start, end)
    if not sessions:
        return [
            "network     not recorded (CLAUDE_DOCKER_NET_LOG=0, or not sandboxed)"
        ], []
    filtered = [session for session in sessions if session.ip]
    captured = [session for session in sessions if session.capture]
    found = [proxy_requests(filtered, start, end)] if filtered else []
    found += [captured_connections(host, session, full) for session in captured]
    lines = ["network", *(line for some, _ in found for line in some)]
    return lines, [event for _, events in found for event in events]


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
        label = (event.details[0] if event.details else fields["tool"])[:DURING_WIDTH]
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


def session_events(path: Path, host: Host, full: bool) -> tuple[list[str], list[Event]]:
    """The header lines of a session and its events, those of the
    transcript and of the network record together, in the order they
    happened."""
    entries = read_entries(path)
    project_dir = project_root(path, host)
    net_lines, net_events = network(host, entries, full)
    header = [
        f"session     {flat(path.stem)}  {title(entries)}",
        *summary(entries, project_dir),
        *net_lines,
    ]
    # Stable, so what the transcript has at the same time keeps its order
    events = sorted(
        transcript_events(entries, project_dir, full) + net_events,
        key=lambda event: event.when,
    )
    timeline = Timeline()
    for event in events:
        timeline.take(event)
    return header, events


def prefixed(start: str, texts: list[str]) -> list[str]:
    """Whatever a value holds, no line of the output starts without its
    prefix: a line break in one must not pass for the start of an event."""
    return [
        (start + line).rstrip()
        for text in texts
        for line in (text.splitlines() or [""])
    ]


def use_colour(env: Mapping[str, str]) -> bool:
    """Whether the lines are coloured: on a terminal, unless NO_COLOR says
    not to (no-color.org), and anywhere when FORCE_COLOR asks for it, as a
    shell buffer of Emacs may want, which is not a terminal but shows
    colours."""
    if env.get("NO_COLOR"):
        return False
    return bool(env.get("FORCE_COLOR")) or sys.stdout.isatty()


def painted(style: str, text: str) -> str:
    """Text in a style, as it is without one. What is painted has been
    through clean, it holds no escape of its own to end the style early."""
    return f"\x1b[{style}m{text}\x1b[0m" if style and text else text


def header_lines(header: list[str], colour: bool = False) -> list[str]:
    lines = prefixed("# ", header)
    return [painted(DIM, line) for line in lines] if colour else lines


def alerting(event: Event, line: str) -> bool:
    """Whether a line of an event tells of something gone wrong: how a
    failed call ended, a write outside the project, a request the filter
    refused, a connection that was refused or not answered, a lookup that
    failed."""
    fields = event.fields
    return bool(
        (fields.get("failed") and line.startswith(("result: ", "out: ")))
        or (fields.get("outside_project") and line.startswith("file: "))
        or fields.get("denied")
        or fields.get("outcome") in ("refused", "no answer")
        or fields.get("error")
    )


def event_lines(event: Event, colour: bool = False) -> list[str]:
    """An event as text, each of its lines starting with when, who and
    what. In colour the time is dimmed and the rest of a line has the
    style of what the event is, or of an alert."""
    clock = f"{datetime.fromtimestamp(event.when):%Y-%m-%d %H:%M:%S}"
    about = f"{event.who.value:<7}  {event.what:<8}  "
    if not colour:
        return prefixed(f"{clock}  {about}", event.details)
    style = STYLES.get(event.what, "")
    return [
        painted(DIM, clock)
        + "  "
        + painted(ALERT if alerting(event, line) else style, (about + line).rstrip())
        for line in prefixed("", event.details)
    ]


def event_json(session: str, event: Event) -> str:
    """An event as a JSON object on a line: the session, time (ISO 8601
    with its offset), who, what, then the values of that kind of event.
    Escaped by the encoder, which leaves no control character to reach a
    terminal."""
    when = datetime.fromtimestamp(event.when).astimezone()
    about = {
        "session": session,
        "time": when.isoformat(timespec="milliseconds"),
        "who": event.who.value,
        "what": event.what,
    }
    try:
        # NaN and Infinity, which a transcript can hold, are not JSON to
        # most of what reads it
        return json.dumps({**about, **event.fields}, allow_nan=False)
    except ValueError:
        return json.dumps({**about, **finite(event.fields)})
    except RecursionError:
        # Nested as deep as could just be read
        return json.dumps({**about, "unreadable": True})


def finite(value: Any) -> Any:
    """A value with null for each number that JSON has no way to write."""
    if isinstance(value, float) and not math.isfinite(value):
        return None
    if isinstance(value, dict):
        return {key: finite(inner) for key, inner in value.items()}
    if isinstance(value, list):
        return [finite(inner) for inner in value]
    return value


def render(path: Path, host: Host, full: bool, colour: bool = False) -> str:
    """The trace as text: the header, then every event."""
    header, events = session_events(path, host, full)
    lines = header_lines([*header, "", COLUMNS], colour)
    for event in events:
        lines += event_lines(event, colour)
    return "\n".join(lines) + "\n"


def render_json(path: Path, host: Host) -> str:
    """The trace as JSON Lines, an object per event, nothing shortened.
    Every line names its session, so the traces of several can go into one
    file or table."""
    _, events = session_events(path, host, full=True)
    return "\n".join(event_json(path.stem, event) for event in events) + "\n"


def list_sessions(files: list[Path]) -> str:
    """One line per session, the latest first: when it started, the start
    of its id (enough to name it to --trace), its size and its title."""
    lines = []
    for path in files:
        entries = read_entries(path)
        times = entry_times(entries)
        started = f"{times[0]:%Y-%m-%d %H:%M}" if times else " " * 16
        lines.append(
            f"{started}  {flat(path.stem)[:8]}  {len(prompts(entries)):3d} prompts"
            f"  {len(tool_calls(entries)):4d} calls  {title(entries)}"
        )
    return "\n".join(lines) + "\n"


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
) -> tuple[set[str], list[str]]:
    """The arguments of --trace as the options among them and what is
    left, which is at most a name: a session, or list."""
    options = {arg for arg in args if arg in known}
    names = [arg for arg in args if arg not in known]
    if len(names) > 1 or any(name.startswith("-") for name in names):
        raise Fatal(USAGE)
    if {"--full", "--json"} <= options:
        # JSON Lines is in full as it is
        raise Fatal(USAGE)
    return options, names


def picked_session(files: list[Path], name: str) -> Path:
    """The one transcript whose session id starts with name."""
    found = [path for path in files if path.stem.startswith(name)]
    if len(found) != 1:
        problem = "matches several sessions" if found else "matches no session"
        raise Fatal(f"{name} {problem}, see claude-docker --trace list")
    return found[0]


def trace(host: Host, args: list[str]) -> int:
    """Show what a session of this project did: the latest one, or the one
    whose id starts with the given text, as text or with --json as JSON
    Lines. "list" lists them instead."""
    options, names = trace_options(args, ("--full", "--json"))
    files = session_files(host)
    if names == ["list"]:
        show(list_sessions(files))
        return 0
    path = picked_session(files, names[0]) if names else files[0]
    if "--json" in options:
        show(render_json(path, host))
    else:
        colour = use_colour(os.environ)
        show(render(path, host, "--full" in options, colour), colour)
    return 0
