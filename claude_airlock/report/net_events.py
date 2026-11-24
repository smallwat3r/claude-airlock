"""The network's side of a trace: what the launcher kept of a session's
network use and of its processes (see recorded.py, records.py, network.py
and capture.py) as events, and as the lines of the header that sum it up.

What a session asked the network for is the session's to choose, so it is
cleaned like what its transcript holds, see events.py. The records
themselves are the launcher's own."""

from __future__ import annotations

import math
from collections import Counter
from datetime import datetime

from ..events import Event, Kind, Stage, Who, Wrong, clean, flat, labelled
from ..recording.capture import cut_short
from ..recording.egress_log import ProxyRequest
from ..recording.health import health_summary
from ..recording.payloads import Lookup
from ..recording.pcap import Capture, Connection, Flow, Request, Went
from ..recording.processes import ProcessRecord, shown_lineage
from ..recording.records import TracedSession
from .recorded import Recorded, Traced
from .shown import SILENT, STOPPED, over, reached, size, verdict

# Of the command line of a process seen to run
PROCESS_WIDTH = 200
# What is said of a connection the watcher saw and found no process for
HIDDEN_HOLDER = "a process that cannot be looked into"


def proxy_summary(
    requests: list[ProxyRequest], sessions: list[TracedSession]
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
    wrong = Wrong.THROUGHOUT if request.denied else Wrong.NO
    return Event(request.began, Who.SANDBOX, Kind.NET, [detail], fields, wrong=wrong)


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
            event.tag = f"[{clean(name)}]"


def proxy_requests(recorded: Recorded) -> tuple[list[str], list[Event]]:
    """What filtered sessions asked the egress proxy for, as summary lines
    and as one event per request, each with the container it came from
    (see name_container)."""
    if recorded.requests is None:
        return ["  the egress proxy's log cannot be read"], []
    requests, events = [], []
    for request, by in recorded.requests:
        event = proxy_event(request)
        name_container([event], by.name, recorded.several)
        requests.append(request)
        events.append(event)
    return proxy_summary(requests, recorded.filtered), events


def how_it_went(connection: Connection, outcome: str) -> str:
    """An outcome of a connection as the words after its destination,
    none for no outcome: the capture does not always tell."""
    if outcome != Went.CLOSED:
        return "left open" if outcome == Went.OPEN else outcome.upper()
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
        "name": capture.name_of(address, connection.when),
        "address": address,
        "port": port,
        "source_port": connection.source_port,
    }
    when, outcome = ending or (
        connection.when,
        Went.UNKNOWN if live else connection.outcome,
    )
    if live:
        fields["stage"] = Stage.OUTCOME if ending else Stage.OPEN
    if outcome:
        fields["outcome"] = outcome
    if outcome == Went.CLOSED:
        fields.update(
            seconds=connection.seconds,
            bytes_out=connection.sent,
            bytes_in=connection.received,
        )
    went = how_it_went(connection, outcome)
    detail = reached(capture, address, port, "tcp", connection.when)
    detail += f"  {went}" if went else ""
    wrong = Wrong.THROUGHOUT if outcome in Went.WRONG else Wrong.NO
    return Event(when, Who.SANDBOX, Kind.NET, [detail], fields, wrong=wrong)


def flow_event(capture: Capture, flow: Flow, live: bool = False) -> Event:
    """What was sent to one place by another protocol than TCP, as an
    event at the time of the first packet. Of a capture that is all there
    it says how much went out, live just that it started."""
    protocol = over(flow.transport, flow.port)
    fields: dict = {
        "protocol": protocol,
        "name": capture.name_of(flow.address, flow.when),
        "address": flow.address,
        "port": flow.port,
    }
    detail = reached(capture, flow.address, flow.port, flow.transport, flow.when)
    if live:
        fields["stage"] = Stage.OPEN
    else:
        fields.update(packets=flow.packets, bytes_out=flow.sent)
        detail += f"  {sent_by(flow)}"
    return Event(flow.when, Who.SANDBOX, Kind.NET, [detail], fields)


def sent_by(flow: Flow) -> str:
    packets = f"{flow.packets} packet{'s' if flow.packets > 1 else ''}"
    return f"{packets}, {size(flow.sent)} out"


def flag_event(why: str, lookup: Lookup) -> Event:
    """A lookup that stands out, see pcap.py for what makes one."""
    fields = {"name": lookup.name, "type": lookup.kind, "flagged": why}
    detail = flat(f"lookup {lookup.name} {lookup.kind} FLAGGED: {why}")
    return Event(
        lookup.when, Who.SANDBOX, Kind.DNS, [detail], fields, wrong=Wrong.THROUGHOUT
    )


def request_event(request: Request) -> Event:
    """A plain HTTP request, which unlike one over TLS can be read."""
    fields = {
        "protocol": "http",
        "method": request.method,
        "url": request.url,
        "address": request.address,
        "port": request.port,
    }
    detail = flat(f"http {request.method} {request.url}")
    return Event(request.when, Who.SANDBOX, Kind.NET, [detail], fields)


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
    detail = flat(f"lookup {lookup.name} {lookup.kind} {said}")
    wrong = Wrong.THROUGHOUT if lookup.error else Wrong.NO
    return Event(lookup.when, Who.SANDBOX, Kind.DNS, [detail], fields, wrong=wrong)


def capture_summary(capture: Capture, verbose: bool) -> list[str]:
    """Each destination with its number of connections, the busiest
    first, how many of them failed and how many names were looked up."""
    count = Counter(
        reached(capture, connection.address, connection.port, "tcp", connection.when)
        for connection in capture.connections
    )
    lines = [
        f"  {destination} x{count[destination]}"
        for destination in sorted(count, key=lambda to: (-count[to], to))
    ]
    lines += [
        f"  {reached(capture, flow.address, flow.port, flow.transport, flow.when)}"
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


def name_processes(events: list[Event], record: ProcessRecord) -> None:
    """Say of each connection which process made it, where one was noted
    to hold it: by its ports, so this is not a guess by the clock."""
    for event in events:
        fields = event.fields
        if event.what != Kind.NET or "source_port" not in fields:
            continue
        made = (fields["source_port"], fields["address"], fields["port"], event.when)
        lineage = record.holder(*made)
        if not lineage:
            if record.hidden_holder(*made):
                fields["process"] = None
                event.notes.append(f"by: {HIDDEN_HOLDER}")
            continue
        made_it = lineage[0]
        fields["process"] = {
            "pid": made_it.pid,
            "exe": made_it.program,
            "argv": list(made_it.argv),
            "parents": [parent.name for parent in lineage[1:]],
        }
        event.notes.append(f"by: {flat(shown_lineage(lineage))}")


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
        events.append(Event(process.when, Who.SANDBOX, Kind.EXEC, details, fields))
    return events


def listener_events(record: ProcessRecord) -> list[Event]:
    """One event per socket that started to wait for connections, with
    the process that held it. One that waits on more than the session's
    own loopback says so: the other sessions that run are on its network,
    of other projects too."""
    events = []
    for listener in record.listeners:
        detail = flat(listener.at)
        if listener.open:
            detail += "  OPEN to its network"
        lineage = (
            record.lineage(max(listener.pids), listener.when) if listener.pids else []
        )
        if lineage:
            detail += f"  by: {flat(shown_lineage(lineage))}"
        fields = {
            "port": listener.port,
            "address": listener.address,
            "open": listener.open,
            "pids": list(listener.pids),
        }
        events.append(Event(listener.when, Who.SANDBOX, Kind.LISTEN, [detail], fields))
    return events


def watched_summary(
    record: ProcessRecord, verbose: bool, until: float = math.inf
) -> list[str]:
    """The lines of the header on what a session's watcher noted: its
    processes, and how it was doing. With until, when the session ended,
    a watcher that had stopped noting before then is said."""
    if record.outside:
        under = clean(record.outside)
        said = f"  processes not recorded under {under}, only memory and CPU use"
        return [said, *health_summary(record.samples, record.ended)]
    hint = "" if verbose else ", each one shown with --verbose"
    lines = [f"  processes {len(record.processes)} seen to run{hint}"]
    if record.process_limit:
        lines.append(
            f"  its limit of processes was RUN INTO {record.process_limit} times"
        )
    reachable = sum(listener.open for listener in record.listeners)
    if reachable:
        lines.append(
            f"  {reachable} sockets waited for connections, OPEN to its network"
        )
    if record.full:
        lines.append("  the record of them STOPPED at its size limit")
    if record.unreadable:
        lines.append("  which process made a connection could not be seen")
    return lines + health_summary(record.samples, record.ended)
    silent = record.silent_from(until)
    if silent is not None:
        lines.append(f"  {SILENT.format(datetime.fromtimestamp(silent))}")


def captured_connections(
    recorded: Recorded, found: Traced, verbose: bool
) -> tuple[list[str], list[Event]]:
    """What a captured session connected to, as summary lines and as
    events, each connection with the process that made it when a record
    of the session's processes tells. Of the container's whole stay, a
    capture is not tied to one transcript."""
    session, capture = found.session, found.capture
    began = datetime.fromtimestamp(session.start)
    ended = datetime.fromtimestamp(session.until)
    name = clean(session.name)
    heading = f"  captured in {name} from {began:%H:%M:%S} to {ended:%H:%M:%S}"
    if capture is None:
        return [heading, "  its capture is no longer kept"], []
    events = capture_events(capture, verbose)
    record = recorded.processes_of(session)
    if record:
        name_processes(events, record)
    name_container(events, session.name, recorded.several)
    stopped = [f"  {STOPPED.format(flat(session.stopped))}"] if session.stopped else []
    return [heading, *capture_summary(capture, verbose), *stopped], events


def watched_events(record: ProcessRecord, verbose: bool) -> list[Event]:
    """What a session's watcher noted, as events: the sockets that waited
    for connections, how the session was doing, and with --verbose each
    process that was seen to run."""
    ran = listener_events(record) + (process_events(record) if verbose else [])
    ran += [sample.event() for sample in record.samples]
    return ran + [ended.event() for ended in record.ended]


def network(recorded: Recorded, verbose: bool) -> tuple[list[str], list[Event]]:
    """What the sessions did on the network and what ran in them, from
    what the launcher kept of their time: the egress proxy's log for a
    filtered session, a capture for one run without
    CLAUDE_AIRLOCK_NET_LOG=0, and the record of its processes for one run
    without CLAUDE_AIRLOCK_PROC_LOG=0."""
    found = [proxy_requests(recorded)] if recorded.filtered else []
    found += [
        captured_connections(recorded, captured, verbose)
        for captured in recorded.captured
    ]
    lines = (
        ["network", *(line for some, _ in found for line in some)]
        if found
        else [
            labelled(
                "network", "not recorded (CLAUDE_AIRLOCK_NET_LOG=0, or not sandboxed)"
            )
        ]
    )
    events = [event for _, events in found for event in events]
    for session, record in recorded.watched:
        lines += watched_summary(record, verbose, session.until)
        ran = watched_events(record, verbose)
        name_container(ran, session.name, recorded.several)
        events += ran
    return lines, events
