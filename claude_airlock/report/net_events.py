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
from ..recording.capture import parts_cut_short
from ..recording.egress_log import ProxyRequest
from ..recording.health import health_summary
from ..recording.payloads import Lookup
from ..recording.pcap import (
    SPOKEN_NAMES,
    SPOKEN_ON,
    Capture,
    Connection,
    Flow,
    Marks,
    Request,
    Went,
)
from ..recording.processes import (
    UNREADABLE_PROGRAM,
    Opened,
    Process,
    ProcessRecord,
    shown_lineage,
)
from ..recording.records import TracedSession
from ..recording.secrets import own_login, said
from ..recording.uploads import LEAST
from .links import Links, links_of
from .recorded import Recorded, Traced
from .shown import (
    DROPPED,
    LOG_SHORT,
    SILENT,
    SLOWED,
    SLOWED_FROM,
    STOPPED,
    over,
    reached,
    size,
    verdict,
)

# Of the command line of a process seen to run
PROCESS_WIDTH = 200
# What is said of a connection the watcher saw and found no process for
HIDDEN_HOLDER = "a process that cannot be looked into"


def _proxy_summary(
    requests: list[ProxyRequest], sessions: list[TracedSession]
) -> list[str]:
    """Each destination with its number of requests and bytes, the
    refused ones first, then the busiest."""
    lines = []
    # By name: a session that has two addresses is there once for each
    names = sorted({clean(session.name) for session in sessions})
    if len(names) > 1:
        said = ", ".join(names)
        lines.append(f"  from {said}, which ran in this time, each line says which")
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


def _proxy_requests(recorded: Recorded) -> tuple[list[str], list[Event]]:
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
    lines = _proxy_summary(requests, recorded.filtered)
    begins = recorded.log_begins
    if begins is not None:
        lines.append(f"  {LOG_SHORT.format(datetime.fromtimestamp(begins))}")
    return lines, events


def _how_it_went(connection: Connection, outcome: Went) -> str:
    """An outcome of a connection as the words after its destination,
    none for no outcome: the capture does not always tell. Of one left
    open, how much it carried as far as is known, which is no less than
    that: of what came in the capture has a sample, see answers.py. One
    made to the session that it did not take is nothing gone wrong for
    it, and is said in small letters."""
    if outcome == Went.OPEN:
        ways = zip(connection.so_far, ("out", "in"), strict=True)
        carried = ", ".join(f"{size(count)} {way}" for count, way in ways if count)
        # Not of one that carried next to nothing, as most do
        much = sum(count or 0 for count in connection.so_far) >= LEAST
        return f"left open, at least {carried}" if much else "left open"
    if outcome != Went.CLOSED:
        return outcome.lower() if connection.inbound else outcome.upper()
    went = f"closed after {connection.seconds:.1f}s"
    # Of a connection that was reset, one of the two may not be known
    for count, way in ((connection.sent, "out"), (connection.received, "in")):
        if count is not None:
            went += f", {size(count)} {way}"
    return went


def reached_from(capture: Capture, connection: Connection) -> str:
    """A connection made to the session as shown: who made it, by the
    name their address was looked up under when it has one, and the port
    of the session it was made to."""
    address = connection.address
    known = capture.name_of(address, connection.when)
    who = f"{known} ({address})" if known else address
    return flat(f"tcp IN from {who} to its port {connection.port}")


def _spoken_there(connection: Connection) -> str:
    """What a connection speaks, as said next to it: where its port does
    not say, and it is one of the protocols that are told. On a port
    that speaks something else it is noted, see Capture.noticed, and
    what asked a proxy for a destination says that."""
    told = SPOKEN_NAMES.get(connection.speaks)
    if not told or connection.port in SPOKEN_ON or connection.asked:
        return ""
    return f"speaks {told}"


def _uploads_on(capture: Capture, connection: Connection) -> int:
    """How many times something long enough to be worth a line was sent
    over a connection, as far as the capture took that, see uploads.py."""
    ended = math.inf if connection.ended is None else connection.ended
    return sum(
        part.sized_on(connection.key, connection.when, ended)
        for part in (capture.uploads, capture.elsewhere)
    )


def _connection_event(
    capture: Capture,
    connection: Connection,
    links: Links,
    live: bool = False,
    ending: tuple[float, Went] | None = None,
) -> Event:
    """A connection as an event. Of a capture that is all there it says
    how the connection went. Live there are two or more: one as it opens,
    and one for each thing that became of it, ending being when and what
    (no answer, refused or closed). Each is tied to the others, and to
    what went over the connection, by its number, see links.py."""
    address, port = connection.address, connection.port
    fields: dict = {
        "protocol": "tcp" if connection.inbound else over("tcp", port),
        **({} if connection.inbound else {"transport": "tcp"}),
        "name": capture.name_of(address, connection.when),
        "address": address,
        "port": port,
        **_told_of(connection),
    }
    when, outcome = ending or (
        connection.when,
        Went.UNKNOWN if live else connection.outcome,
    )
    if live:
        fields["stage"] = Stage.OUTCOME if ending else Stage.OPEN
    if ending:
        # What it is the outcome of, with the port it is from
        fields["opened"] = connection.when
    if outcome:
        fields["outcome"] = outcome
    if outcome == Went.CLOSED:
        fields.update(
            seconds=connection.seconds,
            bytes_out=connection.sent,
            bytes_in=connection.received,
        )
    went = _how_it_went(connection, outcome)
    uploads = _uploads_on(capture, connection) if went else 0
    if uploads:
        # When the capture took what is sent over it
        went += f", {uploads} uploads"
        fields["uploads"] = uploads
    if connection.inbound:
        detail = reached_from(capture, connection)
    else:
        detail = reached(capture, address, port, "tcp", connection.when)
    unread = (
        "its hello is longer than the capture keeps, what name it asks for is not known"
        if connection.hello_unread
        else ""
    )
    said = [
        f"asked for {flat(connection.asked)}" if connection.asked else "",
        _spoken_there(connection),
        unread,
        went,
    ]
    detail = "  ".join(filter(None, [detail, *said]))
    failed = outcome.wrong and not connection.inbound
    wrong = Wrong.THROUGHOUT if failed else Wrong.NO
    tied = links.of(connection)
    return Event(when, Who.SANDBOX, Kind.NET, [detail], fields, tied, wrong=wrong)


def _told_of(connection: Connection) -> dict:
    """What more a connection is known by, as named values: the port of
    the session it is from, and what its first bytes told. Of one made
    to the session, that it is, and the port of the other end."""
    if connection.inbound:
        return {"inbound": True, "peer_port": connection.source_port}
    told: dict = {"source_port": connection.source_port}
    if connection.asked:
        told["asked"] = connection.asked
    if connection.speaks:
        told["speaks"] = connection.speaks
    if connection.hello:
        told["hello"] = connection.hello.name
        told["offered"] = list(connection.hello.offered)
    if connection.hello_unread:
        told["hello_unread"] = True
    return told


def _noticed_event(
    capture: Capture, links: Links, when: float, what: str, found: Connection
) -> Event:
    """What stands out of a connection, see Capture.noticed of pcap.py,
    as an event of its own at the time it was found, tied to the
    connection by its number."""
    fields = {
        "protocol": over("tcp", found.port),
        "name": capture.name_of(found.address, found.when),
        "address": found.address,
        "port": found.port,
        "source_port": found.source_port,
        "opened": found.when,
        "flagged": what,
    }
    where = reached(capture, found.address, found.port, "tcp", found.when)
    detail = f"{where}  {flat(f'FLAGGED: {what}')}"
    return Event(
        when,
        Who.SANDBOX,
        Kind.NET,
        [detail],
        fields,
        links.of(found),
        wrong=Wrong.THROUGHOUT,
    )


def _flow_event(capture: Capture, flow: Flow, live: bool = False) -> Event:
    """What was sent to one place by another protocol than TCP, as an
    event at the time of the first packet. Of a capture that is all there
    it says how much went out, live just that it started."""
    protocol = over(flow.transport, flow.port)
    fields: dict = {
        "protocol": protocol,
        "transport": flow.transport,
        "name": capture.name_of(flow.address, flow.when),
        "address": flow.address,
        "port": flow.port,
    }
    detail = reached(capture, flow.address, flow.port, flow.transport, flow.when)
    if live:
        fields["stage"] = Stage.OPEN
    else:
        fields.update(packets=flow.packets, bytes_out=flow.sent)
        detail += f"  {_sent_by(flow)}"
    return Event(flow.when, Who.SANDBOX, Kind.NET, [detail], fields)


def _sent_by(flow: Flow) -> str:
    packets = f"{flow.packets} packet{'s' if flow.packets > 1 else ''}"
    return f"{packets}, {size(flow.sent)} out"


def _flag_event(why: str, lookup: Lookup) -> Event:
    """A lookup that stands out, see pcap.py for what makes one."""
    fields = {"name": lookup.name, "type": lookup.kind, "flagged": why}
    detail = flat(f"lookup {lookup.name} {lookup.kind} FLAGGED: {why}")
    return Event(
        lookup.when, Who.SANDBOX, Kind.DNS, [detail], fields, wrong=Wrong.THROUGHOUT
    )


def _request_event(request: Request) -> Event:
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


def _lookup_event(lookup: Lookup) -> Event:
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
        f"  {_sent_by(flow)}"
        for flow in sorted(capture.flows, key=lambda flow: -flow.sent)
    ]
    if not count and not capture.flows:
        lines.append("  no connection")
    failed = sum(connection.failed for connection in capture.connections)
    if failed:
        lines.append(f"  {failed} connections REFUSED or without an answer")
    if capture.requests:
        lines.append(f"  http {len(capture.requests)} requests in the clear")
    names = {lookup.name for lookup in capture.dns.lookups}
    if names:
        hint = "" if verbose else ", each one shown with --verbose"
        lines.append(f"  dns {len(names)} names looked up{hint}")
    if capture.dns.flagged:
        lines.append(f"  dns {len(capture.dns.flagged)} lookups FLAGGED, see --failed")
    if capture.noticed:
        lines.append(f"  {len(capture.noticed)} connections FLAGGED, see --failed")
    made = Counter(reached_from(capture, connection) for connection in capture.inbound)
    lines += [
        f"  {who} x{made[who]}"
        for who in sorted(made, key=lambda who: (-made[who], who))
    ]
    if capture.dns.unread:
        lines.append(
            f"  dns {capture.dns.unread} more messages NOT READ, past the"
            f" {len(capture.dns.lookups)} lookups that are kept"
        )
    if capture.dns.cut:
        lines.append(
            f"  dns {capture.dns.cut} times what was sent to a resolver over TCP"
            " was NOT READ to its end, too long for the capture: a lookup may"
            " be missing each time"
        )
    cut = ", ".join(parts_cut_short(capture))
    if cut:
        lines.append(
            f"  STOPPED at its packet limit ({cut}), what came later is missing"
        )
    return lines


def capture_events(
    capture: Capture,
    verbose: bool,
    past: Marks | None = None,
    upto: Marks | None = None,
    links: Links | None = None,
) -> list[Event]:
    """One event per connection, made by the session or to it, per place
    something was sent to by another protocol, per plain HTTP request,
    per lookup that stands out and per connection that does, with
    --verbose also per answer of the resolver. Of a capture that is all
    there, a connection says how it went. Of one read as it grows, past
    being its marks at the last reading, only what came since: a
    connection when it starts, and what became of it as an event of its
    own. No further than upto, when what is shown of a capture is held
    back, see CaptureTail of tails.py. With links, the numbers the
    connections are told by, see links_of: given in the order they were
    made, those made to the session among the others."""
    live = past is not None
    tied = links_of(links)
    was, now = past or Marks(), upto or capture.marks()
    started = capture.connections[was.connections : now.connections]
    started += capture.inbound[was.inbound : now.inbound]
    for connection in sorted(started, key=lambda made: made.when):
        tied.of(connection)
    events = [
        _connection_event(capture, connection, tied, live) for connection in started
    ]
    if live:
        events += [
            _connection_event(capture, connection, tied, live, (when, what))
            for when, what, connection in capture.endings[was.endings : now.endings]
        ]
    events += [
        _noticed_event(capture, tied, *found)
        for found in capture.noticed[was.noticed : now.noticed]
    ]
    events += [
        _request_event(request)
        for request in capture.requests[was.requests : now.requests]
    ]
    events += [
        _flow_event(capture, flow, live)
        for flow in capture.flows[was.flows : now.flows]
    ]
    events += [
        _flag_event(why, lookup)
        for why, lookup in capture.dns.flagged[was.flagged : now.flagged]
    ]
    if verbose:
        events += [
            _lookup_event(lookup)
            for lookup in capture.dns.lookups[was.lookups : now.lookups]
        ]
    return events


def name_processes(events: list[Event], record: ProcessRecord) -> None:
    """Say of each connection which process made it, where one was noted
    to hold it: by its ports, so this is not a guess by the clock."""
    for event in events:
        fields = event.fields
        if event.kind is not Kind.NET or "process" in fields:
            continue
        # A connection is noted by the session's port and the other end:
        # of one made to the session, the process is the one that took it
        opened = fields.get("opened", event.when)
        if fields.get("inbound"):
            made = (fields["port"], fields["address"], fields["peer_port"], opened)
        elif "source_port" in fields:
            made = (fields["source_port"], fields["address"], fields["port"], opened)
        else:
            continue
        lineage = record.holder(*made)
        if not lineage:
            if record.hidden_holder(*made):
                fields["process"] = None
                event.notes.append(f"by: {HIDDEN_HOLDER}")
            continue
        fields["process"] = _process_fields(lineage)
        event.notes.append(f"by: {flat(shown_lineage(lineage))}")


def _process_fields(lineage: list[Process]) -> dict:
    """A process and those it comes from, as --json has them."""
    made_it = lineage[0]
    return {
        "pid": made_it.pid,
        "exe": made_it.program,
        "argv": list(made_it.argv),
        "parents": [parent.name for parent in lineage[1:]],
    }


def _process_events(record: ProcessRecord) -> list[Event]:
    """One event per process that was seen to run, or to become another
    program. What a process says it is, is its own to choose."""
    events = []
    for process in record.processes:
        parent = record.process(process.parent, process.when)
        details = [flat(f"[{process.pid}] {process.command}")[:PROCESS_WIDTH]]
        details.append("exe: " + (flat(process.program) or UNREADABLE_PROGRAM))
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


def listener_events(record: ProcessRecord, past: int = 0) -> list[Event]:
    """One event per socket that started to wait for connections, with
    the process that held it. One that waits on more than the session's
    own loopback says so: the other sessions that run are on its network,
    of other projects too. Of a record read as it grows, past being how
    many it had at the last reading, only those that came since."""
    events = []
    for listener in record.listeners[past:]:
        detail = flat(listener.at)
        if listener.open:
            detail += "  OPEN to its network"
        lineage = (
            record.lineage(listener.holder, listener.when) if listener.pids else []
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


def own_opening(record: ProcessRecord, opened: Opened) -> bool:
    """Whether a file of secrets was opened by the one it is for, see
    own_login: no sign of anything."""
    process = record.process(opened.pid, opened.when)
    return own_login(opened.kind, process.program if process else "")


def opened_events(
    record: ProcessRecord, past: int = 0, own_too: bool = True
) -> list[Event]:
    """One event per file of secrets a process was seen to hold open,
    with the process, marked as what went wrong: a file that is not the
    process's own to read (see own_opening), which own_too leaves out.
    Of a record read as it grows, past being how many it had at the last
    reading, only those that came since."""
    events = []
    for opened in record.opened[past:]:
        own = own_opening(record, opened)
        if own and not own_too:
            continue
        what = said(opened.kind)
        detail = flat(f"{opened.path}, {what}")
        fields: dict = {
            "path": opened.path,
            "secret": opened.kind,
            "said": what,
            "own": own,
            "pid": opened.pid,
        }
        lineage = record.lineage(opened.pid, opened.when)
        if lineage:
            fields["process"] = _process_fields(lineage)
        if own:
            detail += ", opened by Claude Code itself"
        else:
            detail += ", OPENED"
            if lineage:
                detail += f"  by: {flat(shown_lineage(lineage))}"
        wrong = Wrong.NO if own else Wrong.THROUGHOUT
        events.append(
            Event(opened.when, Who.SANDBOX, Kind.SECRET, [detail], fields, wrong=wrong)
        )
    return events


def opened_files(record: ProcessRecord) -> list[str]:
    """The files of secrets that processes opened that were not theirs
    to (see own_opening), each once, with what each holds."""
    return list(
        dict.fromkeys(
            flat(f"{opened.path}, {said(opened.kind)}")
            for opened in record.opened
            if not own_opening(record, opened)
        )
    )


def _opened_lines(record: ProcessRecord) -> list[str]:
    """The lines of the header on the files of secrets opened."""
    lines = []
    files = opened_files(record)
    if files:
        lines.append(f"  {len(files)} files of secrets OPENED by its processes")
    if record.too_many_opened:
        lines.append(
            "  more files of secrets were opened than are noted, those past"
            " them were NOT NOTED"
        )
    return lines


def _limit_lines(record: ProcessRecord) -> list[str]:
    """The line of the header on a session that ran into its process
    limit, nothing for one that did not."""
    if not record.process_limit:
        return []
    said = f"  its limit of processes was RUN INTO {record.process_limit} times"
    if record.limit_ends_session:
        said += ", which ends the session as a whole"
    return [said]


def slowed(record: ProcessRecord) -> str:
    """What is said of a record whose watcher was slowed enough to tell
    (see SLOWED), empty for one that was not: how long a look takes is
    the session's to set, by what it has the watcher read."""
    late = [noted for noted in record.slowed if noted.longest >= SLOWED_FROM]
    if not late:
        return ""
    longest = max(noted.longest for noted in late)
    return SLOWED.format(longest, sum(noted.seconds for noted in late))


def watched_summary(
    record: ProcessRecord, verbose: bool, until: float = math.inf
) -> list[str]:
    """The lines of the header on what a session's watcher noted: its
    processes, and how it was doing. With until, when the session ended,
    a watcher that had stopped noting before then is said."""
    under = clean(record.outside)
    if not record.processes_known:
        unrecorded = f"  processes not recorded under {under}, only memory and CPU use"
        return [
            unrecorded,
            *_limit_lines(record),
            *health_summary(record.samples, record.ended),
        ]
    hint = "" if verbose else ", each one shown with --verbose"
    told = f", as {under} told" if record.outside else ""
    lines = [f"  processes {len(record.processes)} seen to run{told}{hint}"]
    if record.dropped:
        lines.append(
            f"  {record.dropped} of what {under} would have told COULD NOT BE"
            " TOLD, what ran then may be missing"
        )
    lines += _limit_lines(record)
    lines += _opened_lines(record)
    reachable = sum(listener.open for listener in record.listeners)
    if reachable:
        lines.append(
            f"  {reachable} sockets waited for connections, OPEN to its network"
        )
    if record.full:
        lines.append("  the record of them STOPPED at its size limit")
    # What the watcher saw while it could not write, see Unwritten: in
    # one line, a session can have that be so as often as it likes
    if record.unwritten:
        gaps = record.unwritten
        first = datetime.fromtimestamp(min(gap.since for gap in gaps))
        last = datetime.fromtimestamp(max(gap.until for gap in gaps))
        lines.append(
            f"  {sum(gap.lines for gap in gaps)} lines of the record could NOT"
            f" BE WRITTEN, {len(gaps)} times from {first:%H:%M:%S} to"
            f" {last:%H:%M:%S}: a full disk or the like"
        )
    silent = record.silent_from(until)
    if silent is not None:
        lines.append(f"  {SILENT.format(datetime.fromtimestamp(silent))}")
    if slowed(record):
        lines.append(f"  {slowed(record)}")
    if record.unreadable:
        lines.append("  which process made a connection could not be seen")
    if record.too_many_sockets:
        lines.append(
            "  more sockets were open at once than the watcher keeps: which"
            " process made the connections past those was NOT LOOKED FOR"
        )
    return lines + health_summary(record.samples, record.ended)


def _captured_connections(
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
    events = capture_events(capture, verbose, links=found.links)
    record = recorded.processes_of(session)
    if record:
        name_processes(events, record)
    name_container(events, session.name, recorded.several)
    stopped = [f"  {STOPPED.format(flat(session.stopped))}"] if session.stopped else []
    if session.dropped:
        stopped.append(f"  {DROPPED.format(session.dropped)}")
    return [heading, *capture_summary(capture, verbose), *stopped], events


def _watched_events(record: ProcessRecord, verbose: bool) -> list[Event]:
    """What a session's watcher noted, as events: the sockets that waited
    for connections, the files of secrets that were opened, how the
    session was doing, and with --verbose each process that was seen to
    run and Claude Code's own opening of its login."""
    ran = listener_events(record) + opened_events(record, own_too=verbose)
    ran += _process_events(record) if verbose else []
    ran += [sample.event() for sample in record.samples]
    return ran + [ended.event() for ended in record.ended]


def network(recorded: Recorded, verbose: bool) -> tuple[list[str], list[Event]]:
    """What the sessions did on the network and what ran in them, from
    what the launcher kept of their time: the egress proxy's log for a
    filtered session, a capture for one run without
    CLAUDE_AIRLOCK_NET_LOG=0, and the record of its processes for one run
    without CLAUDE_AIRLOCK_PROC_LOG=0."""
    found = [_proxy_requests(recorded)] if recorded.filtered else []
    found += [
        _captured_connections(recorded, captured, verbose)
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
        ran = _watched_events(record, verbose)
        name_container(ran, session.name, recorded.several)
        events += ran
    return lines, events
