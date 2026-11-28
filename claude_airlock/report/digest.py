"""What a session did that is worth a look, said when it ends, next to the
check of tamper.py: where it went that no session of the project had gone
before, what it sent a lot to, what the egress filter refused it, the
lookups that stand out, what it wrote outside the project, what it took
out of its transcript, and its use of the SSH agent and the Docker socket.

Nothing new is recorded for it but one thing: the destinations each
project is known to reach, to tell a new one by. All of the rest is what
--trace shows, which has every line of it. Silent when there is nothing to
say, and about the first recorded session of a project, whose destinations
are all new.

A destination is known by its name where it has one, addresses change too
often to go by. The name is what the session looked up or asked for, so a
session that wants to pass for a known name can: this is a prompt to look,
the trace has the address."""

from __future__ import annotations

import json
import time
from collections import Counter
from collections.abc import Mapping
from datetime import datetime
from pathlib import Path

from ..errors import Fatal
from ..events import flat
from ..files import json_object, open_locked, private_dir, write_whole
from ..notice import warn
from ..projects import (
    MOST_SUBAGENTS,
    project_root,
    session_transcripts,
    subagent_session,
    subagents_unread,
)
from ..recording.capture import parts_cut_short
from ..recording.model_api import is_model_api, is_model_host
from ..recording.pcap import Capture
from ..recording.recorder import copied_at, last_written, removed_transcripts
from ..recording.records import recorded_sessions
from ..settings import EGRESS_PORT, Host
from .calls import written_paths
from .entries import read_entries, short_id, unreadable_lines
from .net_events import opened_files, reached_from, slowed
from .noted import noted_events
from .outcomes import outside
from .planted import FLAG, read_said
from .recorded import ReadTranscript, Recorded
from .shown import DROPPED, LOG_SHORT, SILENT, STOPPED, reached, size
from .summary import planted_reads

# To one destination in one session, from this many bytes on it is said.
# Not to the model's API, where the conversation goes again with every
# step (see model_api.py): a session that reaches the model another way
# has that way said as a large upload, which it is.
LARGE_UPLOAD = 10_000_000
# Of one kind of thing, how many are said
MOST_SAID = 8
# The destinations kept per project, the ones reached longest ago go first
KEPT_DESTINATIONS = 2000


def destination_key(transport: str, name: str | None, address: str, port: int) -> str:
    """What a destination is known by: its transport, its name (its
    address without one) and its port."""
    return f"{transport} {(name or address).lower()} {port}"


def _destinations(capture: Capture) -> dict[str, str]:
    """Each destination of a capture as it is known by, with how it is
    shown."""
    found: dict[str, str] = {}
    reaches = [(c.address, c.port, "tcp", c.when) for c in capture.connections]
    reaches += [(f.address, f.port, f.transport, f.when) for f in capture.flows]
    for address, port, transport, when in reaches:
        name = capture.name_of(address, when)
        found.setdefault(
            destination_key(transport, name, address, port),
            reached(capture, address, port, transport, when),
        )
    return found


def known_destinations(host: Host) -> frozenset[str] | None:
    """The destinations the sessions of the project were noted to reach
    up to now, each as destination_key has it. None for a project no
    session of which was noted yet, whose destinations are all new, and
    when the record cannot be read: nothing is then said to be new."""
    try:
        with open(host.destinations_file, encoding="utf-8") as record:
            projects = json_object(record.read()) or {}
    except OSError:
        return None
    recorded = projects.get(host.project_dir)
    return frozenset(recorded) if isinstance(recorded, dict) else None


def _uploads(capture: Capture, filtered: bool) -> list[str]:
    """The destinations a lot was sent to, the most first. Not the model's
    API, and of a filtered session not the proxy, which everything goes
    through: what went where behind it is not told apart."""
    sent: Counter[str] = Counter()
    for connection in capture.connections:
        behind_proxy = filtered and connection.port == EGRESS_PORT
        if not behind_proxy and not is_model_api(connection.address):
            where = reached(
                capture, connection.address, connection.port, "tcp", connection.when
            )
            # None of one left open, or reset by the other end: not known
            sent[where] += connection.sent or 0
    for flow in capture.flows:
        if not is_model_api(flow.address):
            where = reached(capture, flow.address, flow.port, flow.transport, flow.when)
            sent[where] += flow.sent
    return [
        f"sent {size(count)} to {where}"
        for where, count in sent.most_common()
        if count >= LARGE_UPLOAD
    ]


def _last_reached(noted: object) -> float:
    """When a destination was last reached as the record has it, long ago
    for what is not a time."""
    return float(noted) if isinstance(noted, (int, float)) else 0.0


def newly_reached(host: Host, found: dict[str, str]) -> list[str]:
    """The destinations no session of the project was noted to reach
    before, as shown, and note them all as reached now. None of them for
    the first session that is noted."""
    private_dir(host.state_dir)
    with open_locked(host.destinations_file, "r+") as record:
        projects = json_object(record.read()) or {}
        recorded = projects.get(host.project_dir)
        first = not isinstance(recorded, dict)
        known: dict[str, object] = dict(recorded) if isinstance(recorded, dict) else {}
        new = [shown for key, shown in found.items() if key not in known]
        known.update(dict.fromkeys(found, round(time.time())))
        latest = sorted(known.items(), key=lambda item: _last_reached(item[1]))
        projects[host.project_dir] = dict(latest[-KEPT_DESTINATIONS:])
        # Under another name, then given the record's, see write_whole:
        # cut short where it is, the record would be left empty by a
        # launcher that is killed, or a disk that is full, before it is
        # written back, and every project's next session would pass for
        # its first, which has nothing new to say
        write_whole(host.destinations_file, json.dumps(projects))
    return [] if first else new


def _headed(heading: str, items: list[str]) -> list[str]:
    """A heading and the first few of what it is about, none without any."""
    if not items:
        return []
    more = len(items) - MOST_SAID
    return [
        heading,
        *(f"  {item}" for item in items[:MOST_SAID]),
        *([f"  and {more} more"] if more > 0 else []),
    ]


def _network_lines(host: Host, recorded: Recorded) -> list[str]:
    """What the captures and the process records of a session's
    containers give."""
    lines: list[str] = []
    found: dict[str, str] = {}
    filtered = bool(recorded.filtered)
    for kept in recorded.traced:
        record, capture = kept.processes, kept.capture
        if record and record.full:
            lines.append("the record of its processes stopped at its size limit")
        silent = record.silent_from(kept.session.until) if record else None
        if silent is not None:
            lines.append(SILENT.format(datetime.fromtimestamp(silent)))
        if record and slowed(record):
            lines.append(slowed(record))
        if record:
            # Each place once, however often a server was started there
            waited = dict.fromkeys(
                flat(listener.at) for listener in record.listeners if listener.open
            )
            lines += _headed(
                "waited for connections, open to the other sessions on its network:",
                list(waited),
            )
            lines += _headed("opened files of secrets:", opened_files(record))
        if record and record.process_limit:
            then = (
                f"which under {flat(record.outside)} ends the session as a whole"
                if record.limit_ends_session
                else "what it tried to start then did not"
            )
            lines.append(
                f"ran into its limit of processes {record.process_limit} times,"
                f" {then}: CLAUDE_AIRLOCK_PIDS sets the limit"
            )
        if capture is None:
            continue
        found.update(_destinations(capture))
        lines += _uploads(capture, filtered)
        # Each once, however often they connected
        made = dict.fromkeys(reached_from(capture, made) for made in capture.inbound)
        lines += _headed("connected to from outside the session:", list(made))
        lines += _headed(
            "connections that stand out:",
            [
                f"{reached(capture, c.address, c.port, 'tcp', c.when)}: {flat(what)}"
                for _, what, c in capture.noticed
            ],
        )
        lines += _headed(
            "lookups that stand out:",
            [flat(f"{lookup.name}: {why}") for why, lookup in capture.dns.flagged],
        )
        if capture.dns.unread:
            unread = f"{capture.dns.unread} DNS messages of its capture were not read"
            lines.append(f"{unread}, more than are kept")
        if capture.dns.cut:
            lines.append(
                f"{capture.dns.cut} times what it sent to a resolver over TCP"
                " was too long for its capture to read: a lookup may be"
                " missing each time"
            )
        cut = ", ".join(parts_cut_short(capture))
        if cut:
            lines.append(f"its capture stopped at its packet limit ({cut})")
        if kept.session.stopped:
            lines.append(STOPPED.format(flat(kept.session.stopped)))
        if kept.session.dropped:
            lines.append(DROPPED.format(kept.session.dropped))
    new = newly_reached(host, found) if recorded.captured else []
    return [*_headed("reached for the first time from this project:", new), *lines]


def _denied_lines(recorded: Recorded) -> list[str]:
    """What the egress filter's log says of the session: where it sent
    a lot, and what it was refused."""
    begins = recorded.log_begins
    short = [] if begins is None else [LOG_SHORT.format(datetime.fromtimestamp(begins))]
    if not recorded.requests:
        return short
    made = [request for request, _ in recorded.requests]
    denied = Counter(flat(request.url) for request in made if request.denied)
    # How much went where through the filter, which a capture cannot tell
    # of a session whose every connection is to the proxy
    sent: Counter[str] = Counter()
    for request in made:
        if not request.denied and request.sent and not is_model_host(request.host):
            sent[flat(f"{request.host}:{request.port}")] += request.sent
    return [
        *(
            f"sent {size(count)} to {where} through the egress filter"
            for where, count in sent.most_common()
            if count >= LARGE_UPLOAD
        ),
        *_headed(
            "refused by the egress filter:",
            [f"{url} x{count}" for url, count in denied.most_common()],
        ),
        *short,
    ]


def _added_since(read: ReadTranscript, length: int) -> list[dict]:
    """The entries a transcript has gained since it was so long, all of
    them when it was not there then. A session that is resumed goes on in
    the transcript of the one before, and what that one did was said when
    it ended: it is not said again with every session after it. All of
    them too for a transcript that lines were taken out of, or that was
    rewritten, since: where its entries then are says nothing of when
    they came."""
    compared = read.compared
    if not length or compared.gone or compared.rewritten:
        return read.entries
    return read.entries[len(read_entries(read.path, most=length)) :]


def _transcript_lines(
    host: Host, start: float, lengths: Mapping[Path, int] | None = None
) -> list[str]:
    """What the transcripts written to since a time say: the files
    written outside the project, how much of what was read shows signs of
    being written to instruct the session, what was taken out of them,
    and how many of a session's subagents have theirs go unread. With
    lengths, how long each was at that time, of what each has gained
    since (see _added_since)."""
    lines: list[str] = []
    written: list[str] = []
    # Those of the subagents too, what one wrote is in its own
    for path in session_transcripts(host):
        if last_written(host, path) < start:
            continue
        project_dir = project_root(path, host)
        read = ReadTranscript.read(host, path)
        added = _added_since(read, (lengths or {}).get(path, 0))
        written.extend(
            flat(file)
            for file, cwd in written_paths(added)
            if outside(file, project_dir, cwd)
        )
        compared = read.compared
        # A subagent's is named by its session
        session = subagent_session(path)
        whose = "a subagent of " if session else ""
        named = f"the transcript of {whose}{short_id(session or path)}"
        unread = 0 if session else subagents_unread(path)
        if unread:
            lines.append(
                f"{unread} transcripts of subagents of {short_id(path)} were"
                f" neither copied nor read, past the first {MOST_SUBAGENTS}:"
                " what those subagents did is not told"
            )
        signs = planted_reads(added)
        if signs:
            said = f"{FLAG} in {named}: {read_said(signs)}"
            lines.append(f"{said}, see --trace --failed")
        if compared.gone or compared.rewritten:
            lines.append(
                f"{named} was changed:"
                f" {compared.missing} lines the launcher copied are gone or altered"
            )
        unreadable = unreadable_lines(added)
        if unreadable:
            lines.append(f"{named} has {unreadable} lines that cannot be read")
        if compared.cut_short:
            lines.append(f"{named} was not all copied, it is past the launcher's limit")
        if compared.uncompared:
            lines.append(f"{named} has too many lines to compare with its copy")
        if compared.dropped:
            lines.append(
                f"{named} was rewritten {compared.rewritten} times, more often"
                " than the launcher keeps all it had copied"
            )
    for path in removed_transcripts(host):
        if copied_at(host, path) >= start:
            lines.append(
                f"the transcript of {short_id(path)} was removed, --trace"
                " shows the launcher's copy of it"
            )
    return [
        *_headed("written outside the project:", list(dict.fromkeys(written))),
        *lines,
    ]


def _session_digest(
    host: Host, session: str, start: float, lengths: Mapping[Path, int] | None = None
) -> list[str]:
    """The lines about a session of this project that has just ended:
    the container of that name, started at that time. lengths as for
    _transcript_lines. A part that cannot be read, or whose record cannot
    be written (a full disk), says so and leaves the others as they are."""
    end = time.time()

    def network() -> list[str]:
        sessions = [
            found
            for found in recorded_sessions(host, start, end)
            if found.name == session and found.start >= start - 1
        ]
        recorded = Recorded(host, sessions, start, end)
        return [*_network_lines(host, recorded), *_denied_lines(recorded)]

    def noted() -> list[str]:
        rows, _ = noted_events(host, start, end, session)
        return [f"{about} {said}" for about, said in rows]

    def transcript() -> list[str]:
        return _transcript_lines(host, start, lengths)

    lines = []
    for about, part in (
        ("the network", network),
        ("the transcript", transcript),
        ("what the launcher noted", noted),
    ):
        try:
            lines += part()
        except (OSError, Fatal) as problem:
            lines.append(f"{about} could not be looked at: {flat(str(problem))[:200]}")
    return lines


def report_session(
    host: Host,
    session: str,
    start: float,
    heard: list[str] | None = None,
    lengths: Mapping[Path, int] | None = None,
) -> None:
    """Say what is worth a look about a session that has just ended, with
    what the launcher heard of it while it ran (see limits.py), and how
    long each transcript was when it started, for what is said to be of
    what came since. What cannot be read is passed over: this runs as a
    session ends, and what is left to do then (the check of tamper.py)
    matters more."""
    try:
        lines = _session_digest(host, session, start, lengths)
    except Exception as problem:  # noqa: BLE001
        # What it reads is a session's to write. Said, and the check that
        # follows is still made.
        lines = [f"this could not be worked out: {flat(repr(problem))[:200]}"]
    lines = [*(heard or []), *lines]
    if lines:
        warn(
            "of this session, claude-airlock --trace has the rest:",
            *(f"  {line}" for line in lines),
        )
