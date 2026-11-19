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

import ipaddress
import json
import subprocess
import sys
import time
from collections import Counter

from .capture import cut_short, session_capture
from .egress_log import logged_requests, requests_made
from .events import flat
from .files import UNREADABLE, json_object, open_locked, private_dir
from .noted import noted_events
from .pcap import Capture
from .processes import session_record
from .projects import project_root, session_transcripts, subagent_session
from .recorder import compare, copied_at, removed_transcripts
from .records import NetSession, recorded_sessions
from .settings import EGRESS_PORT, Fatal, Host
from .shown import reached, size
from .transcript import modified, outside, read_entries, written_paths

# To one destination in one session, from this many bytes on it is said
LARGE_UPLOAD = 10_000_000
# Where Claude Code sends the conversation, again with every step: the
# addresses Anthropic publishes for its API. Told by address, a name is
# the session's to choose. A session that reaches the model another way
# has that way said as a large upload, which it is.
MODEL_API = (
    ipaddress.ip_network("160.79.104.0/23"),
    ipaddress.ip_network("2607:6bc0::/48"),
)
MODEL_DOMAIN = "anthropic.com"
# Of one kind of thing, how many are listed
MOST_LISTED = 8
# The destinations kept per project, the ones reached longest ago go first
KEPT_DESTINATIONS = 2000


def is_model_api(address: str) -> bool:
    try:
        found = ipaddress.ip_address(address)
    except ValueError:
        return False
    return any(found in network for network in MODEL_API)


def is_model_host(host: str) -> bool:
    """The same by name, as a filtered session asks its proxy for it."""
    return host == MODEL_DOMAIN or host.endswith("." + MODEL_DOMAIN)


def destinations(capture: Capture) -> dict[str, str]:
    """Each destination of a capture as it is known by, with how it is
    shown: by its transport, its name (its address without one) and its
    port."""
    found: dict[str, str] = {}
    reaches = [(c.address, c.port, "tcp") for c in capture.connections]
    reaches += [(f.address, f.port, f.transport) for f in capture.flows]
    for address, port, transport in reaches:
        name = capture.names.get(address, address).lower()
        found.setdefault(
            f"{transport} {name} {port}", reached(capture, address, port, transport)
        )
    return found


def uploads(capture: Capture, filtered: bool) -> list[str]:
    """The destinations a lot was sent to, the most first. Not the model's
    API, and of a filtered session not the proxy, which everything goes
    through: what went where behind it is not told apart."""
    sent: Counter[str] = Counter()
    for connection in capture.connections:
        behind_proxy = filtered and connection.port == EGRESS_PORT
        if not behind_proxy and not is_model_api(connection.address):
            where = reached(capture, connection.address, connection.port)
            # None of one left open, or reset by the other end: not known
            sent[where] += connection.sent or 0
    for flow in capture.flows:
        if not is_model_api(flow.address):
            where = reached(capture, flow.address, flow.port, flow.transport)
            sent[where] += flow.sent
    return [
        f"sent {size(count)} to {where}"
        for where, count in sent.most_common()
        if count >= LARGE_UPLOAD
    ]


def last_reached(noted: object) -> float:
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
        latest = sorted(known.items(), key=lambda item: last_reached(item[1]))
        projects[host.project_dir] = dict(latest[-KEPT_DESTINATIONS:])
        record.seek(0)
        record.truncate()
        json.dump(projects, record)
    return [] if first else new


def listed(heading: str, items: list[str]) -> list[str]:
    """A heading and the first few of what it is about, none without any."""
    if not items:
        return []
    more = len(items) - MOST_LISTED
    return [
        heading,
        *(f"  {item}" for item in items[:MOST_LISTED]),
        *([f"  and {more} more"] if more > 0 else []),
    ]


def network_lines(host: Host, sessions: list[NetSession]) -> list[str]:
    """What the captures and the process records of a session's
    containers give."""
    lines: list[str] = []
    found: dict[str, str] = {}
    filtered = any(session.ip for session in sessions)
    for session in sessions:
        record = session_record(host, session)
        if record and record.full:
            lines.append("the record of its processes stopped at its size limit")
        if record:
            # Each place once, however often a server was started there
            waited = dict.fromkeys(
                flat(listener.at) for listener in record.listeners if listener.open
            )
            lines += listed(
                "waited for connections, open to the other sessions on its network:",
                list(waited),
            )
        if record and record.process_limit:
            lines.append(
                f"ran into its limit of processes {record.process_limit} times,"
                " what it tried to start then did not: CLAUDE_AIRLOCK_PIDS sets"
                " the limit"
            )
        capture = session_capture(host, session)
        if capture is None:
            continue
        found.update(destinations(capture))
        lines += uploads(capture, filtered)
        lines += listed(
            "lookups that stand out:",
            [flat(f"{lookup.name}: {why}") for why, lookup in capture.flagged],
        )
        if cut_short(capture):
            lines.append("its capture stopped at its packet limit")
    captured = any(session.capture for session in sessions)
    new = newly_reached(host, found) if captured else []
    return [*listed("reached for the first time from this project:", new), *lines]


def denied_lines(sessions: list[NetSession], start: float, end: float) -> list[str]:
    """What the egress filter's log says of the session: where it sent
    a lot, and what it was refused."""
    filtered = [session for session in sessions if session.ip]
    logged = logged_requests(stderr=subprocess.DEVNULL) if filtered else None
    if not logged:
        return []
    made = [request for request, _ in requests_made(logged, filtered, start, end)]
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
        *listed(
            "refused by the egress filter:",
            [f"{url} x{count}" for url, count in denied.most_common()],
        ),
    ]


def transcript_lines(host: Host, start: float) -> list[str]:
    """What the transcripts written to since a time say: the files
    written outside the project, and what was taken out of them."""
    lines: list[str] = []
    written: list[str] = []
    # Those of the subagents too, what one wrote is in its own
    for path in session_transcripts(host):
        if modified(path) < start:
            continue
        project_dir = project_root(path, host)
        entries = read_entries(path)
        written.extend(
            flat(file) for file in written_paths(entries) if outside(file, project_dir)
        )
        compared = compare(host, path)
        # A subagent's is named by its session
        session = subagent_session(path)
        whose = "a subagent of " if session else ""
        named = f"the transcript of {whose}{flat((session or path).stem)[:8]}"
        if compared.gone or compared.rewritten:
            lines.append(
                f"{named} was changed:"
                f" {len(compared.gone)} lines the launcher copied are gone or altered"
            )
        unreadable = sum(entry.get("type") == UNREADABLE for entry in entries)
        if unreadable:
            lines.append(f"{named} has {unreadable} lines that cannot be read")
        if compared.cut_short:
            lines.append(f"{named} was not all copied, it is past the launcher's limit")
    for path in removed_transcripts(host):
        if copied_at(host, path) >= start:
            lines.append(
                f"the transcript of {flat(path.stem)[:8]} was removed, --trace"
                " shows the launcher's copy of it"
            )
    return [
        *listed("written outside the project:", list(dict.fromkeys(written))),
        *lines,
    ]


def session_digest(host: Host, session: str, start: float) -> list[str]:
    """The lines about a session of this project that has just ended:
    the container of that name, started at that time."""
    end = time.time()
    sessions = [
        found
        for found in recorded_sessions(host, start, end)
        if found.name == session and found.start >= start - 1
    ]
    noted_rows, _ = noted_events(host, start, end, session)
    return [
        *network_lines(host, sessions),
        *denied_lines(sessions, start, end),
        *transcript_lines(host, start),
        *(f"{about} {said}" for about, said in noted_rows),
    ]


def report_session(
    host: Host, session: str, start: float, heard: list[str] | None = None
) -> None:
    """Say what is worth a look about a session that has just ended, with
    what the launcher heard of it while it ran (see limits.py). What
    cannot be read is passed over: this runs as a session ends, and what
    is left to do then (the check of tamper.py) matters more."""
    try:
        lines = session_digest(host, session, start)
    except (OSError, Fatal):
        lines = []
    except Exception as problem:  # noqa: BLE001
        # What it reads is a session's to write. Said, and the check that
        # follows is still made.
        lines = [f"this could not be worked out: {flat(repr(problem))[:200]}"]
    lines = [*(heard or []), *lines]
    if lines:
        print(
            "claude-airlock: of this session, claude-airlock --trace has the rest:",
            *(f"  {line}" for line in lines),
            sep="\n",
            file=sys.stderr,
        )
