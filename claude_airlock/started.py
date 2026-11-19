"""How the sandbox of each session was started: the runtime it runs under,
its image, its limits of memory, processes and CPUs, whether its network
is filtered, what is recorded of it, what is open to it beyond the
defaults and what is mounted next to the project.

The launcher notes it as a session starts, and notes when the session is
over, in a record of its own (see notes.py). A chat says it first,
--trace shows it in its header and ahead of what the session did, and
--trace --follow as a session starts. A transcript tells none of it, and
the settings of a later day are not those a session ran with."""

from __future__ import annotations

import dataclasses
import time
from collections.abc import Iterable
from dataclasses import dataclass

from .events import Event, Who, flat
from .mounts import ExtraDir
from .network import has_socket_proxy
from .notes import Notes
from .runtime import Runtime
from .settings import Host, Settings, SocketAccess

# The notes kept, two per session
KEPT_STARTS = 2000
# What a note says a session did, and what a start is shown as in a trace
STARTED = "started"
ENDED = "ended"
# What can be open to a session that is closed by default, as a start
# and the status of a chat name it
SSH_AGENT = "ssh-agent"
DOCKER_PS = "docker:ps"
DOCKER_FULL = "docker:full"
RW_CONFIG = "config:rw"
ALL_HISTORY = "history:all"
CONNECTORS = "connectors"
TELEMETRY = "telemetry"
SOCKET_SHOWN = {SocketAccess.LIMITED: DOCKER_PS, SocketAccess.FULL: DOCKER_FULL}
# The values of a note that are text, and those that are lists of texts
TEXTS = ("runtime", "image", "memory", "pids", "cpus")
LISTS = ("recorded", "open", "dirs")


@dataclass(frozen=True)
class Start:
    """How the sandbox of one session was started. Of the session, not of
    the settings: the SSH agent and the Docker socket are only open when
    the host has them, and what is recorded depends on the runtime."""

    # The runtime as named to the user, see Runtime.shown
    runtime: str
    image: str
    # The limits as they were set, each as docker reads it
    memory: str
    pids: str
    # Empty for all of the machine's CPUs
    cpus: str
    net_filter: bool
    # What the launcher records of the session from outside it
    recorded: tuple[str, ...] = ()
    # What is open to the session that is closed by default
    open: tuple[str, ...] = ()
    # What is mounted next to the project, (ro) after a read-only one
    dirs: tuple[str, ...] = ()

    @classmethod
    def of(
        cls,
        settings: Settings,
        runtime: Runtime,
        image: str,
        dirs: Iterable[ExtraDir],
        *,
        ssh_agent: bool,
    ) -> Start:
        """The start of a session with those settings, under that runtime
        and in a container of that image, the SSH agent forwarded or
        not."""
        recorded = []
        if settings.net_log:
            recorded.append("connections")
        if settings.proc_log:
            # Under a runtime no sidecar can see into, see host_health.py
            seen = runtime.JOINABLE
            recorded.append("processes" if seen else "memory and CPU use")
        socket = (
            settings.docker_socket if has_socket_proxy(settings) else SocketAccess.OFF
        )
        switches = (
            (ssh_agent, SSH_AGENT),
            (socket in SOCKET_SHOWN, SOCKET_SHOWN.get(socket, "")),
            (settings.rw_config, RW_CONFIG),
            (settings.shared_history, ALL_HISTORY),
            (settings.connectors, CONNECTORS),
            (settings.telemetry, TELEMETRY),
        )
        return cls(
            runtime=runtime.shown,
            image=image,
            memory=settings.memory,
            pids=settings.pids,
            cpus=settings.cpus,
            net_filter=settings.net_filter,
            recorded=tuple(recorded),
            open=tuple(name for on, name in switches if on),
            dirs=tuple(
                extra.path + (" (ro)" if extra.read_only else "") for extra in dirs
            ),
        )


def start_record(host: Host) -> Notes:
    """The record of how the sessions were started, and when each was
    over."""
    return Notes(host.starts_file, KEPT_STARTS)


def note_start(host: Host, session: str, start: Start) -> Event:
    """Add how a session was started to the record, for the container of
    that name. Returns it as the event it is shown as."""
    said = {"did": STARTED, **dataclasses.asdict(start)}
    start_record(host).add(host.project_dir, session, **said)
    return _shown({**said, "t": time.time(), "session": session})


def note_end(host: Host, session: str) -> None:
    """Add to the record that the session of a container is over: its
    name is the next session's to take, which a trace must not take for
    this one."""
    start_record(host).add(host.project_dir, session, did=ENDED)


def _text(said: dict, key: str) -> str:
    """A value of a note as text on one line, empty for one that is not
    text."""
    value = said.get(key)
    return flat(value) if isinstance(value, str) else ""


def _texts(said: dict, key: str) -> list[str]:
    """A list of a note as texts, each on one line."""
    values = said.get(key)
    # A list as read from the record, a tuple as the launcher noted it
    if not isinstance(values, (list, tuple)):
        return []
    return [flat(value) for value in values if isinstance(value, str)]


def start_event(said: dict) -> Event | None:
    """A note of the record as an event, none for one that is not the
    start of a session. The record is the launcher's own, it is still read
    with care and cleaned like the rest: a name or a path in it was not
    chosen by the launcher."""
    return _shown(said) if said.get("did") == STARTED else None


def _shown(said: dict) -> Event:
    """The note of a start as an event."""
    lists = {key: _texts(said, key) for key in LISTS}
    fields: dict[str, object] = {
        "container": _text(said, "session"),
        **{key: _text(said, key) for key in TEXTS},
        "net_filter": said.get("net_filter") is True,
        **lists,
    }
    image = f", image {fields['image']}" if fields["image"] else ""
    filtered = "filtered to the allowed domains" if fields["net_filter"] else "open"
    details = [
        f"{_where(fields)}{image}",
        f"limits: {_limits(fields)}",
        f"network: {filtered}",
        "recorded: " + (", ".join(lists["recorded"]) or "nothing"),
        # Said when there is any
        *(
            f"{label}: " + ", ".join(lists[key])
            for label, key in (("open", "open"), ("mounted", "dirs"))
            if lists[key]
        ),
    ]
    return Event(float(said["t"]), Who.SANDBOX, STARTED, details, fields)


def _where(fields: dict) -> str:
    """The container of a start and the runtime it runs under."""
    return f"{fields['container']} under {fields['runtime'] or 'an unknown runtime'}"


def _limits(fields: dict) -> str:
    """The limits of a start, as they were set."""
    cpus = f"cpus {fields['cpus']}" if fields["cpus"] else "all CPUs"
    return f"memory {fields['memory']}, processes {fields['pids']}, {cpus}"


def start_summary(event: Event) -> str:
    """A start in one line, for the header of a trace."""
    fields = event.fields
    network = "filtered" if fields["net_filter"] else "open"
    return f"{_where(fields)}, {_limits(fields)}, network {network}"


def running_between(notes: list[dict], start: float) -> list[dict]:
    """Of the notes of a record up to some time, in the order they were
    added, the starts of the sessions that ran at some point from start
    on: those that began since, and those that were not over by then. A
    session whose launcher was killed is over when the next one takes
    the name of its container."""
    running: dict[object, dict] = {}
    since = []
    for note in notes:
        began = note.get("did") == STARTED
        if float(note["t"]) > start:
            if began:
                since.append(note)
        elif began:
            running[note.get("session")] = note
        else:
            running.pop(note.get("session"), None)
    return [*running.values(), *since]


def start_events(
    host: Host, start: float, end: float, session: str | None = None
) -> tuple[list[tuple[str, str]], list[Event]]:
    """How this project's sessions that ran between two times were
    started, as events. Of one session when it is named. A session is
    started before its transcript begins, so the start of one is looked
    for from before the first of the two times. No summary rows: a start
    is not worth a word when a session ends, a trace makes its own of the
    events (see start_summary)."""
    notes = start_record(host).read(host.project_dir, 0.0, end, session)
    events = map(start_event, running_between(notes, start))
    found = [event for event in events if event]
    return [], sorted(found, key=lambda event: event.when)
