"""How the sandbox of each session was started: the runtime it runs under,
its image, its limits of memory, processes and CPUs, whether its network
is filtered, what is recorded of it, what is open to it beyond the
defaults, what is mounted next to the project, the plugins switched on
for it and the language servers its image gives it.

The launcher notes it as a session starts, and notes when the session is
over, in a record of its own (see notes.py). A chat says it first,
--trace shows it in its header and ahead of what the session did, and
--trace --follow as a session starts. A transcript tells none of it, and
the settings of a later day are not those a session ran with."""

from __future__ import annotations

import dataclasses
import math
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from typing import Any

from ..events import Event, Kind, Who, flat
from ..sandbox.mounts import ExtraDir
from ..sandbox.runtime import Runtime
from ..sandbox.socket_proxy import has_socket_proxy
from ..settings import Host, Settings, SocketAccess
from .notes import Notes

# The notes kept, two per session
KEPT_STARTS = 2000
# What a note says a session did
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
# The lists of a note that are said when they hold anything, each with
# what it is said as
SAID_WHEN_ANY = (
    ("open", "open"),
    ("mounted", "dirs"),
    ("plugins", "plugins"),
    ("language servers", "servers"),
)


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
    # Whether the user is asked about a host the filter does not allow
    net_ask: bool = False
    # What the launcher records of the session from outside it
    recorded: tuple[str, ...] = ()
    # What is open to the session that is closed by default
    open: tuple[str, ...] = ()
    # What is mounted next to the project, (ro) after a read-only one
    dirs: tuple[str, ...] = ()
    # The plugins switched on, each with its version, see plugins.py
    plugins: tuple[str, ...] = ()
    # The language servers of the image, given to claude as a plugin of
    # the launcher's own that no settings switch on, see image.py
    servers: tuple[str, ...] = ()

    @classmethod
    def of(
        cls,
        settings: Settings,
        runtime: Runtime,
        image: str,
        dirs: Iterable[ExtraDir],
        *,
        ssh_agent: bool,
        net_ask: bool = False,
        plugins: Iterable[str] = (),
        servers: Iterable[str] = (),
    ) -> Start:
        """The start of a session with those settings, under that runtime
        and in a container of that image, the SSH agent forwarded or
        not, the user asked about the hosts its filter does not allow or
        not, with those plugins switched on and those language servers
        of the image."""
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
            net_ask=net_ask,
            recorded=tuple(recorded),
            open=tuple(name for on, name in switches if on),
            dirs=tuple(
                extra.path + (" (ro)" if extra.read_only else "") for extra in dirs
            ),
            plugins=tuple(plugins),
            servers=tuple(servers),
        )

    @classmethod
    def from_note(cls, said: dict) -> Start:
        """The start a note of the record tells of. The record is the
        launcher's own, it is still read with care and cleaned like the
        rest: a name or a path in it was not chosen by the launcher. Each
        value is read as what it is declared to be here, so a value added
        to a start is read too."""
        read = {name.name: _READ[str(name.type)] for name in dataclasses.fields(cls)}
        return cls(**{name: reader(said, name) for name, reader in read.items()})

    def fields(self) -> dict[str, object]:
        """The start as the values of its event."""
        said = dataclasses.asdict(self)
        return {
            name: list(value) if isinstance(value, tuple) else value
            for name, value in said.items()
        }

    def under(self, container: str) -> str:
        """The container of the start and the runtime it runs under."""
        return f"{container} under {self.runtime or 'an unknown runtime'}"

    @property
    def limits(self) -> str:
        """The limits of the start, as they were set."""
        cpus = f"cpus {self.cpus}" if self.cpus else "all CPUs"
        return f"memory {self.memory}, processes {self.pids}, {cpus}"

    @property
    def network(self) -> str:
        if self.asks:
            return "filtered, asks"
        return "filtered" if self.net_filter else "open"

    @property
    def asks(self) -> bool:
        """Whether the user is asked about the hosts the filter does not
        allow. Only a filter asks, whatever a note says."""
        return self.net_filter and self.net_ask


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


def _texts(said: dict, key: str) -> tuple[str, ...]:
    """A list of a note as texts, each on one line."""
    values = said.get(key)
    # A list as read from the record, a tuple as the launcher noted it
    if not isinstance(values, (list, tuple)):
        return ()
    return tuple(flat(value) for value in values if isinstance(value, str))


def _switch(said: dict, key: str) -> bool:
    """A value of a note that is on or off, off for one that is neither."""
    return said.get(key) is True


# How each value of a start is read from a note, by what Start declares
# it to be
_READ: dict[str, Callable[[dict, str], Any]] = {
    "str": _text,
    "bool": _switch,
    "tuple[str, ...]": _texts,
}


def start_event(said: dict) -> Event | None:
    """A note of the record as an event, none for one that is not the
    start of a session."""
    return _shown(said) if said.get("did") == STARTED else None


def _shown(said: dict) -> Event:
    """The note of a start as an event."""
    start = Start.from_note(said)
    container = _text(said, "session")
    filtered = "filtered to the allowed domains" if start.net_filter else "open"
    if start.asks:
        filtered += ", the user is asked about others"
    details = [
        start.under(container) + (f", image {start.image}" if start.image else ""),
        f"limits: {start.limits}",
        f"network: {filtered}",
        "recorded: " + (", ".join(start.recorded) or "nothing"),
        # Said when there is any
        *(
            f"{label}: " + ", ".join(getattr(start, key))
            for label, key in SAID_WHEN_ANY
            if getattr(start, key)
        ),
    ]
    fields = {"container": container, **start.fields()}
    return Event(float(said["t"]), Who.SANDBOX, Kind.STARTED, details, fields)


def start_summary(event: Event) -> str:
    """A start in one line, for the header of a trace."""
    start = Start.from_note(event.fields)
    where = start.under(event.fields["container"])
    return f"{where}, {start.limits}, network {start.network}"


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


def stay_between(host: Host, start: float, end: float) -> tuple[float, float]:
    """The span of time from start to end, made as long as the stay of
    this project's sessions that ran at some point of it: from when the
    first was started to when the last was over. What a session did is
    looked for over all of its stay, see Recorded.stay. Not past the
    end for one that is not noted to be over: it still runs, or its
    launcher was killed, and all that came since is not its own."""
    began: dict[object, float] = {}
    stays: list[tuple[float, float]] = []
    for note in start_record(host).read(host.project_dir, 0.0, math.inf):
        when, session = float(note["t"]), note.get("session")
        if session in began:
            # Over, or its name taken by the next one
            stays.append((began.pop(session), when))
        if note.get("did") == STARTED:
            began[session] = when
    stays += [(when, end) for when in began.values()]
    there = [(first, last) for first, last in stays if first <= end and last >= start]
    return (
        min([start, *(first for first, _ in there)]),
        max([end, *(last for _, last in there)]),
    )


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
