"""Recording what runs in a session and which process made each of its
connections (CLAUDE_AIRLOCK_PROC_LOG, on unless set to 0), and reading that
record for --trace.

The transcript says which tool calls were issued, not what a command went
on to start, and a connection is known by its container: which command
opened it is a guess by the clock. So a sidecar joins the session's process
and network namespaces once it is up and notes, from /proc, each process
it sees and the processes that hold each TCP connection (procwatch.py).
A connection of the capture is then tied to its process by its ports.

The sidecar looks many times a second, it is not told: what lived shorter
than that can be missed, and a connection without a process falls back on
the clock. It comes up a moment after the session, so the very first
moment of one is not covered either.

It runs as root, the session can neither stop it nor reach the record,
which stays in the sidecar until the launcher copies it out. The session
never depends on it: a watcher that did not get to watch is said when the
session is over, and that is all.

Under some runtimes, such as gVisor, a sidecar cannot see into the
session. The launcher then records only memory and CPU use, from outside
the session, see host_health.py."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Iterable, Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import ClassVar

from .background import in_background, wait_for
from .docker import container_running, docker, docker_output, mount_arg
from .health import Ended, Sample, read_health
from .pcap import is_loopback
from .procwatch import Note
from .records import TracedSession
from .settings import Host, Settings
from .sidecar import Sidecar

PROCESSES_SUFFIX = ".procs"
PROCESSES_LABEL = "claude-airlock.processes"
RECORD_FILE = "/processes.jsonl"
WATCHER = os.path.join(os.path.dirname(os.path.realpath(__file__)), "procwatch.py")
# The records are a few hundred kB each as a rule, the oldest go once
# there are more
KEPT_RECORDS = 100
# Of a command line as shown next to a connection
SHOWN_WIDTH = 60
# A session shorter than this may be over before its watcher is up, which
# is then not worth a word
SOON_OVER = 5.0
# How long before a connection of the capture its process may have been
# noted to hold it, and how long after: the two are read at their own pace
HELD_WITHIN = 5.0


class Watcher(Sidecar):
    """The sidecar that notes the processes of one session. It ends with
    the session, whose process namespace it is in."""

    SUFFIX: ClassVar[str] = PROCESSES_SUFFIX
    LABEL: ClassVar[str] = PROCESSES_LABEL
    RECORD: ClassVar[str] = "process record"
    FILE: ClassVar[str] = RECORD_FILE
    EXTENSION: ClassVar[str] = "jsonl"
    KEPT: ClassVar[int] = KEPT_RECORDS
    STOP_SECONDS: ClassVar[int | None] = 1
    MEMORY: ClassVar[str] = "128m"
    # To read as the session's user, see procwatch.py
    CAPABILITIES: ClassVar[tuple[str, ...]] = ("SETUID", "SETGID")

    def directory(self, host: Host) -> str:
        return host.process_records_dir

    def noted(self, file: str, end: float) -> TracedSession:
        return TracedSession(
            self.session, self.project, self.start, processes=file, end=end
        )

    def recorded(self, copied: Path) -> bool:
        return watcher_started(copied)

    def nothing_recorded(self) -> None:
        say_not_recorded(self)


def start_watcher(host: Host, session: str, owner: str, image_tag: str) -> Watcher:
    """Start the sidecar in the namespaces of a session that is up: its
    processes', and its network's, which is owner's (the session, or its
    capture sidecar). It runs the sandbox image, which has Python, as root
    with the two capabilities it takes to read as the session's user, and
    lets go of those itself."""
    watcher = Watcher.for_session(session, host.project_dir)
    docker(
        "run",
        "--detach",
        *watcher.run_args(),
        f"--pid=container:{session}",
        f"--network=container:{owner}",
        mount_arg(WATCHER, "/procwatch.py", "ro,z"),
        "--entrypoint=python3",
        image_tag,
        *("-I", "/procwatch.py", RECORD_FILE, str(os.getuid()), str(os.getgid())),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return watcher


def said_since(watcher: str, since: float) -> list[Sample | Ended]:
    """How a running session was doing since a time, as its watcher said
    it aloud: the record itself stays in the sidecar until the session is
    over, and a command run there to read it would be noted as one of the
    session's. Nothing when it cannot be asked."""
    said = docker_output("logs", f"--since={since:.3f}", watcher)
    return health_said(said.splitlines(), since)


def health_said(lines: Iterable[str], since: float) -> list[Sample | Ended]:
    """The health readings in the lines of a record that are later than
    the given time. Lines that are not valid are skipped."""
    found = []
    for line in lines:
        try:
            said = json.loads(line)
            when = float(said["t"])
            health = read_health(when, said) if when > since else None
        except (ValueError, KeyError, TypeError, AttributeError, RecursionError):
            continue
        if health:
            found.append(health)
    return found


def watcher_started(record: Path) -> bool:
    """Whether a watcher got as far as to watch: it says so first."""
    try:
        with open(record, encoding="utf-8", errors="replace") as file:
            return f'"{Note.STARTED.value}"' in file.readline()
    except OSError:
        return False


def say_not_recorded(watcher: Watcher) -> None:
    """Say that a session's processes were not recorded, with what its
    watcher had to say for itself. Said when the session is over: while it
    runs the terminal is the session's."""
    if time.time() - watcher.start < SOON_OVER:
        return
    print(
        "claude-airlock: the processes of this session were not recorded,"
        " CLAUDE_AIRLOCK_PROC_LOG=0 runs a session without the attempt:\n"
        f"{watcher.last_said(5)}",
        file=sys.stderr,
    )


def watch_when_up(
    host: Host,
    session: str,
    owner: str,
    image_tag: str,
    started: list[Watcher],
    stop: threading.Event,
) -> None:
    """Wait for the session's container, then start its watcher: a
    namespace can only be joined once it is there, by when the launcher
    is waiting on the session, hence the thread."""
    if wait_for(lambda: container_running(session), stop):
        started.append(start_watcher(host, session, owner, image_tag))


@contextmanager
def processes_recorded(
    settings: Settings, host: Host, session: str, owner: str, image_tag: str
) -> Iterator[None]:
    """While a session runs, record its processes. owner is the container
    whose network namespace the session is in."""
    if not settings.proc_log:
        yield
        return
    started: list[Watcher] = []
    try:
        with in_background(watch_when_up, host, session, owner, image_tag, started):
            yield
    finally:
        for watcher in started:
            watcher.collect(host)


@dataclass(frozen=True)
class Process:
    """A process as it was noted: when, what it ran and whose child it
    is."""

    when: float
    pid: int
    parent: int
    program: str
    argv: tuple[str, ...]

    @property
    def name(self) -> str:
        """What it is called for short: its program, else what it says
        it is."""
        return os.path.basename(self.program or (self.argv[0] if self.argv else "?"))

    @property
    def command(self) -> str:
        """Its command line, the program named as it really is: the first
        word of a command line is the process's own to choose."""
        return " ".join([self.name, *self.argv[1:]])


@dataclass(frozen=True)
class Listener:
    """A socket that was noted to wait for connections: when, on which
    port and address, and the processes that held it."""

    when: float
    port: int
    address: str
    pids: tuple[int, ...]

    @property
    def open(self) -> bool:
        """Whether it can be reached from outside the session: not one
        that waits on the session's own loopback alone. A session shares
        its network with the other sessions that run."""
        return not is_loopback(self.address)

    @property
    def at(self) -> str:
        """Where it waits, as written: 0.0.0.0:8080, [::]:8080."""
        address = f"[{self.address}]" if ":" in self.address else self.address
        return f"tcp {address}:{self.port}"


@dataclass
class ProcessRecord:
    """What a watcher noted of one session."""

    # In the order they were noted
    processes: list[Process] = field(default_factory=list)
    # The processes that held each connection, by its port, the address
    # and the port at the other end, with when that was noted
    holders: dict[tuple[int, str, int], list[tuple[float, tuple[int, ...]]]] = field(
        default_factory=dict
    )
    # The sockets that waited for connections, in the order they were noted
    listeners: list[Listener] = field(default_factory=list)
    # How often the session could not start a process for its limit of
    # them, as last noted
    process_limit: int = 0
    # How the session was doing every so often, and each time a process
    # of it was ended for want of memory, see health.py
    samples: list[Sample] = field(default_factory=list)
    ended: list[Ended] = field(default_factory=list)
    # Whether it stopped at its size limit, and whether it could not see
    # which process holds a socket
    full: bool = False
    unreadable: bool = False
    # The runtime's name when the launcher wrote the record from outside
    # the session, with memory and CPU use only (see host_health.py).
    # Empty for a watcher's record.
    outside: str = ""
    _by_pid: dict[int, list[Process]] = field(default_factory=dict, repr=False)

    def take(self, line: str) -> None:
        """Take in a line of the record. It is the watcher's own, but it
        tells of what a session chose to run: a line that does not hold
        up is passed over."""
        try:
            said = json.loads(line)
            when = float(said["t"])
            for key, taken in self._KINDS:
                if key in said:
                    taken(self, when, said)
                    return
            self._process(when, said)
        except (ValueError, KeyError, TypeError, RecursionError):
            return

    def _note(self, _when: float, said: dict) -> None:
        self.full |= said["note"] == Note.FULL
        self.unreadable |= said["note"] == Note.UNREADABLE
        if said["note"] == Note.STARTED:
            self.outside = str(said.get("outside", ""))

    def _limit(self, _when: float, said: dict) -> None:
        if said["limit"] == "pids":
            self.process_limit = max(self.process_limit, int(said["hits"]))

    def _health(self, when: float, said: dict) -> None:
        health = read_health(when, said)
        if isinstance(health, Sample):
            self.samples.append(health)
        elif health:
            self.ended.append(health)

    def _listener(self, when: float, said: dict) -> None:
        pids = tuple(int(pid) for pid in said["pids"])
        self.listeners.append(
            Listener(when, int(said["listen"]), str(said["on"]), pids)
        )

    def _connection(self, when: float, said: dict) -> None:
        key = (int(said["port"]), str(said["to"]), int(said["to_port"]))
        pids = tuple(int(pid) for pid in said["pids"])
        self.holders.setdefault(key, []).append((when, pids))

    def _process(self, when: float, said: dict) -> None:
        argv = tuple(str(argument) for argument in said["argv"])
        found = Process(
            when, int(said["pid"]), int(said["ppid"]), str(said["exe"]), argv
        )
        self.processes.append(found)
        self._by_pid.setdefault(found.pid, []).append(found)

    # What a line of the record tells of, by the key only such a line
    # has, in the order they are looked for. A line with none of them is
    # a process. See procwatch.py for the lines.
    _KINDS: ClassVar[
        tuple[tuple[str, Callable[[ProcessRecord, float, dict], None]], ...]
    ] = (
        ("note", _note),
        ("limit", _limit),
        ("health", _health),
        ("oom", _health),
        ("listen", _listener),
        ("port", _connection),
    )

    def process(self, pid: int, when: float) -> Process | None:
        """What a process id was at a time: the last it was noted as up
        to then, the first when it was only noted later."""
        known = self._by_pid.get(pid)
        if not known:
            return None
        earlier = [found for found in known if found.when <= when]
        return earlier[-1] if earlier else known[0]

    def lineage(self, pid: int, when: float) -> list[Process]:
        """A process and those it comes from, itself first."""
        found: list[Process] = []
        seen: set[int] = set()
        while pid not in seen:
            seen.add(pid)
            process = self.process(pid, when)
            if process is None:
                break
            found.append(process)
            pid = process.parent
        return found

    def holder(
        self, source_port: int, address: str, port: int, when: float
    ) -> list[Process]:
        """The process that held a connection made at a time and those it
        comes from, none when no process was noted to hold it. Of several
        that hold it the one started last: a socket is handed down, the
        one that made it is as a rule the last of the line."""
        noted = [
            (at, pids)
            for at, pids in self.holders.get((source_port, address, port), [])
            if abs(at - when) <= HELD_WITHIN
        ]
        if not noted:
            return []
        at, pids = min(noted, key=lambda found: abs(found[0] - when))
        return self.lineage(max(pids), at) if pids else []


def read_record(path: Path) -> ProcessRecord:
    """What a record file says ran. Raises OSError when it cannot be
    read."""
    record = ProcessRecord()
    with open(path, encoding="utf-8", errors="replace") as file:
        for line in file:
            record.take(line)
    return record


def shown_lineage(lineage: list[Process]) -> str:
    """A process next to its connection: its id and command line, then
    the names of those it comes from."""
    first = lineage[0]
    command = first.command
    if len(command) > SHOWN_WIDTH:
        command = command[: SHOWN_WIDTH - 3] + "..."
    parents = "".join(f" < {parent.name}" for parent in lineage[1:4])
    return f"[{first.pid}] {command}{parents}"


def session_record(host: Host, session: TracedSession) -> ProcessRecord | None:
    """The record of a session's processes, none when it has none or it
    is no longer kept."""
    if not session.processes:
        return None
    try:
        return read_record(Path(host.process_records_dir, session.processes))
    except OSError:
        return None
