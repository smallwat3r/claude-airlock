"""Recording what runs in a session and which process made each of its
connections (CLAUDE_DOCKER_PROC_LOG, on unless set to 0), and reading that
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
session is over, and that is all."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path
from typing import ClassVar

from .capture import Sidecar
from .docker import Launcher, docker, docker_ok, mount_arg, session_alive
from .network import sidecar_running
from .records import NetSession, record_net_session
from .settings import Host, Settings, private_dir

PROCESSES_SUFFIX = ".procs"
PROCESSES_LABEL = "claude-sandbox.processes"
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
    """The sidecar that notes the processes of one session."""

    SUFFIX: ClassVar[str] = PROCESSES_SUFFIX
    LABEL: ClassVar[str] = PROCESSES_LABEL


def start_watcher(host: Host, session: str, owner: str, image_tag: str) -> Watcher:
    """Start the sidecar in the namespaces of a session that is up: its
    processes', and its network's, which is owner's (the session, or its
    capture sidecar). It runs the sandbox image, which has Python, as root
    with the two capabilities it takes to read as the session's user, and
    lets go of those itself."""
    watcher = Watcher(
        session + PROCESSES_SUFFIX, host.project_dir, time.time(), Launcher.current()
    )
    docker(
        "run",
        "--detach",
        f"--name={watcher.name}",
        f"--pid=container:{session}",
        f"--network=container:{owner}",
        f"--label={PROCESSES_LABEL}={watcher.label}",
        "--user=0:0",
        "--cap-drop=ALL",
        "--cap-add=SETUID",
        "--cap-add=SETGID",
        "--security-opt=no-new-privileges",
        "--memory=128m",
        "--pids-limit=16",
        mount_arg(WATCHER, "/procwatch.py", "ro,z"),
        "--entrypoint=python3",
        image_tag,
        *("-I", "/procwatch.py", RECORD_FILE, str(os.getuid()), str(os.getgid())),
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return watcher


def collect_record(host: Host, watcher: Watcher) -> None:
    """Copy a watcher's record to the host and note which project and
    time it covers, for --trace to find it by. The sidecar ends with the
    session, whose process namespace it is in."""
    docker_ok("stop", "--time=1", watcher.name)
    try:
        directory = Path(private_dir(host.process_records_dir))
        target = directory / f"{watcher.name}-{int(watcher.start)}.jsonl"
        copied = docker_ok("cp", f"{watcher.name}:{RECORD_FILE}", str(target))
        if copied and watcher_started(target):
            session = NetSession(
                watcher.session,
                watcher.project,
                watcher.start,
                processes=target.name,
                end=time.time(),
            )
            record_net_session(host, session)
        else:
            target.unlink(missing_ok=True)
            say_not_recorded(watcher)
        kept = sorted(directory.glob("*.jsonl"), key=lambda file: file.stat().st_mtime)
        for old in kept[:-KEPT_RECORDS]:
            old.unlink(missing_ok=True)
    except OSError as problem:
        print(
            f"claude-docker: the process record was not kept: {problem}",
            file=sys.stderr,
        )
    finally:
        docker_ok("rm", "--force", watcher.name)


def watcher_started(record: Path) -> bool:
    """Whether a watcher got as far as to watch: it says so first."""
    try:
        with open(record, encoding="utf-8", errors="replace") as file:
            return '"started"' in file.readline()
    except OSError:
        return False


def say_not_recorded(watcher: Watcher) -> None:
    """Say that a session's processes were not recorded, with what its
    watcher had to say for itself. Said when the session is over: while it
    runs the terminal is the session's."""
    if time.time() - watcher.start < SOON_OVER:
        return
    said = docker(
        "logs",
        "--tail=5",
        watcher.name,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
    )
    print(
        "claude-docker: the processes of this session were not recorded,"
        " CLAUDE_DOCKER_PROC_LOG=0 runs a session without the attempt:\n"
        f"{said.stdout.strip()}",
        file=sys.stderr,
    )


def collect_ended_records(host: Host) -> None:
    """Collect what sessions that ended without their launcher left
    behind, as collect_ended_captures does."""
    for watcher in Watcher.listed(ended_too=True):
        if not session_alive(watcher.launcher, watcher.session):
            collect_record(host, watcher)


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
    while not sidecar_running(session):
        if stop.wait(0.2):
            return
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
    stop = threading.Event()
    started: list[Watcher] = []
    waiting = threading.Thread(
        target=watch_when_up,
        args=(host, session, owner, image_tag, started, stop),
        daemon=True,
    )
    waiting.start()
    try:
        yield
    finally:
        stop.set()
        waiting.join()
        for watcher in started:
            collect_record(host, watcher)


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
    # Whether it stopped at its size limit, and whether it could not see
    # which process holds a socket
    full: bool = False
    unreadable: bool = False
    _by_pid: dict[int, list[Process]] = field(default_factory=dict, repr=False)

    def take(self, line: str) -> None:
        """Take in a line of the record. It is the watcher's own, but it
        tells of what a session chose to run: a line that does not hold
        up is passed over."""
        try:
            said = json.loads(line)
            when = float(said["t"])
            if "note" in said:
                self.full |= said["note"] == "full"
                self.unreadable |= said["note"] == "unreadable"
            elif "port" in said:
                key = (int(said["port"]), str(said["to"]), int(said["to_port"]))
                pids = tuple(int(pid) for pid in said["pids"])
                self.holders.setdefault(key, []).append((when, pids))
            else:
                argv = tuple(str(argument) for argument in said["argv"])
                found = Process(
                    when, int(said["pid"]), int(said["ppid"]), str(said["exe"]), argv
                )
                self.processes.append(found)
                self._by_pid.setdefault(found.pid, []).append(found)
        except (ValueError, KeyError, TypeError, RecursionError):
            return

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
