"""Recording the memory and CPU use of a session from outside it, for
runtimes where a sidecar cannot see into the session, such as gVisor (see
runtime.py).

The watcher of processes.py cannot see into such a session. Nothing is run
inside the session to replace it either: a watcher running as the session's
user could be stopped or deceived by the session, and one running with more
privileges would put those privileges inside the sandbox.

The launcher reads the cgroup of the session's container on the host
instead, as the user it runs as. This gives the memory the session uses
against its limit, the CPU it uses, the time it was throttled, and the time
it waited for memory, CPU or disk. It does not give the session's processes,
the use of each tmpfs (tmpfs counts as memory), or a meaningful process
count, because the cgroup also counts the runtime's own threads.

The cgroup also says when the session ran into its process limit, which
under gVisor ends the session as a whole. The cgroup is removed with the
container, about a tenth of a second later, so a look every second would
miss it: the launcher waits for the kernel to say that the count changed
and reads it at once (see watch_process_limit).

The readings come from CgroupHealth in procwatch.py and are written in the
watcher's line format, to a file in the same directory, so --trace reads
both kinds of record the same way. While the session runs, the file name
ends in .part. This is how --trace --follow finds it, and how the next
launcher recognises a record whose launcher was killed.

This only works when the Docker daemon runs on this host and uses cgroup
version 2. Otherwise nothing is recorded, and the launcher says so when the
session ends."""

from __future__ import annotations

import os
import select
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass, field
from pathlib import Path

from ..background import ASK_EVERY, in_background, wait_for
from ..docker import docker_output
from ..files import json_object, private_dir
from ..launcher import Launcher, session_alive
from ..notice import warn
from ..settings import Host
from .health import Ended, Sample
from .processes import KEPT_RECORDS, SOON_OVER, Watcher, health_said
from .procwatch import LIMITS_EVERY, MOST_BYTES, CgroupHealth, Note, stamped
from .records import TracedSession, record_traced_session
from .sidecar import keep_latest

# Where the host mounts its cgroups (version 2)
CGROUPS = "/sys/fs/cgroup"
# The suffix of a record's file name while its session runs
PART = ".part"
EXTENSION = Watcher.EXTENSION
# The file of a cgroup that counts how often its process limit kept a
# process or thread from starting, on its line max
PIDS_EVENTS = "pids.events"
# The most that is read of it, it holds a line or two
EVENTS_BYTES = 4096


def container_process(container: str) -> tuple[int, str] | None:
    """The host pid of a running container's main process and the id of
    the container, or None while the container is not running."""
    said = docker_output(
        "container", "inspect", "--format={{.State.Pid}} {{.Id}}", container
    ).split()
    if len(said) != 2 or not said[0].isdigit() or int(said[0]) <= 0:
        return None
    return int(said[0]), said[1]


def cgroup_of(pid: int, container: str, proc: str = "/proc") -> str:
    """The directory of the cgroup that a container's process is in, or
    an empty string when it cannot be determined. That happens with cgroup
    version 1, and when the daemon is not on this host, where the pid
    belongs to an unrelated process or to none. To rule that case out, a
    cgroup is only accepted when its path contains the container's id."""
    try:
        said = Path(proc, str(pid), "cgroup").read_text(encoding="ascii")
    except (OSError, ValueError):
        return ""
    for line in said.splitlines():
        # Version 2 has a single line: 0::/system.slice/docker-<id>.scope
        if line.startswith("0::/") and container in line:
            directory = os.path.normpath(CGROUPS + line[3:])
            if directory.startswith(CGROUPS + "/") and os.path.isdir(directory):
                return directory
    return ""


@dataclass
class HealthRecord:
    """The file in which a launcher records the memory and CPU use of one
    session while it runs. Its first line identifies the session and the
    launcher, so that another launcher can finish the record if this one
    is killed."""

    path: Path
    session: str
    project: str
    start: float
    launcher: Launcher
    _written: int = 0
    # Lines come from the thread that reads the health and from the one
    # that waits on the process limit
    _writing: threading.Lock = field(
        default_factory=threading.Lock, repr=False, compare=False
    )

    @classmethod
    def begin(cls, host: Host, session: str, runtime: str) -> HealthRecord:
        """Start the record of a session started by this launcher.
        runtime is the runtime's name as shown to the user. Raises OSError
        when the file cannot be created."""
        start = time.time()
        name = f"{Watcher.name_for(session)}-{int(start)}.{EXTENSION}{PART}"
        path = Path(private_dir(host.process_records_dir), name)
        made = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC, 0o600)
        os.close(made)
        record = cls(path, session, host.project_dir, start, Launcher.current())
        about = {"session": session, "project": record.project, "start": start}
        fields = {**about, **record.launcher.as_fields()}
        record.note(note=Note.STARTED, outside=runtime, **fields)
        return record

    @classmethod
    def found(cls, path: Path) -> HealthRecord | None:
        """The record in a file that is still being written, or None
        when the file does not start with a valid first line."""
        try:
            with open(path, encoding="utf-8", errors="replace") as file:
                said = json_object(file.readline()) or {}
            if said.get("note") != Note.STARTED:
                return None
            session, project = str(said["session"]), str(said["project"])
            return cls(
                path, session, project, float(said["start"]), Launcher.from_fields(said)
            )
        except (OSError, KeyError, ValueError, TypeError, OverflowError):
            return None

    def note(self, **said: object) -> None:
        """Add a line to the record, in the format the watcher of
        procwatch.py uses. Lines past the size limit are dropped."""
        line = stamped(**said)
        with self._writing:
            if self._written + len(line) > MOST_BYTES:
                return
            with suppress(OSError), open(self.path, "a", encoding="utf-8") as file:
                file.write(line)
                self._written += len(line)

    def keep(self, host: Host, end: float) -> None:
        """Finish the record: remove the .part suffix, add the session
        to the list --trace reads, and delete the oldest records beyond
        the number kept. Does nothing when another launcher has already
        finished this record."""
        kept = self.path.with_name(self.path.name.removesuffix(PART))
        try:
            os.rename(self.path, kept)
        except OSError:
            return
        with suppress(OSError):
            record_traced_session(
                host,
                TracedSession(
                    self.session, self.project, self.start, processes=kept.name, end=end
                ),
            )
            keep_latest(kept.parent, f"*.{EXTENSION}", KEPT_RECORDS)


def being_written(host: Host) -> list[HealthRecord]:
    """The records that are not finished yet, for every project: those
    of running sessions and those left behind by a killed launcher."""
    files = Path(host.process_records_dir).glob(f"*.{EXTENSION}{PART}")
    return [record for file in files if (record := HealthRecord.found(file))]


def running_health(host: Host) -> list[tuple[str, str, float]]:
    """The unfinished records of this project's sessions, each as its
    file path, its session name and its start time."""
    return [
        (str(record.path), record.session, record.start)
        for record in being_written(host)
        if record.project == host.project_dir
    ]


def said_in(path: str, since: float) -> list[Sample | Ended]:
    """The health lines written to a record after the given time, or an
    empty list when the file cannot be read."""
    try:
        with open(path, encoding="utf-8", errors="replace") as file:
            return health_said(file, since)
    except OSError:
        return []


def collect_left_behind(host: Host) -> None:
    """Finish the records of sessions whose launcher was killed. The end
    time of each is the time its file was last written."""
    for record in being_written(host):
        if session_alive(record.launcher, record.session):
            continue
        try:
            end = record.path.stat().st_mtime
        except OSError:
            continue
        record.keep(host, end)


def process_limit_hits(events: int) -> int | None:
    """How often the process limit of a cgroup was run into, read from
    its open pids.events file. None when the count cannot be read, which
    is the case once the cgroup is removed."""
    try:
        said = os.pread(events, EVENTS_BYTES, 0).split()
        return int(said[said.index(b"max") + 1])
    except (OSError, ValueError, IndexError):
        return None


def watch_process_limit(
    cgroup: str, note: Callable[..., None], stop: threading.Event
) -> None:
    """Note each time the cgroup in the given directory runs into its
    process limit, as soon as it happens, in the watcher's format. The
    kernel reports a change of pids.events to whoever waits on the file,
    so the count is read before the cgroup of a session that was ended by
    its limit is removed. Returns when the cgroup is gone, or soon after
    stop is set."""
    try:
        events = os.open(f"{cgroup}/{PIDS_EVENTS}", os.O_RDONLY | os.O_CLOEXEC)
    except OSError:
        return
    try:
        changed = select.poll()
        changed.register(events, select.POLLPRI)
        noted = 0
        while True:
            hits = process_limit_hits(events)
            if hits is None:
                return
            if hits > noted:
                noted = hits
                note(limit="pids", hits=hits)
            # After the read, so that what was counted last is noted too
            if stop.is_set():
                return
            changed.poll(ASK_EVERY * 1000)
    finally:
        os.close(events)


def watch(
    host: Host,
    session: str,
    runtime: str,
    records: list[HealthRecord],
    stop: threading.Event,
) -> None:
    """Wait for the session's container, then record its memory and CPU
    use for as long as its cgroup exists, and each time it runs into its
    process limit. The record is appended to records, which stays empty
    when the cgroup was not found."""
    found = wait_for(lambda: container_process(session), stop)
    cgroup = cgroup_of(*found) if found else ""
    if not cgroup:
        return
    try:
        record = HealthRecord.begin(host, session, runtime)
    except OSError:
        return
    records.append(record)
    health = CgroupHealth(record.note)
    with in_background(watch_process_limit, cgroup, record.note):
        while os.path.isdir(cgroup):
            health.look_at(cgroup, time.monotonic())
            if stop.wait(LIMITS_EVERY):
                return


@contextmanager
def health_recorded(host: Host, session: str, runtime: str) -> Iterator[None]:
    """Record the memory and CPU use of a session while it runs, and
    whether it ran into its process limit, from the cgroup of its
    container. runtime is the runtime's name as shown to
    the user. When the cgroup was not found, this is reported once the
    session is over, unless the session ended within a few seconds."""
    records: list[HealthRecord] = []
    started = time.time()
    try:
        with in_background(watch, host, session, runtime, records):
            yield
    finally:
        for record in records:
            record.keep(host, time.time())
        if not records and time.time() - started >= SOON_OVER:
            warn(
                "the memory and CPU use of this session was"
                " not recorded, because the cgroup of its container was not"
                " found on this host",
            )
