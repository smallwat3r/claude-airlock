"""Recording what runs in a session and which process made each of its
connections (CLAUDE_AIRLOCK_PROC_LOG, on unless set to 0), and reading that
record for --trace.

The transcript says which tool calls were issued, not what a command went
on to start, and a connection is known by its container: which command
opened it is a guess by the clock. So a sidecar joins the session's process
and network namespaces once it is up and notes, from /proc, each process
it sees and the processes that hold each TCP connection (procwatch.py).
A connection of the capture is then tied to its process by its ports.

While the session runs the record stays in the sidecar. What its watcher
says aloud is read meanwhile (said_since): how the session is doing, and
each connection with the process that holds it and those that one comes
from, for what follows a session to say who made a connection as it is
made. It says that to a file of the launcher's, mounted in the sidecar
alone (see aloud_path), not to its output: docker keeps the output of a
container for whoever asks, and a session given the docker socket can
ask, of the watchers of every other session too, whose command lines can
carry a token.

The sidecar looks many times a second, it is not told: what lived shorter
than that can be missed, and a connection without a process falls back on
the clock. It comes up a moment after the session, so the very first
moment of one is not covered either. A command of the transcript in whose
time it saw no process is said to be one in a trace, see unseen.py of
report. How long a look takes is the session's to set, by what it has the
sidecar read: looks that came much later than they are meant to are noted
by the sidecar, see Slowed.

It runs as root, the session can neither stop it nor reach the record,
which stays in the sidecar until the launcher copies it out. The session
never depends on it: a watcher that did not get to watch is said when the
session is over, and that is all.

Under some runtimes, such as gVisor, a sidecar cannot see into the
session. The launcher then records memory and CPU use from outside the
session (see host_health.py), and what runs in it as the runtime tells,
where it can (see gvisor.py), in the same lines."""

from __future__ import annotations

import bisect
import json
import math
import operator
import os
import subprocess
import threading
import time
from collections.abc import Callable, Iterable, Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass, field
from pathlib import Path
from typing import ClassVar

from ..background import in_background, wait_for
from ..docker import container_running, docker, mount_arg
from ..files import private_dir, whole_lines, write_whole
from ..notice import warn
from ..settings import Host, Settings
from .health import Ended, Sample, read_health
from .packets import is_loopback
from .procwatch import Note, Secrets, started_last
from .records import TracedSession
from .sidecar import Sidecar

PROCESSES_SUFFIX = "procs"
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
# A watcher that said nothing for so many of its beats has ended, or hung
SILENT_BEATS = 2.5
# Where in the sidecar the file its watcher says aloud to is mounted, and
# the directory of those files among the records
ALOUD_FILE = "/aloud.jsonl"
ALOUD_DIR = "aloud"
# The most of what a watcher said aloud that is read at a time: more than
# it says in one look, MOST_ALOUD bounds the most of it
ALOUD_READ = 4 * 1024 * 1024


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

    def collect(self, host: Host, left_behind: bool = False) -> None:
        """As every sidecar is collected, and what its watcher said aloud
        let go of with it: the record has all of it."""
        try:
            super().collect(host, left_behind)
        finally:
            with suppress(OSError):
                os.unlink(aloud_path(host, self.name))

    def nothing_recorded(self) -> None:
        _say_not_recorded(self)


def aloud_path(host: Host, watcher: str) -> str:
    """The file the watcher of that name says aloud to, see procwatch.py:
    among the records, where no session is given anything. Its name is
    docker's, which has no slash."""
    directory = private_dir(os.path.join(host.process_records_dir, ALOUD_DIR))
    return os.path.join(directory, os.path.basename(watcher) + ".jsonl")


def _start_watcher(
    host: Host, session: str, owner: str, image_tag: str, secrets: Secrets
) -> Watcher:
    """Start the sidecar in the namespaces of a session that is up: its
    processes', and its network's, which is owner's (the session, or its
    capture sidecar). It runs the sandbox image, which has Python, as root
    with the two capabilities it takes to read as the session's user, and
    lets go of those itself. It is told which files hold secrets, see
    secrets.py, and given the file it says aloud to, empty, see
    aloud_path."""
    watcher = Watcher.for_session(session, host.project_dir)
    aloud = aloud_path(host, watcher.name)
    # Made anew, the user's alone: a watcher of an earlier session of the
    # name may have left one, with what it said and the mode it had
    write_whole(aloud, "")
    docker(
        "run",
        "--detach",
        *watcher.run_args(),
        f"--pid=container:{session}",
        f"--network=container:{owner}",
        mount_arg(WATCHER, "/procwatch.py", "ro,z"),
        mount_arg(aloud, ALOUD_FILE, "z"),
        "--entrypoint=python3",
        image_tag,
        *("-I", "/procwatch.py", RECORD_FILE, str(os.getuid()), str(os.getgid())),
        secrets.as_json(),
        ALOUD_FILE,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    return watcher


def said_since(path: str, offset: int) -> tuple[list[str], int]:
    """What the watcher of a running session said aloud past a place in
    the file it says it to (see aloud_path), or what the launcher wrote
    past it in the record it keeps of a session from outside (see
    host_health.py), its lines whole, and where that leaves off: a line
    still being written is read once it is whole. The watcher's own
    record stays in the sidecar until the session is over, and a command
    run there to read it would be noted as one of the session's. Nothing
    when the file cannot be read. How much a watcher says aloud is
    bounded, see MOST_ALOUD of procwatch.py, and so is a record, see
    MOST_BYTES there: no more than ALOUD_READ of either is read at a
    time, see whole_lines."""
    try:
        with open(path, "rb") as file:
            file.seek(offset)
            read = file.read(ALOUD_READ)
    except OSError:
        return [], offset
    lines, taken = whole_lines(read, ALOUD_READ)
    return [line.decode("utf-8", "replace") for line in lines], offset + taken


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


def _say_not_recorded(watcher: Watcher) -> None:
    """Say that a session's processes were not recorded, with what its
    watcher had to say for itself. Said when the session is over: while it
    runs the terminal is the session's."""
    if time.time() - watcher.start < SOON_OVER:
        return
    warn(
        "the processes of this session were not recorded,"
        " CLAUDE_AIRLOCK_PROC_LOG=0 runs a session without the attempt:\n"
        f"{watcher.last_said(5)}",
    )


def _watch_when_up(
    host: Host,
    session: str,
    owner: str,
    image_tag: str,
    secrets: Secrets,
    started: list[Watcher],
    stop: threading.Event,
) -> None:
    """Wait for the session's container, then start its watcher: a
    namespace can only be joined once it is there, by when the launcher
    is waiting on the session, hence the thread."""
    if wait_for(lambda: container_running(session), stop):
        started.append(_start_watcher(host, session, owner, image_tag, secrets))


@contextmanager
def processes_recorded(
    settings: Settings,
    host: Host,
    session: str,
    owner: str,
    image_tag: str,
    secrets: Secrets,
) -> Iterator[None]:
    """While a session runs, record its processes, and the files of
    secrets they open (see secrets.py). owner is the container whose
    network namespace the session is in."""
    if not settings.proc_log:
        yield
        return
    started: list[Watcher] = []
    try:
        with in_background(
            _watch_when_up, host, session, owner, image_tag, secrets, started
        ):
            yield
    finally:
        for watcher in started:
            watcher.collect(host)


# What is said of a process whose program could not be read: it ended
# before the watcher looked, or made itself one that is not looked into
# (prctl PR_SET_DUMPABLE), which leaves the command line it wrote for
# itself readable. The name is then its own word
UNREADABLE_PROGRAM = "NOT READABLE, it is named as it says itself"


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
        """What it is called for short: its program. Where that could
        not be read, what it says it is, marked as that (git?): a
        process can keep its program from being read and call itself
        anything, see UNREADABLE_PROGRAM."""
        if self.program:
            return os.path.basename(self.program)
        return os.path.basename(self.argv[0] if self.argv else "") + "?"

    @property
    def command(self) -> str:
        """Its command line, the program named as it really is: the first
        word of a command line is the process's own to choose."""
        return " ".join([self.name, *self.argv[1:]])


# What a process, a gap of the record and what held a connection are put
# in order by
_noted_when = operator.attrgetter("when")
_until = operator.attrgetter("until")
_held_when = operator.itemgetter(0)


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

    @property
    def holder(self) -> int:
        """Of the processes that held it, the one started last, see
        started_last of procwatch.py. 0 when none was found."""
        return started_last(self.pids) if self.pids else 0


@dataclass(frozen=True)
class Opened:
    """A file of secrets a process was noted to hold open, see Secrets
    of procwatch.py: when, its path as the process held it, the kind of
    secrets it holds (see secrets.py) and the process."""

    when: float
    path: str
    kind: str
    pid: int


@dataclass(frozen=True)
class Slowed:
    """What a watcher noted of its looks that came much later than they
    are meant to: by when, how many did since it last said so, how many
    seconds after the look before them in all, and the longest of those.
    What lived shorter than that in that time may not be in the record,
    which a session can bring about."""

    when: float
    looks: int
    seconds: float
    longest: float


@dataclass(frozen=True)
class Unwritten:
    """What a watcher noted of lines it could not write to its record (a
    full disk, which a session can bring about): from when and until
    when, and how many. What it saw then is not in the record."""

    since: float
    until: float
    lines: int


@dataclass
class ProcessRecord:
    """What a watcher noted of one session."""

    # In the order they were noted
    processes: list[Process] = field(default_factory=list)
    # The processes that held each connection, by its port, the address
    # and the port at the other end, with when that was noted, the
    # earliest first: what the runtime tells of a connection under gVisor
    # has no port of the session, and one address can have thousands
    holders: dict[tuple[int, str, int], list[tuple[float, tuple[int, ...]]]] = field(
        default_factory=dict
    )
    # The sockets that waited for connections, in the order they were noted
    listeners: list[Listener] = field(default_factory=list)
    # The files of secrets that were held open, in the order they were
    # noted, and whether there were more than the watcher notes
    opened: list[Opened] = field(default_factory=list)
    too_many_opened: bool = False
    # How often the session could not start a process for its limit of
    # them, as last noted
    process_limit: int = 0
    # How the session was doing every so often, and each time a process
    # of it was ended for want of memory, see health.py
    samples: list[Sample] = field(default_factory=list)
    ended: list[Ended] = field(default_factory=list)
    # Whether it could not see which process holds a socket, and whether
    # there were more sockets than it keeps, of which it looked for none
    unreadable: bool = False
    too_many_sockets: bool = False
    # Each time it said that its looks came late, in the order it did
    slowed: list[Slowed] = field(default_factory=list)
    # When the watcher got to watch, none for one that did not, and when
    # it stopped noting processes at its size limit, none for one that
    # never did
    watched_from: float | None = None
    full_at: float | None = None
    # Each time lines could not be written to it, in the order it said so
    unwritten: list[Unwritten] = field(default_factory=list)
    # When it said it would say no more aloud of connections and their
    # processes, none for one that did not: of what is read while a
    # session runs, see procwatch.py
    hushed_at: float | None = None
    # Every how many seconds the watcher said it was there, none for one
    # that did not say it would, and the time of the last line it wrote
    beat: float | None = None
    last_line: float = 0.0
    # The runtime's name when the launcher wrote the record from outside
    # the session, with memory and CPU use (see host_health.py). Empty
    # for a watcher's record.
    outside: str = ""
    # Of such a record, from when the runtime told the launcher what ran
    # (see gvisor.py), none when it did not: the record has only memory
    # and CPU use then. And how many of what it would have told it said
    # it could not, as last noted
    monitored_from: float | None = None
    dropped: int = 0
    _by_pid: dict[int, list[Process]] = field(default_factory=dict, repr=False)
    # When each process was noted, the earliest first: the lines of a
    # record come in that order but for a clock that was set back
    _noted_at: list[float] = field(default_factory=list, repr=False)

    def take(self, line: str) -> None:
        """Take in a line of the record. It is the watcher's own, but it
        tells of what a session chose to run: a line that does not hold
        up is passed over."""
        try:
            said = json.loads(line)
            when = float(said["t"])
            self.last_line = max(self.last_line, when)
            for key, taken in self._KINDS:
                if key in said:
                    taken(self, when, said)
                    return
            self._process(when, said)
        except (ValueError, KeyError, TypeError, RecursionError):
            return

    @property
    def full(self) -> bool:
        """Whether it stopped at its size limit."""
        return self.full_at is not None

    @property
    def processes_known(self) -> bool:
        """Whether the record tells what ran: a watcher's, or one the
        runtime told the launcher of."""
        return not self.outside or self.monitored_from is not None

    @property
    def limit_ends_session(self) -> bool:
        """Whether running into the process limit ends the session as a
        whole. That is so under the runtimes the launcher records from
        outside, where the host's kernel sees a single program. Under
        Docker's own, what the session tried to start did not."""
        return bool(self.outside)

    def _note(self, when: float, said: dict) -> None:
        note = said["note"]
        self.unreadable |= note == Note.UNREADABLE
        self.too_many_sockets |= note == Note.TOO_MANY_SOCKETS
        # Each as first said, should a line say it again
        if note == Note.FULL and self.full_at is None:
            self.full_at = when
        if note == Note.HUSHED and self.hushed_at is None:
            self.hushed_at = when
        self.too_many_opened |= note == Note.TOO_MANY_OPENED
        if note == Note.MONITORED and self.monitored_from is None:
            self.monitored_from = when
        if note == Note.UNWRITTEN:
            gap = Unwritten(
                float(said["since"]), float(said["until"]), int(said["lines"])
            )
            # Not one that says nothing, or what is no length of time
            if gap.lines > 0 and gap.since <= gap.until < math.inf:
                self.unwritten.append(gap)
        if note == Note.STARTED:
            beat = said.get("beat")
            if isinstance(beat, (int, float)) and not isinstance(beat, bool):
                self.beat = float(beat) if beat > 0 else None
            self.outside = str(said.get("outside", ""))
            if self.watched_from is None:
                self.watched_from = when

    def _limit(self, _when: float, said: dict) -> None:
        if said["limit"] == "pids":
            self.process_limit = max(self.process_limit, int(said["hits"]))

    def _health(self, when: float, said: dict) -> None:
        health = read_health(when, said)
        if isinstance(health, Sample):
            self.samples.append(health)
        elif health:
            self.ended.append(health)

    def _slowed(self, when: float, said: dict) -> None:
        slow = said["slow"]
        found = Slowed(
            when, int(slow["looks"]), float(slow["seconds"]), float(slow["longest"])
        )
        # Not one that says nothing, or what is no length of time
        if found.looks > 0 and 0 < found.longest <= found.seconds < math.inf:
            self.slowed.append(found)

    def _listener(self, when: float, said: dict) -> None:
        pids = tuple(int(pid) for pid in said["pids"])
        self.listeners.append(
            Listener(when, int(said["listen"]), str(said["on"]), pids)
        )

    def _opened(self, when: float, said: dict) -> None:
        pids = [int(pid) for pid in said["pids"]]
        self.opened.append(
            Opened(when, str(said["opened"]), str(said["secret"]), pids[0])
        )

    def _dropped(self, _when: float, said: dict) -> None:
        self.dropped = max(self.dropped, int(said["dropped"]))

    def _connection(self, when: float, said: dict) -> None:
        key = (int(said["port"]), str(said["to"]), int(said["to_port"]))
        pids = tuple(int(pid) for pid in said["pids"])
        # By when, which a time that is no number would not keep in order
        if math.isfinite(when):
            bisect.insort(
                self.holders.setdefault(key, []), (when, pids), key=_held_when
            )

    def _process(self, when: float, said: dict) -> None:
        argv = tuple(str(argument) for argument in said["argv"])
        found = Process(
            when, int(said["pid"]), int(said["ppid"]), str(said["exe"]), argv
        )
        self.processes.append(found)
        # By when each was noted, so that what a pid was at a time is
        # found without going through all it was: a process that writes
        # its own command line anew is noted as often as it likes
        bisect.insort(self._by_pid.setdefault(found.pid, []), found, key=_noted_when)
        bisect.insort(self._noted_at, when)

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
        ("slow", _slowed),
        ("listen", _listener),
        ("opened", _opened),
        ("dropped", _dropped),
        ("port", _connection),
    )

    def process(self, pid: int, when: float) -> Process | None:
        """What a process id was at a time: the last it was noted as up
        to then, the first when it was only noted later."""
        known = self._by_pid.get(pid)
        if not known:
            return None
        at = bisect.bisect_right(known, when, key=_noted_when)
        return known[at - 1] if at else known[0]

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
        that hold it the one started last, the last of them as the watcher
        lists them (see started_last of procwatch.py): a socket is handed
        down, the one that made it is as a rule the last of the line."""
        noted = self._held(source_port, address, port, when)
        if not noted:
            return []
        at, pids = min(noted, key=lambda found: abs(found[0] - when))
        return self.lineage(started_last(pids), at) if pids else []

    def hidden_holder(
        self, source_port: int, address: str, port: int, when: float
    ) -> bool:
        """Whether a connection made at a time was only ever noted
        without a process that holds it: the watcher saw it and could
        look into none that did, see procwatch.py."""
        noted = [pids for _, pids in self._held(source_port, address, port, when)]
        return bool(noted) and not any(noted)

    def _held(
        self, source_port: int, address: str, port: int, when: float
    ) -> list[tuple[float, tuple[int, ...]]]:
        """What was noted of the processes that held a connection made at
        a time: by its ports, else by where it went alone, as the runtime
        tells of a connection (see gvisor.py), without the port it was
        made from. Those within HELD_WITHIN of the time, looked up by it."""
        for key in ((source_port, address, port), (0, address, port)):
            held = self.holders.get(key, [])
            first = bisect.bisect_left(held, when - HELD_WITHIN, key=_held_when)
            last = bisect.bisect_right(held, when + HELD_WITHIN, key=_held_when)
            if first < last:
                return held[first:last]
        return []

    def silent_from(self, until: float) -> float | None:
        """When its watcher last said anything, if that was longer
        before a time than it ever goes without a word: the watcher had
        ended by then, or hung, and what ran after it is not in the
        record. None for one that said something to the last, and for
        one that never said how often it would. Asked of the time its
        session ended, a record with nothing in it past a point reads
        as a session that ran nothing."""
        if not self.beat or self.watched_from is None or not math.isfinite(until):
            return None
        silent = until > self.last_line + self.beat * SILENT_BEATS
        return self.last_line if silent else None

    def noted_processes(
        self, start: float, end: float, within: float = 0.0
    ) -> bool | None:
        """Whether a process was noted between two times, or within so
        many seconds of them. None when the record cannot tell: the
        launcher wrote it from outside the session, or its watcher was
        not up yet at the first of them, had stopped noting processes by
        the second, or could not write some of them in between."""
        if not self.processes_known or self.watched_from is None:
            return None
        if start < max(self.watched_from, self.monitored_from or 0.0):
            return None
        if self.full_at is not None and end > self.full_at:
            return None
        # The gaps come in the order of their times: the first that ends
        # from the start on is the one that may be in between
        at = bisect.bisect_left(self.unwritten, start - within, key=_until)
        if at < len(self.unwritten) and self.unwritten[at].since <= end + within:
            return None
        if self.silent_from(end) is not None:
            return None
        first = bisect.bisect_left(self._noted_at, start - within)
        return first < len(self._noted_at) and self._noted_at[first] <= end + within


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
