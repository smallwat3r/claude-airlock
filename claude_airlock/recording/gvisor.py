"""What runs in a session under gVisor, as gVisor itself tells it.

A sidecar cannot see into a session under gVisor (see runtime.py): its
processes are the sandbox's own, behind gVisor's kernel. That kernel can
tell what they do though, to a program outside the sandbox (its runtime
monitoring): it sends each point it is asked for, as a protobuf message
behind a header, over a Unix socket of kind SOCK_SEQPACKET it connects to
as a sandbox starts. The launcher listens on one for each session, and
writes what it is told in the lines of procwatch, to the record of
host_health.py: each program a process becomes and each process made,
each connection, each socket of TCP that starts to wait for them, and
each file of secrets opened (see secrets.py). Every start of a program
is told, not looked for, so what lives a moment is not missed, and every
file opened, which a look at what a process holds misses unless it is
still open then.

A runtime of gVisor reads what to send and where from the file it is
registered with (--pod-init-config), when a sandbox is made, and that
file is the same for all of them: the launcher writes its session's
socket into it, under a lock that other launchers wait on, and lets go
once its session runs. A sandbox made meanwhile by something else, which
connects to the session's socket all the same, is told apart by the
container it says it is of, and let go of.

gVisor drops what it cannot send at once, a few tries later (the retries
of the sink), and counts it: a session that opens files faster than the
launcher reads what it is told of them is slowed by those tries, and
what was dropped all the same is noted as a count in the record. It is
not told why a point was dropped, nor which.

Not told: a file opened by openat2 or by a handle, which have no point
of their own, unless it is closed again (close is told with the file's
path, as gVisor finds it); a connection's own port, a connection of the
record is then found by where it went and when, see ProcessRecord.holder;
a socket that waits for connections, under a runsc older than the point
of listen (release-20260727.0). A process's parent is the one that made
it, not the one that took it in once that one was gone.

The record is written on the host, where only the user and root reach,
as gVisor's sinks write: a session can neither stop it nor reach it. The
socket is only the launcher's and root's to connect to, and gVisor runs
as root."""

from __future__ import annotations

import fcntl
import ipaddress
import json
import os
import socket
import struct
import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from typing import TYPE_CHECKING, ClassVar, Protocol

from ..background import ASK_EVERY
from ..files import private_dir
from ..notice import warn
from ..settings import Host
from .processes import SOON_OVER
from .procwatch import (
    Note,
    OpenedOnce,
    Secrets,
    Telling,
    command_line,
    is_loopback,
    kept_path,
    unmapped,
)
from .unix_socket import PrivateSocket

if TYPE_CHECKING:
    from ..sandbox.runtime import Runtime

# The version of the protocol the launcher speaks, gVisor's first
VERSION = 1
# A message of the sink: the size of its header, its type, and how many
# points gVisor dropped so far, in the machine's own order, then the
# message
HEADER = struct.Struct("=HHI")
# The most of a message that is read: of a program started with more
# arguments than that, what came before the cut, see Told.take, and of
# any other message longer than that nothing, it is counted as dropped
MOST_MESSAGE = 1024 * 1024
# How long to wait for the file of the runtime to be the launcher's to
# write, while another launcher starts its session
LOCK_WAIT = 60.0
# What the sink is told of retrying a point it could not send at once:
# so many times, waiting longer each time from the first wait to the
# last, a session that has it tell more than is read is slowed that long
# for each, then the point is dropped
RETRIES = 50
FIRST_WAIT = "100us"
LAST_WAIT = "10ms"
# Of what was told before the record began, the most that is kept for it:
# a session starts a few processes before it, not thousands
MOST_PENDING = 10_000
# The processes kept track of, by their id: a session that has more at
# once than that has those past them told of with the program unknown
MOST_KNOWN = 50_000
# Seconds between two lines on how many points gVisor dropped
DROPPED_EVERY = 5.0
# Numbers of Linux as the session's processes give them to gVisor's
# kernel, the same whatever the host is, not those of errno and socket
# here: what openat is given for a path from the directory the process
# is in, what connect says of a socket that does not wait, the families
# of addresses, and the type of socket TCP is of
AT_FDCWD = -100
EINPROGRESS = 115
AF_INET, AF_INET6 = 2, 10
SOCK_STREAM = 1

# The messages read, by their type (MessageType of gVisor's common.proto)
CONTAINER_START = 1
SENTRY_CLONE = 2
SENTRY_EXEC = 3
SENTRY_TASK_EXIT = 5
SYSCALL_OPEN = 7
SYSCALL_CLOSE = 8
SYSCALL_CONNECT = 10
SYSCALL_LISTEN = 37

# What each point is to say of the task it happened in (ContextData)
CONTEXT = ["time", "thread_id", "group_id", "container_id", "parent_thread_group_id"]
# With the directory a task is in, for a path from there
WITH_CWD = [*CONTEXT, "cwd"]
POINTS = [
    {"name": "container/start", "context_fields": CONTEXT},
    {"name": "sentry/clone", "context_fields": CONTEXT},
    {"name": "sentry/execve", "context_fields": CONTEXT},
    {"name": "sentry/task_exit", "context_fields": CONTEXT},
    {"name": "syscall/connect/exit", "context_fields": CONTEXT},
    # Of runsc release-20260727.0 and later, an older one passes over it
    # (ignore_missing, see pod_init_config)
    {"name": "syscall/listen/exit", "context_fields": CONTEXT},
    {"name": "syscall/open/exit", "context_fields": WITH_CWD},
    {
        "name": "syscall/openat/exit",
        "optional_fields": ["fd_path"],
        "context_fields": WITH_CWD,
    },
    {
        "name": "syscall/close/exit",
        "optional_fields": ["fd_path"],
        "context_fields": CONTEXT,
    },
]


class NotThis(ValueError):
    """What was read is not a message of the kind it was read as."""


class _CutShort(NotThis):
    """What was read ends in the middle of a field."""


def _varint(data: bytes | memoryview, at: int) -> tuple[int, int]:
    """A number as protobuf writes it, and where what follows it is."""
    found = 0
    for shift in range(0, 70, 7):
        if at >= len(data):
            raise _CutShort("a number is cut short")
        byte = data[at]
        at += 1
        found |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return found, at
    raise NotThis("a number is too long")


def _field(data: bytes | memoryview, at: int) -> tuple[int, int | bytes, int]:
    """The field of a message that starts at a place: its number, its
    value, and where what follows it is."""
    key, at = _varint(data, at)
    number, kind = key >> 3, key & 7
    value: int | bytes
    if kind == 0:
        value, at = _varint(data, at)
    elif kind in (1, 5):
        width = 8 if kind == 1 else 4
        value = int.from_bytes(data[at : at + width], "little")
        at += width
    elif kind == 2:
        length, at = _varint(data, at)
        value = bytes(data[at : at + length])
        at += length
    else:
        raise NotThis(f"a field of kind {kind}")
    if at > len(data):
        raise _CutShort("a field is cut short")
    return number, value, at


def _signed(number: int) -> int:
    """A number of 64 bits read as one that can be below zero."""
    return number - (1 << 64) if number >= 1 << 63 else number


@dataclass(frozen=True)
class Message:
    """The fields of a protobuf message by their number, each as often
    as it came: a number, or the bytes of a text or of a message. The
    schema is gVisor's, the fields are read by their numbers there. And
    whether it was cut short, the start of a longer one, see read."""

    fields: dict[int, list[int | bytes]]
    cut: bool = False

    @classmethod
    def read(cls, data: bytes | memoryview, cut: bool = False) -> Message:
        """Raises NotThis for what is not a message. Of the start of one
        (cut), its fields up to the one the cut is in, which is passed
        over: what ends in the middle of a field is no message else."""
        fields: dict[int, list[int | bytes]] = {}
        at = 0
        try:
            while at < len(data):
                number, value, at = _field(data, at)
                fields.setdefault(number, []).append(value)
        except _CutShort:
            if not cut:
                raise
        return cls(fields, cut)

    def number(self, field: int) -> int:
        """The last of a number field, 0 for one not there, as protobuf
        has it."""
        values = [
            value for value in self.fields.get(field, []) if isinstance(value, int)
        ]
        return _signed(values[-1]) if values else 0

    def raw(self, field: int) -> bytes:
        values = [v for v in self.fields.get(field, []) if isinstance(v, bytes)]
        return values[-1] if values else b""

    def text(self, field: int) -> str:
        return self.raw(field).decode("utf-8", "replace")

    def texts(self, field: int) -> list[bytes]:
        return [v for v in self.fields.get(field, []) if isinstance(v, bytes)]

    def message(self, field: int) -> Message:
        return Message.read(self.raw(field))


@dataclass(frozen=True)
class Context:
    """What a point says of the task it happened in (ContextData of
    common.proto): when, the task and its process, by their ids in the
    sandbox, the container, the directory the task is in, and the
    process that made the task's."""

    when: float
    thread: int
    process: int
    container: str
    cwd: str
    parent: int

    @classmethod
    def of(cls, message: Message) -> Context:
        """Of a message whose first field is its context, as all of those
        read are."""
        said = message.message(1)
        nanoseconds = said.number(1)
        return cls(
            nanoseconds / 1e9 if nanoseconds > 0 else time.time(),
            said.number(2),
            said.number(4),
            said.text(6),
            said.text(8),
            said.number(10),
        )


def address(sockaddr: bytes) -> tuple[str, int] | None:
    """Where a connection went, by what connect was given: an address and
    port of IPv4 or IPv6, none for anything else (a Unix socket)."""
    if len(sockaddr) < 2:
        return None
    family = int.from_bytes(sockaddr[:2], "little")
    try:
        if family == AF_INET and len(sockaddr) >= 8:
            found = ipaddress.ip_address(sockaddr[4:8])
        elif family == AF_INET6 and len(sockaddr) >= 24:
            found = ipaddress.ip_address(sockaddr[8:24])
        else:
            return None
    except ValueError:
        return None
    return unmapped(found), int.from_bytes(sockaddr[2:4], "big")


def opened_path(pathname: str, fd: int, cwd: str, fd_path: str) -> str:
    """The path of a file opened, as the process named it: whole when it
    started with a /, else from the directory it was in, or from the one
    it opened it from. Empty when that is not told."""
    if pathname.startswith("/"):
        return pathname
    base = cwd if fd == AT_FDCWD else fd_path
    return os.path.join(base, pathname) if base.startswith("/") else ""


# A line for the record, when it was so, and whether it is of the part of
# the record kept for what is not a process, see HealthRecord.note_at
Line = tuple[float, bool, dict]


class Told:
    """What gVisor tells of one sandbox, as the lines of the record: it
    keeps track of the processes, for each process made to be the
    program the one that made it was, and for a file to be told of once
    for each process."""

    def __init__(self, secrets: Secrets) -> None:
        self._secrets = secrets
        # The bytes any message of a file of secrets has in it, none for
        # rules that cannot be put so: what has none of them is passed
        # over without being read, as most of what is opened is
        self._markers = secrets.markers()
        # Each process: its program and its command line, and the one
        # that made it
        self._known: dict[int, tuple[str, list[str], int]] = {}
        # The files of secrets told of, by the process's id
        self._opened = OpenedOnce()
        # The container the sandbox said it is of, empty until it did
        self.container = ""

    @property
    def too_many_opened(self) -> bool:
        """Whether more files of secrets were opened than are told of."""
        return self._opened.too_many

    def take(self, kind: int, payload: bytes, cut: bool = False) -> list[Line]:
        """What a message of a kind tells, as lines. Raises NotThis for
        one that is not what its kind says. Of one that was cut short,
        longer than the most that is read (cut, see MOST_MESSAGE), what
        came before the cut, where that is all that is needed of it, see
        _CUT_NEEDS: a program started with more arguments than that is
        told with those that came, as a command line the watcher cuts.
        Raises NotThis for any other."""
        needs = self._CUT_NEEDS.get(kind) if cut else ()
        if needs is None:
            raise NotThis("cut short")
        if kind in (SYSCALL_OPEN, SYSCALL_CLOSE) and self._unread(payload):
            return []
        taken = self._TAKEN.get(kind)
        if taken is None:
            return []
        message = Message.read(payload, cut)
        if not set(needs) <= message.fields.keys():
            raise NotThis("cut short of what is needed of it")
        context = Context.of(message)
        if context.container and not self.container:
            self.container = context.container
        return taken(self, message, context)

    def _unread(self, payload: bytes) -> bool:
        """Whether a message of a file is passed over unread: it has none
        of the bytes a path of secrets has, see Secrets.markers."""
        if self._markers is None:
            return False
        return not any(marker in payload for marker in self._markers)

    def _started(self, message: Message, context: Context) -> list[Line]:
        """The container started: its first process, which docker names
        as its program (the init it runs the session under)."""
        argv = [argument.decode("utf-8", "replace") for argument in message.texts(4)]
        self.container = message.text(2) or self.container
        pid = context.process or 1
        return [self._process(context.when, pid, 0, argv[0] if argv else "", argv)]

    def _cloned(self, message: Message, context: Context) -> list[Line]:
        """A task was made: when it is a process, it is the program the
        one that made it is, until it becomes another."""
        made = message.number(4)
        if made <= 0 or made == context.process:
            # A thread of the process, nothing new
            return []
        program, argv, _ = self._known.get(context.process, ("", [], 0))
        return [self._process(context.when, made, context.process, program, argv)]

    def _execed(self, message: Message, context: Context) -> list[Line]:
        """A process became another program: of a message cut short, its
        command line as far as it came, cut."""
        raw = b"\0".join(message.texts(3))
        program = kept_path(message.text(2))
        known = self._known.get(context.process)
        parent = known[2] if known else context.parent
        argv = command_line(raw, cut=message.cut)
        return [self._process(context.when, context.process, parent, program, argv)]

    def _exited(self, _message: Message, context: Context) -> list[Line]:
        """A task ended: of a process, its last, whose id is the
        process's."""
        if context.thread == context.process:
            self._known.pop(context.process, None)
        return []

    def _process(
        self, when: float, pid: int, parent: int, program: str, argv: list[str]
    ) -> Line:
        if pid in self._known or len(self._known) < MOST_KNOWN:
            self._known[pid] = (program, argv, parent)
        # A process that is told of again is another one: its files are
        # told of again as well
        self._opened.forget(pid)
        return when, False, {"pid": pid, "ppid": parent, "exe": program, "argv": argv}

    def _connected(self, message: Message, context: Context) -> list[Line]:
        """A connection was made, or begun: by where it went alone, not
        on the session's own loopback, which no capture has."""
        went = message.message(2)
        if went.number(2) not in (0, EINPROGRESS):
            return []
        to = address(message.raw(6))
        if to is None or not to[1] or is_loopback(to[0]):
            return []
        said = {"port": 0, "to": to[0], "to_port": to[1], "pids": [context.process]}
        return [(context.when, True, said)]

    def _listened(self, message: Message, context: Context) -> list[Line]:
        """A socket of TCP started to wait for connections (Listen of
        syscall.proto): by the address and port gVisor finds it has once
        it does, which it was given where it was bound to none. As the
        watcher notes one: of the part of the record kept for connections
        where it waits on more than the session's own loopback, and not
        where it waits on that alone, which a session opens as fast as it
        likes."""
        went = message.message(2)
        stream = message.number(9) == SOCK_STREAM
        if went.number(2) or message.number(8) not in (AF_INET, AF_INET6) or not stream:
            return []
        on = address(message.raw(7))
        if on is None:
            return []
        said = {"listen": on[1], "on": on[0], "pids": [context.process]}
        return [(context.when, not is_loopback(on[0]), said)]

    def _opened_file(self, message: Message, context: Context) -> list[Line]:
        """A file was opened, by the path the process gave. Not one that
        could not be: an error is said by its number."""
        went = message.message(2)
        if went.number(2) or went.number(1) < 0:
            return []
        path = opened_path(
            message.text(6), message.number(4), context.cwd, message.text(5)
        )
        return self._secret(context, path)

    def _closed(self, message: Message, context: Context) -> list[Line]:
        """A file was closed, by its path as gVisor found it: one opened
        through a link, or in a way that has no point, is told so."""
        return self._secret(context, message.text(5))

    def _secret(self, context: Context, path: str) -> list[Line]:
        kind = self._secrets.of(path)
        if kind is None:
            return []
        telling = self._opened.take(context.process, path)
        if telling is Telling.TOO_MANY:
            return [(context.when, True, {"note": Note.TOO_MANY_OPENED})]
        if telling is Telling.KNOWN:
            return []
        said = {
            "opened": kept_path(path),
            "secret": kind,
            "pids": [context.process],
        }
        return [(context.when, True, said)]

    # Of the messages that are read when cut short, the fields that have
    # to come before the cut: those come in the order of their numbers,
    # and of an exec its context and program before its arguments
    _CUT_NEEDS: ClassVar[dict[int, tuple[int, ...]]] = {SENTRY_EXEC: (1, 2)}

    _TAKEN: ClassVar[dict[int, Callable[[Told, Message, Context], list[Line]]]] = {
        CONTAINER_START: _started,
        SENTRY_CLONE: _cloned,
        SENTRY_EXEC: _execed,
        SENTRY_TASK_EXIT: _exited,
        SYSCALL_OPEN: _opened_file,
        SYSCALL_CLOSE: _closed,
        SYSCALL_CONNECT: _connected,
        SYSCALL_LISTEN: _listened,
    }


def pod_init_config(endpoint: str) -> dict:
    """What a runtime of gVisor is to read as a sandbox starts: the
    points to send, and the socket to send them to. A sandbox whose
    socket is not there starts all the same, and one of an older gVisor
    that lacks some of the points or fields too."""
    sink = {
        "name": "remote",
        "config": {
            "endpoint": endpoint,
            "retries": RETRIES,
            "backoff": FIRST_WAIT,
            "backoff_max": LAST_WAIT,
        },
        "ignore_setup_error": True,
    }
    session = {
        "name": "Default",
        "ignore_missing": True,
        "points": POINTS,
        "sinks": [sink],
    }
    return {"trace_session": session}


class Record(Protocol):
    """What a monitor writes what it was told to: the session's record,
    see HealthRecord of host_health.py."""

    def note_at(self, when: float | None, reserved: bool, said: dict) -> None: ...


class _Locked:
    """The file of the runtime held for one launcher, see pointed_at."""

    def __init__(self, lock: int) -> None:
        self._lock = lock
        self._releasing = threading.Lock()

    def release(self) -> None:
        """Let go of it, once: from the thread that finds the sandbox
        made, or as the session ends."""
        with self._releasing:
            if self._lock < 0:
                return
            with suppress(OSError):
                fcntl.flock(self._lock, fcntl.LOCK_UN)
            os.close(self._lock)
            self._lock = -1


class Monitor:
    """The socket gVisor tells what runs in one session to, and what it
    was told, as lines of the session's record once that has begun (see
    attach). Of the first sandbox that says it is of the session's
    container: another is let go of."""

    def __init__(self, secrets: Secrets, listener: PrivateSocket) -> None:
        self.path = listener.path
        self.secrets = secrets
        self._listener = listener
        # The file of the runtime, held until the session's sandbox is
        # made, see point
        self._held: _Locked | None = None
        # The record, and the container whose sandbox is the session's,
        # once that has begun
        self._record: Record | None = None
        self._container = ""
        # Of what came, how much there was no room for while the record
        # had not begun, and gVisor's count of what it dropped, as last
        # said
        self._passed_over = 0
        self._dropped = 0
        # Whether a sandbox of the container connected, and when what was
        # dropped was last said, see _write
        self._told = False
        self._said_dropped = 0.0
        self._lock = threading.Lock()

    @classmethod
    def listening(cls, host: Host, session: str, secrets: Secrets) -> Monitor:
        """A socket for the session, waited on in the background. Raises
        OSError when it cannot be made."""
        listener = PrivateSocket(host.gvisor_dir, session, socket.SOCK_SEQPACKET, 4)
        monitor = cls(secrets, listener)
        threading.Thread(target=monitor._serve, daemon=True).start()
        return monitor

    def point(self, host: Host) -> bool:
        """Point the file of the runtime at the socket, and hold it so
        until the session's sandbox is made, see pointed_at. False when
        it could not be."""
        self._held = pointed_at(host, self.path)
        return self._held is not None

    @property
    def told(self) -> bool:
        """Whether the session's sandbox told anything."""
        with self._lock:
            return self._told

    @property
    def attached(self) -> bool:
        """Whether the session's record has begun, see attach."""
        with self._lock:
            return self._record is not None

    def sandbox_made(self) -> None:
        """Let go of the file of the runtime: the session's sandbox read
        it as it was made, the next session's is to read it."""
        if self._held is not None:
            self._held.release()

    def attach(self, record: Record, container: str) -> None:
        """Write to the session's record from now on, what came before
        too, of the container of that id."""
        with self._lock:
            self._record, self._container = record, container

    def close(self) -> None:
        self.sandbox_made()
        self._listener.close()

    def _serve(self) -> None:
        # Until it is closed, the session has ended
        while (sandbox := self._listener.accept()) is not None:
            threading.Thread(target=self._read, args=(sandbox,), daemon=True).start()

    def _read(self, sandbox: socket.socket) -> None:
        """Read what one sandbox tells, until it is done or is not of the
        session's container. What it tells before the record has begun,
        or before it is known whose it is, is kept until then."""
        with sandbox:
            try:
                self._shake_hands(sandbox)
            except (OSError, NotThis):
                return
            told = Told(self.secrets)
            buffer = bytearray(MOST_MESSAGE)
            view = memoryview(buffer)
            pending: list[Line] = []
            dropped = 0
            whose: bool | None = None
            while True:
                try:
                    size, _, flags, _ = sandbox.recvmsg_into([buffer])
                except OSError:
                    break
                if not size:
                    break
                if size < HEADER.size:
                    self._pass_over(1)
                    continue
                length, kind, dropped = HEADER.unpack_from(buffer)
                cut = bool(flags & socket.MSG_TRUNC)
                try:
                    lines = told.take(kind, bytes(view[length:size]), cut)
                except NotThis:
                    # Of one cut short, what is not told is counted
                    self._pass_over(int(cut))
                    lines = []
                whose = self._whose(told.container)
                if whose is False:
                    return
                room = MOST_PENDING - len(pending)
                pending += lines[:room]
                self._pass_over(max(len(lines) - room, 0))
                if whose and self._write(pending, dropped):
                    pending = []
            # What was dropped since it was last said, which would wait
            # otherwise for a message that does not come
            if whose:
                self._write(pending, dropped, at_end=True)

    @staticmethod
    def _shake_hands(sandbox: socket.socket) -> None:
        """gVisor says which version of the protocol it speaks first, and
        is told the launcher's."""
        said = Message.read(sandbox.recv(MOST_MESSAGE))
        if said.number(1) < VERSION:
            raise NotThis("an older protocol than the launcher speaks")
        sandbox.sendall(bytes([0x08, VERSION]))

    def _whose(self, container: str) -> bool | None:
        """Whether a sandbox that said it is of a container is the
        session's, none while that is not known."""
        with self._lock:
            if not container or not self._container:
                return None
            return container == self._container

    def _pass_over(self, lines: int) -> None:
        if lines:
            with self._lock:
                self._passed_over += lines

    def _write(self, lines: list[Line], dropped: int, at_end: bool = False) -> bool:
        """Write the lines of the session's sandbox to the record, with a
        word first the first time, and every DROPPED_EVERY seconds at most
        how many points were dropped, by gVisor (dropped) or here, at the
        end of what the sandbox tells whenever that changed: false while
        the record has not begun."""
        with self._lock:
            record = self._record
            if record is None:
                return False
            if not self._told:
                self._told = True
                lines = [(time.time(), True, {"note": Note.MONITORED}), *lines]
            now = time.monotonic()
            gone = dropped + self._passed_over
            due = at_end or now - self._said_dropped >= DROPPED_EVERY
            if gone > self._dropped and due:
                self._dropped, self._said_dropped = gone, now
                lines = [*lines, (time.time(), True, {"dropped": gone})]
        for when, reserved, said in lines:
            record.note_at(when, reserved, said)
        return True


def _waited_for(lock: int, config: str) -> bool:
    """Whether the lock of the file of the runtime was taken, within
    LOCK_WAIT: while another launcher holds it, this one says once that
    it waits, for its session not to seem stuck."""
    until = time.monotonic() + LOCK_WAIT
    said = False
    while True:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            return True
        except BlockingIOError:
            pass
        except OSError:
            return False
        if time.monotonic() >= until:
            return False
        if not said:
            said = True
            warn(
                f"waiting for another launcher to start its session, it holds"
                f" {config} for now, {LOCK_WAIT:.0f} seconds at most"
            )
        time.sleep(ASK_EVERY)


def pointed_at(host: Host, endpoint: str) -> _Locked | None:
    """Point the file a runtime of gVisor reads at a socket, and hold it
    so until released: a sandbox made meanwhile under the runtime sends
    what runs in it there. None when another launcher held it for longer
    than LOCK_WAIT, or it could not be written."""
    try:
        lock = os.open(
            os.path.join(private_dir(host.gvisor_dir), "pod-init.lock"),
            os.O_RDWR | os.O_CREAT | os.O_CLOEXEC,
            0o600,
        )
    except OSError:
        return None
    held = _Locked(lock)
    if not _waited_for(lock, host.pod_init_config):
        held.release()
        return None
    written = f"{host.pod_init_config}.{os.getpid()}"
    try:
        made = os.open(
            written, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_CLOEXEC, 0o600
        )
        with os.fdopen(made, "w", encoding="utf-8") as file:
            json.dump(pod_init_config(endpoint), file)
        os.replace(written, host.pod_init_config)
    except OSError:
        with suppress(OSError):
            os.unlink(written)
        held.release()
        return None
    return held


@contextmanager
def session_monitored(
    host: Host, session: str, runtime: Runtime, secrets: Secrets
) -> Iterator[Monitor | None]:
    """While a session runs, listen for what gVisor tells of it, when
    its runtime can be told to (see Runtime.monitored), with the files
    of secrets of the session. The file of the runtime is held until the
    session's container runs, see pointed_at, or until the session is
    over. None when it cannot be listened for. When the session's record
    began and its sandbox told nothing, that is said once it is over,
    unless it ended within a few seconds."""
    if not runtime.monitored(host.pod_init_config):
        yield None
        return
    unmonitored = f"what runs in this session is not told by {runtime.shown}"
    try:
        monitor = Monitor.listening(host, session, secrets)
    except OSError as problem:
        warn(f"{unmonitored}: {problem}")
        yield None
        return
    if not monitor.point(host):
        monitor.close()
        warn(
            f"{unmonitored}: the file it reads ({host.pod_init_config}) is held"
            " by another launcher, or cannot be written"
        )
        yield None
        return
    started = time.time()
    try:
        yield monitor
    finally:
        monitor.close()
        if monitor.attached and not monitor.told and time.time() - started >= SOON_OVER:
            warn(
                f"what ran in this session was not told by {runtime.shown}, its"
                f" sandbox did not connect to {monitor.path}: is the runtime"
                f" registered with --pod-init-config={host.pod_init_config}?"
                " See docs/sandbox.md"
            )
