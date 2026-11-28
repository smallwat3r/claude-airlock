"""The watcher, as the sidecar runs it (see __main__.py): it notes what
runs in a session and which process holds each of its TCP connections,
in the lines of the record the package tells of.

It looks, it is not told: nothing short of privileges a sidecar should not
have reports every start of a process. So it reads /proc many times a
second, and what lived shorter than the time between two looks can be
missed. What it does note is what was there.

It runs as root, so that the session, which shares its process namespace,
can neither stop it nor reach its file. To read what a process of the
session holds takes that user's rights though, or capabilities: it takes
the user's identity for file access alone (setfsuid), and lets go of every
capability."""

from __future__ import annotations

import ctypes
import os
import sys
import time
from collections.abc import Callable
from typing import TextIO

from .addresses import RESOLVER, is_loopback
from .cgroup import LIMITS_EVERY, Health, limit_hits
from .linked import Linked, identity
from .proc import ProcessRead, kept_path, process
from .record import LineFile, Note, Room, stamped
from .rules import OpenedOnce, Secrets, Telling
from .tables import Holders, Sockets, sockets, started_last, watched

# Seconds between two looks
INTERVAL = 0.04
# A look that comes later than this after the one before it is late. What
# a look takes is the session's to set: its sockets are read at each, and
# the descriptors of all its processes when a socket is new, so a session
# with enough of either has the looks come as far apart as it likes, and
# what it runs between two of them goes unseen. That cannot be kept from
# it, so it is noted: at once when a look first comes late, then no more
# often than every SLOW_EVERY seconds.
SLOW = 3 * INTERVAL
SLOW_EVERY = 10.0
# A process is looked at each time while it is this young, it is as a rule
# right after it was made that it becomes another program, then this often.
# And each time it holds a socket that is new, before that is said: a
# process can wait for longer, then become another program and connect
YOUNG = 2.0
SETTLED_EVERY = 0.5
# How often the holder of a socket is looked for before it is given up on
MOST_TRIES = 3
# Seconds between two notes that the watcher is still there
HEARTBEAT_EVERY = 30.0
# The processes that hold a socket that are named, the ones started last
MOST_HOLDERS = 8
# Of the process that holds a socket, how many of those it comes from are
# said aloud with it: as many as are shown next to a connection
SAID_PARENTS = 3
# What is said aloud of the connections, of the sockets that wait and of
# their processes stops at this size, with a last word that it did. The
# record goes on, it is what is said aloud that is kept on the host.
MOST_ALOUD = 2 * 1024 * 1024
# What a process is called for short, see Watch.name_of, is cut to so
# many characters
NAME_LENGTH = 64
# The version of the header capset is given, see _take_identity
_CAPABILITY_VERSION_3 = 0x20080522


def _take_identity(uid: int, gid: int) -> None:
    """Read files as the session's user from here on, and hold no
    capability. The process stays root's, so not the session's to signal
    or to look into."""
    libc = ctypes.CDLL(None, use_errno=True)
    libc.setfsgid(gid)
    libc.setfsuid(uid)
    # setfsuid does not say whether it worked, asking again does
    if libc.setfsuid(uid) != uid:
        raise OSError("could not take the identity of the session's user")

    class Header(ctypes.Structure):
        _fields_ = (("version", ctypes.c_uint32), ("pid", ctypes.c_int))

    none = (ctypes.c_uint32 * 6)()
    header = Header(_CAPABILITY_VERSION_3, 0)
    if libc.capset(ctypes.byref(header), ctypes.byref(none)) != 0:
        raise OSError(ctypes.get_errno(), "could not drop the capabilities")


class Watch:
    def __init__(
        self,
        out,
        read_process: Callable[[int], ProcessRead | None] = process,
        secrets: Secrets | None = None,
        proc: str = "/proc",
        *,
        aloud: TextIO,
    ) -> None:
        self._out = out
        # Where it says aloud what follows a session reads, see _speak
        self._aloud = aloud
        self._proc = proc
        self._room = Room()
        # Of the lines that could not be written since the last that was,
        # how many, and the times of the first and of the last of them
        self._unwritten: tuple[int, float, float] | None = None
        # Not itself, nor what started it
        self._own = {os.getpid(), os.getppid()}
        # What reads a process, see process of proc.py
        self._process_of = read_process
        # Each process seen: what it was, when it was first seen and when
        # it was last looked at
        self._processes: dict[int, tuple[tuple, float, float]] = {}
        # The parent of each, and what each was when it was last said
        # aloud next to a socket it holds, see _say_who
        self._parents: dict[int, int] = {}
        self._said: dict[int, tuple] = {}
        # How much was said aloud of connections and their processes,
        # and whether that has stopped, see MOST_ALOUD
        self._spoken = 0
        self._hushed = False
        self._connections: set[tuple[int, str, int]] = set()
        self._listening: set[tuple[int, str, int]] = set()
        self._tries: dict[tuple[int, str, int], int] = {}
        self._holders = Holders()
        self._said_unreadable = False
        # Whether it was said that the sockets were more than are kept
        self._said_too_many = False
        # How often the limit of processes was run into as last noted,
        # and when that was last looked at
        self._limit_hits = 0
        self._limits_seen = 0.0
        self._beat = time.monotonic()
        self._health = Health(self.say, self.name_of)
        # When the look before began, and of the looks that came late
        # since that was last said, and when: how many, the seconds each
        # came after the one before it in all, and the most of those
        self._looked = 0.0
        self._late = 0
        self._late_seconds = 0.0
        self._latest = 0.0
        self._late_said = 0.0
        # Which files hold secrets, and the files of them each process was
        # seen to hold, by the process (its id and when it started), see
        # _look_at_files
        self._secrets = secrets
        self._opened = OpenedOnce()
        self._linked = Linked(secrets) if secrets is not None else None

    def name_of(self, pid: int) -> str:
        """What a process is called for short: its program, else what it
        says it is."""
        known = self._processes.get(pid)
        if not known:
            return "?"
        _, program, argv = known[0]
        return os.path.basename(program or (argv[0] if argv else "?"))[:NAME_LENGTH]

    def note(
        self,
        reserved: bool = False,
        aloud: bool = False,
        counted: bool = False,
        **said: object,
    ) -> None:
        """Add a line to the record, of the part that is reserved or of
        the other, while there is room for it, see Room of record.py. A
        line said aloud goes to the file to say aloud to too, no more of
        them than to the record, and of those that are counted no more
        than MOST_ALOUD, see _speak. The word that the record is full is
        the record's alone."""
        line = stamped(**said)
        fitted = self._room.fitted(line, reserved)
        if fitted is None:
            return
        self._write(fitted)
        if aloud and fitted is line:
            self._speak(line, counted)

    def _write(self, line: str) -> None:
        """Write a line to the record. One that cannot be written (a full
        disk, which a session can bring about) is counted, with when, and
        the watcher goes on: once one can be again, a line says how many
        were not and between which times (see Note.UNWRITTEN), ahead of
        it. A record that would stop at the first is one a session could
        have the watcher write no more of, for as long as it runs, by
        filling the disk for a moment."""
        try:
            if self._unwritten:
                lines, since, until = self._unwritten
                gap = stamped(
                    note=Note.UNWRITTEN, lines=lines, since=since, until=until
                )
                self._out.write(gap)
                self._out.flush()
                self._room.took(gap)
                self._unwritten = None
            self._out.write(line)
            self._out.flush()
        except OSError:
            now = round(time.time(), 3)
            lines, since, _ = self._unwritten or (0, now, now)
            self._unwritten = (lines + 1, since, now)
            return
        self._room.took(line)

    def _speak(self, line: str, counted: bool = False) -> None:
        """Say a line aloud, for what follows the session as it runs: to
        the file it was given. One that is counted, a connection or a
        process next to it, only while less than MOST_ALOUD of them was
        said: how many there are is the session's to choose, and what is
        said is kept until the session is over. Past that a last word
        says so, and no more of them come."""
        if counted:
            if self._hushed:
                return
            if self._spoken + len(line) > MOST_ALOUD:
                self._hushed = True
                line = stamped(note=Note.HUSHED)
            self._spoken += len(line)
        try:
            self._aloud.write(line)
            self._aloud.flush()
        except (OSError, ValueError):
            # Nobody listens, the record has it
            pass

    def _say_who(self, held_by: list[int]) -> None:
        """Say aloud which process holds a socket, ahead of the line of
        the socket: the one started last of those that hold it and those
        it comes from, each as the record has it, unless it was said as
        that before. The record has every process, the output only those
        a connection is tied to. Given the holders in the order they
        started, see _by_start."""
        pid = started_last(held_by) if held_by else 0
        for _ in range(SAID_PARENTS + 1):
            known = self._processes.get(pid)
            if not known or self._hushed:
                return
            what = known[0]
            parent = self._parents.get(pid, 0)
            if self._said.get(pid) != what:
                self._said[pid] = what
                _, program, argv = what
                said = stamped(pid=pid, ppid=parent, exe=program, argv=argv)
                self._speak(said, counted=True)
            pid = parent

    def _by_start(self, pids: list[int]) -> list[int]:
        """Processes in the order they started, by when the kernel says
        each did, the last MOST_HOLDERS of them: the one started last is
        the last. Not by their ids, which start over once they reach the
        most there can be, and a long session gets there. One that was
        not read comes first."""

        def started(pid: int) -> tuple[int, int]:
            known = self._processes.get(pid)
            try:
                return (int(known[0][0]) if known else -1), pid
            except ValueError:
                return -1, pid

        return sorted(pids, key=started)[-MOST_HOLDERS:]

    def say(self, **said: object) -> None:
        """Write a line to the record and say it aloud, see note. The
        line does not use the reserved part of the record."""
        self.note(reserved=False, aloud=True, counted=False, **said)

    def look(self) -> None:
        now = time.monotonic()
        self._keep_pace(now)
        pids = [
            int(name)
            for name in os.listdir("/proc")
            if name.isdigit() and int(name) not in self._own
        ]
        self._look_for_links(pids, now)
        self._look_at_processes(pids, now)
        connected, waiting, passed_over = sockets()
        if passed_over:
            self._passed_over()
        self._look_at_connections(connected, pids)
        self._look_at_listeners(waiting, pids)
        if now - self._beat >= HEARTBEAT_EVERY:
            self._beat = now
            self.note(reserved=True, note=Note.ALIVE)
        if now - self._limits_seen >= LIMITS_EVERY:
            self._limits_seen = now
            self._look_at_limits(pids)
            self._health.look(pids, now)

    def _passed_over(self) -> None:
        """Note once that there were more sockets than are kept, see
        MOST_SOCKETS."""
        if not self._said_too_many:
            self._said_too_many = True
            self.note(reserved=True, note=Note.TOO_MANY_SOCKETS)

    def _keep_pace(self, now: float) -> None:
        """Note that looks came late, see SLOW, by when this one begins:
        how many did since it was last said, how long after the look
        before them in all, and the longest of those. A word of the
        watcher's own, on what the record does not hold for it."""
        apart = now - self._looked if self._looked else 0.0
        self._looked = now
        if apart > SLOW:
            self._late += 1
            self._late_seconds += apart
            self._latest = max(self._latest, apart)
        if self._late and now - self._late_said >= SLOW_EVERY:
            said = {
                "looks": self._late,
                "seconds": round(self._late_seconds, 2),
                "longest": round(self._latest, 2),
            }
            self.note(reserved=True, slow=said)
            self._late, self._late_seconds, self._latest = 0, 0.0, 0.0
            self._late_said = now

    def _look_at_processes(self, pids: list[int], now: float) -> None:
        for pid in set(self._processes).difference(pids):
            del self._processes[pid]
            self._parents.pop(pid, None)
            self._said.pop(pid, None)
        for pid in pids:
            known = self._processes.get(pid)
            if known:
                _, first, last = known
                if now - first > YOUNG and now - last < SETTLED_EVERY:
                    continue
            self._look_at_process(pid, now)
            self._look_at_files(pid)

    def _look_for_links(self, pids: list[int], now: float) -> None:
        """Find the files of secrets by what the kernel knows them by, see
        Linked, under the root of the first process of the session: that
        of its container, whose init docker runs."""
        if self._linked is not None and pids:
            self._linked.look(f"{self._proc}/{min(pids)}/root", now)

    def _look_at_files(self, pid: int) -> None:
        """Note each file of secrets a process holds open that it was not
        seen to hold before, said aloud with the process as a connection
        is. As often as the process is looked at: a file opened and
        closed between two looks is not seen. No more than MOST_OPENED in
        all, then a word that there were more."""
        known = self._processes.get(pid)
        if self._secrets is None or known is None or self._opened.too_many:
            return
        directory = f"{self._proc}/{pid}/fd"
        try:
            descriptors = os.listdir(directory)
        except OSError:
            return
        process = (pid, known[0][0])
        for descriptor in descriptors:
            held = self._held(f"{directory}/{descriptor}")
            if held is None:
                continue
            path, kind = held
            telling = self._opened.take(process, path)
            if telling is Telling.TOO_MANY:
                self.note(reserved=True, note=Note.TOO_MANY_OPENED)
                return
            if telling is Telling.KNOWN:
                continue
            self._say_who([pid])
            self.note(
                reserved=True,
                aloud=True,
                counted=True,
                opened=kept_path(path),
                secret=kind,
                pids=[pid],
            )

    def _held(self, descriptor: str) -> tuple[str, str] | None:
        """The file of secrets a descriptor holds, by the link of /proc it
        is, with its kind: by the path the kernel names it by, else of a
        file held under another name, by what the kernel knows it by (see
        Linked), as the path it has among the files of secrets. None for
        what is none."""
        try:
            path = os.readlink(descriptor)
        except OSError:
            return None
        kind = self._secrets.of(path) if self._secrets else None
        if kind:
            return path, kind
        linked = self._linked
        if linked is None or not linked.known or not path.startswith("/"):
            return None
        try:
            return linked.of(identity(os.stat(descriptor)))
        except OSError:
            return None

    def _look_at_process(self, pid: int, now: float) -> None:
        """Note a process when it is new, or has become another program
        since it was last looked at."""
        known = self._processes.get(pid)
        found = self._process_of(pid)
        if found is None:
            return
        started, parent, program, argv = found
        # A process is another one when it started at another time,
        # and another program when it runs something else
        what = (started, program, argv)
        if not known or known[0] != what:
            self.note(pid=pid, ppid=parent, exe=program, argv=argv)
            known = (what, now, now)
            # The files of secrets it holds are noted again, as held by
            # what it is now: a shell that opens a key and becomes the
            # program that reads it is otherwise all the record names
            self._opened.forget((pid, started))
        self._processes[pid] = (what, known[1], now)
        self._parents[pid] = parent

    def _looked_at_again(self, held_by: list[int]) -> None:
        """Look again at the processes that hold a socket, before it is
        said who holds it: one that is not young any more is looked at
        no more than every SETTLED_EVERY seconds, and can have become the
        program that made the connection since, by an exec of a helper
        that waited for that."""
        now = time.monotonic()
        for pid in held_by:
            self._look_at_process(pid, now)

    def _look_at_connections(self, current: Sockets, pids: list[int]) -> None:
        """Note each new connection with the processes that hold it. One
        whose holder is not found is looked at again, it may be the next
        time. After MOST_TRIES it is noted without one: it is there all
        the same, held by a process that cannot be looked into, which a
        process can make itself, and a connection must not go without a
        word for that. Only those that are watched, see watched of tables.py."""
        current = {key: inode for key, inode in current.items() if watched(key)}
        self._connections &= current.keys()
        self._tries = {key: n for key, n in self._tries.items() if key in current}
        new = {
            key: inode for key, inode in current.items() if key not in self._connections
        }
        if not new:
            return
        holders = self._holders.of(set(new.values()), pids)
        for key, inode in new.items():
            held_by = holders.get(inode, [])
            if not held_by:
                self._tries[key] = self._tries.get(key, 0) + 1
                if self._tries[key] < MOST_TRIES:
                    continue
            self._connections.add(key)
            port, to, to_port = key
            self._looked_at_again(held_by)
            held_by = self._by_start(held_by)
            self._say_who(held_by)
            self.note(
                reserved=True,
                aloud=True,
                counted=True,
                port=port,
                to=to,
                to_port=to_port,
                pids=held_by,
            )
        if not self._holders.readable and not self._said_unreadable:
            self._said_unreadable = True
            self.note(reserved=True, note=Note.UNREADABLE)

    def _look_at_limits(self, pids: list[int]) -> None:
        """Note that the session ran into its limit of processes since
        the last look, with how often it has by now."""
        hits = limit_hits(min(pids)) if pids else None
        if hits is not None and hits > self._limit_hits:
            self._limit_hits = hits
            self.note(reserved=True, limit="pids", hits=hits)

    def _look_at_listeners(self, current: Sockets, pids: list[int]) -> None:
        """Note each socket that started to wait for connections, with
        the processes that hold it, none when those were not found: it is
        there all the same, for whatever else is on the session's network
        to connect to. One on the session's own loopback is nothing else's
        to connect to, and has no part of what is kept for those that
        are: a session opens and closes them as fast as it likes."""
        self._listening &= current.keys()
        new = {
            key: inode
            for key, inode in current.items()
            if key not in self._listening and key[1] != RESOLVER
        }
        if not new:
            return
        holders = self._holders.of(set(new.values()), pids)
        for key, inode in new.items():
            self._listening.add(key)
            port, on, _ = key
            held_by = holders.get(inode, [])
            reachable = not is_loopback(on)
            self._looked_at_again(held_by)
            held_by = self._by_start(held_by)
            if reachable:
                self._say_who(held_by)
            self.note(
                reserved=reachable,
                aloud=reachable,
                counted=True,
                listen=port,
                on=on,
                pids=held_by,
            )


def _aloud_to(path: str) -> TextIO:
    """The file to say aloud to, which the launcher made and mounted:
    opened as the session's user, see _take_identity, and never made
    here, a file that is not there is not to be written."""
    made = os.open(path, os.O_WRONLY | os.O_APPEND | os.O_NOFOLLOW | os.O_CLOEXEC)
    return os.fdopen(made, "w", encoding="utf-8")


# What the watcher is given, see _start_watcher of processes.py
USAGE = "usage: procwatch RECORD UID GID SECRETS ALOUD"


def main(args: list[str]) -> int:
    if len(args) != 5:
        print(USAGE, file=sys.stderr)
        return 2
    path, uid, gid, rules, aloud_path = args
    out = LineFile(path)
    try:
        _take_identity(int(uid), int(gid))
        secrets = Secrets.read(rules)
        aloud = _aloud_to(aloud_path)
        watch = Watch(out, secrets=secrets, aloud=aloud)
        watch.note(reserved=True, note=Note.STARTED, beat=HEARTBEAT_EVERY)
        while True:
            watch.look()
            time.sleep(INTERVAL)
    finally:
        out.close()
