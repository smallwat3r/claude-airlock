"""Notes what runs in a session and which process holds each of its TCP
connections, a JSON object per line. Run by the launcher in a sidecar that
shares the session's process and network namespaces (see processes.py),
not part of the launcher itself: it has to stand alone, the sidecar has
nothing of the package.

It looks, it is not told: nothing short of privileges a sidecar should not
have reports every start of a process. So it reads /proc many times a
second, and what lived shorter than the time between two looks can be
missed. What it does note is what was there.

    {"t": 1.5, "pid": 812, "ppid": 640, "exe": "/usr/bin/curl", "argv": [...]}
    {"t": 1.6, "port": 40212, "to": "203.0.113.9", "to_port": 443, "pids": [812]}
    {"t": 1.7, "listen": 8080, "on": "0.0.0.0", "pids": [812]}
    {"t": 2.0, "limit": "pids", "hits": 3}
    {"t": 3.0, "health": {"mem": [used, limit], "cpu": 240.0, "pids": [87, 512], ...}}
    {"t": 4.0, "oom": 1, "gone": [[812, 9876543210, "node"]]}
    {"t": 5.0, "slow": {"looks": 12, "seconds": 2.6, "longest": 0.31}}
    {"t": 6.0, "opened": "/home/me/.config/gh/hosts.yml", "secret": "gh", "pids": [812]}
    {"t": 9.0, "note": "..."}

The first when a process is first seen or has become another program, the
second when a connection is, with the processes that hold its socket, the
third when a socket starts to wait for connections, the fourth when the
session could not start a process for its limit of them, with how often
that has been so. The fifth every HEALTH_EVERY seconds, and out of turn
when the session comes near a limit: how much of its memory, CPUs,
processes and tmpfs it uses, how long it was stalled for want of them and
its largest processes, as its cgroup says (version 2, of version 1 only
what /proc gives). The sixth when a process of it was ended for want of
memory, with the large ones that are gone since. Those two are written to
the watcher's output as well, for what follows a session as it runs: the
record stays in the sidecar until the session is over. So are the second
and the third, of what is not on the session's own loopback, each after
the first of the process that holds the socket and of those it comes
from: which process made a connection is then known while the session
runs, without all its processes being said aloud. No more of that than
MOST_ALOUD, the output of a sidecar is kept by docker until the session
is over. The seventh when
looks came much later than they are meant to, which is the session's
doing: how many did since it was last said, how long after the look before
them in all, and the longest of those. What lived shorter than that, then,
was not seen. The eighth when a process is seen to hold a file of
secrets open (see Secrets), with the kind of secrets it holds, once for
each process and file, and said aloud with the process as a connection
is. A file a process opened and closed again between two looks is not
seen.

It runs as root, so that the session, which shares its process namespace,
can neither stop it nor reach its file. To read what a process of the
session holds takes that user's rights though, or capabilities: it takes
the user's identity for file access alone (setfsuid), and lets go of every
capability."""

from __future__ import annotations

import ctypes
import enum
import fnmatch
import ipaddress
import json
import os
import sys
import time
from collections.abc import Callable, Hashable, Mapping, Sequence
from typing import NamedTuple

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
# What is kept of a command line: so many arguments, of so many characters
# each and in all. A command line is the session's to make as long as it
# likes, and a few hundred long ones must not be what fills the record.
MOST_ARGUMENTS = 64
MOST_ARGUMENT = 512
MOST_COMMAND = 2048
# What stands for the rest of a command line that was cut
CUT = "..."
# How often the holder of a socket is looked for before it is given up on
MOST_TRIES = 3
# The record stops at this size, which bounds what a session can make the
# sidecar write
MOST_BYTES = 20 * 1024 * 1024
# Of that, what is kept for the connections and the sockets that wait for
# them, once the processes have used up the rest: which process made a
# connection is what the record is for, and a session that starts
# processes without end must not be rid of it that way
RESERVED = 4 * 1024 * 1024
# Of that again, what is kept for the record to say that it is full: its
# last line, whichever part filled first
LAST_WORD = 256
TCP_LISTEN = "0A"
# Seconds between two looks at what the session's limits say
LIMITS_EVERY = 1.0
# Where a container finds how often its limit of processes kept it from
# starting one, under the root of one of its processes: with cgroup v2,
# then v1. The watcher is in another container, with another limit.
PIDS_EVENTS = ("sys/fs/cgroup/pids.events", "sys/fs/cgroup/pids/pids.events")
# Where docker's own resolver waits in every container, not the session's
RESOLVER = "127.0.0.11"
# Seconds between two notes that the watcher is still there
HEARTBEAT_EVERY = 30.0
# Seconds between two lines on how the session is doing
HEALTH_EVERY = 30.0
# The percent of a limit from which the session is near it, and at it. A
# line is written out of turn when one is first reached, and again once
# the use has been this much lower in between, no more often than every
# so many seconds: the session can go up and down as it likes.
NEAR_LIMIT = (70, 90)
WELL_BELOW = 5
OUT_OF_TURN_EVERY = 5.0
# The files of secrets seen open that are noted, one for each process and
# file: a session can open them in as many processes as it likes, and
# must not fill the part of the record kept for its connections that way
MOST_OPENED = 1000
# What the kernel puts after the path of a file that was removed while
# it was open
DELETED = " (deleted)"
# The largest processes that are named, and the tmpfs that are looked at
LARGEST = 3
# The processes that hold a socket that are named, the ones started last
MOST_HOLDERS = 8
# Of the process that holds a socket, how many of those it comes from are
# said aloud with it: as many as are shown next to a connection
SAID_PARENTS = 3
# What is said aloud of the connections, of the sockets that wait and of
# their processes stops at this size, with a last word that it did. The
# record goes on, it is the output alone that docker keeps.
MOST_ALOUD = 2 * 1024 * 1024
MOST_TMPFS = 16
NAME_LENGTH = 64
# Where a container finds what it uses and may use, under the root of one
# of its processes (cgroup v2)
CGROUP = "sys/fs/cgroup"
PAGE = os.sysconf("SC_PAGE_SIZE")
_CAPABILITY_VERSION_3 = 0x20080522


class Note(enum.StrEnum):
    """The notes a record can hold about itself, as the value of "note"
    in a line."""

    # The first line: the watcher got as far as watching
    STARTED = "started"
    # The record reached its size limit
    FULL = "full"
    # The watcher could not see which process holds a socket
    UNREADABLE = "unreadable"
    # The watcher is still there: said every HEARTBEAT_EVERY seconds, so
    # that a record that stops being written to for want of a watcher
    # (killed, crashed) is told from a session with nothing to note
    ALIVE = "alive"
    # Said aloud alone, as the last of what is said there of connections
    # and their processes, see MOST_ALOUD: the record has the rest
    HUSHED = "hushed"
    # There were more sockets at once than are kept, see MOST_SOCKETS: the
    # processes of the rest were not looked for
    TOO_MANY_SOCKETS = "too many sockets"
    # Lines that could not be written to the record (a full disk, which a
    # session can bring about), said once one can again: how many, from
    # when and until when, see Watch._write
    UNWRITTEN = "unwritten"
    # More files of secrets were seen open than are noted, see
    # MOST_OPENED: those past them were not
    TOO_MANY_OPENED = "too many opened"
    # Not the watcher's: the runtime began to tell the launcher what runs
    # in the session, see gvisor.py
    MONITORED = "monitored"


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


# What a process is as it is read, see process: when it started, its
# parent, its program and its command line
ProcessRead = tuple[str, int, str, list[str]]


def read(path: str) -> bytes:
    with open(path, "rb") as file:
        return file.read()


def process(pid: int) -> ProcessRead | None:
    """When a process started (in ticks, only good to compare), its
    parent, its program and its command line, none for one that is gone."""
    try:
        # After the name of the command, which can hold anything
        stat = read(f"/proc/{pid}/stat").rsplit(b")", 1)[1].split()
        started, parent = stat[19].decode(), int(stat[1])
        raw = read(f"/proc/{pid}/cmdline")
    except (OSError, IndexError, ValueError):
        return None
    try:
        program = os.readlink(f"/proc/{pid}/exe")
    except OSError:
        # A kernel thread, or one that is not the user's to look into
        program = ""
    # Where it is is the session's to choose as well, as long as a path
    if len(program) > MOST_ARGUMENT:
        program = program[:MOST_ARGUMENT] + CUT
    return started, parent, program, command_line(raw)


def command_line(raw: bytes) -> list[str]:
    """A command line as it is kept, see MOST_COMMAND: its arguments from
    the first on, and CUT in the place of what there was no room for.
    Those past MOST_ARGUMENTS are not taken apart, a command line can
    hold hundreds of thousands."""
    given = raw.split(b"\0", MOST_ARGUMENTS)
    if given and not given[-1]:
        given.pop()
    argv: list[str] = []
    room = MOST_COMMAND
    cut = len(given) > MOST_ARGUMENTS
    for argument in given[:MOST_ARGUMENTS]:
        if not room:
            cut = True
            break
        whole = argument.decode("utf-8", "replace")
        kept = whole[: min(MOST_ARGUMENT, room)]
        cut |= len(kept) < len(whole)
        argv.append(kept)
        room -= len(kept)
    return [*argv, CUT] if cut else argv


def address(encoded: str) -> str:
    """An address as /proc/net/tcp and tcp6 write it: each four bytes of
    it as one number in the machine's own byte order. One of IPv4 inside
    IPv6 as the IPv4 address it is, as it goes over the wire."""
    words = [encoded[at : at + 8] for at in range(0, len(encoded), 8)]
    packed = b"".join(int(word, 16).to_bytes(4, sys.byteorder) for word in words)
    found = ipaddress.ip_address(packed)
    mapped = getattr(found, "ipv4_mapped", None)
    return str(mapped or found)


Sockets = dict[tuple[int, str, int], str]
# No more sockets of each kind are kept from one look than this: some 300
# bytes each, and a session can open as many as it likes
MOST_SOCKETS = 20_000


class Tables(NamedTuple):
    """The TCP sockets of one look, see sockets: the connections, those
    that wait for one, and whether some were passed over for being more
    than MOST_SOCKETS."""

    connected: Sockets
    waiting: Sockets
    passed_over: bool


def _socket(line: str) -> tuple[tuple[int, str, int], str, bool] | None:
    """A socket as a line of /proc/net/tcp or tcp6 has it: by its own
    port, the address and the port at the other end, or for one that
    waits for connections its port and the address it waits on, then its
    inode and whether it waits. None for a line that says none, or one
    that was let go of."""
    parts = line.split()
    try:
        local, remote, state, inode = parts[1], parts[2], parts[3], parts[9]
        on, port = local.rsplit(":", 1)
        to, to_port = remote.rsplit(":", 1)
        waits = state == TCP_LISTEN
        if waits:
            key = (int(port, 16), address(on), 0)
        else:
            key = (int(port, 16), address(to), int(to_port, 16))
    except (IndexError, ValueError):
        return None
    if inode == "0":
        # Let go of
        return None
    return key, inode, waits


# Where the kernel lists the TCP sockets of the network namespace
TCP_TABLES = ("/proc/net/tcp", "/proc/net/tcp6")


def sockets(tables: Sequence[str] = TCP_TABLES) -> Tables:
    """The TCP sockets of the network namespace, each with its inode, from
    one read of each table, the kernel takes its time over them, a line at
    a time: the connections, each by its own port, the address and the
    port at the other end, and the sockets that wait for connections, each
    by its port and the address it waits on. Not the connections on the
    session's own loopback, which nothing asks who made (see
    _look_at_connections), and no more of each kind than MOST_SOCKETS."""
    connected: Sockets = {}
    waiting: Sockets = {}
    passed_over = False
    for table in tables:
        try:
            with open(table, encoding="ascii", errors="replace") as lines:
                # Its heading
                next(lines, None)
                for line in lines:
                    found = _socket(line)
                    if found is None:
                        continue
                    key, inode, waits = found
                    kept = waiting if waits else connected
                    if not waits and not _watched(key):
                        continue
                    if len(kept) >= MOST_SOCKETS:
                        passed_over = True
                        continue
                    kept[key] = inode
        except OSError:
            continue
    return Tables(connected, waiting, passed_over)


def limit_hits(pid: int, root: str = "/proc") -> int | None:
    """How often the container of a process could not start one for its
    limit of them, none when that cannot be read: the line of
    pids.events that counts it, max 3."""
    for events in PIDS_EVENTS:
        try:
            said = read(f"{root}/{pid}/root/{events}").split()
            return int(said[said.index(b"max") + 1])
        except (OSError, ValueError, IndexError):
            continue
    return None


def _keyed(path: str) -> dict[str, int]:
    """A file of names with a number each, a line for each."""
    found = {}
    for line in read(path).decode("ascii", "replace").splitlines():
        name, _, value = line.partition(" ")
        if value.isdigit():
            found[name] = int(value)
    return found


def stalled(path: str) -> int:
    """For how many microseconds something of the session waited for what
    the file is about, since it started (the kernel's pressure files)."""
    for line in read(path).decode("ascii", "replace").splitlines():
        if line.startswith("some "):
            return int(line.rpartition("total=")[2])
    raise ValueError(path)


def limit(said: str) -> int | None:
    """A limit as a cgroup file has it, none for one that is not set."""
    return None if said == "max" else int(said)


def _session_tmpfs(mounts: str) -> list[str]:
    """Where the session has a tmpfs to write to, by the list of what one
    of its processes has mounted: those docker mounts for it, not the
    kernel's own under /proc, /sys and /dev. But /dev/shm, which programs
    fill."""
    found = []
    for line in read(mounts).decode("utf-8", "replace").splitlines():
        parts = line.split()
        if len(parts) < 3 or parts[2] != "tmpfs":
            continue
        place = parts[1]
        kernels = place.startswith(("/proc", "/sys", "/dev")) and place != "/dev/shm"  # noqa: S108
        # A space in a path is written as its number there, none of
        # these has one
        if not kernels and "\\" not in place:
            found.append(place)
    return found[:MOST_TMPFS]


def _watched(connection: tuple[int, str, int]) -> bool:
    """Whether a connection is one the processes of are looked for: one
    with another end, and not on the session's own loopback, which no
    capture has, so nothing asks who made it, and of which a session can
    make as many as it likes without the network."""
    _, to, to_port = connection
    return bool(to_port) and not _is_loopback(to)


def _is_loopback(address: str) -> bool:
    """Whether an address is the session's own loopback, which nothing
    else reaches and no capture has: the same as in packets.py."""
    return address.startswith("127.") or address == "::1"


def stamped(**said: object) -> str:
    """A line of a record: what is said, and now."""
    return lined(time.time(), said)


def lined(when: float, said: dict) -> str:
    """A line of a record: what is said, and when it was so."""
    return json.dumps({"t": round(when, 3), **said}) + "\n"


def percent(used: float, of: float | None) -> int | None:
    return int(100 * used / of) if of else None


class CgroupHealth:
    """Reads the health of a session from the cgroup of its container
    alone: memory, CPU, and the time it waited for memory, CPU or disk.
    This is all that can be read from outside the session (see
    host_health.py). Each figure is read independently, so one that cannot
    be read (another kernel, cgroup v1) is left out and the others are
    still reported. note is the function that writes a line."""

    def __init__(self, note: Callable[..., None]) -> None:
        self._note = note
        # What the counters that only grow said at the last line, and when
        self._counted: dict[str, int] = {}
        self._counted_at = 0.0
        self._said_at = 0.0
        self._out_of_turn_at = 0.0
        # How near each limit the session was last found: 0, 1 (near) or
        # 2 (at it), see NEAR_LIMIT
        self._levels: dict[str, int] = {}
        # How often a process was ended for want of memory, as last read
        self._ended: int | None = None
        # What came nearer a limit and is still to be said
        self._rose: list[str] = []

    def look_at(self, cgroup: str, now: float) -> None:
        """Read the cgroup in the given directory, and write a health
        line when one is due."""
        self._look_for_the_ended(cgroup)
        said, limited = self._used(cgroup)
        self._rose += [name for name in self._risen(limited) if name not in self._rose]
        rose = self._rose
        counted = self._count(cgroup)
        if not self._counted_at:
            # Nothing to compare with yet, the first line comes next time
            self._counted, self._counted_at = counted, now
            return
        out_of_turn = rose and now - self._out_of_turn_at >= OUT_OF_TURN_EVERY
        if not out_of_turn and self._said_at and now - self._said_at < HEALTH_EVERY:
            return
        said.update(self._since(counted, now))
        self._counted, self._counted_at, self._said_at = counted, now, now
        if rose:
            said["rose"] = rose
            self._rose = []
            self._out_of_turn_at = now
        said.update(self._seen_too())
        self._note(health=said)

    def _look_for_the_ended(self, cgroup: str) -> None:
        """Note that a process was ended for want of memory since the
        last look: the kernel ends the one that holds the most, it does
        not say which."""
        try:
            ended = _keyed(f"{cgroup}/memory.events").get("oom_kill", 0)
        except OSError:
            return
        if self._ended is not None and ended > self._ended:
            self._note(oom=ended, gone=self._gone())
        self._ended = ended

    def _gone(self) -> list[list]:
        """The large processes that have gone since the previous look.
        Empty here, because the cgroup alone does not show processes."""
        return []

    def _seen_too(self) -> dict[str, object]:
        """Extra fields for a health line, from sources other than the
        cgroup. None here."""
        return {}

    def _used(
        self, cgroup: str
    ) -> tuple[dict[str, object], dict[str, tuple[int, int | None]]]:
        """What the session uses now, as a line says it, and of that what
        has a limit to be near, each as what is used and the most there
        can be (none for no limit): memory, without what the kernel keeps
        of files and gives back when asked."""
        said: dict[str, object] = {}
        limited: dict[str, tuple[int, int | None]] = {}
        try:
            held = int(read(f"{cgroup}/memory.current"))
            cached = _keyed(f"{cgroup}/memory.stat").get("inactive_file", 0)
            most = limit(read(f"{cgroup}/memory.max").decode().strip())
            limited["memory"] = (max(held - cached, 0), most)
            said["mem"] = list(limited["memory"])
        except (OSError, ValueError):
            pass
        try:
            quota, period = read(f"{cgroup}/cpu.max").decode().split()
            if quota != "max":
                said["cpus"] = round(int(quota) / int(period), 2)
        except (OSError, ValueError):
            pass
        return said, limited

    def _risen(self, limited: dict[str, tuple[int, int | None]]) -> list[str]:
        """What the session has come nearer a limit of than it was, by
        name: memory, pids, or the place of a tmpfs."""
        rose = []
        levels = {}
        for name, (now, most) in limited.items():
            share = percent(now, most)
            if share is None:
                continue
            was = self._levels.get(name, 0)
            level = sum(share >= mark for mark in NEAR_LIMIT)
            if level < was and share >= NEAR_LIMIT[level] - WELL_BELOW:
                # Not far enough below that mark to say so again on the
                # way up, it may be below the ones above it
                level += 1
            if level > was:
                rose.append(name)
            levels[name] = level
        self._levels = levels
        return rose

    def _count(self, cgroup: str) -> dict[str, int]:
        """The counters that only grow: microseconds of CPU used and of
        being held back at the limit of them, and of waiting for memory,
        CPU and disk."""
        counted = {}
        try:
            cpu = _keyed(f"{cgroup}/cpu.stat")
            counted["cpu"] = cpu["usage_usec"]
            counted["throttled"] = cpu.get("throttled_usec", 0)
        except (OSError, KeyError):
            pass
        for what in ("memory", "cpu", "io"):
            try:
                counted[f"stalled {what}"] = stalled(f"{cgroup}/{what}.pressure")
            except (OSError, ValueError):
                continue
        return counted

    def _since(self, counted: dict[str, int], now: float) -> dict[str, object]:
        """What the counters say of the time since the last line: CPU in
        percent of one, the seconds held back, and for what percent of
        the time something waited for memory, CPU or disk."""
        passed = max(now - self._counted_at, 0.001) * 1e6
        grown = {
            name: max(count - self._counted[name], 0)
            for name, count in counted.items()
            if name in self._counted
        }
        said: dict[str, object] = {"seconds": round(passed / 1e6, 1)}
        if "cpu" in grown:
            said["cpu"] = round(100 * grown["cpu"] / passed, 1)
            said["throttled"] = round(grown["throttled"] / 1e6, 1)
        waited = {
            name.partition(" ")[2]: round(100 * count / passed, 1)
            for name, count in grown.items()
            if name.startswith("stalled ")
        }
        if waited:
            said["stalled"] = waited
        return said


class Health(CgroupHealth):
    """Reads the health of a session from inside its process namespace,
    as the watcher does. To what the cgroup gives, it adds the process
    count, the use of each tmpfs and the largest processes, read from
    /proc. note is the function that writes a line, name_of the one that
    names a process."""

    def __init__(
        self,
        note: Callable[..., None],
        name_of: Callable[[int], str],
        proc: str = "/proc",
    ) -> None:
        super().__init__(note)
        self._name_of = name_of
        self._proc = proc
        # The pids seen at the last look, and the /proc directory of the
        # first of them
        self._pids: Sequence[int] = ()
        self._first = ""
        # The largest processes as last seen: pid, bytes and name
        self._largest: list[tuple[int, int, str]] = []

    def look(self, pids: list[int], now: float) -> None:
        """Read the health of the session, given its pids. The cgroup is
        found through the root of the first process."""
        if not pids:
            return
        self._pids, self._first = pids, f"{self._proc}/{min(pids)}"
        self.look_at(f"{self._first}/root/{CGROUP}", now)

    def _look_for_the_ended(self, cgroup: str) -> None:
        super()._look_for_the_ended(cgroup)
        # Updated only now, because finding what has gone needs the
        # largest processes of the previous look
        self._largest = self._sized(self._pids)

    def _gone(self) -> list[list]:
        seen = set(self._pids)
        return [list(process) for process in self._largest if process[0] not in seen]

    def _seen_too(self) -> dict[str, object]:
        if not self._largest:
            return {}
        return {"top": [list(process) for process in self._largest]}

    def _sized(self, pids: Sequence[int]) -> list[tuple[int, int, str]]:
        sized = []
        for pid in pids:
            try:
                pages = int(read(f"{self._proc}/{pid}/statm").split()[1])
            except (OSError, IndexError, ValueError):
                continue
            if pages:
                sized.append((pages * PAGE, pid))
        sized.sort(reverse=True)
        return [(pid, size, self._name_of(pid)) for size, pid in sized[:LARGEST]]

    def _used(
        self, cgroup: str
    ) -> tuple[dict[str, object], dict[str, tuple[int, int | None]]]:
        """Adds the process count against its limit and the use of each
        tmpfs to what the cgroup says of memory."""
        said, limited = super()._used(cgroup)
        try:
            most = limit(read(f"{cgroup}/pids.max").decode().strip())
            limited["pids"] = (int(read(f"{cgroup}/pids.current")), most)
            said["pids"] = list(limited["pids"])
        except (OSError, ValueError):
            pass
        tmpfs = {}
        try:
            places = _session_tmpfs(f"{self._first}/mounts")
        except OSError:
            places = []
        for place in places:
            try:
                about = os.statvfs(f"{self._first}/root{place}")
            except OSError:
                # One that cannot be looked at does not hide the others
                continue
            size = about.f_blocks * about.f_frsize
            limited[place] = (size - about.f_bfree * about.f_frsize, size)
            tmpfs[place] = list(limited[place])
        if tmpfs:
            said["tmpfs"] = tmpfs
        return said, limited


class Holders:
    """Finds the processes that hold sockets, by what their descriptors
    link to."""

    def __init__(self) -> None:
        # Whether the descriptors of any process could be read at all
        self.readable = False

    def of(self, inodes: set[str], pids: list[int]) -> dict[str, list[int]]:
        wanted = {f"socket:[{inode}]": inode for inode in inodes}
        found: dict[str, list[int]] = {}
        for pid in pids:
            directory = f"/proc/{pid}/fd"
            try:
                descriptors = os.listdir(directory)
            except OSError:
                continue
            self.readable = True
            for descriptor in descriptors:
                try:
                    inode = wanted.get(os.readlink(f"{directory}/{descriptor}"))
                except OSError:
                    continue
                if inode is not None and pid not in found.setdefault(inode, []):
                    found[inode].append(pid)
        return found


def _kinds(said: object) -> dict[str, str]:
    """Paths or names, each with a kind of secrets, as the launcher
    wrote them: none of what is not."""
    if not isinstance(said, dict):
        return {}
    return {
        str(key): str(kind)
        for key, kind in said.items()
        if isinstance(key, str) and isinstance(kind, str)
    }


def _names(said: object) -> tuple[str, ...]:
    if not isinstance(said, list):
        return ()
    return tuple(name for name in said if isinstance(name, str))


def _under(directories: Sequence[str]) -> tuple[str, ...]:
    """Directories, each as a path in it starts: with a / at its end,
    one alone for the root."""
    return tuple(
        os.path.join(os.path.normpath(directory), "") for directory in directories
    )


class Secrets:
    """Which files are taken to hold secrets, by the path a process holds
    one under, each with the kind of secrets it holds: a file by its
    path, a file in a directory but for the names passed over there (a
    public key, the hosts ssh knows), and a file of a name in one of the
    roots, but for the templates of those names. The roots are where
    files of those names are hidden from a session (the project and the
    directories mounted next to it, see hidden_files of mounts.py): one
    made elsewhere, in /tmp say, is no secret kept from it. The launcher
    says which they are (see secrets.py), the watcher is given them as
    JSON."""

    def __init__(
        self,
        files: Mapping[str, str] | None = None,
        dirs: Mapping[str, str] | None = None,
        passed: Sequence[str] = (),
        names: Mapping[str, str] | None = None,
        exempt: Sequence[str] = (),
        roots: Sequence[str] = (),
    ) -> None:
        self._files = {
            os.path.normpath(path): kind for path, kind in (files or {}).items()
        }
        self._dirs = {
            os.path.normpath(directory) + "/": kind
            for directory, kind in (dirs or {}).items()
        }
        self._passed = tuple(passed)
        self._names = dict(names or {})
        self._exempt = frozenset(exempt)
        self._roots = _under(roots)

    @classmethod
    def read(cls, said: str) -> Secrets:
        """The rules as as_json wrote them. Raises ValueError for what is
        not JSON, and passes over what is not one of them."""
        rules = json.loads(said)
        if not isinstance(rules, dict):
            rules = {}
        return cls(
            _kinds(rules.get("files")),
            _kinds(rules.get("dirs")),
            _names(rules.get("passed")),
            _kinds(rules.get("names")),
            _names(rules.get("exempt")),
            _names(rules.get("roots")),
        )

    def as_json(self) -> str:
        """The rules, for the watcher to be given on its command line."""
        return json.dumps(
            {
                "files": self._files,
                "dirs": {
                    directory.rstrip("/"): kind
                    for directory, kind in self._dirs.items()
                },
                "passed": list(self._passed),
                "names": self._names,
                "exempt": sorted(self._exempt),
                "roots": [os.path.normpath(root) for root in self._roots],
            },
            separators=(",", ":"),
        )

    def markers(self) -> tuple[bytes, ...] | None:
        """Bytes of which a path taken to hold secrets has one at least,
        for what tells of paths to be passed over unread when it has none
        of them (see gvisor.py): the name of each file and directory, and
        the longest run of letters of each pattern. None when a pattern
        has no run that has to be there, or a class of letters ([ab]),
        whose letters need not be."""
        found = [os.path.basename(path) for path in self._files]
        found += [os.path.basename(directory.rstrip("/")) for directory in self._dirs]
        for pattern in self._names:
            if "[" in pattern:
                return None
            longest = max(pattern.replace("?", "*").split("*"), key=len)
            if not longest:
                return None
            found.append(longest)
        return tuple(dict.fromkeys(marker.encode() for marker in found if marker))

    def of(self, path: str) -> str | None:
        """The kind of secrets a file holds, none for one that is not
        taken to hold any. Of an absolute path only: what a descriptor
        links to otherwise (a socket, a pipe) is no file. The names are
        the session's to choose, each pattern is the launcher's, and a
        pattern of fnmatch takes no more than a pass over a name."""
        if not path.startswith("/"):
            return None
        path = os.path.normpath(path.removesuffix(DELETED))
        kind = self._files.get(path)
        if kind:
            return kind
        name = os.path.basename(path)
        for directory, kind in self._dirs.items():
            if path.startswith(directory):
                passed = any(fnmatch.fnmatchcase(name, one) for one in self._passed)
                return None if passed else kind
        if name in self._exempt or not path.startswith(self._roots):
            return None
        for pattern, kind in self._names.items():
            if fnmatch.fnmatchcase(name, pattern):
                return kind
        return None


class Telling(enum.Enum):
    """What to do of a file of secrets a process was seen to open, see
    OpenedOnce."""

    # Note it
    NEW = enum.auto()
    # Nothing: it was noted already, or there were too many
    KNOWN = enum.auto()
    # Note that there were more than are noted, this once
    TOO_MANY = enum.auto()


class OpenedOnce:
    """The files of secrets noted of each process, for one to be noted
    once for each process and file, and no more than MOST_OPENED in all:
    a session can open them in as many processes as it likes. A process
    is known by what the caller gives, its id and when it started say."""

    def __init__(self) -> None:
        self._noted: dict[Hashable, set[str]] = {}
        self._count = 0
        self.too_many = False

    def take(self, process: Hashable, path: str) -> Telling:
        if self.too_many or path in self._noted.get(process, ()):
            return Telling.KNOWN
        if self._count >= MOST_OPENED:
            self.too_many = True
            return Telling.TOO_MANY
        self._count += 1
        self._noted.setdefault(process, set()).add(path)
        return Telling.NEW

    def forget(self, process: Hashable) -> None:
        """A process that is another now: its files are noted again, and
        counted again."""
        self._noted.pop(process, None)


def started_last(pids: Sequence[int]) -> int:
    """Of the processes that hold a socket, as the watcher lists them in
    the order they started (see Watch._by_start), the one started last.
    Not the highest id, ids start over once they reach the most there can
    be."""
    return pids[-1]


class Watch:
    def __init__(
        self,
        out,
        read_process: Callable[[int], ProcessRead | None] = process,
        secrets: Secrets | None = None,
        proc: str = "/proc",
    ) -> None:
        self._out = out
        self._proc = proc
        self._written = 0
        # Of the lines that could not be written since the last that was,
        # how many, and the times of the first and of the last of them
        self._unwritten: tuple[int, float, float] | None = None
        # Whether the processes have used up their part of the record,
        # and whether all of it is: nothing more is written then
        self._full = False
        self._ended = False
        # Not itself, nor what started it
        self._own = {os.getpid(), os.getppid()}
        # What reads a process, see process
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
        """Add a line to the record, while there is room for it: what is
        not reserved (a process, how the session is doing, what is on the
        session's own loopback) leaves RESERVED for what is (a connection,
        a socket others can reach, a word of the watcher's own), a session
        must not be rid of those by what it makes the others fill. The
        record says that it is full when the first part is, and again as
        its last line when the reserved part is too, which a session can
        fill as well: one that ends without a word reads as a session
        with nothing more to note. A line said aloud goes to the
        watcher's output too, no more of them than to the record, and of
        those that are counted no more than MOST_ALOUD, see _speak."""
        if self._ended or (self._full and not reserved):
            return
        line = stamped(**said)
        if reserved and self._written + len(line) > MOST_BYTES - LAST_WORD:
            self._ended = True
            aloud = False
            line = stamped(note=Note.FULL)
        elif not reserved and self._written + len(line) > MOST_BYTES - RESERVED:
            self._full = True
            aloud = False
            line = stamped(note=Note.FULL)
        self._write(line)
        if aloud:
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
                self._written += len(gap)
                self._unwritten = None
            self._out.write(line)
            self._out.flush()
        except OSError:
            now = round(time.time(), 3)
            lines, since, _ = self._unwritten or (0, now, now)
            self._unwritten = (lines + 1, since, now)
            return
        self._written += len(line)

    def _speak(self, line: str, counted: bool = False) -> None:
        """Write a line to the watcher's output, for what follows the
        session as it runs. One that is counted, a connection or a
        process next to it, only while less than MOST_ALOUD of them was
        said: how many there are is the session's to choose, and docker
        keeps the output until the session is over. Past that a last
        word says so, and no more of them come."""
        if counted:
            if self._hushed:
                return
            if self._spoken + len(line) > MOST_ALOUD:
                self._hushed = True
                line = stamped(note=Note.HUSHED)
            self._spoken += len(line)
        try:
            sys.stdout.write(line)
            sys.stdout.flush()
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
        """Write a line to the record and to the watcher's output, see
        note. The line does not use the reserved part of the record."""
        self.note(reserved=False, aloud=True, counted=False, **said)

    def look(self) -> None:
        now = time.monotonic()
        self._keep_pace(now)
        pids = [
            int(name)
            for name in os.listdir("/proc")
            if name.isdigit() and int(name) not in self._own
        ]
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
            try:
                path = os.readlink(f"{directory}/{descriptor}")
            except OSError:
                continue
            kind = self._secrets.of(path)
            if kind is None:
                continue
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
                opened=path[:MOST_ARGUMENT],
                secret=kind,
                pids=[pid],
            )

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
        word for that. Only those that are watched, see _watched."""
        current = {key: inode for key, inode in current.items() if _watched(key)}
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
            reachable = not _is_loopback(on)
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


class LineFile:
    """The record as it is written: each line straight to its file, none
    held back to be written later, which would come out in the middle of
    another once it could. A line that cannot be written whole raises
    OSError, and what of it did go in is ended by the next line that is
    written, which starts with an end of line of its own: the part reads
    as a line that does not hold up, which the reader passes over, and
    the one after it is whole."""

    def __init__(self, path: str) -> None:
        flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_CLOEXEC
        self._file = os.open(path, flags, 0o644)
        # Whether a line was cut short in the file, see write
        self._cut = False

    def write(self, line: str) -> None:
        data = ("\n" if self._cut else "").encode() + line.encode()
        while data:
            written = os.write(self._file, data)
            if not written:
                raise OSError("nothing could be written to the record")
            data = data[written:]
            self._cut = True
        self._cut = False

    def flush(self) -> None:
        """Nothing to do, every line is written as it comes."""

    def close(self) -> None:
        os.close(self._file)


def _main(args: list[str]) -> int:
    path = args[0]
    out = LineFile(path)
    try:
        if len(args) > 1:
            _take_identity(int(args[1]), int(args[2]))
        secrets = Secrets.read(args[3]) if len(args) > 3 else None
        watch = Watch(out, secrets=secrets)
        watch.note(reserved=True, note=Note.STARTED, beat=HEARTBEAT_EVERY)
        while True:
            watch.look()
            time.sleep(INTERVAL)
    finally:
        out.close()


if __name__ == "__main__":
    try:
        sys.exit(_main(sys.argv[1:]))
    except KeyboardInterrupt:
        sys.exit(0)
