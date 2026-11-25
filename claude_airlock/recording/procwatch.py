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
record stays in the sidecar until the session is over. The seventh when
looks came much later than they are meant to, which is the session's
doing: how many did since it was last said, how long after the look before
them in all, and the longest of those. What lived shorter than that, then,
was not seen.

It runs as root, so that the session, which shares its process namespace,
can neither stop it nor reach its file. To read what a process of the
session holds takes that user's rights though, or capabilities: it takes
the user's identity for file access alone (setfsuid), and lets go of every
capability."""

from __future__ import annotations

import ctypes
import enum
import ipaddress
import json
import os
import sys
import time
from collections.abc import Callable, Sequence

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
# right after it was made that it becomes another program, then this often
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
# The largest processes that are named, and the tmpfs that are looked at
LARGEST = 3
# The processes that hold a socket that are named, the ones started last
MOST_HOLDERS = 8
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


def read(path: str) -> bytes:
    with open(path, "rb") as file:
        return file.read()


def process(pid: int) -> tuple[str, int, str, list[str]] | None:
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
    return started, parent, program, command_line(raw)


def command_line(raw: bytes) -> list[str]:
    """A command line as it is kept, see MOST_COMMAND: its arguments from
    the first on, and CUT in the place of what there was no room for."""
    given = raw.split(b"\0")
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


def sockets() -> tuple[Sockets, Sockets]:
    """The TCP sockets of the network namespace, each with its inode, from
    one read of each table, the kernel takes its time over them: the
    connections, each by its own port, the address and the port at the
    other end, and the sockets that wait for connections, each by its port
    and the address it waits on."""
    connected: Sockets = {}
    waiting: Sockets = {}
    for table in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            lines = read(table).decode("ascii", "replace").splitlines()[1:]
        except OSError:
            continue
        for line in lines:
            parts = line.split()
            try:
                local, remote, state, inode = parts[1], parts[2], parts[3], parts[9]
                on, port = local.rsplit(":", 1)
                to, to_port = remote.rsplit(":", 1)
                if state == TCP_LISTEN:
                    key = (int(port, 16), address(on), 0)
                else:
                    key = (int(port, 16), address(to), int(to_port, 16))
            except (IndexError, ValueError):
                continue
            if inode == "0":
                # Let go of
                continue
            if state == TCP_LISTEN:
                waiting[key] = inode
            elif key[2]:
                connected[key] = inode
    return connected, waiting


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


def _is_loopback(address: str) -> bool:
    """Whether an address is the session's own loopback, which nothing
    else reaches and no capture has: the same as in packets.py."""
    return address.startswith("127.") or address == "::1"


def stamped(**said: object) -> str:
    """A line of a record: what is said, and when."""
    return json.dumps({"t": round(time.time(), 3), **said}) + "\n"


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


class Watch:
    def __init__(self, out) -> None:
        self._out = out
        self._written = 0
        # Whether the processes have used up their part of the record,
        # and whether all of it is: nothing more is written then
        self._full = False
        self._ended = False
        # Not itself, nor what started it
        self._own = {os.getpid(), os.getppid()}
        # Each process seen: what it was, when it was first seen and when
        # it was last looked at
        self._processes: dict[int, tuple[tuple, float, float]] = {}
        self._connections: set[tuple[int, str, int]] = set()
        self._listening: set[tuple[int, str, int]] = set()
        self._tries: dict[tuple[int, str, int], int] = {}
        self._holders = Holders()
        self._said_unreadable = False
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

    def name_of(self, pid: int) -> str:
        """What a process is called for short: its program, else what it
        says it is."""
        known = self._processes.get(pid)
        if not known:
            return "?"
        _, program, argv = known[0]
        return os.path.basename(program or (argv[0] if argv else "?"))[:NAME_LENGTH]

    def note(self, reserved: bool = False, aloud: bool = False, **said: object) -> None:
        """Add a line to the record, while there is room for it: what is
        not reserved (a process, how the session is doing, what is on the
        session's own loopback) leaves RESERVED for what is (a connection,
        a socket others can reach, a word of the watcher's own), a session
        must not be rid of those by what it makes the others fill. The
        record says that it is full when the first part is, and again as
        its last line when the reserved part is too, which a session can
        fill as well: one that ends without a word reads as a session
        with nothing more to note. A line said aloud goes to the
        watcher's output too, no more of them than to the record."""
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
        self._written += len(line)
        self._out.write(line)
        self._out.flush()
        if aloud:
            try:
                sys.stdout.write(line)
                sys.stdout.flush()
            except (OSError, ValueError):
                # Nobody listens, the record has it
                pass

    def say(self, **said: object) -> None:
        """Write a line to the record and to the watcher's output, see
        note. The line does not use the reserved part of the record."""
        self.note(reserved=False, aloud=True, **said)

    def look(self) -> None:
        now = time.monotonic()
        self._keep_pace(now)
        pids = [
            int(name)
            for name in os.listdir("/proc")
            if name.isdigit() and int(name) not in self._own
        ]
        self._look_at_processes(pids, now)
        connected, waiting = sockets()
        self._look_at_connections(connected, pids)
        self._look_at_listeners(waiting, pids)
        if now - self._beat >= HEARTBEAT_EVERY:
            self._beat = now
            self.note(reserved=True, note=Note.ALIVE)
        if now - self._limits_seen >= LIMITS_EVERY:
            self._limits_seen = now
            self._look_at_limits(pids)
            self._health.look(pids, now)

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
        for pid in pids:
            known = self._processes.get(pid)
            if known:
                _, first, last = known
                if now - first > YOUNG and now - last < SETTLED_EVERY:
                    continue
            found = process(pid)
            if found is None:
                continue
            started, parent, program, argv = found
            # A process is another one when it started at another time,
            # and another program when it runs something else
            what = (started, program, argv)
            if not known or known[0] != what:
                self.note(pid=pid, ppid=parent, exe=program, argv=argv)
                known = (what, now, now)
            self._processes[pid] = (what, known[1], now)

    def _look_at_connections(self, current: Sockets, pids: list[int]) -> None:
        """Note each new connection with the processes that hold it. One
        whose holder is not found is looked at again, it may be the next
        time. After MOST_TRIES it is noted without one: it is there all
        the same, held by a process that cannot be looked into, which a
        process can make itself, and a connection must not go without a
        word for that. Not one on the session's own loopback: no capture
        has it, so nothing asks who made it, and a session can make as
        many as it likes without the network."""
        current = {
            key: inode for key, inode in current.items() if not _is_loopback(key[1])
        }
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
            self.note(
                reserved=True,
                port=port,
                to=to,
                to_port=to_port,
                pids=sorted(held_by)[-MOST_HOLDERS:],
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
            held_by = sorted(holders.get(inode, []))[-MOST_HOLDERS:]
            self.note(reserved=not _is_loopback(on), listen=port, on=on, pids=held_by)


def _main(args: list[str]) -> int:
    path = args[0]
    with open(path, "a", encoding="utf-8") as out:
        if len(args) > 1:
            _take_identity(int(args[1]), int(args[2]))
        watch = Watch(out)
        watch.note(reserved=True, note=Note.STARTED, beat=HEARTBEAT_EVERY)
        while True:
            watch.look()
            time.sleep(INTERVAL)


if __name__ == "__main__":
    try:
        sys.exit(_main(sys.argv[1:]))
    except KeyboardInterrupt:
        sys.exit(0)
