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
    {"t": 9.0, "note": "..."}

The first when a process is first seen or has become another program, the
second when a connection is, with the processes that hold its socket, the
third when a socket starts to wait for connections, the fourth when the
session could not start a process for its limit of them, with how often
that has been so.

It runs as root, so that the session, which shares its process namespace,
can neither stop it nor reach its file. To read what a process of the
session holds takes that user's rights though, or capabilities: it takes
the user's identity for file access alone (setfsuid), and lets go of every
capability."""

from __future__ import annotations

import ctypes
import ipaddress
import json
import os
import sys
import time

# Seconds between two looks
INTERVAL = 0.04
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
TCP_LISTEN = "0A"
# Seconds between two looks at what the session's limits say
LIMITS_EVERY = 1.0
# Where a container finds how often its limit of processes kept it from
# starting one, under the root of one of its processes: with cgroup v2,
# then v1. The watcher is in another container, with another limit.
PIDS_EVENTS = ("sys/fs/cgroup/pids.events", "sys/fs/cgroup/pids/pids.events")
# Where docker's own resolver waits in every container, not the session's
RESOLVER = "127.0.0.11"
_CAPABILITY_VERSION_3 = 0x20080522


def take_identity(uid: int, gid: int) -> None:
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


def connections(listening: bool = False) -> dict[tuple[int, str, int], str]:
    """The TCP connections of the network namespace, each by its own
    port, the address and the port at the other end, with the inode of
    its socket. With listening, the sockets that wait for connections
    instead, each by its port and the address it waits on."""
    found = {}
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
                if listening:
                    key = (int(port, 16), address(on), 0)
                else:
                    key = (int(port, 16), address(to), int(to_port, 16))
            except (IndexError, ValueError):
                continue
            if inode == "0":
                # Let go of
                continue
            if listening == (state == TCP_LISTEN) and (listening or key[2]):
                found[key] = inode
    return found


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
        # Whether the processes have used up their part of the record
        self._full = False
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

    def note(self, reserved: bool = False, **said: object) -> None:
        """Add a line to the record, while there is room for it: what is
        not reserved (a process) leaves RESERVED for what is (a
        connection, a socket that waits, a word of the watcher's own). The
        record says once that it is full, when its processes are."""
        if self._written >= MOST_BYTES or (self._full and not reserved):
            return
        line = json.dumps({"t": round(time.time(), 3), **said}) + "\n"
        if reserved and self._written + len(line) > MOST_BYTES:
            self._written = MOST_BYTES
            return
        if not reserved and self._written + len(line) > MOST_BYTES - RESERVED:
            self._full = True
            line = json.dumps({"t": round(time.time(), 3), "note": "full"}) + "\n"
        self._written += len(line)
        self._out.write(line)
        self._out.flush()

    def look(self) -> None:
        now = time.monotonic()
        pids = [
            int(name)
            for name in os.listdir("/proc")
            if name.isdigit() and int(name) not in self._own
        ]
        self._look_at_processes(pids, now)
        self._look_at_connections(pids)
        self._look_at_listeners(pids)
        if now - self._limits_seen >= LIMITS_EVERY:
            self._limits_seen = now
            self._look_at_limits(pids)

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

    def _look_at_connections(self, pids: list[int]) -> None:
        current = connections()
        self._connections &= current.keys()
        self._tries = {key: n for key, n in self._tries.items() if key in current}
        new = {
            key: inode
            for key, inode in current.items()
            if key not in self._connections and self._tries.get(key, 0) < MOST_TRIES
        }
        if not new:
            return
        holders = self._holders.of(set(new.values()), pids)
        for key, inode in new.items():
            held_by = holders.get(inode)
            if not held_by:
                self._tries[key] = self._tries.get(key, 0) + 1
                continue
            self._connections.add(key)
            port, to, to_port = key
            self.note(
                reserved=True,
                port=port,
                to=to,
                to_port=to_port,
                pids=sorted(held_by)[:8],
            )
        if not self._holders.readable and not self._said_unreadable:
            self._said_unreadable = True
            self.note(reserved=True, note="unreadable")

    def _look_at_limits(self, pids: list[int]) -> None:
        """Note that the session ran into its limit of processes since
        the last look, with how often it has by now."""
        hits = limit_hits(min(pids)) if pids else None
        if hits is not None and hits > self._limit_hits:
            self._limit_hits = hits
            self.note(reserved=True, limit="pids", hits=hits)

    def _look_at_listeners(self, pids: list[int]) -> None:
        """Note each socket that started to wait for connections, with
        the processes that hold it, none when those were not found: it is
        there all the same, for whatever else is on the session's network
        to connect to."""
        current = connections(listening=True)
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
            held_by = sorted(holders.get(inode, []))[:8]
            self.note(reserved=True, listen=port, on=on, pids=held_by)


def main(args: list[str]) -> int:
    path = args[0]
    with open(path, "a", encoding="utf-8") as out:
        if len(args) > 1:
            take_identity(int(args[1]), int(args[2]))
        watch = Watch(out)
        watch.note(reserved=True, note="started")
        while True:
            watch.look()
            time.sleep(INTERVAL)


if __name__ == "__main__":
    try:
        sys.exit(main(sys.argv[1:]))
    except KeyboardInterrupt:
        sys.exit(0)
