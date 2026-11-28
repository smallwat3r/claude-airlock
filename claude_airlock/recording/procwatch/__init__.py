"""The watcher of a session's processes, which notes what runs in it and
which process holds each of its TCP connections, a JSON object per line
(see watcher.py). Run by the launcher in a sidecar that shares the
session's process and network namespaces (see processes.py), not part of
the launcher itself: the launcher mounts the directory of this package
alone in the sidecar, read-only, and the Python of the image runs it, see
__main__.py. So it stands alone: nothing of it takes what is outside it
but the standard library, of the Python of the image, Debian's, older
than the launcher's. The launcher takes from it what the two share: the
lines of the record and what keeps it within its size, how a command
line is kept, the rules of what holds secrets, what a cgroup says and how
an address is written. Not the other way round, the sidecar has nothing
of the launcher.

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
memory, with the large ones that are gone since. Those two are said aloud
as well, for what follows a session as it runs: the record stays in the
sidecar until the session is over. So are the second and the third, of
what is not on the session's own loopback, each after the first of the
process that holds the socket and of those it comes from: which process
made a connection is then known while the session runs, without all its
processes being said aloud. No more of that than MOST_ALOUD of watcher.py,
what is said aloud is kept until the session is over. It is said to a file
of the launcher's, which no session has. The seventh when looks came much
later than they are meant to, which is the session's doing: how many did
since it was last said, how long after the look before them in all, and
the longest of those. What lived shorter than that, then, was not seen.
The eighth when a process is seen to hold a file of secrets open (see
Secrets of rules.py), with the kind of secrets it holds, once for each
process and file, and said aloud with the process as a connection is: by
its name, or by what the kernel knows it by, held under another name (see
linked.py). A file a process opened and closed again between two looks is
not seen."""

from __future__ import annotations

from . import addresses, cgroup, proc, record, rules, tables
from .addresses import RESOLVER, is_loopback, unmapped
from .cgroup import HEALTH_EVERY, LIMITS_EVERY, NEAR_LIMIT, CgroupHealth, percent
from .proc import CUT, MOST_ARGUMENT, ProcessRead, command_line, kept_path
from .record import LineFile, Note, Room, lined, stamped
from .rules import OpenedOnce, Secrets, Telling, normal
from .tables import started_last

__all__ = [
    "CUT",
    "HEALTH_EVERY",
    "LIMITS_EVERY",
    "MOST_ARGUMENT",
    "NEAR_LIMIT",
    "RESOLVER",
    "CgroupHealth",
    "LineFile",
    "Note",
    "OpenedOnce",
    "ProcessRead",
    "Room",
    "Secrets",
    "Telling",
    "addresses",
    "cgroup",
    "command_line",
    "is_loopback",
    "kept_path",
    "lined",
    "normal",
    "percent",
    "proc",
    "record",
    "rules",
    "stamped",
    "started_last",
    "tables",
    "unmapped",
]
