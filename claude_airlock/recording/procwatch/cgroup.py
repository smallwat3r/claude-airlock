"""How a session is doing, as its cgroup says and, from inside its process
namespace, /proc: the memory, CPUs, processes and tmpfs it uses, how long
it waited for them, and its largest processes. The launcher reads the
cgroup alone from outside a session, see host_health.py."""

from __future__ import annotations

import os
from collections.abc import Callable, Sequence

from .proc import read

# Seconds between two looks at what the session's limits say
LIMITS_EVERY = 1.0
# Where a container finds how often its limit of processes kept it from
# starting one, under the root of one of its processes: with cgroup v2,
# then v1. The watcher is in another container, with another limit.
PIDS_EVENTS = ("sys/fs/cgroup/pids.events", "sys/fs/cgroup/pids/pids.events")
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
MOST_TMPFS = 16
# Where a container finds what it uses and may use, under the root of one
# of its processes (cgroup v2)
CGROUP = "sys/fs/cgroup"
# The size of a page of memory, by which statm counts
PAGE = os.sysconf("SC_PAGE_SIZE")


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
