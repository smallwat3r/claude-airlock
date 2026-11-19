"""How a session was doing while it ran: what it used of its memory, CPUs,
processes and tmpfs, how long it was stalled for want of them, and which
of its processes was ended for want of memory.

Read from what the watcher of its processes notes of that (procwatch.py):
every so often, when the session comes near a limit and when the kernel
ends a process of it. The figures are the watcher's own, taken from the
cgroup of the session's container. The name of a process is the session's
to choose, it is cleaned as all that is shown.

Shown as lines of a trace (health), from the record of a session that is
over and from the watcher's output of one that runs, and summed up in the
header of a trace."""

from __future__ import annotations

from dataclasses import dataclass, field

from .events import Event, Kind, Who, flat

# The percent of a limit from which a session is said to be at it, as in
# procwatch.py, and the percent of the time it waited for memory from
# which it is said to be stalled
AT_LIMIT = 90
STALLED = 10
# Below this many percent a tmpfs is not worth a word in a line, nor is a
# wait
TMPFS_SHOWN = 50
WAIT_SHOWN = 1
# Of the header: below this many percent what was used of a limit other
# than memory is left out
NEAR_LIMIT = 70


def amount(count: float) -> str:
    """A number of bytes as docker writes a limit of them: 512m, 3.1g."""
    for unit, size in (("g", 2**30), ("m", 2**20), ("k", 2**10)):
        if count >= size:
            shown = (
                f"{count / size:.1f}" if count < 10 * size else f"{count / size:.0f}"
            )
            return shown.removesuffix(".0") + unit
    return f"{count:.0f}b"


def share(used: float, most: float | None) -> int | None:
    """The percent of a limit that is used, none without a limit."""
    return int(100 * used / most) if most else None


def of_limit(used: str, most: str | None, percent: int | None) -> str:
    return used if most is None else f"{used} of {most} ({percent}%)"


@dataclass(frozen=True)
class Sized:
    """A process with the memory it held."""

    pid: int
    size: int
    name: str

    @classmethod
    def read(cls, said: list) -> Sized:
        pid, size, name = said
        return cls(int(pid), int(size), str(name))

    @property
    def shown(self) -> str:
        return f"[{self.pid}] {flat(self.name)} {amount(self.size)}"

    @property
    def fields(self) -> dict:
        return {"pid": self.pid, "rss": self.size, "name": self.name}


def used_of(said: list) -> tuple[int, int | None]:
    used, most = said
    return int(used), None if most is None else int(most)


@dataclass(frozen=True)
class Sample:
    """What a session used at one time, and since the sample before."""

    when: float
    # Each as what is used and its limit, none without one
    memory: tuple[int, int | None] | None = None
    pids: tuple[int, int | None] | None = None
    tmpfs: dict[str, tuple[int, int | None]] = field(default_factory=dict)
    # Over so many seconds: CPU in percent of one, of so many it may use
    # (none for all), the seconds it was held back at that limit, and the
    # percent of the time something waited for memory, cpu and io
    seconds: float = 0.0
    cpu: float | None = None
    cpus: float | None = None
    throttled: float = 0.0
    stalled: dict[str, float] = field(default_factory=dict)
    largest: tuple[Sized, ...] = ()
    # What it came nearer a limit of, which is why it was noted out of
    # turn: memory, pids or the place of a tmpfs
    rose: tuple[str, ...] = ()

    @classmethod
    def read(cls, when: float, said: dict) -> Sample:
        """A sample as the watcher wrote it. Raises ValueError, TypeError
        or KeyError for one that is not."""
        return cls(
            when,
            memory=used_of(said["mem"]) if "mem" in said else None,
            pids=used_of(said["pids"]) if "pids" in said else None,
            tmpfs={
                str(place): used_of(used)
                for place, used in dict(said.get("tmpfs", {})).items()
            },
            seconds=float(said.get("seconds", 0.0)),
            cpu=float(said["cpu"]) if "cpu" in said else None,
            cpus=float(said["cpus"]) if "cpus" in said else None,
            throttled=float(said.get("throttled", 0.0)),
            stalled={
                str(what): float(percent)
                for what, percent in dict(said.get("stalled", {})).items()
            },
            largest=tuple(Sized.read(process) for process in said.get("top", [])),
            rose=tuple(str(name) for name in said.get("rose", [])),
        )

    def shares(self) -> dict[str, int]:
        """The percent used of each limit there is, by what it is of."""
        limited = {"memory": self.memory, "pids": self.pids, **self.tmpfs}
        found = {}
        for name, used in limited.items():
            percent = share(*used) if used else None
            if percent is not None:
                found[name] = percent
        return found

    def wrong(self) -> str:
        """What is wrong with the session at this time, nothing as a
        rule: the limits it is at, and that it is stalled for want of
        memory."""
        full = [name for name, percent in self.shares().items() if percent >= AT_LIMIT]
        said = [f"ALMOST OUT OF {', '.join(full)}"] if full else []
        if self.stalled.get("memory", 0.0) >= STALLED:
            said.append("STALLED for want of memory")
        return ", ".join(said)

    def _said_of_limits(self) -> list[str]:
        """What is wrong, and what the sample was noted out of turn for."""
        wrong = self.wrong()
        nearer = [name for name in self.rose if name not in wrong]
        said = [wrong] if wrong else []
        return said + ([f"running low on {', '.join(nearer)}"] if nearer else [])

    def _said_of_memory(self) -> list[str]:
        if not self.memory:
            return []
        used, most = self.memory
        limit = None if most is None else amount(most)
        return ["mem " + of_limit(amount(used), limit, share(used, most))]

    def _said_of_cpu(self) -> list[str]:
        if self.cpu is None:
            return []
        said = f"cpu {self.cpu:.0f}%"
        if self.cpus is not None:
            said += f" of {self.cpus:g} cpus"
        if self.throttled:
            said += f", held back {self.throttled:.1f}s"
        return [said]

    def _said_of_processes(self) -> list[str]:
        if not self.pids:
            return []
        used, most = self.pids
        return [f"pids {used}" if most is None else f"pids {used} of {most}"]

    def _said_of_tmpfs(self) -> list[str]:
        return [
            f"{flat(place)} {percent}%"
            for place, percent in self.shares().items()
            if place in self.tmpfs and percent >= TMPFS_SHOWN
        ]

    def _said_of_waits(self) -> list[str]:
        waits = [
            f"{flat(what)} {percent:.0f}%"
            for what, percent in self.stalled.items()
            if percent >= WAIT_SHOWN
        ]
        return [f"waited for: {', '.join(waits)}"] if waits else []

    def _said_of_the_largest(self) -> list[str]:
        return [f"top: {self.largest[0].shown}"] if self.largest else []

    def detail(self) -> str:
        """The sample as one line: what is wrong if anything, then each
        figure there is."""
        return "  ".join(
            [
                *self._said_of_limits(),
                *self._said_of_memory(),
                *self._said_of_cpu(),
                *self._said_of_processes(),
                *self._said_of_tmpfs(),
                *self._said_of_waits(),
                *self._said_of_the_largest(),
            ]
        )

    def fields(self) -> dict:
        """The sample as named values, for --json: every figure there
        is, of each tmpfs and of each of the largest processes too."""

        def used(of: tuple[int, int | None], most: str = "limit") -> dict:
            return {"used": of[0], most: of[1]}

        fields: dict = {"seconds": self.seconds}
        if self.memory:
            fields["memory"] = used(self.memory)
        if self.pids:
            fields["pids"] = used(self.pids)
        if self.tmpfs:
            fields["tmpfs"] = {
                place: used(filled, "size") for place, filled in self.tmpfs.items()
            }
        if self.cpu is not None:
            fields.update(cpu=self.cpu, cpus=self.cpus, throttled=self.throttled)
        if self.stalled:
            fields["stalled"] = dict(self.stalled)
        if self.largest:
            fields["top"] = [process.fields for process in self.largest]
        if self.rose:
            fields["rose"] = list(self.rose)
        return fields

    def event(self) -> Event:
        fields = self.fields()
        wrong = self.wrong()
        if wrong:
            fields["flagged"] = wrong
        return Event(self.when, Who.SANDBOX, Kind.HEALTH, [self.detail()], fields)


@dataclass(frozen=True)
class Ended:
    """A process of the session was ended for want of memory: how often
    that has been so by then, and the large processes that were gone
    since the look before. The kernel ends the one that holds the most
    and does not say which, so those are the likely ones, not proof."""

    when: float
    times: int
    gone: tuple[Sized, ...] = ()

    @classmethod
    def read(cls, when: float, said: dict) -> Ended:
        gone = tuple(Sized.read(process) for process in said.get("gone", []))
        return cls(when, int(said["oom"]), gone)

    def event(self) -> Event:
        which = (
            "gone since: " + ", ".join(process.shown for process in self.gone)
            if self.gone
            else "which one was not seen"
        )
        detail = f"OUT OF MEMORY, a process was ended for it  {which}"
        fields = {
            "out_of_memory": self.times,
            "gone": [process.fields for process in self.gone],
            "flagged": "out of memory",
        }
        return Event(self.when, Who.SANDBOX, Kind.HEALTH, [detail], fields)


def read_health(when: float, said: dict) -> Sample | Ended | None:
    """What a line of the watcher says of the session's health, none for
    a line about something else. Raises ValueError, TypeError or KeyError
    for one that does not hold up."""
    if "health" in said:
        if not isinstance(said["health"], dict):
            raise TypeError("not a sample")
        return Sample.read(when, said["health"])
    if "oom" in said:
        return Ended.read(when, said)
    return None


def health_summary(samples: list[Sample], ended: list[Ended]) -> list[str]:
    """The lines of a trace's header on how the session did: the most
    memory it held, the CPU it used, and what it came near the limit of."""
    lines = []
    held = [sample.memory for sample in samples if sample.memory]
    if held:
        used, most = max(held, key=lambda memory: memory[0])
        limit = None if most is None else amount(most)
        lines.append(
            "  memory " + of_limit(amount(used), limit, share(used, most)) + " at most"
        )
    timed = [sample for sample in samples if sample.cpu is not None and sample.seconds]
    if timed:
        seconds = sum(sample.seconds for sample in timed)
        mean = sum((sample.cpu or 0.0) * sample.seconds for sample in timed) / seconds
        said = f"  cpu {mean:.0f}% on average, {max(s.cpu or 0.0 for s in timed):.0f}% at most"
        cpus = timed[-1].cpus
        if cpus is not None:
            said += f" of {cpus:g} cpus"
        held_back = sum(sample.throttled for sample in timed)
        if held_back:
            said += f", held back {held_back:.0f}s in all"
        lines.append(said)
    most_used: dict[str, int] = {}
    for sample in samples:
        for name, percent in sample.shares().items():
            if name != "memory":
                most_used[name] = max(most_used.get(name, 0), percent)
    lines += [
        f"  {flat(name)} {percent}% of its limit at most"
        for name, percent in most_used.items()
        if percent >= NEAR_LIMIT
    ]
    waited = max((s.stalled.get("memory", 0.0) for s in samples), default=0.0)
    if waited >= STALLED:
        lines.append(f"  STALLED for want of memory, up to {waited:.0f}% of the time")
    if ended:
        times = max(found.times for found in ended)
        lines.append(f"  OUT OF MEMORY, a process was ended for it {times} times")
    return lines
