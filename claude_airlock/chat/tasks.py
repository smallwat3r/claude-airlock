"""The tasks claude started and how far each is: a subagent it gave a
part of the work to, a command it left to run.

Claude Code says over the pipe when one starts and when it ends, and of
a subagent how far it is each time it makes a call: how many calls it
has made, how many tokens it holds, and what it is at. What a subagent
does is written as it does it (see followed.py), in lines among those of
every other one. Here is what those lines do not say at a glance: how
many subagents run, how many have ended, and how far each is.

That is said in a line when one starts and when it ends, counted in the
status above the prompt (see status.py), and while they run told in rows
of their own, see Progress."""

from __future__ import annotations

import dataclasses
import threading
import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass

from ..events import flat, labelled
from ..report.entries import measured, seconds
from .console import Page
from .drift import Drift
from .turn import tokens

# Of what a task is said to be about, and of what a subagent is at
ABOUT_WIDTH = 200
# Of the kind of a subagent, and of the tool it called last: names
KIND_WIDTH = 60
# The tasks remembered to name them when they end, and the subagents
# that have ended kept to count them
MOST_TASKS = 1000
# An id longer than this is none: they are kept, and a line of claude's
# can be as long as the session cares to make it
ID_WIDTH = 200
# The subagents /status says in a row each, and counts beyond that
MOST_IN_FULL = 50
# How Claude Code names the kind of task a subagent is
SUBAGENT = "local_agent"
# In the row of a subagent, how much of what it is to do and of what it
# is at: they share a row of the terminal with its figures
ROW_ABOUT = 32
ROW_DOING = 80
# Where one of them was cut, as a trace cuts a name (see shown_what of
# layout.py)
CUT = "~"
# How far in the row of each subagent is, under the row that counts them
INDENT = "  "
# The rows that say how far the subagents are, at most: one counts them,
# and each of the others is of one of them, those that started first. Of
# more subagents than that, the last row says how many have none
MOST_ROWS = 7
# A terminal gives the rows no more than one part in so many of its
# height: what is above the prompt is erased and written again by the
# rows it takes, and no more of them can be than are on the screen
HEIGHT_PART = 3
# Seconds before the rows are said where they are lines that stay, a
# file or a shell buffer of Emacs. The wait is doubled after each time,
# up to the second of these: they are not said more often than that
SAID_EVERY = 30.0
SAID_MOST = 120.0


@dataclass(frozen=True)
class Task:
    """A task claude started, as far as claude said of it. Not changed
    once made: what claude says of it later makes another in its place,
    so whoever was given one reads it while claude is listened to."""

    # What it is to do, in claude's words
    about: str
    # Whether it is a subagent, and the kind of one as Claude Code or the
    # user named it (Explore, general-purpose), empty when not said
    agent: bool = False
    kind: str = ""
    # When it was said to start, as time.monotonic has it
    began: float = 0.0
    # The calls it has made and the tokens it holds, none until it said
    calls: float | None = None
    tokens: float | None = None
    # What it is at, as it said with its last call
    doing: str = ""
    # The seconds it ran, once it has ended
    took: float | None = None

    @property
    def named(self) -> str:
        """What it is to do with the kind of subagent it is, as a line
        names it in full."""
        if self.about and self.kind:
            return f"{self.about} ({self.kind})"
        return self.about or self.kind


@dataclass(frozen=True)
class Running:
    """The tasks claude started that still run, as they are at one
    moment: its subagents in the order they started, and how many other
    tasks. With the subagents that have ended since one last started
    while none ran: they are one lot with those that run, what claude
    started together for a piece of work, and are counted with them."""

    agents: tuple[Task, ...] = ()
    ended: tuple[Task, ...] = ()
    others: int = 0

    @property
    def several(self) -> bool:
        """Whether the lot is of more than one subagent: they are then
        counted, where one alone is only named."""
        return len(self.agents) + len(self.ended) > 1


def _said(value: object, width: int) -> str:
    """A text claude gives of a task as it is shown: on one line, and no
    more of it than so much."""
    return flat(value or "")[:width]


def _task_id(message: dict) -> str | None:
    """The id of the task a message is about, none when it gives none
    that can be kept."""
    task_id = message.get("task_id")
    known = isinstance(task_id, str) and 0 < len(task_id) <= ID_WIDTH
    return task_id if known else None


def _of_a_subagent(message: dict) -> bool:
    """Whether a task that started is one a subagent started, as Claude
    Code says of it: in so many words, or by naming the task of the
    subagent that did. One that claude itself started names none."""
    owned = message.get("owned_by_subagent") is True
    return owned or isinstance(message.get("parent_task_id"), str)


class Tasks:
    """The tasks claude started, from what it says of them over the pipe
    (the system messages task_started, task_progress and
    task_notification). Taken in by the thread that listens to claude
    and asked for by the one that reads the user too (/status): under a
    lock, and given out as they are at one moment, see Running.

    Claude Code says the same of what a subagent started for itself, a
    command of its that runs for a while. That is no task of claude's:
    it is part of what the subagent does, which its calls and how far it
    is say already, and claude does not go on when it ends. So it is
    neither said nor counted. Not so a subagent that a subagent
    started, which is one more of them."""

    def __init__(self, drift: Drift | None = None) -> None:
        # Told what claude does not say of how far a task is any more
        self._drift = drift or Drift()
        self._lock = threading.Lock()
        # Those that run, by their ids, in the order they started
        self._running: dict[str, Task] = {}
        # The subagents of the lot that have ended, see Running, by
        # their ids: claude can say again how one ended, see ended
        self._ended: dict[str, Task] = {}
        # The ids of what subagents started for themselves and still
        # runs, for its end to be passed over as its start was
        self._theirs: set[str] = set()

    @property
    def running(self) -> Running:
        """What runs now, see Running."""
        with self._lock:
            tasks = tuple(self._running.values())
            ended = tuple(self._ended.values())
        agents = tuple(task for task in tasks if task.agent)
        return Running(agents, ended, len(tasks) - len(agents))

    def started(self, message: dict) -> Task | None:
        """Take in that a task started. The task, none when claude does
        not say which one it is, and for what a subagent started for
        itself. A subagent is told by the kind of task it is, and where
        a version of Claude Code does not say that, by its naming a kind
        of subagent."""
        task_id = _task_id(message)
        if task_id is None:
            return None
        kind = message.get("task_type")
        named = _said(message.get("subagent_type"), KIND_WIDTH)
        agent = kind == SUBAGENT or (kind is None and bool(named))
        if not agent and _of_a_subagent(message):
            with self._lock:
                if len(self._theirs) < MOST_TASKS:
                    self._theirs.add(task_id)
            return None
        about = _said(message.get("description"), ABOUT_WIDTH)
        task = Task(about, agent, named if agent else "", time.monotonic())
        with self._lock:
            if agent and not any(other.agent for other in self._running.values()):
                # The first of a new lot
                self._ended.clear()
            # One that claude takes up again has not ended, and what is
            # now a task of claude's is no longer a subagent's own
            self._ended.pop(task_id, None)
            self._theirs.discard(task_id)
            if task_id in self._running or len(self._running) < MOST_TASKS:
                self._running[task_id] = task
        return task

    def progressed(self, message: dict) -> None:
        """Take in how far a task is, which claude says of a subagent
        each time it makes a call: the calls it has made, the tokens it
        holds, and what it is at. Of one that is not known to run,
        nothing."""
        task_id = _task_id(message)
        if task_id is None:
            return
        with self._lock:
            task = self._running.get(task_id)
        if task is None:
            return
        # Only a subagent is shown by its figures, and missed without
        given = message.get("usage")
        if task.agent:
            usage = self._drift.field(message, "usage", dict) or {}
        else:
            usage = given if isinstance(given, dict) else {}
        calls = measured(usage.get("tool_uses"))
        held = measured(usage.get("total_tokens"))
        if task.agent and usage and calls is None:
            self._drift.missed("usage.tool_uses")
        if task.agent and usage and held is None:
            self._drift.missed("usage.total_tokens")
        further = dataclasses.replace(
            task,
            calls=task.calls if calls is None else calls,
            tokens=task.tokens if held is None else held,
            doing=self._doing(message, task),
        )
        with self._lock:
            # Unless it has ended, or started anew, meanwhile
            if self._running.get(task_id) is task:
                self._running[task_id] = further

    @staticmethod
    def _doing(message: dict, task: Task) -> str:
        """What a task is at, as claude says with how far it is: the
        status it gives when it gives one, else what the call it just
        made does (Reading src/main.py), which Claude Code says in the
        place of what the task is to do. A call that has no such words
        is said by the name of its tool, as a trace names it."""
        said = message.get("summary") or message.get("description")
        doing = _said(said, ABOUT_WIDTH)
        if doing and doing != task.about:
            return doing
        tool = _said(message.get("last_tool_name"), KIND_WIDTH).lower()
        return tool or task.doing

    def ended(self, message: dict) -> Task | None:
        """Take in that a task has ended. The task as it ended, with
        what it used in all when claude says so, and one about nothing
        for a task that was not known to run. None when claude does not
        say which one it is, and for what a subagent started for
        itself. Claude can say it again of a subagent, with what it then
        used: that is the same one, as it now ended, and not one more."""
        task_id = _task_id(message)
        if task_id is None:
            return None
        given = message.get("usage")
        usage = given if isinstance(given, dict) else {}
        calls = measured(usage.get("tool_uses"))
        held = measured(usage.get("total_tokens"))
        took = seconds(usage.get("duration_ms"))
        with self._lock:
            if task_id in self._theirs:
                self._theirs.discard(task_id)
                return None
            task = self._running.pop(task_id, None)
            if task is None:
                task = self._ended.get(task_id)
            elif took is None:
                took = time.monotonic() - task.began
            if task is None:
                return Task("")
            over = dataclasses.replace(
                task,
                calls=task.calls if calls is None else calls,
                tokens=task.tokens if held is None else held,
                took=task.took if took is None else took,
            )
            if over.agent and (task_id in self._ended or len(self._ended) < MOST_TASKS):
                self._ended[task_id] = over
        return over


def counted(running: Running) -> str:
    """How many of the subagents of a lot run, and how many of it have
    ended."""
    run, ended = len(running.agents), len(running.ended)
    if not run:
        return f"all {ended} ended" if ended else ""
    return f"{run} running, {ended} ended" if ended else f"{run} running"


def still_running(running: Running) -> str:
    """What claude left to run, in words: its subagents and its other
    tasks. Empty when nothing runs."""
    agents, others = len(running.agents), running.others
    named = []
    if agents:
        named.append("1 agent" if agents == 1 else f"{agents} agents")
    if others:
        named.append("1 task" if others == 1 else f"{others} tasks")
    if not named:
        return ""
    return f"{' and '.join(named)} still {'runs' if agents + others == 1 else 'run'}"


def _figures(calls: float | None, held: float | None, ran: float | None) -> str:
    """How far a subagent is, in figures: the calls it has made, the
    tokens it holds and the seconds it has run, each when known."""
    said = []
    if calls is not None:
        said.append(f"{calls:.0f} call{'' if round(calls) == 1 else 's'}")
    if held is not None:
        said.append(f"{tokens(held)} tokens")
    if ran is not None:
        said.append(f"{ran:.0f}s")
    return ", ".join(said)


def _used(tasks: Iterable[Task]) -> str:
    """What subagents used together, of those that said: the calls they
    made and the tokens they hold."""
    told = list(tasks)
    calls = [task.calls for task in told if task.calls is not None]
    held = [task.tokens for task in told if task.tokens is not None]
    return _figures(sum(calls) if calls else None, sum(held) if held else None, None)


def _cut(text: str, width: int) -> str:
    """A text as it fits a width, with a mark where it was cut."""
    return text if len(text) <= width else text[: width - len(CUT)] + CUT


def agent_row(task: Task, ran: float | None, whole: bool = False) -> str:
    """A subagent that runs, in a row: what it is to do, how far it is,
    for how many seconds it has run when that is said, and what it is
    at. Whole, with the kind of subagent it is and nothing cut, as
    /status says it. Else what it is to do and what it is at are cut,
    they share a row of the terminal with the figures."""
    if whole:
        about, doing = task.named, task.doing
    else:
        about = _cut(task.about or task.kind, ROW_ABOUT)
        doing = _cut(task.doing, ROW_DOING)
    figures = _figures(task.calls, task.tokens, ran)
    said = ": ".join(filter(None, (about, figures)))
    return ", ".join(filter(None, (said, doing)))


def _ran(task: Task, now: float | None) -> float | None:
    """The seconds a task has run by now, none when the time is not
    said."""
    return None if now is None else max(0.0, now - task.began)


def progress_rows(running: Running, now: float | None, most: int) -> list[str]:
    """How far the subagents that run are, as the rows that say it, none
    when none runs. One alone is said in a row. Several are counted in a
    first row, with those of the lot that have ended and what all of
    them used, and each that runs has a row under it, in the order they
    started. In no more than so many rows: of more subagents than there
    is room for, the first have a row and a last one says how many do
    not, and where there is room for two rows or less they are only
    counted. Without a time, how long each has run is not said: rows
    that are written again in their place then change when a subagent
    gets further and not as the time goes by, which would write the
    prompt again every so often under someone who types."""
    agents = running.agents
    if not agents:
        return []
    if not running.several:
        return [labelled("agent", agent_row(agents[0], _ran(agents[0], now)))]
    used = _used([*agents, *running.ended])
    count = counted(running)
    rows = [labelled("agents", f"{count}: {used}" if used else count)]
    shown = agents if len(agents) < most else agents[: max(0, most - 2)]
    rows += [INDENT + agent_row(task, _ran(task, now)) for task in shown]
    left = len(agents) - len(shown)
    return [*rows, f"{INDENT}and {left} more"] if left and shown else rows


def rows_in_full(running: Running, now: float | None = None) -> list[str]:
    """Each subagent that runs as /status says it, in a row of its own
    and whole, see agent_row: the first of them, and how many more
    there are past MOST_IN_FULL."""
    now = time.monotonic() if now is None else now
    shown = running.agents[:MOST_IN_FULL]
    rows = [agent_row(task, _ran(task, now), whole=True) for task in shown]
    left = len(running.agents) - len(shown)
    return [*rows, f"and {left} more"] if left else rows


def started_line(task: Task, running: Running) -> str:
    """What is said of a task that started. Of a subagent the kind it is
    too, and how many now run when it is not the only one of its lot."""
    if not task.agent:
        return labelled("task", f"started: {task.about}".rstrip())
    line = labelled("agent", f"started: {task.named}".rstrip())
    return f"{line}  {counted(running)}" if running.several else line


def ended_line(task: Task, status: str, running: Running) -> str:
    """What is said of a task that has ended, by how claude says it
    ended. Of a subagent what it used in all too, the calls it made, the
    tokens it held and the seconds it ran, and how many of its lot still
    run when it was not the only one."""
    if not task.agent:
        return labelled("task", f"{status}: {task.about}".rstrip(": "))
    used = _figures(task.calls, task.tokens, task.took)
    about = ", ".join(filter(None, (task.about or task.kind, used)))
    line = labelled("agent", f"{status}: {about}".rstrip(": "))
    return f"{line}  {counted(running)}" if running.several else line


class Progress:
    """Says how far the subagents of claude are while they run, in the
    rows of progress_rows. At a terminal above the status, written again
    in their place when one of them gets further, as the line that says
    a turn still runs is, and without how long each has run: the line
    of the turn says the time. Anywhere else in lines that stay, a file or a shell
    buffer of Emacs: after a while, then less and less often for it not
    to fill with them, and only when a subagent has got further since
    they were last said."""

    def __init__(
        self,
        page: Page,
        running: Callable[[], Running],
        held: Callable[[], bool] = lambda: False,
    ):
        self._page = page
        # What runs now, see Tasks.running
        self._running = running
        # Whether no line is to be written for how far they are just
        # now: the user is asked something, and the question waits under
        # what is written, or a reply of claude's is being written, which
        # nothing else is written into
        self._held = held
        # How long the rows are not said, where they are lines that stay
        self.wait = SAID_EVERY
        # Since when: they were last said, or subagents began to run
        self.since: float | None = None
        # The subagents as they were when the rows were last said
        self._told: tuple[tuple[Task, ...], ...] = ()

    def show(self) -> None:
        """Say how far the subagents are, when it is time to."""
        running = self._running()
        now = time.monotonic()
        if self._page.redrawn:
            most = max(1, min(MOST_ROWS, self._page.height // HEIGHT_PART))
            self._page.progress(progress_rows(running, None, most))
            return
        if not running.agents:
            # The next lot is waited for from its start
            self.wait, self.since, self._told = SAID_EVERY, None, ()
            return
        if self.since is None:
            self.since = now
        told = (running.agents, running.ended)
        if now - self.since < self.wait or told == self._told or self._held():
            return
        self._page.say(progress_rows(running, now, MOST_ROWS))
        self.wait = min(self.wait * 2, SAID_MOST)
        self.since, self._told = now, told
