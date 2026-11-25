"""The status of a chat, above its prompt as the head of a shell's prompt
is: the sandbox it runs in, then the model and the effort it is asked
for, the permission mode when it changed, the tasks claude left to run,
how full its context is, the limits of the account and what the session
cost. Made again whenever what it says may have changed, and said in
full when /status asks, a line for each thing.

It takes one row where the terminal has room for it, said shorter if
need be, and two where it has not: the sandbox over the session, or the
model next to the sandbox where less is lost that way (see status_rows).
In a row that is still too short the parts give way, the least needed
first, and a mark says that some did (see fitted): nothing is cut where
the row ends without a word. What is open to the session never gives
way.

The chat makes it of what it knows: what the launcher started the
session with, which is the launcher's own word and comes first, and what
claude says as it goes. Claude Code's own statusline (the statusLine
command of the settings) is made for its screen, it is not run here.
What is not known yet is left out."""

from __future__ import annotations

import dataclasses
import enum
import re
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import datetime

from ..events import LABEL_WIDTH, flat, labelled
from ..recording.started import (
    ALL_HISTORY,
    DOCKER_FULL,
    DOCKER_PS,
    RW_CONFIG,
    SSH_AGENT,
    Start,
)
from ..report.entries import LATEST, measured
from ..report.layout import (
    BOLD,
    DIM,
    GREEN,
    RED,
    YELLOW,
    painted,
    together,
)
from .console import Page
from .drift import Drift
from .said import Session
from .screen import columns_at_most
from .turn import Usage, tokens

# The windows of the limits of the account that are shown, as claude
# names them, with how the status names them. An account has those of its
# plan, not all of them: one without a limit by the hour has no 5h
WINDOWS = {"five_hour": "5h", "seven_day": "7d", "seven_day_overage_included": "fable"}
# Those that are the week of one model alone, each with what the name of
# that model holds: shown while it is the model of the session. Claude
# Code names this one the Fable limit, and says it of no other model
OF_A_MODEL = {"seven_day_overage_included": "fable"}
# The one that starts again within the day, and says when at all times.
# The others say it once they are nearly used up
SHORT = "five_hour"
# Claude gives what is used of a window as a part of it, which is more
# than the whole once a session went on past the limit. Not this much more
MOST_USED = 10
# How long before a window starts again the hour says when, the day too
# from there on
DAY = 24 * 3600
# How the name of the session is coloured
NAME_STYLE = together(BOLD, GREEN)
# From how many percent used a limit or the context is yellow, and red
WARN_AT = 70
ALARM_AT = 90
# The permission mode in which claude plans and changes nothing
PLAN = "plan"
_MODEL = re.compile(r"claude-([a-z]+)-(\d+)(?:-(\d{1,2}))?(?:-\d{8})?(\[1m\])?")
# What is between two groups of a row, and between the parts of a group:
# a reader tells what belongs together without colour too, the time a
# limit starts again from the limit after it
GROUP_GAP = "  "
PART_GAP = " "
# Where a name was cut, as a trace cuts one (see shown_what of layout.py)
CUT = "~"
# No less of the name of a sandbox is shown than this, in its brackets
NAME_LEAST = 10
# How far in /status has each of its lines under the first, and how wide
# what the line is about: its text starts where that of the first does,
# after the label (see labelled)
INDENT = "  "
ABOUT_WIDTH = LABEL_WIDTH - len(INDENT)


class Rank(enum.IntEnum):
    """How soon a part is left out of a row that has no room for it, the
    lowest first: what the session cost, when a limit that is far from
    used up starts again, how the model is asked to work, what is mounted
    next to the project, a limit that is far from used up, and last how
    full the context is while it is far from full. What has no rank is
    never left out: the sandbox, its network and what is open to it, the
    model, the mode, the tasks that run, and whatever is nearly used up."""

    COST = 1
    RESET = 2
    EFFORT = 3
    DIRS = 4
    LIMIT = 5
    CONTEXT = 6


@dataclass(frozen=True)
class Part:
    """A part of the status: its text, in its style. Where a row has no
    room for it, it is said the shorter way it has (terse), and left out
    when it has a rank, see Rank. One that is kept and still too long,
    the name of a sandbox in its brackets, is cut to no less than so
    many columns (least), none for not at all."""

    style: str
    text: str
    terse: str = ""
    rank: Rank | None = None
    least: int = 0


# The parts that are said together, with one space between them
type Group = list[Part]
# What a row ends with when parts were left out of it: /status says them
LEFT_OUT = Part(DIM, "...")
# What of that which is open to a session the status shows, each with its
# colour: yellow what widens what a session reaches, red what shows every
# container on the host with its secrets
OPEN_STYLES = {
    SSH_AGENT: YELLOW,
    DOCKER_PS: YELLOW,
    DOCKER_FULL: RED,
    RW_CONFIG: YELLOW,
    ALL_HISTORY: YELLOW,
}


def display_name(model: str) -> str:
    """The name of a model as Claude Code shows it, Opus 5.5 for
    claude-opus-5-5, or its id when it is not one of those."""
    named = _MODEL.fullmatch(model)
    if not named:
        return model
    family, major, minor, million = named.groups()
    name = f"{family.capitalize()} {major}" + (f".{minor}" if minor else "")
    return name + (" (1M context)" if million else "")


@dataclass
class Limits:
    """What claude said of the limits of the account, by window."""

    windows: dict[str, dict] = field(default_factory=dict)
    # Told when claude says nothing of how much of a window is used
    drift: Drift = field(default_factory=Drift, repr=False, compare=False)

    def heard(self, info: object) -> None:
        """Take in what claude said of the limits. It names the window
        the message is about, with its figures beside the name, and since
        a later version all the windows by name under unifiedWindows,
        where the figures then are. A message about a window that is
        shown says how much of one is used: none is missed."""
        if not isinstance(info, dict):
            return
        about = info.get("rateLimitType")
        windows = info.get("unifiedWindows")
        said = [(about, info)]
        if isinstance(windows, dict):
            said += windows.items()
        # All of them are kept, not only up to the first that has a figure
        used = [self._window(kind, figures) for kind, figures in said]
        shown = any(isinstance(kind, str) and kind in WINDOWS for kind, _ in said)
        if shown and not any(used):
            self.drift.missed("utilization")

    def _window(self, kind: object, said: object) -> bool:
        """Keep what is said of one window, of those that are shown.
        Whether that says how much of it is used."""
        # A name, and not what cannot be looked up as one
        if not isinstance(kind, str) or kind not in WINDOWS:
            return False
        if not isinstance(said, dict):
            # Not the figures of a window
            return False
        window: dict = {}
        # A fraction of the limit, as the API says it
        used = measured(said.get("utilization"))
        if used is not None and 0 <= used <= MOST_USED:
            window["used_percentage"] = round(used * 100, 1)
        resets = measured(said.get("resetsAt"))
        # A time that can be shown as one, see LATEST of report/entries.py
        if resets and resets <= LATEST:
            window["resets_at"] = int(resets)
        self.windows[kind] = {**self.windows.get(kind, {}), **window}
        return "used_percentage" in window


@dataclass(frozen=True)
class Sandbox:
    """What the session was started with, as the status shows it: its
    container, whether its network is filtered, what is open to it and
    what more than the project is mounted. Taken from how the launcher
    started it (see started.py), which is of the session and not of the
    settings."""

    name: str
    net_filter: bool = False
    # Whether the user is asked about a host the filter does not allow
    net_ask: bool = False
    # What is open to it that is closed by default, as a start names it
    open: tuple[str, ...] = ()
    # Each as it is shown, (ro) after one that is read-only
    dirs: tuple[str, ...] = ()

    @classmethod
    def started(cls, name: str, start: Start, home: str) -> Sandbox:
        """The sandbox of a session of that name, started so."""
        dirs = tuple(_home_relative(mounted, home) for mounted in start.dirs)
        return cls(name, start.net_filter, start.asks, start.open, dirs)

    @property
    def network(self) -> str:
        """Its network as the status names it."""
        if not self.net_filter:
            return "net:open"
        return "net:ask" if self.net_ask else "net:filtered"

    def parts(self) -> Group:
        """The sandbox as the parts of the status that are said
        together, with of what is open to it what OPEN_STYLES names.
        Where there is no room, what is mounted is said by how many
        there are, and the name is the one part that is cut."""
        parts = [Part(NAME_STYLE, f"[{flat(self.name)}]", least=NAME_LEAST)]
        parts.append(Part(DIM if self.net_filter else YELLOW, self.network))
        parts += [
            Part(OPEN_STYLES[opened], opened)
            for opened in self.open
            if opened in OPEN_STYLES
        ]
        if self.dirs:
            mounted = "dirs: " + " ".join(flat(d) for d in self.dirs)
            parts.append(Part(DIM, mounted, f"dirs:{len(self.dirs)}", Rank.DIRS))
        return parts

    def said_in_full(self) -> list[tuple[str, str]]:
        """The sandbox as /status says it, each thing with what it is
        about, in the words the start of a session is said in."""
        network = "filtered to the allowed domains" if self.net_filter else "open"
        if self.net_ask:
            network += ", you are asked about others"
        said = [("sandbox", f"{flat(self.name)}, network {network}")]
        if self.open:
            said.append(("open", ", ".join(flat(opened) for opened in self.open)))
        if self.dirs:
            said.append(("mounted", ", ".join(flat(d) for d in self.dirs)))
        return said


def _home_relative(path: str, home: str) -> str:
    """A path as the shell shortens it, ~ for the home directory."""
    return "~" + path[len(home) :] if path.startswith(home + "/") else path


def _used_style(percent: float) -> str:
    """How much of a limit or of the context is used, as its colour."""
    if percent >= ALARM_AT:
        return RED
    return YELLOW if percent >= WARN_AT else DIM


def _starts_again(resets: float, now: float, dated: bool = False) -> str:
    """When a window starts again, as short as tells it apart: the hour
    within a day, with the day of the week further off. Dated, the day
    of the month too, for what is said once and not kept in sight."""
    at = datetime.fromtimestamp(resets)
    if dated:
        return f"{at:%a %d %b %H:%M}"
    return f"{at:%H:%M}" if resets - now < DAY else f"{at:%a %H:%M}"


def current(limits: Limits, model: str, now: float) -> list[tuple[str, dict]]:
    """The windows of the limits claude said that hold now, each under
    its name. Not one that has started again since: what was used of it
    is used no longer, and claude says the new one with its next reply.
    Not the week of a model that is not the session's."""
    held = []
    for kind in WINDOWS:
        window = limits.windows.get(kind, {})
        resets = window.get("resets_at")
        other = kind in OF_A_MODEL and OF_A_MODEL[kind] not in model.lower()
        if "used_percentage" in window and not other and not (resets and resets <= now):
            held.append((kind, window))
    return held


def limit_groups(
    limits: Limits, model: str = "", now: float | None = None
) -> list[Group]:
    """What is used of each window of the limits claude said, for a
    session of that model, each with when it starts again: the shortest
    one always, the others once they are nearly used up. One that is
    nearly used up is never left out, nor is when it starts again, which
    is what there is to wait for."""
    now = time.time() if now is None else now
    groups = []
    for kind, window in current(limits, model, now):
        used = window["used_percentage"]
        near = used >= WARN_AT
        style = _used_style(used)
        said = f"{WINDOWS[kind]}:{used:.0f}%"
        group = [Part(style, f"{said} used", said, None if near else Rank.LIMIT)]
        resets = window.get("resets_at")
        if resets and (kind == SHORT or near):
            again = _starts_again(resets, now)
            group.append(Part(style, again, rank=None if near else Rank.RESET))
        groups.append(group)
    return groups


def _model_of(session: Session) -> str:
    """The model of a session by the name Claude Code shows, empty until
    claude named it."""
    return session.chosen or (display_name(session.model) if session.model else "")


def _mode_shown(session: Session) -> bool:
    """Whether the status says the permission mode. The prompt is the
    same in every mode: said when it is not the one the session started
    in, and of plan always, a prompt is not acted on there."""
    return bool(session.mode) and (
        session.mode != session.first_mode or session.mode == PLAN
    )


def named_group(session: Session, tasks: int = 0) -> Group:
    """How claude is set and what it does, as the parts of the status
    that are said together: the model with how it is asked to work, the
    permission mode when the status says it, and the tasks claude
    started that still run. The mode stands out, it changes what a
    prompt does, and so do the tasks: claude goes on by itself when one
    of them ends."""
    model = _model_of(session)
    named = [Part(BOLD, model)] if model else []
    if session.effort:
        named.append(Part(DIM, f"effort:{session.effort}", rank=Rank.EFFORT))
    if session.fast:
        named.append(Part(DIM, "fast", rank=Rank.EFFORT))
    if _mode_shown(session):
        named.append(Part(BOLD, f"mode:{session.mode}"))
    if tasks:
        named.append(Part("", f"tasks:{tasks}"))
    return named


def used_groups(
    session: Session, usage: Usage, limits: Limits, now: float | None = None
) -> list[Group]:
    """What the session used, as the groups of the status, in the order
    they are shown: how full the context is, each limit of the account
    that holds for its model, and what it cost."""
    groups: list[Group] = []
    if usage.window and usage.context:
        used = min(100, round(100 * usage.context / usage.window))
        rank = None if used >= WARN_AT else Rank.CONTEXT
        groups.append([Part(_used_style(used), f"ctx:{used}%", rank=rank)])
    groups += limit_groups(limits, _model_of(session), now)
    if usage.spent:
        groups.append([Part(DIM, f"${usage.spent:.2f}", rank=Rank.COST)])
    return groups


def row_text(groups: list[Group], colour: bool = False) -> str:
    """Groups as one row, each part in its colour when in colour."""
    return GROUP_GAP.join(
        PART_GAP.join(
            painted(part.style, part.text) if colour else part.text for part in group
        )
        for group in groups
        if group
    )


def _columns(groups: list[Group]) -> int:
    """How many columns a row of groups takes, in the terminal that gives
    it the most: a name is the session's to choose, and a row that is
    counted too short is cut where it ends."""
    return sum(map(columns_at_most, row_text(groups)))


def _cut(part: Part, columns: int) -> Part:
    """A part with so many columns less, as far as it may be cut: a mark
    where it was, and the character it ends with kept, the bracket that
    closes a name."""
    kept = max(part.least, len(part.text) - columns)
    if not part.least or kept >= len(part.text):
        return part
    cut = part.text[: max(0, kept - len(CUT) - 1)] + CUT + part.text[-1]
    return dataclasses.replace(part, text=cut)


def _tersely(groups: list[Group]) -> list[Group]:
    """Groups with each part said the shorter way it has."""
    return [
        [dataclasses.replace(part, text=part.terse or part.text) for part in group]
        for group in groups
    ]


def fitted(groups: list[Group], room: int) -> list[Group]:
    """The groups of a row as they fit so many columns. All of each part
    where there is room. Else every part is said the shorter way it has,
    and then one after the other is left out, by its rank and of a rank
    the last first, until the rest fits: a mark at the end of the row
    says that something was, and /status says all of it. What has no
    rank stays, and where that alone is too long the name of the sandbox
    is cut."""
    if _columns(groups) <= room:
        return groups
    row = _tersely(groups)
    # The parts that can be left out from the last to the first, then in
    # the order they give way: by rank, of a rank still the last first
    last_first = [part for group in reversed(row) for part in reversed(group)]
    ranked = [part for part in last_first if part.rank is not None]
    giving = sorted(ranked, key=lambda part: part.rank or 0)

    def without(gone: list[Part]) -> list[Group]:
        """The row without the parts that are gone, which a mark at its
        end says when any is."""
        left = [
            [part for part in group if not any(part is one for one in gone)]
            for group in row
        ]
        return [group for group in left if group] + ([[LEFT_OUT]] if gone else [])

    kept = row
    for gone in range(len(giving) + 1):
        kept = without(giving[:gone])
        if _columns(kept) <= room:
            return kept
    over = _columns(kept) - room
    return [[_cut(part, over) for part in group] for group in kept]


def _left_out(groups: list[Group], room: int) -> tuple[int, bool]:
    """What a row loses where it has so many columns: how many of its
    parts are left out, and whether the others are said the shorter
    way."""
    kept = sum(part is not LEFT_OUT for group in fitted(groups, room) for part in group)
    return sum(map(len, groups)) - kept, _columns(groups) > room


def status_rows(
    sandbox: Group, named: Group, used: list[Group], room: int | None
) -> list[list[Group]]:
    """The status as the rows it is written on: the sandbox, how claude
    is set, and what the session used. One row where there is room for
    all of it, as there always is in a file, where a line is as long as
    it is, and still one where it fits with each part said the shorter
    way it has: a row less above every prompt is worth more than a
    word. Else two, each fitted to the room there is (see fitted). The
    sandbox over the session, which is the row next to the prompt, the
    one that changes. Unless more is lost that way than with how claude
    is set next to the sandbox, and what was used on a row of its own:
    a sandbox with a short name leaves most of its row free. Only where
    that row has room for both as they are: nothing of the sandbox
    gives way for it."""
    session = [group for group in (named, *used) if group]
    whole = [sandbox, *session]
    if room is None or _columns(whole) <= room:
        return [whole]
    if _columns(_tersely(whole)) <= room:
        return [_tersely(whole)]
    ways = [([sandbox], session)]
    if named and used and _columns([sandbox, named]) <= room:
        ways.append(([sandbox, named], used))

    def lost(rows: tuple[list[Group], list[Group]]) -> tuple[int, int]:
        """All that a way to break the status loses, the parts it
        leaves out before those it says shorter."""
        left, shorter = zip(*(_left_out(row, room) for row in rows), strict=True)
        return sum(left), sum(shorter)

    # The first of those that lose the least: the sandbox on its own row
    rows = min(ways, key=lost)
    return [fitted(row, room) for row in rows if row]


def _limits_in_full(limits: Limits, model: str, now: float) -> list[str]:
    """Each limit that holds now as /status says it: how much of it is
    used, and the day and time it starts again."""
    said = []
    for kind, window in current(limits, model, now):
        line = f"{WINDOWS[kind]}: {window['used_percentage']:.0f}% used"
        if window.get("resets_at"):
            again = _starts_again(window["resets_at"], now, dated=True)
            line += f", starts again {again}"
        said.append(line)
    return said


def said_in_full(
    sandbox: Sandbox,
    session: Session,
    usage: Usage,
    limits: Limits,
    tasks: int = 0,
    now: float | None = None,
) -> list[str]:
    """What /status says: all that the status above the prompt says in
    short, in words and never cut, each thing on a line after what it is
    about, and what the status has no room for at all: how many tokens
    the context holds, the day each limit starts again, the session and
    the version of Claude Code. What is not known yet is left out."""
    now = time.time() if now is None else now
    model = _model_of(session)
    said = sandbox.said_in_full()
    asked = [model] if model else []
    asked += [f"effort {session.effort}"] if session.effort else []
    asked += ["fast mode"] if session.fast else []
    if asked:
        said.append(("model", ", ".join(asked)))
    if session.mode:
        plans = ", claude plans and changes nothing" if session.mode == PLAN else ""
        said.append(("mode", session.mode + plans))
    if tasks:
        runs = "1 still runs" if tasks == 1 else f"{tasks} still run"
        said.append(("tasks", f"{runs}, claude goes on when one ends"))
    if usage.window and usage.context:
        used = min(100, round(100 * usage.context / usage.window))
        held = f"{tokens(usage.context)} of {tokens(usage.window)} tokens"
        said.append(("context", f"{used}% used, {held}"))
    for at, limit in enumerate(_limits_in_full(limits, model, now)):
        said.append(("" if at else "limits", limit))
    if usage.spent:
        said.append(("cost", f"${usage.spent:.2f}, as Claude Code counts it"))
    if session.id:
        said.append(("session", session.id))
    if session.version:
        said.append(("version", f"Claude Code {session.version}"))
    first = labelled("status", "what the status above the prompt says, in full:")
    return [first, *(f"{INDENT}{about:<{ABOUT_WIDTH}}{text}" for about, text in said)]


class StatusLine:
    """The status of a chat, see the module: of a session and of what
    it used, as they are when it is made."""

    def __init__(
        self,
        page: Page,
        sandbox: Sandbox,
        session: Session,
        usage: Usage,
        drift: Drift | None = None,
        tasks: Callable[[], int] = lambda: 0,
    ):
        self._page = page
        self._sandbox = sandbox
        self._session = session
        self._usage = usage
        # How many of the tasks claude started still run
        self._tasks = tasks
        self.limits = Limits(drift=drift or Drift())

    def refresh(self) -> list[str]:
        """Make the status and keep it above the prompt, in the rows
        that fit the page as wide as it is now. Returns them."""
        named = named_group(self._session, self._tasks())
        used = used_groups(self._session, self._usage, self.limits)
        rows = status_rows(self._sandbox.parts(), named, used, self._page.width)
        lines = [row_text(row, self._page.layout.colour) for row in rows]
        self._page.head(lines)
        return lines

    def show(self) -> None:
        """Say the status in full, as /status asks, see said_in_full."""
        self.refresh()
        self._page.say(
            said_in_full(
                self._sandbox, self._session, self._usage, self.limits, self._tasks()
            )
        )
