"""The status of a chat, above its prompt as the head of a shell's prompt
is: the model and the effort it is asked for, the permission mode when it
changed, how full its context is, the limits of the account, what the
session cost, and the sandbox it runs in. Written again at the end of
each turn, and when /status asks, which says it in a line too, and under
it what the line has no room for.

The chat makes it of what it knows: what claude says as it goes, and what
the launcher started the session with. Claude Code's own statusline (the
statusLine command of the settings) is made for its screen, it is not run
here. What is not known yet is left out."""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from datetime import datetime

from ..events import flat, labelled
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
    header_with,
    painted,
    together,
)
from .console import Page
from .drift import Drift
from .said import Session
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

# A part of the status: its style, and its text
type Part = tuple[str, str]
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
        dirs = tuple(home_relative(mounted, home) for mounted in start.dirs)
        return cls(name, start.net_filter, start.asks, start.open, dirs)

    def parts(self) -> list[Part]:
        """The sandbox as parts of the status, with of what is open to
        it what OPEN_STYLES names."""
        parts = [(NAME_STYLE, f"[{flat(self.name)}]")]
        filtered = "net:ask" if self.net_ask else "net:filtered"
        parts.append((DIM, filtered) if self.net_filter else (YELLOW, "net:open"))
        parts += [
            (OPEN_STYLES[opened], opened)
            for opened in self.open
            if opened in OPEN_STYLES
        ]
        if self.dirs:
            parts.append((DIM, "dirs: " + " ".join(flat(d) for d in self.dirs)))
        return parts


def home_relative(path: str, home: str) -> str:
    """A path as the shell shortens it, ~ for the home directory."""
    return "~" + path[len(home) :] if path.startswith(home + "/") else path


def used_style(percent: float) -> str:
    """How much of a limit or of the context is used, as its colour."""
    if percent >= ALARM_AT:
        return RED
    return YELLOW if percent >= WARN_AT else DIM


def starts_again(resets: float, now: float, dated: bool = False) -> str:
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


def limit_parts(
    limits: Limits, model: str = "", now: float | None = None
) -> list[Part]:
    """What is used of each window of the limits claude said, for a
    session of that model, with when the shortest one starts again, and
    the others once they are nearly used up."""
    now = time.time() if now is None else now
    parts = []
    for kind, window in current(limits, model, now):
        used = window["used_percentage"]
        text = f"{WINDOWS[kind]}:{used:.0f}% used"
        resets = window.get("resets_at")
        if resets and (kind == SHORT or used >= WARN_AT):
            text += " " + starts_again(resets, now)
        parts.append((used_style(used), text))
    return parts


def more_said(
    session: Session, usage: Usage, limits: Limits, now: float | None = None
) -> list[str]:
    """What /status says besides the line, which has no room for it: the
    version of Claude Code, how much the context holds, and when each
    limit starts again."""
    now = time.time() if now is None else now
    said = [f"Claude Code {session.version}"] if session.version else []
    if usage.window and usage.context:
        said.append(f"context {tokens(usage.context)} of {tokens(usage.window)}")
    again = [
        f"{WINDOWS[kind]} {starts_again(window['resets_at'], now, dated=True)}"
        for kind, window in current(limits, model_of(session), now)
        if window.get("resets_at")
    ]
    if again:
        said.append("limits start again: " + ", ".join(again))
    return said


def model_of(session: Session) -> str:
    """The model of a session by the name Claude Code shows, empty until
    claude named it."""
    return session.chosen or (display_name(session.model) if session.model else "")


def status_parts(
    session: Session, usage: Usage, limits: Limits, sandbox: Sandbox
) -> list[Part]:
    """The parts of the status, in the order they are shown."""
    parts: list[Part] = []
    model = model_of(session)
    if model:
        parts.append((BOLD, model))
    if session.effort:
        parts.append((DIM, f"effort:{session.effort}"))
    if session.fast:
        parts.append((DIM, "fast"))
    # The prompt is the same in every mode. Said when it is not the one
    # the session started in, and of plan always: a prompt is not acted
    # on there
    if session.mode and (session.mode != session.first_mode or session.mode == PLAN):
        parts.append((DIM, f"mode:{session.mode}"))
    if usage.window and usage.context:
        used = min(100, round(100 * usage.context / usage.window))
        parts.append((used_style(used), f"ctx:{used}%"))
    parts += limit_parts(limits, model)
    if usage.spent:
        parts.append((DIM, f"${usage.spent:.2f}"))
    return parts + sandbox.parts()


def status_line(parts: list[Part], colour: bool) -> str:
    """The parts as one line, each in its colour when in colour."""
    if colour:
        return " ".join(painted(style, text) for style, text in parts)
    return " ".join(text for _, text in parts)


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
    ):
        self._page = page
        self._sandbox = sandbox
        self._session = session
        self._usage = usage
        self.limits = Limits(drift=drift or Drift())

    def refresh(self) -> str:
        """Make the status and keep it above the prompt. Returns it."""
        parts = status_parts(self._session, self._usage, self.limits, self._sandbox)
        line = status_line(parts, self._page.layout.colour)
        self._page.head([line])
        return line

    def show(self) -> None:
        """Say the status, as /status asks, and what the line leaves
        out, see more_said."""
        line = self.refresh()
        head = labelled("status", "")
        self._page.put([header_with(head, line, self._page.layout.colour)])
        more = more_said(self._session, self._usage, self.limits)
        if more:
            self._page.note("status", ", ".join(more))
