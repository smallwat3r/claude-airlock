"""The status of a chat, above its prompt as the head of a shell's prompt
is: the model, the permission mode when it changed, how full its context is, the limits of the account, what
the session cost, and the sandbox it runs in. Written again at the end of
each turn, and when /status asks, which says it in a line too.

The chat makes it of what it knows: what claude says as it goes, and what
the launcher started the session with. Claude Code's own statusline (the
statusLine command of the settings) is made for its screen, it is not run
here. What is not known yet is left out."""

from __future__ import annotations

import re
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
from ..report.layout import BOLD, DIM, GREEN, RED, YELLOW, painted, together
from .console import Page
from .drift import Drift
from .said import Session
from .turn import Usage

# The windows of the limits of the account that are shown, as claude
# names them, with how the status names them
WINDOWS = {"five_hour": "5h", "seven_day": "7d"}
# How the name of the session is coloured
NAME_STYLE = together(BOLD, GREEN)
# From how many percent used a limit or the context is yellow, and red
WARN_AT = 70
ALARM_AT = 90
# The permission mode in which claude plans and changes nothing
PLAN = "plan"
_MODEL = re.compile(r"claude-([a-z]+)-(\d+)(?:-(\d{1,2}))?(?:-\d{8})?(\[1m\])?")

# A part of the status: its style, and its text
Part = tuple[str, str]
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
        if used is not None and used <= 1:
            window["used_percentage"] = round(used * 100, 1)
        resets = measured(said.get("resetsAt"))
        # A time that can be shown as one, see LATEST of transcript.py
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
    # What is open to it that is closed by default, as a start names it
    open: tuple[str, ...] = ()
    # Each as it is shown, (ro) after one that is read-only
    dirs: tuple[str, ...] = ()

    @classmethod
    def started(cls, name: str, start: Start, home: str) -> Sandbox:
        """The sandbox of a session of that name, started so."""
        dirs = tuple(home_relative(mounted, home) for mounted in start.dirs)
        return cls(name, start.net_filter, start.open, dirs)

    def parts(self) -> list[Part]:
        """The sandbox as parts of the status, with of what is open to
        it what OPEN_STYLES names."""
        parts = [(NAME_STYLE, f"[{flat(self.name)}]")]
        parts.append((DIM, "net:filtered") if self.net_filter else (YELLOW, "net:open"))
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


def limit_parts(limits: Limits) -> list[Part]:
    """What is used of each window of the limits claude said, with when
    the shorter one starts again."""
    parts = []
    for kind, label in WINDOWS.items():
        window = limits.windows.get(kind, {})
        used = window.get("used_percentage")
        if used is None:
            continue
        text = f"{label}:{used:.0f}% used"
        resets = window.get("resets_at")
        if resets and kind == "five_hour":
            text += f" {datetime.fromtimestamp(resets):%H:%M}"
        parts.append((used_style(used), text))
    return parts


def status_parts(
    session: Session, usage: Usage, limits: Limits, sandbox: Sandbox
) -> list[Part]:
    """The parts of the status, in the order they are shown."""
    parts: list[Part] = []
    model = session.chosen or (display_name(session.model) if session.model else "")
    if model:
        parts.append((BOLD, model))
    # The prompt is the same in every mode. Said when it is not the one
    # the session started in, and of plan always: a prompt is not acted
    # on there
    if session.mode and (session.mode != session.first_mode or session.mode == PLAN):
        parts.append((DIM, f"mode:{session.mode}"))
    if usage.window and usage.context:
        used = min(100, round(100 * usage.context / usage.window))
        parts.append((used_style(used), f"ctx:{used}%"))
    parts += limit_parts(limits)
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
        """Say the status, as /status asks."""
        line = self.refresh()
        head = labelled("status", "")
        if self._page.layout.colour:
            self._page.put([painted(DIM, "# " + head) + line])
        else:
            self._page.put([f"# {head}{line}"])
