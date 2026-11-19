"""The turns of a chat: one runs from a prompt, or from claude saying
that it starts one, until claude says that it is over. What is counted
of each, and the lines that tell of it."""

from __future__ import annotations

import dataclasses
import threading
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass

from ..events import flat, labelled
from ..report import brief
from ..report.entries import INPUT_TOKENS, content_blocks, measured
from .console import Page
from .drift import Drift
from .said import own

# Seconds claude takes no step before a line says that the turn still
# runs, and the most between two such lines: the wait is doubled after
# each. At a terminal the line is one, said again in its place every
# QUIET seconds.
QUIET = 5.0
QUIET_MOST = 60.0


@dataclass
class Turn:
    """One turn, as far as counted."""

    started: float
    # The calls claude said it made, and those of them that were shown
    said: int = 0
    shown: int = 0
    interrupted: bool = False
    # Whether claude is thinking, as far as it says
    thinking: bool = False
    # The tool of each call claude said it made and has no result of yet,
    # by the id of the call
    waiting: dict[str, str] = dataclasses.field(default_factory=dict)
    # When claude last took a step: made a call, had its result, or
    # started or ended a block of what it makes
    since: float = dataclasses.field(default=0.0, init=False)

    def __post_init__(self) -> None:
        self.since = self.started

    def stepped(self) -> None:
        """Claude took a step, see since."""
        self.since = time.monotonic()

    def heard(self, message: dict) -> None:
        """Take in what claude itself said over the pipe: the calls it
        made, and which of them came back."""
        if not own(message):
            return
        kind = message.get("type")
        for block in content_blocks(message):
            if kind == "assistant" and block.get("type") == "tool_use":
                self.stepped()
                self.said += 1
                call = block.get("id")
                if isinstance(call, str):
                    self.waiting[call] = flat(block.get("name", "?")).lower()
            elif kind == "user" and block.get("type") == "tool_result":
                self.stepped()
                call = block.get("tool_use_id")
                if isinstance(call, str):
                    self.waiting.pop(call, None)

    def piece(self, event: dict) -> None:
        """Take in a piece of what claude itself is making: a block of it
        that starts or ends is a step, and says whether claude thinks."""
        kind = event.get("type")
        block = event.get("content_block")
        if kind == "content_block_start" and isinstance(block, dict):
            self.thinking = block.get("type") == "thinking"
            self.stepped()
        elif kind == "content_block_stop":
            self.thinking = False
            self.stepped()


class Turns:
    """The turn that runs, or the one that ran last, and whether one runs.
    Whoever reads the user starts one with a prompt, whoever listens to
    claude starts one that claude said it starts and ends them all: under
    a lock."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self.current = Turn(time.monotonic())
        self.running = False

    def begin(self) -> bool:
        """Start a turn unless one runs. Whether one was started."""
        with self._lock:
            if self.running:
                return False
            self.current = Turn(time.monotonic())
            self.running = True
            return True

    def end(self) -> None:
        with self._lock:
            self.running = False


def tokens(count: float) -> str:
    """A number of tokens claude gave, as a trace shows one."""
    return brief.amount(round(count))


def read_by(usage: object) -> list[float]:
    """The counts of what was read, of the usage claude gives: new,
    written to the cache and read from it."""
    given = usage if isinstance(usage, dict) else {}
    return [n for n in map(measured, map(given.get, INPUT_TOKENS)) if n is not None]


def used(result: dict, spent: float) -> list[str]:
    """What a turn used, as far as claude said at its end: the tokens it
    read and wrote, and what it cost. The cost claude gives is the
    session's, spent is what it was before the turn."""
    given = result.get("usage")
    usage = given if isinstance(given, dict) else {}
    read = read_by(usage)
    written = measured(usage.get("output_tokens"))
    if not sum(read) and not written:
        # A command of Claude Code's, the model was not asked
        return []
    parts = [f"{tokens(sum(read))} in"] if read else []
    if written is not None:
        parts.append(f"{tokens(written)} out")
    total = measured(result.get("total_cost_usd"))
    if total is not None and total >= spent:
        parts.append(f"${total - spent:.4f}")
    return parts


class Usage:
    """What the session used, taken from what claude says as it goes, for
    the line at the end of each turn."""

    def __init__(self, drift: Drift | None = None) -> None:
        # Told what claude does not say of what it used any more
        self._drift = drift or Drift()
        # What the session cost up to the last turn
        self._spent = 0.0
        # What the last step of claude read, and how much its model can
        self._context = 0.0
        self._window = 0.0
        # The model the line named last
        self._named = ""

    @property
    def spent(self) -> float:
        """What the session cost up to the last turn."""
        return self._spent

    @property
    def context(self) -> float:
        """What the last step read, how full the context is."""
        return self._context

    @property
    def window(self) -> float:
        """How much the model can read at most, 0 until a turn said."""
        return self._window

    def step(self, message: dict) -> None:
        """Take in a step of claude's own: what it read is how full its
        context is, the whole conversation up to it. The model says
        so of what it wrote, not Claude Code of what it wrote in its
        place (<synthetic>)."""
        inner = self._drift.field(message, "message", dict) or {}
        model = inner.get("model")
        if isinstance(model, str) and model and not model.startswith("<"):
            usage = self._drift.field(inner, "usage", dict)
        else:
            usage = inner.get("usage")
        self._context = sum(read_by(usage)) or self._context

    def parts(self, result: dict, model: str) -> list[str]:
        """What the end of a turn says it used, then how full the context
        is and the model when it is not the one named last. Nothing for
        a turn the model was not asked in."""
        parts = used(result, self._spent)
        total = measured(result.get("total_cost_usd"))
        self._spent = self._spent if total is None else total
        window = window_of(result, model)
        self._window = window or self._window
        if not parts:
            return []
        # The model was asked: a turn that went well says how much each
        # one can read
        asked = not window and not ended_badly(result)
        models = self._drift.field(result, "modelUsage", dict) if asked else None
        if models:
            self._drift.missed("contextWindow of a model")
        if self._context and self._window:
            parts.append(f"context {100 * self._context / self._window:.0f}%")
        if model and model != self._named:
            parts.append(model)
            self._named = model
        return parts


def window_of(result: dict, model: str) -> float:
    """How much the model of the session can read at most, as the end of
    a turn says of each model it used."""
    given = result.get("modelUsage")
    models = given if isinstance(given, dict) else {}
    windows = {
        name: measured(about.get("contextWindow"))
        for name, about in models.items()
        if isinstance(about, dict)
    }
    return windows.get(model) or max(filter(None, windows.values()), default=0.0)


def working_line(turn: Turn, step: float = 1.0) -> str:
    """What is said of a turn that runs while it does nothing new for a
    while, that it is not stuck: how long since claude last took a step,
    in steps of so many seconds, and what it waits for."""
    took = (time.monotonic() - turn.since) // step * step
    tools = ", ".join(sorted(set(turn.waiting.values())))
    claude = "claude, thinking" if turn.thinking else "claude"
    return labelled("working", f"{took:.0f}s, waiting for {tools or claude}")


class Heartbeat:
    """Says that the turn still runs when claude took no step for a
    while, so that a long call or a long thought does not pass for a chat
    that is stuck. At a terminal in one line above the prompt. Anywhere
    else in lines, less and less often for a file not to fill with them,
    and not while other lines are written."""

    def __init__(self, page: Page, turns: Turns, asking: Callable[[], bool]):
        self._page = page
        self._turns = turns
        # Whether the user is asked something: the turn waits for them
        self._asking = asking
        # How long a turn may write nothing before a line says it runs,
        # and the step of claude's that wait is counted from
        self.wait = QUIET
        self._since = 0.0

    def beat(self) -> None:
        """Say that the turn still runs, when it is time to."""
        turn = self._turns.current
        running = self._turns.running and not self._asking()
        idle = time.monotonic() - turn.since >= QUIET
        if self._page.redrawn:
            self._page.working(working_line(turn, QUIET) if running and idle else "")
            return
        if turn.since != self._since:
            # Claude took a step, the wait starts over
            self.wait, self._since = QUIET, turn.since
        if not running or not idle:
            return
        if time.monotonic() - self._page.wrote < self.wait:
            return
        self._page.say([working_line(turn)])
        self.wait = min(self.wait * 2, QUIET_MOST)


def ended_badly(result: dict) -> bool:
    """Whether claude says at the end of a turn that it did not go well."""
    return bool(result.get("is_error")) or result.get("subtype") != "success"


def turn_line(turn: Turn, result: dict, more: Sequence[str] = ()) -> str:
    """What is said of a turn that is over: how long it took, how many
    tool calls it made, what more there is to say, and how it ended when
    not well."""
    took = time.monotonic() - turn.started
    calls = f"{turn.said} call{'' if turn.said == 1 else 's'}"
    line = ", ".join([labelled("turn", f"{took:.1f}s"), calls, *more])
    if turn.interrupted:
        line += "  interrupted"
    elif ended_badly(result):
        reason = flat(result.get("result", "")).strip()
        line += f"  ENDED {flat(result.get('subtype', '?'))}" + (
            f": {reason}" if reason else ""
        )
    return line
