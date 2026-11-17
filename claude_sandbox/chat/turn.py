"""The turns of a chat: one runs from a prompt, or from claude saying
that it starts one, until claude says that it is over. What is counted
of each, and the lines that tell of it."""

from __future__ import annotations

import dataclasses
import threading
import time
from collections.abc import Sequence
from dataclasses import dataclass

from ..events import flat, labelled
from ..transcript import content_blocks
from .pipe import amount, own

# Of what a turn used, what was read: new, written to the cache and read
# from it
READ = ("input_tokens", "cache_creation_input_tokens", "cache_read_input_tokens")


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
    return f"{count / 1000:.1f}k" if count >= 1000 else f"{count:.0f}"


def read_by(usage: object) -> list[float]:
    """The counts of what was read, of the usage claude gives."""
    given = usage if isinstance(usage, dict) else {}
    return [n for n in map(amount, map(given.get, READ)) if n is not None]


def used(result: dict, spent: float) -> list[str]:
    """What a turn used, as far as claude said at its end: the tokens it
    read and wrote, and what it cost. The cost claude gives is the
    session's, spent is what it was before the turn."""
    given = result.get("usage")
    usage = given if isinstance(given, dict) else {}
    read = read_by(usage)
    written = amount(usage.get("output_tokens"))
    if not sum(read) and not written:
        # A command of Claude Code's, the model was not asked
        return []
    parts = [f"{tokens(sum(read))} in"] if read else []
    if written is not None:
        parts.append(f"{tokens(written)} out")
    total = amount(result.get("total_cost_usd"))
    if total is not None and total >= spent:
        parts.append(f"${total - spent:.4f}")
    return parts


class Usage:
    """What the session used, taken from what claude says as it goes, for
    the line at the end of each turn."""

    def __init__(self) -> None:
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
        context is, the whole conversation up to it."""
        inner = message.get("message")
        usage = inner.get("usage") if isinstance(inner, dict) else None
        self._context = sum(read_by(usage)) or self._context

    def parts(self, result: dict, model: str) -> list[str]:
        """What the end of a turn says it used, then how full the context
        is and the model when it is not the one named last. Nothing for
        a turn the model was not asked in."""
        parts = used(result, self._spent)
        total = amount(result.get("total_cost_usd"))
        self._spent = self._spent if total is None else total
        self._window = window_of(result, model) or self._window
        if not parts:
            return []
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
        name: amount(about.get("contextWindow"))
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
