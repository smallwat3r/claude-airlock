"""What stops a turn of a chat for what claude was given to read: the
result of a call that shows a sign of being written to instruct it, see
planted.py.

Looked for in what claude says over the pipe, where a result is as soon
as claude has it: a line of the transcript comes later, and the model
needs no longer than that for its next call. The turn is stopped before
that call where it can be, nothing is taken back: claude has read the
text, and whether it goes on with it in the conversation is the user's
to say. What they said yes to is not asked of again, see Guard. How the
turn is stopped, and the user asked, is Brake's to do."""

from __future__ import annotations

import hashlib
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass

from ..events import clean, labelled
from ..report.calls import SERVER_CALLS
from ..report.entries import block_text, content_blocks
from ..report.layout import ALERT, Layout, Shown
from ..report.outcomes import (
    SERVER_RESULTS,
    read_source,
    result_planted,
    said_source,
    server_output,
)
from ..report.planted import Planted
from .asking import ASKED_STYLE, said_yes
from .followed import ASK_SETTLE
from .parts import Parts
from .said import NAME_KEPT, keep_open, kept_id
from .turn import READY_STYLE

# The blocks of what the model replied that are calls: of a tool of
# Claude Code's, and of one that ran on Anthropic's side, whose result
# comes in what the model replied too, next to it (see SERVER_RESULTS)
CALLS = frozenset({"tool_use", *SERVER_CALLS})
# Of where a call reads from that is kept to be said, see said_source: a
# command can be of any length
SOURCE_WIDTH = 1000
# The signs the user went on with that are remembered, each with where
# it was read
MOST_ACCEPTED = 10_000
# What the user is asked once a turn was stopped, where there is one to
# answer, and when the answer is no yes: the conversation is cleared for
# a yes to the second alone, it cannot be brought back
GO_ON = "go on with it in the conversation? [y/N] "
CLEAR = "clear the conversation, and what claude read with it? [y/N] "
# What is said where the user is not asked, or gave no answer: what
# claude is told next does not take the text back
STILL_READ = "what it read stays in the conversation, only /clear takes it out"
# Said once the user answered for a turn that was stopped and the
# conversation is kept, in the colour of a turn that is over: nothing
# goes on until they type
WAITING = "nothing runs, claude waits for you: type how to go on, or continue"
# Seconds a turn that was stopped is given to end, before the
# conversation is cleared
STOP_QUIET = 10.0


def stop_said(found: tuple[Planted, ...], stopped: bool, asked: bool) -> list[str]:
    """What a chat says of a turn it stopped for these signs, or found
    no turn left to stop for them: why, and what is the user's to do
    unless they are asked."""
    why = ", ".join(dict.fromkeys(sign.sign for sign in found))
    sources = ", ".join(dict.fromkeys(sign.where for sign in found if sign.source))
    where = f" in {sources}" if sources else ""
    what = "STOPPED the turn" if stopped else "no turn left to stop"
    said = [f"{what}: what claude was given to read{where} {why}"]
    if not asked:
        said.append(STILL_READ)
    return [labelled("chat", line) for line in said]


@dataclass(frozen=True)
class Called:
    """A call that has no result yet: its tool, what it reads as it is
    remembered by (see _source_of), and where that is said to be from
    (see said_source)."""

    tool: str
    source: str
    said: str


def _source_of(tool: str, given: object) -> str:
    """What a call reads, as what it is remembered by: the file or the
    page when it names one, else all it was called with. No longer than a
    digest, a command can be of any length."""
    what = read_source(given) or clean(given)
    return _digest(f"{tool}\0{what}")


def _digest(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", "replace")).hexdigest()


def _key(source: str, sign: Planted, read: str) -> tuple[str, str, str]:
    """What a sign the user answered for is remembered by: where it was
    read, which sign, and all of what was read there, by its digest. Not
    the place the sign was found at alone, which is the first of them: a
    text that has the same one and more after it, a second place written
    to instruct claude, is not the text the user went on with."""
    return source, sign.sign, read


class Guard:
    """Reads what claude and its subagents say and are given, and finds
    the results a turn is stopped for. Not those the user went on with
    before: a source is asked of once for a sign and the text that was
    read there, all of it, the trace flags it each time. A page that
    reads otherwise the next time is asked of again, in whatever part: it
    can change between two reads, and what was shown of it is the first
    place a sign is at, not what came to be written after that."""

    def __init__(self) -> None:
        # Each call that has no result yet, by its id, see keep_open
        self._calls: dict[str, Called] = {}
        # Whether the user is asked, or about to be, if claude goes on
        # with what the turns were stopped for
        self._asking = False
        # Each sign a turn was stopped for with its source and what was
        # read (see _key), those the user has not answered for yet and
        # those they went on with
        self._asked: set[tuple[str, str, str]] = set()
        self._accepted: set[tuple[str, str, str]] = set()
        # Heard by who listens to claude, answered by who asks the user:
        # what is found is either answered for with the rest or asked of
        # anew, never neither
        self._lock = threading.Lock()

    def heard(self, message: dict) -> tuple[Planted, ...]:
        """Take in what claude said or was given. The signs a turn is
        stopped for, of the results it was given with it: of a call of
        Claude Code's in what claude is given, and of a call that ran on
        Anthropic's side in what the model replied, as the trace reads
        it (see server_output)."""
        replied = message.get("type") == "assistant"
        found: list[Planted] = []
        for block in content_blocks(message):
            kind = block.get("type")
            if not isinstance(kind, str):
                continue
            if replied and kind in CALLS:
                self._called(block)
            elif replied and kind in SERVER_RESULTS:
                output, _ = server_output(block)
                found += self._given(block.get("tool_use_id"), output)
            elif not replied and kind == "tool_result":
                output = block_text(block.get("content"))
                found += self._given(block.get("tool_use_id"), output)
        return tuple(found)

    def question(self) -> bool:
        """Whether the user is to be asked if claude goes on with what a
        turn was just stopped for: not while they are asked already, the
        answer to that is for all that was found until it is given."""
        with self._lock:
            asking, self._asking = self._asking, True
        return not asking

    def answered(self, went_on: bool) -> None:
        """The user answered for what the turns were stopped for. Gone
        on with, none is stopped again for the same sign of the same
        source that reads the same throughout. Not gone on with, or not
        answered, it stops a turn the next time too."""
        with self._lock:
            if went_on:
                if len(self._accepted) + len(self._asked) > MOST_ACCEPTED:
                    # Asked of again, rather than kept without end
                    self._accepted.clear()
                self._accepted |= self._asked
            self._asked.clear()
            self._asking = False

    def _called(self, block: dict) -> None:
        """Remember a call until its result is given, see keep_open. Not
        one whose id cannot be kept: its result is looked at as that of a
        call that was not seen. Its tool no longer than a name is kept,
        a longer one is of no tool whose result is passed over."""
        call = kept_id(block.get("id"))
        if call is None:
            return
        tool, given = str(block.get("name"))[:NAME_KEPT], block.get("input")
        said = said_source(given)[:SOURCE_WIDTH]
        keep_open(self._calls, call, Called(tool, _source_of(tool, given), said))

    def _given(self, said: object, output: str) -> tuple[Planted, ...]:
        """The signs that a turn is stopped for in what a call gave claude
        to read, by the id of the call its result names, of any tool when
        the call was not seen: its source is not known then, and nothing
        is remembered of it."""
        call = self._calls.pop(str(said), None)
        if call is None:
            return tuple(sign for sign in result_planted("", output) if sign.stops)
        found = tuple(
            sign for sign in result_planted(call.tool, output, call.said) if sign.stops
        )
        if not found:
            return ()
        # Of all that was read, once for the signs found in it
        read = _digest(output)
        with self._lock:
            new = tuple(
                sign
                for sign in found
                if _key(call.source, sign, read) not in self._accepted
            )
            if len(self._asked) < MOST_ACCEPTED:
                self._asked.update(_key(call.source, sign, read) for sign in new)
        return new


class Brake:
    """Stops a turn for what claude was just given to read, as Guard
    finds it, and asks the user whether claude goes on with it. Given the
    parts of the chat it writes to and asks through, and what it steers
    of the chat: interrupt asks claude to end the turn that runs, and
    says whether it was asked, send gives claude a prompt, and gone says
    whether there is nobody left to ask, or to ask for."""

    def __init__(
        self,
        guard: Guard,
        parts: Parts,
        interrupt: Callable[[], bool],
        send: Callable[[str], None],
        gone: Callable[[], bool],
    ):
        self._guard = guard
        self._parts = parts
        self._interrupt = interrupt
        self._send = send
        self._gone = gone
        # Whether a turn was stopped and the user sent nothing since
        self.stopped = False

    def heard(self, message: dict) -> None:
        """Take in what claude or a subagent of its said, or was given,
        and stop the turn for what of it Guard finds."""
        found = self._guard.heard(message)
        if found:
            self._stop(found)

    def _stop(self, found: tuple[Planted, ...]) -> None:
        """Stop the turn for what claude was just given to read: first of
        all, its next call may be a moment away. Then say why, under the
        call it is of. Claude has read the text, so whether it goes on
        with it is the user's to say, and what it asked meanwhile is
        refused. The user is asked where there is one to answer, once for
        all that is found until they did."""
        parts = self._parts
        stopped = self._interrupt()
        self.stopped = True
        if parts.turns.running:
            parts.turns.current.guarded = True
        asks = parts.console.interactive
        first = self._guard.question() if asks else True
        if first:
            # Not the question of an earlier stop, which is for this too
            parts.asker.give_up()
        parts.followed.settle(ASK_SETTLE)
        said = stop_said(found, stopped, asks)
        parts.page.put(parts.page.layout.header(said, ALERT))
        parts.console.bell()
        if asks and first:
            parts.asked.then(self._ask_to_go_on)

    def _ask_to_go_on(self) -> None:
        """Ask whether claude goes on with what a turn was stopped for in
        the conversation. A yes keeps it, and is remembered for what was
        read (see Guard). Anything else asks whether the conversation is
        cleared, which a yes alone does: the text is in it until then,
        whatever claude is told, and what is cleared is not brought back.
        No answer, the user interrupted or left, leaves it as it is. The
        turn was stopped either way, so a conversation that is kept says
        that the next line is the user's to type."""
        went_on, clears = None, None
        try:
            went_on = self._said_yes(GO_ON)
            if went_on is False:
                clears = self._said_yes(CLEAR)
        finally:
            # Whatever came of it: a question that is never answered for
            # would be the last one put
            self._guard.answered(bool(went_on))
        if self._gone():
            return
        if clears:
            self._start_anew()
            return
        if went_on:
            kept = "kept: not asked again for what it read"
        elif clears is None:
            kept = f"not answered: {STILL_READ}"
        else:
            kept = f"not cleared: {STILL_READ}"
        page = self._parts.page
        # Written together: the prompt that comes back is under both
        said = page.layout.header([labelled("chat", kept)])
        page.put([*said, waiting_line(page.layout)])

    def _said_yes(self, question: str) -> bool | None:
        """Put a question of a turn that was stopped, where it is not
        missed. Whether it was answered with a yes, none for no answer."""
        typed = self._parts.asker.ask(question, ASKED_STYLE)
        return said_yes(typed)

    def _start_anew(self) -> None:
        """Clear the conversation, once the turn that was stopped is
        over: what claude read goes with it."""
        patience = time.monotonic() + STOP_QUIET
        while self._parts.turns.running and time.monotonic() < patience:
            if self._gone():
                return
            time.sleep(0.05)
        self._parts.page.note(
            "chat", "clearing the conversation, what claude read with it"
        )
        self._send("/clear")


def waiting_line(layout: Layout) -> Shown:
    """The line that says a turn that was stopped is not gone on with
    until the user types, as a turn that is over is said."""
    return layout.header([labelled("chat", WAITING)], READY_STYLE)[0]
