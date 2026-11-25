"""What stops a turn of a chat for what claude was given to read: the
result of a call that shows a sign of being written to instruct it, see
planted.py.

Looked for in what claude says over the pipe, where a result is as soon
as claude has it: a line of the transcript comes later, and the model
needs no longer than that for its next call. The turn is stopped before
that call where it can be, nothing is taken back: claude has read the
text, and whether it goes on with it in the conversation is the user's
to say. What they said yes to is not asked of again, see Guard."""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass

from ..events import clean, labelled
from ..report.entries import block_text, content_blocks
from ..report.outcomes import read_source, result_planted, said_source
from ..report.planted import Planted

# The calls without a result yet whose tool is remembered, what claude
# says is the session's to write
MOST_OPEN = 10_000
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
        # Each call that has no result yet, by its id
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
        stopped for, of the results it was given with it."""
        blocks = content_blocks(message)
        if message.get("type") == "assistant":
            for block in blocks:
                if block.get("type") == "tool_use":
                    self._called(block)
            return ()
        return tuple(
            sign
            for block in blocks
            if block.get("type") == "tool_result"
            for sign in self._given(block)
        )

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
        """Remember a call until its result is given, the oldest gone
        for it when there are more than MOST_OPEN."""
        tool, given = str(block.get("name")), block.get("input")
        self._calls[str(block.get("id"))] = Called(
            tool, _source_of(tool, given), said_source(given)
        )
        while len(self._calls) > MOST_OPEN:
            del self._calls[next(iter(self._calls))]

    def _given(self, block: dict) -> tuple[Planted, ...]:
        """The signs in the result of a call that a turn is stopped for,
        of any tool when the call was not seen: its source is not known
        then, and nothing is remembered of it."""
        call = self._calls.pop(str(block.get("tool_use_id")), None)
        output = block_text(block.get("content"))
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
