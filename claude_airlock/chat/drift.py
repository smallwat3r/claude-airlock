"""Whether what claude says still has the shape a chat reads.

A chat goes by a few fields of the messages of Claude Code's print mode,
and a new version of it may move or rename one. What a chat does not find
it leaves out without a word, so that a change shows only as a part of the
status that is no longer there.

So what reads a field a chat goes by asks for it here (see Drift.field),
and one that is not there, or not of its kind, is kept. Once the message
is taken in, what was missed of it is said, once in a chat, with the shape
of the message for the reading to be put right: its fields and the kind
of each, none of their values. A kind of message no part of a chat takes
in is said the same way. The chat notes it for --trace too (see
changes.py), where nothing else tells that it showed less."""

from __future__ import annotations

from collections.abc import Collection
from dataclasses import dataclass
from typing import TypeVar

from ..events import flat

# How deep the shape of a message is said, and how long it may be
SHAPE_DEPTH = 3
SHAPE_WIDTH = 400
# How much of a name claude gives is said, and how many changes in a chat:
# what a session writes is not to fill the screen or the memory with them
NAME_WIDTH = 60
MOST_SAID = 20
# How much is kept as missed of one message, and by a reader nobody asks
# what it missed
MOST_MISSED = 50

Kind = TypeVar("Kind")


def shape(value: object, depth: int = SHAPE_DEPTH) -> str:
    """The fields of a message and the kind of each, without what they
    hold: enough to see what moved, and nothing of the conversation."""
    if isinstance(value, dict) and depth:
        fields = (
            f"{flat(key)}: {shape(held, depth - 1)}" for key, held in value.items()
        )
        return "{" + ", ".join(fields) + "}"
    return type(value).__name__


@dataclass(frozen=True)
class Change:
    """What differs in a message from what a chat reads of it, the
    version of Claude Code that said it, and its shape."""

    differs: tuple[str, ...]
    version: str
    shape: str

    @property
    def said(self) -> str:
        """The change in a line, as a chat and a trace say it."""
        by = f"Claude Code {self.version}" if self.version else "Claude Code"
        return (
            f"CHANGED in what {by} says: {', '.join(self.differs)}."
            f" Line mode may show less than it did. It has {self.shape}"
        )


class Drift:
    """What a chat did not find of what claude says where it reads it."""

    def __init__(self) -> None:
        # What was said in this chat, and what was missed of the message
        # being taken in
        self._said: set[str] = set()
        self._missed: list[str] = []

    def field(self, holder: object, name: str, kind: type[Kind]) -> Kind | None:
        """A field a chat goes by: what it holds when it is there and of
        its kind, none when not, which is then kept as missed."""
        held = holder.get(name) if isinstance(holder, dict) else None
        if isinstance(held, kind):
            return held
        self.missed(name)
        return None

    def missed(self, what: str) -> None:
        """Keep that something a chat goes by was not in the message
        being taken in."""
        if len(self._missed) < MOST_MISSED:
            self._missed.append(what)

    def told(
        self, message: dict, known: Collection[str], version: str = ""
    ) -> Change | None:
        """What to say of a message once it was taken in, given the
        kinds of message a chat knows: nothing when it was all there, or
        when the same was said before."""
        missed, self._missed = self._missed, []
        if len(self._said) >= MOST_SAID:
            return None
        kind = message.get("type")
        if not isinstance(kind, str):
            differs = ["a message without a type"]
        elif kind not in known:
            differs = [f"a message line mode does not know, {flat(kind)[:NAME_WIDTH]}"]
        else:
            subtype = flat(message.get("subtype") or "")[:NAME_WIDTH]
            name = f"{kind} {subtype}".rstrip()
            differs = [f"no {what} in {name}" for what in dict.fromkeys(missed)]
        new = [what for what in differs if what not in self._said]
        if not new:
            return None
        self._said.update(new)
        said = flat(message.get("claude_code_version") or version)[:NAME_WIDTH]
        return Change(tuple(new), said, shape(message)[:SHAPE_WIDTH])
