"""The texts Claude Code put before the model in an attachment, besides
the files of instructions (see told.py): a skill given again after a
compaction, what an MCP resource holds, what a hook or a plugin added,
a memory it recalled.

Each is read as the model reads it, and looked at for the signs of
planted.py: a hook or a skill can come with the project, a memory is
written by a session, a resource by its server. The shape of each is
that of Claude Code's own, which names these as the attachments that
hold content, and is checked here all the same: a transcript is written
from inside the sandbox, see events.py."""

from __future__ import annotations

import dataclasses
import hashlib
from collections.abc import Callable
from dataclasses import dataclass
from typing import NamedTuple

from ..events import flat
from .brief import amount
from .entries import every, kept
from .planted import Planted, flagged, planted

# The kind of the event that tells of them, a name given here
GIVEN = "given"
# The bytes of what a text is known by, see digest_of: as many as no other
# text is found to have, and few for thousands of them to be kept
DIGEST_SIZE = 32


def digest_of(text: object) -> bytes:
    """What a text is told from another by, which takes a pass over it:
    what is given again is known so before it is looked at for signs,
    which takes many, and a long id is kept as it, see bounded_id of
    transcript.py. Empty for what is no text."""
    if not isinstance(text, str):
        return b""
    # JSON can hold half a surrogate pair, which is no UTF-8
    said = text.encode("utf-8", "surrogatepass")
    return hashlib.blake2b(said, digest_size=DIGEST_SIZE).digest()


def hook_named(event: str, name: str) -> str:
    """A hook as it is named: by the event it ran on, with its own name
    when that is another (PreToolUse:Bash is its event and what it is
    for, tool.call one of its own)."""
    if name in ("", event):
        return event
    return name if name.startswith(f"{event}:") else f"{event} ({name})"


class Text(NamedTuple):
    """A text as an attachment gives it: where it was from, as the
    attachment names it, and what it gives for the text, which is only
    one when it is a string."""

    source: str
    text: object


type Reader = Callable[[dict], list[Text]]


@dataclass(frozen=True)
class Given:
    """A text an attachment put before the model: the attachment's kind,
    where it was from and how long it is, in characters, with the signs
    it shows."""

    kind: str
    source: str
    size: int
    planted: tuple[Planted, ...] = ()
    # What the text is told from another by, see digest_of
    digest: bytes = b""

    @property
    def what(self) -> str:
        """What it is, as it is told."""
        return ATTACHED[self.kind].shown

    @property
    def line(self) -> str:
        """How it is told."""
        return f"{self.what}: {flat(self.source) or '?'} ({amount(self.size)} chars)"

    @property
    def fields(self) -> dict:
        about = {"source": self.source, "chars": self.size}
        return {**about, **flagged(self.planted)}


def _named(*parts: object) -> str:
    """Where a text was from, of the names an attachment gives for it."""
    return " ".join(name for name in map(kept, parts) if name)


def _joined(value: object) -> str:
    """The texts of a list an attachment gives, as the model is given
    them: one after the other, a line apart."""
    return "\n".join(text for text in every(value) if isinstance(text, str))


def _skills(given: dict) -> list[Text]:
    """skills.*.content: each skill given again, by its name and path"""
    return [
        Text(_named(skill.get("name"), skill.get("path")), skill.get("content"))
        for skill in every(given.get("skills"))
        if isinstance(skill, dict)
    ]


def _resource(given: dict) -> list[Text]:
    """content.contents.*.text: what a resource holds, by its server and
    address, its parts that are not text are no text to read"""
    content = given.get("content")
    parts = every(content.get("contents")) if isinstance(content, dict) else []
    text = _joined([part.get("text") for part in parts if isinstance(part, dict)])
    return [Text(f"{kept(given.get('server'))}:{kept(given.get('uri'))}", text)]


def _hook(given: dict) -> list[Text]:
    """content.*: what a hook added, by the event it ran on and its name"""
    event, name = kept(given.get("hookEvent")), kept(given.get("hookName"))
    return [Text(hook_named(event, name), _joined(given.get("content")))]


def _plugin(given: dict) -> list[Text]:
    """content.*: what a plugin noted, given to the model as a prompt"""
    source = kept(given.get("plugin")) or "plugin"
    return [Text(source, _joined(given.get("content")))]


def _memories(given: dict) -> list[Text]:
    """memories.*.content: each memory recalled, by its path"""
    return [
        Text(kept(memory.get("path")), memory.get("content"))
        for memory in every(given.get("memories"))
        if isinstance(memory, dict)
    ]


@dataclass(frozen=True)
class Attached:
    """An attachment that holds texts: how each is told, and what reads
    them out of it."""

    shown: str
    read: Reader


# Each, by its kind as Claude Code names it. One more is one more here.
ATTACHED = {
    "invoked_skills": Attached("skill given again", _skills),
    "mcp_resource": Attached("MCP resource", _resource),
    "hook_additional_context": Attached("hook added", _hook),
    "plugin_note": Attached("plugin noted", _plugin),
    "relevant_memories": Attached("memory recalled", _memories),
}
# The kinds of attachment texts_read reads
GIVING = frozenset(ATTACHED)


def texts_read(given: dict) -> list[tuple[Given, str]]:
    """The texts an attachment put before the model, each as it is told
    without the signs it shows, and its text to look for them in: none
    for an attachment of another kind."""
    kind = given.get("type")
    if not isinstance(kind, str) or kind not in ATTACHED:
        return []
    return [
        (Given(kind, source, len(text), digest=digest_of(text)), text)
        for source, text in ATTACHED[kind].read(given)
        if isinstance(text, str) and text
    ]


def scanned(read: Given, text: str) -> Given:
    """A text as it is told, with the signs it shows."""
    return dataclasses.replace(read, planted=planted(text, read.source))
