"""The record of the requests to the model: what a line of it holds, and
how many lines one session can have. Written by what takes the requests
out of a session's drop (see api_log.py), read by what shows them (see
report/api_events.py), which have this in common and nothing else.

A file of the launcher's state directory with a line per request, see
notes.py. What a line holds was still written by a session, Claude Code
or whatever else ran there: a line is read as a Call, each value as what
it should be, and one that is not is left out."""

from __future__ import annotations

import contextlib
import enum
import os
from collections.abc import Mapping
from dataclasses import dataclass, field

from ..events import flat
from ..settings import Host
from .notes import Notes
from .records import moment

# The lines the record keeps, the oldest go once there are more, and how
# many of them one session can have: the record is of all the sessions,
# and one that could fill it would be rid of what it, or another, sent
# before. Past these a request is counted, see SessionCalls.
KEPT_CALLS = 5000
MOST_SESSION_CALLS = 2000
# In a line of the record: the requests that were counted and not noted
# one by one, how many once the session is over
UNRECORDED = "unrecorded"
# Of an id or a name Claude Code gives, as much as a line holds
NOTED_WIDTH = 100
# More than a request could count: a number above it is not a count
MOST_COUNTED = 10**15


class Part(enum.StrEnum):
    """A part of a request that is measured on its own, by the name the
    API has for it: the definitions of the tools, the system prompt and
    the conversation."""

    TOOLS = "tools"
    SYSTEM = "system"
    MESSAGES = "messages"


class Tokens(enum.StrEnum):
    """A count of tokens the API says a request used, by the name a
    trace has for it (see step_tokens of report/entries.py): the ones
    read, as those not cached, those newly put in the cache and those
    read from it, and the ones written, with how many of them thinking."""

    INPUT = "input_tokens"
    CACHE_WRITTEN = "cache_creation_input_tokens"
    CACHE_READ = "cache_read_input_tokens"
    OUTPUT = "output_tokens"
    THINKING = "thinking_tokens"

    @property
    def read(self) -> bool:
        """Whether it counts what the model read, not what it wrote."""
        return self in (Tokens.INPUT, Tokens.CACHE_WRITTEN, Tokens.CACHE_READ)


def noted_text(value: object) -> str:
    """A value Claude Code gives as it is noted, empty for what is no
    text."""
    return value[:NOTED_WIDTH] if isinstance(value, str) else ""


def count(value: object) -> int | None:
    """A count a session gives, none for what is not one."""
    if type(value) is not int or not 0 <= value <= MOST_COUNTED:
        return None
    return value


def shown_text(said: Mapping, key: str) -> str:
    """A value of a line as text on one line, empty for one that is not
    text."""
    value = said.get(key)
    return flat(value) if isinstance(value, str) else ""


def _kept_ref(value: object) -> str:
    """What the bodies of a request are kept as, a directory and a number
    under it, empty for anything else: never a path out of where the
    bodies are."""
    directory, _, number = (flat(value) if isinstance(value, str) else "").partition(
        "/"
    )
    plain = directory not in ("", ".", "..") and os.sep not in directory
    numbered = number.isascii() and number.isdigit()
    return f"{directory}/{number}" if plain and numbered else ""


def _says_something(value: object) -> bool:
    """Whether a value of a request is worth its place in a line: not
    one that is not known, empty or off. A count of none is."""
    return value is not None and value is not False and value not in ("", {})


@dataclass(frozen=True)
class Call:
    """A request to the model as a line of the record tells of it. Every
    value is the session's word but where its bodies are kept, which is
    the launcher's."""

    # What Claude Code made it for, as it names that, and the model asked
    source: str = ""
    model: str = ""
    # The session Claude Code says it is of, and the ids a transcript
    # knows its answer by: requestId, message.id and uuid
    claude_session: str = ""
    request_id: str = ""
    message_id: str = ""
    message_uuid: str = ""
    # Whether Claude Code said an answer came
    answered: bool = False
    # When the request was written out to be sent, as its file says, none
    # for one that was not found
    asked: float | None = None
    # How long the request was, none for one that was not found, and how
    # much of it each part took, of one that reads as a request
    sent: int | None = None
    parts: Mapping[Part, int] = field(default_factory=dict)
    # How many tools were defined and how many messages the conversation
    # had, none when that is not told
    tool_count: int | None = None
    message_count: int | None = None
    # Whether Claude Code says it left the body of the request out
    withheld: bool = False
    # How long the answer was, what the API says the request used and
    # why the model stopped
    received: int | None = None
    used: Mapping[Tokens, int] = field(default_factory=dict)
    stop: str = ""
    # What the two bodies are kept as, a directory and a number under
    # it, empty when they are not
    kept: str = ""

    def as_note(self) -> dict[str, object]:
        """What a line of the record says of it: each value under its
        name, one that says nothing left out."""
        said: dict[str, object] = {
            "source": self.source,
            "model": self.model,
            "claude_session": self.claude_session,
            "request_id": self.request_id,
            "message_id": self.message_id,
            "message_uuid": self.message_uuid,
            "asked": self.asked,
            "sent": self.sent,
            **{part.value: size for part, size in self.parts.items()},
            "tool_count": self.tool_count,
            "message_count": self.message_count,
            "withheld": self.withheld,
            "received": self.received,
            "usage": {kind.value: used for kind, used in self.used.items()},
            "stop": self.stop,
            "kept": self.kept,
        }
        return {
            **{name: value for name, value in said.items() if _says_something(value)},
            # Said either way: a request without an answer is one
            "answered": self.answered,
        }

    @classmethod
    def from_note(cls, said: Mapping) -> Call:
        """The request a line of the record tells of, each value read as
        what it is declared to be here and a text kept to the one line
        it is: the record is the launcher's own, what it holds is not."""
        given = said.get("usage")
        usage = given if isinstance(given, Mapping) else {}
        return cls(
            source=shown_text(said, "source"),
            model=shown_text(said, "model"),
            claude_session=shown_text(said, "claude_session"),
            request_id=shown_text(said, "request_id"),
            message_id=shown_text(said, "message_id"),
            message_uuid=shown_text(said, "message_uuid"),
            answered=said.get("answered") is True,
            asked=moment(said.get("asked")),
            sent=count(said.get("sent")),
            parts={
                part: size
                for part in Part
                if (size := count(said.get(part.value))) is not None
            },
            tool_count=count(said.get("tool_count")),
            message_count=count(said.get("message_count")),
            withheld=said.get("withheld") is True,
            received=count(said.get("received")),
            used={
                kind: used
                for kind in Tokens
                if (used := count(usage.get(kind.value))) is not None
            },
            stop=shown_text(said, "stop"),
            kept=_kept_ref(said.get("kept")),
        )


def unrecorded(said: Mapping) -> int | None:
    """How many requests a line of the record says were counted and not
    noted one by one, none for a line that is a request. Without a count
    yet, 0, in the line that says it began, see SessionCalls."""
    counted = said.get(UNRECORDED)
    if not counted:
        return None
    return count(counted) or 0


def call_record(host: Host) -> Notes:
    """The record of the requests to the model."""
    return Notes(host.api_calls_file, KEPT_CALLS)


class SessionCalls:
    """The requests of one session, noted as they are taken. Each is a
    line of the record until the session has MOST_SESSION_CALLS of them.
    From then on a request is counted: a line says at once that this
    began, a session is not to be rid of what it sent before by sending
    more, and one says how many there were when the session is over.

    Not used from several threads."""

    def __init__(self, host: Host, session: str) -> None:
        self._record = call_record(host)
        self._project = host.project_dir
        # The container of the session, which its lines are under
        self._session = session
        # The requests noted, and those that were only counted
        self.noted = 0
        self._uncounted = 0

    @property
    def full(self) -> bool:
        """Whether the session has all the lines it can have."""
        return self.noted >= MOST_SESSION_CALLS

    def note(self, call: Call) -> None:
        """Add a request to the record. Raises OSError when the record
        cannot be written."""
        self._record.add(self._project, self._session, **call.as_note())
        self.noted += 1

    def count(self) -> None:
        """Count a request that is not noted on its own."""
        if not self._uncounted:
            # A full disk or the like: counted all the same
            with contextlib.suppress(OSError):
                self._add_unrecorded(True)
        self._uncounted += 1

    def close(self) -> None:
        """Say how many requests were counted and not noted, if any
        were."""
        if self._uncounted:
            # A full disk or the like: the line that said it began stays
            with contextlib.suppress(OSError):
                self._add_unrecorded(self._uncounted)

    def _add_unrecorded(self, counted: bool | int) -> None:
        self._record.add(self._project, self._session, **{UNRECORDED: counted})
