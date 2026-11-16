"""What a trace is made of: events, and text made safe to show.

Most of what an event says was chosen by the session it tells of, the
transcript is the session's to write and so is what it asks the network
for. Nothing of it is trusted: control characters are dropped before
anything is printed."""

from __future__ import annotations

import enum
import json
import re
from dataclasses import dataclass

# C0 and C1 controls except tab and newline, and the bidi overrides: a
# transcript could otherwise drive the terminal or reorder what is shown
_BIDI = "".join(map(chr, [*range(0x202A, 0x202F), *range(0x2066, 0x206A)]))
_UNSAFE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f" + _BIDI + "]")


class Who(enum.Enum):
    """Who did something, the value being how the output names them."""

    USER = "user"
    CLAUDE = "claude"
    # A subagent of Claude's
    AGENT = "agent"
    # The container as a whole: a connection is known by its container,
    # not by the command that opened it
    SANDBOX = "sandbox"


@dataclass
class Event:
    """Something that happened: when (seconds since the epoch), who did
    it, what kind of thing (prompt, reply, net, dns, or the name of the
    tool for a call, which is not a closed set) and the lines that
    describe it."""

    when: float
    who: Who
    what: str
    details: list[str]
    # The same as named values, for --json
    fields: dict


def clean(value: object) -> str:
    """A value as text that is safe to show, one that is not text as the
    JSON it was read from."""
    if isinstance(value, str):
        text = value
    else:
        try:
            text = json.dumps(value, ensure_ascii=False)
        except (ValueError, TypeError, RecursionError):
            # Nested as deep as could just be read
            text = "(not shown, it cannot be written out)"
    return _UNSAFE.sub("", text)


def flat(value: object) -> str:
    """Cleaned and on one line, for a value that has to stay with its
    label: a line break in a path or a reason is shown, not followed."""
    return "\\n".join(clean(value).splitlines())
