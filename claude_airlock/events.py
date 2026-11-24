"""What a trace is made of: events, and text made safe to show.

Most of what an event says was chosen by the session it tells of, the
transcript is the session's to write and so is what it asks the network
for. Nothing of it is trusted: control characters, and those that show
nothing, are dropped before anything is printed."""

from __future__ import annotations

import enum
import json
import re
from dataclasses import dataclass, field

# C0 and C1 controls except tab and newline, and the bidi overrides: a
# transcript could otherwise drive the terminal or reorder what is shown.
# Half a surrogate pair too, which JSON can hold and no output can write.
_BIDI = "".join(map(chr, [*range(0x202A, 0x202F), *range(0x2066, 0x206A)]))
# What takes no column and shows nothing, as Unicode lists what a display
# may ignore: the soft hyphen, the joiners and the spaces of no width, the
# marks of direction, the byte order mark, the tags and the selectors
# after them. A text can be padded with any number of them, which a
# terminal and what counts its columns need not agree on (see
# chat/screen.py), and can carry in them what the user is not shown. Not
# the selectors an emoji takes its colour from (U+FE00 to U+FE0F), which
# are counted as the nothing they take.
_UNSEEN = (
    "\u00ad\u034f\u061c\u17b4\u17b5\u180b-\u180f\u200b-\u200f\u2060-\u206f"
    "\ufeff\ufff0-\ufffb\U0001bca0-\U0001bca3\U0001d173-\U0001d17a"
    "\U000e0000-\U000e0fff"
)
_UNSAFE = re.compile(
    r"[\x00-\x08\x0b-\x1f\x7f-\x9f\ud800-\udfff" + _BIDI + _UNSEEN + "]"
)
# Of the label a header line starts with: session, network, day, chat...
LABEL_WIDTH = 12


class Wrong(enum.IntEnum):
    """How much of an event tells of something gone wrong, said by what
    makes the event: it knows what its values mean, what shows the event
    does not guess it from their names."""

    NO = 0
    # Some of its lines, those among its alerts
    PART = 1
    # Every line of it: a request that was refused, a lookup that failed
    THROUGHOUT = 2


class Who(enum.Enum):
    """Who did something, the value being how the output names them."""

    USER = "user"
    CLAUDE = "claude"
    # A subagent of Claude's
    AGENT = "agent"
    # The container as a whole: a connection is known by its container,
    # not by the command that opened it
    SANDBOX = "sandbox"


class Kind(enum.StrEnum):
    """What an event is when it is not the call of a tool, as the what
    column says it and --only names it. The call of a tool is the name of
    the tool, which is not a closed set: what an event is stays a text,
    and one of these is the text it is written as."""

    PROMPT = "prompt"
    REPLY = "reply"
    # What a command of Claude Code's said
    COMMAND = "command"
    # What a step of the model used
    STEP = "step"
    # What the session was told and became, see told.py
    CONTEXT = "context"
    TASK = "task"
    API = "api"
    COMPACT = "compact"
    MODE = "mode"
    MODEL = "model"
    # A line of the transcript that cannot be read
    TRANSCRIPT = "transcript"
    # What the launcher recorded of the network and of the processes
    NET = "net"
    DNS = "dns"
    EXEC = "exec"
    LISTEN = "listen"
    HEALTH = "health"
    # What the launchers noted, see noted.py
    STARTED = "started"
    CHANGED = "changed"


class Stage(enum.StrEnum):
    """Which part of something an event is, among its values, when it is
    followed as it happens: a tool call and its result, a connection as
    it opens and what became of it."""

    CALL = "call"
    RESULT = "result"
    OPEN = "open"
    OUTCOME = "outcome"


@dataclass
class Event:
    """Something that happened: when (seconds since the epoch), who did
    it, what kind of thing (see Kind, or the name of the tool for a call)
    and the lines that describe it."""

    when: float
    who: Who
    what: str
    details: list[str]
    # The same as named values, for --json
    fields: dict
    # Of a tool call that is followed as it runs, and of its result: the
    # number the two are matched by, in the order the calls were issued
    number: int | None = None
    # Said ahead of its first line: the container it is of, how it came
    tag: str = ""
    # Said after its first line, each found out after the event was made:
    # the process that made a connection, the call it was made during
    notes: list[str] = field(default_factory=list)
    # Which of the details tell of what went wrong, by their place
    alerts: set[int] = field(default_factory=set)
    # Whether it tells of something gone wrong, and in how much of it
    wrong: Wrong = Wrong.NO

    @property
    def lines(self) -> list[str]:
        """The details as they are shown, the first with the tag ahead
        of it and the notes after."""
        first = " ".join(filter(None, (self.tag, *self.details[:1])))
        first = "  ".join(filter(None, (first, *self.notes)))
        return [first, *self.details[1:]] if self.details or first else []

    def say(self, line: str, alert: bool = False) -> None:
        """Add a line to the details, one that tells of what went wrong
        marked as that."""
        if alert:
            self.alerts.add(len(self.details))
        self.details.append(line)

    def went_wrong(self, how: Wrong = Wrong.PART) -> None:
        """Say that it tells of something gone wrong, in so much of it:
        never less than was said before."""
        self.wrong = max(self.wrong, how)


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


def labelled(label: str, text: str) -> str:
    """A header line: what it is about, in its column, then the text."""
    return f"{label:<{LABEL_WIDTH}}{text}"
