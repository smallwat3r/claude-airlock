"""How the events of a trace are laid out as lines of text, coloured on a
terminal, or written as JSON Lines. --trace, --trace --follow and a chat
show them alike.

Nothing an event holds is trusted here: its text has been through clean
of events.py, and prefixed keeps a line break within it from passing for
the start of another event."""

from __future__ import annotations

import dataclasses
import json
import math
import sys
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from ..events import Event, Kind, labelled
from ..recording.pcap import Went

# Of the column that says what an event is, a longer name is cut to it
WHAT_WIDTH = 10
# What a text on a terminal is styled with, each the parameter of an SGR
# escape. A style is one of them or several, see together, and none is "".
# The one place they are named, whatever writes in colour takes them here.
BOLD = "1"
DIM = "2"
ITALIC = "3"
RED = "31"
GREEN = "32"
YELLOW = "33"
BLUE = "34"
MAGENTA = "35"
CYAN = "36"
BRIGHT_GREEN = "92"
BRIGHT_MAGENTA = "95"
BRIGHT_CYAN = "96"


def together(*styles: str) -> str:
    """Several styles as one, those that are none left out."""
    return ";".join(filter(None, styles))


ALERT = together(BOLD, RED)
# How the lines are coloured. What a session did out of sight is what
# stands out: commands, writes and the network. The conversation, which
# its user saw anyway, and the lines about the trace itself are dimmed,
# the other tools are left as they are.
STYLES = {
    Kind.PROMPT: DIM,
    Kind.REPLY: DIM,
    Kind.COMMAND: DIM,
    # What the session was told and became, which no one did
    Kind.CONTEXT: DIM,
    Kind.COMPACT: DIM,
    Kind.MODEL: DIM,
    Kind.TASK: DIM,
    # How the session is doing comes every so often, and is no act of it
    Kind.HEALTH: DIM,
    # Nor is how its sandbox was started
    Kind.STARTED: DIM,
    Kind.NET: CYAN,
    Kind.DNS: CYAN,
    # The tools, each by its name in small letters: the one that runs
    # commands, the network asked for through a tool, and those that
    # write files
    "bash": YELLOW,
    "webfetch": BLUE,
    "websearch": BLUE,
    "edit": MAGENTA,
    "write": MAGENTA,
    "notebookedit": MAGENTA,
}


def wrong_throughout(fields: dict) -> bool:
    """Whether an event tells of something gone wrong that every line of
    it is about: a request the filter refused, a connection that was
    refused or not answered, a lookup that failed or that stands out, a
    use of the SSH agent it refused, what was taken out of the
    transcript, and a line of it that cannot be read."""
    return bool(
        fields.get("denied")
        or fields.get("outcome") in Went.WRONG
        or fields.get("error")
        or fields.get("flagged")
        or fields.get("removed")
        or fields.get("unreadable_line")
    )


def went_wrong(event: Event) -> bool:
    """Whether an event tells of something gone wrong: a call that failed
    or was not allowed to run, a write outside the project, and what
    wrong_throughout names."""
    fields = event.fields
    return bool(
        fields.get("failed")
        or fields.get("refused")
        or fields.get("outside_project")
        or wrong_throughout(fields)
    )


def alerting(event: Event, index: int) -> bool:
    """Whether a detail of an event, by its place, is one that tells of
    what went wrong, see went_wrong: one that what made the event marked
    (how a call ended that failed or was refused, the file of a write
    outside the project), and every one of what is wrong throughout."""
    return index in event.alerts or wrong_throughout(event.fields)


def shown_what(what: str) -> str:
    """What an event is, as it fits its column: of a tool of an MCP
    server (mcp__server__tool) the name of the tool, and a name that is
    still too long cut. --json has it whole."""
    name = what.rpartition("__")[2] or what
    return name if len(name) <= WHAT_WIDTH else name[: WHAT_WIDTH - 1] + "~"


def folded(events: Iterable[Event]) -> list[Event]:
    """The events with each run of the same thing on the network as one,
    said to have happened so many times. What Claude Code itself keeps
    reaching comes by the dozen, and would bury the one connection that
    a command made."""
    runs: list[tuple[Event, int]] = []
    for event in events:
        last, count = runs[-1] if runs else (None, 0)
        if (
            last
            and event.what in (Kind.NET, Kind.DNS)
            and (event.who, event.what, event.lines)
            == (last.who, last.what, last.lines)
            and went_wrong(event) == went_wrong(last)
        ):
            runs[-1] = (last, count + 1)
        else:
            runs.append((event, 1))
    return [
        event
        if count == 1
        else dataclasses.replace(event, notes=[*event.notes, f"x{count}"])
        for event, count in runs
    ]


def prefixed(start: str, texts: list[str]) -> list[str]:
    """Whatever a value holds, no line of the output starts without its
    prefix: a line break in one must not pass for the start of an event."""
    return [
        (start + line).rstrip()
        for text in texts
        for line in (text.splitlines() or [""])
    ]


def use_colour(env: Mapping[str, str]) -> bool:
    """Whether the lines are coloured: on a terminal, unless NO_COLOR says
    not to (no-color.org), and anywhere when FORCE_COLOR asks for it, as a
    shell buffer of Emacs may want, which is not a terminal but shows
    colours."""
    if env.get("NO_COLOR"):
        return False
    return bool(env.get("FORCE_COLOR")) or sys.stdout.isatty()


def painted(style: str, text: str) -> str:
    """Text in a style, as it is without one. What is painted has been
    through clean, it holds no escape of its own to end the style early."""
    return f"\x1b[{style}m{text}\x1b[0m" if style and text else text


@dataclass
class Layout:
    """How the lines of a trace are laid out.

    For a file or a pipe every line starts with when (the date and the
    time), who and what, so a line found by grep says it all and the
    traces of several days can be put together.

    For a reader at a terminal (compact) that is said once per event, on
    its first line, and the lines under it are indented: where an event
    starts is then seen at a glance. The time is that of the day, and the
    day is on a line of its own whenever it changes.

    In colour the time is dimmed and the rest of a line has the style of
    what the event is, or of an alert. Who and what can have a style of
    their own (heads), for the start of what a reader looks for to stand
    out from what is around it, and so can a detail under a label."""

    colour: bool = False
    compact: bool = False
    # The style of each kind of event, when in colour
    styles: Mapping[str, str] = dataclasses.field(default_factory=lambda: STYLES)
    # The style of who and what of each kind of event, when in colour,
    # over that of the event
    heads: Mapping[str, str] = dataclasses.field(default_factory=dict)
    # The style of the details under each of these labels (why: Build),
    # when in colour, over that of the event, with the label bold
    labels: Mapping[str, str] = dataclasses.field(default_factory=dict)
    # The day of the event shown last, when compact
    _day: str = ""

    @classmethod
    def for_output(cls, env: Mapping[str, str]) -> Layout:
        """The layout for where the output goes."""
        return cls(use_colour(env), sys.stdout.isatty())

    @property
    def columns(self) -> str:
        """The header line that names the columns."""
        when = "time    " if self.compact else "time               "
        return f"{when}  {'who':<7}  {'what':<{WHAT_WIDTH}}  details"

    def header(self, header: list[str]) -> list[str]:
        lines = prefixed("# ", header)
        return [painted(DIM, line) for line in lines] if self.colour else lines

    def events(self, events: Iterable[Event]) -> list[str]:
        """The lines of events that follow each other, see folded."""
        return [line for event in folded(events) for line in self.event(event)]

    def event(self, event: Event) -> list[str]:
        """An event as its lines, a call that has a number named by it."""
        clock = f"{datetime.fromtimestamp(event.when):%Y-%m-%d %H:%M:%S}"
        lines: list[str] = []
        if self.compact:
            day, clock = clock.split()
            if day != self._day:
                self._day = day
                lines += self.header([labelled("day", day)])
        about = f"{event.who.value:<7}  {shown_what(event.what):<{WHAT_WIDTH}}  "
        style = self.styles.get(event.what, "")
        head = self.heads.get(event.what, "")
        # Each line with the detail it is of, a detail can hold several
        shown = [
            (index, line)
            for index, detail in enumerate(event.lines)
            for line in prefixed("", [detail])
        ]
        for at, (index, line) in enumerate(shown):
            first = at == 0
            text = f"[{event.number}] {line}" if first and event.number else line
            if self.compact and not first:
                # Under the first line, which said when, who and what
                clock, about = " " * len(clock), " " * len(about)
            rest = (about + text).rstrip()
            if not self.colour:
                lines.append(f"{clock}  {rest}".rstrip())
                continue
            if alerting(event, index):
                rest = painted(ALERT, rest)
            else:
                rest = self._painted(style, head if about.strip() else "", rest, about)
            when = painted(DIM, clock) if clock.strip() else clock
            lines.append(f"{when}  {rest}")
        return lines

    def _painted(self, style: str, head: str, rest: str, about: str) -> str:
        """A line that is not an alert in colour: who and what in the
        style of their head if they have one, and a detail under a label
        that has a style of its own with its label bold."""
        start, said = rest[: len(about)], rest[len(about) :]
        label, colon, reason = said.partition(":")
        extra = self.labels.get(label) if colon else None
        if not head and not extra:
            return painted(style, rest)
        start = headed(head, start) if head else painted(style, start)
        if extra:
            both = together(style, extra)
            bold = together(style, BOLD)
            return start + painted(bold, label + colon) + painted(both, reason)
        return start + painted(style, said)


def headed(style: str, about: str) -> str:
    """Who and what in a style, the columns after them left as they are."""
    name = about.rstrip()
    return painted(style, name) + about[len(name) :]


def event_json(session: str, event: Event) -> str:
    """An event as a JSON object on a line: the session, time (ISO 8601
    with its offset), who, what, then the values of that kind of event.
    Escaped by the encoder, which leaves no control character to reach a
    terminal."""
    when = datetime.fromtimestamp(event.when).astimezone()
    about = {
        "session": session,
        "time": when.isoformat(timespec="milliseconds"),
        "who": event.who.value,
        "what": event.what,
    }
    try:
        try:
            # NaN and Infinity, which a transcript can hold, are not JSON
            # to most of what reads it
            return json.dumps({**about, **event.fields}, allow_nan=False)
        except ValueError:
            return json.dumps({**about, **finite(event.fields)})
    except RecursionError:
        # Nested as deep as could just be read, by either of the two
        return json.dumps({**about, "unreadable": True})


def finite(value: Any) -> Any:
    """A value with null for each number that JSON has no way to write."""
    if isinstance(value, float) and not math.isfinite(value):
        return None
    if isinstance(value, dict):
        return {key: finite(inner) for key, inner in value.items()}
    if isinstance(value, list):
        return [finite(inner) for inner in value]
    return value
