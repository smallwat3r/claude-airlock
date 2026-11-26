"""A reply of claude as the lines a chat shows of it, and the replies
written as claude makes them (see ReplyStream).

Claude writes its replies in Markdown, which a terminal does not show as
such. In colour the marks that read worst as text are taken for what they
mean: the code of a fenced block and of a span between backticks is in a
colour of its own, a heading and what is between two pairs of asterisks
are bold, and the marks themselves are left out. Lists, links and tables
are left as written, they read well enough.

Without colour nothing is taken out: the marks are then all there is to
tell code from prose by, in a file as in a terminal.

Either way the lines of a fenced block are never wrapped, code that is
broken where it was not is no longer the code that was written."""

from __future__ import annotations

import dataclasses
import re
import textwrap
import time
from bisect import bisect_left
from collections import deque
from collections.abc import Callable

from ..events import Event, Kind, Who, clean
from ..report.entries import content_blocks
from ..report.layout import BLANK, BOLD, GREEN, Shown, Styled, painted
from .console import Page

CODE = GREEN
# What stands for the start and the end of a span until its line is
# wrapped: an escape would count as text that takes room. Neither is in a
# text that has been through clean.
_CODE_MARK = "\x01"
_BOLD_MARK = "\x02"
_STYLE_OF = {_CODE_MARK: CODE, _BOLD_MARK: BOLD}
_MARKS = re.compile(f"([{_CODE_MARK}{_BOLD_MARK}])")
_FENCE = re.compile(r"\s*(`{3,}|~{3,})")
_HEADING = re.compile(r"(\s*)#{1,6}\s+(\S.*)")
_TICKS = re.compile(r"`+")
_BOLD = "**"
# A line longer than this is not looked through for marks, it is the
# model's to write and no prose. A shorter one is looked through once,
# however many of its marks are opened and not closed: see _code_spans
# and _bold_marked
MOST_MARKED = 4000


def wrapped(line: str, width: int, under: str | None = None) -> list[str]:
    """A line as the lines that fit a width, each indented as it is, or
    those after the first by what they are to be under."""
    indent = line[: len(line) - len(line.lstrip())] if under is None else under
    return textwrap.wrap(
        line,
        width,
        subsequent_indent=indent,
        break_long_words=False,
        break_on_hyphens=False,
    ) or [""]


def _code_spans(text: str) -> list[tuple[int, int, int]]:
    """The spans of code of a text, each as where it starts, where it
    ends and how many backticks are at either end of it: from a run of
    backticks to the next one of as many, as Markdown has it. Found in
    one pass, the runs of each length in a queue of their own: a run
    that is never closed is not looked for to the end of the text, and a
    text of nothing but those is the model's to write."""
    runs = [(run.start(), len(run.group())) for run in _TICKS.finditer(text)]
    later: dict[int, deque[int]] = {}
    for at, (_, length) in enumerate(runs):
        later.setdefault(length, deque()).append(at)
    spans = []
    closed = -1
    for at, (start, length) in enumerate(runs):
        same = later[length]
        # This run, and those of its length that are behind it
        while same and same[0] <= at:
            same.popleft()
        if at <= closed or not same:
            continue
        closed = same[0]
        spans.append((start, runs[closed][0] + length, length))
    return spans


def _code_marked(text: str, bold: bool = False) -> str:
    """A text with the backticks of its spans of code replaced by the
    marks of this module. With bold, what is between two spans has its
    marks of bold replaced too, what is within one is code as it is."""
    plain: Callable[[str], str] = _bold_marked if bold else str
    parts = []
    rest = 0
    for start, end, ticks in _code_spans(text):
        code = text[start + ticks : end - ticks]
        parts += [plain(text[rest:start]), _CODE_MARK, code, _CODE_MARK]
        rest = end
    return "".join([*parts, plain(text[rest:])])


def _marked(line: str) -> str:
    """A line of prose with its Markdown marks replaced by those of this
    module. What is between backticks is code, whatever else it holds.
    A line past MOST_MARKED is as it was."""
    if len(line) > MOST_MARKED:
        return line
    heading = _HEADING.fullmatch(line)
    if heading:
        title = _code_marked(heading[2].replace(_BOLD, ""))
        return heading[1] + _BOLD_MARK + title + _BOLD_MARK
    return _code_marked(line, bold=True)


def _opens_bold(text: str, at: int) -> bool:
    """Whether two asterisks at a place can start what is bold: not after
    a letter, a digit or an asterisk, which is the power of a number in
    code that was written without backticks, and with no space after."""
    before = text[at - 1] if at else " "
    after = text[at + 2 : at + 3]
    return not (before.isalnum() or before in "_*") and bool(after.strip())


def _closes_bold(text: str, at: int) -> bool:
    """Whether two asterisks at a place can end what is bold: with no
    space before, and not ahead of a letter, a digit or an asterisk."""
    before = text[at - 1 : at] if at else ""
    after = text[at + 2 : at + 3]
    return bool(before.strip()) and not (after.isalnum() or after in ("_", "*"))


def _bold_marked(text: str) -> str:
    """A text with the asterisks around what is bold replaced by the
    marks of this module: from two that can start it to the first two
    after them that can end it. The places that can end one are found
    once, and the one after a start looked up among them: a text of
    starts without an end is the model's to write, and is not looked
    through to its end for each."""
    places = []
    at = text.find(_BOLD)
    while at >= 0:
        places.append(at)
        at = text.find(_BOLD, at + 1)
    ends = [place for place in places if _closes_bold(text, place)]
    parts = []
    rest = 0
    for start in places:
        if start < rest or not _opens_bold(text, start):
            continue
        # At least a character between the two
        nearest = bisect_left(ends, start + len(_BOLD) + 1)
        if nearest == len(ends):
            break
        end = ends[nearest]
        inside = text[start + len(_BOLD) : end]
        parts += [text[rest:start], _BOLD_MARK, inside, _BOLD_MARK]
        rest = end + len(_BOLD)
    return "".join([*parts, text[rest:]])


def _styled(lines: list[str]) -> list[Styled]:
    """The lines one marked line was wrapped to, in the styles of their
    spans. A span that is open at the end of a line goes on in the next."""
    styled = []
    styles: list[str] = []
    for line in lines:
        parts = []
        for part in _MARKS.split(line):
            style = _STYLE_OF.get(part)
            if style is None:
                parts.append(painted(";".join(styles), part))
            elif style in styles:
                styles.remove(style)
            else:
                styles.append(style)
        styled.append(Styled("".join(parts)))
    return styled


def _closes(line: str, fence: str) -> bool:
    """Whether a line ends the block a fence started: the same marks, as
    many or more, and nothing else."""
    marks = line.strip()
    return len(marks) >= len(fence) and not marks.strip(fence[0])


class ReplyWriter:
    """A reply taken in as it is written, in pieces that end anywhere, and
    given back as the lines that are complete: those of prose wrapped to a
    width when there is one, and in colour styled as the module says. As
    of a reply that is all there, the empty lines at its start and its end
    are left out."""

    def __init__(self, width: int | None, colour: bool):
        self._width = width
        self._colour = colour
        # The marks that started the block of code a line is in
        self._fence = ""
        # The start of a line whose end has not come yet, in the pieces
        # it came in: put together once the line is whole, a line of any
        # length comes in any number of them
        self._partial: list[str] = []
        # Whether a line was given back, and the empty ones since the last
        self._started = False
        self._empty = 0

    def feed(self, text: str) -> list[Styled]:
        """The lines that a piece of the reply completes."""
        if "\n" not in text:
            self._partial.append(text)
            return []
        *whole, rest = "".join([*self._partial, text]).split("\n")
        self._partial = [rest]
        return [shown for line in whole for shown in self._taken(line)]

    def end(self) -> list[Styled]:
        """The line that was left without its end, if any."""
        last, self._partial = "".join(self._partial), []
        return self._taken(last.rstrip())

    def _taken(self, line: str) -> list[Styled]:
        """The lines a line of the reply is given back as. Cleaned here,
        ahead of any style: what comes out has no escape but those."""
        line = clean(line.rstrip("\r"))
        if not line.strip():
            # Shown once something follows it
            self._empty += self._started
            return []
        if not self._started:
            line = line.lstrip()
        between, self._empty, self._started = [Styled("")] * self._empty, 0, True
        return between + self._shown(line)

    def _shown(self, line: str) -> list[Styled]:
        if self._fence:
            closing = _closes(line, self._fence)
            if closing:
                self._fence = ""
            if not self._colour:
                return [Styled(line)]
            return [] if closing else [Styled(painted(CODE, line))]
        opening = _FENCE.match(line)
        if opening:
            self._fence = opening[1]
            return [] if self._colour else [Styled(line)]
        if self._colour:
            line = _marked(line)
        parts = wrapped(line, self._width) if self._width else [line]
        return _styled(parts) if self._colour else [Styled(part) for part in parts]


def reply_lines(text: str, width: int | None, colour: bool) -> list[Styled]:
    """A reply that is all there as its lines, see ReplyWriter."""
    writer = ReplyWriter(width, colour)
    return writer.feed(text) + writer.end()


def said_whole(page: Page, said: Event) -> list[Shown]:
    """What was said with all of its lines, where a trace has a few: a
    chat is where it is read. At a terminal a line says when and who, and
    the text is under it (see Page.replied), wrapped to the terminal
    and with an empty line after it. In a file every line says when and
    who, as of any event."""
    text = said.fields.get("text", "")
    lines = reply_lines(text, page.width, page.layout.colour)
    if not page.layout.compact:
        whole = dataclasses.replace(said, details=[*lines] or said.details)
        return page.layout.event(whole)
    head = page.layout.event(dataclasses.replace(said, details=[""]))
    return [*head, *page.replied(lines), BLANK]


class ReplyStream:
    """The replies of claude itself, written from what it says over the
    pipe: a chat has no other screen for them.

    Claude tells a reply twice. In pieces as it makes it, which at a
    terminal are written line by line as they come. And whole once it is
    made, which is what is written of a reply that was not told in
    pieces. In a file a reply is written once it is whole either way,
    every line of it saying when.

    The whole of a reply comes while its pieces still do, or after them:
    a reply written from its pieces is owed one whole that is passed
    over. What a command of Claude Code's said comes whole too, and is
    left to the transcript, which has it for all of them."""

    def __init__(self, page: Page, before: Callable[[], None]):
        self._page = page
        # Called ahead of the first line of a reply, for what the session
        # did before it to be written above it
        self._before = before
        self._writer: ReplyWriter | None = None
        self._started = 0.0
        # Its lines, where it is written once it is whole
        self._lines: list[Styled] = []
        # Whether its first line is out, and whether its whole was told
        self._headed = False
        self._met = False
        # The replies written from their pieces whose whole has not come
        self._owed = 0

    @property
    def writing(self) -> bool:
        """Whether a reply is being written, which nothing else is to be
        written into."""
        return self._writer is not None

    def piece(self, event: dict) -> None:
        """Take in a piece of what claude is making."""
        kind = event.get("type")
        if kind == "content_block_start":
            given = event.get("content_block")
            if isinstance(given, dict) and given.get("type") == "text":
                self.finish()
                # The whole of a reply comes before its last piece: one
                # that has not come by now will not
                self._owed = 0
                self._writer = ReplyWriter(self._page.width, self._page.layout.colour)
                self._started = time.time()
        elif kind == "content_block_delta" and self._writer:
            given = event.get("delta")
            text = given.get("text") if isinstance(given, dict) else None
            if isinstance(text, str):
                self._take(self._writer.feed(text))
        elif kind == "content_block_stop":
            self.finish()

    def whole(self, message: dict) -> None:
        """Take in what claude said once it had made it: written when its
        pieces were not."""
        if "local_command_run" in message:
            return
        for block in content_blocks(message):
            text = block.get("text")
            if block.get("type") != "text" or not isinstance(text, str):
                continue
            if self._writer is not None and not self._met:
                self._met = True
            elif self._owed:
                self._owed -= 1
            elif text.strip():
                self._before()
                said = Event(time.time(), Who.CLAUDE, Kind.REPLY, [], {"text": text})
                self._page.put(said_whole(self._page, said))

    def finish(self) -> None:
        """End the reply that is being written, if one is."""
        if self._writer is None:
            return
        self._take(self._writer.end())
        if self._headed:
            self._page.put([BLANK])
        elif self._lines:
            self._before()
            said = Event(self._started, Who.CLAUDE, Kind.REPLY, [*self._lines], {})
            self._page.put(self._page.layout.event(said))
        self._owed += not self._met
        self._writer = None
        self._lines = []
        self._headed = self._met = False

    def turn_over(self) -> None:
        """A turn ended: what was owed of it will not come."""
        self.finish()
        self._owed = 0

    def _take(self, lines: list[Styled]) -> None:
        """Write lines of the reply, at a terminal: under the line that
        says when and who, none of its own does. In a file they are
        kept for its end."""
        if not lines:
            return
        if not self._page.layout.compact:
            self._lines += lines
            return
        shown = self._page.replied(lines)
        if not self._headed:
            self._before()
            self._headed = True
            head = Event(self._started, Who.CLAUDE, Kind.REPLY, [""], {})
            shown = self._page.layout.event(head) + shown
        self._page.put(shown)
