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
from collections.abc import Callable

from ..events import Event, Who, clean
from ..layout import painted
from ..transcript import content_blocks
from .console import Page

CODE = "32"
BOLD = "1"
# What stands for the start and the end of a span until its line is
# wrapped: an escape would count as text that takes room. Neither is in a
# text that has been through clean.
_CODE_MARK = "\x01"
_BOLD_MARK = "\x02"
_STYLE_OF = {_CODE_MARK: CODE, _BOLD_MARK: BOLD}
_MARKS = re.compile(f"([{_CODE_MARK}{_BOLD_MARK}])")
_FENCE = re.compile(r"\s*(`{3,}|~{3,})")
_HEADING = re.compile(r"(\s*)#{1,6}\s+(\S.*)")
_CODE_SPAN = re.compile(r"(`+)(.+?)\1")
# Not the power of a number in code that was written without backticks
_BOLD_SPAN = re.compile(r"(?<![\w*])\*\*(\S(?:.*?\S)?)\*\*(?![\w*])")


def wrapped(line: str, width: int) -> list[str]:
    """A line of a reply as the lines that fit a width, each indented as
    it is."""
    indent = line[: len(line) - len(line.lstrip())]
    return textwrap.wrap(
        line,
        width,
        subsequent_indent=indent,
        break_long_words=False,
        break_on_hyphens=False,
    ) or [""]


def _code_marked(text: str) -> str:
    return _CODE_SPAN.sub(lambda span: _CODE_MARK + span[2] + _CODE_MARK, text)


def _marked(line: str) -> str:
    """A line of prose with its Markdown marks replaced by those of this
    module. What is between backticks is code, whatever else it holds."""
    heading = _HEADING.fullmatch(line)
    if heading:
        title = _code_marked(heading[2].replace("**", ""))
        return heading[1] + _BOLD_MARK + title + _BOLD_MARK
    marked = ""
    rest = 0
    for span in _CODE_SPAN.finditer(line):
        marked += _BOLD_SPAN.sub(_bold_marked, line[rest : span.start()])
        marked += _CODE_MARK + span[2] + _CODE_MARK
        rest = span.end()
    return marked + _BOLD_SPAN.sub(_bold_marked, line[rest:])


def _bold_marked(span: re.Match[str]) -> str:
    return _BOLD_MARK + span[1] + _BOLD_MARK


def _styled(lines: list[str]) -> list[str]:
    """The lines one marked line was wrapped to, in the styles of their
    spans. A span that is open at the end of a line goes on in the next."""
    styled = []
    styles: list[str] = []
    for line in lines:
        text = ""
        for part in _MARKS.split(line):
            style = _STYLE_OF.get(part)
            if style is None:
                text += painted(";".join(styles), part)
            elif style in styles:
                styles.remove(style)
            else:
                styles.append(style)
        styled.append(text)
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
        # The start of a line whose end has not come yet
        self._partial = ""
        # Whether a line was given back, and the empty ones since the last
        self._started = False
        self._empty = 0

    def feed(self, text: str) -> list[str]:
        """The lines that a piece of the reply completes."""
        *whole, self._partial = (self._partial + text).split("\n")
        return [shown for line in whole for shown in self._taken(line)]

    def end(self) -> list[str]:
        """The line that was left without its end, if any."""
        last, self._partial = self._partial, ""
        return self._taken(last.rstrip())

    def _taken(self, line: str) -> list[str]:
        line = clean(line.rstrip("\r"))
        if not line.strip():
            # Shown once something follows it
            self._empty += self._started
            return []
        if not self._started:
            line = line.lstrip()
        between, self._empty, self._started = [""] * self._empty, 0, True
        return between + self._shown(line)

    def _shown(self, line: str) -> list[str]:
        if self._fence:
            closing = _closes(line, self._fence)
            if closing:
                self._fence = ""
            if not self._colour:
                return [line]
            return [] if closing else [painted(CODE, line)]
        opening = _FENCE.match(line)
        if opening:
            self._fence = opening[1]
            return [] if self._colour else [line]
        if self._colour:
            line = _marked(line)
        parts = wrapped(line, self._width) if self._width else [line]
        return _styled(parts) if self._colour else parts


def reply_lines(text: str, width: int | None, colour: bool) -> list[str]:
    """A reply that is all there as its lines, see ReplyWriter."""
    writer = ReplyWriter(width, colour)
    return writer.feed(text) + writer.end()


def said_whole(page: Page, said: Event) -> list[str]:
    """What was said with all of its lines, where a trace has a few: a
    chat is where it is read. At a terminal a line says when and who, and
    the text is under it from the left edge, wrapped to the terminal and
    with an empty line after it. In a file every line says when and who,
    as of any event."""
    text = said.fields.get("text", "")
    lines = reply_lines(text, page.width, page.layout.colour)
    if not page.layout.compact:
        whole = dataclasses.replace(said, details=lines or said.details)
        return page.layout.event(whole)
    head = page.layout.event(dataclasses.replace(said, details=[""]))
    return [*head, *lines, ""]


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
        self._lines: list[str] = []
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
                said = Event(time.time(), Who.CLAUDE, "reply", [], {"text": text})
                self._page.put(said_whole(self._page, said))

    def finish(self) -> None:
        """End the reply that is being written, if one is."""
        if self._writer is None:
            return
        self._take(self._writer.end())
        if self._headed:
            self._page.put([""])
        elif self._lines:
            self._before()
            said = Event(self._started, Who.CLAUDE, "reply", self._lines, {})
            self._page.put(self._page.layout.event(said))
        self._owed += not self._met
        self._writer = None
        self._lines = []
        self._headed = self._met = False

    def turn_over(self) -> None:
        """A turn ended: what was owed of it will not come."""
        self.finish()
        self._owed = 0

    def _take(self, lines: list[str]) -> None:
        """Write lines of the reply, at a terminal. In a file they are
        kept for its end."""
        if not lines:
            return
        if not self._page.layout.compact:
            self._lines += lines
            return
        if not self._headed:
            self._before()
            self._headed = True
            head = Event(self._started, Who.CLAUDE, "reply", [""], {})
            lines = self._page.layout.event(head) + lines
        self._page.put(lines)
