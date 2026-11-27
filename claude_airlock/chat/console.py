"""The terminal of a chat: a line is read from the user while lines are
written for them to read.

One thread reads, the others write. What is written while a line is being
typed goes above it, in one of two ways:

At a terminal that takes escapes, the line being typed is erased, the new
lines are written in its place, and the prompt and what was typed are
written again under them. That one line is the only thing a chat ever
writes twice. What was typed is put back as a whole, with the cursor
where it was in it, as far as readline says where that is (see
_before_cursor): else at its end.

Anywhere else, a shell buffer of Emacs or a pipe, nothing can be erased
and nothing has to be: what is being typed is not on the screen as far as
this process knows. The new lines start on a line of their own and the
prompt is written again after them. Not while a turn runs (see hold): a
prompt after each of its lines would stand among them, and a line can be
typed there without one. It is written once the turn is over.

The prompt of a line can have a head, lines above it as a shell's prompt
has (the status, see status.py), and above that the lines that say what
runs now, a turn and the subagents of claude, see set_working. At a
terminal it goes with the prompt, under what is written, and is written
again in its place when it changes. Anywhere else it is written with the
prompt of each line read, and once it changed under what is written
next, with the prompt: never for the change alone, see _head_changed.

A line the user typed is written again in a style of its own once it is
entered, for what they said to be found among what is written around it.
At a terminal that is in its place, in a file or a pipe it is written so
the first time. Not in a shell buffer of Emacs, which shows what was typed
itself.

Lines pasted together are one prompt. A terminal that marks a paste has
readline take it whole, what comes unmarked (a shell buffer of Emacs, a
terminal that does not mark one) is read with the line it came after, see
_with_paste. At a terminal a paste waits for Enter, to be typed on.

At a terminal the Tab key completes the names of commands and of files
(@src/main.py), and the lines typed are kept from one chat of a project to
the next, where readline is there to do both.

The Python of macOS is often made with editline in the place of GNU
readline. It ends a line at any line break put at its end, and cannot be
given the start of one. So the lines before a key of a new line, and a
paste, are kept here and written after the prompt for what is typed to
go on from: they can be typed on and dropped (Ctrl-C), not changed. A
key of a new line pressed within a line shows as ^M until it is entered."""

from __future__ import annotations

import contextlib
import ctypes
import enum
import functools
import io
import os
import select
import shutil
import sys
import termios
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from types import CodeType, FrameType
from typing import Concatenate, TextIO

from ..events import Event, clean, labelled
from ..report.layout import Layout, Shown, Styled, painted, prefixed
from .screen import (
    SGR,
    Prompt,
    cursor_back,
    erased,
    first_row,
    shown_typed,
    uncounted,
)

try:
    import readline
except ImportError:  # pragma: no cover, a Python built without it
    readline = None  # type: ignore[assignment]


def _readline_int(name: str) -> ctypes.c_int | None:
    """A variable of the library readline is made with, which the module
    of Python does not give. None where it cannot be had."""
    try:
        library = ctypes.CDLL(getattr(readline, "__file__", None))
        return ctypes.c_int.in_dll(library, name)
    except (OSError, ValueError, TypeError, AttributeError):
        return None


def _readline_point() -> Callable[[], int] | None:
    """What reads where the cursor is in the line being typed, in bytes
    from its start (rl_point). None where that cannot be had. Editline
    has it too, left where it was when the line was started: not asked
    there, see _before_cursor."""
    point = _readline_int("rl_point")
    return (lambda: point.value) if point is not None else None


_point = _readline_point() if readline else None
# Whether readline is the editline of macOS, which does less: see the end
# of what this module says of itself
EDITLINE = bool(readline) and "libedit" in (readline.__doc__ or "")
# What has GNU readline end the line being read once the key it is at is
# done, as Enter does (rl_done), see Console._end_for_interrupt. None for
# editline, which reads a line otherwise, and where it cannot be had
_done = _readline_int("rl_done") if readline and not EDITLINE else None

# Lines of history kept from one chat to the next
HISTORY_LINES = 1000
# How many names are offered to complete a word with
NAMES_OFFERED = 200
# What a terminal sends for Shift+Enter when set to tell it from Enter, as
# a key of the kitty keyboard protocol (iTerm2's CSI u mode, or mapped in
# kitty, WezTerm, Ghostty, foot) or of xterm's modifyOtherKeys, and Alt+Enter,
# what Claude Code's /terminal-setup maps it to. Each starts a new line of
# the prompt. Most terminals send Enter itself unless set, a line ending
# with a backslash does the same there.
NEW_LINE_KEYS = (r"\e[13;2u", r"\e[27;2;13~", r"\e\C-m")
# The same keys as editline is told them. It reads Enter as the terminal
# passes it on, a line feed for one that is set so
EDITLINE_NEW_LINE_KEYS = ("^[[13;2u", "^[[27;2;13~", "^[^M", "^[^J")
# What editline puts into the line for them, a carriage return as it is
# (Ctrl-V, Enter), and how it shows it. It ends a line at any line break
# put at its end, and keeps which one that was until the next line is
# typed: this one says the line goes on, see _line. Of a key macro it
# does the first key at once and the rest with the next key pressed, so
# this is all one can do
EDITLINE_NEW_LINE = "\r"
CONTROL_SHOWN = "^M"
# How long to wait for more of what was pasted after a line break, in
# seconds: a paste arrives at once, or in chunks close together, a line
# typed after the one entered never comes this soon
PASTE_WAIT = 0.05
# How long to wait for the rest once some of it came: Emacs sends a long
# input in bunches, and reads what processes write in between
PASTE_GAP = 0.3
# How much of a paste is read past the line entered, in bytes
PASTE_LIMIT = 1 << 20
# A terminal narrower than this is written to as if it were so wide
NARROWEST = 20


def _read_whatever_comes(stream: TextIO) -> None:
    """Have what is read from the input and is no text in its encoding
    read all the same, each such byte as the character that stands for
    one that could not be (U+FFFD), which shows in the line. It would
    else be raised, in every locale but C: a file of prompts kept in
    another encoding, or a terminal set to one, would end the chat
    where it stands, and the session with it. A stream that was read
    from cannot be set so: only a chat before this one has by then, the
    one of a session that was resumed, which has set it."""
    if isinstance(stream, io.TextIOWrapper) and stream.errors != "replace":
        with contextlib.suppress(io.UnsupportedOperation):
            stream.reconfigure(errors="replace")


def completions(word: str, first: bool, commands: list[str], root: str) -> list[str]:
    """What a word being typed may become: a command when it starts the
    line with a slash, a file of the project after an @. Directories end
    with a slash, to be gone into. The names are a session's to choose,
    and readline writes them to the terminal as they are: one with
    anything in it that is not shown as it is (see clean) is passed over.
    So is what a link leads to outside the project, a session has nothing
    else mounted there and could have made the link."""
    if first and word.startswith("/"):
        return sorted(name for name in commands if name.startswith(word))
    if not word.startswith("@"):
        return []
    typed = word[1:]
    directory, _, start = typed.rpartition("/")
    place = os.path.realpath(os.path.join(root, directory))
    real_root = os.path.realpath(root)
    if os.path.commonpath([real_root, place]) != real_root:
        return []
    try:
        names = sorted(os.listdir(place))
    except OSError:
        return []
    found = []
    for name in names:
        if not name.startswith(start) or (name.startswith(".") and not start):
            continue
        if clean(name) != name or "\n" in name or "\t" in name:
            continue
        ending = "/" if os.path.isdir(os.path.join(place, name)) else ""
        found.append("@" + (f"{directory}/" if directory else "") + name + ending)
    return found[:NAMES_OFFERED]


# The code readline runs of a console within the wait for a line, where
# what is raised is dropped: that of each _readline_hook
_HOOKS: set[CodeType] = set()


def _readline_hook[**P, R](
    hook: Callable[Concatenate[Console, P], R],
) -> Callable[Concatenate[Console, P], R]:
    """What readline calls of a console within the wait for a line (Tab
    completion, the prompt written), which is not interrupted while it
    runs: readline drops what is raised there, and the line could then no
    longer be interrupted, see Console.interrupt. Once it is done, the
    line is ended for a Ctrl-C that came meanwhile, see
    _end_for_interrupt. What runs it is known by its code, see
    _in_readline_hook."""

    def hooked(console: Console, *args: P.args, **kwargs: P.kwargs) -> R:
        console._waiting = False
        try:
            return hook(console, *args, **kwargs)
        finally:
            console._waiting = True
            console._end_for_interrupt()

    _HOOKS.add(hooked.__code__)
    return functools.wraps(hook)(hooked)


def _in_readline_hook(frame: FrameType | None) -> bool:
    """Whether a signal came within a readline hook, see _readline_hook:
    in it or in what it calls, _end_for_interrupt among them once the
    line is waited for again. What is raised there is dropped."""
    while frame is not None:
        if frame.f_code in _HOOKS:
            return True
        frame = frame.f_back
    return False


class Wait(enum.Enum):
    """How far the line being read is: none is, its prompt was given to
    readline and is not on the screen yet, or it is and what is written
    goes above it."""

    IDLE = enum.auto()
    ENTERING = enum.auto()
    READING = enum.auto()


@dataclass(frozen=True)
class Prompting:
    """The line being read as far as it is, with its prompt: one value,
    a line is not about to be read and being read at once, and a prompt
    is of one or the other."""

    wait: Wait = Wait.IDLE
    prompt: str = ""

    def of(self, wait: Wait) -> str | None:
        """Its prompt when it is that far, none when it is not."""
        return self.prompt if self.wait is wait else None


@dataclass(frozen=True)
class Question:
    """A question that takes the place of the usual prompt: what it
    asks, and since when it is before the user, as the prompt of a line
    being read. None while it is not: no answer can be read then, and
    another question starts without one."""

    prompt: str
    since: float | None = None


class Console:
    """Where a chat reads its lines and writes its own: to out, the
    standard output unless given, as wide as columns says, the terminal
    unless given."""

    def __init__(
        self,
        root: str,
        history: str | None = None,
        sent: str = "",
        out: TextIO | None = None,
        columns: Callable[[], int] | None = None,
    ):
        self._lock = threading.Lock()
        self._given_out = out
        # How many columns what is written to has, and how many rows
        self.columns = columns or (lambda: shutil.get_terminal_size().columns)
        self.height: Callable[[], int] = lambda: shutil.get_terminal_size().lines
        # The style of a line once it is entered, none for as it was typed
        self._sent = sent
        # The line being read, as far as it is, see Prompting: had and
        # set through _reading and _entering, its prompt at each stage
        self._prompting = Prompting()
        # The question that is read with instead of the prompt asked
        # for, see ask and Question: had and set through _asked and
        # _asked_at. And the prompt asked for, to go back to
        self._question: Question | None = None
        self._usual = ""
        # Whether readline says when it has written the prompt of a line
        # it is about to read
        self._hooked = False
        # What the next line read starts with, the start of a paste
        self._filled = ""
        # What the line being read starts with that readline does not
        # have, see _line: editline cannot be given the start of a line
        self._begun = ""
        # The lines above the prompt, and above those the ones that say
        # what runs now, see set_working. Whether the line being read
        # has them, and what is on the screen of it, head and prompt: at
        # a terminal what is erased, anywhere else the head last written
        self._head: list[str] = []
        self._working: list[str] = []
        self._headed = False
        self._shown = ""
        # Where nothing is erased: whether the prompt is held back, see
        # hold, and whether it is what was written last, the cursor after it
        self._held = False
        self._on_screen = False
        # Whether the thread that reads waits for a line with nothing of
        # the console held, whether Ctrl-C came for the line while it did
        # not, see interrupt, and whether readline was had to end the
        # line for it, see _end_for_interrupt
        self._waiting = False
        self._interrupted = False
        self._ended_for_interrupt = False
        self.interactive = sys.stdin.isatty()
        # Whatever is typed or sent in, reading it is not what fails
        _read_whatever_comes(sys.stdin)
        # Whether the line being typed can be erased and written again
        self._redrawn = bool(
            readline
            and self.interactive
            and self._out.isatty()
            and os.environ.get("TERM", "dumb") != "dumb"
        )
        self._editline = EDITLINE
        self._root = root
        self._history = history if self._redrawn else None
        # The commands a line can start with, see completions
        self.commands: list[str] = []
        self._offered: list[str] = []
        if self._redrawn:
            self._set_up()

    @property
    def _reading(self) -> str | None:
        """The prompt of the line being read, none while none is."""
        return self._prompting.of(Wait.READING)

    @_reading.setter
    def _reading(self, prompt: str | None) -> None:
        if prompt is not None:
            self._prompting = Prompting(Wait.READING, prompt)
        elif self._prompting.wait is Wait.READING:
            self._prompting = Prompting()

    @property
    def _entering(self) -> str | None:
        """The prompt of a line readline is about to read, none once it
        has written it."""
        return self._prompting.of(Wait.ENTERING)

    @_entering.setter
    def _entering(self, prompt: str | None) -> None:
        if prompt is not None:
            self._prompting = Prompting(Wait.ENTERING, prompt)
        elif self._prompting.wait is Wait.ENTERING:
            self._prompting = Prompting()

    @property
    def _asked(self) -> str | None:
        """The prompt of the question asked, none without one."""
        return self._question.prompt if self._question else None

    @_asked.setter
    def _asked(self, prompt: str | None) -> None:
        # Another question has not come before the user yet
        if prompt is None:
            self._question = None
        elif prompt != self._asked:
            self._question = Question(prompt)

    @property
    def _asked_at(self) -> float | None:
        """When the question asked came before the user, none while it
        has not, or there is none."""
        return self._question.since if self._question else None

    @_asked_at.setter
    def _asked_at(self, since: float | None) -> None:
        if self._question is not None:
            self._question = Question(self._question.prompt, since)

    @property
    def _typed_on(self) -> bool:
        """Whether what was pasted can be the start of the next line
        read, for the user to type on: put into readline once it says it
        has written the prompt, or kept here for editline, see _line."""
        return self._hooked or (self._editline and self._redrawn)

    @property
    def _out(self) -> TextIO:
        """Where lines are written: the standard output as it is when
        written to, unless another was given."""
        return self._given_out or sys.stdout

    def _say(self, text: str) -> None:
        self._out.write(text)
        self._out.flush()

    def _set_up(self) -> None:
        readline.set_completer(self._complete)
        readline.set_completer_delims(" \t\n")
        # The editline of macOS is told its keys in another way
        editline = self._editline
        readline.parse_and_bind("bind ^I rl_complete" if editline else "tab: complete")
        if not editline:
            # Python turns bracketed paste off when readline is imported,
            # each line break of a paste would then enter a line of its
            # own: on, what is pasted is one prompt, line breaks and all
            readline.parse_and_bind("set enable-bracketed-paste on")
            # Inserted as it is, where Ctrl-J alone would enter the line
            for keys in NEW_LINE_KEYS:
                readline.parse_and_bind(f'"{keys}": "\\C-v\\C-j"')
        else:
            for keys in EDITLINE_NEW_LINE_KEYS:
                readline.parse_and_bind(f'bind -s "{keys}" "^V^M"')
        # Editline has the hook and never calls it: a prompt waited for
        # there would never be the line that what is written goes above
        if not editline and hasattr(readline, "set_pre_input_hook"):
            readline.set_pre_input_hook(self._prompted)
            self._hooked = True
        if self._history:
            readline.set_history_length(HISTORY_LINES)
            # Not on top of those of the chat before this one, which a
            # resumed one follows in the same launcher
            readline.clear_history()
            with contextlib.suppress(OSError):
                readline.read_history_file(self._history)

    @_readline_hook
    def _complete(self, word: str, state: int) -> str | None:
        """Asked by readline for each of what a word may become in turn."""
        if state == 0:
            first = readline.get_begidx() == 0
            self._offered = completions(word, first, self.commands, self._root)
        return self._offered[state] if state < len(self._offered) else None

    def _end_for_interrupt(self) -> None:
        """Have GNU readline end the line once the key it is at is done,
        or the next one where it is at none (the prompt just written),
        when Ctrl-C came while the chat's own code ran within the wait
        for it (Tab completion, see interrupt): the key would else be
        lost, readline does not see it. Raised once readline gives the
        line, see _typed. Nothing for editline, where it comes with the
        next line."""
        if self._interrupted and _done is not None:
            _done.value = 1
            self._ended_for_interrupt = True

    def interrupt(self, frame: FrameType | None = None) -> None:
        """End the wait for the line being read as KeyboardInterrupt. For
        the handler of a signal, which runs in the thread that reads,
        between any two steps of it. Raised while that thread holds a
        lock, the lock can stay held: a with does not let go of one that
        was taken in the step before. Whatever needs it next, that thread
        first, would then wait forever. So it is raised only where the
        thread waits for the line and holds nothing, once: one that comes
        a moment before is raised when it gets there, one that comes
        after is dropped with the line.

        Nor is it raised in what readline calls within the wait (see
        _readline_hook), given the frame the signal came in: readline
        drops what is raised there, and in the step before one of them
        says that it does not wait, or after it says again that it does,
        Ctrl-C would be gone, and the line could no longer be
        interrupted. The line is ended for it instead, as within them."""
        hooked = _in_readline_hook(frame)
        if self._waiting and not hooked:
            self._waiting = False
            raise KeyboardInterrupt
        self._interrupted = True
        if hooked:
            self._end_for_interrupt()

    def close(self) -> None:
        """Keep the lines typed for the next chat, for the user alone."""
        if not self._history:
            return
        with contextlib.suppress(OSError):
            # Made for the user alone before anything is written to it
            os.close(os.open(self._history, os.O_WRONLY | os.O_CREAT, 0o600))
            os.chmod(self._history, 0o600)
            readline.write_history_file(self._history)

    def read(
        self,
        prompt: Prompt,
        keep: Callable[[], bool] = lambda: True,
        headed: bool = False,
    ) -> str | None:
        """A line from the user, none when there are no more, with the
        head above its prompt when headed. Not kept among the lines typed
        when keep says so once it is read, as the answer to a question is
        not. Ctrl-C ends it as KeyboardInterrupt when the handler of the
        signal asks for it, see interrupt."""
        line: str | None = None
        try:
            typed = self._line(prompt, headed)
            if self.interactive:
                typed = self._with_paste(typed, prompt, headed)
            # Entered once what came with it is too, not before: Ctrl-C
            # or the end of the input while a paste is typed on drops
            # all of it, and nothing of it is written again as sent
            line = typed
        except EOFError:
            return None
        finally:
            with self._lock:
                # Before anything else is written under it
                if line is not None and self._redrawn:
                    self._entered(line)
                if line is not None:
                    # Enter went to the next line
                    self._on_screen = False
                self._prompting = Prompting()
                # What was pasted goes with a line that was dropped
                self._begun = self._filled = ""
            # One that came once the line was entered is not for the next
            self._interrupted = False
        if not self.interactive:
            # Nobody typed it: said here, for what is written to read as
            # a conversation and to start on a line of its own
            with self._lock:
                self._say(self._styled(shown_typed(line)) + "\n")
        if self._redrawn and not keep():
            self._forget(line)
        return line

    def _line(self, prompt: str, headed: bool) -> str:
        """Read a line, from when its prompt is on the screen being the
        line that what is written goes above. Not before: what is written
        in the moment between would put the prompt there twice. For
        editline, read again while a key of a new line ended it, see
        _set_up: as many times as it is pressed."""
        while True:
            above, shown, begun = self._prompt_set(prompt, headed)
            given = self._given(above, shown) + shown_typed(begun)
            typed = self._typed(given if self._redrawn else "")
            if not (self._editline and self._redrawn):
                return typed
            line = self._editline_line(begun, typed)
            if line is not None:
                return line

    def _prompt_set(self, prompt: str, headed: bool) -> tuple[str, str, str]:
        """Make ready for a line to be read with a prompt, and write that
        where it is not readline's to write: what is above it, the prompt
        it is read with, a question asked instead, and what the line
        starts with that readline does not have."""
        with self._lock:
            self._headed = headed
            self._usual = prompt
            self._comes_before_the_user()
            shown = prompt if self._asked is None else self._asked
            above = self._above()
            if self._redrawn and self._hooked:
                # Its prompt is written by readline, which says when it
                # has, see _prompted
                self._entering = shown
                self._shown = above + shown
            else:
                self._reading = shown
                if self._redrawn:
                    self._shown = above + shown
                    # The start of the line, a paste or the lines
                    # before a key of a new line, which editline cannot
                    # be given to go on from: written after the prompt
                    # as typed, and typed on, but not changed
                    self._begun, self._filled = self._filled, ""
                    if self._editline:
                        # The head is written here, and editline given
                        # the prompt alone, see _given
                        self._say(above)
                elif not self._held or self._asked is not None:
                    self._shown = above
                    self._say(above + shown)
                    self._on_screen = True
            return above, shown, self._begun

    def _editline_line(self, begun: str, typed: str) -> str | None:
        """The line editline read after what it began with, none when a
        key of a new line ended it (see _set_up): it then goes on, as
        the start of the next line read."""
        line = begun + typed.replace(EDITLINE_NEW_LINE, "\n")
        if line != typed:
            self._forget(typed)
            readline.add_history(line)
        if not readline.get_line_buffer().endswith(EDITLINE_NEW_LINE):
            return line
        # Editline did not move to the next row, as it does for Enter:
        # the cursor is still after the key as it shows it, where the
        # erase starts from
        with self._lock:
            shows = shown_typed(line) + CONTROL_SHOWN
            self._say(self._erased(self._shown, shows))
            self._forget(line)
            self._filled = line + "\n"
        return None

    def _given(self, above: str, shown: str) -> str:
        """The prompt readline is given to write: it counts the columns
        of one, and takes an escape of colour for none only when told
        so, a question can be in colour. With the head above it, which
        GNU readline writes once and leaves alone. Not for editline,
        which has the head written for it, see _line: it writes an
        escape with the character after it, and before a line break it
        writes neither, so a head in colour would share a row with the
        prompt. And it counts the rows of a prompt as one, and breaks
        the last where all of them together are as wide as the
        terminal."""
        return uncounted(shown if self._editline else above + shown)

    def _typed(self, prompt: str) -> str:
        """Wait for a line, the one place Ctrl-C ends as
        KeyboardInterrupt, see interrupt. A line readline ended for one
        (see _end_for_interrupt) is no line: dropped, as one that Ctrl-C
        ends while it waits."""
        try:
            self._waiting = True
            if self._interrupted:
                raise KeyboardInterrupt
            line = input(prompt)
            if self._ended_for_interrupt:
                self._forget(line)
                raise KeyboardInterrupt
            return line
        finally:
            self._waiting = False
            self._ended_for_interrupt = False

    def _with_paste(self, line: str, prompt: str, headed: bool) -> str:
        """A line with what came with it: what was pasted without the
        escapes that mark a paste, as a shell buffer of Emacs sends it and
        a terminal that does not mark one, would be a prompt for each of
        its lines. At a terminal it is the start of the line typed on,
        written again, a line break at its end or not: the same as with
        those escapes, Enter enters it."""
        while True:
            with self._lock:
                # Nothing is written meanwhile, the screen is as readline
                # left it
                pasted = self._pasted()
                if not pasted:
                    return line
                text = line + "\n" + pasted.replace("\r\n", "\n").replace("\r", "\n")
                unfinished = self._typed_on
                if self._redrawn:
                    # The line entered alone, written again with the rest
                    out = "\x1b[1A" + self._erased(self._shown, shown_typed(line))
                    self._forget(line)
                    if not unfinished:
                        out += self._shown + shown_typed(text)
                        readline.add_history(text.removesuffix("\n"))
                    self._say(out)
                if not unfinished:
                    return text.removesuffix("\n")
                self._filled = text.rstrip("\n")
            line = self._line(prompt, headed)

    @staticmethod
    def _pasted() -> str:
        """What came after the line just read, read now: a paste arrives
        at once, or in chunks close together, further apart once it has
        started. Not echoed, what is read is written where it belongs.
        Empty when nothing came."""
        fd = sys.stdin.fileno()
        try:
            saved = termios.tcgetattr(fd)
        except (termios.error, OSError):
            return ""
        quiet = list(saved)
        quiet[3] &= ~(termios.ECHO | termios.ICANON)
        quiet[6] = list(saved[6])
        quiet[6][termios.VMIN] = 0
        quiet[6][termios.VTIME] = 0
        data = b""
        wait = PASTE_WAIT
        termios.tcsetattr(fd, termios.TCSANOW, quiet)
        try:
            while len(data) < PASTE_LIMIT and select.select([fd], [], [], wait)[0]:
                chunk = os.read(fd, 65536)
                if not chunk:
                    break
                data += chunk
                wait = PASTE_GAP
        finally:
            termios.tcsetattr(fd, termios.TCSANOW, saved)
        return data.decode(errors="replace")

    @staticmethod
    def _forget(line: str) -> None:
        """Take the line just entered out of the lines typed, where
        readline put it."""
        last = readline.get_current_history_length()
        if line.strip() and last and readline.get_history_item(last) == line:
            readline.remove_history_item(last - 1)

    def _entered(self, line: str) -> None:
        """Write a line that was entered again in its style, in its place
        under the head it was typed under, that head without the lines
        that said what ran then: they would stay on the screen, no longer
        true. Called with the lock held."""
        prompt = self._reading
        line = shown_typed(line)
        styled = bool(self._sent and line.strip())
        working = bool(self._working and self._above())
        if prompt is None or not (styled or working):
            return
        # The cursor is on the row after it, where Enter left it
        shown = self._shown if working else SGR.sub("", prompt)
        out = "\x1b[1A" + self._erased(shown, line)
        if working and self._head:
            out += "\n".join(self._head) + "\n"
        # A prompt in a colour of its own keeps it, a question is: the
        # style is of what was typed after it
        own = prompt if SGR.search(prompt) else ""
        rows = (line if own else prompt + line).split("\n")
        out += own + "\n".join(self._styled(row) if styled else row for row in rows)
        self._say(out + "\n")

    def _styled(self, text: str) -> str:
        """Text the user typed in the style of a line that was entered."""
        return painted(self._sent, text) if self._sent else text

    @_readline_hook
    def _prompted(self) -> None:
        """Told by readline once it has written the prompt of a line. A
        question that was put in the moment before, or a head that changed,
        has the prompt written again as it now is. Not interrupted while
        it holds the lock, see _readline_hook."""
        with self._lock:
            if self._entering is None:
                return
            self._reading = self._entering
            prompt = self._reading if self._asked is None else self._asked
            if self._asked is not None and self._asked_at is None:
                # Put in the moment before, and written just below
                self._asked_at = time.monotonic()
            if self._filled:
                readline.insert_text(self._filled)
                self._filled = ""
                readline.redisplay()
            if self._above() + prompt != self._shown:
                self._put("", prompt)

    @property
    def redrawn(self) -> bool:
        """Whether what is above the line being typed is written again in
        its place when it changes, at a terminal."""
        return self._redrawn

    def _above(self) -> str:
        """The head as it is written above the prompt of the line being
        read: none above a question, nor for a line that has none."""
        head = [*self._working, *self._head]
        if not self._headed or self._asked is not None or not head:
            return ""
        return "\n".join(head) + "\n"

    def set_head(self, lines: list[str]) -> None:
        """Have these lines above the prompt of the lines read with a
        head, the one being read too."""
        with self._lock:
            if lines != self._head:
                self._head = list(lines)
                self._head_changed()

    def set_working(self, lines: list[str]) -> None:
        """Have these lines above the head, none when empty: what runs
        now, a turn and the subagents of claude, said in its place
        rather than in lines that pile up. It holds only while it is
        said, and is not left above a line that was entered, see
        _entered."""
        with self._lock:
            if lines != self._working:
                self._working = list(lines)
                self._head_changed()

    def _head_changed(self) -> None:
        """Write the head of the line being read again, at a terminal,
        where that is done in its place. Anywhere else nothing is
        written for a head that changed: what is written next has it
        under it, with the prompt, and so has the next line read. A
        prompt for each change would stand among the lines, one for
        each figure that moved. Called with the lock held."""
        if not self._redrawn:
            return
        if self._reading is not None and self._headed and self._asked is None:
            self._put("", self._reading)

    def ask(self, prompt: Prompt | None) -> None:
        """Have the next line read with a prompt of its own, the one being
        read too, or with none for the usual one again. For a question
        that comes while the user is at the prompt, and for one that is
        over without a line: the line being read is not its answer."""
        with self._lock:
            # One that differs starts as not yet before the user
            was, self._asked = self._asked, prompt
            if self._reading is None or prompt == was:
                return
            shown = self._usual if prompt is None else prompt
            self._put("", shown)
            # Also where the prompt is held back and nothing was written
            self._reading = shown
            if prompt is not None:
                self._asked_at = time.monotonic()

    def asked_for(self) -> float | None:
        """The seconds the question asked has been before the user, see
        ask. None while it is not: no line was read since it was put, and
        one entered before that is no answer to it."""
        with self._lock:
            if self._asked is None or self._asked_at is None:
                return None
            return time.monotonic() - self._asked_at

    def _comes_before_the_user(self) -> None:
        """The question asked is about to be the prompt of a line, if one
        is and it was not yet. What was typed while nothing read is
        dropped first: a command of the user's ran, or a list they chose
        from was up, and a line entered then was typed before the
        question could be read. Left where it is, it would answer the
        question in the moment it is put, a yes would allow a call
        unseen. Called with the lock held."""
        if self._asked is None or self._asked_at is not None:
            return
        if self.interactive:
            # No terminal after all, or one that is gone
            with contextlib.suppress(termios.error, OSError, ValueError):
                termios.tcflush(sys.stdin.fileno(), termios.TCIFLUSH)
        self._asked_at = time.monotonic()

    def hold(self, held: bool) -> None:
        """Hold the prompt back where nothing is erased, while a turn
        runs, or no longer: the prompt of the line being read is then
        written, with its head. A question is put either way."""
        with self._lock:
            self._held = held
            if held or self._redrawn or self._reading is None or self._on_screen:
                return
            self._shown = self._above()
            self._say(self._shown + self._reading)
            self._on_screen = True

    @property
    def sees_typing(self) -> bool:
        """Whether what is being typed is known, see typed: not in a
        shell buffer of Emacs, which keeps the line to itself until it is
        entered."""
        return self._redrawn

    def typed(self) -> str:
        """What the user has typed of the line being read, as far as that
        is known: at a terminal that is redrawn."""
        with self._lock:
            if self._reading is None or not self._redrawn:
                return ""
            return self._buffer()

    def write(self, lines: list[Shown]) -> None:
        """Write lines, above the line being typed when one is. Lines
        that were laid out, see Shown: a text is not written as it is."""
        if not lines:
            return
        with self._lock:
            self._put("\n".join(lines) + "\n", self._reading)

    def bell(self) -> None:
        """Ring, for a user who looks elsewhere while a turn runs: where
        someone sits, not into a file."""
        if self.interactive and self._out.isatty():
            with self._lock:
                self._say("\a")

    def end_line(self) -> None:
        """Go to a new line, after a line that was left unfinished.
        Where nothing is erased, not after a prompt that was held back:
        there is no line to leave."""
        with self._lock:
            if self._redrawn or self._on_screen or not self.interactive:
                self._say("\n")
            self._on_screen = False

    def _put(self, text: str, prompt: str | None) -> None:
        """Write text and under it the prompt of the line being read, if
        one is. Called with the lock held."""
        was = self._reading
        above = self._above() if prompt is not None else ""
        if was is None:
            out = text
        elif self._redrawn:
            raw = self._buffer()
            typed, before = shown_typed(raw), shown_typed(self._before_cursor(raw))
            shown = above + (prompt or "")
            # Erased from where the cursor is, and the cursor put back
            # there: readline goes on from where it left it
            out = self._erased(self._shown, before) + text + shown + typed
            out += cursor_back(shown, typed, before, self.columns())
            self._shown = shown
        else:
            # Nothing is erased: what is written starts on a line of its
            # own, and the prompt comes after it unless it is held back
            out = ("\n" if self._on_screen else "") + text
            shows = prompt is not None and (not self._held or self._asked is not None)
            if not text and not shows:
                return
            if shows:
                # The head only when it is not what was written last
                if above != self._shown:
                    self._shown = above
                    out += above
                out += prompt or ""
            self._on_screen = shows
        if was is not None:
            self._reading = prompt
        self._say(out)

    def _buffer(self) -> str:
        """What is typed of the line being read, as it is on the screen:
        what it was begun with, see _line, and what readline has of it.
        Editline keeps the line last entered, its line break at the end,
        until a key of the next is typed: that one is not being typed."""
        typed = readline.get_line_buffer()
        if self._editline:
            if typed.endswith(("\n", EDITLINE_NEW_LINE)):
                typed = ""
            # A new line put within the line, as editline shows it
            typed = typed.replace(EDITLINE_NEW_LINE, CONTROL_SHOWN)
        return self._begun + typed

    def _before_cursor(self, typed: str) -> str:
        """What is typed up to the cursor, all of it where readline does
        not say where the cursor is. It counts in bytes. Editline has the
        place and does not keep it while a line is typed."""
        if _point is None or self._editline:
            return typed
        encoding = sys.stdin.encoding or "utf-8"
        raw = typed.encode(encoding, "replace")
        return raw[: max(0, _point())].decode(encoding, "ignore")

    def _erased(self, prompt: str, typed: str) -> str:
        """The escapes that erase a prompt and what is typed after it, at
        a terminal as wide as it is now, see erased of screen.py."""
        return erased(prompt, typed, self.columns())


class Page:
    """What a chat writes, laid out as a trace is (see Layout), and when
    it last wrote. The one place a chat writes through: it takes lines
    that were laid out (see Shown of layout.py), which are the launcher's
    own as a header line or an event, or the session's word, as said and
    replied make them.

    The session's word is cleaned, and in no style but those given it
    here: a line of it is never dimmed as a header line is, nor in the
    colour of an event. Nothing else tells it from a line of the chat's
    own, without colour one written as a header line or as a question
    reads as one."""

    def __init__(self, console: Console, layout: Layout):
        self._console = console
        self.layout = layout
        # When a line was last written, for a turn that then writes
        # nothing to say that it still runs
        self.wrote = time.monotonic()
        # What is said above the head while it holds, each as it is
        # written: that a turn still runs, and how far the subagents are
        self._working: list[str] = []
        self._progress: list[str] = []

    @property
    def width(self) -> int | None:
        """What prose is wrapped to: the terminal, where a reader sits at
        one. None in a file, where a line is as long as it is."""
        if not self.layout.compact:
            return None
        return max(NARROWEST, self._console.columns() - 1)

    def said(
        self, texts: list[str], style: Callable[[str], str] | None = None
    ) -> list[Shown]:
        """Texts of the session's own word as the lines they are written
        as: cleaned here, whatever was done to them before, and a line
        for each line of one that holds a line break. With style, each
        line in the style that gives for it, in colour."""
        lines = prefixed("", [clean(text) for text in texts])
        if style and self.layout.colour:
            lines = [painted(style(line), line) for line in lines]
        return [Shown(line) for line in lines]

    def replied(self, lines: list[Styled]) -> list[Shown]:
        """Lines of a reply of claude's as they are written: cleaned and
        styled by what made them, see ReplyWriter."""
        return [Shown(line) for line in prefixed("", list(lines))]

    def _row(self, line: str) -> str:
        """No more of a line than a row of the terminal, see first_row.
        As it is in a file, where a line is as long as it is."""
        width = self.width
        return line if width is None else first_row(line, width)

    def put(self, lines: list[Shown]) -> None:
        """Write lines, each as long as it is: one longer than the
        terminal is wide is the terminal's to wrap."""
        if lines:
            self._console.write(lines)
            self.touched()

    def put_said(
        self, texts: list[str], style: Callable[[str], str] | None = None
    ) -> None:
        """Write texts of the session's own word, see said."""
        self.put(self.said(texts, style))

    def touched(self) -> None:
        """Something was written, or read, that is no line of the page:
        what the user typed, a question that was put."""
        self.wrote = time.monotonic()

    @property
    def redrawn(self) -> bool:
        """Whether what is above the prompt is written again in its place
        when it changes, see Console.redrawn."""
        return self._console.redrawn

    def head(self, lines: list[str]) -> None:
        """Have these lines above the prompt, see Console.set_head. No
        more of each than a row of the terminal: what is erased with the
        prompt is counted in rows, and a line of more, long by what the
        session named, could have the rows above it erased."""
        self._console.set_head([self._row(line) for line in lines])

    @property
    def height(self) -> int:
        """How many rows the terminal has, see Console.height."""
        return self._console.height()

    def working(self, line: str) -> None:
        """Say that a turn still runs above the head, as a header line,
        or no longer when empty. See Console.set_working."""
        self._working = self._above_head([line] if line else [])
        self._console.set_working([*self._working, *self._progress])

    def progress(self, rows: list[str]) -> None:
        """Say how far the subagents of claude are above the head, under
        the line that says a turn still runs, as header lines, or no
        longer when there are none. See Console.set_working."""
        self._progress = self._above_head(rows)
        self._console.set_working([*self._working, *self._progress])

    def _above_head(self, texts: list[str]) -> list[str]:
        """Texts of the chat's own as the header lines that are written
        above the head, no more of each than a row of the terminal, as
        of the head itself, see head."""
        return [self._row(line) for line in self.layout.header(texts)]

    def say(self, notes: list[str]) -> None:
        """Lines about the chat itself, as the header lines of a trace."""
        self.put(self.layout.header(notes))

    def note(self, label: str, text: str) -> None:
        """A line about the chat itself under a label, see labelled."""
        self.say([labelled(label, text)])

    def events(self, events: list[Event]) -> list[Shown]:
        return self.layout.events(events)
