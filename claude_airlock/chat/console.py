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
has (the status, see status.py), and above that a line that says a turn
still runs, see set_working. At a terminal it goes with the
prompt, under what is written, and is written again in its place when it
changes. Anywhere else it is written with the prompt of each line read,
and with the prompt written again when it changed.

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
the next, where readline is there to do both."""

from __future__ import annotations

import contextlib
import ctypes
import os
import select
import shutil
import sys
import termios
import threading
import time
from collections.abc import Callable
from typing import TextIO

from ..events import Event, labelled
from ..report.layout import Layout, painted
from .screen import SGR, cursor_back, erased, uncounted

try:
    import readline
except ImportError:  # pragma: no cover, a Python built without it
    readline = None  # type: ignore[assignment]


def _readline_point() -> Callable[[], int] | None:
    """What reads where the cursor is in the line being typed, in bytes
    from its start. The module of Python does not say, the library it is
    made with does (rl_point, of GNU readline and of editline alike).
    None where that cannot be had."""
    try:
        library = ctypes.CDLL(getattr(readline, "__file__", None))
        point = ctypes.c_int.in_dll(library, "rl_point")
    except (OSError, ValueError, TypeError, AttributeError):
        return None
    return lambda: point.value


_point = _readline_point() if readline else None

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


def completions(word: str, first: bool, commands: list[str], root: str) -> list[str]:
    """What a word being typed may become: a command when it starts the
    line with a slash, a file of the project after an @. Directories end
    with a slash, to be gone into."""
    if first and word.startswith("/"):
        return sorted(name for name in commands if name.startswith(word))
    if not word.startswith("@"):
        return []
    typed = word[1:]
    directory, _, start = typed.rpartition("/")
    place = os.path.normpath(os.path.join(root, directory))
    if os.path.commonpath([root, place]) != root:
        # Not out of the project, a session has nothing else mounted there
        return []
    try:
        names = sorted(os.listdir(place))
    except OSError:
        return []
    found = []
    for name in names:
        if not name.startswith(start) or (name.startswith(".") and not start):
            continue
        ending = "/" if os.path.isdir(os.path.join(place, name)) else ""
        found.append("@" + (f"{directory}/" if directory else "") + name + ending)
    return found[:NAMES_OFFERED]


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
        # How many columns what is written to has
        self.columns = columns or (lambda: shutil.get_terminal_size().columns)
        # The style of a line once it is entered, none for as it was typed
        self._sent = sent
        # The prompt of the line being read, none while none is
        self._reading: str | None = None
        # The prompt to read with instead of the one asked for, see ask
        self._asked: str | None = None
        # The prompt of a line readline is about to read, and whether it
        # says when it has written it
        self._entering: str | None = None
        self._hooked = False
        # What the next line read starts with, the start of a paste
        self._filled = ""
        # The lines above the prompt, whether the line being read has
        # them, and what is on the screen of it, head and prompt: at a
        # terminal what is erased, anywhere else the head last written
        self._head: list[str] = []
        self._working = ""
        self._headed = False
        self._shown = ""
        # Where nothing is erased: whether the prompt is held back, see
        # hold, and whether it is what was written last, the cursor after it
        self._held = False
        self._on_screen = False
        # Whether the thread that reads waits for a line with nothing of
        # the console held, and whether Ctrl-C came for the line while it
        # did not, see interrupt
        self._waiting = False
        self._interrupted = False
        self.interactive = sys.stdin.isatty()
        # Whether the line being typed can be erased and written again
        self._redrawn = bool(
            readline
            and self.interactive
            and self._out.isatty()
            and os.environ.get("TERM", "dumb") != "dumb"
        )
        self._root = root
        self._history = history if self._redrawn else None
        # The commands a line can start with, see completions
        self.commands: list[str] = []
        self._offered: list[str] = []
        if self._redrawn:
            self._set_up()

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
        editline = "libedit" in (readline.__doc__ or "")
        readline.parse_and_bind("bind ^I rl_complete" if editline else "tab: complete")
        if not editline:
            # Python turns bracketed paste off when readline is imported,
            # each line break of a paste would then enter a line of its
            # own: on, what is pasted is one prompt, line breaks and all
            readline.parse_and_bind("set enable-bracketed-paste on")
            # Inserted as it is, where Ctrl-J alone would enter the line
            for keys in NEW_LINE_KEYS:
                readline.parse_and_bind(f'"{keys}": "\\C-v\\C-j"')
        if hasattr(readline, "set_pre_input_hook"):
            readline.set_pre_input_hook(self._prompted)
            self._hooked = True
        if self._history:
            readline.set_history_length(HISTORY_LINES)
            with contextlib.suppress(OSError):
                readline.read_history_file(self._history)

    def _complete(self, word: str, state: int) -> str | None:
        """Asked by readline for each of what a word may become in turn.
        Not interrupted meanwhile: readline drops what is raised here, and
        the line could then no longer be interrupted, see interrupt."""
        self._waiting = False
        try:
            if state == 0:
                first = readline.get_begidx() == 0
                self._offered = completions(word, first, self.commands, self._root)
            return self._offered[state] if state < len(self._offered) else None
        finally:
            self._waiting = True

    def interrupt(self) -> None:
        """End the wait for the line being read as KeyboardInterrupt. For
        the handler of a signal, which runs in the thread that reads,
        between any two steps of it. Raised while that thread holds a
        lock, the lock can stay held: a with does not let go of one that
        was taken in the step before. Whatever needs it next, that thread
        first, would then wait forever. So it is raised only where the
        thread waits for the line and holds nothing, once: one that comes
        a moment before is raised when it gets there, one that comes
        after is dropped with the line."""
        if self._waiting:
            self._waiting = False
            raise KeyboardInterrupt
        self._interrupted = True

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
        prompt: str,
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
            line = self._line(prompt, headed)
            if self.interactive:
                line = self._with_paste(line, prompt, headed)
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
                self._reading = self._entering = None
            # One that came once the line was entered is not for the next
            self._interrupted = False
        if not self.interactive:
            # Nobody typed it: said here, for what is written to read as
            # a conversation and to start on a line of its own
            self._say(self._styled(line) + "\n")
        if self._redrawn and line.strip() and not keep():
            with contextlib.suppress(ValueError):
                readline.remove_history_item(readline.get_current_history_length() - 1)
        return line

    def _line(self, prompt: str, headed: bool) -> str:
        """Read a line, from when its prompt is on the screen being the
        line that what is written goes above. Not before: what is written
        in the moment between would put the prompt there twice."""
        with self._lock:
            self._headed = headed
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
                elif not self._held or self._asked is not None:
                    self._shown = above
                    self._say(above + shown)
                    self._on_screen = True
        # Readline counts the columns of a prompt, and takes an escape of
        # colour for none only when told so: a question can be in colour
        return self._typed(uncounted(above + shown) if self._redrawn else "")

    def _typed(self, prompt: str) -> str:
        """Wait for a line, the one place Ctrl-C ends as
        KeyboardInterrupt, see interrupt."""
        try:
            self._waiting = True
            if self._interrupted:
                raise KeyboardInterrupt
            return input(prompt)
        finally:
            self._waiting = False

    def _with_paste(self, line: str, prompt: str, headed: bool) -> str:
        """A line with what came with it: what was pasted without the
        escapes that mark a paste, as a shell buffer of Emacs sends it and
        a terminal that does not mark one, would be a prompt for each of
        its lines. At a terminal it is the start of the line typed on,
        written again, a line break at its end or not: the same as with
        those escapes, Enter enters it. A shell buffer of Emacs sends
        nothing until Enter is pressed, what ends with a line break there
        is entered, what does not is typed on."""
        while True:
            with self._lock:
                # Nothing is written meanwhile, the screen is as readline
                # left it
                pasted = self._pasted()
                if not pasted:
                    return line
                text = line + "\n" + pasted.replace("\r\n", "\n").replace("\r", "\n")
                unfinished = self._hooked and (self._redrawn or not text.endswith("\n"))
                if self._redrawn:
                    # The line entered alone, written again with the rest
                    out = "\x1b[1A" + self._erased(self._shown, line)
                    self._forget(line)
                    if not unfinished:
                        out += self._shown + text
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
        under the head it was typed under, that head without the line that
        said a turn still runs: it would stay on the screen, no longer
        true. Called with the lock held."""
        prompt = self._reading
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

    def _prompted(self) -> None:
        """Told by readline once it has written the prompt of a line. A
        question that was put in the moment before, or a head that changed,
        has the prompt written again as it now is. Called within the wait
        for a line, and not interrupted while it holds the lock, see
        interrupt."""
        self._waiting = False
        try:
            with self._lock:
                if self._entering is None:
                    return
                self._reading, self._entering = self._entering, None
                prompt = self._reading if self._asked is None else self._asked
                if self._filled:
                    readline.insert_text(self._filled)
                    self._filled = ""
                    readline.redisplay()
                if self._above() + prompt != self._shown:
                    self._put("", prompt)
        finally:
            self._waiting = True

    @property
    def redrawn(self) -> bool:
        """Whether what is above the line being typed is written again in
        its place when it changes, at a terminal."""
        return self._redrawn

    def _above(self) -> str:
        """The head as it is written above the prompt of the line being
        read: none above a question, nor for a line that has none."""
        head = [self._working, *self._head] if self._working else self._head
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

    def set_working(self, line: str) -> None:
        """Have this line above the head, none when empty: that a turn
        still runs, said in its place rather than in lines that pile up."""
        with self._lock:
            if line != self._working:
                self._working = line
                self._head_changed()

    def _head_changed(self) -> None:
        """Write the head of the line being read again. Called with the
        lock held."""
        if self._reading is not None and self._headed and self._asked is None:
            self._put("", self._reading)

    def ask(self, prompt: str | None) -> None:
        """Have the next line read with a prompt of its own, the one being
        read too, or with none for the usual one again. For a question
        that comes while the user is at the prompt."""
        with self._lock:
            self._asked = prompt
            if self._reading is not None and prompt is not None:
                self._put("", prompt)

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
            return readline.get_line_buffer()

    def write(self, lines: list[str]) -> None:
        """Write lines, above the line being typed when one is."""
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
            typed = readline.get_line_buffer()
            before = self._before_cursor(typed)
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

    @staticmethod
    def _before_cursor(typed: str) -> str:
        """What is typed up to the cursor, all of it where readline does
        not say where the cursor is. It counts in bytes."""
        if _point is None:
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
    it last wrote."""

    def __init__(self, console: Console, layout: Layout):
        self._console = console
        self.layout = layout
        # When a line was last written, for a turn that then writes
        # nothing to say that it still runs
        self.wrote = time.monotonic()

    @property
    def width(self) -> int | None:
        """What prose is wrapped to: the terminal, where a reader sits at
        one. None in a file, where a line is as long as it is."""
        if not self.layout.compact:
            return None
        return max(NARROWEST, self._console.columns() - 1)

    def put(self, lines: list[str]) -> None:
        if lines:
            self._console.write(lines)
            self.touched()

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
        """Have these lines above the prompt, see Console.set_head."""
        self._console.set_head(lines)

    def working(self, line: str) -> None:
        """Say that a turn still runs above the head, as a header line,
        or no longer when empty. See Console.set_working."""
        self._console.set_working(self.layout.header([line])[0] if line else "")

    def say(self, notes: list[str]) -> None:
        """Lines about the chat itself, as the header lines of a trace."""
        self.put(self.layout.header(notes))

    def note(self, label: str, text: str) -> None:
        """A line about the chat itself under a label, see labelled."""
        self.say([labelled(label, text)])

    def events(self, events: list[Event]) -> list[str]:
        return self.layout.events(events)
