"""What the session writes besides what claude says in a conversation: a
line of its errors, a line of its output that is no message (see Agent),
and the lines of claude's that could not be read.

Each is written as it comes, cleaned, the session's own word. Not
without end: a process of the session writes to the errors of the first
as fast as it likes (yes > /proc/1/fd/2), and what the user is to read,
a question among it, would be gone from the screen before they could.
No more lines than can be read are shown of those that come together,
and of the rest it is said how many there were."""

from __future__ import annotations

import math
import time

from .console import Page

# No more lines than this are shown of those that come within WINDOW
# seconds. More than is written at once by a command of claude's that
# the launcher does not know yet, its help or a list, which is shown as
# it writes it (see NO_CONVERSATION of claude_args.py). Past it they are
# counted, and a line says how many once the window is over. While they
# keep coming at more than that, no more than FEW of each window are
# shown, enough to tell what is being written
MOST = 500
WINDOW = 5.0
FEW = 5
# What is said of a line of claude's that was not read, see Unread of
# pipe.py: a request it made in it has no answer, and the end of a turn
# said in it is not known
UNREAD = (
    "a line of the session was too long to read: if claude waits for an"
    " answer to it, none can be given, Ctrl-C stops the turn"
)


class PlainLines:
    """Writes the lines of a session that are no message of claude's,
    and counts those it leaves out, see the module."""

    def __init__(self, page: Page):
        self._page = page
        # When the window that is counted in started, how many lines it
        # may show, and how many of its lines were shown and left out
        self._since = -math.inf
        self._room = MOST
        self._shown = 0
        self._left_out = 0
        # Whether a line of claude's was said to be unread in it
        self._unread = False

    def heard(self, line: str) -> None:
        """Write a line the session wrote, unless as many were written
        as the window may show: it is counted then."""
        self.say_left_out()
        if self._shown >= self._room:
            self._left_out += 1
            return
        self._shown += 1
        self._page.put_said([line.rstrip()])

    def unread(self) -> None:
        """Say that a line of claude's could not be read, once for all
        those of a window, the others counted: what it may mean is the
        same for each. Whatever else the session writes meanwhile, this
        is not what is left out for it."""
        self.say_left_out()
        if self._unread:
            self._left_out += 1
            return
        self._unread = True
        self._page.note("chat", UNREAD)

    def say_left_out(self, now: bool = False) -> None:
        """Say how many lines were left out, once the window they came
        in is over, and start the next one. Or now, when the session has
        ended. Called at every look at what the session did: a session
        that stops writing is not waited for to write again."""
        if not now and time.monotonic() - self._since < WINDOW:
            return
        left_out, self._left_out = self._left_out, 0
        if left_out:
            more = "1 more line" if left_out == 1 else f"{left_out} more lines"
            faster = "it writes them faster than they can be read"
            self._page.note("chat", f"left out {more} of the session, {faster}")
        # As many came as were shown and left out together
        self._room = FEW if self._shown + left_out > MOST else MOST
        self._since = time.monotonic()
        self._shown = 0
        self._unread = False
