"""What the launcher says of itself to the user."""

from __future__ import annotations

import sys

from .events import clean, flat
from .settings import NAME


def warn(message: str, *more: str) -> None:
    """Say something of the launcher's own to the user, on the errors: a
    line under its name, and the lines that go with it. Never on the
    output, which is the session's or a report's. What is said names
    what a session made, a file by the name it gave it: nothing of it
    drives the terminal, and each of the lines that go with it stays the
    one line it is, so that a name can neither erase what was said nor
    pass for another line of it."""
    lines = [f"{NAME}: {clean(message)}", *map(flat, more)]
    print(*lines, sep="\n", file=sys.stderr)
