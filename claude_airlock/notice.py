"""What the launcher says of itself to the user."""

from __future__ import annotations

import sys

from .events import flat
from .settings import NAME


def warn(message: str, *more: str) -> None:
    """Say something of the launcher's own to the user, on the errors: a
    line under its name, and the lines that go with it. Never on the
    output, which is the session's or a report's. What is said names
    what a session made, a file by the name it gave it: nothing of it
    drives the terminal, and the line under its name stays the one line
    it is, as each of the lines that go with it does, so that a name can
    neither erase what was said nor pass for another line of it, one of
    the launcher's own among them. What ends a launch (Fatal) is said
    here too."""
    lines = [f"{NAME}: {flat(message)}", *map(flat, more)]
    print(*lines, sep="\n", file=sys.stderr)
