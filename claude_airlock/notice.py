"""What the launcher says of itself to the user."""

from __future__ import annotations

import sys

from .settings import NAME


def warn(message: str, *more: str) -> None:
    """Say something of the launcher's own to the user, on the errors: a
    line under its name, and the lines that go with it. Never on the
    output, which is the session's or a report's."""
    print(f"{NAME}: {message}", *more, sep="\n", file=sys.stderr)
