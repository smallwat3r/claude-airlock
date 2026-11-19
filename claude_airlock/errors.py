"""What the launcher gives up on."""

from __future__ import annotations


class Fatal(Exception):
    """A problem to report to the user as one line, without a traceback."""
