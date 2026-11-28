"""What is kept of what a session can make any number of: the latest of
it, by the order it was put in."""

from __future__ import annotations


def forget_oldest(kept: dict, most: int) -> None:
    """Let go of the oldest of what a mapping keeps, by the order it was
    put in, until it keeps no more than most."""
    while len(kept) > most:
        del kept[next(iter(kept))]
