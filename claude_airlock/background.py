"""Doing something next to a session while the launcher waits on it."""

from __future__ import annotations

import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager

from .notice import warn

# How often wait_for asks again
ASK_EVERY = 0.2


@contextmanager
def in_background(work: Callable[..., None], *args: object) -> Iterator[None]:
    """Run work in a thread for as long as the block lasts. It is given
    its arguments and then an event, which is set when the block is left:
    work has to return soon after, it is waited for.

    Work that fails ends alone, the session goes on without it: said
    when the block is left, by the name of the work. What is done here
    is what the launcher keeps of a session, its transcripts copied, its
    address noted, its health, and a thread that ended on something
    unforeseen would leave that record short without a word, for the
    rest of the session."""
    stop = threading.Event()
    failed: list[BaseException] = []

    def run() -> None:
        try:
            work(*args, stop)
        except Exception as error:  # noqa: BLE001
            # Whatever it is: kept to be said, a thread has nowhere to
            # raise it
            failed.append(error)

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    try:
        yield
    finally:
        stop.set()
        thread.join()
        for error in failed:
            name = getattr(work, "__name__", "work").replace("_", " ")
            warn(
                f"what the launcher does next to a session FAILED ({name}) and"
                " was not done for the rest of it, what it keeps of the"
                " session may be incomplete:",
                repr(error),
            )


def wait_for[Found](ask: Callable[[], Found], stop: threading.Event) -> Found | None:
    """Ask until the answer is something, every ASK_EVERY seconds, and
    return it. None when stop is set first."""
    while not (answer := ask()):
        if stop.wait(ASK_EVERY):
            return None
    return answer
