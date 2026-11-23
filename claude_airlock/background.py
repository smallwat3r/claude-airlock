"""Doing something next to a session while the launcher waits on it."""

from __future__ import annotations

import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager

# How often wait_for asks again
ASK_EVERY = 0.2


@contextmanager
def in_background(work: Callable[..., None], *args: object) -> Iterator[None]:
    """Run work in a thread for as long as the block lasts. It is given
    its arguments and then an event, which is set when the block is left:
    work has to return soon after, it is waited for."""
    stop = threading.Event()
    thread = threading.Thread(target=work, args=(*args, stop), daemon=True)
    thread.start()
    try:
        yield
    finally:
        stop.set()
        thread.join()


def wait_for[Found](ask: Callable[[], Found], stop: threading.Event) -> Found | None:
    """Ask until the answer is something, every ASK_EVERY seconds, and
    return it. None when stop is set first."""
    while not (answer := ask()):
        if stop.wait(ASK_EVERY):
            return None
    return answer
