"""Doing something next to a session while the launcher waits on it."""

from __future__ import annotations

import threading
from collections.abc import Callable, Iterator
from contextlib import contextmanager


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
