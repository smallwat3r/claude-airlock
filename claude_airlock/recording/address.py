"""Noting the address a filtered session was given, which is how --trace
tells the sessions in the proxy's shared log apart."""

from __future__ import annotations

import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager

from ..background import in_background, wait_for
from ..sandbox.network import session_address
from ..settings import Host, Settings
from .records import TracedSession, record_traced_session


def record_address(
    name: str, owner: str, host: Host, started: float, stop: threading.Event
) -> None:
    address = wait_for(lambda: session_address(owner), stop)
    if address:
        record_traced_session(
            host, TracedSession(name, host.project_dir, started, ip=address)
        )


@contextmanager
def session_address_recorded(
    settings: Settings, host: Host, name: str, owner: str
) -> Iterator[None]:
    """While a filtered session runs, note the address it was given. The
    proxy logs each request with the address it came from, which a
    container without capabilities cannot forge, so this is what lets
    --trace tell the sessions in the shared log apart. The address is only
    known once the container is up, by when the launcher is waiting on it,
    hence the thread. owner is the container the address belongs to: the
    session, or its capture sidecar."""
    if not settings.net_filter:
        yield
        return
    with in_background(record_address, name, owner, host, time.time()):
        yield
