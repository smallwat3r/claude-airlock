"""The parts of a chat that more than one of what makes it up reads: the
conversation (see talk.py), what takes in what claude says (see
listener.py), and what stops a turn for what claude was given to read
(see guard.py). Each is made once for a chat, and each of those is given
the same."""

from __future__ import annotations

import threading
from collections.abc import Callable
from dataclasses import dataclass

from ..projects import sandboxed_root
from ..settings import Host
from .asking import Asked, Asker
from .console import Console, Page
from .drift import Drift
from .followed import Followed
from .reply import ReplyStream
from .said import Session
from .status import Sandbox, StatusLine
from .tasks import Tasks
from .turn import Turns, Usage


@dataclass(frozen=True)
class Parts:
    """Where a chat writes, what it knows of the session by what claude
    says, and what puts to the user what claude asks, see made."""

    host: Host
    # Of the session's container
    name: str
    console: Console
    page: Page
    # Told what claude no longer says as a chat reads it, by what reads it
    drift: Drift
    session: Session
    turns: Turns
    usage: Usage
    # The tasks claude started, its subagents among them
    tasks: Tasks
    replies: ReplyStream
    followed: Followed
    status: StatusLine
    asker: Asker
    # What claude asked and has no answer to yet
    asked: Asked
    # Set when a turn ends, a question is put or claude ends
    wake: threading.Event

    @classmethod
    def made(
        cls,
        host: Host,
        sandbox: Sandbox,
        console: Console,
        page: Page,
        gone: Callable[[], bool],
    ) -> Parts:
        """The parts of a chat with the session of a sandbox, written to
        a page of the console. Nothing is asked once gone says there is
        nobody left to ask, or to ask for."""
        drift = Drift()
        session = Session(drift=drift)
        turns = Turns()
        usage = Usage(drift)
        tasks = Tasks(drift)
        replies = ReplyStream(page, lambda: followed.show(now=True))
        followed = Followed(host, sandbox.name, page, turns, replies)
        wake = threading.Event()
        # The paths claude asks about are those of the sandbox: the project
        # is the one the session knows, not where it is on the host
        asker = Asker(page, console, sandboxed_root(host), gone, wake.set)
        status = StatusLine(page, sandbox, session, usage, drift, lambda: tasks.running)
        return cls(
            host,
            sandbox.name,
            console,
            page,
            drift,
            session,
            turns,
            usage,
            tasks,
            replies,
            followed,
            status,
            asker,
            Asked(asker, page),
            wake,
        )
