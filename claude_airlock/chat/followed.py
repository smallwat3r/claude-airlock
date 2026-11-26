"""What the session did, written as a chat goes: its tool calls, what it
reached on the network, what its subagents did, taken from the records
--trace --follow reads (see follow.py). Not what claude says over the pipe,
which the chat writes as it comes, see told_over_the_pipe."""

from __future__ import annotations

import time
from collections.abc import Callable

from ..events import Event, Kind, Stage, Who
from ..report.follow import Follower
from ..report.layout import Shown
from ..settings import Host
from .console import Page
from .reply import said_whole
from .said import transcript_of
from .turn import Turns

# Seconds between two looks at what is followed while a turn runs, and
# while none does: what a session does on its own then is rare
POLL = 0.5
IDLE_POLL = 2.0
# Seconds a turn that is over is given for its last lines to be written
SETTLE = 3.0
# What a chat shows whole of what the transcript has, see said_whole
READ_WHOLE = (Kind.COMMAND,)
# The events a chat is told of by claude itself as they happen, which it
# says in its own words (see notices.py), and the one it notes itself
# (see changes.py)
SAID_LIVE = frozenset({Kind.API, Kind.COMPACT, Kind.TASK, Kind.CHANGED})


def told_over_the_pipe(event: Event, since: float) -> bool:
    """Whether an event is one the chat wrote, or will, from what
    claude says over the pipe: a reply of claude's (see ReplyStream),
    and what claude says of the session as it happens (see Notices).
    Any since the chat started, one from before is the history of a
    session that is resumed, which only the transcript has."""
    claudes = event.who is Who.CLAUDE and event.kind is Kind.REPLY
    said = claudes or event.kind in SAID_LIVE
    return said and event.when >= since


class Followed:
    """The session of a chat as it is followed, and what it did written
    to the page. With writing, whether a reply is being written: what is
    found is not written into it."""

    def __init__(
        self,
        host: Host,
        name: str,
        page: Page,
        turns: Turns,
        writing: Callable[[], bool],
    ):
        self._host = host
        # Of the session's container
        self._name = name
        self._page = page
        self._turns = turns
        self._writing = writing
        self._follower: Follower | None = None
        # When what is followed was last looked at, and when the chat
        # started: what the transcript has of before is its history
        self._looked = 0.0
        self._started = time.time()

    def follow(self, session: str) -> None:
        """Follow the session claude says it is. Of the network only what
        this session's container does, the project's other sessions have
        their own screens."""
        path = transcript_of(self._host, session)
        if self._follower:
            if path:
                self._follower.follow_only(path)
            return
        if path is None:
            self._page.note("chat", "claude did not say which session it is,")
            self._page.note("chat", "every session of the project is followed")
        self._follower = Follower(
            self._host, False, path, container=self._name, steps=True
        )

    def show(self, now: bool = False) -> None:
        """Write what the session did since the last look. Not more often
        than every POLL seconds, less often still while no turn runs,
        unless it has to be now. And not into a reply that is being
        written."""
        if not self._follower:
            return
        pace = POLL if self._turns.running else IDLE_POLL
        waited = time.monotonic() - self._looked
        if not now and (self._writing() or waited < pace):
            return
        found = self._follower.poll()
        self._looked = time.monotonic()
        self._page.say(found.notes)
        lines: list[Shown] = []
        # The events since the last one that is shown whole
        together: list[Event] = []
        for _, event in found.events:
            if event.who is Who.CLAUDE and event.fields.get("stage") == Stage.CALL:
                self._turns.current.shown += 1
            if told_over_the_pipe(event, self._started):
                continue
            if event.kind in READ_WHOLE:
                lines += self._page.events(together) + said_whole(self._page, event)
                together = []
            else:
                together.append(event)
        self._page.put(lines + self._page.events(together))

    def network(self) -> str:
        """What the session did on the network since this was last
        asked, as a turn that is over says it: empty when it did
        nothing there, or nothing of it is recorded."""
        return self._follower.traffic().said if self._follower else ""

    def settle(self, patience: float = SETTLE) -> None:
        """Show what a turn did up to now, for what comes next to be
        written under it. The last of it may not be in the transcript
        yet: until every call claude made was shown, but not for long."""
        deadline = time.monotonic() + patience
        self.show(now=True)
        turn = self._turns.current
        while turn.shown < turn.said and time.monotonic() < deadline:
            time.sleep(0.1)
            self.show(now=True)
