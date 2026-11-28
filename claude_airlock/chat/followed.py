"""What the session did, written as a chat goes: its tool calls, what it
reached on the network, what its subagents did, taken from the records
--trace --follow reads (see follow.py). Not what claude says over the pipe,
which the chat writes as it comes, see told_over_the_pipe."""

from __future__ import annotations

import time
from collections.abc import Callable
from typing import Protocol

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


def _always(_event: Event) -> bool:
    """Every event of a kind claude tells the chat of."""
    return True


# Of the events of the transcript, by their kind, whether one is what
# claude told the chat of as it happened, which the chat says in its own
# words (see notices.py), or notes itself (see changes.py), by the fields
# told.py gives it. A request the API did not answer, which claude says
# with an api_retry for each api_error. A task, but not one of the
# schedule that fired, a turn that no user started, which notices.py
# passes over. A call refused without asking the user, not a change of
# mode, and another model gone on with when one failed, not a change of
# model nor a request the model refused: those the chat leaves to the
# transcript
SAID_LIVE: dict[Kind, Callable[[Event], bool]] = {
    Kind.API: _always,
    Kind.COMPACT: _always,
    Kind.CHANGED: _always,
    Kind.MEMORY: _always,
    Kind.TASK: lambda event: "cron" not in event.fields,
    Kind.MODE: lambda event: "denied_tool" in event.fields,
    Kind.MODEL: lambda event: (
        "trigger" in event.fields and not event.fields.get("refused")
    ),
}


def told_over_the_pipe(event: Event, since: float) -> bool:
    """Whether an event is one the chat wrote, or will, from what
    claude says over the pipe: a reply of claude's (see ReplyStream),
    and what claude says of the session as it happens (see Notices and
    SAID_LIVE). Any since the chat started, one from before is the
    history of a session that is resumed, which only the transcript
    has."""
    kind = event.kind
    claudes = event.who is Who.CLAUDE and kind is Kind.REPLY
    live = SAID_LIVE.get(kind) if kind else None
    said = claudes or (live is not None and live(event))
    return said and event.when >= since


class Writing(Protocol):
    """A reply of claude's that is being written, which what is found is
    not written into while it holds that back, and which makes way for
    it once it no longer does: see ReplyStream."""

    @property
    def holding(self) -> bool: ...

    def make_way(self) -> None: ...


class Followed:
    """The session of a chat as it is followed, and what it did written
    to the page. With reply, the reply that is being written, which what
    is found is not written into while it holds that back."""

    def __init__(
        self,
        host: Host,
        name: str,
        page: Page,
        turns: Turns,
        reply: Writing,
    ):
        self._host = host
        # Of the session's container
        self._name = name
        self._page = page
        self._turns = turns
        self._reply = reply
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
        written while it holds that back, between two of its lines once
        it no longer does (see HOLD_OPEN of reply.py)."""
        if not self._follower:
            return
        pace = POLL if self._turns.running else IDLE_POLL
        waited = time.monotonic() - self._looked
        if not now and (self._reply.holding or waited < pace):
            return
        found = self._follower.poll()
        self._looked = time.monotonic()
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
        lines += self._page.events(together)
        if not now and (found.notes or lines):
            self._reply.make_way()
        self._page.say(found.notes)
        self._page.put(lines)

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
