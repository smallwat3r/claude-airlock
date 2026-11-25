"""What the events of sessions go through before they are shown, in a
trace and in what follows the sessions as they run: put in the order they
happened, each thing on the network said to be made during the tool call
that ran then, and those that were asked for chosen."""

from __future__ import annotations

import time
from collections.abc import Callable, Iterable
from dataclasses import dataclass

from ..events import Event, Kind, Stage, Who, labelled
from .calls import call_label
from .layout import shown_what, went_wrong

# Of the call a connection is said to be made during
DURING_WIDTH = 60
# Seconds for which the timeline remembers a call that has ended, for the
# events of the network that are read later than they happened
TIMELINE_SLACK = 30.0
# No more calls than this are remembered, the ones started first go: a
# call whose result never comes is never known to have ended
MOST_CALLS = 10_000

# What an event comes with, where it is not alone: the transcript it is
# from, for what follows several sessions


@dataclass(frozen=True)
class Filter:
    """Which events are shown, all of them unless told otherwise: with
    --only those of the kinds named (what the what column says, bash or
    net), with --failed those that tell of something gone wrong."""

    only: frozenset[str] = frozenset()
    failed: bool = False

    def __bool__(self) -> bool:
        return bool(self.only) or self.failed

    def wants(self, event: Event) -> bool:
        if self.only and not {event.what, shown_what(event.what)} & self.only:
            return False
        return went_wrong(event) or not self.failed

    def header(self) -> list[str]:
        """The line that says what was left out, none when nothing was:
        a trace kept in a file must not pass for a whole one."""
        said = [f"only {', '.join(sorted(self.only))}"] if self.only else []
        said += ["only what went wrong"] if self.failed else []
        return [labelled("shown", ", ".join(said))] if said else []


# The filter that leaves nothing out
EVERYTHING = Filter()


@dataclass
class RunningCall:
    """A tool call as the timeline knows it: from when to when it ran,
    and what it is shown by."""

    started: float
    ended: float
    label: str


class Timeline:
    """Says of each thing on the network which tool call was running when
    it happened, from the events in the order they come. That is not proof
    the call did it, a connection is known by its container and not by the
    command that opened it, but a connection made while one command ran is
    as a rule that command's, and one made while none ran is Claude Code's
    own or that of something left running."""

    def __init__(self) -> None:
        self._calls: dict[str, RunningCall] = {}
        # The latest time seen, the events of the network can come late
        self._now = 0.0
        # From when the calls are next looked through for those to let
        # go of, not with every one of them
        self._next_look = 0.0

    def take(self, event: Event) -> None:
        """Note a tool call or its result, or mark an event of the
        network with the calls running at its time."""
        fields = event.fields
        # No later than it is: an entry is the session's to date, and one
        # dated ahead would have all that is read after it be too long ago
        self._now = max(self._now, min(event.when, time.time()))
        call = fields.get("id")
        if event.call and isinstance(call, str):
            self._note(event, call)
        elif event.kind is Kind.NET and fields.get("stage") != Stage.OUTCOME:
            self._mark(event)

    def _note(self, event: Event, call: str) -> None:
        fields = event.fields
        stage = fields.get("stage")
        if stage == Stage.RESULT:
            if call in self._calls:
                self._calls[call].ended = event.when
            return
        # Live a call runs until its result comes. In a transcript that
        # is all there it ran for as long as its result says, and one
        # without a result is not known to have run at all.
        seconds = fields.get("seconds")
        length = seconds if isinstance(seconds, (int, float)) else 0.0
        ended = float("inf") if stage == Stage.CALL else event.when + length
        # As its line has it: one taken out of the transcript says so
        # here too
        named = "  ".join([call_label(event) or fields["tool"], *event.notes])
        self._calls[call] = RunningCall(event.when, ended, named[:DURING_WIDTH])
        self._forget()

    def _forget(self) -> None:
        """Let go of the calls that ended too long ago to be the one
        anything read from now on was made during, and of the oldest
        past MOST_CALLS. As calls are noted, not as the network is
        marked: what follows a session without a capture marks nothing,
        and still runs for as long as the session does."""
        if self._now >= self._next_look:
            self._next_look = self._now + TIMELINE_SLACK
            forgotten = self._now - TIMELINE_SLACK
            for call in [c for c, ran in self._calls.items() if ran.ended < forgotten]:
                del self._calls[call]
        while len(self._calls) > MOST_CALLS:
            del self._calls[next(iter(self._calls))]

    def _mark(self, event: Event) -> None:
        if event.when < self._now - TIMELINE_SLACK:
            # Too long ago to tell: the calls of then are forgotten
            return
        running = {
            call: ran
            for call, ran in self._calls.items()
            if ran.started <= event.when <= ran.ended
        }
        event.fields["during"] = list(running)
        if not running:
            event.notes.append("(no call running)")
            return
        # The one started last: the others are what it runs within, a
        # subagent for one
        latest = max(running.values(), key=lambda ran: ran.started)
        more = f" (+{len(running) - 1} more)" if len(running) > 1 else ""
        event.notes.append(f"during: {latest.label}{more}")


def ordered[Found](
    found: Iterable[Found],
    event: Callable[[Found], Event],
    timeline: Timeline,
    chosen: Filter,
) -> list[Found]:
    """What was found in the order it happened, each event of it taken by
    the timeline, and of that what is chosen. Every event goes by the
    timeline, one that is not shown may be the call another was made
    during."""
    # Stable, so what a transcript has at the same time keeps its order
    in_order = sorted(found, key=lambda one: event(one).when)
    for one in in_order:
        timeline.take(event(one))
    return [one for one in in_order if chosen.wants(event(one))]


def record_event(when: float, lines: list[str]) -> Event:
    """What is said above the events as one of them, for JSON Lines,
    which has no other place for it: the lines as they are. Among them
    is what says that a record is not all there (a transcript CHANGED or
    NOT ALL COPIED, a capture STOPPED or INCOMPLETE), which the events
    read as if nothing were missing do not tell."""
    return Event(when, Who.SANDBOX, Kind.RECORD, [], {"lines": lines})


def wants_record(chosen: Filter) -> bool:
    """Whether the lines above the events are given with them: also
    with --failed, they say what is missing, and not with --only unless
    it names them."""
    return not chosen.only or Kind.RECORD in chosen.only
