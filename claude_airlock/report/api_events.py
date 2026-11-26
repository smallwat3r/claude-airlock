"""The requests to the model that api_log.py noted, as line mode, --trace
and the lines said when a session ends show them: a line per request,
with how much was sent and what of, what the API says it used, and where
the two bodies are kept."""

from __future__ import annotations

import enum
import functools
import os
from collections.abc import Callable, Collection, Iterable

from ..events import Event, Kind, Who, Wrong
from ..recording.api_calls import (
    UNRECORDED,
    Call,
    Tokens,
    call_record,
    shown_text,
    unrecorded,
)
from ..recording.api_log import NOTED_WITHIN
from ..settings import Host
from .brief import amount
from .entries import SHORT_ID
from .shown import size

# What is said of a request that names no model
NO_MODEL = "(no model named)"
# What is said of a request the transcript of its session has no step of
NO_STEP = "no step of the transcript"
# The directories of bodies the header names, a trace is of few sessions
MOST_NAMED = 3
# Among the values of a request whose bodies were kept and no longer are
GONE = "bodies_gone"


class Origin(enum.Enum):
    """What Claude Code made a request for, as far as the name it gives
    that tells, each by how such a name starts."""

    # The conversation itself: at Claude Code's own screen, and run by a
    # chat or a script
    CONVERSATION = ("repl_main_thread", "sdk")
    # A subagent of claude's
    SUBAGENT = ("agent:",)
    # Anything else Claude Code asks the model besides: a title, a
    # summary, what a page it fetched says
    BESIDES = ()

    @classmethod
    def of(cls, source: str) -> Origin:
        """What the request of a name was made for. One without a name
        is taken for the conversation's: nothing says otherwise."""
        if not source:
            return cls.CONVERSATION
        for origin in (cls.CONVERSATION, cls.SUBAGENT):
            if source.startswith(origin.value):
                return origin
        return cls.BESIDES

    @property
    def who(self) -> Who:
        """Who an event says made such a request."""
        return Who.AGENT if self is Origin.SUBAGENT else Who.CLAUDE

    def said(self, source: str) -> str:
        """What is said after a request of what it was made for, nothing
        of one of the conversation."""
        if self is Origin.CONVERSATION:
            return ""
        return source if self is Origin.SUBAGENT else f"for: {source}"


def _sent(call: Call) -> str:
    """What a request sent, as it is said: how long the body was, and
    how much of it each part took."""
    if call.withheld:
        return "sent: the body was withheld by Claude Code"
    if not call.sent:
        return "sent: the request was NOT FOUND"
    if not call.parts:
        return f"sent {size(call.sent)}, not read as a request"
    of = ", ".join(f"{part.value} {size(taken)}" for part, taken in call.parts.items())
    return f"sent {size(call.sent)}: {of}"


def _used(call: Call) -> str:
    """What the API says a request used and why the model stopped, as it
    is said. Of one without an answer, that."""
    if not call.answered:
        return "NO ANSWER was noted"
    read = sum(used for kind, used in call.used.items() if kind.read)
    written = call.used.get(Tokens.OUTPUT, 0)
    if not read and not written:
        return call.stop or "the answer was not read"
    cached = call.used.get(Tokens.CACHE_READ, 0)
    tokens = (
        f"tokens: {amount(read)} in ({amount(cached)} cached), {amount(written)} out"
    )
    return "  ".join(filter(None, (tokens, call.stop)))


# Whether the directory of some bodies, by its name, is still kept
type StillKept = Callable[[str], bool]


def _kept(call: Call, gone: bool) -> str:
    """Where the bodies of a request are, as it is said: the number they
    are kept under, in the directory the header names. Or that they
    were not kept, or no longer are: what is kept goes after some days."""
    if gone:
        return "bodies NO LONGER KEPT"
    return f"kept as {call.kept.partition('/')[2]}" if call.kept else "bodies NOT KEPT"


def _fields(call: Call, container: str, gone: bool) -> dict[str, object]:
    """A request as the values of its event: what the record has of it,
    the tokens under the names a step has them by, and its container.
    Not where its bodies were kept when they no longer are, that they
    are gone instead."""
    said: dict[str, object] = {
        "source": call.source,
        "model": call.model,
        "claude_session": call.claude_session,
        "request_id": call.request_id,
        "message_id": call.message_id,
        "message_uuid": call.message_uuid,
        "sent": call.sent,
        **{part.value: taken for part, taken in call.parts.items()},
        "tool_count": call.tool_count,
        "message_count": call.message_count,
        "received": call.received,
        **{kind.value: used for kind, used in call.used.items()},
        "stop": call.stop,
    }
    return {
        "container": container,
        "answered": call.answered,
        **{name: value for name, value in said.items() if value not in (None, "")},
        # Said either way, empty of one whose bodies are not kept
        "kept": "" if gone else call.kept,
        **({GONE: True} if gone else {}),
    }


def _unrecorded_event(when: float, number: int) -> Event:
    """That a session made more requests than are noted one by one."""
    if number:
        detail = f"{number} more requests NOT RECORDED one by one"
    else:
        detail = "more requests than are recorded one by one, counted from here"
    fields = {UNRECORDED: number, "error": "not recorded one by one"}
    return Event(
        when, Who.SANDBOX, Kind.REQUEST, [detail], fields, wrong=Wrong.THROUGHOUT
    )


def call_event(said: dict, still_kept: StillKept | None = None) -> Event | None:
    """A line of the record as an event: a request to the model, or that
    there were more than are noted. The record is the launcher's own,
    what it holds was still written by a session: it is read as a Call,
    which takes nothing as it is. With still_kept, the bodies of a
    request are said to be gone when their directory no longer is kept:
    not asked of a request that was just noted."""
    when = float(said["t"])
    counted = unrecorded(said)
    if counted is not None:
        return _unrecorded_event(when, counted)
    call = Call.from_note(said)
    origin = Origin.of(call.source)
    gone = bool(
        call.kept and still_kept and not still_kept(call.kept.partition("/")[0])
    )
    detail = "  ".join(
        (call.model or NO_MODEL, _sent(call), _used(call), _kept(call, gone))
    )
    fields = _fields(call, shown_text(said, "session"), gone)
    event = Event(when, origin.who, Kind.REQUEST, [detail], fields)
    made_for = origin.said(call.source)
    if made_for:
        event.notes.append(made_for)
    return event


def _summary(host: Host, events: list[Event]) -> list[tuple[str, str]]:
    """The rows that sum up the requests of some events: how many there
    were, how much they sent, what is missing of them, and where their
    bodies are kept."""
    calls = [event for event in events if UNRECORDED not in event.fields]
    more = sum(event.fields.get(UNRECORDED, 0) for event in events)
    unanswered = sum(not event.fields["answered"] for event in calls)
    gone = sum(GONE in event.fields for event in calls)
    unkept = sum(not event.fields["kept"] for event in calls) - gone
    sent = sum(event.fields.get("sent", 0) for event in calls)
    said = f"{len(calls)} to the model, {size(sent)} sent"
    if unanswered:
        said += f", {unanswered} without an answer"
    if unkept:
        said += f", the bodies of {unkept} NOT KEPT"
    if gone:
        said += f", the bodies of {gone} NO LONGER KEPT"
    if len(calls) < len(events):
        said += f", {more or 'some'} more NOT RECORDED one by one"
    directories = dict.fromkeys(
        event.fields["kept"].partition("/")[0]
        for event in calls
        if event.fields["kept"]
    )
    kept = [
        ("requests", "bodies kept in " + os.path.join(host.api_bodies_dir, directory))
        for directory in list(directories)[:MOST_NAMED]
    ]
    return [("requests", said), *kept]


def call_events(
    host: Host, start: float, end: float, session: str | None = None
) -> tuple[list[tuple[str, str]], list[Event]]:
    """The requests this project's sessions made to the model between
    two times, as summary rows when there are any and as events. Of one
    session when it is named, by its container. A request is noted a
    moment after its answer is in the transcript, which is where a span
    of time ends for a session that is not over: those noted within
    NOTED_WITHIN of the end are of that span too."""
    record = call_record(host)
    noted = record.read(host.project_dir, start, end + NOTED_WITHIN, session)

    @functools.cache
    def still_kept(directory: str) -> bool:
        return os.path.isdir(os.path.join(host.api_bodies_dir, directory))

    events = [event for said in noted if (event := call_event(said, still_kept))]
    return (_summary(host, events), events) if events else ([], [])


def place_calls(
    events: Iterable[Event], session: str, steps: Collection[str] | None
) -> None:
    """Say of each request to the model where it stands next to the
    transcript of a session, by the id of that session. One that Claude
    Code says is of another session is said to be: the record is of the
    project, and its sessions can run side by side. One of this session
    whose answer is no step of its transcript, nor of those of its
    subagents, is said to be none, which is what Claude Code asked
    besides the conversation: by the ids of the steps, none when the
    transcripts were not read whole and that cannot be told."""
    for event in events:
        if event.kind is not Kind.REQUEST or UNRECORDED in event.fields:
            continue
        claimed = event.fields.get("claude_session", "")
        if claimed != session:
            if claimed:
                event.notes.append(f"of session {claimed[:SHORT_ID]}")
            continue
        answer = event.fields.get("message_id")
        if steps is not None and event.fields["answered"] and answer not in steps:
            event.notes.append(NO_STEP)
            event.fields["no_step"] = True
