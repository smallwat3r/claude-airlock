"""What a chat does with each thing claude says over the pipe, by its
kind: a turn that starts and is over, a reply and the pieces it is made
of, a call and its result, what claude asks the user and what it answers
the chat, and what it says of the session (see notices.py). Taken in on
the thread that listens to claude, one message at a time (see Chat), and
what of a message is not as a chat reads it is said (see Drift)."""

from __future__ import annotations

import contextlib
import threading
import time
from collections.abc import Callable

from ..events import flat, labelled
from ..recording.changes import note_change
from ..report.layout import Layout, Shown
from .asking import NOT_ANSWERED
from .commands import LOCAL
from .followed import ASK_SETTLE
from .guard import Brake
from .notices import Notices
from .parts import Parts
from .pipe import Agent
from .said import NAME_KEPT, kept_id, own
from .tasks import Running, still_running
from .turn import READY, READY_STYLE, ended_badly, turn_line

# The messages of claude a chat knows and has no use for
PASSED_OVER = frozenset(
    {
        "auth_status",
        "keep_alive",
        "prompt_suggestion",
        "tool_use_summary",
        "update_environment_variables",
    }
)
# A turn that ran this many seconds rings when it ends, for a user who
# looked elsewhere meanwhile
LONG_TURN = 30.0
# What is said of what claude asks under an id that is none, and of a
# call it asks about while as much of what it asked waits as may (see
# MOST_WAITING of asking.py), which is refused without a question
NO_ID = "claude asked under an id that is none, it cannot be answered"
TOO_MUCH_ASKED = "as much of what claude asked waits for an answer as may"


class Listener:
    """Takes in what claude says, given the parts of the chat it writes
    to and keeps as claude says they are, and claude once the chat is
    run. With brake, what stops a turn for what claude was given to
    read, none when the user switched that off."""

    def __init__(
        self,
        parts: Parts,
        claude: Callable[[], Agent],
        brake: Brake | None = None,
    ):
        self._parts = parts
        self._claude = claude
        self._brake = brake
        self._notices = Notices(parts.page, parts.tasks)
        # What takes in each kind of message claude says
        self._takes: dict[str, Callable[[dict], None]] = {
            "system": self._system,
            "control_request": self._answer,
            "control_cancel_request": self._withdrawn,
            "control_response": self._answered,
            "conversation_reset": self._reset,
            "rate_limit_event": self._limited,
            "stream_event": self._piece,
            "tool_progress": self._notices.call_progress,
            "result": self._turn_over,
            "assistant": self._said,
            "user": self._said,
        }
        # The kinds of message a chat knows, see Drift
        self._known = PASSED_OVER.union(self._takes)
        # Whether claude was asked for its settings and has not answered,
        # and set once it answered the first time, or ended
        self._settings_asked = False
        self.settled = threading.Event()

    def heard(self, message: dict) -> None:
        """Take in one thing claude said, by its kind, then say what of
        it was not as a chat reads it (see Drift). Not of the empty one
        that stands for nothing said, see Chat._listen."""
        kind = message.get("type")
        take = self._takes.get(kind) if isinstance(kind, str) else None
        try:
            if take:
                take(message)
        finally:
            # Also of one that could not be taken in, which may be why.
            # What fails here is not to stand in for what failed there
            if message:
                with contextlib.suppress(Exception):
                    self._changed(message)

    def begin(self) -> bool:
        """Start a turn unless one runs, the prompt held back while it
        does (see Console.hold). Whether one was started."""
        started = self._parts.turns.begin()
        if started:
            self._parts.console.hold(True)
        return started

    def ask_settings(self) -> None:
        """Ask claude which settings it goes by, for the effort the
        status shows: no message of a turn says it. As the chat starts,
        and after each turn, which may have changed it (/effort, /model).
        Not waited for, and not asked again while no answer came: a
        version that does not know the request shows no effort."""
        if self._settings_asked:
            return
        self._settings_asked = True
        self._claude().request("get_settings", self._settings_said, waited=False)

    def _changed(self, message: dict) -> None:
        """Say what of a message was not as a chat reads it, and note it
        for a trace of the session, which has no other way to know."""
        parts = self._parts
        change = parts.drift.told(
            message, self._known, parts.session.version, self._notices.known
        )
        if not change:
            return
        parts.page.note("chat", change.said)
        # A record that cannot be written is no reason to stop
        with contextlib.suppress(OSError):
            note_change(parts.host, parts.name, change.said)

    def _system(self, message: dict) -> None:
        if self._parts.session.heard(message):
            self._turn_started()
        self._notices.system(message)

    def _answered(self, message: dict) -> None:
        """Claude answered a request of the chat's, which is told to
        what asked for it, see Agent.request."""
        self._claude().answered(message)
        # The mode may have changed
        self._parts.status.refresh()
        self._parts.wake.set()

    def _settings_said(self, response: dict) -> None:
        """Take in the settings claude answers that it goes by. The
        status is written again once an answer was taken in, see
        _answered."""
        self._settings_asked = False
        try:
            if response.get("subtype") != "success":
                self._parts.drift.missed("settings")
                return
            applied = self._parts.drift.field(response.get("response"), "applied", dict)
            if applied is not None:
                self._parts.session.settled(applied)
        finally:
            # Whatever it answered, the first prompt waits no longer
            self.settled.set()

    def _reset(self, _message: dict) -> None:
        self._notices.cleared()

    def _limited(self, message: dict) -> None:
        self._notices.limit(message.get("rate_limit_info"))
        self._parts.status.limits.heard(message.get("rate_limit_info"))

    def _said(self, message: dict) -> None:
        """Take in what claude or a subagent of its said, or was given:
        a reply, a tool call or its result."""
        parts = self._parts
        parts.turns.current.heard(message)
        if self._brake:
            self._brake.heard(message)
        if message.get("type") == "assistant" and own(message):
            parts.session.replied(message)
            parts.usage.step(message)
            parts.replies.whole(message)

    def _turn_started(self) -> None:
        """Claude said that a turn starts, and which session it is of:
        that one is followed, /clear goes on as another. The turn is one
        claude starts on its own unless a prompt started it."""
        parts = self._parts
        parts.console.commands = sorted({*LOCAL, *parts.session.commands})
        # The prompt has the status from the first turn on
        parts.status.refresh()
        self._notices.servers(parts.session.servers)
        parts.followed.follow(parts.session.id)
        self.begin()

    def _piece(self, message: dict) -> None:
        """Take in a piece of what claude itself is making: its reply,
        and whether it thinks."""
        if not own(message):
            return
        event = self._parts.drift.field(message, "event", dict)
        if event is None:
            return
        if not isinstance(event.get("type"), str):
            self._parts.drift.missed("event.type")
        self._parts.turns.current.piece(event)
        self._parts.replies.piece(event)

    def _turn_over(self, result: dict) -> None:
        """A turn ended: write the rest of it and what it took. Not for a
        result when no turn runs, nor one of a subagent's: a turn that
        is over is not over again, and the next one has not started."""
        parts = self._parts
        if not parts.turns.running or not own(result):
            return
        parts.replies.turn_over()
        parts.followed.settle()
        more = parts.usage.parts(result, parts.session.model)
        turn = parts.turns.current
        parts.page.working("")
        # A command of Claude Code's that went well took nothing worth a
        # line: the model was not asked and no call was made
        if more or turn.said or turn.interrupted or ended_badly(result):
            parts.page.say([turn_line(turn, result, more)])
        # And what it did on the network, as its capture saw it: since
        # the turn before, what the session does between two is in the
        # next one's
        reached = parts.followed.network()
        if reached:
            parts.page.say([labelled("network", reached)])
        parts.status.refresh()
        self.ask_settings()
        if not turn.guarded:
            # Not of a turn that was stopped for what claude read: it has
            # not finished, and what comes next is said where it stopped
            parts.page.put([ready_line(parts.page.layout, parts.tasks.running)])
        if not turn.interrupted and time.monotonic() - turn.started >= LONG_TURN:
            parts.console.bell()
        parts.console.hold(False)
        parts.turns.end()
        parts.wake.set()

    def _answer(self, message: dict) -> None:
        """Answer what claude asks its host: whether a tool may be used,
        which is the user's to say. Anything else is not for a chat, and
        said to be asked. Not what is asked under an id that is none,
        which no answer could name: it is the session's to send, nested
        as deep as can be read, and answered it would be written back."""
        page = self._parts.page
        request = message.get("request")
        asked = kept_id(message.get("request_id"))
        if asked is None:
            page.note("chat", NO_ID)
            return
        if not isinstance(request, dict) or request.get("subtype") != "can_use_tool":
            what = (
                flat(request.get("subtype", "?")) if isinstance(request, dict) else "?"
            )
            page.say(
                [
                    labelled(
                        "chat", f"claude asked for {what}, which a chat cannot answer"
                    )
                ]
            )
            self._refuse(asked, "not supported by claude-airlock --line-mode")
            return
        try:
            # The call it asks about first, the question comes under it
            self._parts.followed.settle(ASK_SETTLE)
        finally:
            # Put however that went: claude waits for an answer to what
            # it asked, and the turn with it. Refused at once when as
            # much of it waits as may
            if not self._parts.asked.put(asked, request):
                self._refuse(asked, "too much is asked at once")
                tool = flat(request.get("tool_name", "?")).lower()[:NAME_KEPT]
                page.note("chat", f"REFUSED {tool} unasked: {TOO_MUCH_ASKED}")

    def _refuse(self, asked: str, why: str) -> None:
        """Refuse what claude asked under an id, and say so when that
        could not be said to it, see Agent.refuse."""
        if not self._claude().refuse(asked, why):
            self._parts.page.note("chat", NOT_ANSWERED)

    def _withdrawn(self, message: dict) -> None:
        """Claude no longer asks what it asked under an id, see
        Asked.cancel. Not under one that is none, which nothing was
        asked under, see _answer."""
        asked = kept_id(message.get("request_id"))
        if asked is not None:
            self._parts.asked.cancel(asked)


def ready_line(layout: Layout, running: Running | None = None) -> Shown:
    """What is said once a turn is over, for the eye to find where claude
    stopped and the prompt is the user's again: bright green in colour.
    With subagents or other tasks of claude's that still run, it says
    so: the turn is over and the work is not, claude takes up again
    when one of them ends."""
    said = READY
    left = still_running(running) if running else ""
    if left:
        paused = f"claude has paused, {left}, it goes on when one ends"
        said = labelled("ready", paused)
    return layout.header([said], READY_STYLE)[0]
