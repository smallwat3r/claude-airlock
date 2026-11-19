"""The conversation of a chat with one session: what the user types read
and sent, what the session does written.

Three threads. The one the chat is run by reads the lines the user types,
at any time, and does what each asks: a prompt typed while a turn runs is
taken up by claude when it can. The second listens to claude and looks at
what is followed, and writes. What claude asks the user is put by the
third, one question at a time, and answered through the first (see
asking.py): the second goes on listening meanwhile, a session whose
subagents work on is not held up by a question nobody has answered yet.

What each of them does is not here: what the session did is written by
followed.py, a turn that is quiet is said to run by turn.py, a line that
is the chat's own to do is done by commands.py."""

from __future__ import annotations

import contextlib
import dataclasses
import os
import queue
import signal
import threading
import time
from collections.abc import Callable

from ..docker import docker_ok, project_slug
from ..events import Event, Kind, clean, flat, labelled
from ..files import private_dir
from ..projects import sandboxed_root
from ..recording.changes import note_change
from ..report.layout import (
    BOLD,
    BRIGHT_CYAN,
    BRIGHT_GREEN,
    BRIGHT_MAGENTA,
    ITALIC,
    STYLES,
    Layout,
    painted,
    together,
)
from ..settings import Host
from .asking import Asked, Asker
from .commands import LOCAL, Commands, Did, Handover, Resume
from .console import Console, Page
from .drift import Drift
from .followed import POLL, Followed
from .notices import Notices
from .pipe import Agent
from .reply import ReplyStream
from .said import Session, own
from .shell import Shell
from .status import Sandbox, StatusLine
from .turn import Heartbeat, Turns, Usage, ended_badly, turn_line

# What reaches claude for a chat, given what to tell once claude has ended
Connect = Callable[[Callable[[], None]], Agent]

# The messages of claude a chat knows and has no use for
PASSED_OVER = frozenset(
    {
        "auth_status",
        "control_cancel_request",
        "keep_alive",
        "prompt_suggestion",
        "tool_progress",
        "tool_use_summary",
        "update_environment_variables",
    }
)
PROMPT = "> "
# After a line that ended with a backslash, which takes the next one too
MORE = ". "
# A turn that ran this many seconds rings when it ends, for a user who
# looked elsewhere meanwhile
LONG_TURN = 30.0
# Said once a turn is over, and how in colour: bold bright green
READY = labelled("ready", "claude has finished, waiting for your input")
READY_STYLE = together(BOLD, BRIGHT_GREEN)
# Where each side of the conversation starts, to be found among what the
# session does: the line over a reply of claude bold and bright cyan, a
# line the user sent bold and bright magenta
REPLY_HEAD_STYLE = together(BOLD, BRIGHT_CYAN)
SENT_STYLE = together(BOLD, BRIGHT_MAGENTA)
# Why claude says it makes a call, in italics under its bold label
REASON_STYLE = ITALIC
# Seconds the call claude asks about is given to be written, before the
# question is put
ASK_SETTLE = 1.0
# Seconds a session is given to end before a line says how to stop it
LEAVE_QUIET = 2.0
# How long a session that was told to stop is waited for, docker gives it
# ten seconds before it ends it
STOP_WAIT = 15.0
# The messages in a row that may fail to be taken in before the chat
# gives up on showing what the session does
MOST_FAILED = 5


class Chat:
    """The conversation with one session, see the module. With connect,
    what reaches claude for it: the session of a docker command, see
    chat."""

    def __init__(
        self,
        host: Host,
        sandbox: Sandbox,
        layout: Layout,
        connect: Connect,
        console: Console | None = None,
        handover: Handover | None = None,
        start: Event | None = None,
    ):
        self._host = host
        # How the sandbox was started as the launcher noted it, said first
        self._start = start
        # Of the session's container, to stop it by
        self._name = sandbox.name
        self._connect = connect
        # Claude, from when the chat is run
        self._agent: Agent
        self._console = console or Console(host.project_dir)
        self._console.commands = sorted(LOCAL)
        self._page = Page(self._console, layout)
        self._handover = handover
        # Told what claude no longer says as a chat reads it, by what
        # reads it
        self._drift = Drift()
        self._session = Session(drift=self._drift)
        self._turns = Turns()
        self._usage = Usage(self._drift)
        self._notices = Notices(self._page)
        self._followed = Followed(
            host, sandbox.name, self._page, self._turns, lambda: self._replies.writing
        )
        self._replies = ReplyStream(self._page, lambda: self._followed.show(now=True))
        # Set when a turn ends, a question is put or claude ends
        self._wake = threading.Event()
        # The paths claude asks about are those of the sandbox: the project
        # is the one the session knows, not where it is on the host
        self._asker = Asker(
            self._page,
            self._console,
            sandboxed_root(host),
            self._gone,
            self._wake.set,
        )
        # What claude asked and has no answer to yet, see _leave
        self._asked = Asked(self._asker, self._page)
        self._heartbeat = Heartbeat(self._page, self._turns, lambda: self._asker.asking)
        self._status = StatusLine(
            self._page, sandbox, self._session, self._usage, self._drift
        )
        self._shell = Shell(self._page, sandbox.name)
        resume = Resume(self._page, host, self._turns, self._read, handover)
        self._commands = Commands(
            self._page,
            self._session,
            lambda *asked, **more: self._agent.request(*asked, **more),
            self._shell.run,
            resume.resume,
            self._status.show,
        )
        # What takes in each kind of message claude says
        self._takes: dict[str, Callable[[dict], None]] = {
            "system": self._system,
            "control_request": self._answer,
            "control_response": self._answered,
            "conversation_reset": self._reset,
            "rate_limit_event": self._limited,
            "stream_event": self._piece,
            "result": self._turn_over,
            "assistant": self._said,
            "user": self._said,
        }
        # Whether a line is waited for, and whether Ctrl-C came for a turn
        self._reading = False
        self._interrupt = False
        # Whether claude has ended, whether the user is leaving, and
        # whether it was they who left and not claude that ended
        self._over = False
        self._leaving = False
        self._left = False

    def run(self) -> int:
        """Run the session and talk to it until the user leaves or it
        ends. Returns how docker ended."""
        previous = signal.signal(signal.SIGINT, self._on_interrupt)
        connected = False
        try:
            self._agent = self._connect(self._session_ended)
            connected = True
            title = labelled("chat", flat(self._host.project_dir))
            columns = self._page.layout.columns
            self._page.say([f"{title}, /help says what there is", columns])
            if self._start:
                self._page.put(self._page.events([self._start]))
            listener = threading.Thread(target=self._listen, daemon=True)
            listener.start()
            self._asked.start(self._agent)
            # What the session was started with heads the first prompt
            # too: that is when it matters most
            self._status.refresh()
            self._converse()
            return self._leave(listener)
        except BaseException:
            # However the chat ends, the session ends with it: what the
            # launcher checks next is checked of a session that is over
            if connected:
                self._abandon()
            raise
        finally:
            signal.signal(signal.SIGINT, previous)
            self._console.close()

    def _abandon(self) -> None:
        """End a session the chat can no longer talk to: no more prompts
        come, and one that does not take that for its end is stopped."""
        self._agent.close()
        if not self._agent.over_within(LEAVE_QUIET):
            docker_ok("stop", self._name)
            self._agent.over_within(STOP_WAIT)

    def _gone(self) -> bool:
        """Whether there is nobody left to ask, or to ask for."""
        return self._leaving or self._over

    def _on_interrupt(self, _number: int, _frame: object) -> None:
        """Ctrl-C: for the turn that runs when one does, and for a session
        that is slow to leave. Else it ends the wait for a line, which
        drops what was typed."""
        if self._shell.running and not self._leaving:
            # For the command the user runs
            self._shell.interrupt()
            return
        if self._leaving or (self._turns.running and not self._over):
            self._interrupt = True
            # What claude asked is refused with it
            self._asker.give_up()
        elif self._reading:
            raise KeyboardInterrupt

    def _session_ended(self) -> None:
        """Told by the thread that reads claude. A wait for a line would
        go on until the user ends it: it is ended as Ctrl-C would. One
        that has not started yet sees that claude is over, see _read."""
        self._over = True
        self._wake.set()
        if self._reading:
            os.kill(os.getpid(), signal.SIGINT)

    def _read(self, prompt: str, headed: bool = False) -> str | None:
        """A line from the user, none when there are no more, with the
        status above its prompt when headed. As Ctrl-C when claude has
        ended, there is nobody left to read it. The answer to a question is
        not kept among the lines typed."""
        self._reading = True
        try:
            # After _reading is set: an end that comes from here on is told
            # by _session_ended, one that came before is seen here
            if self._over:
                raise KeyboardInterrupt
            return self._console.read(prompt, lambda: not self._asker.asking, headed)
        except KeyboardInterrupt:
            self._console.end_line()
            raise
        finally:
            self._reading = False
            self._page.touched()

    def _converse(self) -> None:
        """Read what the user types and do what it asks, until they leave
        or the session has ended."""
        lines: list[str] = []
        while not self._over:
            if not self._console.interactive:
                self._wait_for_turn()
            try:
                if lines:
                    line = self._read(MORE)
                else:
                    line = self._read(PROMPT, headed=True)
            except KeyboardInterrupt:
                # Ctrl-C drops what was typed, unless the session is over
                lines = []
                continue
            if line is None:
                self._console.end_line()
                return
            if self._asker.take(line):
                continue
            if line.endswith("\\"):
                lines.append(line[:-1])
                continue
            text = "\n".join([*lines, line]).strip()
            lines = []
            if not text:
                continue
            did = self._commands.do(text)
            if did is Did.LEFT:
                return
            if did is Did.NOTHING:
                self._send(text)

    def _wait_for_turn(self) -> None:
        """Wait until claude has nothing left to do, or asks something.
        For lines that are not typed but all there, a file or a pipe: each
        is for the turn after the one before it, and the answer to a
        question is the line after the prompt that led to it."""
        while (
            (self._turns.running or self._agent.pending)
            and not self._asker.asking
            and not self._over
        ):
            self._wake.wait(0.2)
            self._wake.clear()

    def _send(self, text: str) -> None:
        """Give claude a prompt. While a turn runs claude takes it up
        when it can: within that turn between two of its steps, or as a
        turn of its own after it, which it then says it starts."""
        started = self._begin()
        self._agent.prompt(text)
        if not started:
            self._page.note("chat", "sent, claude takes it up when it can")

    def _begin(self) -> bool:
        """Start a turn unless one runs, the prompt held back while it
        does (see Console.hold). Whether one was started."""
        started = self._turns.begin()
        if started:
            self._console.hold(True)
        return started

    def _listen(self) -> None:
        """Take in what claude says and write what the session does,
        until claude has ended."""
        # The messages in a row that could not be taken in
        stumbled = 0
        try:
            while True:
                # Nothing said within POLL is an empty message, for what is
                # followed to be looked at meanwhile. None is the end.
                try:
                    message = self._agent.messages.get(timeout=POLL)
                except queue.Empty:
                    message = {}
                if message is None:
                    break
                if isinstance(message, str):
                    # Not what claude says in a conversation, see Agent
                    self._page.put([clean(message).rstrip()])
                    continue
                if self._interrupt:
                    self._interrupt = False
                    self._stop()
                try:
                    self._heard(message)
                    self._followed.show()
                    self._heartbeat.beat()
                    stumbled = 0
                except Exception as error:
                    # One message that cannot be taken in is not the end
                    # of the session, what it holds is claude's to write
                    stumbled += 1
                    if stumbled >= MOST_FAILED:
                        raise
                    skipped = f"FAILED to show a message: {flat(repr(error))[:200]}"
                    self._page.say([labelled("chat", skipped)])
            self._replies.turn_over()
            self._followed.show(now=True)
            if not self._left:
                self._page.note("chat", "the session ended")
        except Exception as error:  # noqa: BLE001
            # Whatever it is, the user is told and can leave: a chat that
            # no longer writes would pass for a session that does nothing
            failed = labelled(
                "chat", f"FAILED, nothing more is shown: {flat(repr(error))}"
            )
            self._page.say([failed])
        finally:
            self._session_ended()
            self._asked.close()

    def _heard(self, message: dict) -> None:
        """Take in one thing claude said, by its kind, then say what of
        it was not as a chat reads it (see Drift). Not of the empty one
        that stands for nothing said, see _listen."""
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

    def _changed(self, message: dict) -> None:
        """Say what of a message was not as a chat reads it, and note it
        for a trace of the session, which has no other way to know."""
        known = PASSED_OVER.union(self._takes)
        change = self._drift.told(message, known, self._session.version)
        if not change:
            return
        self._page.note("chat", change.said)
        # A record that cannot be written is no reason to stop
        with contextlib.suppress(OSError):
            note_change(self._host, self._name, change.said)

    def _system(self, message: dict) -> None:
        if self._session.heard(message):
            self._turn_started()
        self._notices.system(message)

    def _answered(self, message: dict) -> None:
        """Claude answered a request of the chat's, which is told to
        what asked for it, see Agent.request."""
        self._agent.answered(message)
        # The mode may have changed
        self._status.refresh()
        self._wake.set()

    def _reset(self, _message: dict) -> None:
        self._notices.cleared()

    def _limited(self, message: dict) -> None:
        self._notices.limit(message.get("rate_limit_info"))
        self._status.limits.heard(message.get("rate_limit_info"))

    def _said(self, message: dict) -> None:
        """Take in what claude or a subagent of its said, or was given:
        a reply, a tool call or its result."""
        self._turns.current.heard(message)
        if message.get("type") == "assistant" and own(message):
            self._session.replied(message)
            self._usage.step(message)
            self._replies.whole(message)

    def _turn_started(self) -> None:
        """Claude said that a turn starts, and which session it is of:
        that one is followed, /clear goes on as another. The turn is one
        claude starts on its own unless a prompt started it."""
        self._console.commands = sorted({*LOCAL, *self._session.commands})
        # The prompt has the status from the first turn on
        self._status.refresh()
        self._notices.servers(self._session.servers)
        self._followed.follow(self._session.id)
        self._begin()

    def _piece(self, message: dict) -> None:
        """Take in a piece of what claude itself is making: its reply,
        and whether it thinks."""
        if not own(message):
            return
        event = self._drift.field(message, "event", dict)
        if event is None:
            return
        if not isinstance(event.get("type"), str):
            self._drift.missed("event.type")
        self._turns.current.piece(event)
        self._replies.piece(event)

    def _turn_over(self, result: dict) -> None:
        """A turn ended: write the rest of it and what it took."""
        self._replies.turn_over()
        self._followed.settle()
        more = self._usage.parts(result, self._session.model)
        turn = self._turns.current
        self._page.working("")
        # A command of Claude Code's that went well took nothing worth a
        # line: the model was not asked and no call was made
        if more or turn.said or turn.interrupted or ended_badly(result):
            self._page.say([turn_line(turn, result, more)])
        self._status.refresh()
        self._page.put([ready_line(self._page.layout.colour, self._notices.running)])
        if not turn.interrupted and time.monotonic() - turn.started >= LONG_TURN:
            self._console.bell()
        self._console.hold(False)
        self._turns.end()
        self._wake.set()

    def _stop(self) -> None:
        """Ctrl-C: claude is asked to end the turn that runs, and the
        second time the session is stopped. So is one that is slow to
        leave."""
        turn = self._turns.current
        if self._leaving or (self._turns.running and turn.interrupted):
            self._page.note("chat", "stopping the session")
            docker_ok("stop", self._name)
        elif self._turns.running:
            turn.interrupted = True
            self._agent.request("interrupt")
            self._page.note("chat", "interrupting, Ctrl-C again stops the session")

    def _leave(self, listener: threading.Thread) -> int:
        """End the session, which leaves when it is told no more prompts
        come. Ctrl-C stops one that does not, see _stop."""
        self._left = not self._over
        self._leaving = True
        self._asker.give_up()
        # What claude asked is answered before it is told to leave, a
        # refusal that came too late would not be read
        self._asked.answered_within(LEAVE_QUIET)
        self._agent.close()
        told = False
        started = time.monotonic()
        while True:
            if listener.is_alive():
                listener.join(0.1)
            elif not self._agent.drain():
                break
            elif self._interrupt:
                # Nobody listens any more, see _listen
                self._interrupt = False
                docker_ok("stop", self._name)
            if not told and time.monotonic() - started > LEAVE_QUIET:
                told = True
                waiting = labelled(
                    "chat", "waiting for the session to end, Ctrl-C stops it"
                )
                self._page.say([waiting])
        self._say_how_to_go_on()
        return self._agent.status()

    def _say_how_to_go_on(self) -> None:
        """Say how the session that was left is gone on with, unless
        another one is about to be."""
        resumed = self._handover is not None and self._handover.session
        if self._session.id and self._left and not resumed:
            again = f"claude-airlock --line-mode --resume {self._session.id}"
            self._page.note("chat", f"to go on with this session: {again}")

    def _answer(self, message: dict) -> None:
        """Answer what claude asks its host: whether a tool may be used,
        which is the user's to say. Anything else is not for a chat, and
        said to be asked."""
        request = message.get("request")
        asked = message.get("request_id")
        if not isinstance(request, dict) or request.get("subtype") != "can_use_tool":
            what = (
                flat(request.get("subtype", "?")) if isinstance(request, dict) else "?"
            )
            self._page.say(
                [
                    labelled(
                        "chat", f"claude asked for {what}, which a chat cannot answer"
                    )
                ]
            )
            self._agent.refuse(asked, "not supported by claude-airlock --line-mode")
            return
        # The call it asks about first, the question comes under it
        self._followed.settle(ASK_SETTLE)
        self._asked.put(asked, request)


def ready_line(colour: bool, running: int = 0) -> str:
    """What is said once a turn is over, for the eye to find where claude
    stopped and the prompt is the user's again: bright green in colour.
    With tasks of claude's that still run, it says so: the turn is over
    and the work is not, claude takes up again when one of them ends."""
    line = f"# {READY}"
    if running:
        tasks = "1 task still runs" if running == 1 else f"{running} tasks still run"
        said = f"claude has paused, {tasks}, it goes on when one ends"
        line = f"# {labelled('ready', said)}"
    return painted(READY_STYLE, line) if colour else line


def chat(
    host: Host,
    sandbox: Sandbox,
    docker_args: list[str],
    handover: Handover | None = None,
    start: Event | None = None,
) -> int:
    """Talk to the session a docker command runs, given its arguments, in
    the sandbox it was started with. Returns how docker ended. What the
    user asked to be done after it is left in handover. With start, how
    the sandbox was started is said first, as a trace shows it."""
    # What is said is dimmed in a trace, where it was read before. Not here.
    styles = {**STYLES, Kind.REPLY: "", Kind.COMMAND: ""}
    layout = dataclasses.replace(
        Layout.for_output(os.environ),
        styles=styles,
        heads={Kind.REPLY: REPLY_HEAD_STYLE},
        labels={"why": REASON_STYLE},
    )
    # The lines typed, kept for the next chat of the project
    kept = private_dir(os.path.join(host.state_dir, "line-mode-history"))
    history = os.path.join(kept, project_slug(host.project_dir))
    sent = SENT_STYLE if layout.colour else ""
    console = Console(host.project_dir, history, sent)

    def connect(on_end: Callable[[], None]) -> Agent:
        return Agent(docker_args, on_end)

    return Chat(host, sandbox, layout, connect, console, handover, start).run()
