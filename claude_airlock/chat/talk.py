"""The conversation of a chat with one session: what the user types read
and sent, what the session does written.

Three threads. The one the chat is run by reads the lines the user types,
at any time, and does what each asks: a prompt typed while a turn runs is
taken up by claude when it can. The second listens to claude and looks at
what is followed, and writes. What claude asks the user is put by the
third, one question at a time, and answered through the first (see
asking.py): the second goes on listening meanwhile, a session whose
subagents work on is not held up by a question nobody has answered yet.

What each of them does is not here: what claude says is taken in by
listener.py, a turn is stopped for what claude was given to read by
guard.py, what the session did is written by followed.py, a turn that is
quiet is said to run by turn.py, how far the subagents of claude are is
said by tasks.py, a line that is the chat's own to do is done by
commands.py. The parts they share are made in parts.py. A command of the
user's has a thread more while it runs, which writes what it writes: the
first waits for it, and reads a line meanwhile only when the user is
asked something (see shell.py)."""

from __future__ import annotations

import dataclasses
import enum
import math
import os
import queue
import signal
import threading
import time
from collections.abc import Callable
from types import FrameType

from ..docker import docker_ok, project_slug
from ..events import Event, Kind, flat, labelled
from ..files import private_dir
from ..report.layout import (
    BOLD,
    BRIGHT_CYAN,
    BRIGHT_MAGENTA,
    ITALIC,
    STYLES,
    Layout,
    together,
)
from ..settings import Host
from .commands import LOCAL, Commands, Did, Handover, Resume, Taken
from .console import Console, Page
from .followed import ASK_SETTLE, POLL
from .guard import Brake, Guard
from .hosts import HostQuestions, Hosts
from .listener import Listener
from .parts import Parts
from .pipe import Agent, Answer, Unread
from .plain import PlainLines
from .screen import Prompt, as_prompt
from .shell import Shell
from .status import Sandbox
from .tasks import Progress
from .turn import Heartbeat

# What reaches claude for a chat, given what to tell once claude has ended
# and the page to write what it still writes to its errors after that
type Connect = Callable[[Callable[[], None], Page], Agent]

PROMPT = as_prompt("> ")
# After a line that ended with a backslash, which takes the next one too
MORE = as_prompt(". ")
# Where each side of the conversation starts, to be found among what the
# session does: the line over a reply of claude bold and bright cyan, a
# line the user sent bold and bright magenta
REPLY_HEAD_STYLE = together(BOLD, BRIGHT_CYAN)
SENT_STYLE = together(BOLD, BRIGHT_MAGENTA)
# Why claude says it makes a call, in italics under its bold label
REASON_STYLE = ITALIC
# Seconds within which a second Ctrl-C at the prompt leaves, as it does in
# Claude Code's own UI. One that comes later drops the line again.
LEAVE_WITHIN = 3.0
# Seconds a session is given to end before a line says how to stop it
LEAVE_QUIET = 2.0
# How long a session that was told to stop is waited for, docker gives it
# ten seconds before it ends it
STOP_WAIT = 15.0
# The messages in a row that may fail to be taken in before the chat
# gives up on showing what the session does
MOST_FAILED = 5
# Seconds the first prompt waits for claude to say which settings it goes
# by, where a prompt is written once and stays as it is: its status then
# names the model. Claude answers as soon as it runs, in about as long as
# its container takes to start
SETTLE_WAIT = 3.0
# Seconds the next prompt waits there for claude to answer what the chat
# asked of it (/mode), which it does at once
ANSWER_WAIT = 1.0
# Seconds lines that are all there, a file or a pipe, wait for claude to
# answer what one of them asked of it, see _wait_for_turn
ANSWER_PATIENCE = 10.0


class Life(enum.Enum):
    """How far a chat is, by who ended first: claude, which can end on
    its own, or the user, who can leave. One value, changed in one place
    (see Chat._becomes): which of the two came first is then not asked
    of one thing while another changes the other."""

    RUNNING = enum.auto()
    # Claude has ended and the user has not left yet
    ENDED = enum.auto()
    # The user has left and claude has not ended yet
    LEAVING = enum.auto()
    # The user left, and claude ended for it
    LEFT = enum.auto()
    # Claude ended, and the chat is now being left
    CLOSING = enum.auto()

    @property
    def over(self) -> bool:
        """Whether claude has ended."""
        return self in (Life.ENDED, Life.LEFT, Life.CLOSING)

    @property
    def leaving(self) -> bool:
        """Whether the chat is being left, by the user or after claude."""
        return self in (Life.LEAVING, Life.LEFT, Life.CLOSING)

    @property
    def left(self) -> bool:
        """Whether it was the user who left, and not claude that ended."""
        return self in (Life.LEAVING, Life.LEFT)

    def ended(self) -> Life:
        """What it is once claude has ended."""
        return {Life.RUNNING: Life.ENDED, Life.LEAVING: Life.LEFT}.get(self, self)

    def leave(self) -> Life:
        """What it is once the chat is being left."""
        return {Life.RUNNING: Life.LEAVING, Life.ENDED: Life.CLOSING}.get(self, self)


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
        guard: Guard | None = None,
        hosts: Hosts | None = None,
    ):
        self._host = host
        # How the sandbox was started as the launcher noted it, said first
        self._start = start
        # Of the session's container, to stop it by
        self._name = sandbox.name
        self._connect = connect
        # Claude, from when the chat is run
        self._agent: Agent
        self._handover = handover
        console = console or Console(host.project_dir)
        console.commands = sorted(LOCAL)
        page = Page(console, layout)
        self._parts = parts = Parts.made(host, sandbox, console, page, self._gone)
        # What a turn is stopped by for what claude was given to read,
        # none when the user switched that off
        self._brake = (
            Brake(guard, parts, self._interrupt_turn, self._send, self._gone)
            if guard
            else None
        )
        self._listener = Listener(parts, lambda: self._agent, self._brake)
        # What the session writes that is no message of claude's
        self._plain = PlainLines(page)
        # What the egress filter asks the user about, none when it does
        # not ask
        self._hosts = hosts and HostQuestions(
            hosts,
            page,
            parts.asker,
            parts.asked,
            console.interactive,
            lambda: parts.followed.settle(ASK_SETTLE),
        )
        self._heartbeat = Heartbeat(page, parts.turns, lambda: parts.asker.asking)
        self._progress = Progress(
            page,
            lambda: parts.tasks.running,
            lambda: parts.asker.asking or parts.replies.writing,
        )
        self._shell = Shell(page, sandbox.name, lambda: parts.asker.asking)
        resume = Resume(page, host, parts.turns, self._read_line, handover)
        self._commands = Commands(
            page,
            parts.session,
            self._request,
            self._shell.run,
            resume.resume,
            parts.status.show,
            parts.status.refresh,
        )
        # When claude was last asked for something a line of the user's
        # asks of it, see _request
        self._requested = -math.inf
        # Whether a line is waited for, and whether Ctrl-C came for a turn
        self._reading = False
        self._interrupt = False
        # Whether claude has ended, whether the user is leaving, and
        # which of the two came first, see Life. Read as it is, from the
        # handler of Ctrl-C too, and changed by _becomes alone.
        self._life = Life.RUNNING
        self._living = threading.Lock()

    def run(self) -> int:
        """Run the session and talk to it until the user leaves or it
        ends. Returns how docker ended."""
        previous = signal.signal(signal.SIGINT, self._on_interrupt)
        connected = False
        page = self._parts.page
        try:
            self._agent = self._connect(self._session_ended, page)
            connected = True
            title = labelled("chat", flat(self._host.project_dir))
            page.say([f"{title}, /help says what there is", page.layout.columns])
            if self._start:
                page.put(page.events([self._start]))
            listening = threading.Thread(target=self._listen, daemon=True)
            listening.start()
            self._parts.asked.start(self._agent)
            self._listener.ask_settings()
            if self._parts.console.interactive and not page.redrawn:
                # Where the first prompt stays as it is written, it
                # waits a moment for what claude goes by. At a terminal
                # its status is written again in its place when that
                # comes, and lines that are all there wait for nothing
                self._listener.settled.wait(SETTLE_WAIT)
            # What the session was started with heads the first prompt
            # too: that is when it matters most
            self._parts.status.refresh()
            self._converse()
            return self._leave(listening)
        except BaseException:
            # However the chat ends, the session ends with it: what the
            # launcher checks next is checked of a session that is over
            if connected:
                self._abandon()
            raise
        finally:
            signal.signal(signal.SIGINT, previous)
            self._parts.console.close()

    def _abandon(self) -> None:
        """End a session the chat can no longer talk to: no more prompts
        come, and one that does not take that for its end is stopped."""
        self._agent.close()
        if not self._agent.over_within(LEAVE_QUIET):
            docker_ok("stop", self._name)
            self._agent.over_within(STOP_WAIT)

    def _becomes(self, step: Callable[[Life], Life]) -> None:
        """Take a step of the chat's life: one at a time, the thread that
        reads claude says that it ended while the user leaves. Not called
        from the handler of Ctrl-C, which could come while this is held."""
        with self._living:
            self._life = step(self._life)

    def _gone(self) -> bool:
        """Whether there is nobody left to ask, or to ask for."""
        return self._life.leaving or self._life.over

    def _on_interrupt(self, _number: int, frame: FrameType | None) -> None:
        """Ctrl-C: for the turn that runs when one does, and for a session
        that is slow to leave. Else it ends the wait for a line, which
        drops what was typed, and leaves a question that waits without
        an answer (see _converse). Given the frame it came in, see
        Console.interrupt."""
        # Whether claude has ended while a line is read, as one can be
        # while a command runs: this is then how the end is told, and
        # for the line, see _session_ended
        told = self._life.over and self._reading
        if self._shell.running and not (self._life.leaving or told):
            # For the command the user runs
            self._shell.interrupt()
            return
        if self._life.leaving or (self._parts.turns.running and not self._life.over):
            # Acted on by the thread that listens, see _listen: what
            # claude asked is refused with it, which is not done from here
            self._interrupt = True
        elif self._reading:
            # Where the wait for the line can be ended, see there
            self._parts.console.interrupt(frame)

    def _session_ended(self) -> None:
        """Told by the thread that reads claude. A wait for a line would
        go on until the user ends it: it is ended as Ctrl-C would. One
        that has not started yet sees that claude is over, see _read."""
        self._becomes(Life.ended)
        self._parts.wake.set()
        self._listener.settled.set()
        if self._reading:
            os.kill(os.getpid(), signal.SIGINT)

    def _read(self, prompt: Prompt, headed: bool = False) -> str | None:
        """A line from the user, none when there are no more, with the
        status above its prompt when headed. As Ctrl-C when claude has
        ended, there is nobody left to read it. The answer to a question is
        not kept among the lines typed."""
        parts = self._parts
        self._reading = True
        try:
            # After _reading is set: an end that comes from here on is told
            # by _session_ended, one that came before is seen here
            if self._life.over:
                raise KeyboardInterrupt
            return parts.console.read(prompt, lambda: not parts.asker.asking, headed)
        except KeyboardInterrupt:
            parts.console.end_line()
            raise
        finally:
            self._reading = False
            parts.page.touched()

    def _read_line(self, prompt: Prompt, headed: bool = False) -> str | Taken | None:
        """A line from the user as _read has it, given first to the
        question that waits, if one does (see Asker.take): Taken for one
        it took, whatever the line was read for. Ctrl-C leaves that
        question without an answer too, which refuses what it asks."""
        try:
            line = self._read(prompt, headed)
        except KeyboardInterrupt:
            self._parts.asker.line_dropped()
            raise
        if line is not None and self._parts.asker.take(line):
            return Taken.ANSWER
        return line

    def _converse(self) -> None:
        """Read what the user types and do what it asks, until they leave
        or the session has ended."""
        lines: list[str] = []
        # When Ctrl-C last dropped the line, for the one that follows it
        dropped = -math.inf
        while not self._life.over:
            # A command of the user's that still runs is waited for, no
            # line is read meanwhile unless they are asked something
            self._shell.wait()
            self._wait_for_answer()
            if not self._parts.console.interactive:
                self._wait_for_turn()
                if self._brake and self._brake.stopped:
                    # Nobody is there to say how to go on, and the lines
                    # that are left were written before this was known
                    self._parts.page.note(
                        "chat", "the lines left are not sent, leaving"
                    )
                    return
            try:
                line = (
                    self._read_line(MORE)
                    if lines
                    else self._read_line(PROMPT, headed=True)
                )
            except KeyboardInterrupt:
                lines.clear()
                again = self._dropped_again(dropped)
                if again is None:
                    return
                dropped = again
                continue
            dropped = -math.inf
            if line is None:
                self._parts.console.end_line()
                return
            if line is Taken.ANSWER:
                continue
            text = _joined(lines, line)
            if not text:
                continue
            did = self._commands.do(text)
            if did is Did.LEFT:
                return
            if did is Did.NOTHING:
                self._send(text)

    def _dropped_again(self, dropped: float) -> float | None:
        """Ctrl-C at the prompt dropped what was typed, given when it last
        did: when it did now, for the one after it. None to leave, when
        the session is over, and as Ctrl-D does when it comes right after
        the one before, see LEAVE_WITHIN."""
        if self._life.over:
            return None
        now = time.monotonic()
        if now - dropped <= LEAVE_WITHIN:
            return None
        self._parts.page.note("chat", "Ctrl-C again leaves")
        return now

    def _wait_for_turn(self) -> None:
        """Wait until claude has nothing left to do, or asks something.
        For lines that are not typed but all there, a file or a pipe: each
        is for the turn after the one before it, and the answer to a
        question is the line after the prompt that led to it. What a line
        asked of claude (/mode) is waited for no longer than ANSWER_PATIENCE:
        a claude that does not answer it holds up no line after it."""
        parts = self._parts
        patience = self._requested + ANSWER_PATIENCE
        while (
            (
                parts.turns.running
                or (self._agent.pending and time.monotonic() < patience)
            )
            and not parts.asker.asking
            and not self._life.over
        ):
            parts.wake.wait(0.2)
            parts.wake.clear()

    def _request(
        self, subtype: str, on_answer: Answer | None = None, **more: object
    ) -> str:
        """Ask claude for something a line of the user's asks of it
        (/mode, see Commands), and note when: its answer is waited
        for, and the next prompt gives it a moment to come, see
        _wait_for_answer."""
        self._requested = time.monotonic()
        return self._agent.request(subtype, on_answer, True, **more)

    def _wait_for_answer(self) -> None:
        """Give claude a moment to answer what the chat just asked of
        it, where someone types and a prompt that was written stays as
        it is: the answer is then above the prompt, which has the
        status as it now is. Not at a terminal, where what comes later
        is written above the prompt, nor for lines that are all there,
        which wait for more than that, see _wait_for_turn. And once for
        what was asked: a claude that does not answer holds up no
        prompt after the first."""
        if self._parts.page.redrawn or not self._parts.console.interactive:
            return
        patience = self._requested + ANSWER_WAIT
        while (
            self._agent.pending and not self._life.over and time.monotonic() < patience
        ):
            time.sleep(0.02)

    def _send(self, text: str) -> None:
        """Give claude a prompt. While a turn runs claude takes it up
        when it can: within that turn between two of its steps, or as a
        turn of its own after it, which it then says it starts."""
        started = self._listener.begin()
        if self._brake:
            self._brake.stopped = False
        if self._agent.prompt(text) is False:
            unread = "not sent, the session does not read what it is told"
            self._parts.page.note("chat", f"{unread}: Ctrl-C stops it")
        elif not started:
            self._parts.page.note("chat", "sent, claude takes it up when it can")

    def _listen(self) -> None:
        """Take in what claude says and write what the session does,
        until claude has ended."""
        parts = self._parts
        # The messages in a row that could not be taken in
        stumbled = 0
        # When what the session did was last looked at
        looked = -math.inf
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
                if self._interrupt:
                    # Ahead of whatever was said: a session writes lines
                    # of its own as fast as it likes, and Ctrl-C is not
                    # to wait until it pauses
                    self._interrupt = False
                    # What claude asked is refused with it
                    parts.asker.give_up()
                    self._stop()
                try:
                    claudes = self._taken_in(message)
                    # After each message of claude's, and while the
                    # session writes lines of its own as often as while
                    # it says nothing: there is no end to those
                    if claudes or time.monotonic() - looked >= POLL:
                        self._look()
                        looked = time.monotonic()
                    stumbled = 0
                except Exception as error:
                    # One message that cannot be taken in is not the end
                    # of the session, what it holds is claude's to write
                    stumbled += 1
                    if stumbled >= MOST_FAILED:
                        raise
                    skipped = f"FAILED to show a message: {flat(repr(error))[:200]}"
                    parts.page.say([labelled("chat", skipped)])
            parts.replies.turn_over()
            parts.followed.show(now=True)
            self._plain.say_left_out(now=True)
            if not self._life.left:
                parts.page.note("chat", "the session ended")
        except Exception as error:  # noqa: BLE001
            # Whatever it is, the user is told and can leave: a chat that
            # no longer writes would pass for a session that does nothing
            failed = labelled(
                "chat", f"FAILED, nothing more is shown: {flat(repr(error))}"
            )
            parts.page.say([failed])
        finally:
            self._session_ended()
            parts.asked.close()

    def _taken_in(self, message: dict | str | Unread) -> bool:
        """Take in what came over the pipe. Whether it was a message of
        claude's, the empty one that stands for nothing said too: not a
        line that is none, which is the session's word all the same
        (see Agent), nor what stands for a line that could not be
        read."""
        if isinstance(message, dict):
            self._listener.heard(message)
            return True
        if isinstance(message, Unread):
            self._plain.unread()
        else:
            self._plain.heard(message)
        return False

    def _look(self) -> None:
        """Look at what the session did besides saying it: write what
        is followed, have the user asked about the hosts that wait, and
        say that a turn that is quiet still runs. The status first,
        made again as it is by now, and with it how far the subagents
        of claude are, which it counts: what claude said since may have
        changed them, and so may the time, at which a limit starts
        again, and how wide the terminal is. What is written next then
        has them under it as they are."""
        self._parts.status.refresh()
        self._progress.show()
        self._parts.followed.show()
        if self._hosts:
            self._hosts.look()
        self._heartbeat.beat()
        self._plain.say_left_out()

    def _interrupt_turn(self) -> bool:
        """Ask claude to end the turn that runs. Whether it was asked:
        not without a turn, and not twice for one."""
        turns = self._parts.turns
        turn = turns.current
        if not turns.running or turn.interrupted:
            return False
        turn.interrupted = True
        self._agent.request("interrupt")
        return True

    def _stop(self) -> None:
        """Ctrl-C: claude is asked to end the turn that runs, and the
        second time the session is stopped. So is one that is slow to
        leave."""
        page = self._parts.page
        if not self._life.leaving and self._interrupt_turn():
            page.note("chat", "interrupting, Ctrl-C again stops the session")
        elif self._life.leaving or self._parts.turns.running:
            page.note("chat", "stopping the session")
            docker_ok("stop", self._name)

    def _leave(self, listening: threading.Thread) -> int:
        """End the session, which leaves when it is told no more prompts
        come. Ctrl-C stops one that does not, see _stop."""
        self._becomes(Life.leave)
        self._parts.asker.give_up()
        # What claude asked is answered before it is told to leave, a
        # refusal that came too late would not be read
        self._parts.asked.answered_within(LEAVE_QUIET)
        self._agent.close()
        told = False
        started = time.monotonic()
        while True:
            if listening.is_alive():
                listening.join(0.1)
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
                self._parts.page.say([waiting])
        self._say_how_to_go_on()
        return self._agent.status()

    def _say_how_to_go_on(self) -> None:
        """Say how the session that was left is gone on with, unless
        another one is about to be."""
        resumed = self._handover is not None and self._handover.session
        session = self._parts.session.id
        if session and self._life.left and not resumed:
            again = f"claude-airlock --line-mode --resume {session}"
            self._parts.page.note("chat", f"to go on with this session: {again}")


def _joined(lines: list[str], line: str) -> str | None:
    """What a line that was entered says, with the lines before it that
    ended with a backslash, which takes the next one too: none while it
    does, the line kept in lines until one does not, which takes them."""
    if line.endswith("\\"):
        lines.append(line[:-1])
        return None
    text = "\n".join([*lines, line]).strip()
    lines.clear()
    return text


def chat(
    host: Host,
    sandbox: Sandbox,
    docker_args: list[str],
    handover: Handover | None = None,
    start: Event | None = None,
    guarded: bool = False,
    hosts: Hosts | None = None,
    on_started: Callable[[], None] = lambda: None,
) -> int:
    """Talk to the session a docker command runs, given its arguments, in
    the sandbox it was started with. Returns how docker ended. What the
    user asked to be done after it is left in handover. With start, how
    the sandbox was started is said first, as a trace shows it. Guarded,
    a turn is stopped for what claude was given to read, see guard.py.
    With hosts, the user is asked about those the egress filter does not
    allow, see hosts.py. on_started is told once docker was started."""
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

    def connect(on_end: Callable[[], None], page: Page) -> Agent:
        agent = Agent(docker_args, on_end, late=page)
        on_started()
        return agent

    guard = Guard() if guarded else None
    return Chat(
        host, sandbox, layout, connect, console, handover, start, guard, hosts
    ).run()
