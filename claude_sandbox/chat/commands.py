"""What a chat does itself with a line the user types, any other line
being for claude: the things of Claude Code's screen that are here in
their own way.

/mode changes the permission mode, which claude is asked for over the
pipe. /resume goes on with an earlier session of the project, which is
another launch (see Handover). /mcp lists the MCP servers claude said it
has. !COMMAND runs a command in the sandbox."""

from __future__ import annotations

import enum
import subprocess
from collections.abc import Callable
from dataclasses import dataclass

from ..docker import docker_popen, exec_args
from ..events import clean, flat, labelled
from ..settings import Host
from ..trace import session_rows
from ..transcript import session_files, sessions_named
from .asking import is_number
from .console import Page
from .pipe import Agent, Session, is_session_id
from .turn import Turns

LEAVE = ("/exit", "/quit")
MODE = "/mode"
# Claude Code's own two are not there in its print mode, these say the
# status of the chat
STATUS = ("/status", "/statusline")
# What a line can start with that the chat does itself
LOCAL = (MODE, "/help", "/mcp", "/resume", *STATUS, *LEAVE)
HELP = [
    labelled("chat", "what the chat does itself, any other line is for claude:"),
    "  /mode [NAME]   the permission mode, or change it (default, acceptEdits, plan)",
    "  /resume [ID]   leave this session for an earlier one of the project",
    "  /mcp           the MCP servers of the session",
    "  /status        the model, context, limits, cost and sandbox, or /statusline",
    "  !COMMAND       run a command in the sandbox, claude is not told",
    "  /exit, /quit   leave, as Ctrl-D does",
    labelled("chat", "claude's own commands that answer in text work as typed:"),
    "  /model [NAME], /context, /usage, /compact, /clear, and skills",
    labelled(
        "chat", "a line can be typed while a turn runs, claude takes it up when it can"
    ),
    "  a line that ends with a backslash takes the next one too, as Alt+Enter",
    "  does, and Shift+Enter in a terminal set to tell it from Enter",
    "  Tab completes commands and @files, Ctrl-C interrupts the turn that",
    "  runs and a second one stops the session, at the prompt it drops the line",
]
# How many of the project's sessions /resume lists
RESUME_LISTED = 15
# Of a line a command of the user's writes, what is shown as one line
SHELL_WIDTH = 4096


@dataclass
class Handover:
    """What a chat leaves for the launcher to do once its session is over
    and checked: the session to go on with, when the user asked for one
    (/resume). A session is a container, another one is another launch."""

    session: str = ""


class Did(enum.Enum):
    """What came of a line the user typed."""

    # Not the chat's to do: for claude
    NOTHING = enum.auto()
    DONE = enum.auto()
    # Done, and the chat is to be left for it
    LEFT = enum.auto()


class Commands:
    def __init__(
        self,
        page: Page,
        host: Host,
        name: str,
        session: Session,
        turns: Turns,
        read: Callable[[str], str | None],
        handover: Handover | None,
        status: Callable[[], None] = lambda: None,
    ):
        self._page = page
        self._host = host
        # Of the session's container
        self._name = name
        self._session = session
        self._turns = turns
        # Reads a line from the user, see Chat
        self._read = read
        self._handover = handover
        # Says the status, see StatusLine
        self._status = status
        # The request to change the mode that has no answer yet
        self.mode_request = ""
        # Whether a command of the user's runs (!COMMAND): Ctrl-C is then
        # for it, which docker ends on it, and not for claude's turn
        self.shelling = False

    def do(self, agent: Agent, text: str) -> Did:
        """Do what a line asks of the chat itself."""
        words = text.split()
        if text.startswith("!"):
            self._shell(text[1:].strip())
        elif words[0] in LEAVE:
            return Did.LEFT
        elif words[0] == MODE:
            self._mode(agent, words[1:])
        elif words[0] in STATUS:
            self._status()
        elif words[0] == "/help":
            self._page.say(HELP)
        elif words[0] == "/mcp":
            self._mcp()
        elif words[0] == "/resume":
            return Did.LEFT if self._resume(words[1:]) else Did.DONE
        else:
            return Did.NOTHING
        return Did.DONE

    def _mcp(self) -> None:
        """/mcp: the MCP servers claude said the session has, which it
        says at the start of a turn."""
        servers = self._session.servers
        if not servers:
            known = "none" if self._session.id else "not known before the first turn"
            self._page.note("chat", f"the MCP servers of the session: {known}")
            return
        self._page.say(
            [labelled("chat", "the MCP servers of the session:")]
            + [f"  {name}  {status}" for name, status in servers]
        )

    def _shell(self, command: str) -> None:
        """!COMMAND: run a command in the session's container. Claude is
        not told of it and the transcript does not have it, the record of
        what ran does. What it writes is the session's word as anything
        else from there: shown a line at a time, cleaned. Ctrl-C is for
        the command while it runs, see shelling."""
        if not command:
            return
        self._page.note("shell", f"$ {flat(command)}  (claude is not told)")
        self.shelling = True
        try:
            process = docker_popen(
                *exec_args(self._name, command),
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
            )
            with process:
                out = process.stdout
                while out and (line := out.readline(SHELL_WIDTH)):
                    text = line.decode("utf-8", "replace").rstrip("\r\n")
                    self._page.put([clean(text)])
        except OSError:
            self._page.note("shell", "docker could not be run")
            return
        finally:
            self.shelling = False
        if process.returncode:
            self._page.note("shell", f"ended with {process.returncode}")

    def _mode(self, agent: Agent, names: list[str]) -> None:
        """/mode: ask claude for the permission mode of that name, which
        is its own to know, or say which one it is in. What claude answers
        is said when it comes, see answered."""
        if len(names) != 1:
            now = f"mode {self._session.mode}, " if self._session.mode else ""
            self._page.note("chat", f"{now}{MODE} NAME changes it, plan for one")
            return
        self.mode_request = agent.request("set_permission_mode", mode=names[0])

    def answered(self, message: dict) -> None:
        """Take in what claude answers to a request of the chat's: whether
        the mode changed. An interrupt shows in how its turn ends."""
        response = message.get("response")
        if not isinstance(response, dict) or not self.mode_request:
            return
        if response.get("request_id") != self.mode_request:
            return
        self.mode_request = ""
        if response.get("subtype") != "success":
            reason = flat(response.get("error", "claude refused"))
            self._page.note("chat", f"mode not changed: {reason}")
            return
        told = response.get("response")
        mode = told.get("mode") if isinstance(told, dict) else None
        self._session.mode = flat(mode or self._session.mode)
        self._page.note("chat", f"mode {self._session.mode}")

    def _resume(self, names: list[str]) -> bool:
        """/resume: leave this session for an earlier one of the project,
        the one whose id starts as said or one picked from the latest.
        Whether one is to be resumed."""
        if self._handover is None:
            self._page.note("chat", "nothing here to resume a session with")
            return False
        if self._turns.running:
            self._page.note("chat", "not while a turn runs")
            return False
        files = session_files(self._host)
        if names:
            found = sessions_named(files, names[0])
            if len(found) != 1:
                line = labelled(
                    "chat", f"{flat(names[0])} is not one session, none resumed"
                )
                self._page.say([line])
                return False
            session = found[0].stem
        else:
            session = self._picked(files)
        if not is_session_id(session):
            return False
        self._handover.session = session
        self._page.note("chat", f"resuming {session}, once this session is over")
        return True

    def _picked(self, files: list) -> str:
        """Ask which of the project's latest sessions, by a number. Its
        id, empty for none."""
        rows = session_rows(files)[:RESUME_LISTED]
        self._page.say(
            [labelled("chat", "the latest sessions of this project:")]
            + [f"  {number}. {line}" for number, (_, line) in enumerate(rows, 1)]
        )
        try:
            typed = self._read("resume which, by its number (none: Enter): ")
        except KeyboardInterrupt:
            return ""
        number = (typed or "").strip()
        if not is_number(number) or not 1 <= int(number) <= len(rows):
            return ""
        return rows[int(number) - 1][0].stem
