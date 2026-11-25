"""What a chat does itself with a line the user types, any other line
being for claude: the things of Claude Code's screen that are here in
their own way.

/mode changes the permission mode, which claude is asked for over the
pipe. /resume goes on with an earlier session of the project, which is
another launch (see Handover). /mcp lists the MCP servers claude said it
has. !COMMAND runs a command in the sandbox (see shell.py). /login and
/logout say where that is done, claude does neither over the pipe.

Each is one line of LOCALS: what completes at the prompt and what /help
says are made of that."""

from __future__ import annotations

import enum
from collections.abc import Callable
from dataclasses import dataclass

from ..errors import Fatal
from ..events import flat, labelled
from ..report.entries import session_files, sessions_named
from ..report.trace import session_rows
from ..settings import Host
from .console import Page
from .said import Session, is_number, is_session_id
from .turn import Turns

LEAVE = ("/exit", "/quit")
MODE = "/mode"
# Claude Code's own two are not there in its print mode, these say the
# status of the chat
STATUS = ("/status", "/statusline")
# Claude Code's own two are not there in its print mode either, and
# these cannot stand in for them: a login is a page to open and a code to
# type back. The launcher carries the host's login to the session, see
# sandbox/login.py
LOGIN = ("/login", "/logout")
NATIVE_UI = "CLAUDE_AIRLOCK_LINE_MODE=0 claude-airlock"
# What a line starts with that is a command for the sandbox, not a word of
# its own: the command follows it
SHELL = "!"
# How wide /help has what is typed, before what it does
TYPED_WIDTH = 15
# How many of the project's sessions /resume lists
RESUME_LISTED = 15


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


class Resume:
    """/resume: leaves this session for an earlier one of the project."""

    def __init__(
        self,
        page: Page,
        host: Host,
        turns: Turns,
        read: Callable[[str], str | None],
        handover: Handover | None,
    ):
        self._page = page
        self._host = host
        self._turns = turns
        # Reads a line from the user, see Chat
        self._read = read
        self._handover = handover

    def resume(self, names: list[str]) -> bool:
        """Leave this session for the one whose id starts as said, or one
        picked from the latest. Whether one is to be resumed."""
        if self._handover is None:
            self._page.note("chat", "nothing here to resume a session with")
            return False
        if self._turns.running:
            self._page.note("chat", "not while a turn runs")
            return False
        try:
            files = session_files(self._host)
        except Fatal:
            self._page.note("chat", "no session of this project to resume")
            return False
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
        rows = session_rows(files[:RESUME_LISTED])
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


class Commands:
    """Does what a line asks of the chat itself, see LOCALS. What is not
    its own to do it is given: request asks claude for something of its
    own doing and has the answer told (see Agent.request), shell runs a
    command in the sandbox, resume leaves for an earlier session and says
    whether it does, status says the status."""

    def __init__(
        self,
        page: Page,
        session: Session,
        request: Callable[..., object],
        shell: Callable[[str], None],
        resume: Callable[[list[str]], bool],
        status: Callable[[], None] = lambda: None,
    ):
        self._page = page
        self._session = session
        self._request = request
        self._shell = shell
        self._resume = resume
        self._status = status

    def do(self, text: str) -> Did:
        """Do what a line asks of the chat itself."""
        if text.startswith(SHELL):
            name, words = SHELL, [text[len(SHELL) :].strip()]
        else:
            name, *words = text.split()
        local = BY_NAME.get(name)
        return local.do(self, words) if local else Did.NOTHING

    def _shelled(self, words: list[str]) -> Did:
        """!COMMAND: all that follows the mark is the command."""
        self._shell(words[0])
        return Did.DONE

    def _left(self, _words: list[str]) -> Did:
        return Did.LEFT

    def _said_status(self, _words: list[str]) -> Did:
        self._status()
        return Did.DONE

    def _login(self, _words: list[str]) -> Did:
        """/login and /logout: where to do it, which is not here."""
        self._page.say(
            [
                labelled(
                    "chat", "line mode cannot log in or out, do it one of two ways:"
                ),
                "  with claude on the host, the sessions are given its login",
                f"  in a session with Claude Code's own UI: {NATIVE_UI}",
            ]
        )
        return Did.DONE

    def _help(self, _words: list[str]) -> Did:
        self._page.say(HELP)
        return Did.DONE

    def _resumed(self, names: list[str]) -> Did:
        return Did.LEFT if self._resume(names) else Did.DONE

    def _mcp(self, _words: list[str]) -> Did:
        """/mcp: the MCP servers claude said the session has, which it
        says at the start of a turn."""
        servers = self._session.servers
        if not servers:
            known = "none" if self._session.id else "not known before the first turn"
            self._page.note("chat", f"the MCP servers of the session: {known}")
            return Did.DONE
        self._page.say(
            [labelled("chat", "the MCP servers of the session:")]
            + [f"  {name}  {status}" for name, status in servers]
        )
        return Did.DONE

    def _mode(self, names: list[str]) -> Did:
        """/mode: ask claude for the permission mode of that name, which
        is its own to know, or say which one it is in. What claude answers
        is said when it comes, see _mode_answered."""
        if len(names) != 1:
            now = f"mode {self._session.mode}, " if self._session.mode else ""
            self._page.note("chat", f"{now}{MODE} NAME changes it, plan for one")
            return Did.DONE
        self._request("set_permission_mode", self._mode_answered, mode=names[0])
        return Did.DONE

    def _mode_answered(self, response: dict) -> None:
        """Take in what claude answers to a request for a mode: whether
        it changed."""
        if response.get("subtype") != "success":
            reason = flat(response.get("error", "claude refused"))
            self._page.note("chat", f"mode not changed: {reason}")
            return
        told = response.get("response")
        mode = told.get("mode") if isinstance(told, dict) else None
        self._session.mode = flat(mode or self._session.mode)
        self._page.note("chat", f"mode {self._session.mode}")


@dataclass(frozen=True)
class Local:
    """Something a chat does itself with a line: what the line starts
    with for it, how /help says it is typed and what it does, nothing for
    what /help leaves out, and what does it, given the words after."""

    names: tuple[str, ...]
    typed: str
    about: str
    do: Callable[[Commands, list[str]], Did]


# In the order /help says them
LOCALS = (
    Local(
        (MODE,),
        f"{MODE} [NAME]",
        "the permission mode, or change it (default, acceptEdits, plan)",
        Commands._mode,
    ),
    Local(
        ("/resume",),
        "/resume [ID]",
        "leave this session for an earlier one of the project",
        Commands._resumed,
    ),
    Local(("/mcp",), "/mcp", "the MCP servers of the session", Commands._mcp),
    Local(
        STATUS,
        "/status",
        "the model, context, limits, cost and sandbox, or /statusline",
        Commands._said_status,
    ),
    Local(
        (SHELL,),
        "!COMMAND",
        "run a command in the sandbox, claude is not told",
        Commands._shelled,
    ),
    Local(
        LOGIN,
        "/login",
        "where to log in or out, which line mode cannot do",
        Commands._login,
    ),
    Local(LEAVE, "/exit, /quit", "leave, as Ctrl-D does", Commands._left),
    Local(("/help",), "", "", Commands._help),
)
BY_NAME = {name: local for local in LOCALS for name in local.names}
# The words a line can start with that the chat does itself
LOCAL = tuple(name for name in BY_NAME if name != SHELL)
HELP = [
    labelled("chat", "what the chat does itself, any other line is for claude:"),
    *(
        f"  {local.typed:<{TYPED_WIDTH}}{local.about}"
        for local in LOCALS
        if local.typed
    ),
    labelled("chat", "claude's own commands that answer in text work as typed:"),
    "  /model [NAME], /context, /usage, /compact, /clear, and skills",
    labelled(
        "chat", "a line can be typed while a turn runs, claude takes it up when it can"
    ),
    "  a line that ends with a backslash takes the next one too, as Alt+Enter",
    "  does, and Shift+Enter in a terminal set to tell it from Enter",
    "  Tab completes commands and @files, Ctrl-C interrupts the turn that",
    "  runs and a second one stops the session, at the prompt it drops the line",
    "  and a second one leaves, at a question it refuses what is asked too",
]
