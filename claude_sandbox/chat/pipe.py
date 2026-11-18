"""Claude Code at the other end of a pipe: the process a chat talks to,
what it is told, and what it says read with care.

Claude Code runs in its print mode and speaks JSON Lines over its standard
input and output, the protocol of the Agent SDK. A line each way is one
object: a prompt, a request (to interrupt, to change the mode) or the
answer to one of its own going in, what it does and asks coming out.

What comes out is the session's to write, as its transcript is. It is
bounded as it is read, and what is taken from it is checked for being
what it should be: a number, a name, the id of a session."""

from __future__ import annotations

import contextlib
import itertools
import json
import queue
import re
import subprocess
import sys
import threading
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

from ..docker import NOT_FOUND, docker_popen
from ..events import clean, flat
from ..files import json_object
from ..projects import transcript_dirs
from ..settings import Fatal, Host
from ..transcript import content_blocks

# What claude is run with: print mode, JSON Lines both ways, its questions
# about permissions asked over the same pipe, and a reply told as it is made
CHAT_ARGS = (
    "--print",
    "--verbose",
    "--input-format=stream-json",
    "--output-format=stream-json",
    "--permission-prompt-tool=stdio",
    "--include-partial-messages",
)
# A line longer than this is dropped, and no more than so many wait to be
# taken in
LINE_LIMIT = 64 << 20
BACKLOG = 1000
# Of a line claude writes that is no object, what is shown
PLAIN_WIDTH = 2000
# More than a session could use: a count or a cost above it is not one
MOST = 1e12
# Of a list claude gives (its commands, its MCP servers), what is kept
MOST_LISTED = 1000
_COMMAND = re.compile(r"[\w:.-]{1,100}")
_SESSION_ID = re.compile(r"[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}")
# What /model says of the model it chose, by the name Claude Code shows
_CHOSEN = re.compile(r"(?:Set model to|Kept model as) `([^`\n]{1,100})`")


class Agent:
    """Claude Code in its container, spoken to over the pipes of the
    docker command that runs it."""

    def __init__(self, docker_args: list[str], on_end: Callable[[], None]):
        try:
            # A session of its own: Ctrl-C at the terminal is for the chat
            # to pass on as an interrupt, not for docker to end claude with
            self._process = docker_popen(
                *docker_args,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                # Read and cleaned as the rest is, see _read_errors
                stderr=subprocess.PIPE,
                start_new_session=True,
            )
        except FileNotFoundError:
            raise Fatal(NOT_FOUND) from None
        self._on_end = on_end
        self._speaking = threading.Lock()
        self._requests = itertools.count(1)
        # What claude said, each an object, or the text of a line that is
        # none, then None when it has ended
        self.messages: queue.Queue[dict | str | None] = queue.Queue(BACKLOG)
        self.ended = threading.Event()
        self._reader = threading.Thread(target=self._read, daemon=True)
        self._errors = threading.Thread(target=self._read_errors, daemon=True)
        self._errors.start()
        self._reader.start()

    def _read(self) -> None:
        out = self._process.stdout
        dropping = False
        try:
            while out:
                line = out.readline(LINE_LIMIT)
                if not line:
                    break
                complete = line.endswith(b"\n")
                if complete and not dropping:
                    # Not an object: claude run for something else than a
                    # conversation, which is then shown as it is written
                    plain = line[:PLAIN_WIDTH].decode("utf-8", "replace")
                    self.messages.put(json_object(line) or plain)
                # The rest of a line that was too long goes with its start
                dropping = not complete
        finally:
            # What it had to say for itself as it ended comes first
            self._errors.join(1.0)
            self.ended.set()
            self._on_end()
            self.messages.put(None)

    def _read_errors(self) -> None:
        """Pass on what the session writes to its errors, as lines that
        are no object: docker's own word when it cannot run the session,
        and whatever a process of the session writes there, which is not
        to reach the terminal as it is."""
        errors = self._process.stderr
        while errors:
            line = errors.readline(PLAIN_WIDTH)
            if not line:
                return
            text = line.decode("utf-8", "replace").rstrip("\n")
            if not text.strip():
                continue
            if not self.ended.is_set():
                with contextlib.suppress(queue.Full):
                    self.messages.put(text, timeout=1.0)
                    continue
            # Nobody listens any more, or not fast enough
            print(clean(text), file=sys.stderr)

    def send(self, message: dict) -> None:
        """Say something to claude, nothing to one that has ended."""
        pipe = self._process.stdin
        try:
            # Whole lines: more than one thread speaks
            with self._speaking:
                if pipe:
                    pipe.write(json.dumps(message).encode() + b"\n")
                    pipe.flush()
        except (OSError, ValueError):
            pass

    def prompt(self, text: str) -> None:
        """Give claude what the user asks."""
        content = [{"type": "text", "text": text}]
        message = {"role": "user", "content": content}
        self.send({"type": "user", "message": message})

    def request(self, subtype: str, **more: object) -> str:
        """Ask claude for something of its own doing. The id its answer
        will name."""
        asked = f"chat-{next(self._requests)}"
        request = {"subtype": subtype, **more}
        self.send({"type": "control_request", "request_id": asked, "request": request})
        return asked

    def respond(self, asked: object, decision: dict) -> None:
        """Answer what claude asked under an id."""
        response = {"request_id": asked, "subtype": "success", "response": decision}
        self.send({"type": "control_response", "response": response})

    def refuse(self, asked: object, why: str) -> None:
        """Say that what claude asked under an id is not answered."""
        response = {"request_id": asked, "subtype": "error", "error": why}
        self.send({"type": "control_response", "response": response})

    def close(self) -> None:
        """Say that no more prompts come, which is how claude is left."""
        with contextlib.suppress(OSError, ValueError):
            if self._process.stdin:
                self._process.stdin.close()

    def drain(self) -> bool:
        """Let go of what claude still says, for it not to wait on a full
        pipe. Whether it may say more."""
        with contextlib.suppress(queue.Empty):
            self.messages.get(timeout=0.1)
        return self._reader.is_alive()

    def status(self) -> int:
        return self._process.wait()

    def over_within(self, seconds: float) -> bool:
        """Whether the session has ended, once that long was waited."""
        try:
            self._process.wait(seconds)
        except subprocess.TimeoutExpired:
            return False
        return True


def amount(value: object) -> float | None:
    """A count or a cost claude gave, none for what is not one."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    # Not a number and the infinities are not within it either
    return float(value) if 0 <= value <= MOST else None


def is_session_id(value: object) -> bool:
    """Whether a value is the id of a session, and so safe as the name of
    its transcript."""
    return isinstance(value, str) and bool(_SESSION_ID.fullmatch(value))


def transcript_of(host: Host, session: object) -> Path | None:
    """The transcript of the session that has an id, there or not yet.
    None for what is not an id: it comes from the session."""
    if not is_session_id(session):
        return None
    places = [directory / f"{session}.jsonl" for directory in transcript_dirs(host)]
    for path in places:
        if path.is_file() and not path.is_symlink():
            return path
    # Where a sandboxed session writes it, see project_roots
    return places[-1]


def command_names(given: object) -> list[str]:
    """The commands claude says it has, as they are typed: only what is
    a name."""
    names = given if isinstance(given, list) else []
    return [
        "/" + name.lstrip("/")
        for name in names[:MOST_LISTED]
        if isinstance(name, str) and _COMMAND.fullmatch(name.lstrip("/"))
    ]


def servers_of(given: object) -> list[tuple[str, str]]:
    """The MCP servers claude lists, each with how it is."""
    servers = given if isinstance(given, list) else []
    return [
        (flat(server.get("name", "?")), flat(server.get("status", "?")))
        for server in servers[:MOST_LISTED]
        if isinstance(server, dict)
    ]


def own(message: dict) -> bool:
    """Whether a message is of claude itself, not of a subagent of its."""
    return not message.get("parent_tool_use_id")


@dataclass
class Session:
    """What claude says of the session at the start of each turn, as far
    as a chat goes by it."""

    # Its id once it is seen to be one, which /clear changes
    id: str = ""
    mode: str = ""
    # The mode it was first said to be in, the one it was started with
    first_mode: str = ""
    model: str = ""
    # The name of the model /model chose, until claude names it by its id
    chosen: str = ""
    # Of Claude Code
    version: str = ""
    servers: list[tuple[str, str]] = field(default_factory=list)
    commands: list[str] = field(default_factory=list)

    def heard(self, message: dict) -> bool:
        """Take in something claude says of the session. Whether it is
        the start of a turn."""
        self.mode = flat(message.get("permissionMode") or self.mode)
        self.first_mode = self.first_mode or self.mode
        if message.get("subtype") != "init":
            return False
        session = message.get("session_id")
        self.id = session if is_session_id(session) else ""  # type: ignore[assignment]
        self.model = flat(message.get("model") or self.model)
        self.chosen = ""
        self.version = flat(message.get("claude_code_version") or self.version)
        self.commands = command_names(message.get("slash_commands"))
        self.servers = servers_of(message.get("mcp_servers"))
        return True

    def replied(self, message: dict) -> None:
        """Take in a reply of claude's own: the model that wrote it is the
        session's. The start of a turn says the one it started with. What
        /model says names the one it chose, by its name alone, which stands
        for it until the next turn or reply names its id. Not the stand-in
        Claude Code names for what it wrote itself (<synthetic>)."""
        command = message.get("local_command_run")
        if isinstance(command, dict) and command.get("command") == "model":
            for block in content_blocks(message):
                said = _CHOSEN.search(str(block.get("text", "")))
                if said:
                    self.chosen = flat(said[1])
            return
        reply = message.get("message")
        model = reply.get("model") if isinstance(reply, dict) else None
        if isinstance(model, str) and model and not model.startswith("<"):
            self.model = flat(model)
            self.chosen = ""
