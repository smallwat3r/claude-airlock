"""What claude says over the pipe, read with care: it is the session's to
write, as its transcript is. What is taken from it is checked for being
what it should be, a number, a name, the id of a session, and so is what
the user types where a number is asked for."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path

from ..events import flat
from ..projects import transcript_dirs
from ..report.entries import content_blocks
from ..settings import Host
from .drift import Drift

# Of a list claude gives (its commands, its MCP servers), what is kept
MOST_LISTED = 1000
# No more of a name the session gives of itself is kept than this, its
# model, its mode, its version: they are shown above the prompt
NAME_KEPT = 100
_COMMAND = re.compile(r"[\w:.-]{1,100}")
_SESSION_ID = re.compile(r"[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}")
# What /model says of the model it chose, by the name Claude Code shows
_CHOSEN = re.compile(r"(?:Set model to|Kept model as) `([^`\n]{1,100})`")


def is_number(typed: str) -> bool:
    """Whether what was typed is a number as int reads one: isdigit also
    takes digits of other scripts and a superscript, which int refuses."""
    return typed.isascii() and typed.isdigit()


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


def _command_names(given: object) -> list[str]:
    """The commands claude says it has, as they are typed: only what is
    a name."""
    names = given if isinstance(given, list) else []
    return [
        "/" + name.lstrip("/")
        for name in names[:MOST_LISTED]
        if isinstance(name, str) and _COMMAND.fullmatch(name.lstrip("/"))
    ]


def _servers_of(given: object) -> list[tuple[str, str]]:
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
    # How hard the model is asked to think, as Claude Code names it
    # (high), empty for a model that is not told and until claude said
    effort: str = ""
    # Whether the replies are made in fast mode
    fast: bool = False
    # Of Claude Code
    version: str = ""
    servers: list[tuple[str, str]] = field(default_factory=list)
    commands: list[str] = field(default_factory=list)
    # Told what claude does not say of the session any more, see heard
    drift: Drift = field(default_factory=Drift, repr=False, compare=False)

    def heard(self, message: dict) -> bool:
        """Take in something claude says of the session. Whether it is
        the start of a turn, which says all of it: what is not there then
        is missed."""
        starts = message.get("subtype") == "init"
        read = self.drift.field
        # Said in between too, when it changes
        mode = (
            read(message, "permissionMode", str)
            if starts
            else message.get("permissionMode")
        )
        self.mode = flat(mode or self.mode)[:NAME_KEPT]
        self.first_mode = self.first_mode or self.mode
        if not starts:
            return False
        session = read(message, "session_id", str)
        self.id = session if session and is_session_id(session) else ""
        self.model = flat(read(message, "model", str) or self.model)[:NAME_KEPT]
        self.chosen = ""
        version = read(message, "claude_code_version", str) or self.version
        self.version = flat(version)[:NAME_KEPT]
        self.commands = _command_names(read(message, "slash_commands", list))
        self.servers = _servers_of(read(message, "mcp_servers", list))
        # Not said by every version, and not missed
        self.fast = message.get("fast_mode_state") == "on"
        return True

    def settled(self, applied: dict) -> None:
        """Take in the settings claude says it goes by, as it answers
        when asked for them (get_settings): the effort, which the start
        of a turn does not say. None for a model that is not told one."""
        effort = applied.get("effort")
        self.effort = flat(effort)[:NAME_KEPT] if isinstance(effort, str) else ""

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
            self.model = flat(model)[:NAME_KEPT]
            self.chosen = ""
