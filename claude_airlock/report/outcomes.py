"""How a tool call ended, as its result in the transcript says: whether it
failed, who decided that it may run, the files a command changed, and the
signs that what it put out was written to instruct the session.

A result is the session's to write: nothing of it is trusted, see
events.py."""

from __future__ import annotations

import os
import re
from collections.abc import Sequence
from dataclasses import dataclass
from datetime import datetime

from ..events import clean, flat
from ..files import is_within
from ..recording.procwatch import Secrets
from ..settings import CONTAINER_HOME
from .brief import PREVIEW_WIDTH
from .entries import (
    block_text,
    counted,
    every,
    local_time,
)
from .planted import Planted, flagged, planted

# The tools that write a file
FILE_TOOLS = ("Edit", "Write", "NotebookEdit")
# The tools of Claude Code's own that read or write a file by its path,
# in its own process: the record of processes has their use as Claude
# Code's, when it sees it at all. Those that search a directory too.
OWN_FILE_TOOLS = frozenset(
    {"Read", "Edit", "Write", "MultiEdit", "NotebookEdit", "Grep", "Glob"}
)
SEARCH_TOOLS = frozenset({"Grep", "Glob"})
# The arguments they are given a file or a directory by
PATH_KEYS = ("file_path", "notebook_path", "path")
# What follows a call on a file of secrets, with the kind of its secrets
SECRETS_FLAG = "SECRETS FILE"
# A name in a directory that no file of one is passed over by (a public
# key, the hosts ssh knows), and no name hidden from a session is: a
# directory is one of secrets when it would be one there, see secrets_of
_IN_A_DIRECTORY = "\0"
# What follows a call that acted outside the sandbox, through Anthropic,
# with what it acted on
OUTSIDE_SANDBOX_FLAG = "OUTSIDE SANDBOX"
# The tool that sends a message to another session, and how its result
# says a session it reached is not one of the sandbox: a session of
# claude.ai, or one reached over Remote Control
SEND_MESSAGE = "SendMessage"
SENT_OUTSIDE = ("a Claude session running in the cloud", "over Remote Control")
SENT_SAID = "a Claude session that is not in the sandbox"
# The blocks of a result of a call that ran on Anthropic's side, in the
# reply of the model next to its call, see server_output
SERVER_RESULTS = frozenset(
    {
        "web_search_tool_result",
        "web_fetch_tool_result",
        "code_execution_tool_result",
        "bash_code_execution_tool_result",
        "text_editor_code_execution_tool_result",
        "tool_search_tool_result",
        "mcp_tool_result",
        "advisor_tool_result",
    }
)
# Of such a result, the values that hold what it gave the model to read,
# and those that hold more of it: a page fetched is the data of the
# source of the content of the content of its result. No deeper than so
# many levels, nothing Claude Code writes goes further.
_SERVER_TEXTS = ("title", "url", "text", "stdout", "stderr", "data", "error_code")
_SERVER_HOLDS = ("content", "source")
SERVER_DEPTH = 8
# The tools whose result is not something read from elsewhere, and is not
# looked at for text written to instruct the session (see planted.py):
# what the session or the user wrote, and what a subagent said. What that
# read is looked at in its own transcript, and Claude Code adds words of
# its own to its result that read as a sign.
NOT_READ = frozenset(
    {*FILE_TOOLS, "TodoWrite", "AskUserQuestion", "ExitPlanMode", "Agent", "Task"}
)
# What a call names what it reads by, when it reads one thing: the same
# file read from another line on is the same source
SOURCE_KEYS = ("file_path", "notebook_path", "url")
# An address a command names, up to what ends a word of a shell. A
# command is the session's to write and can be of any length: one class
# of characters, a pass over it
_ADDRESS = re.compile(r"https?://[^\s'\"`<>|;&()\\]+", re.IGNORECASE)
# What a sentence ends an address with, and is no part of it
_ADDRESS_END = ".,:"
# Where a hunk of a diff is, as Claude Code names it: from which line and
# how many, of the file before and after
HUNK_SPANS = ("oldStart", "oldLines", "newStart", "newLines")
# What follows the name of a written file that is not in the project
OUTSIDE_FLAG = "  OUTSIDE PROJECT"
# What Claude Code trims from around a path it is given, as JavaScript's
# trim does: the blanks and line breaks, and the mark of byte order
_AROUND = re.compile(r"^[\s\ufeff]+|[\s\ufeff]+$")


def as_written_to(path: str) -> str:
    """A path a tool of Claude Code was given as Claude Code takes it:
    without the blanks around it, and a leading ~ as the home of the
    session's container, where the file then is. Written as " /etc/x" or
    "~/.bashrc", it is not in the project, whatever it reads as."""
    path = _AROUND.sub("", path)
    if path == "~" or path.startswith("~/"):
        return CONTAINER_HOME + path[1:]
    return path


def working_dir(value: object) -> str | None:
    """The directory the session was in, as an entry names it (its cwd),
    none for what is no absolute path: a path that is not absolute is
    from there, see outside."""
    return value if isinstance(value, str) and os.path.isabs(value) else None


def entry_cwd(entry: dict) -> str | None:
    """The directory the session was in at an entry, see working_dir."""
    return working_dir(entry.get("cwd"))


def taken_path(path: str, project_dir: str, cwd: str | None) -> str:
    """The absolute path a tool of Claude Code's was given, as Claude
    Code takes it (see as_written_to), one that is not absolute from the
    directory the session was in then (cwd, see working_dir): it can be
    one next to the project, and is the project when none is known."""
    return os.path.normpath(os.path.join(cwd or project_dir, as_written_to(path)))


def outside(path: str, project_dir: str, cwd: str | None) -> bool:
    """Whether a path a session wrote to is outside its project, by the
    path as it is written, see taken_path. Not by where the links on it
    lead: the trace is made later and on the host, where a link of the
    project may lead somewhere else than it did for the session, or be
    gone, so a write through one to a place outside is not told as
    that."""
    return not is_within(taken_path(path, project_dir, cwd), project_dir)


def outside_flag(path: str, project_dir: str, cwd: str | None) -> str:
    """What follows the name of a written file that is not in the
    project, see outside."""
    return OUTSIDE_FLAG if outside(path, project_dir, cwd) else ""


def secrets_of(
    path: str, secrets: Secrets, project_dir: str, cwd: str | None, searched: bool
) -> str | None:
    """The kind of secrets a path a tool of Claude Code's was given names,
    none for one that holds none: by the path as Claude Code takes it,
    see taken_path. The secrets are those of the session, see
    session_secrets of secrets.py. Of a search, a directory every file of
    which holds secrets too (~/.ssh): it reads them."""
    absolute = taken_path(path, project_dir, cwd)
    kind = secrets.of(absolute)
    if kind is None and searched:
        kind = secrets.of(os.path.join(absolute, _IN_A_DIRECTORY))
    return kind


def sent_outside(tool: str, output: str) -> str:
    """What a call reached outside the sandbox by its result, empty when
    the result says nothing of it: SendMessage that reached a session of
    claude.ai, or one over Remote Control. Through Anthropic, of which the
    capture sees a connection and no more."""
    if tool == SEND_MESSAGE and any(said in output for said in SENT_OUTSIDE):
        return SENT_SAID
    return ""


def server_output(block: dict) -> tuple[str, bool]:
    """What the result of a call that ran on Anthropic's side gave the
    model to read, and whether it failed: the texts its content holds, a
    page, the titles and addresses of a search, what code wrote out, and
    an error. Failed when it says so, is an error, or when the code it
    ran ended with another code than 0. Its content is the session's to
    write, and is gone through no deeper than SERVER_DEPTH."""
    texts: list[str] = []
    failed = block.get("is_error") is True
    held: list[tuple[object, int]] = [(block.get("content"), 0)]
    while held:
        value, depth = held.pop()
        if isinstance(value, str):
            texts.append(value)
            continue
        if depth >= SERVER_DEPTH:
            continue
        if isinstance(value, list):
            held += [(item, depth + 1) for item in reversed(value)]
            continue
        if not isinstance(value, dict):
            continue
        kind, code = value.get("type"), value.get("return_code")
        if isinstance(kind, str) and kind.endswith("_error") or "error_code" in value:
            failed = True
        if type(code) is int and code != 0:
            failed = True
        texts += [
            text for key in _SERVER_TEXTS if isinstance(text := value.get(key), str)
        ]
        held += [
            (value[key], depth + 1) for key in reversed(_SERVER_HOLDS) if key in value
        ]
    return "\n".join(text for text in texts if text), failed


@dataclass(frozen=True)
class Decision:
    """Who let a call run or refused it, when that was not the permission
    mode of the session letting it run."""

    allowed: bool
    # In the words of Claude Code, see _decided
    by: str

    def fields(self) -> dict:
        """The decision as the values of the result it is of."""
        values: dict = {
            "permission": "accept" if self.allowed else "reject",
            "permission_by": self.by,
        }
        return values if self.allowed else {**values, "refused": True}


def _decided(entry: dict) -> Decision | None:
    """Who let a call run or refused it, as the entry of its result says,
    none when the permission mode of the session let it run: that is
    most calls, and the mode is told where it is set. The words for who
    are Claude Code's, which says where a decision is from (the settings
    or the user), of the settings what kind (the mode, a rule), and of the
    user for how long (once)."""
    decision = entry.get("permissionDecision")
    if not isinstance(decision, dict):
        return None
    source = decision.get("source")
    source = source if isinstance(source, str) else "?"
    allowed = decision.get("decision") == "accept"
    kind = decision.get("reasonType")
    if source == "config":
        if allowed and kind == "mode":
            return None
        kinds = {"mode": "the permission mode", "rule": "a rule"}
        by = kinds.get(str(kind), "the settings")
    elif source.startswith("user"):
        by = "you"
        scope = decision.get("grantScope")
        if allowed and isinstance(scope, str) and scope:
            by += ", " + flat(scope)[:PREVIEW_WIDTH]
    else:
        by = flat(source).replace("_", " ")[:PREVIEW_WIDTH]
    return Decision(allowed, by)


def refused(entry: dict) -> bool:
    """Whether the entry of a result says its call was not let run."""
    decision = _decided(entry)
    return decision is not None and not decision.allowed


def _hunk_lines(hunk: dict) -> list[str]:
    """A hunk of a diff as its lines, under the line that says where."""
    spans = [counted(hunk.get(key)) for key in HUNK_SPANS]
    given = hunk.get("lines")
    if None in spans or not isinstance(given, list):
        return []
    lines = [clean(line) for line in given if isinstance(line, str)]
    return ["@@ -{},{} +{},{} @@".format(*spans), *lines]


@dataclass(frozen=True)
class ChangedFile:
    """A file a command changed, as Claude Code noted with its result."""

    path: str
    # Whether the command made it
    created: bool
    # Whether it is outside the project
    outside: bool
    # What changed, as the lines of a diff: none for a file that Claude
    # Code only names
    diff: tuple[str, ...] = ()

    def fields(self) -> dict:
        """The file as one of the values of the result it is of."""
        return {
            "path": self.path,
            "created": self.created,
            "outside": self.outside,
            "diff": list(self.diff),
        }


def files_changed(entry: dict, project_dir: str) -> list[ChangedFile]:
    """The files a command changed, as Claude Code noted with its result.
    All of them, one past what is shown may be the one outside the
    project. This is what Claude Code noticed, a command can write what
    it did not. A path that is not absolute is from where the command
    ran, see outside."""
    cwd = entry_cwd(entry)
    result = entry.get("toolUseResult")
    noted = result.get("bashEditDiff") if isinstance(result, dict) else None
    if not isinstance(noted, dict):
        return []
    changed: dict[str, ChangedFile] = {}
    for file in every(noted.get("files")):
        path = file.get("filePath") if isinstance(file, dict) else None
        if not isinstance(path, str):
            continue
        hunks = [hunk for hunk in every(file.get("hunks")) if isinstance(hunk, dict)]
        changed[path] = ChangedFile(
            path,
            created=bool(file.get("created")),
            outside=outside(path, project_dir, cwd),
            diff=tuple(line for hunk in hunks for line in _hunk_lines(hunk)),
        )
    for path in every(noted.get("changedFiles")):
        if isinstance(path, str) and path not in changed:
            changed[path] = ChangedFile(
                path, created=False, outside=outside(path, project_dir, cwd)
            )
    return list(changed.values())


@dataclass(frozen=True)
class Outcome:
    """How a tool call ended: whether it failed, its output, and what
    Claude Code noted of it besides."""

    failed: bool
    output: str
    # How long it took, none when the call or its result does not say when
    seconds: float | None = None
    # Who decided that it may run, none for the mode of the session
    decision: Decision | None = None
    interrupted: bool = False
    # What its exit code means when that is not a failure (grep that
    # found nothing), empty when Claude Code says nothing of it
    exit_meaning: str = ""
    # Where its output was kept when that was too long to give the model,
    # and how long it was
    output_kept: str = ""
    output_size: int | None = None
    # The files a command changed
    changed: tuple[ChangedFile, ...] = ()
    # The signs that its output was written to instruct the session
    planted: tuple[Planted, ...] = ()
    # What it reached outside the sandbox, through Anthropic, as its
    # output says, see sent_outside. Empty when it says nothing of it.
    outside_sandbox: str = ""

    @property
    def refused(self) -> bool:
        return self.decision is not None and not self.decision.allowed

    @property
    def outside_project(self) -> bool:
        """Whether what ran changed a file outside the project."""
        return any(file.outside for file in self.changed)

    @property
    def wrong(self) -> bool:
        """Whether it tells of something gone wrong: a call that failed
        or was not let run, a change outside the project, what it put
        out showing signs of being written to instruct the session, and
        what it reached outside the sandbox."""
        return bool(
            self.failed
            or self.refused
            or self.outside_project
            or self.planted
            or self.outside_sandbox
        )

    def fields(self) -> dict:
        """The outcome as the values of its event, each there when there
        is something to say."""
        fields: dict = {"failed": self.failed, "output": self.output}
        if self.seconds is not None:
            fields["seconds"] = self.seconds
        if self.decision:
            fields.update(self.decision.fields())
        if self.interrupted:
            fields["interrupted"] = True
        if self.exit_meaning:
            fields["exit_meaning"] = self.exit_meaning
        if self.output_kept:
            fields["output_kept"] = self.output_kept
            fields["output_size"] = self.output_size
        if self.changed:
            fields["changed"] = [file.fields() for file in self.changed]
            fields["outside_project"] = self.outside_project
        if self.outside_sandbox:
            fields["outside_sandbox"] = self.outside_sandbox
        return {**fields, **flagged(self.planted)}


def read_source(tool_input: object) -> str:
    """The file or the page a call reads, as the call names it, empty
    for a call that names none: a command, a search, a tool of a
    server."""
    given = tool_input if isinstance(tool_input, dict) else {}
    named = (given.get(key) for key in SOURCE_KEYS)
    return next((name for name in named if isinstance(name, str) and name), "")


def _command_addresses(tool_input: object) -> tuple[str, ...]:
    """The addresses the command of a call names, each once and in the
    order they are written, none for a call that is no command."""
    given = tool_input if isinstance(tool_input, dict) else {}
    command = given.get("command")
    if not isinstance(command, str):
        return ()
    found = (address.rstrip(_ADDRESS_END) for address in _ADDRESS.findall(command))
    return tuple(dict.fromkeys(filter(None, found)))


def said_source(tool_input: object) -> str:
    """Where what a call read is said to be from: the file or the page
    it names (see read_source), else the addresses its command names.
    Those are what the command was written with, not what it was seen to
    fetch, and what it read can be of something else it ran. Empty when
    it names none."""
    return read_source(tool_input) or ", ".join(_command_addresses(tool_input))


def is_read(tool: str) -> bool:
    """Whether the result of a tool is something read from elsewhere,
    to be looked at for signs, see NOT_READ."""
    return tool not in NOT_READ


def result_planted(tool: str, output: str, source: str = "") -> tuple[Planted, ...]:
    """The signs in what a tool call gave the session to read, each with
    the source the call named, see said_source. None for a tool whose
    result is no such thing, see is_read."""
    return planted(output, source) if is_read(tool) else ()


def outcome(
    started: datetime | None,
    entry: dict,
    block: dict,
    tool: str,
    source: str,
    changed: Sequence[ChangedFile],
) -> Outcome:
    """How a tool call ended, from when it was issued, the entry of its
    result, the result itself and the name of the tool: whether it
    failed, how long it took, its output, who decided that it may run
    when that was not the mode of the session, and what Claude Code noted
    of a command besides its output: that it was interrupted, what its
    exit code means, where its output was kept, and the files it changed.
    And the signs that the output was written to instruct the session,
    with the source the call read when it named one, see planted.py. A
    result of a call that ran on Anthropic's side is read as it is
    written, see server_output.

    The files changed are those the walk read of the entry, see
    files_changed: Claude Code notes them once for the entry, which holds
    one result, and an entry the session wrote with many is not read
    again for each."""
    if block.get("type") in SERVER_RESULTS:
        output, failed = server_output(block)
    else:
        output, failed = block_text(block.get("content")), bool(block.get("is_error"))
    finished = local_time(entry)
    said = entry.get("toolUseResult")
    noted = said if isinstance(said, dict) else {}
    meaning = noted.get("returnCodeInterpretation")
    kept = noted.get("persistedOutputPath")
    output_kept = kept if isinstance(kept, str) else ""
    held = counted(noted.get("persistedOutputSize")) if output_kept else None
    return Outcome(
        failed=failed,
        output=output,
        seconds=(
            round((finished - started).total_seconds(), 3)
            if started and finished
            else None
        ),
        decision=_decided(entry),
        interrupted=noted.get("interrupted") is True,
        exit_meaning=meaning if isinstance(meaning, str) else "",
        output_kept=output_kept,
        output_size=held,
        changed=tuple(changed),
        planted=result_planted(tool, output, source),
        outside_sandbox=sent_outside(tool, output),
    )
