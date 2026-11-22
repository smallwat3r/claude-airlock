"""How a tool call ended, as its result in the transcript says: whether it
failed, who decided that it may run, the files a command changed, and the
signs that what it put out was written to instruct the session.

A result is the session's to write: nothing of it is trusted, see
events.py."""

from __future__ import annotations

import os
import re
from dataclasses import dataclass

from ..events import clean, flat
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


def outside(path: str, project_dir: str) -> bool:
    absolute = os.path.normpath(os.path.join(project_dir, path))
    return absolute != project_dir and not absolute.startswith(project_dir + os.sep)


def outside_flag(path: str, project_dir: str) -> str:
    """What follows the name of a written file that is not in the project."""
    return OUTSIDE_FLAG if outside(path, project_dir) else ""


@dataclass(frozen=True)
class Decision:
    """Who let a call run or refused it, when that was not the permission
    mode of the session letting it run."""

    allowed: bool
    # In the words of Claude Code, see decided
    by: str

    def fields(self) -> dict:
        """The decision as the values of the result it is of."""
        values: dict = {
            "permission": "accept" if self.allowed else "reject",
            "permission_by": self.by,
        }
        return values if self.allowed else {**values, "refused": True}


def decided(entry: dict) -> Decision | None:
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
    decision = decided(entry)
    return decision is not None and not decision.allowed


def hunk_lines(hunk: dict) -> list[str]:
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
    it did not."""
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
            outside=outside(path, project_dir),
            diff=tuple(line for hunk in hunks for line in hunk_lines(hunk)),
        )
    for path in every(noted.get("changedFiles")):
        if isinstance(path, str) and path not in changed:
            changed[path] = ChangedFile(
                path, created=False, outside=outside(path, project_dir)
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
        or was not let run, a change outside the project, and what it put
        out showing signs of being written to instruct the session."""
        return bool(self.failed or self.refused or self.outside_project or self.planted)

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


def result_planted(tool: str, output: str, source: str = "") -> tuple[Planted, ...]:
    """The signs in what a tool call gave the session to read, each with
    the source the call named, see said_source. None for a tool whose
    result is no such thing, see NOT_READ."""
    return () if tool in NOT_READ else planted(output, source)


def outcome(
    call: dict,
    entry: dict,
    block: dict,
    project_dir: str,
    tool: str,
    source: str = "",
) -> Outcome:
    """How a tool call ended, from the entry it is in, the entry of its
    result, the result itself and the name of the tool: whether it
    failed, how long it took, its output, who decided that it may run
    when that was not the mode of the session, and what Claude Code noted
    of a command besides its output: that it was interrupted, what its
    exit code means, where its output was kept, and the files it changed.
    And the signs that the output was written to instruct the session,
    with the source the call read when it named one, see planted.py."""
    output = block_text(block.get("content"))
    started, finished = local_time(call), local_time(entry)
    said = entry.get("toolUseResult")
    noted = said if isinstance(said, dict) else {}
    meaning = noted.get("returnCodeInterpretation")
    kept = noted.get("persistedOutputPath")
    output_kept = kept if isinstance(kept, str) else ""
    held = counted(noted.get("persistedOutputSize")) if output_kept else None
    return Outcome(
        failed=bool(block.get("is_error")),
        output=output,
        seconds=(
            round((finished - started).total_seconds(), 3)
            if started and finished
            else None
        ),
        decision=decided(entry),
        interrupted=noted.get("interrupted") is True,
        exit_meaning=meaning if isinstance(meaning, str) else "",
        output_kept=output_kept,
        output_size=held,
        changed=tuple(files_changed(entry, project_dir)),
        planted=result_planted(tool, output, source),
    )
