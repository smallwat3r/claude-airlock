"""The tool calls of a transcript as they are shown: the lines that
describe a call (a command, a file and what an Edit changes in it, the
arguments of any other tool), how it ended, who decided that it may run,
and the files a command changed.

Like the rest of a transcript, a call and its result are the session's to
write: nothing of them is trusted, see events.py."""

from __future__ import annotations

import bisect
import difflib
import os
import re
from collections.abc import Iterator
from dataclasses import dataclass

from ..events import Event, Who, clean, flat
from ..sandbox.plugins import plugin_server, skill_plugin
from .brief import PREVIEW_WIDTH, clip, clip_ends, shortened
from .entries import (
    MOST_LISTED,
    block_text,
    call_input,
    counted,
    every,
    local_time,
    tool_calls,
)
from .planted import Planted, flagged, planted
from .shown import size

# The lines of each side of an Edit that are compared, with --verbose and
# without: only the start of a diff is shown then
DIFFED_LINES = 5000
DIFFED_LINES_BRIEF = 500
# Of the output of a call, how many lines of its start and of its end are
# shown: when it failed, and with --verbose. The end comes first in worth, it
# is where a command says what went wrong. All of it is in --json.
FAILED_OUTPUT = (2, 6)
VERBOSE_OUTPUT = (10, 10)
# What starts a here-document in a command: << or <<-, then the word that
# ends it, quoted or not. Not <<<, which is a here-string.
_HEREDOC = re.compile(r"(?<!<)<<(?!<)(-?)\s*(['\"]?)(\w+)\2")
# What a shell reads as it is, a << in it starts nothing: between quotes
# of either kind, and in the arithmetic of (( ))
_SINGLE, _DOUBLE = "'", '"'
_ARITHMETIC, _ARITHMETIC_END = "((", "))"
# What a comment follows, at the start of a line or after one of these
_BEFORE_COMMENT = " \t;&|("
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
# What tells the plugin a call is of, each value of the event with what
# its line starts with
PLUGIN_SAID = {"plugin": "plugin", "plugin_server": "plugin server"}
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


def heredoc_starts(line: str, within: str) -> tuple[list[tuple[str, str]], str]:
    """The here-documents a line of a command starts, each as whether
    its end can be indented (<<-) and the word that ends it, and what the
    line ends within: a quote, the arithmetic of (( )), or nothing. Not
    what is written within one of those or in a comment, where a shell
    starts none: taken for one, the lines after it that the shell runs
    would be left out as what it holds. Read as a shell does only so
    far: what is in doubt starts none, and is shown."""
    starts: list[tuple[str, str]] = []
    at = 0
    while at < len(line):
        char = line[at]
        if within == _SINGLE:
            if char == _SINGLE:
                within = ""
        elif within == _DOUBLE:
            if char == "\\":
                # What follows it is not the end of the quote
                at += 1
            elif char == _DOUBLE:
                within = ""
        elif within == _ARITHMETIC:
            if line.startswith(_ARITHMETIC_END, at):
                within = ""
                at += 1
        elif char == "\\":
            at += 1
        elif char in (_SINGLE, _DOUBLE):
            within = char
        elif line.startswith(_ARITHMETIC, at):
            within = _ARITHMETIC
            at += 1
        elif char == "#" and (at == 0 or line[at - 1] in _BEFORE_COMMENT):
            break
        else:
            found = _HEREDOC.match(line, at)
            if found:
                starts.append((found[1], found[3]))
                at = found.end() - 1
        at += 1
    return starts, within


def without_heredocs(lines: list[str]) -> list[str]:
    """The lines of a command without what its here-documents hold, each
    said to be so many lines instead: a script fed to an interpreter is
    as a rule most of the command, and the line that starts it tells what
    it is given to. One whose end is not found is left as it is, and so
    is what only reads as one, see heredoc_starts."""
    # Where each line is, as it is and without the tabs <<- lets the word
    # that ends a here-document be indented with: a command is the
    # session's to write, its end is not looked for a line at a time
    plain: dict[str, list[int]] = {}
    tabbed: dict[str, list[int]] = {}
    for at, line in enumerate(lines):
        plain.setdefault(line, []).append(at)
        tabbed.setdefault(line.lstrip("\t"), []).append(at)
    shown: list[str] = []
    index = 0
    # What the lines shown so far end within, see heredoc_starts
    within = ""
    while index < len(lines):
        shown.append(lines[index])
        starts, within = heredoc_starts(lines[index], within)
        index += 1
        for dash, word in starts:
            found = (tabbed if dash else plain).get(word, [])
            later = bisect.bisect_left(found, index)
            if later < len(found):
                body = found[later] - index
                held = "1 line" if body == 1 else f"{body} lines"
                shown.append(f"... here-document of {held}, see --verbose")
                index = found[later] + 1
    return shown


def file_path(tool_input: dict) -> str | None:
    """The file a tool call is about, for the tools that name one."""
    path = tool_input.get("file_path") or tool_input.get("notebook_path")
    return path if isinstance(path, str) else None


def bash_details(
    tool_input: dict, cwd: object, project_dir: str, verbose: bool
) -> list[str]:
    """A command: what ran, why (the reason Claude gave for it) and where,
    when that is not the project directory."""
    lines = clean(tool_input.get("command", "")).splitlines() or [""]
    command = clip(lines if verbose else without_heredocs(lines), verbose)
    details = ["$ " + command[0], *("$   " + line for line in command[1:])]
    if tool_input.get("description"):
        details.append("why: " + flat(tool_input["description"]))
    if isinstance(cwd, str) and cwd != project_dir:
        details.append("cwd: " + flat(cwd))
    return details


def edit_diff(tool_input: dict, verbose: bool = True) -> list[str]:
    """What an Edit call changes, as the lines of a unified diff. Of the
    first DIFFED_LINES of each side, fewer when only the start of the diff
    is shown: comparing takes the square of the lines, which are the
    session's to write, and a line says so when there were more."""
    most = DIFFED_LINES if verbose else DIFFED_LINES_BRIEF
    sides = [
        clean(tool_input.get(side, "")).splitlines()
        for side in ("old_string", "new_string")
    ]
    old, new = (side[:most] for side in sides)
    # Without the --- and +++ lines, the file is named with the call
    diff = list(difflib.unified_diff(old, new, lineterm="", n=1))[2:]
    longest = max(map(len, sides))
    if longest > most:
        hint = "" if verbose else ", more of it with --verbose"
        diff.append(f"... only the first {most} of {longest} lines compared{hint}")
    return diff


def file_details(
    name: str, path: str, tool_input: dict, project_dir: str, verbose: bool
) -> list[str]:
    """A call on a file: which one, flagged when it is written outside the
    project, and what an Edit changes or a Write puts there."""
    about = "file: " + flat(path)
    changes: list[str] = []
    if name == "Edit":
        diff = edit_diff(tool_input, verbose)
        changes = ["diff: " + line for line in clip(diff, verbose)]
    elif name == "Write":
        content = clean(tool_input.get("content", "")).splitlines()
        about += f" ({len(content)} lines)"
        changes = ["content: " + line for line in clip(content, verbose)]
    if name in FILE_TOOLS:
        about += outside_flag(path, project_dir)
    return [about, *changes]


def todo_details(todos: list, verbose: bool) -> list[str]:
    """The list of what claude set out to do, as how far it is: how many
    are done and the one it is at. Each of them with --verbose."""
    listed = [todo for todo in todos if isinstance(todo, dict)]
    done = sum(todo.get("status") == "completed" for todo in listed)
    line = f"todos: {done}/{len(listed)} done"
    for todo in listed:
        if todo.get("status") == "in_progress":
            line += ", now: " + flat(todo.get("activeForm") or todo.get("content", ""))
            break
    if not verbose:
        return [line]
    marks = {"completed": "[x]", "in_progress": "[>]"}
    return [line] + [
        f"  {marks.get(str(todo.get('status')), '[ ]')} {flat(todo.get('content', ''))}"
        for todo in listed
    ]


def question_details(questions: list) -> list[str]:
    """What claude asks the user, a line for each question: its options
    are put with it where it is answered, and are in --json."""
    return [
        f"question: {flat(question.get('question', ''))}"
        for question in questions
        if isinstance(question, dict)
    ]


def call_details(
    name: str, tool_input: dict, cwd: object, project_dir: str, verbose: bool
) -> list[str]:
    """The lines that describe a tool call."""
    path = file_path(tool_input)
    if name == "Bash":
        return bash_details(tool_input, cwd, project_dir, verbose)
    if name == "TodoWrite" and isinstance(tool_input.get("todos"), list):
        return todo_details(tool_input["todos"], verbose)
    if path is not None:
        return file_details(name, path, tool_input, project_dir, verbose)
    if name == "AskUserQuestion" and isinstance(tool_input.get("questions"), list):
        return question_details(tool_input["questions"])
    # Any other tool: its arguments as they are
    return [
        line
        for key, value in tool_input.items()
        for line in clip(argument_lines(flat(key), clean(value)), verbose)
    ]


def argument_lines(key: str, value: str) -> list[str]:
    """An argument of a call as its lines, each under its name: a line
    of a value is the model's to write, and one that stood alone could
    read as a line of the report (a result, a file outside the project)."""
    first, *more = value.splitlines() or [""]
    return [f"{key}: {first}", *(f"{key}:   {line}" for line in more)]


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


def changed_details(
    changed: tuple[ChangedFile, ...], verbose: bool
) -> list[tuple[str, bool]]:
    """The lines for the files a command changed, each with whether it
    tells of a write outside the project: every file with how many lines
    it gained and lost, flagged when it is outside. The diff itself is in
    --json. Without --verbose the first of many, and how many more there
    are, flagged when one of those is outside."""
    shown = changed if verbose else changed[:MOST_LISTED]
    lines = []
    for file in shown:
        added = sum(line.startswith("+") for line in file.diff)
        removed = sum(line.startswith("-") for line in file.diff)
        how = "created, " if file.created else ""
        sizes = (
            f" ({how}+{added} -{removed})" if file.diff else " (created)" if how else ""
        )
        flag = OUTSIDE_FLAG if file.outside else ""
        lines.append((f"changed: {flat(file.path)}{sizes}{flag}", file.outside))
    more = changed[len(shown) :]
    if more:
        beyond = any(file.outside for file in more)
        flag = OUTSIDE_FLAG if beyond else ""
        said = f"changed: ... {len(more)} more files, see --verbose{flag}"
        lines.append((said, beyond))
    return lines


def result_details(ended: Outcome | None, verbose: bool) -> list[tuple[str, bool]]:
    """The lines for how a tool call ended and how much it put out, each
    with whether it tells of what went wrong: how a call ended that
    failed or was refused, a file changed outside the project, and each
    sign that what it put out was written to instruct the session. None
    for a call that no result was recorded of. Of the output itself the
    start and the end, when the call failed or with --verbose: never all
    of it, a command can put out thousands of lines."""
    if ended is None:
        return [("result: none recorded (interrupted or still running)", False)]
    notes = ["FAILED" if ended.failed else "ok"]
    if ended.seconds is not None:
        notes.append(f"{ended.seconds:.1f}s")
    if ended.decision:
        verdict = "REFUSED" if ended.refused else "allowed"
        notes.append(f"{verdict} by {ended.decision.by}")
    if ended.interrupted:
        notes.append("INTERRUPTED")
    if ended.exit_meaning:
        notes.append(shortened(flat(ended.exit_meaning)))
    output = clean(ended.output).splitlines()
    if output:
        notes.append(f"{len(output)} line{'s' if len(output) > 1 else ''} out")
    shown: list[str] = []
    if verbose:
        shown = clip_ends(output, *VERBOSE_OUTPUT, "see --json")
    elif ended.failed:
        ends = clip_ends(output, *FAILED_OUTPUT, "see --verbose")
        shown = [shortened(line) for line in ends]
    badly = ended.failed or ended.refused
    lines = [
        ("result: " + ", ".join(notes), badly),
        *(("out: " + line, badly) for line in shown),
        *((sign.shown, True) for sign in ended.planted),
    ]
    if ended.output_kept:
        # Too long to give the model whole: it was given the start, and
        # where the rest is
        kept, held = flat(ended.output_kept), ended.output_size
        said = f"output kept: {kept}" + (f" ({size(held)})" if held else "")
        lines.append((said, False))
    return lines + changed_details(ended.changed, verbose)


def tell_result(event: Event, ended: Outcome | None, verbose: bool) -> None:
    """Add to an event the lines for how a tool call ended, see
    result_details."""
    for line, alert in result_details(ended, verbose):
        event.say(line, alert)


def call_event(
    when: float, who: Who, entry: dict, block: dict, project_dir: str, verbose: bool
) -> Event:
    """A tool call as it was issued, how it ended is added by the walk
    that finds its result."""
    # On one line: it is what the event is, and stays in its column
    name = flat(block.get("name", "?"))
    tool_input = call_input(block)
    details = call_details(name, tool_input, entry.get("cwd"), project_dir, verbose)
    # A call without arguments is a call all the same, and has its line
    details = details or ["(no arguments)"]
    fields = {
        "tool": name,
        "id": str(block.get("id")),
        "input": tool_input,
        "cwd": entry.get("cwd"),
    }
    alerts: set[int] = set()
    path = file_path(tool_input)
    if name in FILE_TOOLS and path is not None:
        fields["outside_project"] = outside(path, project_dir)
        if fields["outside_project"]:
            # The line that names the file, see file_details
            alerts.add(0)
    # After the arguments, a call is named by the first of its lines
    for key, plugin in plugin_called(name, tool_input).items():
        fields[key] = plugin
        details.append(f"{PLUGIN_SAID[key]}: {plugin}")
    return Event(when, who, name.lower(), details, fields, alerts=alerts)


def plugin_called(name: str, tool_input: dict) -> dict[str, str]:
    """The plugin a tool call is of, by what tells it: the plugin of the
    skill it runs, or the server of a plugin whose tool it is. Empty for
    a call that is of none. As the session named them, like the call."""
    said = {
        "plugin": skill_plugin(name, tool_input),
        "plugin_server": plugin_server(name),
    }
    return {key: flat(plugin) for key, plugin in said.items() if plugin}


def call_label(event: Event) -> str:
    """What a call is named by next to something else, its result that
    comes later or a connection made while it ran: its command, or the
    tool and what it was called on."""
    first = event.details[0] if event.details else ""
    if event.fields.get("tool") != "Bash":
        _, found, value = first.partition(": ")
        first = f"{event.what} {value if found else first}".rstrip()
    return f"[{event.number}] {first}" if event.number is not None else first


def written_paths(entries: list[dict]) -> Iterator[str]:
    """The path of each file the session wrote, once for every call that
    did: with a tool of its, or by a command that Claude Code saw change
    the file, see files_changed."""
    for _, block in tool_calls(entries):
        if block.get("name") in FILE_TOOLS:
            path = file_path(call_input(block))
            if path is not None:
                yield path
    for entry in entries:
        if entry.get("type") == "user":
            for file in files_changed(entry, ""):
                yield file.path
