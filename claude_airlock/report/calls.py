"""The tool calls of a transcript as they are shown: the lines that
describe a call (a command, a file and what an Edit changes in it, the
arguments of any other tool) and those that say how it ended.

How a call ended is read by outcomes.py, the here-documents of a command
by heredocs.py. Like the rest of a transcript, a call and its result are
the session's to write: nothing of them is trusted, see events.py."""

from __future__ import annotations

import difflib
from collections.abc import Iterator

from ..events import Event, Who, Wrong, clean, flat
from ..sandbox.plugins import plugin_server, skill_plugin
from .brief import clip, clip_ends, shortened
from .entries import (
    MOST_LISTED,
    call_input,
    tool_calls,
)
from .heredocs import without_heredocs
from .outcomes import (
    FILE_TOOLS,
    OUTSIDE_FLAG,
    ChangedFile,
    Outcome,
    files_changed,
    outside,
    outside_flag,
)
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
# What tells the plugin a call is of, each value of the event with what
# its line starts with
PLUGIN_SAID = {"plugin": "plugin", "plugin_server": "plugin server"}


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
    result_details, and whether that tells of something gone wrong."""
    for line, alert in result_details(ended, verbose):
        event.say(line, alert)
    if ended is not None and ended.wrong:
        event.went_wrong()


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
    wrong = Wrong.PART if alerts else Wrong.NO
    return Event(when, who, name.lower(), details, fields, alerts=alerts, wrong=wrong)


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
