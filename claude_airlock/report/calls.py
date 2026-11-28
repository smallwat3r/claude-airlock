"""The tool calls of a transcript as they are shown: the lines that
describe a call (a command, a file and what an Edit changes in it, the
arguments of any other tool) and those that say how it ended.

How a call ended is read by outcomes.py, the here-documents of a command
by heredocs.py. Like the rest of a transcript, a call and its result are
the session's to write: nothing of them is trusted, see events.py."""

from __future__ import annotations

import difflib
from collections.abc import Collection, Iterator
from dataclasses import dataclass

from ..events import Event, Who, Wrong, clean, flat, holds_unseen
from ..recording.procwatch import Secrets
from ..recording.secrets import said
from ..sandbox.plugins import plugin_server, skill_plugin
from .brief import clip, lines_out, output_shown, shortened
from .entries import (
    MOST_LISTED,
    block_text,
    call_input,
    content_blocks,
    every_result,
    kept,
    tool_calls,
)
from .heredocs import without_heredocs
from .outcomes import (
    FILE_TOOLS,
    OUTSIDE_FLAG,
    OUTSIDE_SANDBOX_FLAG,
    OWN_FILE_TOOLS,
    PATH_KEYS,
    SEARCH_TOOLS,
    SECRETS_FLAG,
    SEND_MESSAGE,
    SENT_SAID,
    ChangedFile,
    Outcome,
    entry_cwd,
    files_changed,
    outside,
    outside_flag,
    secrets_of,
    sent_outside,
    working_dir,
)
from .shown import size

# The lines of each side of an Edit that are compared, with --verbose and
# without: only the start of a diff is shown then
DIFFED_LINES = 5000
DIFFED_LINES_BRIEF = 500
# And the steps comparing them may take, see Sides: about a tenth of a
# second of them. An edit of a few hundred lines takes some thousands, one
# of five thousand that is changed in many places a hundred thousand.
DIFF_STEPS = 1_000_000
# What is said of two sides that were not compared within them
NOT_COMPARED = (
    "... alike in too many places to compare line by line,"
    " shown as all taken out and all put in"
)
# Said of a call that is asked about, see call_whole
UNSEEN_FLAG = "CHARACTERS THAT DO NOT SHOW (control, direction or zero width)"
# What tells the plugin a call is of, each value of the event with what
# its line starts with
PLUGIN_SAID = {"plugin": "plugin", "plugin_server": "plugin server"}
# The blocks of a reply of the model that are calls Anthropic ran on its
# side: of a tool of the API's own (a search of the web, code run in a
# container of Anthropic's), and of an MCP server Anthropic reaches
SERVER_CALLS = frozenset({"server_tool_use", "mcp_tool_use"})
# What is said of such a call, under its arguments
SERVER_SIDE = "ran on Anthropic's side"
# What a call without arguments is told by: it is a call all the same
NO_ARGUMENTS = "(no arguments)"
# Of those, the tools that run code there, in a container that is not the
# sandbox: what the code reaches is out of the launcher's sight
CODE_RUNNERS = frozenset(
    {"code_execution", "bash_code_execution", "text_editor_code_execution"}
)
# The block of a prompt that hands a file to that container
UPLOAD = "container_upload"
# What the connectors of a claude.ai account are named as, as tools
CONNECTOR_START = "mcp__claude_ai_"
# What each acts on outside the sandbox, as it is said
CODE_RUN = "code run in a container of Anthropic's"
SERVER_REACHED = "the MCP server {}, which Anthropic reaches"
UPLOADED = "a file handed to a container of Anthropic's"
CONNECTOR = "the {} connector of the claude.ai account"
REMOTE_AGENT = "an agent in Anthropic's cloud, given the repository"
# The tools that start an agent, the second the name it had before
AGENT_TOOLS = frozenset({"Agent", "Task"})
# What the address of SendMessage starts with when it reaches a session
# of claude.ai or one over Remote Control, or a peer named by a DID, none
# of which is in the sandbox
SENT_AWAY = ("bridge:", "did:")


@dataclass(frozen=True)
class ActsAway:
    """A tool of Claude Code's that acts on the user's claude.ai account,
    on Anthropic's side: the argument that says what a call does, the
    values of it that only read, as Claude Code tells them, and what it
    acts on otherwise, as it is said."""

    by: str
    reads: frozenset[str]
    on: str


# Each, by its name. One more is one more here.
ACTING_AWAY = {
    "RemoteTrigger": ActsAway(
        "action",
        frozenset({"list", "get", "list_runs", "get_run_log"}),
        "a routine of claude.ai, which runs on its own and outlives the session",
    ),
    "DesignSync": ActsAway(
        "method",
        frozenset(
            {
                "list_projects",
                "get_project",
                "list_files",
                "get_file",
                "report_validate",
            }
        ),
        "a design project of claude.ai",
    ),
    "Artifact": ActsAway(
        "action",
        frozenset(
            {
                "list",
                "read",
                "list_types",
                "describe_type",
                "quickstart",
                "comments",
                "status",
                "verify",
                "list_assets",
                "list_files",
                "preview",
                "open",
                "get_endpoints",
            }
        ),
        "an artifact published on claude.ai",
    ),
}


def outside_sandbox(block: dict) -> str:
    """What a call acts on outside the sandbox, through Anthropic, empty
    for one that does not: of the capture, it is a connection to
    Anthropic and no more. A tool that acts on the user's claude.ai
    account (see ACTING_AWAY), a connector of it, an agent run in the
    cloud, a message to a session that is not in the sandbox (by its
    address, see sent_outside for what its result says), code run on
    Anthropic's side, an MCP server it reaches, and a file handed to it.
    Not a search of the web, nor a page fetched there: those only read."""
    kind, name = block.get("type"), block.get("name")
    if kind == UPLOAD:
        return UPLOADED
    if kind == "mcp_tool_use":
        return SERVER_REACHED.format(shortened(flat(block.get("server_name", "?"))))
    if not isinstance(name, str):
        return ""
    if kind == "server_tool_use":
        return CODE_RUN if name in CODE_RUNNERS else ""
    return _tool_acts_away(name, call_input(block))


def _tool_acts_away(name: str, tool_input: dict) -> str:
    """What a call of a tool of Claude Code's acts on outside the
    sandbox, see outside_sandbox."""
    acts = ACTING_AWAY.get(name)
    if acts is not None:
        does = tool_input.get(acts.by)
        if isinstance(does, str) and does in acts.reads:
            return ""
        return acts.on + (
            f" ({shortened(flat(does))})" if isinstance(does, str) else ""
        )
    if name.startswith(CONNECTOR_START):
        server = name.removeprefix(CONNECTOR_START).partition("__")[0]
        return CONNECTOR.format(shortened(flat(server)) or "?")
    if name in AGENT_TOOLS and tool_input.get("isolation") == "remote":
        return REMOTE_AGENT
    to = tool_input.get("to")
    if name == SEND_MESSAGE and isinstance(to, str) and to.startswith(SENT_AWAY):
        return SENT_SAID
    return ""


def outside_sandbox_calls(entries: list[dict]) -> list[tuple[str, str]]:
    """Each call that acted outside the sandbox, through Anthropic, once,
    with what it acted on (see outside_sandbox): by what it was called
    with, and by what its result says (see sent_outside). The calls of
    the model, those Anthropic ran on its side, and each file handed to
    it."""
    found: dict[str, tuple[str, str]] = {}
    tools: dict[str, str] = {}
    for at, entry in enumerate(entries):
        for place, block in enumerate(content_blocks(entry)):
            kind, name = block.get("type"), flat(kept(block.get("name")))
            call = block.get("id")
            if entry.get("type") == "assistant" and kind in ("tool_use", *SERVER_CALLS):
                tools[str(call)] = name
            elif not (entry.get("type") == "user" and kind == UPLOAD):
                continue
            reaches = outside_sandbox(block)
            # By its id, or where it is when it has none
            key = str(call) if isinstance(call, str) else f"\0{at}.{place}"
            if reaches:
                found.setdefault(key, (name or UPLOAD, reaches))
    for _, block in every_result(entries):
        call = str(block.get("tool_use_id"))
        if tools.get(call) != SEND_MESSAGE:
            continue
        reaches = sent_outside(SEND_MESSAGE, block_text(block.get("content")))
        if reaches:
            found.setdefault(call, (SEND_MESSAGE, reaches))
    return list(found.values())


def file_path(tool_input: dict) -> str | None:
    """The file a tool call is about, for the tools that name one."""
    path = tool_input.get("file_path") or tool_input.get("notebook_path")
    return path if isinstance(path, str) else None


def command_lines(command: object) -> list[str]:
    """A command as the lines a shell reads it in, each as it was
    written: cut at a line feed and nowhere else. A text has more places
    it can be cut at, a carriage return, a form feed, the separators
    Unicode has for lines, which are all part of a word to a shell: cut
    there, a line would start that the shell never read as one."""
    text = command if isinstance(command, str) else clean(command)
    lines = text.split("\n")
    # What ends the last line starts no other
    return lines[:-1] if len(lines) > 1 and not lines[-1] else lines


def _bash_details(
    tool_input: dict, cwd: object, project_dir: str, verbose: bool
) -> list[str]:
    """A command: what ran, why (the reason Claude gave for it) and where,
    when that is not the project directory. Its here-documents are told
    by its lines as the shell has them, see command_lines, and each of
    those is then shown on a line of its own, cleaned."""
    lines = command_lines(tool_input.get("command", ""))
    held = lines if verbose else without_heredocs(lines)
    command = clip([flat(line) for line in held], verbose)
    details = ["$ " + command[0], *("$   " + line for line in command[1:])]
    if tool_input.get("description"):
        details.append("why: " + flat(tool_input["description"]))
    if isinstance(cwd, str) and cwd != project_dir:
        details.append("cwd: " + flat(cwd))
    return details


class TooAlike(Exception):
    """Two sides have more places in common than there are steps to
    compare them in, see Sides."""


class Sides(difflib.SequenceMatcher[int]):
    """The two sides of an Edit held against each other as difflib does,
    in no more than so many steps. Its look for the longest run that two
    stretches share takes a step for each line of the one and for each
    place the other has that line at, and it looks again in what is left
    on either side of the run. Sides written to be alike in many places
    make that the cube of their lines, seconds for one call, and both
    are the session's to write: a look past the steps there are raises
    TooAlike.

    The lines are compared by a number that stands for each, so that a
    step takes as long whatever a line holds."""

    # What difflib keeps of the two sides, which its types do not say:
    # the first, and the places each line it looks for is at in the second
    a: list[int]
    b2j: dict[int, list[int]]

    def __init__(self, old: list[str], new: list[str], steps: int = DIFF_STEPS):
        numbers: dict[str, int] = {}
        super().__init__(
            None,
            [numbers.setdefault(line, len(numbers)) for line in old],
            [numbers.setdefault(line, len(numbers)) for line in new],
        )
        self._steps = steps
        # The steps a look takes from the first line of the old side up
        # to each: one for a line, and one for each place the new side
        # has it at
        self._taken = [0]
        for line in self.a:
            places = len(self.b2j.get(line, ()))
            self._taken.append(self._taken[-1] + 1 + places)

    def find_longest_match(
        self, alo: int = 0, ahi: int | None = None, blo: int = 0, bhi: int | None = None
    ) -> difflib.Match:
        """As difflib looks, once the steps it takes are counted."""
        end = len(self.a) if ahi is None else ahi
        self._steps -= self._taken[end] - self._taken[alo]
        if self._steps < 0:
            raise TooAlike
        return super().find_longest_match(alo, ahi, blo, bhi)


def _span(start: int, end: int) -> str:
    """Where the lines from one place of a side up to another are, as a
    unified diff says it: the first and how many, the number left out
    when it is one, and the line before for none."""
    length = end - start
    if length == 1:
        return str(start + 1)
    return f"{start + 1 if length else start},{length}"


def unified(old: list[str], new: list[str]) -> list[str]:
    """What changed from one side to the other, as the lines of a unified
    diff with a line around each change: as difflib writes one, without
    the two lines that name the files. Sides that are not compared within
    bounds (see Sides) are shown as one change of all of the first to all
    of the second, which is true of any two, and a line says so."""
    try:
        hunks = list(Sides(old, new).get_grouped_opcodes(1))
        said = []
    except TooAlike:
        hunks = [[("replace", 0, len(old), 0, len(new))]]
        said = [NOT_COMPARED]
    lines = []
    for hunk in hunks:
        (_, start, _, start_new, _), (_, _, end, _, end_new) = hunk[0], hunk[-1]
        lines.append(f"@@ -{_span(start, end)} +{_span(start_new, end_new)} @@")
        for change, low, high, low_new, high_new in hunk:
            if change == "equal":
                lines += [" " + line for line in old[low:high]]
                continue
            if change != "insert":
                lines += ["-" + line for line in old[low:high]]
            if change != "delete":
                lines += ["+" + line for line in new[low_new:high_new]]
    return lines + said


def edit_diff(tool_input: dict, verbose: bool = True) -> list[str]:
    """What an Edit call changes, as the lines of a unified diff, see
    unified: the file is named with the call. Of the first DIFFED_LINES
    of each side, fewer when only the start of the diff is shown:
    comparing takes the square of the lines, which are the session's to
    write, and a line says so when there were more."""
    most = DIFFED_LINES if verbose else DIFFED_LINES_BRIEF
    sides = [
        clean(tool_input.get(side, "")).splitlines()
        for side in ("old_string", "new_string")
    ]
    old, new = (side[:most] for side in sides)
    diff = unified(old, new)
    longest = max(map(len, sides))
    if longest > most:
        hint = "" if verbose else ", more of it with --verbose"
        diff.append(f"... only the first {most} of {longest} lines compared{hint}")
    return diff


def _file_details(
    name: str,
    path: str,
    tool_input: dict,
    cwd: str | None,
    project_dir: str,
    verbose: bool,
    diffed: bool = True,
) -> list[str]:
    """A call on a file: which one, flagged when it is written outside the
    project (from the directory the session was in, cwd, see outside),
    and what an Edit changes or a Write puts there. Not what an Edit
    changes unless diffed, see call_details."""
    about = "file: " + flat(path)
    changes: list[str] = []
    if name == "Edit" and diffed:
        diff = edit_diff(tool_input, verbose)
        changes = ["diff: " + line for line in clip(diff, verbose)]
    elif name == "Write":
        content = clean(tool_input.get("content", "")).splitlines()
        about += f" ({len(content)} lines)"
        changes = ["content: " + line for line in clip(content, verbose)]
    if name in FILE_TOOLS:
        about += outside_flag(path, project_dir, cwd)
    return [about, *changes]


def _todo_details(todos: list, verbose: bool) -> list[str]:
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


def _question_details(questions: list) -> list[str]:
    """What claude asks the user, a line for each question: its options
    are put with it where it is answered, and are in --json."""
    return [
        f"question: {flat(question.get('question', ''))}"
        for question in questions
        if isinstance(question, dict)
    ]


def call_details(
    name: str,
    tool_input: dict,
    cwd: object,
    project_dir: str,
    verbose: bool,
    diffed: bool = True,
) -> list[str]:
    """The lines that describe a tool call, made where the session was in
    cwd as the entry of the call names it, none when that is not known.
    Without diffed, not those of what an Edit changes: comparing its
    sides is what takes time here, and is not done for lines that no one
    is shown."""
    path = file_path(tool_input)
    if name == "Bash":
        return _bash_details(tool_input, cwd, project_dir, verbose)
    if name == "TodoWrite" and isinstance(tool_input.get("todos"), list):
        return _todo_details(tool_input["todos"], verbose)
    if path is not None:
        within = working_dir(cwd)
        return _file_details(
            name, path, tool_input, within, project_dir, verbose, diffed
        )
    if name == "AskUserQuestion" and isinstance(tool_input.get("questions"), list):
        return _question_details(tool_input["questions"])
    # Any other tool: its arguments as they are
    return _arguments(tool_input, verbose)


def _told_keys(name: str, tool_input: dict) -> set[str] | None:
    """The arguments of a call that call_details tells of with all they
    hold, none when it tells of every one: a call it has a way of its
    own to describe is described by some of them."""
    if name == "Bash":
        return {"command", "description"}
    if name == "TodoWrite" and isinstance(tool_input.get("todos"), list):
        return {"todos"}
    if file_path(tool_input) is not None:
        named = "file_path" if tool_input.get("file_path") else "notebook_path"
        held = {"Edit": {"old_string", "new_string"}, "Write": {"content"}}
        return {named, *held.get(name, ())}
    if name == "AskUserQuestion" and isinstance(tool_input.get("questions"), list):
        return {"questions"}
    return None


def call_whole(
    name: str, tool_input: dict, project_dir: str, apart: Collection[str] = ()
) -> list[str]:
    """The lines of a call with all it would be made with, for what is
    asked before it is, see call_parts."""
    details, rest = call_parts(name, tool_input, project_dir, apart)
    return details + rest


def call_parts(
    name: str, tool_input: dict, project_dir: str, apart: Collection[str] = ()
) -> tuple[list[str], list[str]]:
    """The lines of a call with all it would be made with, for what is
    asked before it is, in two parts: as call_details describes it in
    full, and every argument that does not tell of, as it is. The call
    of a tool with a file among its arguments is otherwise described by
    the file alone, and what is allowed is all of it. Said too when an
    argument holds characters that are not shown, which would be written
    or run with the rest. Without the arguments shown apart, a plan as a
    reply, which are still looked at for those characters."""
    shown = {key: value for key, value in tool_input.items() if key not in apart}
    told = _told_keys(name, shown)
    # Asked before it runs, of no entry that says where the session is:
    # a path that is not absolute is taken from the project
    details = call_details(name, shown, None, project_dir, True)
    rest: list[str] = []
    for key, value in shown.items():
        if told is not None and key not in told:
            rest += _argument_lines(flat(key), clean(value))
    unseen = [flat(key) for key, value in tool_input.items() if holds_unseen(value)]
    if unseen:
        rest.append(f"{UNSEEN_FLAG} in {', '.join(unseen)}")
    return details, rest


def _argument_lines(key: str, value: str) -> list[str]:
    """An argument of a call as its lines, each under its name: a line
    of a value is the model's to write, and one that stood alone could
    read as a line of the report (a result, a file outside the project)."""
    first, *more = value.splitlines() or [""]
    return [f"{key}: {first}", *(f"{key}:   {line}" for line in more)]


def _arguments(tool_input: dict, verbose: bool) -> list[str]:
    """The arguments of a call as they are, each as its lines, see
    _argument_lines: the first few of each, all of them with verbose."""
    return [
        line
        for key, value in tool_input.items()
        for line in clip(_argument_lines(flat(key), clean(value)), verbose)
    ]


def _changed_details(
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


def _result_details(ended: Outcome | None, verbose: bool) -> list[tuple[str, bool]]:
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
        notes.append(lines_out(len(output)))
    shown = output_shown(output, verbose, ended.failed)
    badly = ended.failed or ended.refused
    lines = [
        ("result: " + ", ".join(notes), badly),
        *(("out: " + line, badly) for line in shown),
        *((sign.shown, True) for sign in ended.planted),
    ]
    if ended.outside_sandbox:
        lines.append((f"{OUTSIDE_SANDBOX_FLAG}: {ended.outside_sandbox}", True))
    if ended.output_kept:
        # Too long to give the model whole: it was given the start, and
        # where the rest is
        kept, held = flat(ended.output_kept), ended.output_size
        said = f"output kept: {kept}" + (f" ({size(held)})" if held else "")
        lines.append((said, False))
    return lines + _changed_details(ended.changed, verbose)


def tell_result(event: Event, ended: Outcome | None, verbose: bool) -> None:
    """Add to an event the lines for how a tool call ended, see
    _result_details, and whether that tells of something gone wrong."""
    for line, alert in _result_details(ended, verbose):
        event.say(line, alert)
    if ended is not None and ended.wrong:
        event.went_wrong()


def _server_details(block: dict, tool_input: dict, verbose: bool) -> list[str]:
    """A call Anthropic ran on its side, or a file handed to it: the MCP
    server it reached, then its arguments as they are, by whatever name
    it has: a call named as one of Claude Code's tools is not one."""
    server = block.get("server_name")
    named = [f"server: {flat(server)}"] if block.get("type") == "mcp_tool_use" else []
    return named + _arguments(tool_input, verbose)


def on_secrets(
    name: str,
    tool_input: dict,
    cwd: str | None,
    project_dir: str,
    secrets: Secrets,
) -> tuple[str, str] | None:
    """Of a call of one of Claude Code's own file tools on a file of
    secrets, the path it was given and the kind of its secrets, none for
    any other: the tool runs in Claude Code's process, which the record
    of processes takes to read its own files, when it sees it at all."""
    if name not in OWN_FILE_TOOLS:
        return None
    for key in PATH_KEYS:
        path = tool_input.get(key)
        if not isinstance(path, str):
            continue
        kind = secrets_of(path, secrets, project_dir, cwd, name in SEARCH_TOOLS)
        if kind:
            return path, kind
    return None


def secrets_called(
    entries: list[dict], project_dir: str, secrets: Secrets
) -> list[tuple[str, str]]:
    """The path and the kind of secrets of each file of secrets a call
    of Claude Code's own file tools was on, once for every call that
    was, see on_secrets."""
    found = (
        on_secrets(
            str(block.get("name")),
            call_input(block),
            entry_cwd(entry),
            project_dir,
            secrets,
        )
        for entry, block in tool_calls(entries)
    )
    return [one for one in found if one]


def secrets_said(path: str, kind: str) -> str:
    """A file of secrets a call was on, as it is said."""
    return f"{flat(path)}, {said(kind)}"


def _flag(details: list[str], alerts: set[int], flag: str, said: str) -> None:
    """Add to the lines of a call one that tells of what went wrong: its
    flag, and what it says of it."""
    alerts.add(len(details))
    details.append(f"{flag}: {said}")


def _flag_away(block: dict, details: list[str], fields: dict, alerts: set[int]) -> None:
    """Flag a call that acts outside the sandbox, through Anthropic, with
    what it acts on, see outside_sandbox."""
    reaches = outside_sandbox(block)
    if reaches:
        fields["outside_sandbox"] = reaches
        _flag(details, alerts, OUTSIDE_SANDBOX_FLAG, reaches)


def _call_made(
    when: float, who: Who, details: list[str], fields: dict, alerts: set[int]
) -> Event:
    """The event of a call, by its lines, its values and which of its
    lines tell of what went wrong."""
    wrong = Wrong.PART if alerts else Wrong.NO
    return Event(
        when,
        who,
        fields["tool"].lower(),
        details,
        fields,
        alerts=alerts,
        wrong=wrong,
        call=True,
    )


def call_event(
    when: float,
    who: Who,
    entry: dict,
    block: dict,
    project_dir: str,
    verbose: bool,
    diffed: bool = True,
    secrets: Secrets | None = None,
) -> Event:
    """A call of a tool of Claude Code's as it was issued, how it ended
    is added by the walk that finds its result. diffed as for
    call_details. One that acts outside the sandbox is flagged, see
    outside_sandbox, and so is one of Claude Code's own file tools on a
    file of secrets, of those it is given, see secrets_of. A call that
    ran on Anthropic's side is told by server_call_event."""
    tool_input = call_input(block)
    # On one line: it is what the event is, and stays in its column
    name = flat(block.get("name", "?"))
    cwd = entry.get("cwd")
    within = working_dir(cwd)
    details = call_details(name, tool_input, cwd, project_dir, verbose, diffed)
    # A call without arguments is a call all the same, and has its line
    details = details or [NO_ARGUMENTS]
    fields = {"tool": name, "id": str(block.get("id")), "input": tool_input, "cwd": cwd}
    alerts: set[int] = set()
    path = file_path(tool_input)
    if name in FILE_TOOLS and path is not None:
        fields["outside_project"] = outside(path, project_dir, within)
        if fields["outside_project"]:
            # The line that names the file, see _file_details
            alerts.add(0)
    found = (
        None
        if secrets is None
        else on_secrets(name, tool_input, within, project_dir, secrets)
    )
    if found:
        fields["secrets_file"] = found[1]
        _flag(details, alerts, SECRETS_FLAG, secrets_said(*found))
    _flag_away(block, details, fields, alerts)
    # After the arguments, a call is named by the first of its lines
    for key, plugin in _plugin_called(name, tool_input).items():
        fields[key] = plugin
        details.append(f"{PLUGIN_SAID[key]}: {plugin}")
    return _call_made(when, who, details, fields, alerts)


def server_call_event(
    when: float, who: Who, entry: dict, block: dict, verbose: bool
) -> Event:
    """A call that ran on Anthropic's side as it was issued (see
    SERVER_CALLS), whose result the walk finds in the reply of the model,
    or a file handed to a container of Anthropic's with a prompt, which
    is told as a call that has no result. Each by its arguments, that it
    ran there, and what it acts on outside the sandbox, flagged, see
    outside_sandbox."""
    if block.get("type") == UPLOAD:
        file = block.get("file_id")
        name, call, tool_input = UPLOAD, file, {"file_id": file}
    else:
        # On one line, as of a call of Claude Code's
        name, call = flat(block.get("name", "?")), block.get("id")
        tool_input = call_input(block)
    details = _server_details(block, tool_input, verbose) or [NO_ARGUMENTS]
    details.append(SERVER_SIDE)
    fields = {
        "tool": name,
        "id": str(call),
        "input": tool_input,
        "cwd": entry.get("cwd"),
        "server_side": True,
    }
    alerts: set[int] = set()
    _flag_away(block, details, fields, alerts)
    return _call_made(when, who, details, fields, alerts)


def _plugin_called(name: str, tool_input: dict) -> dict[str, str]:
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
    return f"[{event.link}] {first}" if event.link else first


def written_paths(entries: list[dict]) -> Iterator[tuple[str, str | None]]:
    """The path of each file the session wrote, once for every call that
    did: with a tool of its, or by a command that Claude Code saw change
    the file, see files_changed. Each with the directory the session was
    in then, which a path that is not absolute is from, see outside."""
    for entry, block in tool_calls(entries):
        if block.get("name") in FILE_TOOLS:
            path = file_path(call_input(block))
            if path is not None:
                yield path, entry_cwd(entry)
    for entry in entries:
        if entry.get("type") == "user":
            for file in files_changed(entry, ""):
                yield file.path, entry_cwd(entry)
