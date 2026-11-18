"""Reading the transcript Claude Code keeps of each session in
~/.claude/projects (every prompt, reply, tool call and result) as events,
and as the header lines of a trace.

The transcript is written from inside the sandbox, so it is a convenience
for review and not an audit log, a session could rewrite its own. For the
same reason nothing in it is trusted here, see events.py, and no shape it
can be given stops the reading."""

from __future__ import annotations

import bisect
import difflib
import os
import re
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit

from .brief import (
    PREVIEW_WIDTH,
    TALK_LINES,
    amount,
    between,
    clip,
    clip_ends,
    shortened,
)
from .events import Event, Who, clean, flat, labelled
from .files import UNREADABLE, bounded_lines, json_object, line_entry, open_plain
from .projects import transcript_dirs, transcript_files
from .settings import Fatal, Host
from .shown import size
from .told import Asides, counted, instructions_read, listed, typed_while_working

# A live walk of a transcript lets go of the oldest calls once this many
# wait for a result, and of the oldest steps it has shown
MOST_REMEMBERED = 10_000
# Of the call a result is named after, when other things came between
LABEL_WIDTH = 100
# Of the output of a call, how many lines of its start and of its end are
# shown: when it failed, and with --verbose. The end comes first in worth, it
# is where a command says what went wrong. All of it is in --json.
FAILED_OUTPUT = (2, 6)
VERBOSE_OUTPUT = (10, 10)
# What starts a here-document in a command: << or <<-, then the word that
# ends it, quoted or not. Not <<<, which is a here-string.
_HEREDOC = re.compile(r"(?<!<)<<(?!<)(-?)\s*(['\"]?)(\w+)\2")
FILE_TOOLS = ("Edit", "Write", "NotebookEdit")
# Where a hunk of a diff is, as Claude Code names it: from which line and
# how many, of the file before and after
HUNK_SPANS = ("oldStart", "oldLines", "newStart", "newLines")
# What follows the name of a written file that is not in the project
OUTSIDE_FLAG = "  OUTSIDE PROJECT"
# How Claude Code records a command the user gave it (/model sonnet): its
# name and its arguments in tags, and what the command said in others
# Each is found by where it starts and where it then ends, see between
_COMMAND_NAME = ("<command-name>", "</command-name>")
_COMMAND_ARGS = ("<command-args>", "</command-args>")
_COMMAND_SAID = re.compile(r"<local-command-(stdout|stderr)>")
# The times an entry can say it was written at, as seconds since the
# epoch: any other is not one a session ran at, and not one every
# platform and time zone can show as a date
EARLIEST, LATEST = 86400.0, 2e11
# More than a session could use or cost: a count above it is not one
MOST_COUNTED = 10**15
# What a step of the model read, as the API counts it: not cached, newly
# put in the cache, and read from it
# A step that reads less than one in so many of what the step before read
# from the cache has missed it
MISS_SHARE = 2
INPUT_TOKENS = (
    "input_tokens",
    "cache_creation_input_tokens",
    "cache_read_input_tokens",
)


def modified(path: Path) -> float:
    """When a file was last written, 0 for one that has gone since it was
    listed."""
    try:
        return path.stat().st_mtime
    except OSError:
        return 0.0


def session_files(host: Host) -> list[Path]:
    """The project's transcripts, the latest session first."""
    files = sorted(transcript_files(host), key=modified, reverse=True)
    if not files:
        looked = ", ".join(map(str, transcript_dirs(host)))
        raise Fatal(f"no session recorded for this project (looked in {looked})")
    return files


def sessions_named(files: list[Path], name: str) -> list[Path]:
    """The transcripts whose session id starts with name."""
    return [path for path in files if path.stem.startswith(name)]


def read_entries(path: Path) -> list[dict]:
    """The transcript's entries, none for one that cannot be read."""
    file = open_plain(path)
    if file is None:
        return []
    entries = []
    with file:
        for line in bounded_lines(file):
            if line is None or line.endswith(b"\n"):
                entry = line_entry(line)
            else:
                # A last line may be half written by a running session
                entry = json_object(line)
            if entry:
                entries.append(entry)
    return entries


def local_time(entry: dict) -> datetime | None:
    stamp = entry.get("timestamp")
    if not isinstance(stamp, str):
        return None
    try:
        # fromisoformat only takes a trailing Z from Python 3.11
        when = datetime.fromisoformat(stamp.replace("Z", "+00:00"))  # noqa: FURB162
        # Both can fail on a date too far from now for the platform
        if not EARLIEST <= when.timestamp() <= LATEST:
            return None
        return when.astimezone()
    except (ValueError, OverflowError, OSError):
        return None


def entry_times(entries: list[dict]) -> list[datetime]:
    """When each entry that says so was written, in order."""
    return [when for when in map(local_time, entries) if when]


def content_blocks(entry: dict) -> list[dict]:
    """The content of a user or assistant entry as blocks, a prompt typed
    as plain text becoming one text block."""
    message = entry.get("message")
    content = message.get("content") if isinstance(message, dict) else None
    if isinstance(content, str):
        return [{"type": "text", "text": content}]
    if isinstance(content, list):
        return [block for block in content if isinstance(block, dict)]
    return []


def block_text(content: object) -> str:
    """The text of a tool result, which is a string or a list of blocks."""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = (b.get("text", "") for b in content if isinstance(b, dict))
        return "\n".join(part for part in parts if isinstance(part, str) and part)
    return ""


def call_input(block: dict) -> dict:
    tool_input = block.get("input")
    return tool_input if isinstance(tool_input, dict) else {}


def is_prompt(entry: dict) -> bool:
    """Whether an entry is something the user asked. Not what Claude Code
    puts in their name, and not what a subagent is asked, which is in the
    call that started it."""
    return (
        entry.get("type") == "user"
        and not entry.get("isMeta")
        and not entry.get("isSidechain")
    )


def tool_calls(entries: list[dict]) -> list[tuple[dict, dict]]:
    """Every tool call with the entry it is in, in order."""
    return [
        (entry, block)
        for entry in entries
        if entry.get("type") == "assistant"
        for block in content_blocks(entry)
        if block.get("type") == "tool_use"
    ]


def tool_results(entries: list[dict]) -> dict[str, tuple[dict, dict]]:
    """Each tool result and the entry it is in, by the id of its call."""
    return {
        str(block.get("tool_use_id")): (entry, block)
        for entry in entries
        if entry.get("type") == "user"
        for block in content_blocks(entry)
        if block.get("type") == "tool_result"
    }


def prompts(entries: list[dict]) -> list[str]:
    return [
        block.get("text", "")
        for entry in entries
        if is_prompt(entry)
        for block in content_blocks(entry)
        if block.get("type") == "text"
    ]


def title(entries: list[dict]) -> str:
    """Claude's own title for the session, else the start of its first
    prompt."""
    titles = [e.get("aiTitle") for e in entries if e.get("type") == "ai-title"]
    asked = prompts(entries)
    text = titles[-1] if titles else asked[0] if asked else "(no prompt)"
    lines = clean(text).strip().splitlines() or [""]
    return lines[0][:70]


def outside(path: str, project_dir: str) -> bool:
    absolute = os.path.normpath(os.path.join(project_dir, path))
    return absolute != project_dir and not absolute.startswith(project_dir + os.sep)


def outside_flag(path: str, project_dir: str) -> str:
    """What follows the name of a written file that is not in the project."""
    return OUTSIDE_FLAG if outside(path, project_dir) else ""


def without_heredocs(lines: list[str]) -> list[str]:
    """The lines of a command without what its here-documents hold, each
    said to be so many lines instead: a script fed to an interpreter is
    as a rule most of the command, and the line that starts it tells what
    it is given to. One whose end is not found is left as it is."""
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
    while index < len(lines):
        shown.append(lines[index])
        starts = _HEREDOC.findall(lines[index])
        index += 1
        for dash, _, word in starts:
            found = (tabbed if dash else plain).get(word, [])
            later = bisect.bisect_left(found, index)
            if later < len(found):
                body = found[later] - index
                shown.append(f"... here-document of {body} lines, see --verbose")
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


def edit_diff(tool_input: dict) -> list[str]:
    """What an Edit call changes, as the lines of a unified diff."""
    diff = difflib.unified_diff(
        clean(tool_input.get("old_string", "")).splitlines(),
        clean(tool_input.get("new_string", "")).splitlines(),
        lineterm="",
        n=1,
    )
    # Without the --- and +++ lines, the file is named with the call
    return list(diff)[2:]


def file_details(
    name: str, path: str, tool_input: dict, project_dir: str, verbose: bool
) -> list[str]:
    """A call on a file: which one, flagged when it is written outside the
    project, and what an Edit changes or a Write puts there."""
    about = "file: " + flat(path)
    changes: list[str] = []
    if name == "Edit":
        changes = ["diff: " + line for line in clip(edit_diff(tool_input), verbose)]
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
    # Any other tool: its arguments as they are
    return [
        line
        for key, value in tool_input.items()
        for line in clip(f"{clean(key)}: {clean(value)}".splitlines(), verbose)
    ]


def decided(entry: dict) -> dict:
    """Who let a call run or refused it, as the values of its result,
    empty when the permission mode of the session let it run: that is
    most calls, and the mode is told where it is set. The words for who
    are Claude Code's, which says where a decision is from (the settings
    or the user), of the settings what kind (the mode, a rule), and of the
    user for how long (once)."""
    decision = entry.get("permissionDecision")
    if not isinstance(decision, dict):
        return {}
    source = decision.get("source")
    source = source if isinstance(source, str) else "?"
    allowed = decision.get("decision") == "accept"
    kind = decision.get("reasonType")
    if source == "config":
        if allowed and kind == "mode":
            return {}
        kinds = {"mode": "the permission mode", "rule": "a rule"}
        by = kinds.get(str(kind), "the settings")
    elif source.startswith("user"):
        by = "you"
        scope = decision.get("grantScope")
        if allowed and isinstance(scope, str) and scope:
            by += ", " + flat(scope)[:PREVIEW_WIDTH]
    else:
        by = flat(source).replace("_", " ")[:PREVIEW_WIDTH]
    values: dict = {
        "permission": "accept" if allowed else "reject",
        "permission_by": by,
    }
    return values if allowed else {**values, "refused": True}


def hunk_lines(hunk: dict) -> list[str]:
    """A hunk of a diff as its lines, under the line that says where."""
    spans = [counted(hunk.get(key)) for key in HUNK_SPANS]
    given = hunk.get("lines")
    if None in spans or not isinstance(given, list):
        return []
    lines = [clean(line) for line in given if isinstance(line, str)]
    return ["@@ -{},{} +{},{} @@".format(*spans), *lines]


def files_changed(entry: dict, project_dir: str) -> list[dict]:
    """The files a command changed, as Claude Code noted with its result:
    of each its path, whether the command made it, whether it is outside
    the project, and what changed as the lines of a diff. A file the
    command changed that Claude Code only names has no diff. This is what
    Claude Code noticed, a command can write what it did not."""
    result = entry.get("toolUseResult")
    noted = result.get("bashEditDiff") if isinstance(result, dict) else None
    if not isinstance(noted, dict):
        return []
    changed: dict[str, dict] = {}
    for file in listed(noted.get("files")):
        path = file.get("filePath") if isinstance(file, dict) else None
        if not isinstance(path, str):
            continue
        hunks = [hunk for hunk in listed(file.get("hunks")) if isinstance(hunk, dict)]
        changed[path] = {
            "path": path,
            "created": bool(file.get("created")),
            "outside": outside(path, project_dir),
            "diff": [line for hunk in hunks for line in hunk_lines(hunk)],
        }
    for path in listed(noted.get("changedFiles")):
        if isinstance(path, str) and path not in changed:
            changed[path] = {
                "path": path,
                "created": False,
                "outside": outside(path, project_dir),
                "diff": [],
            }
    return list(changed.values())


def command_ending(entry: dict, project_dir: str) -> dict:
    """What Claude Code noted of how a command ended, besides its output:
    that it was interrupted, what its exit code means when that is not a
    failure (grep that found nothing), where its output was kept when
    that was too long to give the model, and the files it changed."""
    result = entry.get("toolUseResult")
    if not isinstance(result, dict):
        return {}
    ended: dict = {}
    if result.get("interrupted") is True:
        ended["interrupted"] = True
    meaning = result.get("returnCodeInterpretation")
    if isinstance(meaning, str) and meaning:
        ended["exit_meaning"] = meaning
    kept = result.get("persistedOutputPath")
    if isinstance(kept, str) and kept:
        ended["output_kept"] = kept
        ended["output_size"] = counted(result.get("persistedOutputSize"))
    changed = files_changed(entry, project_dir)
    if changed:
        ended["changed"] = changed
        ended["outside_project"] = any(file["outside"] for file in changed)
    return ended


def outcome(call: dict, result: tuple[dict, dict] | None, project_dir: str) -> dict:
    """How a tool call ended, empty when no result was recorded: whether it
    failed, how long it took, its output, who decided that it may run when
    that was not the mode of the session, and what Claude Code noted of a
    command."""
    if result is None:
        return {}
    entry, block = result
    ended: dict = {
        "failed": bool(block.get("is_error")),
        "output": block_text(block.get("content")),
    }
    started, finished = local_time(call), local_time(entry)
    if started and finished:
        ended["seconds"] = round((finished - started).total_seconds(), 3)
    return {**ended, **decided(entry), **command_ending(entry, project_dir)}


def changed_details(changed: list[dict], verbose: bool) -> list[str]:
    """The lines for the files a command changed: each one, flagged when
    it is outside the project, and what changed in it."""
    lines = []
    for file in changed:
        diff = file["diff"]
        added = sum(line.startswith("+") for line in diff)
        removed = sum(line.startswith("-") for line in diff)
        how = "created, " if file["created"] else ""
        sizes = f" ({how}+{added} -{removed})" if diff else " (created)" if how else ""
        flag = OUTSIDE_FLAG if file["outside"] else ""
        lines.append(f"changed: {flat(file['path'])}{sizes}{flag}")
        lines += ["diff: " + line for line in clip(diff, verbose)]
    return lines


def result_details(ended: dict, verbose: bool) -> list[str]:
    """The lines for how a tool call ended and how much it put out. Of
    the output itself the start and the end, when the call failed or with
    --verbose: never all of it, a command can put out thousands of lines."""
    if not ended:
        return ["result: none recorded (interrupted or still running)"]
    notes = ["FAILED" if ended["failed"] else "ok"]
    if "seconds" in ended:
        notes.append(f"{ended['seconds']:.1f}s")
    if "permission" in ended:
        verdict = "REFUSED" if ended.get("refused") else "allowed"
        notes.append(f"{verdict} by {ended['permission_by']}")
    if ended.get("interrupted"):
        notes.append("INTERRUPTED")
    if "exit_meaning" in ended:
        notes.append(shortened(flat(ended["exit_meaning"])))
    output = clean(ended["output"]).splitlines()
    if output:
        notes.append(f"{len(output)} line{'s' if len(output) > 1 else ''} out")
    shown: list[str] = []
    if verbose:
        shown = clip_ends(output, *VERBOSE_OUTPUT, "see --json")
    elif ended["failed"]:
        ends = clip_ends(output, *FAILED_OUTPUT, "see --verbose")
        shown = [shortened(line) for line in ends]
    lines = ["result: " + ", ".join(notes), *("out: " + line for line in shown)]
    if "output_kept" in ended:
        # Too long to give the model whole: it was given the start, and
        # where the rest is
        kept, held = flat(ended["output_kept"]), ended.get("output_size")
        lines.append(f"output kept: {kept}" + (f" ({size(held)})" if held else ""))
    return lines + changed_details(ended.get("changed", []), verbose)


def command_said(content: str) -> list[str]:
    """What a command of Claude Code's said, each part it is recorded in:
    what it wrote to its output and to its errors, in their order."""
    parts: list[str] = []
    at = 0
    # The kinds that have no end from here on
    open_ended: set[str] = set()
    for opening in _COMMAND_SAID.finditer(content):
        kind = opening[1]
        if opening.start() < at or kind in open_ended:
            continue
        closing = f"</local-command-{kind}>"
        end = content.find(closing, opening.end())
        if end < 0:
            open_ended.add(kind)
            continue
        parts.append(content[opening.end() : end])
        at = end + len(closing)
    return parts


def as_typed(text: str) -> str:
    """A prompt as the user typed it: a command of Claude Code's is
    recorded as its name and arguments in tags, anything else as it is."""
    if not text.lstrip().startswith("<command-"):
        return text
    name = between(text, *_COMMAND_NAME)
    if name is None:
        return text
    args = between(text, *_COMMAND_ARGS) or ""
    return f"{name.strip()} {args.strip()}".strip()


def command_event(when: float, entry: dict, verbose: bool) -> Event | None:
    """What a command of Claude Code's said (/model, /context), which the
    model had no part in. None for an entry that holds nothing said."""
    content = entry.get("content")
    said = command_said(content) if isinstance(content, str) else []
    text = "\n".join(said).strip()
    lines = [line for line in clean(text).splitlines() if verbose or line.strip()]
    if not lines:
        return None
    details = clip(lines, verbose, TALK_LINES)
    return Event(when, Who.CLAUDE, "command", details, {"text": text})


def talk_event(when: float, who: Who, block: dict, verbose: bool) -> Event | None:
    """A prompt or a reply, none for one without text."""
    said = clean(block.get("text", ""))
    text = (as_typed(said) if who is Who.USER else said).strip().splitlines()
    if not verbose:
        # Paragraph breaks would use up the preview
        text = [line for line in text if line.strip()]
    if not text:
        return None
    what = "prompt" if who is Who.USER else "reply"
    return Event(
        when, who, what, clip(text, verbose, TALK_LINES), {"text": block["text"]}
    )


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
    path = file_path(tool_input)
    if name in FILE_TOOLS and path is not None:
        fields["outside_project"] = outside(path, project_dir)
    return Event(when, who, name.lower(), details, fields)


def unreadable_event(when: float, entry: dict) -> Event:
    """A line of the transcript that holds no entry, see line_entry of
    files.py: what a session did there is not told, that it is so is.
    When is not known either, it is put where it was found."""
    text = entry.get("text")
    shown = shortened(flat(text if isinstance(text, str) else ""))
    details = [f"UNREADABLE line of the transcript: {shown}"]
    fields = {"unreadable_line": True, "text": text}
    return Event(when, Who.SANDBOX, "transcript", details, fields)


def call_label(event: Event) -> str:
    """What a call is named by next to something else, its result that
    comes later or a connection made while it ran: its command, or the
    tool and what it was called on."""
    first = event.details[0] if event.details else ""
    if event.fields.get("tool") != "Bash":
        _, found, value = first.partition(": ")
        first = f"{event.what} {value if found else first}".rstrip()
    return f"[{event.number}] {first}" if event.number is not None else first


def step_usage(entry: dict) -> tuple[str, dict] | None:
    """The step of the model an entry of Claude's is part of, by its id,
    and what the API said that step used, none for an entry without. A
    step is one answer of the model: what it thought, said and called
    before it was given results. Each of those is an entry of its own, and
    each repeats the usage of the whole step."""
    message = entry.get("message")
    if entry.get("type") != "assistant" or not isinstance(message, dict):
        return None
    step, usage = message.get("id") or entry.get("requestId"), message.get("usage")
    if not isinstance(step, str) or not isinstance(usage, dict):
        return None
    return step, usage


def tokens(usage: object, kind: str) -> int:
    """A count of tokens in what the API said was used, 0 without one."""
    count = usage.get(kind) if isinstance(usage, dict) else None
    return count if type(count) is int and 0 < count <= MOST_COUNTED else 0


def step_tokens(usage: dict) -> dict[str, int]:
    """What a step used, under the names the API has for it: the tokens
    it wrote, how many of those thinking, and the ones it read, which is
    the whole conversation so far, as those not cached, those newly put
    in the cache and those read from it."""
    return {
        "output_tokens": tokens(usage, "output_tokens"),
        "thinking_tokens": tokens(
            usage.get("output_tokens_details"), "thinking_tokens"
        ),
        **{kind: tokens(usage, kind) for kind in INPUT_TOKENS},
    }


def read_anew(used: dict[str, int], before: int) -> int:
    """How much of the conversation a step read at full price that the
    step before had left in the cache, 0 when the cache held: a step
    reads again what the one before read, and less than half of that
    from the cache is a miss. The conversation then changed near its
    start (another model, thinking that was dropped), or the cache was
    let go of over a pause. Before is what the step before read."""
    if used["cache_read_input_tokens"] * MISS_SHARE >= before:
        return 0
    return sum(used[kind] for kind in INPUT_TOKENS) - used["cache_read_input_tokens"]


def step_event(when: float, who: Who, usage: dict) -> Event | None:
    """What a step of the model used, none when that is nothing: the
    tokens it wrote, and the ones it read with how many of them are new
    since the step before, which is what the results it was given and the
    prompt took."""
    used = step_tokens(usage)
    read = sum(used[kind] for kind in INPUT_TOKENS)
    if not read and not used["output_tokens"]:
        return None
    thinking = used["thinking_tokens"]
    new = read - used["cache_read_input_tokens"]
    detail = (
        f"{amount(used['output_tokens'])} tokens out"
        + (f" ({amount(thinking)} thinking)" if thinking else "")
        + f", {amount(read)} in ({amount(new)} new)"
    )
    return Event(when, who, "step", [detail], used)


@dataclass
class OpenCall:
    """A tool call that has no result yet."""

    who: Who
    # The cleaned name of the tool
    name: str
    # The entry the call is in, as far as its result needs it
    started: dict
    # What the call is shown by, to name it next to its result
    label: str
    # Its event, to add the result to. None in a live walk, where the
    # result is an event of its own.
    event: Event | None
    # Its number in a live walk, see Event
    number: int | None = None


class Walk:
    """Turns the entries of a transcript into events, an entry at a time
    and in their order: each prompt, reply and tool call, what a command
    of Claude Code's said, ahead of what a step of the model did, what
    the step used, and what the session was told or became besides, see
    told.py.

    There are two ways to walk. Over a transcript that is all there, a call
    and its result are one event: the result is added to the event of its
    call when it is found, and end marks the calls left without one. Live,
    over a transcript as it is written, events are shown as they come and
    cannot change later: a result is an event of its own, named after its
    call when something else came between the two (always with
    name_results, for when not every event is shown), and both carry the
    id of the call and its number. Of what is said only the first line is
    shown. What a live walk remembers is bounded, the transcript is the
    session's to write.

    What a step used is only told when verbose: it is the cost of the
    session, not what it did, and the header of a trace sums it up."""

    def __init__(
        self,
        project_dir: str,
        verbose: bool,
        live: bool = False,
        usage: dict[str, dict] | None = None,
        name_results: bool = False,
    ):
        self._project_dir = project_dir
        self._verbose = verbose
        self._live = live
        self._name_results = name_results
        # How many calls a live walk has seen
        self._calls = 0
        # What each step used when that is known ahead, else the entry
        # that starts a step is taken at its word
        self._usage = usage or {}
        # An entry without a time of its own happened with the one before
        self._when = 0.0
        self._open: dict[str, OpenCall] = {}
        # The call shown last, when nothing of the session came after it
        self._last_call: str | None = None
        # The steps of the model whose usage was shown
        self._steps: dict[str, None] = {}
        # How much the last step of each read, which the next one of
        # theirs finds in the cache or has missed
        self._read: dict[Who, int] = {}
        self._asides = Asides(verbose)

    def take(self, entry: dict) -> list[Event]:
        """The events an entry adds."""
        kind = entry.get("type")
        if kind == UNREADABLE:
            return [unreadable_event(self._when, entry)]
        stamp = local_time(entry)
        self._when = stamp.timestamp() if stamp else self._when
        if kind == "system" and entry.get("subtype") == "local_command":
            return self._command(entry)
        if kind not in ("user", "assistant"):
            return self._aside(entry)
        by_claude = kind == "assistant"
        claude = Who.AGENT if entry.get("isSidechain") else Who.CLAUDE
        events = self._step(claude, entry)
        if not by_claude:
            events += self._beside(self._asides.prompted(entry, self._when))
        for block in content_blocks(entry):
            part = block.get("type")
            if part == "text" and (by_claude or is_prompt(entry)):
                events += self._talk(claude if by_claude else Who.USER, block)
            elif part == "tool_use" and by_claude:
                events.append(self._call(claude, entry, block))
            elif part == "tool_result" and not by_claude:
                events += self._result(entry, block)
        return events

    def end(self) -> None:
        """Mark the calls that were left without a result."""
        for call in self._open.values():
            if call.event:
                call.event.details += result_details({}, self._verbose)
        self._open.clear()

    def _remember(self, kept: dict) -> None:
        """Let go of the oldest of what a live walk keeps."""
        while self._live and len(kept) > MOST_REMEMBERED:
            del kept[next(iter(kept))]

    def _step(self, who: Who, entry: dict) -> list[Event]:
        """What the step an entry starts used, nothing for a later entry
        of the same step."""
        step = step_usage(entry) if self._verbose else None
        if not step or step[0] in self._steps:
            return []
        self._steps[step[0]] = None
        self._remember(self._steps)
        used = step_event(self._when, who, self._usage.get(*step))
        # Said with the step it is about, or not at all
        why = self._asides.dropped()
        if not used:
            return []
        anew = read_anew(used.fields, self._read.get(who, 0))
        self._read[who] = sum(used.fields[kind] for kind in INPUT_TOKENS)
        if anew:
            said = f"  cache MISSED, {amount(anew)} read anew"
            used.details[0] += said + (f": {why}" if why else "")
            used.fields = {**used.fields, "cache_missed": anew, "cache_missed_why": why}
        return [used]

    def _aside(self, entry: dict) -> list[Event]:
        """What an entry that is neither said nor done by the model adds:
        a line the user typed while claude worked, which is a prompt, and
        what told.py reads."""
        typed = typed_while_working(entry)
        if typed is None:
            events = self._asides.take(entry, self._when)
            if any(event.what == "compact" for event in events):
                # What is read from here on is another conversation
                self._read.clear()
            return self._beside(events)
        blocks = content_blocks({"message": {"content": typed}})
        events = []
        for block in blocks:
            if block.get("type") != "text" or not isinstance(block.get("text"), str):
                continue
            for said in self._talk(Who.USER, block):
                said.details[0] = f"(typed while claude worked) {said.details[0]}"
                said.fields["queued"] = True
                events.append(said)
        return events

    def _beside(self, events: list[Event]) -> list[Event]:
        """Events that came between a call and its result: the result is
        then named after its call."""
        if events:
            self._last_call = None
        return events

    def _talk(self, who: Who, block: dict) -> list[Event]:
        return self._said(talk_event(self._when, who, block, self._whole))

    def _command(self, entry: dict) -> list[Event]:
        """What a command of Claude Code's said, as of anything said."""
        return self._said(command_event(self._when, entry, self._whole))

    @property
    def _whole(self) -> bool:
        """Whether what is said is shown whole. Live just its first line,
        when verbose too: whoever follows is after what the session does,
        what it says is on its own screen."""
        return self._verbose and not self._live

    def _said(self, said: Event | None) -> list[Event]:
        """Something said, which ends the call before it, live its first
        line alone."""
        if not said:
            return []
        if self._live:
            del said.details[1:]
        self._last_call = None
        return [said]

    def _call(self, who: Who, entry: dict, block: dict) -> Event:
        event = call_event(
            self._when, who, entry, block, self._project_dir, self._verbose
        )
        call = str(block.get("id"))
        name = event.fields["tool"]
        # Before the event has its number: a result shows that itself
        label = (call_label(event) or name)[:LABEL_WIDTH]
        started = {"timestamp": entry.get("timestamp")}
        if self._live:
            self._calls += 1
            event.number = self._calls
            event.fields = {"stage": "call", **event.fields}
        kept = None if self._live else event
        self._open[call] = OpenCall(who, name, started, label, kept, event.number)
        self._remember(self._open)
        self._last_call = call
        return event

    def _result(self, entry: dict, block: dict) -> list[Event]:
        """How a call that was seen ended: added to its event, or live an
        event of its own. Nothing for the result of any other call."""
        call = str(block.get("tool_use_id"))
        issued = self._open.pop(call, None)
        if issued is None:
            return []
        ended = outcome(issued.started, (entry, block), self._project_dir)
        lines = result_details(ended, self._verbose)
        if issued.event:
            issued.event.details += lines
            # Whether it wrote outside the project stays the last value,
            # and is so when the call or what it ran did
            fields = issued.event.fields
            key = "outside_project"
            flags = [of.pop(key) for of in (fields, ended) if key in of]
            fields.update(ended)
            if flags:
                fields["outside_project"] = any(flags)
            return []
        if self._name_results or self._last_call != call:
            lines.insert(0, "of: " + issued.label)
        self._last_call = None
        fields = {"stage": "result", "tool": issued.name, "id": call, **ended}
        what = issued.name.lower()
        return [Event(self._when, issued.who, what, lines, fields, issued.number)]


def transcript_events(
    entries: list[dict], project_dir: str, verbose: bool
) -> list[Event]:
    """The events of a transcript that is all there."""
    # As the last entry of a step has it, should an earlier one be short
    usage = dict(found for found in map(step_usage, entries) if found)
    walk = Walk(project_dir, verbose, usage=usage)
    events = [event for entry in entries for event in walk.take(entry)]
    walk.end()
    return events


def overview(entries: list[dict]) -> list[tuple[str, str]]:
    """The session at a glance, as labelled values: what ran it, when, at
    what cost, how many calls and how many of them failed."""
    calls = tool_calls(entries)
    times = entry_times(entries)
    last = {str(e.get("type")): e for e in entries}
    cost = last.get("cost-state", {})

    def seen(key: str) -> str:
        values = {flat(e[key]) for e in entries if isinstance(e.get(key), str)}
        return ", ".join(sorted(values)) or "?"

    models = {
        flat(e["message"].get("model", ""))
        for e in entries
        if e.get("type") == "assistant" and isinstance(e.get("message"), dict)
    }
    rows = [
        ("branch", seen("gitBranch")),
        ("claude", seen("version")),
        ("model", ", ".join(sorted(models - {"", "<synthetic>"})) or "?"),
        ("permissions", seen("permissionMode")),
    ]
    if times:
        # Not the first and the last: the order of the entries is the
        # session's to choose
        first, last_time = min(times), max(times)
        minutes = int((last_time - first).total_seconds() // 60)
        span = f"{first:%Y-%m-%d %H:%M} to {last_time:%H:%M} ({minutes} min)"
        rows.append(("when", f"{span}, times are {first:%Z}"))
    spent = cost.get("totalCostUSD")
    # Not a number and a number too large to write are not a cost
    if isinstance(spent, (int, float)) and 0 <= spent <= MOST_COUNTED:
        rows.append(("cost", f"${spent:.2f}"))
    if "totalLinesAdded" in cost:
        added, removed = cost.get("totalLinesAdded"), cost.get("totalLinesRemoved")
        rows.append(("lines", flat(f"+{added} -{removed}")[:PREVIEW_WIDTH]))
    rows.append(("prompts", str(len(prompts(entries)))))
    steps = [
        step_tokens(u) for u in dict(filter(None, map(step_usage, entries))).values()
    ]
    if steps:
        wrote = sum(used["output_tokens"] for used in steps)
        read = sum(used[kind] for used in steps for kind in INPUT_TOKENS)
        cached = sum(used["cache_read_input_tokens"] for used in steps)
        total = (
            f"{amount(wrote)} out, {amount(read)} in ({amount(cached)} from the cache)"
        )
        rows.append(("tokens", f"{total}, over {len(steps)} steps of the model"))

    by_tool = Counter(flat(block.get("name", "?")) for _, block in calls)
    counts = ", ".join(f"{name} {count}" for name, count in by_tool.most_common())
    rows.append(("tool calls", f"{len(calls)} ({counts})" if calls else "0"))
    results = tool_results(entries).values()
    rows.append(("failed", str(sum(bool(b.get("is_error")) for _, b in results))))
    refused = sum(bool(decided(entry).get("refused")) for entry, _ in results)
    if refused:
        rows.append(("refused", f"{refused} calls were not allowed to run"))
    return rows


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
                yield file["path"]


def files_written(entries: list[dict], project_dir: str) -> list[str]:
    """Each file the session wrote and how often, flagged when it is
    outside the project."""
    written = Counter(written_paths(entries))
    lines = ["files written"] if written else []
    for path, count in sorted(written.items()):
        lines.append(f"  {flat(path)} x{count}{outside_flag(path, project_dir)}")
    return lines


def url_host(url: str) -> str:
    """The host a URL names, the URL as it is when it names none or is
    not one: it is the session's to write."""
    try:
        return urlsplit(url).hostname or url
    except ValueError:
        return url


def pages_fetched(entries: list[dict]) -> list[str]:
    """Each host the session fetched a page from with its tools."""
    urls = [call_input(block).get("url") for _, block in tool_calls(entries)]
    hosts = Counter(url_host(url) for url in urls if isinstance(url, str))
    lines = ["pages fetched"] if hosts else []
    return lines + [f"  {flat(host)} x{count}" for host, count in sorted(hosts.items())]


def summary(entries: list[dict], project_dir: str) -> list[str]:
    """What to know before reading on."""
    rows = [("project", flat(project_dir)), *overview(entries)]
    return [
        *(labelled(name, value) for name, value in rows),
        *instructions_read(entries),
        *files_written(entries, project_dir),
        *pages_fetched(entries),
    ]
