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

from .events import Event, Who, clean, flat, labelled
from .files import json_object, open_plain
from .projects import transcript_dirs, transcript_files
from .settings import Fatal, Host

# A live walk of a transcript lets go of the oldest calls once this many
# wait for a result, and of the oldest steps it has shown
MOST_REMEMBERED = 10_000
# Of the call a result is named after, when other things came between
LABEL_WIDTH = 100
# Lines of one command, diff or output shown without --verbose, and of one
# prompt or reply: the conversation is context, what ran is the point
PREVIEW_LINES = 8
TALK_LINES = 3
PREVIEW_WIDTH = 200
# Of the output of a call, how many lines of its start and of its end are
# shown: when it failed, and with --verbose. The end comes first in worth, it
# is where a command says what went wrong. All of it is in --json.
FAILED_OUTPUT = (2, 6)
VERBOSE_OUTPUT = (10, 10)
# What starts a here-document in a command: << or <<-, then the word that
# ends it, quoted or not. Not <<<, which is a here-string.
_HEREDOC = re.compile(r"(?<!<)<<(?!<)(-?)\s*(['\"]?)(\w+)\2")
FILE_TOOLS = ("Edit", "Write", "NotebookEdit")
# How Claude Code records a command the user gave it (/model sonnet): its
# name and its arguments in tags, and what the command said in others
_COMMAND_NAME = re.compile(r"<command-name>(.*?)</command-name>", re.DOTALL)
_COMMAND_ARGS = re.compile(r"<command-args>(.*?)</command-args>", re.DOTALL)
_COMMAND_SAID = re.compile(
    r"<local-command-(stdout|stderr)>(.*?)</local-command-\1>", re.DOTALL
)
# What a step of the model read, as the API counts it: not cached, newly
# put in the cache, and read from it
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
    with file:
        # A last line may be half written by a running session
        return [entry for entry in map(json_object, file) if entry]


def local_time(entry: dict) -> datetime | None:
    stamp = entry.get("timestamp")
    if not isinstance(stamp, str):
        return None
    try:
        # fromisoformat only takes a trailing Z from Python 3.11
        when = datetime.fromisoformat(stamp.replace("Z", "+00:00"))  # noqa: FURB162
        # Both can fail on a date too far from now for the platform
        when.timestamp()
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
    return "  OUTSIDE PROJECT" if outside(path, project_dir) else ""


def shortened(line: str) -> str:
    """A line cut to the width of a preview."""
    return line if len(line) <= PREVIEW_WIDTH else line[:PREVIEW_WIDTH] + "..."


def clip(lines: list[str], verbose: bool, limit: int = PREVIEW_LINES) -> list[str]:
    """Lines as shown: all of them with --verbose, else the first few."""
    if verbose:
        return lines
    shown = [shortened(line) for line in lines[:limit]]
    if len(lines) > limit:
        shown.append(f"... {len(lines) - limit} more lines, see --verbose")
    return shown


def clip_ends(lines: list[str], head: int, tail: int, hint: str) -> list[str]:
    """Lines of which both ends matter: the first and the last few, with
    how many were left out between them and where those are to be seen."""
    left_out = len(lines) - head - tail
    if left_out <= 0:
        return lines
    return [*lines[:head], f"... {left_out} more lines, {hint}", *lines[-tail:]]


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


def call_details(
    name: str, tool_input: dict, cwd: object, project_dir: str, verbose: bool
) -> list[str]:
    """The lines that describe a tool call."""
    path = file_path(tool_input)
    if name == "Bash":
        return bash_details(tool_input, cwd, project_dir, verbose)
    if path is not None:
        return file_details(name, path, tool_input, project_dir, verbose)
    # Any other tool: its arguments as they are
    return [
        line
        for key, value in tool_input.items()
        for line in clip(f"{clean(key)}: {clean(value)}".splitlines(), verbose)
    ]


def outcome(call: dict, result: tuple[dict, dict] | None) -> dict:
    """How a tool call ended, empty when no result was recorded: whether it
    failed, how long it took, its output, and the permission decision when
    that was not a plain accept."""
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
    decision = entry.get("permissionDecision")
    if isinstance(decision, dict) and decision.get("decision") != "accept":
        ended["permission"] = str(decision.get("decision", "?"))
    return ended


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
        notes.append("permission " + clean(ended["permission"]))
    output = clean(ended["output"]).splitlines()
    if output:
        notes.append(f"{len(output)} line{'s' if len(output) > 1 else ''} out")
    shown: list[str] = []
    if verbose:
        shown = clip_ends(output, *VERBOSE_OUTPUT, "see --json")
    elif ended["failed"]:
        ends = clip_ends(output, *FAILED_OUTPUT, "see --verbose")
        shown = [shortened(line) for line in ends]
    return ["result: " + ", ".join(notes), *("out: " + line for line in shown)]


def as_typed(text: str) -> str:
    """A prompt as the user typed it: a command of Claude Code's is
    recorded as its name and arguments in tags, anything else as it is."""
    name = _COMMAND_NAME.search(text)
    if not name or not text.lstrip().startswith("<command-"):
        return text
    args = _COMMAND_ARGS.search(text)
    return f"{name[1].strip()} {args[1].strip() if args else ''}".strip()


def command_event(when: float, entry: dict, verbose: bool) -> Event | None:
    """What a command of Claude Code's said (/model, /context), which the
    model had no part in. None for an entry that holds nothing said."""
    content = entry.get("content")
    said = _COMMAND_SAID.findall(content) if isinstance(content, str) else []
    text = "\n".join(part for _, part in said).strip()
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
    name = clean(block.get("name", "?"))
    tool_input = call_input(block)
    details = call_details(name, tool_input, entry.get("cwd"), project_dir, verbose)
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
    return count if type(count) is int and count > 0 else 0


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


def amount(count: int) -> str:
    """A number of tokens as shown: 950, 1.4k, 2.31M."""
    if count < 1000:
        return str(count)
    return f"{count / 1e3:.1f}k" if count < 1e6 else f"{count / 1e6:.2f}M"


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
    of Claude Code's said, and ahead of what a step of the model did, what
    the step used.

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

    def take(self, entry: dict) -> list[Event]:
        """The events an entry adds."""
        kind = entry.get("type")
        said_by_command = kind == "system" and entry.get("subtype") == "local_command"
        if kind not in ("user", "assistant") and not said_by_command:
            return []
        stamp = local_time(entry)
        self._when = stamp.timestamp() if stamp else self._when
        if said_by_command:
            return self._command(entry)
        by_claude = kind == "assistant"
        claude = Who.AGENT if entry.get("isSidechain") else Who.CLAUDE
        events = self._step(claude, entry)
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
        return [used] if used else []

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
        ended = outcome(issued.started, (entry, block))
        lines = result_details(ended, self._verbose)
        if issued.event:
            issued.event.details += lines
            # Whether it wrote outside the project stays the last value
            flag = {
                key: issued.event.fields.pop(key)
                for key in ("outside_project",)
                if key in issued.event.fields
            }
            issued.event.fields.update(ended, **flag)
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
        values = {clean(e[key]) for e in entries if isinstance(e.get(key), str)}
        return ", ".join(sorted(values)) or "?"

    models = {
        clean(e["message"].get("model", ""))
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
        minutes = int((times[-1] - times[0]).total_seconds() // 60)
        span = f"{times[0]:%Y-%m-%d %H:%M} to {times[-1]:%H:%M} ({minutes} min)"
        rows.append(("when", f"{span}, times are {times[0]:%Z}"))
    if isinstance(cost.get("totalCostUSD"), (int, float)):
        rows.append(("cost", f"${cost['totalCostUSD']:.2f}"))
    if "totalLinesAdded" in cost:
        added, removed = cost.get("totalLinesAdded"), cost.get("totalLinesRemoved")
        rows.append(("lines", clean(f"+{added} -{removed}")))
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

    by_tool = Counter(clean(block.get("name", "?")) for _, block in calls)
    counts = ", ".join(f"{name} {count}" for name, count in by_tool.most_common())
    rows.append(("tool calls", f"{len(calls)} ({counts})" if calls else "0"))
    results = tool_results(entries).values()
    rows.append(("failed", str(sum(bool(b.get("is_error")) for _, b in results))))
    return rows


def written_paths(entries: list[dict]) -> Iterator[str]:
    """The path of each file the session wrote with its tools, once for
    every call."""
    for _, block in tool_calls(entries):
        if block.get("name") in FILE_TOOLS:
            path = file_path(call_input(block))
            if path is not None:
                yield path


def files_written(entries: list[dict], project_dir: str) -> list[str]:
    """Each file the session wrote with its tools and how often, flagged
    when it is outside the project."""
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
    rows = [("project", clean(project_dir)), *overview(entries)]
    return [
        *(labelled(name, value) for name, value in rows),
        *files_written(entries, project_dir),
        *pages_fetched(entries),
    ]
