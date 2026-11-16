"""Reading the transcript Claude Code keeps of each session in
~/.claude/projects (every prompt, reply, tool call and result) as events,
and as the header lines of a trace.

The transcript is written from inside the sandbox, so it is a convenience
for review and not an audit log, a session could rewrite its own. For the
same reason nothing in it is trusted here, see events.py, and no shape it
can be given stops the reading."""

from __future__ import annotations

import difflib
import json
import os
import re
import stat
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import BinaryIO
from urllib.parse import urlsplit

from .events import Event, Who, clean, flat
from .session import CONTAINER_HOME
from .settings import Fatal, Host

# A live walk of a transcript lets go of the oldest calls once this many
# wait for a result, and of the oldest steps it has shown
MOST_REMEMBERED = 10_000
# Of the call a result is named after, when other things came between
LABEL_WIDTH = 100
# Lines of one command, diff or output shown without --full, and of one
# prompt or reply: the conversation is context, what ran is the point
PREVIEW_LINES = 8
TALK_LINES = 3
PREVIEW_WIDTH = 200
FILE_TOOLS = ("Edit", "Write", "NotebookEdit")
# What a step of the model read, as the API counts it: not cached, newly
# put in the cache, and read from it
INPUT_TOKENS = (
    "input_tokens",
    "cache_creation_input_tokens",
    "cache_read_input_tokens",
)


def project_roots(host: Host) -> list[str]:
    """The project directory as a session may have known it: its host
    path, and for a project under the user's home the same place under the
    container's. The image links the host home to the container's and
    Claude Code resolves the link, so a sandboxed session records the
    second, one run on the host the first."""
    roots = [host.project_dir]
    home = host.home.rstrip(os.sep)
    if host.project_dir == home or host.project_dir.startswith(home + os.sep):
        sandboxed = CONTAINER_HOME + host.project_dir[len(home) :]
        if sandboxed != host.project_dir:
            roots.append(sandboxed)
    return roots


def transcript_dir(host: Host, root: str) -> Path:
    """Where Claude Code keeps the transcripts of the sessions that knew
    the project as root: named after the path, everything but letters and
    digits dashed."""
    return Path(host.claude_dir, "projects", re.sub(r"[^A-Za-z0-9]", "-", root))


def project_root(path: Path, host: Host) -> str:
    """The project directory as the session of this transcript knew it,
    what the paths it recorded are to be compared with."""
    for root in project_roots(host):
        if transcript_dir(host, root) == path.parent:
            return root
    return host.project_dir


def transcript_dirs(host: Host) -> list[Path]:
    """Where the project's transcripts are, see project_roots."""
    return list(
        dict.fromkeys(transcript_dir(host, root) for root in project_roots(host))
    )


def transcript_files(host: Host) -> list[Path]:
    """The project's transcripts, in no order, none for a project without
    a session."""
    # The directories are writable from inside the sandbox: only plain
    # files, not a link to something else on the host or a pipe that never
    # ends
    return [
        f
        for directory in transcript_dirs(host)
        for f in directory.glob("*.jsonl")
        if f.is_file() and not f.is_symlink()
    ]


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


def open_transcript(path: Path) -> BinaryIO | None:
    """A transcript opened to be read, none when it is not there or is
    not a plain file. The directory is writable from inside the sandbox,
    and a session can put something else in a transcript's place after it
    was listed: never a link to something else on the host, nor a pipe
    that never ends."""
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
    try:
        descriptor = os.open(path, flags)
    except OSError:
        return None
    file = os.fdopen(descriptor, "rb")
    try:
        plain = stat.S_ISREG(os.fstat(descriptor).st_mode)
    except OSError:
        plain = False
    if not plain:
        file.close()
        return None
    return file


def parse_entry(line: bytes) -> dict | None:
    """The entry on a line of a transcript, none for a line that is not a
    JSON object: the last one may be half written by a running session,
    and one nested too deep to read is the session's doing."""
    try:
        entry = json.loads(line.decode("utf-8", "replace"))
    except (ValueError, RecursionError):
        return None
    return entry if isinstance(entry, dict) else None


def read_entries(path: Path) -> list[dict]:
    """The transcript's entries, none for one that cannot be read."""
    file = open_transcript(path)
    if file is None:
        return []
    with file:
        return [entry for entry in map(parse_entry, file) if entry]


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
    return entry.get("type") == "user" and not entry.get("isMeta")


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


def clip(lines: list[str], full: bool, limit: int = PREVIEW_LINES) -> list[str]:
    """Lines as shown: all of them with --full, else the first few."""
    if full:
        return lines
    shown = [
        line if len(line) <= PREVIEW_WIDTH else line[:PREVIEW_WIDTH] + "..."
        for line in lines[:limit]
    ]
    if len(lines) > limit:
        shown.append(f"... {len(lines) - limit} more lines, see --full")
    return shown


def file_path(tool_input: dict) -> str | None:
    """The file a tool call is about, for the tools that name one."""
    path = tool_input.get("file_path") or tool_input.get("notebook_path")
    return path if isinstance(path, str) else None


def bash_details(
    tool_input: dict, cwd: object, project_dir: str, full: bool
) -> list[str]:
    """A command: what ran, why (the reason Claude gave for it) and where,
    when that is not the project directory."""
    command = clip(clean(tool_input.get("command", "")).splitlines() or [""], full)
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
    name: str, path: str, tool_input: dict, project_dir: str, full: bool
) -> list[str]:
    """A call on a file: which one, flagged when it is written outside the
    project, and what an Edit changes or a Write puts there."""
    about = "file: " + flat(path)
    changes: list[str] = []
    if name == "Edit":
        changes = ["diff: " + line for line in clip(edit_diff(tool_input), full)]
    elif name == "Write":
        content = clean(tool_input.get("content", "")).splitlines()
        about += f" ({len(content)} lines)"
        changes = ["content: " + line for line in clip(content, full)]
    if name in FILE_TOOLS:
        about += outside_flag(path, project_dir)
    return [about, *changes]


def call_details(
    name: str, tool_input: dict, cwd: object, project_dir: str, full: bool
) -> list[str]:
    """The lines that describe a tool call."""
    path = file_path(tool_input)
    if name == "Bash":
        return bash_details(tool_input, cwd, project_dir, full)
    if path is not None:
        return file_details(name, path, tool_input, project_dir, full)
    # Any other tool: its arguments as they are
    return [
        line
        for key, value in tool_input.items()
        for line in clip(f"{clean(key)}: {clean(value)}".splitlines(), full)
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


def result_details(ended: dict, full: bool) -> list[str]:
    """The lines for how a tool call ended, its output among them when it
    failed or with --full."""
    if not ended:
        return ["result: none recorded (interrupted or still running)"]
    notes = ["FAILED" if ended["failed"] else "ok"]
    if "seconds" in ended:
        notes.append(f"{ended['seconds']:.1f}s")
    if "permission" in ended:
        notes.append("permission " + clean(ended["permission"]))
    details = ["result: " + ", ".join(notes)]
    if ended["failed"] or full:
        output = clean(ended["output"]).splitlines()
        details += ["out: " + line for line in clip(output, full)]
    return details


def talk_event(when: float, who: Who, block: dict, full: bool) -> Event | None:
    """A prompt or a reply, none for one without text."""
    text = clean(block.get("text", "")).strip().splitlines()
    if not full:
        # Paragraph breaks would use up the preview
        text = [line for line in text if line.strip()]
    if not text:
        return None
    what = "prompt" if who is Who.USER else "reply"
    return Event(when, who, what, clip(text, full, TALK_LINES), {"text": block["text"]})


def call_event(
    when: float, who: Who, entry: dict, block: dict, project_dir: str, full: bool
) -> Event:
    """A tool call as it was issued, how it ended is added by the walk
    that finds its result."""
    name = clean(block.get("name", "?"))
    tool_input = call_input(block)
    details = call_details(name, tool_input, entry.get("cwd"), project_dir, full)
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


class Walk:
    """Turns the entries of a transcript into events, an entry at a time
    and in their order: each prompt, reply and tool call, and ahead of what
    a step of the model did, what the step used.

    There are two ways to walk. Over a transcript that is all there, a call
    and its result are one event: the result is added to the event of its
    call when it is found, and end marks the calls left without one. Live,
    over a transcript as it is written, events are shown as they come and
    cannot change later: a result is an event of its own, named after its
    call when something else came between the two, and both carry the id
    of the call. Of what is said only the first line is shown. What a live
    walk remembers is bounded, the transcript is the session's to write."""

    def __init__(
        self,
        project_dir: str,
        full: bool,
        live: bool = False,
        usage: dict[str, dict] | None = None,
    ):
        self._project_dir = project_dir
        self._full = full
        self._live = live
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
        if kind not in ("user", "assistant"):
            return []
        stamp = local_time(entry)
        self._when = stamp.timestamp() if stamp else self._when
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
                call.event.details += result_details({}, self._full)
        self._open.clear()

    def _remember(self, kept: dict) -> None:
        """Let go of the oldest of what a live walk keeps."""
        while self._live and len(kept) > MOST_REMEMBERED:
            del kept[next(iter(kept))]

    def _step(self, who: Who, entry: dict) -> list[Event]:
        """What the step an entry starts used, nothing for a later entry
        of the same step."""
        step = step_usage(entry)
        if not step or step[0] in self._steps:
            return []
        self._steps[step[0]] = None
        self._remember(self._steps)
        used = step_event(self._when, who, self._usage.get(*step))
        return [used] if used else []

    def _talk(self, who: Who, block: dict) -> list[Event]:
        # Live just its first line, in full too: whoever follows is after
        # what the session does, what it says is on its own screen
        talk = talk_event(self._when, who, block, self._full and not self._live)
        if not talk:
            return []
        if self._live:
            del talk.details[1:]
        self._last_call = None
        return [talk]

    def _call(self, who: Who, entry: dict, block: dict) -> Event:
        event = call_event(self._when, who, entry, block, self._project_dir, self._full)
        call = str(block.get("id"))
        name = event.fields["tool"]
        label = (event.details[0] if event.details else name)[:LABEL_WIDTH]
        started = {"timestamp": entry.get("timestamp")}
        kept = None if self._live else event
        self._open[call] = OpenCall(who, name, started, label, kept)
        self._remember(self._open)
        self._last_call = call
        if self._live:
            event.fields = {"stage": "call", **event.fields}
        return event

    def _result(self, entry: dict, block: dict) -> list[Event]:
        """How a call that was seen ended: added to its event, or live an
        event of its own. Nothing for the result of any other call."""
        call = str(block.get("tool_use_id"))
        issued = self._open.pop(call, None)
        if issued is None:
            return []
        ended = outcome(issued.started, (entry, block))
        lines = result_details(ended, self._full)
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
        if self._last_call != call:
            lines.insert(0, "of: " + issued.label)
        self._last_call = None
        fields = {"stage": "result", "tool": issued.name, "id": call, **ended}
        return [Event(self._when, issued.who, issued.name.lower(), lines, fields)]


def transcript_events(entries: list[dict], project_dir: str, full: bool) -> list[Event]:
    """The events of a transcript that is all there."""
    # As the last entry of a step has it, should an earlier one be short
    usage = dict(found for found in map(step_usage, entries) if found)
    walk = Walk(project_dir, full, usage=usage)
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


def files_written(entries: list[dict], project_dir: str) -> list[str]:
    """Each file the session wrote with its tools and how often, flagged
    when it is outside the project."""
    written = Counter(
        path
        for _, block in tool_calls(entries)
        if block.get("name") in FILE_TOOLS
        for path in [file_path(call_input(block))]
        if path is not None
    )
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
        *(f"{name.ljust(12)}{value}" for name, value in rows),
        *files_written(entries, project_dir),
        *pages_fetched(entries),
    ]
