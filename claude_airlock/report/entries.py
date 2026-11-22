"""The entries of the transcript Claude Code keeps of each session in
~/.claude/projects: finding the transcripts, reading one, and what an
entry holds, each value taken with care.

The transcript is written from inside the sandbox, so nothing in it is
trusted here, see events.py: a value is what it should be or it is none,
a count is one a session could reach, a list and a text are bounded."""

from __future__ import annotations

from datetime import datetime
from pathlib import Path

from ..errors import Fatal
from ..events import Who, clean, flat
from ..files import UNREADABLE, bounded_lines, json_object, line_entry, open_plain
from ..projects import transcript_dirs, transcript_files
from ..settings import Host

# The times an entry can say it was written at, as seconds since the
# epoch: any other is not one a session ran at, and not one every
# platform and time zone can show as a date
EARLIEST, LATEST = 86400.0, 2e11
# What a step of the model read, as the API counts it: not cached, newly
# put in the cache, and read from it
INPUT_TOKENS = (
    "input_tokens",
    "cache_creation_input_tokens",
    "cache_read_input_tokens",
)
# Of one list a transcript gives (files, names, messages), how much is
# read and shown
MOST_LISTED = 50
# Of a path or a name that is kept to tell a change by
KEPT_WIDTH = 4096
# More than a session could count: a number above it is not a count
MOST_COUNTED = 10**15
# Of a transcript, as much as is read: what the launcher copies of one at
# most (see recorder.py). What is said in the place of the rest.
MOST_READ = 512 * 1024 * 1024
NOT_ALL_READ = f"(the rest of the transcript, past {MOST_READ >> 20} MB, was not read)"
# Of a session id, as much as names it in a line
SHORT_ID = 8


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


def short_id(path: Path) -> str:
    """The start of the session id of a transcript, enough to name the
    session in a line and to --trace."""
    return flat(path.stem)[:SHORT_ID]


def read_entries(path: Path) -> list[dict]:
    """The transcript's entries, none for one that cannot be read. Of one
    longer than MOST_READ those of its start, then an entry that says the
    rest was not read: a session can make its transcript as long as the
    disk, and all of it is held here."""
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
            if file.tell() >= MOST_READ:
                if file.read(1):
                    entries.append({"type": UNREADABLE, "text": NOT_ALL_READ})
                break
    return entries


def counted(value: object) -> int | None:
    """A count a transcript gives, none for what is not one."""
    if type(value) is not int or not 0 <= value <= MOST_COUNTED:
        return None
    return value


def measured(value: object) -> float | None:
    """A count, a cost or a length of time Claude Code gives, in a
    transcript or to a chat, none for what is not one."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    # Not a number and the infinities are not within it either
    return float(value) if 0 <= value <= MOST_COUNTED else None


def seconds(value: object) -> float | None:
    """Milliseconds a transcript gives as seconds, none for what is not
    a length of time."""
    spent = measured(value)
    return None if spent is None else spent / 1000


def kept(value: object) -> str:
    """A text as it is kept to tell a change by, empty for what is none."""
    return value[:KEPT_WIDTH] if isinstance(value, str) else ""


def every(value: object) -> list:
    """A list a transcript gives, empty for what is none."""
    return value if isinstance(value, list) else []


def listed(value: object) -> list:
    """The start of a list a transcript gives, empty for what is none."""
    return every(value)[:MOST_LISTED]


def claude_of(entry: dict) -> Who:
    """Which of the two an entry of the model's side is of: a subagent,
    whose entries Claude Code marks, or claude itself."""
    return Who.AGENT if entry.get("isSidechain") else Who.CLAUDE


def local_time(entry: dict) -> datetime | None:
    stamp = entry.get("timestamp")
    if not isinstance(stamp, str):
        return None
    try:
        # fromisoformat only takes a trailing Z from Python 3.11
        when = datetime.fromisoformat(stamp.replace("Z", "+00:00"))
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
    return counted(count) or 0


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


def unreadable_lines(entries: list[dict]) -> int:
    """How many of the lines entries were read from cannot be read, see
    line_entry of files.py."""
    return sum(entry.get("type") == UNREADABLE for entry in entries)
