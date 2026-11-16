"""Reviewing what a session did: what it ran, where and why, what it wrote
and what it reached on the network, in the order it happened.

From the transcript Claude Code keeps of each session in ~/.claude/projects
(every prompt, reply, tool call and result), and from what the launcher
kept of the session's network use (see network.py and capture.py).

The output is plain text, one event per line or lines, each line starting
with when, who and what, so it reads as well in a file or through grep as
on a terminal. The header lines start with a #. With --json it is JSON
Lines instead, an object per event, for jq or a database.

The transcript is written from inside the sandbox, so it is a convenience
for review and not an audit log, a session could rewrite its own. For the
same reason nothing in it is trusted here: control characters are dropped
before anything is printed. The network record is the launcher's own."""

from __future__ import annotations

import difflib
import functools
import json
import os
import pydoc
import re
import socket
import subprocess
import sys
from collections import Counter
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from urllib.parse import urlsplit

from .capture import read_capture
from .network import access_log
from .settings import Fatal, Host

USAGE = "usage: claude-docker --trace [list | SESSION] [--full | --json]"
# Lines of one command, diff or output shown without --full, and of one
# prompt or reply: the conversation is context, what ran is the point
PREVIEW_LINES = 8
TALK_LINES = 3
PREVIEW_WIDTH = 200
FILE_TOOLS = ("Edit", "Write", "NotebookEdit")
PORT_USES = {
    22: "ssh",
    53: "dns",
    80: "http",
    443: "https",
    1883: "mqtt",
    2375: "docker",
    3128: "proxy",
    3306: "mysql",
    5432: "postgres",
    6379: "redis",
    27017: "mongodb",
}

# C0 and C1 controls except tab and newline, and the bidi overrides: a
# transcript could otherwise drive the terminal or reorder what is shown
_BIDI = "".join(map(chr, [*range(0x202A, 0x202F), *range(0x2066, 0x206A)]))
_UNSAFE = re.compile(r"[\x00-\x08\x0b-\x1f\x7f-\x9f" + _BIDI + "]")


@dataclass
class Event:
    """Something that happened: when (seconds since the epoch), who did it
    (user, claude, agent for a subagent, sandbox for the container as a
    whole), what kind of thing, and the lines that describe it."""

    when: float
    who: str
    what: str
    details: list[str]
    # The same as named values, for --json
    fields: dict


def clean(value: object) -> str:
    text = value if isinstance(value, str) else json.dumps(value, ensure_ascii=False)
    return _UNSAFE.sub("", text)


def flat(value: object) -> str:
    """Cleaned and on one line, for a value that has to stay with its
    label: a line break in a path or a reason is shown, not followed."""
    return "\\n".join(clean(value).splitlines())


def transcript_dir(host: Host) -> Path:
    """Where Claude Code keeps the project's transcripts. The project is
    mounted at its host path, so the name is the same in and out of the
    sandbox: the path with everything but letters and digits dashed."""
    name = re.sub(r"[^A-Za-z0-9]", "-", host.project_dir)
    return Path(host.claude_dir, "projects", name)


def session_files(host: Host) -> list[Path]:
    """The project's transcripts, the latest session first."""
    directory = transcript_dir(host)
    # The directory is writable from inside the sandbox: only plain files,
    # not a link to something else on the host or a pipe that never ends
    files = sorted(
        (f for f in directory.glob("*.jsonl") if f.is_file() and not f.is_symlink()),
        key=lambda f: f.stat().st_mtime,
        reverse=True,
    )
    if not files:
        raise Fatal(f"no session recorded for this project (looked in {directory})")
    return files


def read_entries(path: Path) -> list[dict]:
    """The transcript's entries. A line that is not a JSON object is
    skipped, the last one may be half written by a running session. Also
    reads the launcher's own record of filtered sessions, none if it has
    not been written yet."""
    entries = []
    try:
        with open(path, encoding="utf-8", errors="replace") as lines:
            for line in lines:
                try:
                    entry = json.loads(line)
                except ValueError:
                    continue
                if isinstance(entry, dict):
                    entries.append(entry)
    except FileNotFoundError:
        pass
    return entries


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


def call_details(
    name: str, tool_input: dict, cwd: object, project_dir: str, full: bool
) -> list[str]:
    """The lines that describe a tool call: what it ran or touched, why
    (the reason Claude gave for a command) and where, when that is not the
    project directory."""
    path = tool_input.get("file_path") or tool_input.get("notebook_path")
    if name == "Bash":
        command = clip(clean(tool_input.get("command", "")).splitlines() or [""], full)
        details = ["$ " + command[0], *("$   " + line for line in command[1:])]
        if tool_input.get("description"):
            details.append("why: " + flat(tool_input["description"]))
        if isinstance(cwd, str) and cwd != project_dir:
            details.append("cwd: " + flat(cwd))
        return details
    if isinstance(path, str):
        flag = "  OUTSIDE PROJECT" if outside(path, project_dir) else ""
        details = [f"file: {flat(path)}{flag if name in FILE_TOOLS else ''}"]
        if name == "Edit":
            diff = difflib.unified_diff(
                clean(tool_input.get("old_string", "")).splitlines(),
                clean(tool_input.get("new_string", "")).splitlines(),
                lineterm="",
                n=1,
            )
            # Without the --- and +++ lines, the file is named above
            details += ["diff: " + line for line in clip(list(diff)[2:], full)]
        elif name == "Write":
            content = clean(tool_input.get("content", "")).splitlines()
            details[0] += f" ({len(content)} lines)"
            details += ["content: " + line for line in clip(content, full)]
        return details
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


def transcript_events(entries: list[dict], project_dir: str, full: bool) -> list[Event]:
    """The transcript as events: each prompt, reply and tool call, a call
    together with how it ended."""
    results = tool_results(entries)
    events = []
    # An entry without a time of its own happened with the one before it
    when = 0.0
    for entry in entries:
        if entry.get("type") not in ("user", "assistant"):
            continue
        stamp = local_time(entry)
        when = stamp.timestamp() if stamp else when
        by_claude = entry["type"] == "assistant"
        who = "agent" if entry.get("isSidechain") else "claude" if by_claude else "user"
        for block in content_blocks(entry):
            kind = block.get("type")
            if kind == "text" and (by_claude or is_prompt(entry)):
                text = clean(block.get("text", "")).strip().splitlines()
                if not full:
                    # Paragraph breaks would use up the preview
                    text = [line for line in text if line.strip()]
                if text:
                    what = "reply" if by_claude else "prompt"
                    shown = clip(text, full, TALK_LINES)
                    fields = {"text": block.get("text", "")}
                    events.append(Event(when, who, what, shown, fields))
            elif kind == "tool_use" and by_claude:
                name = clean(block.get("name", "?"))
                tool_input = call_input(block)
                cwd = entry.get("cwd")
                ended = outcome(entry, results.get(str(block.get("id"))))
                details = call_details(name, tool_input, cwd, project_dir, full)
                details += result_details(ended, full)
                fields = {"tool": name, "input": tool_input, "cwd": cwd, **ended}
                path = tool_input.get("file_path") or tool_input.get("notebook_path")
                if name in FILE_TOOLS and isinstance(path, str):
                    fields["outside_project"] = outside(path, project_dir)
                events.append(Event(when, who, name.lower(), details, fields))
    return events


def summary(entries: list[dict], project_dir: str) -> list[str]:
    """What to know before reading on: when, how much, which files were
    written and which calls failed."""
    calls = tool_calls(entries)
    results = tool_results(entries)
    times = [when for when in map(local_time, entries) if when]
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
        ("project", clean(project_dir)),
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

    by_tool = Counter(clean(block.get("name", "?")) for _, block in calls)
    counts = ", ".join(f"{name} {count}" for name, count in by_tool.most_common())
    rows.append(("tool calls", f"{len(calls)} ({counts})" if calls else "0"))
    failed = sum(1 for _, block in results.values() if block.get("is_error"))
    rows.append(("failed", str(failed)))

    written: Counter[str] = Counter()
    hosts: Counter[str] = Counter()
    for _, block in calls:
        tool_input = call_input(block)
        path = tool_input.get("file_path") or tool_input.get("notebook_path")
        if block.get("name") in FILE_TOOLS and isinstance(path, str):
            written[path] += 1
        if isinstance(tool_input.get("url"), str):
            hosts[urlsplit(tool_input["url"]).hostname or tool_input["url"]] += 1

    lines = [f"{name.ljust(12)}{value}" for name, value in rows]
    if written:
        lines.append("files written")
        for path, count in sorted(written.items()):
            flag = "  OUTSIDE PROJECT" if outside(path, project_dir) else ""
            lines.append(f"  {flat(path)} x{count}{flag}")
    if hosts:
        lines.append("pages fetched")
        lines += [f"  {clean(host)} x{count}" for host, count in sorted(hosts.items())]
    return lines


def recorded_sessions(host: Host, start: float, end: float) -> list[dict]:
    """The sessions of this project with a network record that ran at some
    point between start and end. A filtered one, known by its address, ran
    until a later session was given the same address."""
    sessions = [
        s
        for s in read_entries(Path(host.net_sessions_file))
        if isinstance(s.get("start"), (int, float))
    ]
    found = []
    for session in sessions:
        until = session.get("end")
        if not isinstance(until, (int, float)):
            later = [
                s["start"]
                for s in sessions
                if s.get("ip") == session.get("ip") and s["start"] > session["start"]
            ]
            until = min(later, default=float("inf"))
        mine = session.get("project") == host.project_dir
        if mine and session["start"] <= end and until >= start:
            found.append({**session, "until": until})
    return found


def size(count: int) -> str:
    amount = float(count)
    for unit in ("B", "kB", "MB"):
        if amount < 1000:
            return f"{amount:.0f} {unit}"
        amount /= 1000
    return f"{amount:.1f} GB"


@functools.cache
def over(transport: str, port: int) -> str:
    """How a connection was made and, going by its port, what for:
    tcp/https, proxy/ssh, plain tcp for a port without a known use. The
    usual ones are named here, a host need not have a services file."""
    if port in PORT_USES:
        return f"{transport}/{PORT_USES[port]}"
    try:
        return f"{transport}/{socket.getservbyport(port, 'tcp')}"
    except (OSError, OverflowError):
        return transport


def proxy_requests(
    sessions: list[dict], start: float, end: float
) -> tuple[list[str], list[Event]]:
    """What filtered sessions asked the egress proxy for, as summary lines
    (each destination with its number of requests and bytes, the refused
    ones first) and as one event per request. From the proxy's log, by the
    address each session's container had and the time the transcript
    spans."""
    log = access_log(stderr=subprocess.DEVNULL)
    if log is None:
        return ["  the egress proxy is not running, its log cannot be read"], []

    events = []
    totals: Counter[tuple[bool, str]] = Counter()
    volume: Counter[tuple[bool, str]] = Counter()
    for line in log.splitlines():
        fields = line.split()
        try:
            ended, took = float(fields[0]), float(fields[1]) / 1000
            address, result, sent, method, url = fields[2:7]
            count = int(sent)
        except (IndexError, ValueError):
            continue
        # A request counts when it was open at some point of the session,
        # the proxy logs a tunnel when it closes, which can be much later
        if not any(
            s["ip"] == address
            and ended >= max(start, s["start"])
            and ended - took <= min(end, s["until"])
            for s in sessions
        ):
            continue
        denied = "DENIED" in result
        method, url = clean(method), clean(url)
        totals[(denied, url)] += 1
        volume[(denied, url)] += count
        try:
            # CONNECT names host:port, the other methods a whole URL
            target = urlsplit(url if "://" in url else "//" + url)
            port = target.port or (443 if target.scheme == "https" else 80)
        except ValueError:
            port = 0
        verdict = "DENIED" if denied else "allowed"
        detail = f"{over('proxy', port)} {method} {url} {verdict} {size(count)}"
        values = {
            "protocol": over("proxy", port),
            "method": method,
            "url": url,
            "port": port,
            "denied": denied,
            "bytes": count,
            "seconds": took,
        }
        text = [f"{detail} {took:.1f}s"]
        events.append(Event(ended - took, "sandbox", "net", text, values))

    lines = []
    if len(sessions) > 1:
        names = ", ".join(sorted({clean(s.get("name", "?")) for s in sessions}))
        lines.append(f"  from {names}, which ran in this time and are not told apart")
    if not totals:
        lines.append("  no request in the egress proxy's log")
    # Refused first, then the busiest
    for (denied, url), number in sorted(
        totals.items(), key=lambda item: (not item[0][0], -item[1], item[0][1])
    ):
        verdict = "DENIED " if denied else "allowed"
        lines.append(f"  {verdict}  {url} x{number}  {size(volume[(denied, url)])}")
    return lines, events


def captured_connections(
    host: Host, session: dict, full: bool
) -> tuple[list[str], list[Event]]:
    """What a captured session connected to, as summary lines (each
    destination, by name where the capture has one, with its number of
    connections) and as one event per connection, with --full also per
    name looked up. Of the container's whole stay, a capture is not tied
    to one transcript."""
    began = datetime.fromtimestamp(session["start"])
    ended = datetime.fromtimestamp(session["until"])
    name = clean(session.get("name", "?"))
    lines = [f"  captured in {name} from {began:%H:%M:%S} to {ended:%H:%M:%S}"]
    try:
        # Only ever a file of the captures directory, whatever the record says
        file = Path(host.captures_dir, os.path.basename(str(session.get("capture"))))
        capture = read_capture(file)
    except OSError:
        return [*lines, "  its capture is no longer kept"], []

    def destination(address: str, port: int) -> str:
        known = capture.names.get(address)
        return clean(f"{known} ({address}):{port}" if known else f"{address}:{port}")

    events = []
    reached: Counter[str] = Counter()
    for when, address, port in capture.connections:
        reached[f"{over('tcp', port)} {destination(address, port)}"] += 1
        detail = f"{over('tcp', port)} {destination(address, port)}"
        fields = {
            "protocol": over("tcp", port),
            "name": capture.names.get(address),
            "address": address,
            "port": port,
        }
        events.append(Event(when, "sandbox", "net", [detail], fields))
    for connection, number in sorted(reached.items(), key=lambda i: (-i[1], i[0])):
        lines.append(f"  {connection} x{number}")
    if not reached:
        lines.append("  no connection")
    looked_up = {lookup for _, lookup in capture.lookups}
    if looked_up:
        hint = "" if full else ", each one shown with --full"
        lines.append(f"  dns {len(looked_up)} names looked up{hint}")
    if capture.cut_short:
        lines.append("  STOPPED at its packet limit, what came later is missing")
    if full:
        events += [
            Event(when, "sandbox", "dns", ["lookup " + clean(lookup)], {"name": lookup})
            for when, lookup in capture.lookups
        ]
    return lines, events


def network(
    host: Host, entries: list[dict], full: bool
) -> tuple[list[str], list[Event]]:
    """What the session did on the network, from what the launcher kept of
    it: the egress proxy's log for a filtered session, a capture for one
    run without CLAUDE_DOCKER_NET_LOG=0."""
    times = [when.timestamp() for when in map(local_time, entries) if when]
    if not times:
        return [], []
    start, end = times[0], times[-1]
    sessions = recorded_sessions(host, start, end)
    if not sessions:
        return [
            "network     not recorded (CLAUDE_DOCKER_NET_LOG=0, or not sandboxed)"
        ], []
    lines, events = ["network"], []
    filtered = [s for s in sessions if isinstance(s.get("ip"), str)]
    if filtered:
        found = proxy_requests(filtered, start, end)
        lines += found[0]
        events += found[1]
    for session in sessions:
        if isinstance(session.get("capture"), str):
            found = captured_connections(host, session, full)
            lines += found[0]
            events += found[1]
    return lines, events


def session_events(path: Path, host: Host, full: bool) -> tuple[list[str], list[Event]]:
    """The header lines of a session and its events, those of the
    transcript and of the network record together, in the order they
    happened."""
    entries = read_entries(path)
    net_lines, net_events = network(host, entries, full)
    header = [
        f"session     {flat(path.stem)}  {title(entries)}",
        *summary(entries, host.project_dir),
        *net_lines,
    ]
    # Stable, so what the transcript has at the same time keeps its order
    events = sorted(
        transcript_events(entries, host.project_dir, full) + net_events,
        key=lambda event: event.when,
    )
    return header, events


def render(path: Path, host: Host, full: bool) -> str:
    """The trace as text: the header, then every event, each of its lines
    starting with when, who and what."""
    header, events = session_events(path, host, full)
    header += ["", "time                 who      what      details"]

    # Whatever a value holds, no line of the output starts without its
    # prefix: a line break in one must not pass for the start of an event
    def prefixed(start: str, texts: list[str]) -> list[str]:
        return [
            (start + line).rstrip()
            for text in texts
            for line in (text.splitlines() or [""])
        ]

    lines = prefixed("# ", header)
    for event in events:
        clock = f"{datetime.fromtimestamp(event.when):%Y-%m-%d %H:%M:%S}"
        lines += prefixed(f"{clock}  {event.who:<7}  {event.what:<8}  ", event.details)
    return "\n".join(lines) + "\n"


def render_json(path: Path, host: Host) -> str:
    """The trace as JSON Lines, an object per event: the session, time
    (ISO 8601 with its offset), who, what, then the values of that kind of
    event, nothing shortened. Every line names its session, so the traces
    of several can go into one file or table. Escaped by the encoder, which
    leaves no control character to reach a terminal."""
    _, events = session_events(path, host, full=True)
    lines = []
    for event in events:
        when = datetime.fromtimestamp(event.when).astimezone()
        about = {
            "session": path.stem,
            "time": when.isoformat(timespec="milliseconds"),
            "who": event.who,
            "what": event.what,
        }
        lines.append(json.dumps({**about, **event.fields}))
    return "\n".join(lines) + "\n"


def list_sessions(files: list[Path]) -> str:
    """One line per session, the latest first: when it started, the start
    of its id (enough to name it to --trace), its size and its title."""
    lines = []
    for path in files:
        entries = read_entries(path)
        times = [when for when in map(local_time, entries) if when]
        started = f"{times[0]:%Y-%m-%d %H:%M}" if times else " " * 16
        lines.append(
            f"{started}  {flat(path.stem)[:8]}  {len(prompts(entries)):3d} prompts"
            f"  {len(tool_calls(entries)):4d} calls  {title(entries)}"
        )
    return "\n".join(lines) + "\n"


def show(text: str) -> None:
    """Through the pager on a terminal, as it is when piped."""
    if sys.stdout.isatty():
        pydoc.pager(text)
    else:
        sys.stdout.write(text)


def trace(host: Host, args: list[str]) -> int:
    """Show what a session of this project did: the latest one, or the one
    whose id starts with the given text, as text or with --json as JSON
    Lines. "list" lists them instead."""
    full, as_json = "--full" in args, "--json" in args
    names = [arg for arg in args if arg not in ("--full", "--json")]
    if len(names) > 1 or any(name.startswith("-") for name in names):
        raise Fatal(USAGE)
    files = session_files(host)
    if names == ["list"]:
        show(list_sessions(files))
        return 0
    if names:
        files = [path for path in files if path.stem.startswith(names[0])]
        if len(files) != 1:
            problem = "matches several sessions" if files else "matches no session"
            raise Fatal(f"{names[0]} {problem}, see claude-docker --trace list")
    show(render_json(files[0], host) if as_json else render(files[0], host, full))
    return 0
