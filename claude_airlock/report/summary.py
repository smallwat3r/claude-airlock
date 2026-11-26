"""What a transcript says of its session as a whole, for the header of a
trace: what ran it, when and at what cost, how many calls it made and how
many failed, how much of what it read shows signs of being written to
instruct it, the instructions it read, the files it wrote and the pages
it fetched.

Like the rest of a transcript, all of it is the session's own word, see
events.py."""

from __future__ import annotations

from collections import Counter
from collections.abc import Iterable
from urllib.parse import urlsplit

from ..events import Event, Kind, flat, labelled
from .brief import PREVIEW_WIDTH, amount
from .calls import written_paths
from .entries import (
    INPUT_TOKENS,
    block_text,
    call_input,
    entry_times,
    every,
    every_result,
    measured,
    prompts,
    step_tokens,
    step_usage,
    tool_calls,
)
from .outcomes import outside_flag, refused, result_planted
from .planted import INJECTION, read_said
from .told import INSTRUCTIONS, attachment, instruction_files, instructions_read


def planted_reads(entries: list[dict]) -> int:
    """How many of the results of its calls and of the files it read as
    instructions show signs of being written to instruct the session,
    see planted.py. A file of instructions is read again as the session
    goes, and counts once. Every result counts, and by every tool its
    call is named as: the transcript is the session's to add to, and a
    second result under the id of a call, or a second call under it
    named as a tool whose results are not read, takes no sign away."""
    tools: dict[str, set[str]] = {}
    for _, block in tool_calls(entries):
        tools.setdefault(str(block.get("id")), set()).add(str(block.get("name")))
    results = sum(
        any(
            result_planted(tool, block_text(block.get("content")))
            for tool in tools.get(str(block.get("tool_use_id")), {""})
        )
        for _, block in every_result(entries)
    )
    files = {
        file.path
        for entry in entries
        for file in instruction_files(attachment(entry))
        if file.planted
    }
    return results + len(files)


def planted_shown(events: Iterable[Event]) -> int:
    """The same count as planted_reads, by the events of a transcript
    that tell of the signs: what was looked through to make them is not
    looked through again for the header of their trace. An event is
    taken for what it is, not for what a value of it says, and its values
    for no more than they hold: most of them are the session's to give."""
    results = 0
    files: set[str] = set()
    for event in events:
        fields = event.fields
        if event.call:
            results += bool(fields.get(INJECTION))
        elif event.kind is Kind.CONTEXT and fields.get("kind") == INSTRUCTIONS:
            for file in every(fields.get("files")):
                path = file.get("path") if isinstance(file, dict) else None
                if isinstance(path, str) and file.get(INJECTION):
                    files.add(path)
    return results + len(files)


def overview(entries: list[dict], planted: int | None = None) -> list[tuple[str, str]]:
    """The session at a glance, as labelled values: what ran it, when, at
    what cost, how many calls and how many of them failed. With how many
    of what it read show signs of being planted, counted here unless
    given."""
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
    spent = measured(cost.get("totalCostUSD"))
    if spent is not None:
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
    # Each of them: a result added under the id of a call that failed
    # does not make it one that did not
    results = every_result(entries)
    rows.append(("failed", str(sum(bool(b.get("is_error")) for _, b in results))))
    not_run = sum(refused(entry) for entry, _ in results)
    if not_run:
        rows.append(("refused", f"{not_run} calls were not allowed to run"))
    signs = planted_reads(entries) if planted is None else planted
    if signs:
        rows.append((INJECTION, f"{read_said(signs)}, see --failed"))
    return rows


def _files_written(entries: list[dict], project_dir: str) -> list[str]:
    """Each file the session wrote and how often, flagged when it is
    outside the project."""
    written = Counter(written_paths(entries))
    lines = ["files written"] if written else []
    for path, count in sorted(written.items()):
        lines.append(f"  {flat(path)} x{count}{outside_flag(path, project_dir)}")
    return lines


def _url_host(url: str) -> str:
    """The host a URL names, the URL as it is when it names none or is
    not one: it is the session's to write."""
    try:
        return urlsplit(url).hostname or url
    except ValueError:
        return url


def _pages_fetched(entries: list[dict]) -> list[str]:
    """Each host the session fetched a page from with its tools."""
    urls = [call_input(block).get("url") for _, block in tool_calls(entries)]
    hosts = Counter(_url_host(url) for url in urls if isinstance(url, str))
    lines = ["pages fetched"] if hosts else []
    return lines + [f"  {flat(host)} x{count}" for host, count in sorted(hosts.items())]


def summary(
    entries: list[dict], project_dir: str, planted: int | None = None
) -> list[str]:
    """What to know before reading on. planted as for overview."""
    rows = [("project", flat(project_dir)), *overview(entries, planted)]
    return [
        *(labelled(name, value) for name, value in rows),
        *instructions_read(entries),
        *_files_written(entries, project_dir),
        *_pages_fetched(entries),
    ]
