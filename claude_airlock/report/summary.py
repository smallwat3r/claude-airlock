"""What a transcript says of its session as a whole, for the header of a
trace: what ran it, when and at what cost, how many calls it made and how
many failed, the instructions it read, the files it wrote and the pages
it fetched.

Like the rest of a transcript, all of it is the session's own word, see
events.py."""

from __future__ import annotations

from collections import Counter
from urllib.parse import urlsplit

from ..events import flat, labelled
from .brief import PREVIEW_WIDTH, amount
from .calls import outside_flag, refused, written_paths
from .entries import (
    INPUT_TOKENS,
    call_input,
    entry_times,
    measured,
    prompts,
    step_tokens,
    step_usage,
    tool_calls,
    tool_results,
)
from .told import instructions_read


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
    results = tool_results(entries).values()
    rows.append(("failed", str(sum(bool(b.get("is_error")) for _, b in results))))
    not_run = sum(refused(entry) for entry, _ in results)
    if not_run:
        rows.append(("refused", f"{not_run} calls were not allowed to run"))
    return rows


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
