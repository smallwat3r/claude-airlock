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
from dataclasses import dataclass
from urllib.parse import urlsplit

from ..events import Event, Kind, flat, labelled
from .brief import PREVIEW_WIDTH, amount, shortened
from .calls import written_paths
from .entries import (
    INPUT_TOKENS,
    block_text,
    call_input,
    content_blocks,
    entry_times,
    every,
    every_result,
    measured,
    prompts,
    step_tokens,
    step_usage,
    tool_calls,
)
from .entries import MOST_LISTED as MOST_NAMED
from .given import GIVEN, texts_read
from .hooks import STOP_SUMMARY, hook_planted, summary_planted
from .outcomes import (
    OUTSIDE_FLAG,
    OUTSIDE_SANDBOX_FLAG,
    SECRETS_FLAG,
    SERVER_RESULTS,
    is_read,
    outside,
    refused,
    server_output,
)
from .planted import INJECTION, planted, read_said
from .told import (
    INSTRUCTIONS,
    attachment,
    entry_told_planted,
    files_read,
    instructions_read,
    scanned_file,
    told_from_outside,
)
from .transcript import kinds_counted, untold_kinds

# The values of a field of the entries the header names, no more than so
# many: the branches, versions and models a session ran under. Of the
# tools, the files and the hosts it names, as many as a list of the
# transcript is read to (MOST_NAMED), then how many more there are.
MOST_LISTED = 5


def _results_planted(entries: list[dict]) -> int:
    """How many of the results of the calls show signs, see planted_reads:
    those Claude Code gave the model, and those Anthropic's side gave it
    of what it ran there."""
    tools: dict[str, set[str]] = {}
    for _, block in tool_calls(entries):
        tools.setdefault(str(block.get("id")), set()).add(str(block.get("name")))
    results = sum(
        any(map(is_read, tools.get(str(block.get("tool_use_id")), {""})))
        and bool(planted(block_text(block.get("content"))))
        for _, block in every_result(entries)
    )
    server = (
        block
        for entry in entries
        if entry.get("type") == "assistant"
        for block in content_blocks(entry)
        if isinstance(block.get("type"), str) and block["type"] in SERVER_RESULTS
    )
    return results + sum(bool(planted(server_output(block)[0])) for block in server)


def _given_planted(entries: list[dict]) -> int:
    """How many of the files read as instructions and of the texts of
    given.py show signs, see planted_reads: each counts once by its path
    or by where it is from. One given again as it was is not looked at
    again, its signs are counted already."""
    looked: set[tuple[str, str, bytes]] = set()
    files: set[str] = set()
    texts: set[tuple[str, str]] = set()
    for entry in entries:
        given = attachment(entry)
        for file, content in files_read(given):
            if (INSTRUCTIONS, file.path, file.digest) not in looked:
                looked.add((INSTRUCTIONS, file.path, file.digest))
                if scanned_file(file, content).planted:
                    files.add(file.path)
        for text, said in texts_read(given):
            key = (text.kind, text.source)
            if (*key, text.digest) not in looked:
                looked.add((*key, text.digest))
                if planted(said, text.source):
                    texts.add(key)
    return len(files) + len(texts)


def planted_reads(entries: list[dict]) -> int:
    """How many of the results of its calls, of the files it read as
    instructions, of the texts of given.py, of what its hooks gave the
    model and of the prompts that came from outside the session show
    signs of being written to instruct the session, see planted.py. A
    file of instructions is read again as the session goes, and counts
    once, as does a text by where it is from. Every result counts, and by
    every tool its call is named as: the transcript is the session's to
    add to, and a second result under the id of a call, or a second call
    under it named as a tool whose results are not read, takes no sign
    away. Each result is looked at once, whatever the number of tools:
    the signs do not depend on the tool, only whether any is read. So is
    each run of a hook, and each prompt."""
    told = sum(
        bool(
            hook_planted(attachment(entry))
            or entry_told_planted(entry)
            or (
                entry.get("type") == "system"
                and entry.get("subtype") == STOP_SUMMARY
                and summary_planted(entry)
            )
        )
        for entry in entries
    )
    return _results_planted(entries) + _given_planted(entries) + told


def planted_shown(events: Iterable[Event]) -> int:
    """The same count as planted_reads, by the events of a transcript
    that tell of the signs: what was looked through to make them is not
    looked through again for the header of their trace. An event is
    taken for what it is, not for what a value of it says, and its values
    for no more than they hold: most of them are the session's to give."""
    results = 0
    read: set[tuple[object, str]] = set()
    for event in events:
        fields = event.fields
        if event.call or event.kind in (Kind.HOOK, Kind.PROMPT):
            # A result, a run of a hook, a prompt from outside the session
            results += bool(fields.get(INJECTION))
        elif event.kind is Kind.CONTEXT and fields.get("kind") == INSTRUCTIONS:
            read.update(_planted_in(fields.get("files"), "path", INSTRUCTIONS))
        elif event.kind is Kind.CONTEXT and fields.get("kind") == GIVEN:
            read.update(_planted_in(fields.get("texts"), "source", fields.get("of")))
    return results + len(read)


@dataclass(frozen=True)
class Flagged:
    """How many calls of a session the header of its trace says were
    flagged, as the events of its transcripts count them (see
    flagged_shown): those that acted outside the sandbox, through
    Anthropic (see outside_sandbox of calls.py), and those of Claude
    Code's own file tools on a file of secrets (see on_secrets)."""

    outside: int = 0
    secrets: int = 0


def flagged_shown(events: Iterable[Event]) -> Flagged:
    """The calls the events of a transcript flag, see Flagged: what the
    walk looked through to flag them is not looked through again for the
    header of their trace. A call that acted outside the sandbox counts
    once by its id, however many of its events say so (a result told
    apart from its call says it too), and a call on a file of secrets
    once for each call."""
    away: set[object] = set()
    secrets = 0
    for event in events:
        if event.call and event.fields.get("outside_sandbox"):
            away.add(event.fields.get("id"))
        secrets += bool(event.call and event.fields.get("secrets_file"))
    return Flagged(len(away), secrets)


def _planted_in(read: object, named: str, kind: object) -> set[tuple[object, str]]:
    """What of the things an event tells of shows a sign, each by its
    kind and by the field it is named in, as planted_reads counts them."""
    return {
        (kind, one[named])
        for one in every(read)
        if isinstance(one, dict) and isinstance(one.get(named), str)
        if one.get(INJECTION)
    }


def _listed(values: Iterable[object]) -> str:
    """The texts of some values, each once and sorted, as a line
    that stays one: no more than MOST_LISTED of them and each cut to the
    width of a preview, then how many more there are. Every entry can
    give a value of its own, of any length."""
    found = sorted(
        {flat(v[:PREVIEW_WIDTH]) for v in values if isinstance(v, str) and v}
    )
    if not found:
        return "?"
    more = len(found) - MOST_LISTED
    return ", ".join(found[:MOST_LISTED]) + (f", and {more} more" if more > 0 else "")


def overview(entries: list[dict], planted: int) -> list[tuple[str, str]]:
    """The session at a glance, as labelled values: what ran it, when, at
    what cost, how many calls and how many of them failed. With how many
    of what it read show signs of being planted, as its events count them
    (see planted_shown)."""
    calls = tool_calls(entries)
    times = entry_times(entries)
    last = {str(e.get("type")): e for e in entries}
    cost = last.get("cost-state", {})

    def seen(key: str) -> str:
        return _listed(e.get(key) for e in entries)

    models = [
        e["message"].get("model")
        for e in entries
        if e.get("type") == "assistant" and isinstance(e.get("message"), dict)
    ]
    rows = [
        ("branch", seen("gitBranch")),
        ("claude", seen("version")),
        ("model", _listed(model for model in models if model != "<synthetic>")),
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
    rows.append(("prompts", _prompts_said(entries)))
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

    by_tool = Counter(shortened(flat(block.get("name", "?"))) for _, block in calls)
    named = by_tool.most_common(MOST_NAMED)
    counts = ", ".join(f"{name} {count}" for name, count in named)
    if len(by_tool) > len(named):
        counts += f", and {len(by_tool) - len(named)} more"
    rows.append(("tool calls", f"{len(calls)} ({counts})" if calls else "0"))
    # Each of them: a result added under the id of a call that failed
    # does not make it one that did not
    results = every_result(entries)
    rows.append(("failed", str(sum(bool(b.get("is_error")) for _, b in results))))
    not_run = sum(refused(entry) for entry, _ in results)
    if not_run:
        rows.append(("refused", f"{not_run} calls were not allowed to run"))
    if planted:
        rows.append((INJECTION, f"{read_said(planted)}, see --failed"))
    return rows


def _prompts_said(entries: list[dict]) -> str:
    """How many prompts the user gave, and how many came from outside
    the session, by where they came from, see told_from_outside."""
    said = str(len(prompts(entries)))
    away = told_from_outside(entries)
    if not away:
        return said
    # The most first, then by name
    most = sorted(away.items(), key=lambda item: (-item[1], item[0]))[:MOST_LISTED]
    kinds = ", ".join(f"{shortened(flat(kind))} {count}" for kind, count in most)
    more = ", ..." if len(away) > MOST_LISTED else ""
    return f"{said}, and {away.total()} NOT FROM YOU ({kinds}{more}), see --failed"


def _more(count: int, flag: str = "") -> list[str]:
    """The line that says how many more there are than are named."""
    return [f"  ... {count} more{flag}"] if count > 0 else []


def _files_written(entries: list[dict], project_dir: str) -> list[str]:
    """Each file the session wrote and how often, flagged when it is
    outside the project: by a path that is not absolute, when it was
    from a directory outside, see outside. No more than MOST_NAMED, then
    how many more, those outside first: a session can write any number."""
    found = list(written_paths(entries))
    written = Counter(path for path, _ in found)
    away = {path for path, cwd in found if outside(path, project_dir, cwd)}
    lines = ["files written"] if written else []
    paths = sorted(written.items(), key=lambda item: (item[0] not in away, item[0]))
    for path, count in paths[:MOST_NAMED]:
        flag = OUTSIDE_FLAG if path in away else ""
        lines.append(f"  {shortened(flat(path))} x{count}{flag}")
    beyond = any(path in away for path, _ in paths[MOST_NAMED:])
    return lines + _more(len(paths) - MOST_NAMED, OUTSIDE_FLAG if beyond else "")


def _url_host(url: str) -> str:
    """The host a URL names, the URL as it is when it names none or is
    not one: it is the session's to write."""
    try:
        return urlsplit(url).hostname or url
    except ValueError:
        return url


def _pages_fetched(entries: list[dict]) -> list[str]:
    """Each host the session fetched a page from with its tools, no more
    than MOST_NAMED, then how many more."""
    urls = [call_input(block).get("url") for _, block in tool_calls(entries)]
    hosts = Counter(_url_host(url) for url in urls if isinstance(url, str))
    lines = ["pages fetched"] if hosts else []
    named = sorted(hosts.items())[:MOST_NAMED]
    lines += [f"  {shortened(flat(host))} x{count}" for host, count in named]
    return lines + _more(len(hosts) - len(named))


def _flagged_rows(flagged: Flagged) -> list[tuple[str, str]]:
    """How many calls acted outside the sandbox, through Anthropic, and
    how many of Claude Code's own file tools were on a file of secrets,
    none when none did, see Flagged."""
    rows = []
    if flagged.outside:
        said = f"{flagged.outside} calls {OUTSIDE_SANDBOX_FLAG}, through Anthropic"
        rows.append(("outside", f"{said}, see --failed"))
    if flagged.secrets:
        said = f"{flagged.secrets} calls of Claude Code's own tools on a {SECRETS_FLAG}"
        rows.append(("secrets", f"{said}, see --failed"))
    return rows


def _untold_rows(entries: list[dict]) -> list[tuple[str, str]]:
    """The line that counts what the transcript holds of kinds the trace
    neither reads nor knows to tell nothing (see untold_kinds), none when
    there is none: a kind Claude Code writes that is new to the trace."""
    kinds = untold_kinds(entries)
    if not kinds:
        return []
    said = f"{kinds.total()} of kinds the trace does not read ({kinds_counted(kinds)})"
    return [("untold", said)]


def summary(
    entries: list[dict], project_dir: str, planted: int, flagged: Flagged = Flagged()
) -> list[str]:
    """What to know before reading on. planted as for overview, flagged
    as the events count the calls that were, see flagged_shown."""
    rows = [
        ("project", flat(project_dir)),
        *overview(entries, planted),
        *_flagged_rows(flagged),
        *_untold_rows(entries),
    ]
    return [
        *(labelled(name, value) for name, value in rows),
        *instructions_read(entries),
        *_files_written(entries, project_dir),
        *_pages_fetched(entries),
    ]
