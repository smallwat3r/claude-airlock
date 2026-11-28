"""How --trace stats shows what stats.py counted: as the lines of a header
(see Layout.header), or as one JSON object.

What the sessions wrote is cleaned and cut before it is shown. Of each
kind of name the text names the MOST_SHOWN counted most, the JSON every
one that was kept."""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Callable, Hashable
from dataclasses import asdict
from datetime import datetime

from ..events import flat, labelled
from .brief import shortened
from .outcomes import OUTSIDE_FLAG
from .planted import read_said
from .shown import size
from .stats import (
    COMMAND_TOOL,
    Destination,
    Flags,
    Network,
    Opened,
    Rank,
    SessionLine,
    Stats,
    Tally,
    by,
)
from .summary import tokens_said, tools_said

# Of each kind of name, how many the text names, the most first
MOST_SHOWN = 10
# The order files are shown in: those written outside the project first,
# so that no number of others can leave them unnamed
FILES_RANK: Rank = by("outside", "writes")
# How each kind of thing flagged is said, by its count
FLAGS_SAID: dict[str, Callable[[int], str]] = {
    "injections": read_said,
    "outside_sandbox": lambda count: f"{count} calls OUTSIDE THE SANDBOX",
    "secrets_calls": lambda count: f"{count} calls on a FILE OF SECRETS",
    "outside_project": lambda count: f"{count} files written {OUTSIDE_FLAG.strip()}",
    "removed": lambda count: f"{count} entries REMOVED FROM A TRANSCRIPT",
}


def stats_lines(stats: Stats) -> list[str]:
    """The stats as the lines of a header."""
    span = ""
    if stats.first and stats.last:
        span = f", {stats.first:%Y-%m-%d %H:%M} to {stats.last:%Y-%m-%d %H:%M}"
    of = f"{len(stats.sessions)} sessions of {flat(stats.project)}{span}"
    lines = [labelled("stats", of)]
    if stats.since is not None:
        since = datetime.fromtimestamp(stats.since)
        said = f"{since:%Y-%m-%d %H:%M}, by when each was last written"
        lines.append(labelled("since", said))
    if not stats.sessions:
        return lines
    return [
        *lines,
        *_calls_lines(stats),
        *_named_lines(stats),
        *_network_lines(stats.network),
        labelled("sessions", "the latest first"),
        *map(_session_line, stats.latest_first()),
    ]


def stats_json(stats: Stats) -> str:
    """The stats as one JSON object on a line, every name that was kept
    with its counts, and how many were counted past those."""
    network = stats.network
    tallies: dict[str, Tally] = {
        "commands": stats.commands,
        "files_written": stats.files,
        "pages_fetched": stats.pages,
        "destinations": network.destinations,
        "secrets_opened": network.secrets,
    }
    said = {
        "what": "stats",
        "project": stats.project,
        "since": _iso(
            datetime.fromtimestamp(stats.since) if stats.since is not None else None
        ),
        "first": _iso(stats.first),
        "last": _iso(stats.last),
        "sessions": len(stats.sessions),
        "prompts": stats.prompts,
        "not_from_you": stats.not_from_you,
        "calls": dict(stats.calls.most_common()),
        "failed": stats.failed,
        "refused": stats.refused,
        "tokens": asdict(stats.tokens),
        "cost": round(stats.cost, 6) if stats.costed else None,
        "costed_sessions": stats.costed,
        "flagged": asdict(stats.flags),
        "commands": _named(stats.commands, "program", by("calls")),
        "files_written": [
            {
                "path": path,
                "writes": counts["writes"],
                "outside": bool(counts["outside"]),
            }
            for path, counts in stats.files.most(FILES_RANK)
        ],
        "pages_fetched": _named(stats.pages, "host", by("fetches")),
        "reached": dict(network.destinations.totals),
        "destinations": [
            {**where._asdict(), **counts}
            for where, counts in network.destinations.most(_reached_rank)
        ],
        "model_requests": network.model_requests,
        "uploads": network.uploads,
        "uploaded_bytes": network.uploaded,
        "inbound": network.inbound,
        "stand_out": network.stand_out,
        "processes": network.processes,
        "doors": dict(network.doors),
        "secrets_opened": [
            {**opened._asdict(), **counts}
            for opened, counts in network.secrets.most(by("opened"))
        ],
        "left_out": {
            name: tally.left_out for name, tally in tallies.items() if tally.left_out
        },
        "per_session": [
            {**asdict(one), "last": _iso(one.last)} for one in stats.latest_first()
        ],
    }
    # What makes the values keeps NaN and the infinities out
    return json.dumps(said, allow_nan=False) + "\n"


def _calls_lines(stats: Stats) -> list[str]:
    """What was asked and called, at what cost, and what was flagged."""
    asked = str(stats.prompts)
    if stats.not_from_you:
        asked += f", and {stats.not_from_you} NOT FROM YOU"
    lines = [
        labelled("prompts", asked),
        labelled("tool calls", tools_said(stats.calls)),
        labelled("failed", str(stats.failed)),
    ]
    if stats.refused:
        lines.append(
            labelled("refused", f"{stats.refused} calls were not allowed to run")
        )
    if stats.tokens.steps:
        lines.append(labelled("tokens", tokens_said(stats.tokens)))
    if stats.costed:
        unsaid = len(stats.sessions) - stats.costed
        of_them = f", {unsaid} sessions do not say" if unsaid else ""
        lines.append(labelled("cost", f"${stats.cost:.2f}{of_them}"))
    flagged = _flags_said(stats.flags)
    return lines + ([labelled("flagged", flagged)] if flagged else [])


def _flags_said(flags: Flags) -> str:
    """What was flagged, empty for nothing."""
    counts = asdict(flags)
    said = ", ".join(
        say(counts[name]) for name, say in FLAGS_SAID.items() if counts[name]
    )
    return f"{said}, see --trace SESSION --failed" if said else ""


def _named_lines(stats: Stats) -> list[str]:
    """The programs run, the files written and the pages fetched most."""
    lines = []
    if stats.commands:
        calls = stats.calls[COMMAND_TOOL]
        said = f"by the programs they run, of {calls} calls of {COMMAND_TOOL}"
        listed = _listed(stats.commands, by("calls"), _program_said)
        lines += [labelled("commands", said), *listed]
    if stats.files:
        lines += ["files written", *_listed(stats.files, FILES_RANK, _written_said)]
    if stats.pages:
        lines += ["pages fetched", *_listed(stats.pages, by("fetches"), _fetched_said)]
    return lines


def _network_lines(network: Network) -> list[str]:
    """Where the sandboxes reached, the rest of what was recorded on the
    network and of the processes, the doors used and the files of
    secrets opened."""
    where = network.destinations
    said = [_reached_said(where)] if where else []
    recorded = (
        (network.model_requests, "requests to the model seen on the wire"),
        (network.uploads, f"uploads elsewhere, {size(network.uploaded)}"),
        (network.inbound, "connections made to a session from outside"),
        (network.stand_out, "connections and lookups that stand out"),
        (network.processes, "processes seen to run"),
    )
    said += [f"{count} {what}" for count, what in recorded if count]
    lines = []
    if said:
        lines.append(labelled("network", said[0]))
        lines += _listed(where, _reached_rank, _destination_said)
        lines += [f"  {text}" for text in said[1:]]
    if network.doors:
        used = ", ".join(
            f"{door} {count}" for door, count in sorted(network.doors.items())
        )
        lines.append(labelled("doors", f"used: {used}"))
    if network.secrets:
        opened = network.secrets.totals["opened"]
        lines.append(labelled("secrets", f"{opened} files of secrets opened"))
        lines += _listed(network.secrets, by("opened"), _opened_said)
    return lines


def _reached_said(where: Tally[Destination]) -> str:
    """How often the sandboxes reached how many destinations, how much
    went either way and how often it failed."""
    totals = where.totals
    ways = [
        f"{totals[key]} {said}"
        for key, said in (
            ("connections", "connections"),
            ("requests", "requests through the egress proxy"),
        )
        if totals[key]
    ]
    more = "more than " if where.left_out else ""
    parts = [f"{' and '.join(ways)} to {more}{len(where)} destinations"]
    parts += _carried(totals)
    if totals["failed"]:
        parts.append(f"{totals['failed']} REFUSED or unanswered")
    if totals["denied"]:
        parts.append(f"{totals['denied']} DENIED")
    return ", ".join(parts)


def _reached_rank(counts: Counter[str]) -> tuple[int, ...]:
    """A destination by how often it was reached, either way, see Rank."""
    return (counts["connections"] + counts["requests"],)


def _listed[Name: Hashable](
    tally: Tally[Name], rank: Rank, said: Callable[[Name, Counter[str]], str]
) -> list[str]:
    """The names ranked highest, no more than MOST_SHOWN, each a line
    under a line of the header, then how many more there are."""
    most = tally.most(rank)
    lines = [f"  {said(name, counts)}" for name, counts in most[:MOST_SHOWN]]
    if len(most) > MOST_SHOWN:
        lines.append(f"  ... {len(most) - MOST_SHOWN} more, see --json")
    if tally.left_out:
        kept = tally.most_kept
        lines.append(f"  ... and {tally.left_out} counted past the {kept} kept")
    return lines


def _program_said(program: str, counts: Counter[str]) -> str:
    failed = f", {counts['failed']} of them FAILED" if counts["failed"] else ""
    return f"{_cut(program)} x{counts['calls']}{failed}"


def _written_said(path: str, counts: Counter[str]) -> str:
    away = OUTSIDE_FLAG if counts["outside"] else ""
    return f"{_cut(path)} x{counts['writes']}{away}"


def _fetched_said(host: str, counts: Counter[str]) -> str:
    return f"{_cut(host)} x{counts['fetches']}"


def _destination_said(where: Destination, counts: Counter[str]) -> str:
    parts = [f"x{counts['connections']}"] if counts["connections"] else []
    if counts["requests"]:
        parts.append(f"{counts['requests']} requests through the egress proxy")
    parts += _carried(counts)
    parts += [f"{counts['failed']} failed"] if counts["failed"] else []
    parts += [f"{counts['denied']} DENIED"] if counts["denied"] else []
    return f"{_cut(f'{where.protocol} {where.name}:{where.port}')} {', '.join(parts)}"


def _opened_said(opened: Opened, counts: Counter[str]) -> str:
    return f"{_cut(f'{opened.path}, {opened.said}')} x{counts['opened']}"


def _carried(counts: Counter[str]) -> list[str]:
    """How much went out and came in, as far as the records say."""
    return [
        f"{size(counts[key])} {way}"
        for key, way in (("bytes_out", "out"), ("bytes_in", "in"))
        if counts[key]
    ]


def _session_line(one: SessionLine) -> str:
    when = f"{one.last:%Y-%m-%d %H:%M}" if one.last else ""
    cost = f"${one.cost:.2f}" if one.cost is not None else ""
    flagged = f"  {one.flagged} FLAGGED" if one.flagged else ""
    return (
        f"  {when:16}  {flat(one.session)[:8]:8}  {one.prompts:3d} prompts"
        f"  {one.calls:4d} calls  {one.failed:3d} failed  {cost:>8}"
        f"{flagged}  {one.title}"
    )


def _named(tally: Tally[str], name: str, rank: Rank) -> list[dict]:
    """Every name kept with its counts, those ranked highest first, for
    the JSON."""
    return [{name: named, **counts} for named, counts in tally.most(rank)]


def _cut(text: str) -> str:
    """What a session wrote, as a line shows it."""
    return shortened(flat(text))


def _iso(when: datetime | None) -> str | None:
    """A time as the JSON of a trace has it, see event_json."""
    return when.astimezone().isoformat(timespec="milliseconds") if when else None
