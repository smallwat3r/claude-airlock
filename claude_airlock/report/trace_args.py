"""The arguments of --trace, which --trace --follow takes too: the options
among them, the session they name, and the events they ask for."""

from __future__ import annotations

import re
import time
from datetime import datetime
from pathlib import Path
from typing import NamedTuple

from ..errors import Fatal
from ..events import flat
from .entries import sessions_named
from .stream import Filter

USAGE = (
    "usage: claude-airlock --trace [list | all | stats | SESSION] [--since WHEN]"
    " [--follow] [--verbose | --json] [--only KIND,...] [--failed]"
)
# What --trace takes in the place of a session: each is of all of them
LIST, ALL, STATS = "list", "all", "stats"
# What --since takes a span of time in, as so many of: 30m, 12h, 7d, 2w
SINCE_UNITS = {"m": 60, "h": 3600, "d": 86400, "w": 7 * 86400}
# The most of a unit it takes, past which a span is not worth the number
MOST_SINCE = 99_999


class TraceArgs(NamedTuple):
    """The arguments of --trace: the options among them, what it is of
    (a session, list, all or stats, none for the latest session), the
    events asked for, and from when the sessions are, none for all of
    them."""

    options: set[str]
    name: str | None
    chosen: Filter
    since: float | None


def since_time(value: str, now: float) -> float:
    """What --since says as a time: so long before now (30m, 12h, 7d,
    2w), or a day or a time of it in local time (2026-11-20,
    2026-11-20T10:00)."""
    if not value:
        raise Fatal(USAGE)
    span = re.fullmatch(r"([0-9]{1,5})([mhdw])", value)
    if span and int(span[1]) <= MOST_SINCE:
        return now - int(span[1]) * SINCE_UNITS[span[2]]
    try:
        return datetime.fromisoformat(value).timestamp()
    except (ValueError, OverflowError, OSError):
        raise Fatal(
            f"--since {flat(value)!r} is neither a span (30m, 12h, 7d, 2w) nor"
            " a day or time (2026-11-20, 2026-11-20T10:00)"
        ) from None


def trace_options(args: list[str], known: tuple[str, ...]) -> TraceArgs:
    """The arguments of --trace, see TraceArgs: --only takes its kinds
    after an = or as the next argument, separated by commas, and --since
    its time the same way, see since_time. Refused when they cannot be
    taken together, see _refuse_unfit."""
    options: set[str] = set()
    names: list[str] = []
    only: set[str] = set()
    failed = False
    since: float | None = None
    rest = iter(args)
    for arg in rest:
        option, has_value, value = arg.partition("=")
        if option == "--only":
            kinds = (value if has_value else next(rest, "")).lower().split(",")
            only |= {kind.strip() for kind in kinds if kind.strip()}
            if not only:
                raise Fatal(USAGE)
        elif option == "--since" and since is None:
            since = since_time(value if has_value else next(rest, ""), time.time())
        elif arg == "--failed":
            failed = True
        elif arg in known:
            options.add(arg)
        else:
            names.append(arg)
    if len(names) > 1 or any(name.startswith("-") for name in names):
        raise Fatal(USAGE)
    given = TraceArgs(
        options, names[0] if names else None, Filter(frozenset(only), failed), since
    )
    _refuse_unfit(given)
    return given


def _refuse_unfit(given: TraceArgs) -> None:
    """Refuse arguments that cannot be taken together: --verbose with
    --json, which has everything as it is, --since but with what is of
    several sessions, and stats with what picks the events of a trace."""
    if {"--verbose", "--json"} <= given.options:
        raise Fatal(USAGE)
    if given.since is not None and given.name not in (LIST, ALL, STATS):
        raise Fatal(f"--since is for {LIST}, {ALL} and {STATS}: {USAGE}")
    if given.name == STATS and (given.chosen or given.options - {"--json"}):
        raise Fatal(f"{STATS} takes --since and --json alone: {USAGE}")


def picked_session(files: list[Path], name: str) -> Path:
    """The one transcript whose session id starts with name."""
    found = sessions_named(files, name)
    if len(found) != 1:
        problem = "matches several sessions" if found else "matches no session"
        raise Fatal(f"{name} {problem}, see claude-airlock --trace list")
    return found[0]
