"""The arguments of --trace, which --trace --follow takes too: the options
among them, the session they name, and the events they ask for."""

from __future__ import annotations

from pathlib import Path

from .entries import sessions_named
from .errors import Fatal
from .stream import Filter

USAGE = (
    "usage: claude-airlock --trace [list | SESSION] [--follow] [--verbose | --json]"
    " [--only KIND,...] [--failed]"
)


def trace_options(
    args: list[str], known: tuple[str, ...]
) -> tuple[set[str], list[str], Filter]:
    """The arguments of --trace as the options among them, what is left,
    which is at most a name (a session, or list), and which events are
    asked for: --only takes its kinds after an = or as the next argument,
    separated by commas."""
    options: set[str] = set()
    names: list[str] = []
    only: set[str] = set()
    failed = False
    rest = iter(args)
    for arg in rest:
        option, has_value, value = arg.partition("=")
        if option == "--only":
            kinds = (value if has_value else next(rest, "")).lower().split(",")
            only |= {kind.strip() for kind in kinds if kind.strip()}
            if not only:
                raise Fatal(USAGE)
        elif arg == "--failed":
            failed = True
        elif arg in known:
            options.add(arg)
        else:
            names.append(arg)
    if len(names) > 1 or any(name.startswith("-") for name in names):
        raise Fatal(USAGE)
    if {"--verbose", "--json"} <= options:
        # JSON Lines has everything as it is
        raise Fatal(USAGE)
    return options, names, Filter(frozenset(only), failed)


def picked_session(files: list[Path], name: str) -> Path:
    """The one transcript whose session id starts with name."""
    found = sessions_named(files, name)
    if len(found) != 1:
        problem = "matches several sessions" if found else "matches no session"
        raise Fatal(f"{name} {problem}, see claude-airlock --trace list")
    return found[0]
