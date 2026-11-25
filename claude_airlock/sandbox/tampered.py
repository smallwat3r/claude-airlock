"""Saying what a session changed of what is watched: two fingerprints
compared (see fingerprint.py), and what differs named to the user, each
kind of it apart and with what to do about it."""

from __future__ import annotations

import os
from collections.abc import Sequence

from ..notice import warn
from ..settings import CHECKOUT_DIR, NAME
from .fingerprint import (
    CONFIG_WATCHED_TREES,
    MOST_PROJECTS,
    PROJECTS,
    WATCHED_TREE_DEPTH,
    is_launcher_file,
    project_names,
)
from .history import is_own

# The changed ones that are named, the others are counted
MOST_NAMED = 20


def differing(before: dict[str, str], after: dict[str, str]) -> list[str]:
    """The paths two fingerprints do not agree on, in their order: those
    of a file that changed, came or went."""
    return sorted(
        path
        for path in before.keys() | after.keys()
        if before.get(path) != after.get(path)
    )


def _first_named(paths: list[str]) -> list[str]:
    """The lines that name the first MOST_NAMED paths of a report, and
    say how many more there are."""
    more = len(paths) - MOST_NAMED
    lines = [f"  {path}" for path in paths[:MOST_NAMED]]
    return lines + ([f"  and {more} more"] if more > 0 else [])


def report_build_changes(
    before: dict[str, str], after: dict[str, str], unchecked: str = ""
) -> None:
    """Name the files of build_fingerprint that differ, the first
    MOST_NAMED of them. unchecked as for report_tampering."""
    differ = differing(before, after)
    whose = f"the session {unchecked} started" if unchecked else "this session started"
    own = [path for path in differ if is_launcher_file(path)]
    if own:
        warn(
            f"since {whose}, files of {NAME} itself have changed,"
            " which the next session is started and sandboxed by:",
            *_first_named(own),
            f"Review them (git diff in {CHECKOUT_DIR}) before you start"
            " another session.",
        )
    changed = [path for path in differ if path not in own]
    if not changed:
        return
    warn(
        f"since {whose}, these files that your tools run on the"
        " host (make, a package manager, a test runner, a hook manager, an"
        " editor), or that git and Claude follow below the top of the"
        " project, have changed:",
        *_first_named(changed),
        "Read them before you build, test or commit there outside the sandbox.",
    )


def _named_changes(changed: list[str], claude_dir: str) -> list[str]:
    """The changed files as they are named in the report: each by its
    path, those under a watched tree of ~/.claude by their directory
    WATCHED_TREE_DEPTH down, with how many of them changed there."""
    roots = [
        os.path.join(claude_dir, name) + os.sep
        for name in (CONFIG_WATCHED_TREES if claude_dir else ())
    ]
    named: dict[str, int] = {}
    for path in changed:
        root = next((root for root in roots if path.startswith(root)), "")
        parts = path[len(root) :].split(os.sep) if root else []
        if len(parts) > WATCHED_TREE_DEPTH:
            path = root + os.sep.join(parts[:WATCHED_TREE_DEPTH]) + os.sep
        named[path] = named.get(path, 0) + 1
    return [
        f"{path} ({count} files)" if path.endswith(os.sep) else path
        for path, count in named.items()
    ]


def _report_memory(changed: list[str], unchecked: str = "") -> None:
    """Name the changed files of what Claude remembers of the project.
    Said apart from the rest: a session writes there in the ordinary way
    of things, when it is told something to keep. But what is there is
    given to every later session as the user's own notes, so what a
    session read can have it leave instructions for the next ones."""
    if not changed:
        return
    whose = f"the session {unchecked}" if unchecked else "this session"
    warn(
        f"{whose} changed what Claude remembers of this project,"
        " which every later session here is told:",
        *_first_named(changed),
        "Read them, a later session follows what they say.",
    )


def _report_servers(config: str, unchecked: str = "") -> None:
    """Say that the servers of the config the sandboxed sessions share
    have changed. Said apart from the rest: nothing of it runs on the
    host, but a server is a command, and one a session of this project
    added there for every project, or for another one, is started by
    the next session of that project, in its sandbox and with its
    files."""
    whose = f"the session {unchecked}" if unchecked else "this session"
    warn(
        f"{whose} changed the MCP servers that sandboxed sessions"
        " start, of other projects too:",
        f"  {config}",
        "Look at them (claude mcp list in a session) before the next session.",
    )


def report_tampering(
    before: dict[str, str],
    after: dict[str, str],
    unchecked: str = "",
    claude_dir: str = "",
    memory: Sequence[str] = (),
    shared_config: str = "",
) -> None:
    """Name the files that differ, see _named_changes for how, those of
    the memory directories apart (see _report_memory), and the servers of
    the sandbox's own config (see _report_servers). unchecked is the
    name of an earlier session that ended without this check, when the
    report is the late one for it."""
    differ = differing(before, after)
    roots = tuple(directory + os.sep for directory in memory)
    remembered = [path for path in differ if path in memory or path.startswith(roots)]
    _report_memory(remembered, unchecked)
    # Not for a check saved by a version that did not watch them
    if shared_config and shared_config in differ and shared_config in before:
        _report_servers(shared_config, unchecked)
    others = set(differ).difference(remembered, [shared_config])
    changed = _named_changes([path for path in differ if path in others], claude_dir)
    if not changed:
        return
    if unchecked:
        heading = (
            f"the session {unchecked} ended without its check. Since"
            " it started, by its doing or yours, these files that can run commands"
            " on the host, or that Claude follows there, have changed:"
        )
    else:
        heading = (
            "this session changed files that can run commands"
            " on the host, or that Claude follows there:"
        )
    warn(
        heading,
        *(f"  {path}" for path in changed),
        "Review them before using git or claude there outside the sandbox.",
    )


def planted_projects(
    before: list[str] | None, own: Sequence[str], claude_dir: str
) -> list[str] | None:
    """The directories of other projects that came to be since a session
    started, by their paths: not those of the project itself, which its
    own sessions make. None when that cannot be told, see project_names.
    A session is kept out of the directories of the other projects that
    are there (see history.py), but can make one for a project that has
    none yet, under the name Claude Code would give it: what it puts
    there as that project's memory is told to its next session as the
    user's own notes, to claude on the host as well."""
    after = project_names(claude_dir)
    if before is None or after is None:
        return None
    mine, known = set(own), set(before)
    return [
        os.path.join(claude_dir, PROJECTS, name)
        for name in after
        if name not in known and not is_own(name, mine)
    ]


def report_projects(planted: list[str] | None, unchecked: str = "") -> None:
    """Name the directories of other projects that came to be while a
    session ran, see planted_projects. Said apart from the rest: nothing
    of it is the project's own, and it is not always the session's
    doing, a project first used meanwhile has one made for it."""
    whose = f"the session {unchecked}" if unchecked else "this session"
    if planted is None:
        warn(
            f"more than {MOST_PROJECTS} directories are where Claude Code"
            f" keeps what it remembers of each project: whether {whose} made"
            " one for another project cannot be told"
        )
    elif planted:
        warn(
            f"since {whose} started, Claude Code has a directory for"
            " other projects that had none, by its doing or that of a project"
            " first used meanwhile:",
            *_first_named(planted),
            "A session can make one for a project that has none yet. What is"
            " there is told to the next session of that project, on the host too:"
            " look into them, and remove what is not yours.",
        )
