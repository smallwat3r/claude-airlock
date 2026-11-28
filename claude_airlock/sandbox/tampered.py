"""Saying what a session changed of what is watched: two fingerprints
compared (see fingerprint.py), and what differs named to the user, each
kind of it apart and with what to do about it."""

from __future__ import annotations

import os
from collections.abc import Sequence

from ..notice import warn
from ..paths import is_within
from ..settings import CHECKOUT_DIR, NAME
from .bounded import left_out
from .build_files import is_launcher_file
from .fingerprint import (
    CONFIG_WATCHED_TREES,
    MOST_PROJECTS,
    PROJECTS,
    WATCHED_TREE_DEPTH,
    project_names,
)
from .history import is_own
from .home import SHARED_AGENT_MEMORY
from .shared_config import (
    ENVIRONMENT_NAMED,
    ENVIRONMENT_REST,
    SHARED_STEERING,
    shared_part,
)

# The changed ones that are named, the others are counted
MOST_NAMED = 20


def _whose(unchecked: str) -> str:
    """The session a report is of: this one, or by its name an earlier
    one that ended without its check (unchecked)."""
    return f"the session {unchecked}" if unchecked else "this session"


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
    whose = f"{_whose(unchecked)} started"
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


def report_left_out(*fingerprints: dict[str, str]) -> None:
    """Say, as a session starts, what is larger already than the check
    of what it changes watches (see left_out): what a session changes
    past that goes unseen. Said at the end too when a session made it
    so, this is for what was so before."""
    cut = sorted({path for each in fingerprints for path in left_out(each)})
    if not cut:
        return
    warn(
        "the check of what this session changes watches no more than a part"
        " of these, a change to the rest is not said when it ends:",
        *_first_named(cut),
        "Review what changed there yourself (git status) before you build or"
        " commit outside the sandbox.",
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


def _report_memory(changed: list[str], heading: str) -> None:
    """Name the changed files of a memory under the heading given, see
    _report_remembered."""
    if not changed:
        return
    warn(
        heading,
        *_first_named(changed),
        "Read them, a later session follows what they say.",
    )


def _report_remembered(
    remembered: list[str], shared_memory: str, unchecked: str = ""
) -> None:
    """Name the changed files of what Claude remembers of the project,
    and apart, those of what the agents remember for every project in
    the ~/.claude of the sandboxed sessions (shared_memory). Said apart
    from the rest: a session writes there in the ordinary way of things,
    when it is told something to keep. But what is there is given to
    every later session as the user's own notes, so what a session read
    can have it leave instructions for the next ones. What the sandboxed
    sessions share is written by every one of them, of another project
    too, that ran meanwhile."""
    whose = _whose(unchecked)
    shared = [
        path for path in remembered if shared_memory and is_within(path, shared_memory)
    ]
    _report_memory(
        [path for path in remembered if path not in shared],
        f"{whose} changed what Claude remembers of this project,"
        " which every later session here is told:",
    )
    _report_memory(
        shared,
        f"since {whose} started, by its doing or that of another sandboxed"
        " session, what the agents remember for every project has changed,"
        " which every later sandboxed session is told:",
    )


def _shared_changes(differ: list[str], config: str) -> list[str]:
    """What steers the sandboxed sessions that changed in the config they
    share, by the entries of a fingerprint that differ (see
    shared_config_hashes): the servers, by the config's own, then the
    environment by the names of its variables, the first MOST_NAMED of
    them, then the rest of SHARED_STEERING."""
    parts = {part for path in differ if (part := shared_part(config, path)) is not None}
    said = ["the MCP servers"] if "" in parts else []
    names = sorted(
        part.removeprefix(ENVIRONMENT_NAMED)
        for part in parts
        if part.startswith(ENVIRONMENT_NAMED)
    )
    variables = names[:MOST_NAMED]
    if len(names) > MOST_NAMED:
        variables.append(f"{len(names) - MOST_NAMED} more")
    if ENVIRONMENT_REST in parts:
        variables.append("the rest of it")
    if variables:
        said.append(f"the environment ({', '.join(variables)})")
    return said + [part for part, _ in SHARED_STEERING if part in parts]


def _report_shared_config(config: str, changed: list[str], unchecked: str = "") -> None:
    """Say what changed of what the config the sandboxed sessions share
    has them do, see _shared_changes. Said apart from the rest: nothing
    of it runs on the host, but every later sandboxed session of every
    project starts with it, in its sandbox and with its files. A server
    is a command. The environment can name another, for every shell to
    run first (BASH_ENV), or send all that Claude Code says to another
    address (ANTHROPIC_BASE_URL, a proxy). Remote Control has the
    account the session is logged in with drive it from elsewhere, and
    an API key approved there is taken without a question."""
    warn(
        f"{_whose(unchecked)} changed what sandboxed sessions start with, of other"
        " projects too, in the config they share:",
        f"  {config}: {', '.join(changed)}",
        "Look at it before the next session: the servers with claude mcp list"
        " in a session, the rest in the file.",
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
    the memory directories apart (see _report_remembered), what the
    agents remember in the ~/.claude of the sandboxed sessions too, next
    to the config they share, and what steers them of that config, the
    sandbox's own (see _report_shared_config). unchecked is the name of
    an earlier session that ended without this check, when the report is
    the late one for it."""
    differ = differing(before, after)
    remembered = [path for path in differ if any(is_within(path, d) for d in memory)]
    base = os.path.dirname(shared_config)
    shared_memory = os.path.join(base, SHARED_AGENT_MEMORY) if shared_config else ""
    _report_remembered(remembered, shared_memory, unchecked)
    of_config = [
        path
        for path in differ
        if shared_config and shared_part(shared_config, path) is not None
    ]
    # Not for a check saved by a version that did not watch the config
    if of_config and shared_config in before:
        _report_shared_config(
            shared_config, _shared_changes(of_config, shared_config), unchecked
        )
    others = set(differ).difference(remembered, of_config)
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
    whose = _whose(unchecked)
    if planted is None:
        warn(
            f"where Claude Code keeps what it remembers of each project, more"
            f" than {MOST_PROJECTS} directories are, or what is there cannot be"
            f" listed: whether {whose} made one for another project cannot be"
            " told"
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
