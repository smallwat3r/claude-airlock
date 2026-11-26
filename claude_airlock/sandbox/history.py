"""Keeping what Claude Code remembers of other projects out of a session.

Of the host's ~/.claude a session is given the transcripts (projects),
Claude Code needs the project's own past there, see home.py. That
directory also holds the past of every other project: every prompt,
command output and file that was read. So do three things Claude Code
keeps in ~/.claude for all projects at once: the prompts typed anywhere,
what was pasted, and the copies of edited files that rewinding uses. A
session has no use for those of another project, and one that went wrong
could read them all, so unless CLAUDE_AIRLOCK_SHARED_HISTORY=1 they are
left out:

- In projects, the directory of every other project is covered by an empty
  one. The project's own stay, with those of its worktrees. Covered and not
  left out, so that a directory Claude Code makes while the session runs
  (for a new worktree) is a real one on the host. The cost is that a
  project first used after the session started is not covered in it.
- The prompt history, the paste cache and the file history are kept per
  project by the launcher and mounted into the session's ~/.claude, the
  prompt history starting from the project's own lines of the host's.
  Sandboxed sessions of a project share them, the host's claude does not
  see them: it cannot rewind the files of a session run in here.

With CLAUDE_AIRLOCK_SHARED_HISTORY=1 the three are the host's, mounted from
its ~/.claude, and nothing of projects is covered.

Directories mounted next to the project (--add-dir) do not bring their
history along: a directory holds what is in it now, its history also what
was typed, pasted and read there."""

from __future__ import annotations

import os
import re
from pathlib import Path

from ..docker import env_arg, mount_arg, project_slug
from ..files import bounded_lines, json_object, private_dir, write_whole
from ..projects import project_roots, transcript_dirs
from ..settings import CONTAINER_CLAUDE, Host, Settings, variable
from .mounts import empty_dir

# What Claude Code names the transcripts of a worktree after: the project's
# own name, then its path below the project (.claude/worktrees/NAME) dashed
WORKTREE_MARK = "--claude-worktrees-"
# Kept per project, as directories
PER_PROJECT_DIRS = ("file-history", "paste-cache")
# The prompts typed in every project, a line each that names its project.
# Claude Code adds to it in place, so one file can be mounted over it.
PROMPT_HISTORY = "history.jsonl"
# A name that can be spelled in a mount. Claude Code's own are, another is
# something a session put there, which holds nothing of another project.
_MOUNTABLE = re.compile(r"[A-Za-z0-9_.-]+")


def own_names(host: Host) -> set[str]:
    """The names of the project's transcript directories."""
    return {directory.name for directory in transcript_dirs(host)}


def is_own(name: str, own: set[str]) -> bool:
    """Whether a directory of projects is the project's, or a worktree's
    of it."""
    return any(name == mine or name.startswith(mine + WORKTREE_MARK) for mine in own)


def _other_projects(host: Host) -> list[str]:
    """The directories of projects that are another project's, by name."""
    projects = Path(host.claude_dir, "projects")
    own = own_names(host)
    try:
        entries = sorted(os.scandir(projects), key=lambda entry: entry.name)
    except OSError:
        return []
    return [
        entry.name
        for entry in entries
        if entry.is_dir(follow_symlinks=False)
        and _MOUNTABLE.fullmatch(entry.name)
        and not is_own(entry.name, own)
    ]


def _project_store(host: Host) -> Path:
    """Where the launcher keeps what a project's sessions remember, named
    like the project's cache volume."""
    store = os.path.join(host.history_dir, project_slug(host.project_dir))
    return Path(private_dir(store))


def _own_prompts(host: Host) -> list[str]:
    """The lines of the shared prompt history that are this project's."""
    roots = set(project_roots(host))
    kept = []
    try:
        # Shared, the host's history is a session's to write: no line of
        # it is trusted to be short
        with open(Path(host.claude_dir, PROMPT_HISTORY), "rb") as history:
            for line in bounded_lines(history):
                said = json_object(line) if line is not None else None
                project = said.get("project") if said else None
                if line is None or not isinstance(project, str):
                    continue
                if project in roots:
                    kept.append(line.decode("utf-8", "replace").rstrip("\r\n") + "\n")
    except OSError:
        pass
    return kept


def _prepare_store(host: Host) -> Path:
    """The project's store with what is mounted from it in place. What
    each is mounted over is made with the session's ~/.claude, see
    home.py."""
    store = _project_store(host)
    for name in PER_PROJECT_DIRS:
        (store / name).mkdir(mode=0o700, exist_ok=True)
    prompts = store / PROMPT_HISTORY
    if not prompts.exists():
        # Whole or not at all: a launcher that starts meanwhile mounts it
        write_whole(str(prompts), "".join(_own_prompts(host)), replace=False)
    return store


def _prepare_shared(host: Host) -> Path:
    """The host's ~/.claude with what is mounted from it in place when the
    history is shared: there has to be something to mount."""
    shared = Path(host.claude_dir)
    for name in PER_PROJECT_DIRS:
        (shared / name).mkdir(exist_ok=True)
    prompts = shared / PROMPT_HISTORY
    if not prompts.exists():
        prompts.touch(mode=0o600)
    return shared


def history_args(settings: Settings, host: Host) -> list[str]:
    """What a session is given of the history, on top of its ~/.claude:
    the project's own, with the transcripts of other projects covered, or
    the host's when it is shared."""
    claude = CONTAINER_CLAUDE
    kept = (*PER_PROJECT_DIRS, PROMPT_HISTORY)
    if settings.shared_history:
        shared = _prepare_shared(host)
        return [
            # Said in docker/CLAUDE-airlock.md
            env_arg(variable("shared_history"), 1),
            *(mount_arg(str(shared / name), f"{claude}/{name}", "z") for name in kept),
        ]
    others = _other_projects(host)
    args = []
    if others:
        empty = empty_dir(host)
        args += [
            mount_arg(empty, f"{claude}/projects/{name}", "ro,z") for name in others
        ]
    store = _prepare_store(host)
    args += [mount_arg(str(store / name), f"{claude}/{name}", "z") for name in kept]
    return args
