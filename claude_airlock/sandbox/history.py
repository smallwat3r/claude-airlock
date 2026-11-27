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
from collections import deque
from pathlib import Path

from ..docker import env_arg, mount_arg, project_slug
from ..files import json_object, last_lines, open_plain, private_dir, write_whole
from ..projects import project_roots, transcript_dirs
from ..settings import CONTAINER_CLAUDE, Host, Settings, variable
from .mounts import empty_dir, refuse_past_most

# What Claude Code names the transcripts of a worktree after: the project's
# own name, then its path below the project (.claude/worktrees/NAME) dashed
WORKTREE_MARK = "--claude-worktrees-"
# Kept per project, as directories
PER_PROJECT_DIRS = ("file-history", "paste-cache")
# The prompts typed in every project, a line each that names its project.
# Claude Code adds to it in place, so one file can be mounted over it.
PROMPT_HISTORY = "history.jsonl"
# Of it, as much of its end as is read for the lines of a project, no
# longer a line than this, and no more of them than this are kept: what
# Claude Code goes back through is the latest
PROMPTS_READ = 64 << 20
PROMPT_LINE = 4 << 20
MOST_PROMPTS = 10_000
# A name that can be spelled in a mount. Claude Code's own are, another is
# something a session put there, which holds nothing of another project.
_MOUNTABLE = re.compile(r"[A-Za-z0-9_.-]+")
# No more directories of other projects are covered than this, see
# refuse_past_most: a session that can write ~/.claude/projects can make
# any number of them
MOST_COVERED = 2000


def own_names(host: Host) -> set[str]:
    """The names of the project's transcript directories."""
    return {directory.name for directory in transcript_dirs(host)}


def is_own(name: str, own: set[str]) -> bool:
    """Whether a directory of projects is the project's, or a worktree's
    of it."""
    return any(name == mine or name.startswith(mine + WORKTREE_MARK) for mine in own)


def _other_projects(host: Host) -> list[str]:
    """The directories of projects that are another project's, by name.
    Fatal for more of them than MOST_COVERED (see refuse_past_most):
    none could be covered, and a session started with them all in reach
    would see them all."""
    projects = Path(host.claude_dir, "projects")
    own = own_names(host)
    others = []
    try:
        with os.scandir(projects) as entries:
            for entry in entries:
                if _is_other(entry, own):
                    others.append(entry.name)
                    what = f"directories of other projects in {projects}"
                    refuse_past_most(len(others), MOST_COVERED, what)
    except OSError:
        return []
    return sorted(others)


def _is_other(entry: os.DirEntry[str], own: set[str]) -> bool:
    """Whether an entry of projects is the directory of another project,
    one whose name can be spelled in a mount."""
    return (
        entry.is_dir(follow_symlinks=False)
        and _MOUNTABLE.fullmatch(entry.name) is not None
        and not is_own(entry.name, own)
    )


def _project_store(host: Host) -> Path:
    """Where the launcher keeps what a project's sessions remember, named
    like the project's cache volume."""
    store = os.path.join(host.history_dir, project_slug(host.project_dir))
    return Path(private_dir(store))


def _own_prompts(host: Host) -> list[str]:
    """The lines of the shared prompt history that are this project's,
    the latest of them. Shared, the host's history is a session's to
    write, as long as the disk takes: no more of its end is read than
    PROMPTS_READ, no line longer than PROMPT_LINE, and no more of them
    kept than MOST_PROMPTS. Nor read at all when it is no plain file,
    a pipe that would hold the launch."""
    roots = set(project_roots(host))
    kept: deque[str] = deque(maxlen=MOST_PROMPTS)
    file = open_plain(Path(host.claude_dir, PROMPT_HISTORY), links=True)
    if file is None:
        return []
    with file:
        try:
            for line in last_lines(file, PROMPTS_READ, PROMPT_LINE):
                if line is not None and _prompt_project(line) in roots:
                    kept.append(line.decode("utf-8", "replace").rstrip("\r\n") + "\n")
        except OSError:
            pass
    return list(kept)


def _prompt_project(line: bytes) -> str | None:
    """The project a line of the prompt history names, none for a line
    that names none."""
    said = json_object(line)
    project = said.get("project") if said else None
    return project if isinstance(project, str) else None


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
