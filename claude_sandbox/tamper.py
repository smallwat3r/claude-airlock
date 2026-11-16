"""Noticing what a session left behind that can run commands on the host,
or that Claude follows there."""

from __future__ import annotations

import hashlib
import json
import os
import shlex
import subprocess
import sys
from collections.abc import Iterator
from pathlib import Path

from .files import expand_home, private_dir, write_whole
from .launcher import Launcher, session_alive
from .settings import CONFIG_FILES, CONFIG_TREES

# What Claude follows or starts in a project, on the host as in a session:
# its settings, the servers it is told to run and its instructions. Relative
# to the project, single files then whole directories.
PROJECT_FILES = (
    ".claude/settings.json",
    ".claude/settings.local.json",
    ".mcp.json",
    "CLAUDE.md",
    "CLAUDE.local.md",
    ".claude/CLAUDE.md",
)
PROJECT_TREES = (
    ".claude/hooks",
    ".claude/commands",
    ".claude/skills",
    ".claude/agents",
    ".claude/rules",
)
# The same of ~/.claude is CONFIG_FILES and CONFIG_TREES of settings.py.
# Most of it is mounted read-only and cannot differ, unless
# CLAUDE_DOCKER_RW_CONFIG=1 leaves it writable.
# What is watched there and cannot be protected: Claude Code updates its
# plugins itself, so they stay writable, and a plugin brings hooks, servers
# and instructions that the host's claude runs and follows too. The
# plugins as installed, where they are installed from, and the two files
# that say which those are. Not the rest of plugins, which is what Claude
# Code notes for itself and rewrites in every session.
CONFIG_WATCHED_TREES = ("plugins/cache", "plugins/marketplaces")
CONFIG_WATCHED_FILES = (
    "plugins/installed_plugins.json",
    "plugins/known_marketplaces.json",
)
# A plugin is many files, and an update changes most of them: the changed
# files under a watched tree are named by their directory this far down,
# with how many they are. That is the plugin: where it is from, then its
# name.
WATCHED_TREE_DEPTH = 2
# The files whose commands are followed to the scripts they name
COMMAND_FILES = (".claude/settings.json", ".claude/settings.local.json", ".mcp.json")
# No more of a file than this is read. Which files are hashed is partly up
# to the session, and one could be made as large as the disk.
HASHED_BYTES = 64 * 1024 * 1024
# A settings file past this is not read for the scripts it names. It is
# hashed like any other, so the change that made it this large still shows.
SETTINGS_BYTES = 1024 * 1024


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def git_config_hash(file: str) -> str:
    """Hash of a git config without its branch tracking entries, they change
    on every push -u or checkout and cannot run anything. One that cannot
    be read says so: the file is the session's, which can take the right
    to read it away, and the check must not be made to fail."""
    try:
        listing = subprocess.run(
            ["git", "config", "--file", file, "--list"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=True,
        ).stdout
    except (OSError, subprocess.CalledProcessError):
        # Unparseable, or no git: fall back to the file as it is
        return file_hash(file)
    kept = [line for line in listing.split(b"\n") if not line.startswith(b"branch.")]
    return sha256_hex(b"\n".join(kept))


def file_hash(path: str) -> str:
    """Hash of a file, of a link where it points and what is there. Of a
    file past HASHED_BYTES, its start and its size."""
    digest = hashlib.sha256()
    try:
        if os.path.islink(path):
            digest.update(b"link:" + os.fsencode(os.readlink(path)) + b"\n")
            if not os.path.isfile(path):
                return digest.hexdigest()
        with open(path, "rb") as file:
            left = HASHED_BYTES
            while left > 0 and (chunk := file.read(min(left, 1024 * 1024))):
                digest.update(chunk)
                left -= len(chunk)
            if left == 0:
                digest.update(b"size:%d" % os.fstat(file.fileno()).st_size)
    except OSError:
        return "unreadable"
    return digest.hexdigest()


def file_stamp(path: str) -> str:
    """What tells a file from one written since, without reading it: where
    it is, how long, and when it and what is known of it last changed. The
    last of those is the system's to set, a session cannot put it back. For
    the trees with too much in them to hash at every start and end of a
    session."""
    try:
        about = os.lstat(path)
    except OSError:
        return "unreadable"
    return f"{about.st_ino}:{about.st_size}:{about.st_mtime_ns}:{about.st_ctime_ns}"


def tree_files(root: str) -> list[str]:
    """Every file under a directory. A link to a directory is listed and not
    entered, the root too: a session can point one at the whole disk, and
    the link itself is what changed then."""
    if os.path.islink(root):
        return [root]
    found = []
    for directory, subdirs, files in os.walk(root):
        links = [
            name for name in subdirs if os.path.islink(os.path.join(directory, name))
        ]
        found += [os.path.join(directory, name) for name in (*files, *links)]
    return found


def module_git_dirs(directory: str) -> Iterator[str]:
    """The git directories of the submodules kept under a directory, and of
    theirs. A submodule's name can hold slashes, so they sit at any depth.
    Without recursion: a session can nest directories deeper than Python
    calls, and the check must not be made to fail."""
    pending = [directory]
    while pending:
        try:
            entries = list(os.scandir(pending.pop()))
        except OSError:
            continue
        for entry in entries:
            if not entry.is_dir(follow_symlinks=False):
                continue
            if os.path.isfile(os.path.join(entry.path, "HEAD")):
                yield entry.path
                pending.append(os.path.join(entry.path, "modules"))
            else:
                pending.append(entry.path)


def git_configs(git_dir: str) -> list[str]:
    """The config files of a git directory: its own, and the ones a
    worktree reads on top once extensions.worktreeConfig is set."""
    configs = [os.path.join(git_dir, name) for name in ("config", "config.worktree")]
    configs += map(str, sorted(Path(git_dir, "worktrees").glob("*/config.worktree")))
    return [config for config in configs if os.path.isfile(config)]


def moved_hooks_dir(directory: str) -> str | None:
    """The directory core.hooksPath has git take its hooks from in place of
    .git/hooks (husky and the like), when it is inside the project. One
    outside is out of a session's reach, unless it is mounted too and then
    it is the session's choice of what gets read here."""
    try:
        value = subprocess.run(
            ["git", "config", "--file", os.path.join(directory, ".git", "config")]
            + ["--type=path", "--get", "core.hooksPath"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=True,
            text=True,
            errors="replace",
        ).stdout.strip()
    except (OSError, subprocess.CalledProcessError):
        return None
    hooks = os.path.realpath(os.path.join(directory, value))
    inside = hooks.startswith(os.path.realpath(directory) + os.sep)
    return (
        os.path.normpath(os.path.join(directory, value)) if value and inside else None
    )


def commands_in(value: object) -> Iterator[str]:
    """Every "command" in a settings file, of a hook, a statusline or a
    server, at whatever depth."""
    if isinstance(value, dict):
        for key, inner in value.items():
            if key == "command" and isinstance(inner, str):
                yield inner
            else:
                yield from commands_in(inner)
    elif isinstance(value, list):
        for inner in value:
            yield from commands_in(inner)


def named_files(settings_file: str, base: str) -> list[str]:
    """The files the commands of a settings file name. A hook that runs a
    script is changed by changing the script, with the settings as they
    were. Found by taking each word of a command for a path, relative ones
    from base, which catches the usual "path/to/script arguments" and
    misses a path a shell would have to work out. A file a session made
    too large or nested too deep to read names nothing, the check goes on
    without it."""
    try:
        if os.path.getsize(settings_file) > SETTINGS_BYTES:
            return []
        settings = json.loads(Path(settings_file).read_text(encoding="utf-8"))
        commands = list(commands_in(settings))
    except (OSError, ValueError, RecursionError):
        return []
    home = os.path.expanduser("~")
    found = []
    for command in commands:
        try:
            words = shlex.split(command)
        except ValueError:
            words = command.split()
        for word in words:
            for variable in ("${CLAUDE_PROJECT_DIR}", "$CLAUDE_PROJECT_DIR"):
                word = word.replace(variable, base)
            path = os.path.normpath(os.path.join(base, expand_home(word, home)))
            if os.path.isfile(path):
                found.append(path)
    return found


def claude_files(
    root: str,
    files: tuple[str, ...],
    trees: tuple[str, ...],
    command_files: tuple[str, ...],
) -> list[str]:
    """What is watched of a project or of ~/.claude for Claude's sake."""
    watched = [os.path.join(root, name) for name in files]
    for name in trees:
        watched += tree_files(os.path.join(root, name))
    for name in command_files:
        watched += named_files(os.path.join(root, name), root)
    return watched


def host_exec_fingerprint(
    directories: list[str], claude_dir: str = ""
) -> dict[str, str]:
    """Hashes, by path, of the files a session can write that run commands
    on the host once it is over, or that Claude follows there. In each
    mounted directory: the git config and hooks, of its submodules too,
    Claude's settings and the scripts they name, and its instructions
    (CLAUDE.md, skills, agents, commands, rules). In ~/.claude the same,
    most of which is read-only in a session, and the plugins, which are
    not and are told apart by file_stamp. They have to stay writable for
    git and claude to work, so instead of locking them the launcher compares
    this before and after a session (see report_tampering). Not seen: a
    CLAUDE.md below the top of a project, and what a script goes on to
    run."""
    fingerprint = {}
    watched = []
    for directory in directories:
        git_dir = os.path.join(directory, ".git")
        modules = module_git_dirs(os.path.join(git_dir, "modules"))
        for each in (git_dir, *modules):
            for config in git_configs(each):
                fingerprint[config] = git_config_hash(config)
            watched += tree_files(os.path.join(each, "hooks"))
        moved = moved_hooks_dir(directory)
        if moved:
            watched += tree_files(moved)
        watched += claude_files(directory, PROJECT_FILES, PROJECT_TREES, COMMAND_FILES)
    if claude_dir:
        files = (*CONFIG_FILES, *CONFIG_WATCHED_FILES)
        watched += claude_files(claude_dir, files, CONFIG_TREES, ("settings.json",))
    for path in watched:
        if os.path.isfile(path) or os.path.islink(path):
            fingerprint[path] = file_hash(path)
    for name in CONFIG_WATCHED_TREES if claude_dir else ():
        for path in tree_files(os.path.join(claude_dir, name)):
            fingerprint[path] = file_stamp(path)
    return fingerprint


def named_changes(changed: list[str], claude_dir: str) -> list[str]:
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


def report_tampering(
    before: dict[str, str],
    after: dict[str, str],
    unchecked: str = "",
    claude_dir: str = "",
) -> None:
    """Name the files that differ, see named_changes for how. unchecked
    is the name of an earlier session that ended without this check, when
    the report is the late one for it."""
    changed = named_changes(
        sorted(
            path
            for path in before.keys() | after.keys()
            if before.get(path) != after.get(path)
        ),
        claude_dir,
    )
    if not changed:
        return
    if unchecked:
        heading = (
            f"claude-docker: the session {unchecked} ended without its check. Since"
            " it started, by its doing or yours, these files that can run commands"
            " on the host, or that Claude follows there, have changed:"
        )
    else:
        heading = (
            "claude-docker: this session changed files that can run commands"
            " on the host, or that Claude follows there:"
        )
    print(
        heading,
        *(f"  {path}" for path in changed),
        "Review them before using git or claude there outside the sandbox.",
        sep="\n",
        file=sys.stderr,
    )


def save_pending_check(
    file: Path, watched: list[str], claude_dir: str, before: dict[str, str]
) -> None:
    """Keep a session's starting fingerprint on disk until its check has
    run. A launcher that dies with its terminal (a killed Emacs buffer, a
    closed window, a crash) never gets to compare, the next launch finds
    this file and does it instead (see report_unchecked_sessions). Written
    whole: a launcher that starts meanwhile reads the checks that are
    there, and drops one it cannot read."""
    private_dir(str(file.parent))
    launcher = Launcher.current()
    pending = {
        "pid": launcher.pid,
        "launched": launcher.started,
        "watched": watched,
        "claude_dir": claude_dir,
        "before": before,
    }
    write_whole(str(file), json.dumps(pending))


def report_unchecked_sessions(directory: Path) -> None:
    """Run the check for every session that ended without it, one still
    going is left alone. The file is named after the container."""
    for file in sorted(directory.glob("*.json")):
        try:
            pending = json.loads(file.read_text(encoding="utf-8"))
            launcher, watched, claude_dir, before = (
                # Neither its start nor claude_dir are in a check saved
                # by an earlier version
                Launcher(int(pending["pid"]), str(pending.get("launched", ""))),
                [str(watched_dir) for watched_dir in pending["watched"]],
                str(pending.get("claude_dir", "")),
                {str(k): str(v) for k, v in pending["before"].items()},
            )
        except (OSError, ValueError, KeyError, TypeError, AttributeError):
            # Said out loud, a check must not vanish without a word
            print(
                f"claude-docker: dropping an unreadable pending check: {file}",
                file=sys.stderr,
            )
            file.unlink(missing_ok=True)
            continue
        if session_alive(launcher, file.stem):
            continue
        after = host_exec_fingerprint(watched, claude_dir)
        report_tampering(before, after, unchecked=file.stem, claude_dir=claude_dir)
        file.unlink(missing_ok=True)
