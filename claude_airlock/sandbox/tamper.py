"""Noticing what a session left behind that can run commands on the host,
or that Claude follows there."""

from __future__ import annotations

import hashlib
import json
import os
import shlex
import subprocess
import sys
from collections.abc import Iterator, Sequence
from dataclasses import dataclass
from itertools import islice
from operator import attrgetter
from pathlib import Path

from ..files import (
    expand_home,
    json_object,
    open_plain,
    private_dir,
    settings_object,
    write_whole,
)
from ..launcher import Launcher, session_alive
from ..projects import memory_dirs
from ..settings import CONFIG_FILES, CONFIG_TREES, Host
from .home import CONFIG
from .plugins import INSTALLED

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
# CLAUDE_AIRLOCK_RW_CONFIG=1 leaves it writable.
# What is watched there and cannot be protected: Claude Code updates its
# plugins itself, so they stay writable, and a plugin brings hooks, servers
# and instructions that the host's claude runs and follows too. The
# plugins as installed, where they are installed from, and the two files
# that say which those are. Not the rest of plugins, which is what Claude
# Code notes for itself and rewrites in every session.
PLUGIN_CACHE = "plugins/cache"
CONFIG_WATCHED_TREES = (PLUGIN_CACHE, "plugins/marketplaces")
CONFIG_WATCHED_FILES = (
    INSTALLED,
    "plugins/known_marketplaces.json",
)
# A plugin is many files, and an update changes most of them: the changed
# files under a watched tree are named by their directory this far down,
# with how many they are. That is the plugin: where it is from, then its
# name.
WATCHED_TREE_DEPTH = 2
# Where Claude Code notes the sessions that use a plugin, a file for each
# in this directory at the top of an installed version, written when a
# session starts and removed when it ends. Nothing runs or follows them,
# so they are not watched: every session with a plugin would be reported.
PLUGIN_USE_MARKERS = ".in_use"
PLUGIN_VERSION_DEPTH = 3
# What the tools of a project run on the host, by the name of the file,
# wherever in the project it is: what make, a package manager, a test
# runner, a hook manager or direnv is told to do. Not what git and Claude
# run of their own accord, which is above: these run when their tool is
# used, so a change to one is said apart, as something to read before
# that. No such list is whole, it is the ones most projects have.
BUILD_FILES = frozenset(
    (
        *("Makefile", "makefile", "GNUmakefile", "justfile", "Justfile", ".justfile"),
        *("Taskfile.yml", "Taskfile.yaml", "Rakefile", "Gemfile", "Procfile"),
        *("package.json", ".npmrc", ".yarnrc", ".yarnrc.yml", ".pnpmfile.cjs"),
        *("pyproject.toml", "setup.py", "setup.cfg", "conftest.py", "noxfile.py"),
        *("tox.ini", "sitecustomize.py", "usercustomize.py"),
        *("build.gradle", "build.gradle.kts", "settings.gradle", "gradlew", "mvnw"),
        *("settings.gradle.kts", "pom.xml", "CMakeLists.txt", "meson.build"),
        *("build.rs", "build.zig", "configure", "configure.ac"),
        *(".pre-commit-config.yaml", "lefthook.yml", ".lefthook.yml"),
        *(".envrc", ".tool-versions", "mise.toml", ".mise.toml"),
        *(".gitattributes", ".gitmodules", ".gitlab-ci.yml"),
        *("Dockerfile", "Vagrantfile", "Tiltfile"),
        *("docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"),
    )
)
# The directories all of which is such a file, by their name: the hooks of
# husky, the tasks and settings an editor runs, a dev container
BUILD_TREES = frozenset((".husky", ".vscode", ".devcontainer"))
# And the one that is by where it is, in .github
WORKFLOWS = (".github", "workflows")
# What tells that a directory below the top of a project is one Claude
# follows instructions in, or one git runs hooks in: what the check above
# watches at the top
CLAUDE_MARKS = frozenset((".claude", "CLAUDE.md", "CLAUDE.local.md", ".mcp.json"))
# The directories that are not looked into for those: what git keeps for
# itself, and what a package manager fills with thousands of other
# projects' build files. What is in them can still run on the host, it is
# not seen here.
NOT_LOOKED_INTO = frozenset((".git", "node_modules", ".venv", "__pycache__"))
# Nor are the working trees claude makes for a session of its own
# (--worktree): each is the whole project again, and all of it new
WORKTREES = os.path.join(".claude", "worktrees")
# No more of them than this are watched, a session can make any number
MOST_BUILD_FILES = 5000
# The changed ones that are named, the others are counted
MOST_NAMED = 20
# No more of what Claude remembers of a project is watched than this many
# files, a session can write any number
MOST_MEMORY_FILES = 1000
# The files whose commands are followed to the scripts they name
COMMAND_FILES = (".claude/settings.json", ".claude/settings.local.json", ".mcp.json")
# No more of a file than this is read. Which files are hashed is partly up
# to the session, and one could be made as large as the disk.
HASHED_BYTES = 64 * 1024 * 1024
# Nor more than this of all the files of one fingerprint: past it a file
# is told from one written since as file_stamp does, without reading it
MOST_HASHED_BYTES = 1024 * 1024 * 1024
# No more files of one tree are watched than this, of a tree whose files
# are hashed and of one whose files are only told apart (the plugins,
# thousands of files as they come): a session can write any number
MOST_TREE_FILES = 5000
MOST_STAMPED_FILES = 100_000
# Nor the submodules of more than this many git directories
MOST_MODULES = 1000
# The seconds git is given to read a config, it takes a moment: a file a
# session swapped for a pipe must not have the check wait on it
GIT_SECONDS = 10
# The servers of the config the sandboxed sessions share, by this name
# wherever in it they are: those of every project, and those of each
SERVERS = "mcpServers"
# No more of that config is read than this, it is a session's to write
SERVERS_BYTES = 16 * 1024 * 1024
# What a fingerprint has in the place of a hash for what it does not
# watch, by a name that says what that is
UNWATCHED = "unwatched"


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def git_config_hash(file: str) -> str:
    """Hash of a git config without its branch tracking entries, they change
    on every push -u or checkout and cannot run anything. One that cannot
    be read says so: the file is the session's, which can take the right
    to read it away, and the check must not be made to fail. Nor to wait:
    git is not given what is no plain file, a pipe a session of this
    project that still runs can put there, and is given GIT_SECONDS for
    one that was swapped in since."""
    probe = open_plain(file, links=True)
    if probe is None:
        return file_hash(file)
    probe.close()
    try:
        listing = subprocess.run(
            ["git", "config", "--file", file, "--list"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=True,
            timeout=GIT_SECONDS,
        ).stdout
    except (OSError, subprocess.SubprocessError):
        # Unparseable, no git, or one that did not end: fall back to the
        # file as it is
        return file_hash(file)
    kept = [line for line in listing.split(b"\n") if not line.startswith(b"branch.")]
    return sha256_hex(b"\n".join(kept))


def file_hash(path: str) -> str:
    """Hash of a file, of a link where it points and what is there. Of a
    file past HASHED_BYTES, its start and its size. What is no plain file
    is unreadable, and is not opened to find out: a pipe would have the
    check wait for whoever writes to it."""
    digest = hashlib.sha256()
    try:
        if os.path.islink(path):
            digest.update(b"link:" + os.fsencode(os.readlink(path)) + b"\n")
            if not os.path.isfile(path):
                return digest.hexdigest()
        file = open_plain(path, links=True)
        if file is None:
            return "unreadable"
        with file:
            left = HASHED_BYTES
            while left > 0 and (chunk := file.read(min(left, 1024 * 1024))):
                digest.update(chunk)
                left -= len(chunk)
            if left == 0:
                digest.update(b"size:%d" % os.fstat(file.fileno()).st_size)
    except OSError:
        return "unreadable"
    return digest.hexdigest()


def servers_in(value: object, at: tuple[str, ...] = ()) -> Iterator[tuple[str, str]]:
    """Every set of servers a config holds, at whatever depth: where it
    is and what it says. Not one that names no server, which is what a
    project that was only run in the sandbox has."""
    if not isinstance(value, dict):
        return
    for key, inner in value.items():
        if key == SERVERS:
            if inner:
                yield "/".join(at), json.dumps(inner, sort_keys=True)
        else:
            yield from servers_in(inner, (*at, str(key)))


def servers_hash(config: str) -> str:
    """Hash of the servers a config of Claude Code starts, see servers_in,
    and of nothing else in it: the rest is rewritten by every session.
    The file is a session's to write, so one that is not a plain file
    says so, and one too large or too odd to read is told from one
    written since as file_stamp does."""
    file = open_plain(config)
    if file is None:
        return "absent"
    try:
        with file:
            content = file.read(SERVERS_BYTES + 1)
    except OSError:
        return "unreadable"
    held = None if len(content) > SERVERS_BYTES else json_object(content)
    if held is None:
        return "not read: " + file_stamp(config)
    try:
        said = sorted(servers_in(held))
    except (ValueError, RecursionError):
        return "not read: " + file_stamp(config)
    return sha256_hex(json.dumps(said).encode())


def hash_files(paths: list[str], fingerprint: dict[str, str]) -> None:
    """Add the hash of each file or link among the paths to a
    fingerprint, while no more than MOST_HASHED_BYTES were read for it.
    A file that would go past that is told apart as file_stamp does: any
    number of files of any size is a session's to make, and the check
    must end. The paths are in the same order at the start and the end
    of a session, so the same files are read both times unless one of
    them changed."""
    left = MOST_HASHED_BYTES
    for path in paths:
        if not (os.path.isfile(path) or os.path.islink(path)):
            continue
        try:
            size = min(os.path.getsize(path), HASHED_BYTES)
        except OSError:
            # A link to nothing, hashed as where it points
            size = 0
        if size > left:
            fingerprint[path] = "not read: " + file_stamp(path)
            continue
        left -= size
        fingerprint[path] = file_hash(path)


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


def tree_files(
    root: str, fingerprint: dict[str, str], most: int = MOST_TREE_FILES
) -> list[str]:
    """The files under a directory, no more than most of them: a tree
    with more has the rest said as unwatched in the fingerprint, which
    shows as a change when a session made it so. A link to a directory is
    listed and not entered, the root too: a session can point one at the
    whole disk, and the link itself is what changed then. In the order of
    their names, the files of a directory ahead of what is below it: the
    same ones at the start and the end of a session, where there are more
    than are watched. Without recursion, as module_git_dirs and for the
    same reason."""
    if os.path.islink(root):
        return [root]
    found: list[str] = []
    pending = [root]
    while pending and len(found) <= most:
        below = []
        for entry in listed(pending.pop(), most):
            if entry.is_dir(follow_symlinks=False):
                below.append(entry.path)
            else:
                found.append(entry.path)
        # The first by its name is the next looked into
        pending += reversed(below)
    if len(found) > most:
        fingerprint[f"{root}: more than {most} files, the rest"] = UNWATCHED
    return found[:most]


def listed(directory: str, most: int) -> list[os.DirEntry[str]]:
    """What a directory holds, in the order of the names, nothing for
    one that cannot be read. No more than could be watched, and one more
    to tell that there is more: a session can put any number there."""
    try:
        with os.scandir(directory) as entries:
            return sorted(islice(entries, most + 1), key=attrgetter("name"))
    except OSError:
        return []


def is_plugin_use_marker(path: str, cache: str) -> bool:
    """Whether a file of the plugin cache is one of the notes of the
    sessions using a plugin (see PLUGIN_USE_MARKERS). Only inside that
    directory at the top of a version: one of that name further down is
    the plugin's own, and a link put in its place is listed as itself, not
    as what is inside, so both are still watched."""
    parts = os.path.relpath(path, cache).split(os.sep)
    return (
        len(parts) > PLUGIN_VERSION_DEPTH + 1
        and parts[PLUGIN_VERSION_DEPTH] == PLUGIN_USE_MARKERS
    )


def module_git_dirs(directory: str, fingerprint: dict[str, str]) -> list[str]:
    """The git directories of the submodules kept under a directory, and of
    theirs, no more than MOST_MODULES of them and of the directories
    looked into for them: the rest is said as unwatched in the
    fingerprint. A submodule's name can hold slashes, so they sit at any
    depth. Without recursion: a session can nest directories deeper than
    Python calls, and the check must not be made to fail."""
    found: list[str] = []
    pending = [directory]
    looked = 0
    while pending and looked <= MOST_MODULES:
        looked += 1
        for entry in listed(pending.pop(), MOST_MODULES):
            if not entry.is_dir(follow_symlinks=False):
                continue
            if os.path.isfile(os.path.join(entry.path, "HEAD")):
                found.append(entry.path)
                pending.append(os.path.join(entry.path, "modules"))
            else:
                pending.append(entry.path)
    if pending or len(found) > MOST_MODULES:
        said = f"{directory}: more than {MOST_MODULES} submodules, the rest"
        fingerprint[said] = UNWATCHED
    return found[:MOST_MODULES]


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
    config = os.path.join(directory, ".git", "config")
    if not os.path.isfile(config):
        # None, or a pipe a session left for git to wait on
        return None
    try:
        value = subprocess.run(
            ["git", "config", "--file", config]
            + ["--type=path", "--get", "core.hooksPath"],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=True,
            text=True,
            errors="replace",
            timeout=GIT_SECONDS,
        ).stdout.strip()
    except (OSError, subprocess.SubprocessError):
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
    without it: it is hashed like any other, so the change that made it
    so still shows."""
    commands = list(commands_in(settings_object(settings_file)))
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
    fingerprint: dict[str, str],
) -> list[str]:
    """What is watched of a project or of ~/.claude for Claude's sake,
    what is not said in the fingerprint, see tree_files."""
    watched = [os.path.join(root, name) for name in files]
    for name in trees:
        watched += tree_files(os.path.join(root, name), fingerprint)
    for name in command_files:
        watched += named_files(os.path.join(root, name), root)
    return watched


def host_exec_fingerprint(
    directories: list[str],
    claude_dir: str = "",
    memory: Sequence[str] = (),
    shared_config: str = "",
) -> dict[str, str]:
    """Hashes, by path, of the files a session can write that run commands
    on the host once it is over, or that Claude follows there. In each
    mounted directory: the git config and hooks, of its submodules too,
    Claude's settings and the scripts they name, and its instructions
    (CLAUDE.md, skills, agents, commands, rules). In ~/.claude the same,
    most of which is read-only in a session, and the plugins, which are
    not and are told apart by file_stamp. They have to stay writable for
    git and claude to work, so instead of locking them the launcher compares
    this before and after a session (see report_tampering). With them
    what Claude remembers of the project, the files of the memory
    directories, which is said apart (see report_memory), and the
    servers of the config the sandboxed sessions share, which is too
    (see report_servers). Not seen: a CLAUDE.md below the top of a
    project, and what a script goes on to run."""
    fingerprint: dict[str, str] = {}
    watched = []
    for directory in directories:
        git_dir = os.path.join(directory, ".git")
        # A file, in a working tree or a submodule: where its directory is
        watched.append(git_dir)
        modules = module_git_dirs(os.path.join(git_dir, "modules"), fingerprint)
        for each in (git_dir, *modules):
            for config in git_configs(each):
                fingerprint[config] = git_config_hash(config)
            watched += tree_files(os.path.join(each, "hooks"), fingerprint)
        moved = moved_hooks_dir(directory)
        if moved:
            watched += tree_files(moved, fingerprint)
        watched += claude_files(
            directory, PROJECT_FILES, PROJECT_TREES, COMMAND_FILES, fingerprint
        )
    if claude_dir:
        files = (*CONFIG_FILES, *CONFIG_WATCHED_FILES)
        watched += claude_files(
            claude_dir, files, CONFIG_TREES, ("settings.json",), fingerprint
        )
    for directory in memory:
        watched += tree_files(directory, fingerprint, MOST_MEMORY_FILES)
    hash_files(watched, fingerprint)
    for name in CONFIG_WATCHED_TREES if claude_dir else ():
        root = os.path.join(claude_dir, name)
        for path in tree_files(root, fingerprint, MOST_STAMPED_FILES):
            if name == PLUGIN_CACHE and is_plugin_use_marker(path, root):
                continue
            fingerprint[path] = file_stamp(path)
    if shared_config:
        fingerprint[shared_config] = servers_hash(shared_config)
    return fingerprint


def build_files(root: str, fingerprint: dict[str, str]) -> list[str]:
    """The files of one mounted directory that build_fingerprint hashes,
    the git configs it finds on the way hashed as those are."""
    watched: list[str] = []
    for directory, subdirs, files in os.walk(root):
        if len(watched) > MOST_BUILD_FILES:
            break
        names = {*subdirs, *files}
        if directory != root:
            watched += below_the_top(directory, names, fingerprint)
        watched += [os.path.join(directory, name) for name in BUILD_FILES & names]
        for name in sorted(BUILD_TREES.intersection(subdirs)):
            watched += tree_files(os.path.join(directory, name), fingerprint)
        if WORKFLOWS[0] in subdirs:
            watched += tree_files(os.path.join(directory, *WORKFLOWS), fingerprint)
        subdirs[:] = [
            name
            for name in subdirs
            if name not in NOT_LOOKED_INTO
            and name not in BUILD_TREES
            and os.path.join(directory, name) != os.path.join(root, WORKTREES)
        ]
    return watched


def build_fingerprint(directories: list[str]) -> dict[str, str]:
    """Hashes, by path, of what a session can write that the tools of a
    project run on the host, see BUILD_FILES, anywhere in the mounted
    directories. With what the check of host_exec_fingerprint watches at
    the top of each, found below it: the instructions and settings Claude
    follows in a directory it works in, and the config and hooks of a
    repository that is there, or that a session planted there."""
    fingerprint: dict[str, str] = {}
    watched: list[str] = []
    try:
        for root in directories:
            watched += build_files(root, fingerprint)
    except RecursionError:
        # Directories nested deeper than Python walks, a session's doing:
        # said as a change, the check must not be made to fail
        fingerprint["directories nested too deep to look into"] = UNWATCHED
    hash_files(watched[:MOST_BUILD_FILES], fingerprint)
    if len(watched) > MOST_BUILD_FILES:
        fingerprint[f"more than {MOST_BUILD_FILES} such files, the rest"] = UNWATCHED
    return fingerprint


def below_the_top(
    directory: str, names: set[str], fingerprint: dict[str, str]
) -> list[str]:
    """What is watched of a directory below the top of a project for
    git's and Claude's sake, as host_exec_fingerprint does of the top:
    the files to hash, the git configs hashed as those are."""
    watched: list[str] = []
    if CLAUDE_MARKS & names:
        watched += claude_files(
            directory, PROJECT_FILES, PROJECT_TREES, COMMAND_FILES, fingerprint
        )
    if ".git" in names:
        git_dir = os.path.join(directory, ".git")
        # A file, in a working tree or a submodule: where its directory is
        watched.append(git_dir)
        for config in git_configs(git_dir):
            fingerprint[config] = git_config_hash(config)
        watched += tree_files(os.path.join(git_dir, "hooks"), fingerprint)
    return watched


def differing(before: dict[str, str], after: dict[str, str]) -> list[str]:
    """The paths two fingerprints do not agree on, in their order: those
    of a file that changed, came or went."""
    return sorted(
        path
        for path in before.keys() | after.keys()
        if before.get(path) != after.get(path)
    )


def first_named(paths: list[str]) -> list[str]:
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
    changed = differing(before, after)
    if not changed:
        return
    whose = f"the session {unchecked} started" if unchecked else "this session started"
    print(
        f"claude-airlock: since {whose}, these files that your tools run on the"
        " host (make, a package manager, a test runner, a hook manager, an"
        " editor), or that git and Claude follow below the top of the"
        " project, have changed:",
        *first_named(changed),
        "Read them before you build, test or commit there outside the sandbox.",
        sep="\n",
        file=sys.stderr,
    )


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


def report_memory(changed: list[str], unchecked: str = "") -> None:
    """Name the changed files of what Claude remembers of the project.
    Said apart from the rest: a session writes there in the ordinary way
    of things, when it is told something to keep. But what is there is
    given to every later session as the user's own notes, so what a
    session read can have it leave instructions for the next ones."""
    if not changed:
        return
    whose = f"the session {unchecked}" if unchecked else "this session"
    print(
        f"claude-airlock: {whose} changed what Claude remembers of this project,"
        " which every later session here is told:",
        *first_named(changed),
        "Read them, a later session follows what they say.",
        sep="\n",
        file=sys.stderr,
    )


def report_servers(config: str, unchecked: str = "") -> None:
    """Say that the servers of the config the sandboxed sessions share
    have changed. Said apart from the rest: nothing of it runs on the
    host, but a server is a command, and one a session of this project
    added there for every project, or for another one, is started by
    the next session of that project, in its sandbox and with its
    files."""
    whose = f"the session {unchecked}" if unchecked else "this session"
    print(
        f"claude-airlock: {whose} changed the MCP servers that sandboxed sessions"
        " start, of other projects too:",
        f"  {config}",
        "Look at them (claude mcp list in a session) before the next session.",
        sep="\n",
        file=sys.stderr,
    )


def report_tampering(
    before: dict[str, str],
    after: dict[str, str],
    unchecked: str = "",
    claude_dir: str = "",
    memory: Sequence[str] = (),
    shared_config: str = "",
) -> None:
    """Name the files that differ, see named_changes for how, those of
    the memory directories apart (see report_memory), and the servers of
    the sandbox's own config (see report_servers). unchecked is the
    name of an earlier session that ended without this check, when the
    report is the late one for it."""
    differ = differing(before, after)
    roots = tuple(directory + os.sep for directory in memory)
    remembered = [path for path in differ if path in memory or path.startswith(roots)]
    report_memory(remembered, unchecked)
    # Not for a check saved by a version that did not watch them
    if shared_config and shared_config in differ and shared_config in before:
        report_servers(shared_config, unchecked)
    others = set(differ).difference(remembered, [shared_config])
    changed = named_changes([path for path in differ if path in others], claude_dir)
    if not changed:
        return
    if unchecked:
        heading = (
            f"claude-airlock: the session {unchecked} ended without its check. Since"
            " it started, by its doing or yours, these files that can run commands"
            " on the host, or that Claude follows there, have changed:"
        )
    else:
        heading = (
            "claude-airlock: this session changed files that can run commands"
            " on the host, or that Claude follows there:"
        )
    print(
        heading,
        *(f"  {path}" for path in changed),
        "Review them before using git or claude there outside the sandbox.",
        sep="\n",
        file=sys.stderr,
    )


def texts(value: object) -> list[str]:
    """A list of a pending check as the texts it holds. Raises TypeError
    for what is no list."""
    if not isinstance(value, list):
        raise TypeError("not a list")
    return [str(text) for text in value]


def fingerprint_of(value: object) -> dict[str, str]:
    """A fingerprint of a pending check. Raises TypeError for what is
    none."""
    if not isinstance(value, dict):
        raise TypeError("not a fingerprint")
    return {str(path): str(stamp) for path, stamp in value.items()}


@dataclass(frozen=True)
class HostCheck:
    """What a session is checked against once it is over: the directories
    it could write, and how the files watched in them were as it started
    (see host_exec_fingerprint and build_fingerprint)."""

    watched: list[str]
    claude_dir: str
    memory: list[str]
    before: dict[str, str]
    # None in a check saved by a version that did not take it
    build: dict[str, str] | None
    # The config the sandboxed sessions share, empty in a check saved by
    # a version that did not watch it
    shared_config: str = ""

    @classmethod
    def take(
        cls, watched: list[str], claude_dir: str, memory: list[str], shared_config: str
    ) -> HostCheck:
        """The check of a session about to start."""
        before = host_exec_fingerprint(watched, claude_dir, memory, shared_config)
        build = build_fingerprint(watched)
        return cls(watched, claude_dir, memory, before, build, shared_config)

    def as_fields(self) -> dict[str, object]:
        return {
            "watched": self.watched,
            "claude_dir": self.claude_dir,
            "before": self.before,
            "build": self.build or {},
            "memory": self.memory,
            "shared_config": self.shared_config,
        }

    @classmethod
    def from_fields(cls, pending: dict) -> HostCheck:
        """A check as it was saved. Raises KeyError or TypeError for
        what is none. The fields after the first two are not in a check
        saved by an earlier version."""
        return cls(
            texts(pending["watched"]),
            str(pending.get("claude_dir", "")),
            texts(pending.get("memory", [])),
            fingerprint_of(pending["before"]),
            fingerprint_of(pending["build"]) if "build" in pending else None,
            str(pending.get("shared_config", "")),
        )

    def report(self, unchecked: str = "") -> None:
        """Compare with how the files are now and say what changed.
        unchecked is the name of an earlier session that ended without
        this check, when the report is the late one for it."""
        after = host_exec_fingerprint(
            self.watched, self.claude_dir, self.memory, self.shared_config
        )
        report_tampering(
            self.before,
            after,
            unchecked,
            self.claude_dir,
            self.memory,
            self.shared_config,
        )
        if self.build is not None:
            report_build_changes(self.build, build_fingerprint(self.watched), unchecked)


class PendingCheck:
    """The check of a session, kept on disk until it has run. A launcher
    that dies with its terminal (a killed Emacs buffer, a closed window,
    a crash) never gets to compare, the next launch finds the file and
    does it instead (see report_unchecked_sessions). The file is named
    after the container."""

    def __init__(self, file: Path, check: HostCheck) -> None:
        self._file = file
        self._check = check

    @classmethod
    def begin(cls, host: Host, session: str, watched: list[str]) -> PendingCheck:
        """Take the check of a session about to start and keep it, once
        the checks earlier sessions left have run. Written whole: a
        launcher that starts meanwhile reads the checks that are there,
        and drops one it cannot read."""
        file = Path(host.pending_checks_dir, session + ".json")
        report_unchecked_sessions(file.parent)
        shared_config = os.path.join(host.sandbox_claude_dir, CONFIG)
        check = HostCheck.take(
            watched, host.claude_dir, memory_dirs(host), shared_config
        )
        private_dir(str(file.parent))
        pending = {**Launcher.current().as_fields(), **check.as_fields()}
        write_whole(str(file), json.dumps(pending))
        return cls(file, check)

    def drop(self) -> None:
        """For a session that did not start: there is nothing of it to
        check."""
        self._file.unlink(missing_ok=True)

    def run(self) -> None:
        """Run the check of the session, now over."""
        self._check.report()
        self._file.unlink(missing_ok=True)


def report_unchecked_sessions(directory: Path) -> None:
    """Run the check for every session that ended without it, one still
    going is left alone."""
    for file in sorted(directory.glob("*.json")):
        try:
            pending = json.loads(file.read_text(encoding="utf-8"))
            launcher = Launcher.from_fields(pending)
            check = HostCheck.from_fields(pending)
        except (OSError, ValueError, KeyError, TypeError, AttributeError):
            # Said out loud, a check must not vanish without a word
            print(
                f"claude-airlock: dropping an unreadable pending check: {file}",
                file=sys.stderr,
            )
            file.unlink(missing_ok=True)
            continue
        if session_alive(launcher, file.stem):
            continue
        check.report(file.stem)
        file.unlink(missing_ok=True)
