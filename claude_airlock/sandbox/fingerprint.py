"""What is watched of what a session can write: the files that run
commands on the host once it is over, or that Claude follows there, and
how they are as a fingerprint, a hash or a stamp for each by its path.
Taken as a session starts and again when it is over, the two are compared
by tampered.py. Read within bounds, see bounded.py."""

from __future__ import annotations

import json
import os
import shlex
import subprocess
from collections.abc import Iterator, Sequence
from itertools import islice
from pathlib import Path

from ..files import expand_home, json_object, open_plain, settings_object
from ..settings import CHECKOUT_DIR, CONFIG_FILES, CONFIG_TREES
from .bounded import (
    MOST_STAMPED_FILES,
    UNWATCHED,
    file_hash,
    file_stamp,
    hash_files,
    module_git_dirs,
    sha256_hex,
    tree_files,
)
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
        # What Emacs sets for the files of a directory, eval forms too
        *(".dir-locals.el", ".dir-locals-2.el"),
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
# No more of what Claude remembers of a project is watched than this many
# files, a session can write any number
MOST_MEMORY_FILES = 1000
# The files whose commands are followed to the scripts they name
COMMAND_FILES = (".claude/settings.json", ".claude/settings.local.json", ".mcp.json")
# The seconds git is given to read a config, it takes a moment: a file a
# session swapped for a pipe must not have the check wait on it
GIT_SECONDS = 10
# What of its checkout the launcher runs and starts its sidecars from: its
# programs, its modules, and the parts of the image with the rules of the
# two proxies. Watched when a session can write them, see launcher_files.
LAUNCHER_TREES = ("bin", "claude_airlock", "docker")
# Where Python keeps what it compiled of the modules, written again
# whenever one changed or another Python runs them
COMPILED = "__pycache__"
# Where Claude Code keeps the transcripts and the memory of each project,
# in its directory, and how many of them are told apart at most
PROJECTS = "projects"
MOST_PROJECTS = 100_000
# The entries of a branch that say where it is pushed to and pulled
# from, as git lists them
BRANCH_TARGETS = (b"remote", b"pushremote")
# The file of a git directory that names another one, which git then takes
# the config and the hooks from in place of its own. No more of it is read
# than this, it is a session's to write.
COMMON_DIR = "commondir"
COMMON_DIR_BYTES = 4096
# The servers of the config the sandboxed sessions share, by this name
# wherever in it they are: those of every project, and those of each
SERVERS = "mcpServers"
# No more of that config is read than this, it is a session's to write
SERVERS_BYTES = 16 * 1024 * 1024


def git_config_hash(file: str) -> str:
    """Hash of a git config without its branch tracking entries, they change
    on every push -u or checkout and cannot run anything, see
    lasting_entries for those that are kept. One that cannot
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
            ["git", "config", "--file", file, "--list", "-z"],
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
    return sha256_hex(b"\0".join(lasting_entries(listing)))


def lasting_entries(listing: bytes) -> list[bytes]:
    """The entries of a git config, as git lists them with -z (a name,
    a line break, the value), without those of branch tracking. Still
    with where a branch is pushed to and pulled from when that is no
    remote the config names: git takes an address there as well as a
    name, and the next push would go to it. A remote it names has its
    address among the entries that are kept."""
    entries = [entry.partition(b"\n") for entry in listing.split(b"\0")]
    remotes = {
        name[len(b"remote.") : -len(b".url")]
        for name, _, _ in entries
        if name.startswith(b"remote.") and name.endswith(b".url")
    }
    # The repository itself, as a branch made from a local one has it
    remotes.add(b".")
    kept = []
    for name, line_break, value in entries:
        if name.startswith(b"branch."):
            key = name.rpartition(b".")[2]
            if key not in BRANCH_TARGETS or value in remotes:
                continue
        kept.append(name + line_break + value)
    return kept


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


def git_configs(git_dir: str) -> list[str]:
    """The config files of a git directory: its own, and the ones a
    worktree reads on top once extensions.worktreeConfig is set."""
    configs = [os.path.join(git_dir, name) for name in ("config", "config.worktree")]
    configs += map(str, sorted(Path(git_dir, "worktrees").glob("*/config.worktree")))
    return [config for config in configs if os.path.isfile(config)]


def common_dir(git_dir: str) -> str | None:
    """The directory a git directory has git take its config and hooks
    from in place of its own, none when it names none: what its commondir
    file says, from the git directory. A linked worktree has one, and a
    session can write one into any git directory, to have git read a
    config and hooks the check would not look at."""
    file = open_plain(os.path.join(git_dir, COMMON_DIR), links=True)
    if file is None:
        return None
    with file:
        try:
            named = file.read(COMMON_DIR_BYTES + 1)
        except OSError:
            return None
    named = named.rstrip(b"\r\n")
    if not named or len(named) > COMMON_DIR_BYTES or b"\0" in named:
        # What git cannot follow either. The file is hashed as it is.
        return None
    return os.path.normpath(os.path.join(git_dir, os.fsdecode(named)))


def git_sources(git_dir: str) -> list[str]:
    """The directories git reads the config and the hooks of a git
    directory from: itself, and the one its commondir names. Both, git
    keeps to the second, but what is left in the first is read again the
    moment the file is gone."""
    common = common_dir(git_dir)
    return [git_dir] if common in (None, git_dir) else [git_dir, common]


def git_files(git_dir: str, fingerprint: dict[str, str]) -> list[str]:
    """What is watched of one git directory: the files to hash, its
    configs hashed as those are. The file that has git read another
    directory, and the config and hooks of both."""
    watched = [os.path.join(git_dir, COMMON_DIR)]
    for source in git_sources(git_dir):
        for config in git_configs(source):
            fingerprint[config] = git_config_hash(config)
        watched += tree_files(os.path.join(source, "hooks")).into(fingerprint)
    return watched


def moved_hooks_dir(directory: str, git_dir: str | None = None) -> str | None:
    """The directory core.hooksPath has git take its hooks from in place of
    .git/hooks (husky and the like), when it is inside the project. One
    outside is out of a session's reach, unless it is mounted too and then
    it is the session's choice of what gets read here. By the config of
    the project's git directory, or of the one given."""
    config = os.path.join(git_dir or os.path.join(directory, ".git"), "config")
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
        watched += tree_files(os.path.join(root, name)).into(fingerprint)
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
        modules = module_git_dirs(os.path.join(git_dir, "modules")).into(fingerprint)
        for each in (git_dir, *modules):
            watched += git_files(each, fingerprint)
        for source in git_sources(git_dir):
            moved = moved_hooks_dir(directory, source)
            if moved:
                watched += tree_files(moved).into(fingerprint)
        watched += claude_files(
            directory, PROJECT_FILES, PROJECT_TREES, COMMAND_FILES, fingerprint
        )
    if claude_dir:
        files = (*CONFIG_FILES, *CONFIG_WATCHED_FILES)
        watched += claude_files(
            claude_dir, files, CONFIG_TREES, ("settings.json",), fingerprint
        )
    for directory in memory:
        watched += tree_files(directory, MOST_MEMORY_FILES).into(fingerprint)
    hash_files(watched, fingerprint)
    for name in CONFIG_WATCHED_TREES if claude_dir else ():
        root = os.path.join(claude_dir, name)
        for path in tree_files(root, MOST_STAMPED_FILES).into(fingerprint):
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
            watched += tree_files(os.path.join(directory, name)).into(fingerprint)
        if WORKFLOWS[0] in subdirs:
            watched += tree_files(os.path.join(directory, *WORKFLOWS)).into(fingerprint)
        subdirs[:] = [
            name
            for name in subdirs
            if name not in NOT_LOOKED_INTO
            and name not in BUILD_TREES
            and os.path.join(directory, name) != os.path.join(root, WORKTREES)
        ]
    return watched


def reaches_launcher(directories: Sequence[str], checkout: str = "") -> bool:
    """Whether one of the directories a session is given holds the
    launcher's own checkout, or a part of it: by where each leads, a
    link to the checkout is the checkout."""
    launcher = os.path.realpath(checkout or CHECKOUT_DIR) + os.sep
    for directory in directories:
        mounted = os.path.realpath(directory) + os.sep
        if launcher.startswith(mounted) or mounted.startswith(launcher):
            return True
    return False


def launcher_files(
    directories: Sequence[str], fingerprint: dict[str, str], checkout: str = ""
) -> list[str]:
    """The files of the launcher itself, when a session can write them:
    its checkout is the project, or in it, or mounted next to it. They
    decide how the next session is sandboxed, its mounts, what its
    filter lets through, the rules of the socket proxy, and run on the
    host with the next launch. Not what Python compiled of them, which
    changes without a session's doing."""
    checkout = checkout or CHECKOUT_DIR
    if not reaches_launcher(directories, checkout):
        return []
    compiled = os.sep + COMPILED + os.sep
    return [
        path
        for tree in LAUNCHER_TREES
        for path in tree_files(os.path.join(checkout, tree)).into(fingerprint)
        if compiled not in path
    ]


def is_launcher_file(path: str, checkout: str = "") -> bool:
    """Whether a path of a fingerprint is of the launcher itself, see
    launcher_files."""
    checkout = checkout or CHECKOUT_DIR
    return path.startswith(
        tuple(os.path.join(checkout, tree) + os.sep for tree in LAUNCHER_TREES)
    )


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
        # First, should there be more files than are hashed
        watched += launcher_files(directories, fingerprint)
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
        watched += git_files(git_dir, fingerprint)
    return watched


def project_names(claude_dir: str) -> list[str] | None:
    """The names of what is where Claude Code keeps the transcripts and
    the memory of each project, whatever each is. None when they cannot
    be told apart, more of them than MOST_PROJECTS: a session can make
    any number."""
    try:
        with os.scandir(os.path.join(claude_dir, PROJECTS)) as entries:
            names = [entry.name for entry in islice(entries, MOST_PROJECTS + 1)]
    except OSError:
        return []
    return sorted(names) if len(names) <= MOST_PROJECTS else None
