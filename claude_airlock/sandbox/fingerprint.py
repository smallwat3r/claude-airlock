"""What is watched of what a session can write: the files that run
commands on the host once it is over, or that Claude follows there, and
how they are as a fingerprint, a hash or a stamp for each by its path.
Taken as a session starts and again when it is over, the two are compared
by tampered.py. Read within bounds, see bounded.py."""

from __future__ import annotations

import importlib.machinery
import json
import os
import re
import shlex
import subprocess
import threading
from collections.abc import Callable, Iterator, Sequence
from itertools import islice

from ..files import (
    SETTINGS_BYTES,
    NotRead,
    expand_home,
    is_under,
    json_object,
    open_plain,
    overlap,
    read_plain,
    settings_object,
)
from ..settings import CHECKOUT_DIR, CONFIG_FILES, CONFIG_TREES, Host
from .bounded import (
    MOST_STAMPED_FILES,
    MOST_TREE_FILES,
    UNWATCHED,
    closed_entry,
    file_hash,
    file_stamp,
    hash_files,
    listed,
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
    # Read as a CLAUDE.md is, by a project that has none
    "AGENTS.md",
    ".claude/AGENTS.md",
    # The prompts Claude Code runs at their times, and the one it runs
    # over and over
    ".claude/scheduled_tasks.json",
    ".claude/loop.md",
)
PROJECT_TREES = (
    ".claude/hooks",
    ".claude/commands",
    ".claude/skills",
    ".claude/agents",
    ".claude/rules",
    ".claude/output-styles",
    ".claude/workflows",
    ".claude/routines",
)
# What Claude Code notes for itself of the routines it ran, in their
# directory: nothing follows it, and every session with one would be
# reported
ROUTINES_STATE = os.path.join(".claude", "routines", ".state")
# What the agents of a project remember from one session to the next, in
# the project itself. Said with what Claude remembers of the project, see
# agent_memory_dirs.
AGENT_MEMORY = (".claude/agent-memory", ".claude/agent-memory-local")
# The files of instructions, by their name wherever they are. Each can
# name others to be read with it, see imported_files.
INSTRUCTION_NAMES = frozenset(("CLAUDE.md", "CLAUDE.local.md", "AGENTS.md"))
# How a file of instructions names another to be read with it: an @ at
# the start of a word, then its path
_IMPORT = re.compile(r"(?:^|(?<=\s))@([^\s@]+)")
# What can follow such a path in a sentence and is no part of it
_AFTER_IMPORT = ".,;:!?)]}'\"`"
# No more files are followed from one file of instructions than this, and
# no further from it than Claude Code follows them: both are a session's
# to write
MOST_IMPORTED = 100
IMPORT_DEPTH = 5
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
CLAUDE_MARKS = frozenset(
    (".claude", "CLAUDE.md", "CLAUDE.local.md", "AGENTS.md", ".mcp.json")
)
# What git takes a directory for one of its own by, whatever its name
GIT_HEAD = "HEAD"
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
GIT_SECONDS = 10.0
# No larger config is given to git, and no more of what git says of one
# is read: both are a session's to make large, and a config of a few
# kilobytes can be written to list as gigabytes
GIT_CONFIG_BYTES = 1024 * 1024
GIT_SAID_BYTES = 4 * 1024 * 1024
# The entries of a config that have git read another file with it, at all
# times or on a condition, as git lists them
_INCLUDES = re.compile(rb"include(if\..*)?\.path", re.DOTALL)
# No more configs are followed from one config than this, a session can
# have each include the next
MOST_INCLUDED = 100
# Where a git directory keeps one of its own for each working tree made of
# it (git worktree add), and how many of those are looked into
GIT_WORKTREES = "worktrees"
MOST_WORKTREES = 200
# What of its checkout the launcher runs and starts its sidecars from: its
# programs, its modules, and the parts of the image with the rules of the
# two proxies. Watched when a session can write them, see _launcher_files.
LAUNCHER_TREES = ("bin", "claude_airlock", "docker")
# What Python takes for a module in a directory it looks for them in, by
# how the name of the file ends, and for a package, by the file a
# directory has: the launcher looks for its package at the top of its
# checkout, see _modules_at_top
MODULE_ENDINGS = tuple(importlib.machinery.all_suffixes())
PACKAGE_FILES = tuple("__init__" + ending for ending in MODULE_ENDINGS)
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
# The settings of Claude Code that it runs as a command, as it does a
# hook's: what gives it a key for the API, renews a login to a cloud and
# makes the headers of what it reports
HELPER_KEYS = (
    "apiKeyHelper",
    "awsAuthRefresh",
    "awsCredentialExport",
    "otelHeadersHelper",
)
COMMAND_KEYS = frozenset(("command", *HELPER_KEYS))
# The servers of the config the sandboxed sessions share, by this name
# wherever in it they are: those of every project, and those of each
SERVERS = "mcpServers"
# No more of that config is read than this, it is a session's to write
SERVERS_BYTES = 16 * 1024 * 1024


# What has git read a repository or a config besides the file it is
# asked about, which the launcher may have been started with
GIT_READ_ELSEWHERE = (
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_COMMON_DIR",
    "GIT_CONFIG",
    "GIT_CONFIG_PARAMETERS",
    "GIT_CONFIG_COUNT",
)


def _git_environment(git_dir: str | None = None) -> dict[str, str]:
    """What git is run with for a config: nothing of a repository, nor
    the user's own config and the system's. Git reads those as it starts
    whatever it is asked, and the files they include, and the user's own
    can be a link into a directory a session was given: a pipe it named
    there would hold every look for GIT_SECONDS, and a file that is no
    config would have git list none. From the root, for the same reason:
    from the project, git would take the repository there for its own,
    and read the config a session can leave in its place. But for the
    git directory given, whose config is the one asked about: what it
    includes on a condition of where the repository is (includeIf
    "gitdir:") is read only in one."""
    told = {"GIT_DIR": git_dir} if git_dir else {}
    environment = {
        name: value
        for name, value in os.environ.items()
        if name not in GIT_READ_ELSEWHERE
        and not name.startswith("GIT_CONFIG_KEY_")
        and not name.startswith("GIT_CONFIG_VALUE_")
    }
    unread = {"GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}
    return {**environment, **unread, **told}


def _git_says(*args: str, git_dir: str | None = None) -> bytes | None:
    """What git says when it is asked about a config, none when that
    cannot be had: no git, a config it cannot read, one it was not done
    with within GIT_SECONDS, and one it says more of than GIT_SAID_BYTES.
    No more than that is read, and git is ended there: a config is the
    session's to write, and one of a few kilobytes can be made to list
    as gigabytes, which would all be held here."""
    try:
        git = subprocess.Popen(
            ["git", *args],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            cwd="/",
            env=_git_environment(git_dir),
        )
    except OSError:
        return None
    # Ended when its time is up, which the read below then sees as the end
    late = threading.Timer(GIT_SECONDS, git.kill)
    late.start()
    try:
        with git:
            said = git.stdout.read(GIT_SAID_BYTES + 1) if git.stdout else b""
            if len(said) > GIT_SAID_BYTES:
                git.kill()
    finally:
        late.cancel()
    if git.returncode != 0 or len(said) > GIT_SAID_BYTES:
        return None
    return said


def git_listing(file: str) -> bytes | None:
    """The entries of a git config as git lists them with -z, none for
    one that git is not asked about or has no answer for (see _git_says).
    Git is not given what is no plain file, a pipe a session of this
    project that still runs can put there, nor a file past
    GIT_CONFIG_BYTES, which no config a user keeps comes near."""
    probe = open_plain(file, links=True)
    if probe is None:
        return None
    with probe:
        try:
            large = os.fstat(probe.fileno()).st_size > GIT_CONFIG_BYTES
        except OSError:
            return None
    if large:
        return None
    return _git_says("config", "--file", file, "--list", "-z")


def _listing_hash(listing: bytes) -> str:
    """Hash of the entries of a git config that last, see
    _lasting_entries."""
    return sha256_hex(b"\0".join(_lasting_entries(listing)))


def _included_configs(listing: bytes, config: str, home: str = "") -> list[str]:
    """The files a git config has git read with it, by its listing:
    those of include.path, and of includeIf whatever its condition, which
    holds in one place and not in another. A relative one is taken from
    where the config is, as git takes it, and ~ is the home given, else
    the one of this process."""
    home = home or os.path.expanduser("~")
    found = []
    for entry in listing.split(b"\0"):
        name, _, value = entry.partition(b"\n")
        if value and _INCLUDES.fullmatch(name):
            path = expand_home(os.fsdecode(value), home)
            found.append(os.path.normpath(os.path.join(os.path.dirname(config), path)))
    return found


def included_configs(
    configs: Sequence[str], home: str, taken: Callable[[str], bool] = lambda _: True
) -> list[str]:
    """The files that some git configs have git read with them, and
    those that these do, each once and as git takes it (see
    _included_configs): those that are there, no more than MOST_INCLUDED.
    Not one that taken says no to, nor what that one includes."""
    seen = set(configs)
    pending = list(reversed(configs))
    found: list[str] = []
    while pending and len(found) < MOST_INCLUDED:
        config = pending.pop()
        listing = git_listing(config)
        if listing is None:
            continue
        for path in _included_configs(listing, config, home):
            if path in seen or not os.path.isfile(path):
                continue
            seen.add(path)
            if taken(path):
                found.append(path)
                pending.append(path)
    return found[:MOST_INCLUDED]


def hash_git_config(config: str, fingerprint: dict[str, str]) -> None:
    """Add a git config to a fingerprint without its branch tracking
    entries, they change on every push -u or checkout and cannot run
    anything, see _lasting_entries for those that are kept. One that
    cannot be read says so: the file is the session's, which can take
    the right to read it away, and the check must not be made to fail.
    Nor to wait, nor to hold more than a config takes, see git_listing:
    one git has no listing of is hashed as the file it is. With the
    files it includes, theirs too, each by its own path. Git reads
    them as part of the config, and one that is in the project is the
    session's to write with the config itself left as it was. One that
    is not there yet shows as a change once it is. No more of them than
    MOST_INCLUDED: the rest is said to be left out. An included file git
    has no listing of is not read, it is told from one written since as
    file_stamp does: a config can name any number of files of any size."""
    pending = [config]
    seen: set[str] = set()
    while pending:
        file = pending.pop()
        if file in seen:
            continue
        if len(seen) >= MOST_INCLUDED:
            rest = f"{config}: more than {MOST_INCLUDED} configs included, the rest"
            fingerprint[rest] = UNWATCHED
            return
        seen.add(file)
        listing = git_listing(file)
        if listing is None:
            unread = "not read: " + file_stamp(file)
            fingerprint[file] = file_hash(file) if file == config else unread
            continue
        fingerprint[file] = _listing_hash(listing)
        included = _included_configs(listing, file)
        pending += [path for path in reversed(included) if os.path.lexists(path)]


def _lasting_entries(listing: bytes) -> list[bytes]:
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


def _servers_in(value: object, at: tuple[str, ...] = ()) -> Iterator[tuple[str, str]]:
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
            yield from _servers_in(inner, (*at, str(key)))


def _servers_hash(config: str) -> str:
    """Hash of the servers a config of Claude Code starts, see _servers_in,
    and of nothing else in it: the rest is rewritten by every session.
    The file is a session's to write, so one that is not a plain file
    says so, and one too large or too odd to read is told from one
    written since as file_stamp does."""
    content = read_plain(config, SERVERS_BYTES)
    if content is NotRead.ABSENT:
        return "absent"
    if content is NotRead.UNREADABLE:
        return "unreadable"
    held = None if isinstance(content, NotRead) else json_object(content)
    if held is None:
        return "not read: " + file_stamp(config)
    try:
        said = sorted(_servers_in(held))
    except (ValueError, RecursionError):
        return "not read: " + file_stamp(config)
    return sha256_hex(json.dumps(said).encode())


def _is_plugin_use_marker(path: str, cache: str) -> bool:
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


def _git_configs(git_dir: str) -> list[str]:
    """The config files of a git directory: its own, and the one a
    working tree reads on top once extensions.worktreeConfig is set.
    Those of the working trees it keeps are read from their own
    directories, see _worktree_sources."""
    configs = [os.path.join(git_dir, name) for name in ("config", "config.worktree")]
    return [config for config in configs if os.path.isfile(config)]


def common_dir(git_dir: str) -> str | None:
    """The directory a git directory has git take its config and hooks
    from in place of its own, none when it names none: what its commondir
    file says, from the git directory. A linked worktree has one, and a
    session can write one into any git directory, to have git read a
    config and hooks the check would not look at."""
    # Its line break is not counted
    named = read_plain(
        os.path.join(git_dir, COMMON_DIR), COMMON_DIR_BYTES + 2, links=True
    )
    if isinstance(named, NotRead):
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


def _worktree_sources(
    git_dir: str, watched: list[str], fingerprint: dict[str, str]
) -> list[str]:
    """The directories git reads a config and hooks from in the working
    trees a git directory keeps (git worktree add), besides the git
    directory itself. Each working tree has a directory of its own in
    there, with a commondir that leads back to the git directory. That
    file is a session's to write: one that leads elsewhere has git take
    the config and the hooks from there in that working tree, and
    without one git takes them from the working tree's own directory. So
    both are directories to watch, and a commondir that leads elsewhere
    is added to what is hashed. One that leads back is not: a working
    tree made in a session (--worktree) is then nothing to report. What
    is there in the place of such a directory, a link, is hashed as it
    is. No more of them than MOST_WORKTREES, the rest is said to be left
    out."""
    worktrees = os.path.join(git_dir, GIT_WORKTREES)
    listing = listed(worktrees, MOST_WORKTREES)
    if listing.more:
        rest = f"{git_dir}: more than {MOST_WORKTREES} working trees, the rest"
        fingerprint[rest] = UNWATCHED
    if listing.closed:
        fingerprint[closed_entry(worktrees)] = UNWATCHED
    sources = []
    for entry in listing.entries[:MOST_WORKTREES]:
        if not entry.is_dir(follow_symlinks=False):
            watched.append(entry.path)
            continue
        sources.append(entry.path)
        elsewhere = common_dir(entry.path)
        if elsewhere is not None and elsewhere not in (git_dir, entry.path):
            watched.append(os.path.join(entry.path, COMMON_DIR))
            sources.append(elsewhere)
    return sources


def git_files(
    git_dir: str, fingerprint: dict[str, str], within: Sequence[str] = ()
) -> list[str]:
    """What is watched of one git directory: the files to hash, its
    configs hashed as those are, with the files they include. The file
    that has git read another directory, and the config and hooks of
    both, then those of the working trees it keeps. The hooks through a
    link that leads into a directory within, see tree_files."""
    watched = [os.path.join(git_dir, COMMON_DIR)]
    sources = git_sources(git_dir)
    sources += _worktree_sources(git_dir, watched, fingerprint)
    for source in dict.fromkeys(sources):
        for config in _git_configs(source):
            hash_git_config(config, fingerprint)
        hooks = tree_files(os.path.join(source, "hooks"), within=within)
        watched += hooks.into(fingerprint)
    return watched


def repository_files(
    directory: str, fingerprint: dict[str, str], within: Sequence[str] = ()
) -> list[str]:
    """What is watched of the repository of a directory, its .git, at the
    top of a project or below it: the files to hash, the git configs
    hashed as those are. Its config and hooks, those of its submodules,
    and those of the directory its core.hooksPath names."""
    git_dir = os.path.join(directory, ".git")
    # A file, in a working tree or a submodule: where its directory is
    watched = [git_dir]
    modules = module_git_dirs(os.path.join(git_dir, "modules")).into(fingerprint)
    for each in (git_dir, *modules):
        watched += git_files(each, fingerprint, within)
    for source in git_sources(git_dir):
        moved = moved_hooks_dir(directory, source, within)
        if moved:
            watched += tree_files(moved, within=within).into(fingerprint)
    return watched


def moved_hooks_dir(
    directory: str, git_dir: str | None = None, within: Sequence[str] = ()
) -> str | None:
    """The directory core.hooksPath has git take its hooks from in place of
    .git/hooks (husky and the like), when it is in the project, or in a
    directory within, those a session was given: one elsewhere is out
    of a session's reach. By the config of the project's git directory,
    or of the one given."""
    git_dir = git_dir or os.path.join(directory, ".git")
    config = os.path.join(git_dir, "config")
    if not os.path.isfile(config):
        # None, or a pipe a session left for git to wait on
        return None
    # With what the config includes, where a project keeps such a setting
    # as often as in the config itself, on a condition of where it is too
    asked = ("--includes", "--type=path", "--get", "core.hooksPath")
    said = _git_says("config", "--file", config, *asked, git_dir=git_dir)
    if said is None:
        return None
    value = said.decode("utf-8", "replace").strip()
    hooks = os.path.realpath(os.path.join(directory, value))
    roots = (directory, *within)
    inside = any(is_under(hooks, os.path.realpath(root)) for root in roots)
    return (
        os.path.normpath(os.path.join(directory, value)) if value and inside else None
    )


def commands_in(value: object) -> Iterator[str]:
    """Every "command" in a settings file, of a hook, a statusline or a
    server, at whatever depth, and each of the "args" it is given: a
    server is as often "node" given its script as the script itself.
    With the settings Claude Code runs as a command under a name of
    their own, see HELPER_KEYS. Without recursion: a file is read at a
    depth Python cannot call to, and the check must not be made to
    fail."""
    pending = [value]
    while pending:
        value = pending.pop()
        if isinstance(value, dict):
            commanded = isinstance(value.get("command"), str)
            for key, inner in value.items():
                if key in COMMAND_KEYS and isinstance(inner, str):
                    yield inner
                elif key == "args" and commanded and isinstance(inner, list):
                    yield from (word for word in inner if isinstance(word, str))
                else:
                    pending.append(inner)
        elif isinstance(value, list):
            pending += value


def _named_files(settings_file: str, base: str) -> list[str]:
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


def _import_text(file: str) -> str:
    """What a file of instructions says, nothing for one that is not
    there, is no plain file or is past what is read of one, as
    settings_object has it of a settings file."""
    content = read_plain(file, SETTINGS_BYTES, links=True)
    return "" if isinstance(content, NotRead) else content.decode("utf-8", "replace")


def imported_files(instructions: str) -> list[str]:
    """The files a file of instructions has Claude read with it, theirs
    too: each @path in it that is a file, a relative one from where the
    file that names it is. Changing one of those changes what Claude is
    told, with the CLAUDE.md as it was. As far from it as IMPORT_DEPTH
    and no more than MOST_IMPORTED: taken by the word, which also takes
    what only looks like one and misses nothing Claude Code would
    read."""
    home = os.path.expanduser("~")
    found: dict[str, None] = {}
    pending = [(instructions, 0)]
    while pending and len(found) < MOST_IMPORTED:
        file, depth = pending.pop()
        for word in _IMPORT.findall(_import_text(file)):
            for named in dict.fromkeys((word, word.rstrip(_AFTER_IMPORT))):
                path = expand_home(named, home)
                path = os.path.normpath(os.path.join(os.path.dirname(file), path))
                if path in found or path == instructions or not os.path.isfile(path):
                    continue
                found[path] = None
                if depth + 1 < IMPORT_DEPTH:
                    pending.append((path, depth + 1))
    return list(found)[:MOST_IMPORTED]


def _claude_files(
    root: str,
    files: tuple[str, ...],
    trees: tuple[str, ...],
    command_files: tuple[str, ...],
    fingerprint: dict[str, str],
    within: Sequence[str] = (),
) -> list[str]:
    """What is watched of a project or of ~/.claude for Claude's sake,
    what is not said in the fingerprint, see tree_files, which follows a
    link into a directory within. With the files its instructions name
    to be read with them, and without what Claude Code notes for itself
    of its routines."""
    watched = [os.path.join(root, name) for name in files]
    noted = os.path.join(root, ROUTINES_STATE)
    for name in trees:
        found = tree_files(os.path.join(root, name), within=within).into(fingerprint)
        watched += [path for path in found if not is_under(path, noted)]
    for name in command_files:
        watched += _named_files(os.path.join(root, name), root)
    for name in files:
        if os.path.basename(name) in INSTRUCTION_NAMES:
            watched += imported_files(os.path.join(root, name))
    return watched


def agent_memory_dirs(directories: Sequence[str]) -> list[str]:
    """Where the agents of a project keep what they remember, in each
    mounted directory. A session writes there in the ordinary way of
    things and every later one is told what is there, as with what
    Claude remembers of the project: said with that, see
    _report_memory."""
    return [
        os.path.join(directory, name)
        for directory in directories
        for name in AGENT_MEMORY
    ]


def home_git_configs(host: Host) -> list[str]:
    """The user's own git configs, which git reads wherever it is run:
    ~/.gitconfig and the one of ~/.config/git."""
    return [
        os.path.join(host.home, ".gitconfig"),
        os.path.join(host.config_home, "git", "config"),
    ]


def _home_git_configs(
    configs: Sequence[str], directories: Sequence[str], fingerprint: dict[str, str]
) -> None:
    """Add the user's own git configs, as those of a repository are, by
    what of them a session could have written: each that is, or that they
    include, which is in a directory it was given, by where it leads.
    Dotfiles are often kept in a repository, with ~/.gitconfig a link
    into it, and git on the host runs what a config says (core.fsmonitor,
    core.pager, an alias) wherever it is run. Not what the user changed
    on the host meanwhile, which is no session's doing."""
    roots = [os.path.realpath(directory) for directory in directories]
    for config in configs:
        found: dict[str, str] = {}
        hash_git_config(config, found)
        for path, stamp in found.items():
            real = os.path.realpath(path)
            if any(is_under(real, root) for root in roots):
                fingerprint[path] = stamp


def host_exec_fingerprint(
    directories: list[str],
    claude_dir: str = "",
    memory: Sequence[str] = (),
    shared_config: str = "",
    git_configs: Sequence[str] = (),
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
    directories, which is said apart (see _report_memory), and the
    servers of the config the sandboxed sessions share, which is too
    (see _report_servers). And the user's own git configs, see
    _home_git_configs. Not seen: a CLAUDE.md below the top of a
    project, and what a script goes on to run."""
    fingerprint: dict[str, str] = {}
    _home_git_configs(git_configs, directories, fingerprint)
    watched = []
    for directory in directories:
        watched += repository_files(directory, fingerprint, directories)
        watched += _claude_files(
            directory,
            PROJECT_FILES,
            PROJECT_TREES,
            COMMAND_FILES,
            fingerprint,
            directories,
        )
    if claude_dir:
        files = (*CONFIG_FILES, *CONFIG_WATCHED_FILES)
        watched += _claude_files(
            claude_dir,
            files,
            CONFIG_TREES,
            ("settings.json",),
            fingerprint,
            directories,
        )
    for directory in memory:
        watched += tree_files(directory, MOST_MEMORY_FILES).into(fingerprint)
    hash_files(watched, fingerprint)
    for name in CONFIG_WATCHED_TREES if claude_dir else ():
        root = os.path.join(claude_dir, name)
        for path in tree_files(root, MOST_STAMPED_FILES).into(fingerprint):
            if name == PLUGIN_CACHE and _is_plugin_use_marker(path, root):
                continue
            fingerprint[path] = file_stamp(path)
    if shared_config:
        fingerprint[shared_config] = _servers_hash(shared_config)
    return fingerprint


def _build_files(
    root: str, fingerprint: dict[str, str], within: Sequence[str]
) -> list[str]:
    """The files of one mounted directory that build_fingerprint hashes,
    the git configs it finds on the way hashed as those are. Through a
    link into a directory within, see tree_files."""
    watched: list[str] = []
    closed: list[str] = []

    def not_looked_into(problem: OSError) -> None:
        if isinstance(problem.filename, str) and not isinstance(
            problem, (FileNotFoundError, NotADirectoryError)
        ):
            closed.append(problem.filename)

    for directory, subdirs, files in os.walk(root, onerror=not_looked_into):
        # A directory closed counts as a file: a session can close any
        # number of them, each a part of the fingerprint
        if len(watched) + len(closed) > MOST_BUILD_FILES:
            break
        names = {*subdirs, *files}
        if directory != root:
            watched += _below_the_top(directory, names, fingerprint, within)
        if GIT_HEAD in files:
            # A git directory by what it holds, without a .git to say so:
            # git takes it for one from there on down, with the config
            # and the hooks a session left in it (core.fsmonitor runs a
            # command on git status). At the top too, where only the .git
            # of the project is looked for.
            watched += git_files(directory, fingerprint, within)
        built = sorted(BUILD_FILES & names)
        watched += [os.path.join(directory, name) for name in built]
        for name in sorted(BUILD_TREES.intersection(subdirs)):
            tree = tree_files(os.path.join(directory, name), within=within)
            watched += tree.into(fingerprint)
        if WORKFLOWS[0] in subdirs:
            tree = tree_files(os.path.join(directory, *WORKFLOWS), within=within)
            watched += tree.into(fingerprint)
        # In the order of their names: where there are more files than
        # are watched, the same ones fall past the count at the start and
        # at the end of a session, whatever order the directory keeps
        subdirs[:] = [
            name
            for name in sorted(subdirs)
            if name not in NOT_LOOKED_INTO
            and name not in BUILD_TREES
            and os.path.join(directory, name) != os.path.join(root, WORKTREES)
        ]
    for directory in closed[:MOST_BUILD_FILES]:
        fingerprint[closed_entry(directory)] = UNWATCHED
    return watched


def reaches_launcher(directories: Sequence[str]) -> bool:
    """Whether one of the directories a session is given holds the
    launcher's own checkout, or a part of it: by where each leads, a
    link to the checkout is the checkout."""
    launcher = os.path.realpath(CHECKOUT_DIR)
    return any(overlap(os.path.realpath(d), launcher) for d in directories)


def _modules_at_top(checkout: str, fingerprint: dict[str, str]) -> list[str]:
    """What Python would take for a module or a package at the top of
    the launcher's checkout, besides the launcher's own: the launcher
    looks for its package there (see bin/claude-airlock), after
    everywhere else, so a module left there under a name the standard
    library has is not run. One under a name it does not have on the
    Python at hand is: readline is tried, and missing from some. So what
    could be one is watched, a file by how its name ends, a directory or
    a link to one by the file that makes it a package. No more entries
    are looked at than files of a tree are watched, the rest is said."""
    listing = listed(checkout, MOST_TREE_FILES)
    if listing.more:
        fingerprint[f"{checkout}: more than {MOST_TREE_FILES} entries, the rest"] = (
            UNWATCHED
        )
    if listing.closed:
        fingerprint[closed_entry(checkout)] = UNWATCHED
    found = []
    for entry in listing.entries:
        if entry.name in LAUNCHER_TREES:
            continue
        if entry.name.endswith(MODULE_ENDINGS) and not entry.is_dir():
            found.append(entry.path)
        elif entry.is_dir():
            found += [
                path
                for name in PACKAGE_FILES
                if os.path.lexists(path := os.path.join(entry.path, name))
            ]
    return found


def _launcher_files(
    directories: Sequence[str], fingerprint: dict[str, str]
) -> list[str]:
    """The files of the launcher itself, when a session can write them:
    its checkout is the project, or in it, or mounted next to it. They
    decide how the next session is sandboxed, its mounts, what its
    filter lets through, the rules of the socket proxy, and run on the
    host with the next launch. And what Python would run in their place
    from the top of the checkout, see _modules_at_top. Not what Python
    compiled of them, which changes without a session's doing."""
    if not reaches_launcher(directories):
        return []
    compiled = os.sep + COMPILED + os.sep
    return [
        path
        for tree in LAUNCHER_TREES
        for path in tree_files(os.path.join(CHECKOUT_DIR, tree)).into(fingerprint)
        if compiled not in path
    ] + _modules_at_top(CHECKOUT_DIR, fingerprint)


def is_launcher_file(path: str) -> bool:
    """Whether a path of a fingerprint is of the launcher itself, see
    _launcher_files: in one of its trees, or what Python would take for
    a module or a package at the top of its checkout."""
    checkout = CHECKOUT_DIR
    if any(is_under(path, os.path.join(checkout, tree)) for tree in LAUNCHER_TREES):
        return True
    above, name = os.path.split(path)
    if above == checkout:
        return name.endswith(MODULE_ENDINGS)
    return name in PACKAGE_FILES and os.path.dirname(above) == checkout


def build_fingerprint(directories: list[str]) -> dict[str, str]:
    """Hashes, by path, of what a session can write that the tools of a
    project run on the host, see BUILD_FILES, anywhere in the mounted
    directories. With what the check of host_exec_fingerprint watches at
    the top of each, found below it: the instructions and settings Claude
    follows in a directory it works in, and the config and hooks of a
    repository that is there, or that a session planted there."""
    fingerprint: dict[str, str] = {}
    watched: list[str] = []
    # First, should there be more files than are hashed
    watched += _launcher_files(directories, fingerprint)
    for root in directories:
        watched += _build_files(root, fingerprint, directories)
    hash_files(watched[:MOST_BUILD_FILES], fingerprint)
    if len(watched) > MOST_BUILD_FILES:
        fingerprint[f"more than {MOST_BUILD_FILES} such files, the rest"] = UNWATCHED
    return fingerprint


def _below_the_top(
    directory: str, names: set[str], fingerprint: dict[str, str], within: Sequence[str]
) -> list[str]:
    """What is watched of a directory below the top of a project for
    git's and Claude's sake, as host_exec_fingerprint does of the top:
    the files to hash, the git configs hashed as those are. Of its
    repository as much as of the one at the top, see repository_files: a
    project can be a directory of clones, each with its submodules and
    the hooks of a hook manager."""
    watched: list[str] = []
    if CLAUDE_MARKS & names:
        watched += _claude_files(
            directory, PROJECT_FILES, PROJECT_TREES, COMMAND_FILES, fingerprint, within
        )
    if ".git" in names:
        watched += repository_files(directory, fingerprint, within)
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
