"""What is watched of what a session can write: the files that run
commands on the host once it is over, or that Claude follows there, and
how they are as a fingerprint, a hash or a stamp for each by its path.
Taken as a session starts and again when it is over, the two are compared
by tampered.py. Read within bounds, see bounded.py. A git config is read
as git_config.py has it, the config the sandboxed sessions share as
shared_config.py has it, and the build files and the launcher's own are
watched apart, in build_files.py."""

from __future__ import annotations

import os
import re
import shlex
from collections.abc import Iterator, Sequence
from itertools import islice

from ..files import (
    SETTINGS_BYTES,
    NotRead,
    expand_home,
    read_plain,
    settings_object,
)
from ..paths import is_under
from ..settings import CLAUDE_TREES, CONFIG_FILES, CONFIG_TREES
from .bounded import (
    MOST_STAMPED_FILES,
    UNWATCHED,
    Look,
    closed_entry,
    file_hash,
    file_stamp,
    hash_files,
    listed,
    module_git_dirs,
    sha256_hex,
    tree_files,
)
from .git_config import ConfigRead
from .plugins import INSTALLED
from .shared_config import shared_config_hashes

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
    # The commands the preview of Claude's desktop app starts the
    # project's servers with
    ".claude/launch.json",
)
PROJECT_TREES = tuple(f".claude/{name}" for name in CLAUDE_TREES)
# What Claude Code notes for itself of the routines it ran, in their
# directory, of a project and of ~/.claude alike: nothing follows it, and
# every session with one would be reported
ROUTINES = "routines"
ROUTINES_STATE = ".state"
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
# No more of what Claude remembers of a project is watched than this many
# files, a session can write any number
MOST_MEMORY_FILES = 1000
# The files whose commands are followed to the scripts they name
COMMAND_FILES = (".claude/settings.json", ".claude/settings.local.json", ".mcp.json")
# What a git directory holds of a rebase, or a cherry-pick or a revert of
# several commits, still to be done: what it lists is done on --continue,
# an exec line runs its command on the host
GIT_TODOS = (
    os.path.join("rebase-merge", "git-rebase-todo"),
    os.path.join("sequencer", "todo"),
)
# Where a git directory keeps one of its own for each working tree made of
# it (git worktree add), and how many of those are looked into
GIT_WORKTREES = "worktrees"
MOST_WORKTREES = 200
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


def _listing_hash(listing: bytes) -> str:
    """Hash of the entries of a git config that last, see
    _lasting_entries."""
    return sha256_hex(b"\0".join(_lasting_entries(listing)))


def hash_git_config(
    config: str, fingerprint: dict[str, str], look: Look | None = None
) -> None:
    """Add a git config to a fingerprint without its branch tracking
    entries, they change on every push -u or checkout and cannot run
    anything, see _lasting_entries for those that are kept. One that
    cannot be read says so: the file is the session's, which can take
    the right to read it away, and the check must not be made to fail.
    Nor to wait, nor to hold more than a config takes, see git_listing
    of git_config.py: one git has no listing of is hashed as the file it
    is. With the files it includes, theirs too, each by its own path,
    see ConfigRead.
    Git reads them as part of the config, and one that is in the project
    is the session's to write with the config itself left as it was. One
    that is not there yet shows as a change once it is. Past
    MOST_INCLUDED the rest is said to be left out. What a config git was
    not run for includes, past the runs of the look, is not known, the
    look says so (see Look.into). An included file git has no listing
    of is not read, it is told from one written since as file_stamp
    does: a config can name any number of files of any size."""
    read = ConfigRead(config, look or Look())
    for file, listing in read:
        if listing is not None:
            fingerprint[file] = _listing_hash(listing)
        elif file == config:
            fingerprint[file] = file_hash(file)
        else:
            fingerprint[file] = "not read: " + file_stamp(file)
    if read.more:
        rest = f"{config}: more than {read.most} configs included, the rest"
        fingerprint[rest] = UNWATCHED


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
    git_dir: str, watched: list[str], fingerprint: dict[str, str], look: Look
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
    out, and each is one of what the look may still take."""
    worktrees = os.path.join(git_dir, GIT_WORKTREES)
    listing = listed(worktrees, MOST_WORKTREES)
    if listing.more:
        rest = f"{git_dir}: more than {MOST_WORKTREES} working trees, the rest"
        fingerprint[rest] = UNWATCHED
    if listing.closed:
        fingerprint[closed_entry(worktrees)] = UNWATCHED
    sources = []
    for entry in listing.entries[:MOST_WORKTREES]:
        if not look.take():
            break
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
    git_dir: str,
    fingerprint: dict[str, str],
    within: Sequence[str] = (),
    look: Look | None = None,
) -> list[str]:
    """What is watched of one git directory: the files to hash, its
    configs hashed as those are, with the files they include. The file
    that has git read another directory, and the config, the hooks and
    what is still to be done of a rebase (see GIT_TODOS) of both, then
    those of the working trees it keeps. The hooks through a link that
    leads into a directory within, see tree_files. Nothing once the look
    can take no more, which it then says, see Look.into."""
    look = look or Look()
    if not look.any_left():
        return []
    watched = [os.path.join(git_dir, COMMON_DIR)]
    sources = git_sources(git_dir)
    sources += _worktree_sources(git_dir, watched, fingerprint, look)
    for source in dict.fromkeys(sources):
        for config in _git_configs(source):
            hash_git_config(config, fingerprint, look)
        hooks = tree_files(os.path.join(source, "hooks"), within=within, look=look)
        watched += hooks.into(fingerprint)
        watched += [os.path.join(source, todo) for todo in GIT_TODOS]
    return watched


def repository_files(
    directory: str, fingerprint: dict[str, str], within: Sequence[str], look: Look
) -> list[str]:
    """What is watched of the repository of a directory, its .git, at the
    top of a project or below it, see git_dir_files. A .git that is a
    file, in a working tree or a submodule, is where its directory is."""
    git_dir = os.path.join(directory, ".git")
    return [git_dir, *git_dir_files(git_dir, directory, fingerprint, within, look)]


def git_dir_files(
    git_dir: str,
    top: str,
    fingerprint: dict[str, str],
    within: Sequence[str],
    look: Look,
) -> list[str]:
    """What is watched of a git directory: the files to hash, the git
    configs hashed as those are. Its config and hooks, those of its
    submodules, and those of the directory its core.hooksPath names, a
    relative one from top. Top is the working tree of a .git, and the git
    directory itself for one git takes for its own by what it holds, as
    for a bare repository. No more than the look can take, see Look: the
    bounds of each multiply, a session can make each submodule a
    repository of working trees with hooks."""
    modules = module_git_dirs(os.path.join(git_dir, "modules"), look)
    watched: list[str] = []
    for each in (git_dir, *modules.into(fingerprint)):
        watched += git_files(each, fingerprint, within, look)
    for source in git_sources(git_dir):
        for moved in moved_hooks_dirs(top, source, within, look):
            hooks = tree_files(moved, within=within, look=look)
            watched += hooks.into(fingerprint)
    return watched


def _config_values(config: str, name: bytes, look: Look, home: str = "") -> list[str]:
    """The values a git config gives an entry, by its name as git lists
    it (in lower case, but for a subsection), with those of the files it
    includes, whatever their condition, see ConfigRead."""
    values = []
    for _, listing in ConfigRead(config, look, home):
        for entry in listing.split(b"\0") if listing else ():
            key, _, value = entry.partition(b"\n")
            if key == name and value:
                values.append(os.fsdecode(value))
    return values


def moved_hooks_dirs(
    directory: str,
    git_dir: str | None = None,
    within: Sequence[str] = (),
    look: Look | None = None,
) -> list[str]:
    """The directories core.hooksPath has git take its hooks from in place
    of .git/hooks (husky and the like), when they are in the project, or
    in a directory within, those a session was given: one elsewhere is
    out of a session's reach. By the config of the project's git
    directory, or of the one given, and what it includes, where a
    project keeps such a setting as often as in the config itself. Of
    what is included on a condition, whether it holds or not (see
    _config_values): it can hold in one place and not in another, and
    more is watched then, not less. What git lists of the configs is had
    from the look, see git_listing of git_config.py."""
    git_dir = git_dir or os.path.join(directory, ".git")
    roots = [os.path.realpath(root) for root in (directory, *within)]
    found = []
    home = os.path.expanduser("~")
    config = os.path.join(git_dir, "config")
    for value in _config_values(config, b"core.hookspath", look or Look()):
        path = os.path.normpath(os.path.join(directory, expand_home(value, home)))
        hooks = os.path.realpath(path)
        if any(is_under(hooks, root) for root in roots) and path not in found:
            found.append(path)
    return found


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


def _noted_in(tree: str) -> str:
    """What Claude Code notes for itself in a tree of a project or of
    ~/.claude, empty for one where it notes nothing: the state of the
    routines in theirs, see ROUTINES_STATE."""
    if os.path.basename(tree) != ROUTINES:
        return ""
    return os.path.join(tree, ROUTINES_STATE)


def claude_files(
    root: str,
    files: tuple[str, ...],
    trees: tuple[str, ...],
    command_files: tuple[str, ...],
    fingerprint: dict[str, str],
    within: Sequence[str],
    look: Look,
) -> list[str]:
    """What is watched of a project or of ~/.claude for Claude's sake,
    what is not said in the fingerprint, see tree_files, which follows a
    link into a directory within, no more than the look can take. With
    the files its instructions name to be read with them, and without
    what Claude Code notes for itself of its routines, see _noted_in."""
    watched = [os.path.join(root, name) for name in files]
    for name in trees:
        tree = os.path.join(root, name)
        found = tree_files(tree, within=within, look=look).into(fingerprint)
        noted = _noted_in(tree)
        watched += [path for path in found if not (noted and is_under(path, noted))]
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


def _home_git_configs(
    configs: Sequence[str],
    directories: Sequence[str],
    fingerprint: dict[str, str],
    look: Look,
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
        hash_git_config(config, found, look)
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
    directories, which is said apart (see _report_memory), and what
    steers the sessions of the config the sandboxed sessions share,
    which is too (see _report_shared_config). And the user's own git
    configs, see _home_git_configs. Not seen: a CLAUDE.md below the top
    of a project, and what a script goes on to run. The git directories
    and the trees of all of it together are looked at within one Look:
    the plugins and the memory directories, bounded on their own, apart."""
    fingerprint: dict[str, str] = {}
    look = Look.of_a_fingerprint()
    _home_git_configs(git_configs, directories, fingerprint, look)
    watched = []
    for directory in directories:
        watched += repository_files(directory, fingerprint, directories, look)
        watched += claude_files(
            directory,
            PROJECT_FILES,
            PROJECT_TREES,
            COMMAND_FILES,
            fingerprint,
            directories,
            look,
        )
    if claude_dir:
        files = (*CONFIG_FILES, *CONFIG_WATCHED_FILES)
        watched += claude_files(
            claude_dir,
            files,
            CONFIG_TREES,
            ("settings.json",),
            fingerprint,
            directories,
            look,
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
        fingerprint.update(shared_config_hashes(shared_config))
    look.into(fingerprint)
    return fingerprint


def project_names(claude_dir: str) -> list[str] | None:
    """The names of what is where Claude Code keeps the transcripts and
    the memory of each project, whatever each is, none where there is no
    such place. None when they cannot be told apart, more of them than
    MOST_PROJECTS, a session can make any number, or where they cannot be
    listed, which a session can make so too."""
    try:
        with os.scandir(os.path.join(claude_dir, PROJECTS)) as entries:
            names = [entry.name for entry in islice(entries, MOST_PROJECTS + 1)]
    except FileNotFoundError:
        return []
    except OSError:
        return None
    return sorted(names) if len(names) <= MOST_PROJECTS else None
