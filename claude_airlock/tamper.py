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
from pathlib import Path

from .files import expand_home, private_dir, settings_object, write_whole
from .launcher import Launcher, session_alive
from .plugins import INSTALLED
from .projects import memory_dirs
from .settings import CONFIG_FILES, CONFIG_TREES, Host

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
) -> list[str]:
    """What is watched of a project or of ~/.claude for Claude's sake."""
    watched = [os.path.join(root, name) for name in files]
    for name in trees:
        watched += tree_files(os.path.join(root, name))
    for name in command_files:
        watched += named_files(os.path.join(root, name), root)
    return watched


def host_exec_fingerprint(
    directories: list[str], claude_dir: str = "", memory: Sequence[str] = ()
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
    directories, which is said apart (see report_memory). Not seen: a
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
    for directory in memory:
        watched += tree_files(directory)[:MOST_MEMORY_FILES]
    for path in watched:
        if os.path.isfile(path) or os.path.islink(path):
            fingerprint[path] = file_hash(path)
    for name in CONFIG_WATCHED_TREES if claude_dir else ():
        root = os.path.join(claude_dir, name)
        for path in tree_files(root):
            if name == PLUGIN_CACHE and is_plugin_use_marker(path, root):
                continue
            fingerprint[path] = file_stamp(path)
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
        for name in BUILD_TREES.intersection(subdirs):
            watched += tree_files(os.path.join(directory, name))
        if WORKFLOWS[0] in subdirs:
            watched += tree_files(os.path.join(directory, *WORKFLOWS))
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
        fingerprint["directories nested too deep to look into"] = "unwatched"
    for path in watched[:MOST_BUILD_FILES]:
        if os.path.isfile(path) or os.path.islink(path):
            fingerprint[path] = file_hash(path)
    if len(watched) > MOST_BUILD_FILES:
        fingerprint[f"more than {MOST_BUILD_FILES} such files, the rest"] = "unwatched"
    return fingerprint


def below_the_top(
    directory: str, names: set[str], fingerprint: dict[str, str]
) -> list[str]:
    """What is watched of a directory below the top of a project for
    git's and Claude's sake, as host_exec_fingerprint does of the top:
    the files to hash, the git configs hashed as those are."""
    watched: list[str] = []
    if CLAUDE_MARKS & names:
        watched += claude_files(directory, PROJECT_FILES, PROJECT_TREES, COMMAND_FILES)
    if ".git" in names:
        git_dir = os.path.join(directory, ".git")
        # A file, in a working tree or a submodule: where its directory is
        watched.append(git_dir)
        for config in git_configs(git_dir):
            fingerprint[config] = git_config_hash(config)
        watched += tree_files(os.path.join(git_dir, "hooks"))
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


def report_tampering(
    before: dict[str, str],
    after: dict[str, str],
    unchecked: str = "",
    claude_dir: str = "",
    memory: Sequence[str] = (),
) -> None:
    """Name the files that differ, see named_changes for how, those of
    the memory directories apart (see report_memory). unchecked is the
    name of an earlier session that ended without this check, when the
    report is the late one for it."""
    differ = differing(before, after)
    roots = tuple(directory + os.sep for directory in memory)
    remembered = [path for path in differ if path in memory or path.startswith(roots)]
    report_memory(remembered, unchecked)
    changed = named_changes(
        [path for path in differ if path not in remembered], claude_dir
    )
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

    @classmethod
    def take(cls, watched: list[str], claude_dir: str, memory: list[str]) -> HostCheck:
        """The check of a session about to start."""
        before = host_exec_fingerprint(watched, claude_dir, memory)
        return cls(watched, claude_dir, memory, before, build_fingerprint(watched))

    def as_fields(self) -> dict[str, object]:
        return {
            "watched": self.watched,
            "claude_dir": self.claude_dir,
            "before": self.before,
            "build": self.build or {},
            "memory": self.memory,
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
        )

    def report(self, unchecked: str = "") -> None:
        """Compare with how the files are now and say what changed.
        unchecked is the name of an earlier session that ended without
        this check, when the report is the late one for it."""
        after = host_exec_fingerprint(self.watched, self.claude_dir, self.memory)
        report_tampering(self.before, after, unchecked, self.claude_dir, self.memory)
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
        check = HostCheck.take(watched, host.claude_dir, memory_dirs(host))
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
