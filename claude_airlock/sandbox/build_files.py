"""What is watched of what a session can write that the tools of a
project run on the host, anywhere in the directories it is given, with
what git and Claude follow below the top of a project (see
build_fingerprint), and the launcher's own files when a session can
write its checkout. Compared apart from the rest, and said as something
to read before building, see report_build_changes of tampered.py."""

from __future__ import annotations

import functools
import importlib.machinery
import os
from collections.abc import Iterable, Sequence

from ..paths import is_under, resolved_overlap
from ..settings import CHECKOUT_DIR
from .bounded import (
    MOST_TREE_FILES,
    UNWATCHED,
    Look,
    closed_entry,
    hash_files,
    listed,
    tree_files,
)
from .fingerprint import (
    COMMAND_FILES,
    PROJECT_FILES,
    PROJECT_TREES,
    claude_files,
    git_dir_files,
    repository_files,
)


def _js_configs(*stems: str) -> tuple[str, ...]:
    """The names a config of a tool of JavaScript is run from, which it
    looks for by its stem with each ending of JavaScript and TypeScript."""
    endings = (".js", ".mjs", ".cjs", ".ts", ".mts", ".cts")
    return tuple(stem + ending for stem in stems for ending in endings)


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
        # What direnv evaluates for an .envrc that says use nix, or use
        # flake, and what the second fetches by
        *("shell.nix", "default.nix", "flake.nix", "flake.lock"),
        # What the checkers an editor runs as a file is opened load and
        # run, with no command typed: ESLint, Prettier and Stylelint
        *_js_configs("eslint.config", ".eslintrc"),
        *_js_configs("prettier.config", ".prettierrc"),
        *_js_configs("stylelint.config", ".stylelintrc"),
    )
)
# The directories all of which is such a file, by their name: the hooks of
# husky, the tasks and settings an editor runs, a dev container
BUILD_TREES = frozenset((".husky", ".vscode", ".devcontainer"))
# And those that are by where they are, from the directory they are in:
# what GitHub runs, and the release of yarn that .yarnrc.yml has every
# yarn command run (yarnPath)
NESTED_TREES = (".github/workflows", ".yarn/releases")
# The same of files: what cargo is set by, and the editor's checker of Rust
# runs cargo with (a rustc wrapper, a runner) as the project is opened
NESTED_FILES = (".cargo/config.toml", ".cargo/config")
# What tells that a directory below the top of a project is one Claude
# follows instructions in, or one git runs hooks in: what the check above
# watches at the top
CLAUDE_MARKS = frozenset(
    (".claude", "CLAUDE.md", "CLAUDE.local.md", "AGENTS.md", ".mcp.json")
)
# What git takes a directory for one of its own by, whatever its name
GIT_HEAD = "HEAD"
# The same and a .git as sets, for _named
_HEAD = frozenset((GIT_HEAD,))
_GIT = frozenset((".git",))
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


def build_fingerprint(directories: list[str]) -> dict[str, str]:
    """Hashes, by path, of what a session can write that the tools of a
    project run on the host, see BUILD_FILES, anywhere in the mounted
    directories. With what the check of host_exec_fingerprint watches at
    the top of each, found below it: the instructions and settings Claude
    follows in a directory it works in, and the config and hooks of a
    repository that is there, or that a session planted there. Those
    trees and git directories within one Look, see _build_files."""
    fingerprint: dict[str, str] = {}
    watched: list[str] = []
    # First, should there be more files than are hashed
    watched += _launcher_files(directories, fingerprint)
    look = Look.of_a_fingerprint()
    for root in directories:
        watched += _build_files(root, fingerprint, directories, look)
    hash_files(watched[:MOST_BUILD_FILES], fingerprint)
    if len(watched) > MOST_BUILD_FILES:
        fingerprint[f"more than {MOST_BUILD_FILES} such files, the rest"] = UNWATCHED
    look.into(fingerprint)
    return fingerprint


def _build_files(
    root: str, fingerprint: dict[str, str], within: Sequence[str], look: Look
) -> list[str]:
    """The files of one mounted directory that build_fingerprint hashes,
    the git configs it finds on the way hashed as those are. Through a
    link into a directory within, see tree_files, the trees and the git
    directories no more than the look can take."""
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
            watched += _below_the_top(directory, names, fingerprint, within, look)
        if _named(files, _HEAD):
            # A git directory by what it holds, without a .git to say so:
            # git takes it for one from there on down, with what a session
            # left in it (core.fsmonitor runs a command on git status). At
            # the top too, where only the .git of the project is looked for.
            watched += git_dir_files(directory, directory, fingerprint, within, look)
        watched += _build_files_in(directory, names, subdirs, fingerprint, within, look)
        # In the order of their names: where there are more files than
        # are watched, the same ones fall past the count at the start and
        # at the end of a session, whatever order the directory keeps.
        # What is not looked into by its exact name alone: a session could
        # hide build files in a NODE_MODULES, which is none where case
        # tells names apart.
        trees = set(_named(subdirs, BUILD_TREES))
        subdirs[:] = [
            name
            for name in sorted(subdirs)
            if name not in NOT_LOOKED_INTO
            and name not in trees
            and os.path.join(directory, name) != os.path.join(root, WORKTREES)
        ]
    for directory in closed[:MOST_BUILD_FILES]:
        fingerprint[closed_entry(directory)] = UNWATCHED
    return watched


def _below_the_top(
    directory: str,
    names: set[str],
    fingerprint: dict[str, str],
    within: Sequence[str],
    look: Look,
) -> list[str]:
    """What is watched of a directory below the top of a project for
    git's and Claude's sake, as host_exec_fingerprint does of the top:
    the files to hash, the git configs hashed as those are. Of its
    repository as much as of the one at the top, see repository_files: a
    project can be a directory of clones, each with its submodules and
    the hooks of a hook manager."""
    watched: list[str] = []
    if _named(names, CLAUDE_MARKS):
        watched += claude_files(
            directory,
            PROJECT_FILES,
            PROJECT_TREES,
            COMMAND_FILES,
            fingerprint,
            within,
            look,
        )
    if _named(names, _GIT):
        watched += repository_files(directory, fingerprint, within, look)
    return watched


@functools.cache
def _folded(names: frozenset[str]) -> frozenset[str]:
    return frozenset(name.casefold() for name in names)


def _named(names: Iterable[str], wanted: frozenset[str]) -> list[str]:
    """The names among those that are one of those wanted, whatever their
    case, in their own case and the order of their names: where files
    are told apart by case alone (Linux) another case is another file,
    and watching it too is no harm. Where they are not (macOS), a tool
    that looks for GNUmakefile is given GNUMAKEFILE, git takes .GIT for
    .git and Claude reads claude.md."""
    folded = _folded(wanted)
    return sorted(name for name in names if name.casefold() in folded)


def _nested(directory: str, subdirs: Sequence[str], paths: Sequence[str]) -> list[str]:
    """Where in a directory the paths given are, each by its first part
    in any case among the directories in it (see _named): every one that
    is, a case where case tells names apart being another directory."""
    found: list[str] = []
    for path in paths:
        top, _, inner = path.partition("/")
        for name in _named(subdirs, frozenset((top,))):
            found.append(os.path.join(directory, name, inner))
    return found


def _build_files_in(
    directory: str,
    names: set[str],
    subdirs: list[str],
    fingerprint: dict[str, str],
    within: Sequence[str],
    look: Look,
) -> list[str]:
    """What is watched of one directory for its tools, whatever the case
    of the names (see _named): its build files, the trees that are all
    such files, and those of NESTED_TREES and NESTED_FILES. Through a
    link into a directory within, see tree_files."""
    watched = [os.path.join(directory, name) for name in _named(names, BUILD_FILES)]
    trees = [os.path.join(directory, name) for name in _named(subdirs, BUILD_TREES)]
    for tree in trees + _nested(directory, subdirs, NESTED_TREES):
        watched += tree_files(tree, within=within, look=look).into(fingerprint)
    return watched + _nested(directory, subdirs, NESTED_FILES)


def reaches_launcher(directories: Sequence[str]) -> bool:
    """Whether one of the directories a session is given holds the
    launcher's own checkout, or a part of it: by where each leads, a
    link to the checkout is the checkout."""
    return any(resolved_overlap(d, CHECKOUT_DIR) for d in directories)


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
        try:
            directory = entry.is_dir()
        except OSError:
            # A link that leads round in a loop, or through what cannot
            # be looked into: watched as the link it is, which a session
            # can point elsewhere
            found.append(entry.path)
            continue
        if entry.name.endswith(MODULE_ENDINGS) and not directory:
            found.append(entry.path)
        elif directory:
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
