"""What a session is given of the host besides its project: the
directories mounted next to it, what of them it cannot change, and the
files of secrets hidden from it."""

from __future__ import annotations

import fnmatch
import os
import stat
from dataclasses import dataclass

from ..docker import env_arg, hidden_arg, mount_arg
from ..errors import Fatal
from ..files import expand_home
from ..settings import SESSION_DIRS, Host, Settings

SHADOWED_NAMES = (".env", ".env.*", ".envrc", ".netrc", ".pypirc")
SHADOW_EXEMPT = (".env.example", ".env.sample", ".env.template")
SHADOW_PRUNED_DIRS = ("node_modules", ".git")


@dataclass(frozen=True)
class ExtraDir:
    """A host directory mounted alongside the project, at its host path."""

    path: str
    read_only: bool = False


def kept_out(host: Host) -> list[str]:
    """The directories of the home that are never a session's to have,
    nor anything in them or around them: the user's keys, and what
    decides how the next session is sandboxed and what it is told, the
    launcher's settings and records and Claude's own directory. What a
    session needs of the last is mounted by the launcher, see home.py."""
    return [
        os.path.join(host.home, ".ssh"),
        os.path.join(host.home, ".gnupg"),
        host.claude_dir,
        host.user_conf,
        host.state_dir,
    ]


def reaches(one: str, other: str) -> bool:
    """Whether one of two directories is the other or is inside it,
    either way round: mounting the first brings in the second, or a part
    of it."""
    one, other = one.rstrip("/") + "/", other.rstrip("/") + "/"
    return one.startswith(other) or other.startswith(one)


def refuse_unsafe_dir(path: str, host: Host) -> None:
    """Refuse the filesystem root, the home directory or any of its parents:
    mounting one read-write would expose the whole home and defeat the
    sandbox. And what is kept out of every session, see kept_out, with
    the directories around it. By the path as it is written and by where
    it leads, a link to the home directory is the home directory."""
    real = os.path.realpath(path)
    for home, directory in ((host.home, path), (os.path.realpath(host.home), real)):
        if (home.rstrip("/") + "/").startswith(directory.rstrip("/") + "/"):
            raise Fatal(f"refusing to mount {path}: it would defeat the sandbox")
    for kept in kept_out(host):
        if reaches(path, kept) or reaches(real, os.path.realpath(kept)):
            raise Fatal(
                f"refusing to mount {path}: {kept} is not a session's to have,"
                " it would defeat the sandbox"
            )


def refuse_links_out(dirs: list[ExtraDir], host: Host) -> None:
    """Refuse a directory to mount that is named by a path in the project,
    or in another directory a session can write, and is not in there: it
    is reached through a link, which a session could have left for this,
    to be given the next time what it points to. One the user keeps such
    a link to is named by where it is."""
    writable = [host.project_dir, *(each.path for each in dirs if not each.read_only)]
    for extra in dirs:
        for root in writable:
            inside = extra.path.startswith(root.rstrip("/") + "/")
            if inside and within(extra.path, root) is None:
                raise Fatal(
                    f"refusing to mount {extra.path}: it is a link out of {root},"
                    " which a session could have made. Name the directory it"
                    " leads to"
                )


def absolute_path(raw: str, host: Host) -> str:
    """A path as written by the user made absolute, a leading ~ expanded
    and a relative one taken from the project."""
    expanded = expand_home(raw, host.home)
    return os.path.normpath(os.path.join(host.project_dir, expanded))


def resolve_dir(raw: str, host: Host) -> str:
    """Absolute path of an existing directory."""
    path = absolute_path(raw, host)
    if not os.path.isdir(path):
        raise Fatal(f"not a directory: {raw}")
    return path


def add_extra_dir(
    dirs: list[ExtraDir], raw: str, host: Host, read_only: bool = False
) -> None:
    """Add a directory to mount. Duplicates and the project itself are
    skipped: docker rejects a repeated mount destination, and the project is
    already mounted. A directory already added read-write stays so."""
    path = resolve_dir(raw, host)
    refuse_unsafe_dir(path, host)
    if path == host.project_dir or any(extra.path == path for extra in dirs):
        return
    dirs.append(ExtraDir(path, read_only))


def configured_extra_dirs(settings: Settings, host: Host) -> list[ExtraDir]:
    """The directories asked for by the settings, before the command line."""
    dirs: list[ExtraDir] = []
    # The scratch directory shared between sessions. The default is skipped
    # when missing, one asked for by name must exist.
    default_shared = os.path.join(host.home, "claude-shared")
    if settings.shared_dir is None:
        if os.path.isdir(default_shared):
            add_extra_dir(dirs, default_shared, host)
    elif settings.shared_dir:
        add_extra_dir(dirs, settings.shared_dir, host)
    for raw in settings.extra_dirs:
        add_extra_dir(dirs, raw, host)
    for raw in settings.extra_dirs_ro:
        add_extra_dir(dirs, raw, host, read_only=True)
    return dirs


def within(path: str, root: str) -> str | None:
    """Where a path is under a directory as that directory is mounted,
    none when it is not under it. By where the two lead, either can be
    reached through a link."""
    real_path, real_root = os.path.realpath(path), os.path.realpath(root)
    if real_path != real_root and not real_path.startswith(real_root + os.sep):
        return None
    return os.path.normpath(os.path.join(root, os.path.relpath(real_path, real_root)))


def protected_dirs(
    dirs: list[ExtraDir], settings: Settings, host: Host
) -> tuple[list[ExtraDir], list[str]]:
    """What CLAUDE_AIRLOCK_PROTECT makes of a session's mounts: the
    directories to mount, those it names read-only, and the paths inside
    one of them (or the project) to mount read-only on top, each as it is
    found there. For what a session must be able to read and must not
    change, wherever it is mounted from: the host's claude may follow
    files that are in a directory every session can write, a kit of
    skills in the shared directory for one. A path that is in no mounted
    directory is not in the session at all, and passed over."""
    dirs = list(dirs)
    inside: list[str] = []
    for raw in settings.protect:
        path = absolute_path(raw, host)
        if within(host.project_dir, path):
            raise Fatal(
                f"cannot protect {raw}: the project is in it, --add-dir-ro"
                " mounts a directory read-only"
            )
        roots = [host.project_dir, *(extra.path for extra in dirs)]
        found = [mounted for mounted in (within(path, r) for r in roots) if mounted]
        if not found:
            continue
        if not os.path.lexists(path):
            # It could be made from inside the session, as anything
            raise Fatal(f"cannot protect {raw}: it does not exist")
        for at, extra in enumerate(dirs):
            if extra.path in found:
                dirs[at] = ExtraDir(extra.path, read_only=True)
        # Each once: a path is found in every mounted directory it is
        # in, the same when one of those is inside another, and docker
        # refuses to mount twice at one place
        for mounted in found:
            if mounted not in roots and mounted not in inside:
                inside.append(mounted)
    return dirs, inside


def held_in_place(inside: list[str], host: Host, dirs: list[ExtraDir]) -> list[str]:
    """The directories between each protected path and what it is mounted
    in, when that is writable. A session cannot write to a read-only
    mount, but it can rename a directory above one and make the path
    again with its own content, which is what the host would then read.
    A directory that is a mount cannot be renamed or removed: each of
    these is mounted on itself, writable as before. None for a path in
    what is read-only anyway, a mounted directory or another protected
    path: there is nothing to rename there, and a writable mount would
    open it."""
    writable = [host.project_dir, *(d.path for d in dirs if not d.read_only)]
    read_only = [*(d.path for d in dirs if d.read_only), *inside]
    held: dict[str, None] = {}
    for path in inside:
        above = [
            root
            for root in (*writable, *read_only)
            if root != path and path.startswith(root + os.sep)
        ]
        root = max(above, key=len, default=None)
        if root is None or root in read_only:
            continue
        directory = os.path.dirname(path)
        while directory != root:
            held[directory] = None
            directory = os.path.dirname(directory)
    return sorted(held)


def protect_args(inside: list[str], host: Host, dirs: list[ExtraDir]) -> list[str]:
    """The read-only mounts of protected_dirs, on top of what they are
    in, and the mounts that keep them where they are, see
    held_in_place."""
    held = [mount_arg(path, path, "z") for path in held_in_place(inside, host, dirs)]
    return held + [mount_arg(path, path, "ro,z") for path in inside]


def extra_dir_args(dirs: list[ExtraDir]) -> list[str]:
    args = [
        mount_arg(extra.path, extra.path, "ro,z" if extra.read_only else "z")
        for extra in dirs
    ]
    if dirs:
        # Read by bin/claude-statusline to list the mounted extra directories
        shown = ":".join(d.path + ("(ro)" if d.read_only else "") for d in dirs)
        args.append(env_arg(SESSION_DIRS, shown))
    return args


def protect_env_args(inside: list[str]) -> list[str]:
    """The session is told what it cannot change of what it has mounted,
    see docker/CLAUDE-airlock.md."""
    return [env_arg("CLAUDE_AIRLOCK_PROTECT", ":".join(inside))] if inside else []


def shadow_args(settings: Settings, host: Host, dirs: list[ExtraDir]) -> list[str]:
    """Shadow .env files (and direnv's .envrc, which commonly exports
    secrets, plus .netrc and .pypirc, which hold nothing but credentials) so
    they are never visible inside the container. Template files (.env.example
    and friends) stay readable, they exist to be read and hold no secrets.
    Regular files only: a .env directory (some virtualenvs) cannot take a
    /dev/null bind mount and would abort the run. CLAUDE_AIRLOCK_SHADOW adds
    name globs, e.g. "*.pem:.npmrc". The whole tree is walked on purpose,
    pruning more directories would be faster but could leave a real secret
    visible."""
    patterns = SHADOWED_NAMES + settings.shadow
    # By path, in the order found: a directory mounted next to the project
    # can be inside it, and docker refuses to mount twice at one place
    hidden: dict[str, None] = {}
    for root in [host.project_dir] + [extra.path for extra in dirs]:
        for directory, subdirs, files in os.walk(root):
            subdirs[:] = sorted(d for d in subdirs if d not in SHADOW_PRUNED_DIRS)
            for name in sorted(files):
                if name in SHADOW_EXEMPT:
                    continue
                if not any(fnmatch.fnmatchcase(name, pattern) for pattern in patterns):
                    continue
                path = os.path.join(directory, name)
                try:
                    plain = stat.S_ISREG(os.lstat(path).st_mode)
                except OSError:
                    # Gone since it was listed, a build or another session
                    continue
                if plain:
                    hidden[path] = None
    return [hidden_arg(path) for path in hidden]
