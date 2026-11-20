"""What a session is given of the host besides its project: the
directories mounted next to it, what of them it cannot change, and the
files of secrets hidden from it."""

from __future__ import annotations

import fnmatch
import os
import stat
from dataclasses import dataclass

from ..docker import env_arg, mount_arg
from ..errors import Fatal
from ..files import expand_home
from ..settings import Host, Settings

SHADOWED_NAMES = (".env", ".env.*", ".envrc", ".netrc", ".pypirc")
SHADOW_EXEMPT = (".env.example", ".env.sample", ".env.template")
SHADOW_PRUNED_DIRS = ("node_modules", ".git")


@dataclass(frozen=True)
class ExtraDir:
    """A host directory mounted alongside the project, at its host path."""

    path: str
    read_only: bool = False


def refuse_unsafe_dir(path: str, host: Host) -> None:
    """Refuse the filesystem root, the home directory or any of its parents:
    mounting one read-write would expose the whole home and defeat the
    sandbox. By the path as it is written and by where it leads, a link
    to the home directory is the home directory."""
    for home, directory in (
        (host.home, path),
        (os.path.realpath(host.home), os.path.realpath(path)),
    ):
        if (home.rstrip("/") + "/").startswith(directory.rstrip("/") + "/"):
            raise Fatal(f"refusing to mount {path}: it would defeat the sandbox")


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
        inside += [m for m in found if m not in roots and m not in inside]
    return dirs, inside


def protect_args(inside: list[str]) -> list[str]:
    """The read-only mounts of protected_dirs, on top of what they are
    in."""
    return [mount_arg(path, path, "ro,z") for path in inside]


def extra_dir_args(dirs: list[ExtraDir]) -> list[str]:
    args = [
        mount_arg(extra.path, extra.path, "ro,z" if extra.read_only else "z")
        for extra in dirs
    ]
    if dirs:
        # Read by bin/claude-statusline to list the mounted extra directories
        shown = ":".join(d.path + ("(ro)" if d.read_only else "") for d in dirs)
        args.append(env_arg("CLAUDE_AIRLOCK_DIRS", shown))
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
    for path in hidden:
        if ":" in path:
            # Not left visible, and not for docker to trip over
            raise Fatal(
                f"cannot hide {path}: docker takes no path with a colon,"
                " rename or remove the file"
            )
    return [mount_arg("/dev/null", path, "ro") for path in hidden]
