"""The directories a session is given besides its project, and what of
them it cannot change: those mounted next to it, the paths protected in
them and the directories held in place above what is mounted inside one.
What of the host a session is never given is in withheld.py, the files
of secrets hidden from it in hidden.py, and the look again at all of it
right before docker run in placed.py."""

from __future__ import annotations

import os
from collections.abc import Sequence
from dataclasses import dataclass
from typing import NamedTuple

from ..docker import env_arg, held_arg, mount_arg, refuse_past_most
from ..errors import Fatal
from ..events import flat
from ..files import expand_home
from ..notice import warn
from ..paths import nearest, resolved_within
from ..settings import SESSION_DIRS, Host, Settings, variable
from .hidden import NO_SECRETS, Hidden
from .withheld import Rule, Written, links_on_the_way, withheld

# No more directories are held in place than this, see refuse_past_most:
# a session can make a file of secrets as deep as a path goes
MOST_HELD = 2000


@dataclass(frozen=True)
class ExtraDir:
    """A host directory mounted alongside the project, at its host path."""

    path: str
    read_only: bool = False


def mounted_dirs(dirs: list[ExtraDir], host: Host) -> list[str]:
    """The directories a session is given: the project, and those mounted
    next to it."""
    return [host.project_dir, *(each.path for each in dirs)]


def writable_dirs(dirs: list[ExtraDir], host: Host) -> list[str]:
    """The directories a session is given to write: the project, and those
    mounted next to it that are not read-only."""
    return [host.project_dir, *(each.path for each in dirs if not each.read_only)]


def refuse_withheld_dirs(
    dirs: list[ExtraDir], host: Host, written_before: Sequence[str] = ()
) -> None:
    """Refuse a directory to mount that withheld keeps back: one that is
    never to be mounted, see _unsafe_dir, and one that is, or goes
    through, a link in the project, or in another directory a session can
    write, or could at an earlier launch (written_before), and leads out
    of there. A session could have left the link for this, to be given
    the next time what it points to, named from there or from anywhere
    else. One the user keeps such a link to is named by where it is. The
    project too, started from such a link: a session of the project it is
    in could have left it, for ~/.aws to be the next project mounted."""
    written = Written.of([*writable_dirs(dirs, host), *written_before])
    for path in mounted_dirs(dirs, host):
        refused = withheld(path, host, written)
        if refused is None:
            continue
        said = refused.said
        if refused.rule is Rule.LINK_OUT:
            said += (
                ". Start from the directory it leads to"
                if path == host.project_dir
                else ". Name the directory it leads to"
            )
        raise Fatal(f"refusing to mount {flat(path)}: {said}")


def _absolute_path(raw: str, host: Host) -> str:
    """A path as written by the user made absolute, a leading ~ expanded
    and a relative one taken from the project."""
    expanded = expand_home(raw, host.home)
    return os.path.normpath(os.path.join(host.project_dir, expanded))


def read_only_paths(
    dirs: list[ExtraDir], settings: Settings, host: Host, inside: Sequence[str]
) -> list[str]:
    """What a session has read-only of what it is given: the directories
    mounted read-only, and the paths CLAUDE_AIRLOCK_PROTECT protects, as
    they are named and as they are found in what is mounted (inside, see
    protected_dirs). Read-only through whatever else leads there, see
    HostMounts of withheld.py."""
    named = [_absolute_path(raw, host) for raw in settings.protect]
    kept = [extra.path for extra in dirs if extra.read_only]
    return list(dict.fromkeys([*kept, *named, *inside]))


def _resolve_dir(raw: str, host: Host) -> str:
    """Absolute path of an existing directory."""
    path = _absolute_path(raw, host)
    if not os.path.isdir(path):
        raise Fatal(f"not a directory: {raw}")
    return path


def add_extra_dir(
    dirs: list[ExtraDir], raw: str, host: Host, read_only: bool = False
) -> None:
    """Add a directory to mount. One that was added before is not added
    again, docker rejects a repeated mount destination, and read-only
    wins whichever way it was asked for first: what one setting keeps a
    session from, another does not give back without a word. The project
    is already mounted, and writable: asked for read-only it is refused,
    there is no session that does not write to it. What is never to be
    mounted is refused with the rest, see refuse_withheld_dirs."""
    path = _resolve_dir(raw, host)
    if path == host.project_dir:
        if read_only:
            raise Fatal(
                f"cannot mount {raw} read-only: it is the project of this"
                " session, which is mounted writable"
            )
        return
    for at, extra in enumerate(dirs):
        if extra.path != path:
            continue
        if read_only:
            dirs[at] = ExtraDir(path, read_only=True)
        elif extra.read_only:
            warn(f"{path} stays read-only: it was asked for read-only as well")
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


def _refuse_protected_link(
    raw: str, path: str, dirs: list[ExtraDir], host: Host
) -> None:
    """Refuse a path to protect that is, or goes through, a link in what
    a session can write: the read-only mount is where the link leads, and
    nothing holds the link, which no mount can. A session would replace
    it with what it likes, which the host reads at the path protected.
    Each link on the way by the mounted directory it is in, the one
    nearest to it by where they lead, whether the link leads out of it or
    not: wherever the path is named from, ~/kit as a link into the shared
    directory too, which is in none of them as it is written."""
    writable = writable_dirs(dirs, host)
    # Each by where it leads, the first of those that lead to the same
    by_real: dict[str, str] = {}
    for root in mounted_dirs(dirs, host):
        by_real.setdefault(os.path.realpath(root), root)
    links, _ = links_on_the_way(path)
    for link in links:
        real = nearest(link, by_real)
        root = by_real[real] if real else ""
        if root in writable:
            raise Fatal(
                f"cannot protect {raw}: it is, or goes through, a link in {root},"
                " which a session could replace. Name the path it leads to"
            )


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
    directory is not in the session at all, and passed over. A directory
    that is mounted from inside a protected path is a part of it, and is
    read-only with it: mounted writable it would be written to there,
    whatever the path around it is said to be."""
    dirs = list(dirs)
    inside: list[str] = []
    for raw in settings.protect:
        path = _absolute_path(raw, host)
        if resolved_within(host.project_dir, path):
            raise Fatal(
                f"cannot protect {raw}: the project is in it, --add-dir-ro"
                " mounts a directory read-only"
            )
        for at, extra in enumerate(dirs):
            if not extra.read_only and resolved_within(extra.path, path):
                dirs[at] = ExtraDir(extra.path, read_only=True)
                warn(
                    f"{extra.path} is mounted read-only: it is in {raw},"
                    " which CLAUDE_AIRLOCK_PROTECT protects"
                )
        _refuse_protected_link(raw, path, dirs, host)
        roots = mounted_dirs(dirs, host)
        found = [
            mounted for mounted in (resolved_within(path, r) for r in roots) if mounted
        ]
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


def _held_in_place(
    inside: list[str], host: Host, dirs: list[ExtraDir], hidden: Hidden = NO_SECRETS
) -> list[str]:
    """The directories between each protected path and what it is mounted
    in, when that is writable. A session cannot write to a read-only
    mount, but it can rename a directory above one and make the path
    again with its own content, which is what the host would then read.
    A directory that is a mount cannot be renamed or removed: each of
    these is mounted on itself, writable as before. None for a path in
    what is read-only anyway, a mounted directory or another protected
    path: there is nothing to rename there, and a writable mount would
    open it.

    The same for a directory mounted inside another, read-only or not,
    the project too, which is no more held by being a mount than what is
    above it. And for each hidden file and covered directory: a session
    cannot read it, but it could move a directory above it to where the
    next launch does not look for files to hide (see SHADOW_PRUNED_DIRS),
    and read it then. Not what is covered, or in it: one mount at a
    place, see Hidden.hides."""
    writable = writable_dirs(dirs, host)
    read_only = [*(d.path for d in dirs if d.read_only), *inside]
    held: dict[str, None] = {}
    for path in (*inside, *hidden.files, *hidden.covered, *mounted_dirs(dirs, host)):
        root = nearest(path, (*writable, *read_only))
        if root is None or root in read_only:
            continue
        directory = os.path.dirname(path)
        while directory != root:
            held[directory] = None
            directory = os.path.dirname(directory)
        refuse_past_most(
            len(held),
            MOST_HELD,
            "directories to hold in place above the files hidden and the paths"
            f" protected, {flat(path)} among them",
        )
    return sorted(path for path in held if not hidden.hides(path))


class _MountPoints(NamedTuple):
    """Where the mounts of protect_args go: the directories held in place,
    and the protected paths mounted read-only."""

    held: list[str]
    protected: list[str]


def mount_points(
    inside: list[str], host: Host, dirs: list[ExtraDir], hidden: Hidden
) -> _MountPoints:
    """Where the mounts of protect_args go, for it and for Placed of
    placed.py: the paths of protected_dirs, but for one that is hidden,
    or covered, which is read-only there already, one mount at a place
    (see Hidden.hides), and the directories that keep them, the
    directories mounted inside another and the hidden files where they
    are, see _held_in_place."""
    protected = [path for path in inside if not hidden.hides(path)]
    return _MountPoints(_held_in_place(protected, host, dirs, hidden), protected)


def protect_args(
    inside: list[str], host: Host, dirs: list[ExtraDir], hidden: Hidden = NO_SECRETS
) -> list[str]:
    """The read-only mounts of protected_dirs, on top of what they are
    in, and the mounts that keep them, see mount_points."""
    points = mount_points(inside, host, dirs, hidden)
    held = [held_arg(path) for path in points.held]
    return held + [mount_arg(path, path, "ro,z") for path in points.protected]


def extra_dir_args(dirs: list[ExtraDir]) -> list[str]:
    args = [
        mount_arg(extra.path, extra.path, "ro,z" if extra.read_only else "z")
        for extra in dirs
    ]
    if dirs:
        # The mounted extra directories, said in docker/CLAUDE-airlock.md
        shown = ":".join(d.path + ("(ro)" if d.read_only else "") for d in dirs)
        args.append(env_arg(SESSION_DIRS, shown))
    return args


def protect_env_args(inside: list[str]) -> list[str]:
    """The session is told what it cannot change of what it has mounted,
    see docker/CLAUDE-airlock.md."""
    return [env_arg(variable("protect"), ":".join(inside))] if inside else []
