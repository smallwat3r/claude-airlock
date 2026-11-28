"""What the mounts of a session go from and to, looked at again right
before docker run: a session that runs meanwhile can write the
directories they are in, and swap what is there for a link."""

from __future__ import annotations

import os
import stat
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from typing import NamedTuple

from ..errors import Fatal
from ..events import flat
from ..files import CLOSED, file_id
from ..paths import is_within, nearest
from ..settings import Host
from .hidden import NO_SECRETS, Hidden
from .mounts import (
    ExtraDir,
    mount_points,
    mounted_dirs,
    refuse_withheld_dirs,
    writable_dirs,
)
from .withheld import HostMounts, Written

# What a file is to the system, whatever it is named and whatever leads to
# it: the device it is on and its number there
type Identity = tuple[int, int]


def _moved(path: str, said: str) -> Fatal:
    """What is said of a path a mount goes from or to that is not as it
    has to be to be mounted: gone, a link, or another than was planned."""
    return Fatal(
        f"cannot mount at {flat(path)}: {said}, a session that runs meanwhile"
        " may have made it so. Launch again once it is as it was"
    )


def _about(path: str, *, links: bool = False) -> os.stat_result | None:
    """What lstat says of a path, or stat through the links on the way
    when told. None for one in a directory closed to the launcher. Fatal
    for one that is not there, see _moved."""
    try:
        return os.stat(path) if links else os.lstat(path)
    except OSError as problem:
        if problem.errno in CLOSED:
            return None
        raise _moved(path, f"{problem.strerror}") from None


def _identity(about: os.stat_result | None) -> Identity:
    """What a path is by what lstat or stat says of it, and what no file
    is for one in a directory closed to the launcher, see _about."""
    return file_id(about) if about else (-1, -1)


def _root_identity(root: str) -> Identity:
    """What a mounted directory leads to, through the links on the way."""
    return _identity(_about(root, links=True))


def _parts_below(root: str, path: str) -> tuple[tuple[Identity, ...], str]:
    """What each part of a path below a mounted directory is, from the
    one under it down to the path, none for the directory itself. With
    the first that is a link, empty when none is, after which no part is
    looked at: a mount at the path would go where the link leads, which
    a session that can write there could have pointed anywhere. Nor any
    after one in a directory closed to the launcher, which cannot be
    told: a file hidden there as it was, see _hidden_again. That
    directory is held in place where a session can write, as every one
    above a hidden file, see _held_in_place of mounts.py."""
    if path == root:
        return (), ""
    parts: list[Identity] = []
    here = root
    for name in os.path.relpath(path, root).split(os.sep):
        here = os.path.join(here, name)
        about = _about(here)
        if about and stat.S_ISLNK(about.st_mode):
            return tuple(parts), here
        parts.append(_identity(about))
        if about is None:
            break
    return tuple(parts), ""


class _Below(NamedTuple):
    """A path below a directory a mount goes from or to, by what each
    part of it is from the one under the directory down, see
    _parts_below."""

    root: str
    path: str
    parts: tuple[Identity, ...]

    @classmethod
    def of(cls, root: str, path: str) -> _Below:
        """The path as it is now. Fatal for one that goes through a link:
        the walk for files to hide follows none, a session can have made
        one since, or the user named a directory to mount inside another
        through one."""
        parts, link = _parts_below(root, path)
        if link:
            raise Fatal(
                f"cannot mount at {flat(path)}: it goes through {flat(link)},"
                " a link, which a session that can write there could point"
                " anywhere. Name the path it leads to"
            )
        return cls(root, path, parts)

    def refuse_moved(self) -> None:
        """Fatal when a part of the path is a link now, or another than
        it was."""
        parts, link = _parts_below(self.root, self.path)
        if link:
            raise _moved(self.path, f"it goes through {flat(link)}, a link now")
        if parts != self.parts:
            raise _moved(self.path, "it is another than was planned")


class _Led(NamedTuple):
    """A path of the host mounted through HostMounts, by where it leads,
    which is below a directory a session can write, or could at an
    earlier launch (see _led_into)."""

    path: str
    below: _Below


def _led_into(files: Iterable[str], written: Written) -> list[_Led]:
    """Of the paths of the host mounted through HostMounts, those that
    lead into a directory a session can write, or could at an earlier
    launch (written), each by where it leads in the one nearest above
    that: ~/.gitconfig or ~/.claude/CLAUDE.md kept as a link into a
    repository of dotfiles that a session of its own has. Not those that
    lead elsewhere, which are out of a session's reach. Fatal for one
    that goes through a link below there, see _Below.of."""
    roots = [root for _, root in written.places]
    led = []
    for path in dict.fromkeys(files):
        real = os.path.realpath(path)
        root = nearest(real, roots)
        if root is not None:
            led.append(_Led(path, _Below.of(root, real)))
    return led


@dataclass(frozen=True)
class Placed:
    """What a session's mounts go from and to of the directories it is
    given, as it was when they were planned, for refuse_moved: each of
    those directories by what it leads to, and each path below one, the
    directories held in place, the paths protected, the files hidden and
    the directories covered (see _Below). The paths of the host mounted
    through HostMounts that lead into a directory a session can write,
    by where they lead (see _led_into). With what refuse_withheld_dirs
    asks of the directories again."""

    host: Host
    dirs: tuple[ExtraDir, ...]
    written_before: tuple[str, ...]
    roots: tuple[tuple[str, Identity], ...]
    below: tuple[_Below, ...]
    led: tuple[_Led, ...]

    @classmethod
    def of(
        cls,
        inside: list[str],
        host: Host,
        dirs: list[ExtraDir],
        hidden: Hidden = NO_SECRETS,
        written_before: Sequence[str] = (),
        from_host: HostMounts | None = None,
    ) -> Placed:
        """Where the mounts of protect_args and hidden.args go, and the
        directories they are in, as they are now, and where the paths of
        the host mounted through from_host lead. Fatal for a path below
        one of those directories that goes through a link, see
        _Below.of."""
        roots = mounted_dirs(dirs, host)
        points = mount_points(inside, host, dirs, hidden)
        paths = (*points.held, *points.protected, *hidden.files, *hidden.covered)
        below = [
            _Below.of(root, path)
            for path in dict.fromkeys(paths)
            if (root := nearest(path, roots, within=is_within)) is not None
        ]
        written = Written.of([*writable_dirs(dirs, host), *written_before])
        return cls(
            host,
            tuple(dirs),
            tuple(written_before),
            tuple((root, _root_identity(root)) for root in roots),
            tuple(below),
            tuple(_led_into(from_host.sources if from_host else (), written)),
        )

    def refuse_moved(self) -> None:
        """Fatal when what the mounts go from or to is not as it was
        planned. The directories they are in, and those mounted inside
        them, are what a session that runs meanwhile can write, and what
        was planned to be held in place there it can swap for a link to
        the home, for docker to mount that, writable, where the
        directory was. So each directory mounted is asked again what
        refuse_withheld_dirs asks of it, and has to lead to what it did,
        and no part of a path below one may be a link now, or another
        than it was. The same of a path of the host that leads into such
        a directory, which has to lead where it did: a session can swap
        it there for a link to a key, or to the home, for docker to mount
        that in its place. For right before docker run: docker resolves each path
        itself once it has them, so a moment is left in which one can
        still be moved, this keeps it to that."""
        refuse_withheld_dirs(list(self.dirs), self.host, self.written_before)
        for root, was in self.roots:
            if _root_identity(root) != was:
                raise _moved(root, "it is another directory than was checked")
        for led in self.led:
            if os.path.realpath(led.path) != led.below.path:
                raise _moved(led.path, "it leads elsewhere than was planned")
        for below in (*self.below, *(led.below for led in self.led)):
            below.refuse_moved()
