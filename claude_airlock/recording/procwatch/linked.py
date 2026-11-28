"""The files of secrets by what the kernel knows a file by, for the watcher
to know one a process holds under another name, see Linked."""

from __future__ import annotations

import math
import os
import stat
from collections.abc import Iterator

from .rules import Secrets

# The files of secrets are known by their device and inode too, see
# Linked: found again every so many seconds, no more than so many of
# them, nor more of what is in each of their directories looked at,
# which a session can fill. And no more links followed on the way to
# one than the kernel follows.
LINKED_EVERY = 5.0
MOST_LINKED = 1000
MOST_IN_DIRECTORY = 256
MOST_LINKS = 40
# What the kernel knows a file by, whatever its name: its device and inode
Identity = tuple[int, int]


def identity(about: os.stat_result) -> Identity:
    return about.st_dev, about.st_ino


class Linked:
    """The files of secrets by what the kernel knows a file by, each with
    its path and its kind: a hard link to one is another name of the same
    file, which a process can hold open by that name, ln ~/.ssh/id_rsa x;
    cat x. Found under the root of a process of the session (see within),
    no more often than LINKED_EVERY seconds: a file of secrets is written
    anew under its name as another file, as a login is renewed. One that
    had a link to it when it was last found is known after that too, the
    link is still to it. No more than MOST_LINKED of either, a session
    can fill the directories of secrets with as many as it likes.

    Not of the names hidden from the session (see Secrets of rules.py):
    each is a file mounted over one of the name, which nothing links to,
    a link is made within a mount alone."""

    def __init__(self, secrets: Secrets) -> None:
        self._secrets = secrets
        self._found: dict[Identity, tuple[str, str]] = {}
        self._linked: dict[Identity, tuple[str, str]] = {}
        self._looked = -math.inf

    def look(self, root: str, now: float) -> None:
        """Find the files of secrets under root, a root of the session as
        /proc has it, when it is time to."""
        if now - self._looked < LINKED_EVERY:
            return
        self._looked = now
        found: dict[Identity, tuple[str, str]] = {}
        for path, kind, about in self._kept_in(root):
            if len(found) >= MOST_LINKED:
                break
            # By the first of its paths, that of the container's home
            known = found.setdefault(identity(about), (path, kind))
            room = len(self._linked) < MOST_LINKED
            if about.st_nlink > 1 and (room or identity(about) in self._linked):
                self._linked[identity(about)] = known
        self._found = found

    @property
    def known(self) -> bool:
        """Whether any file of secrets is known by what the kernel knows
        it by."""
        return bool(self._found or self._linked)

    def of(self, held: Identity) -> tuple[str, str] | None:
        """The path and the kind of the file of secrets a file is, by what
        the kernel knows it by, none for one that is none."""
        return self._found.get(held) or self._linked.get(held)

    def _kept_in(self, root: str) -> Iterator[tuple[str, str, os.stat_result]]:
        """The files of secrets under root: each file of the rules there
        is, then the files below each of their directories, each by its
        path in the session. A file alone, not a link to one."""
        files, dirs = self._secrets.places()
        for path, kind in files.items():
            directory = within(root, os.path.dirname(path))
            if directory is None:
                continue
            about = _file(os.path.join(directory, os.path.basename(path)))
            if about:
                yield path, kind, about
        walked: set[str] = set()
        for directory in dirs:
            reached = within(root, directory)
            # Of both homes, which are one
            if reached is None or reached in walked:
                continue
            walked.add(reached)
            for below, about in _files_below(reached):
                held = self._secrets.of(directory + below)
                if held:
                    yield directory + below, held, about


def within(root: str, path: str) -> str | None:
    """Where an absolute path of the session is under one of its roots
    as /proc has it (/proc/PID/root), each link on the way followed as
    the kernel follows it for the session: from that root, where it is
    absolute, as the links of the host's home to the container's are.
    Through /proc the kernel would follow such a link from the watcher's
    own root. None for a path that leads nowhere, or through more links
    than MOST_LINKS. A path is the session's to change as it is followed,
    which can have it lead elsewhere: what is found by it is to be held
    against what the session holds, nothing more."""
    left = [part for part in path.split("/") if part]
    reached: list[str] = []
    links = 0
    while left:
        part = left.pop(0)
        if part in (".", ".."):
            if part == ".." and reached:
                reached.pop()
            continue
        here = os.path.join(root, *reached, part)
        try:
            if not stat.S_ISLNK(os.lstat(here).st_mode):
                reached.append(part)
                continue
            target = os.readlink(here)
        except OSError:
            return None
        links += 1
        if links > MOST_LINKS:
            return None
        if target.startswith("/"):
            reached = []
        left[:0] = [part for part in target.split("/") if part]
    return os.path.join(root, *reached)


def _file(path: str) -> os.stat_result | None:
    """What stat says of a file, none for what is not one: not there, or
    a link, a directory, a device."""
    try:
        about = os.lstat(path)
    except OSError:
        return None
    return about if stat.S_ISREG(about.st_mode) else None


def _files_below(top: str) -> list[tuple[str, os.stat_result]]:
    """The files below a directory, each by its path from it (/a/b), with
    what stat says of it: no more than MOST_IN_DIRECTORY of what is there
    looked at, and no link followed."""
    found: list[tuple[str, os.stat_result]] = []
    waiting = [""]
    looked = 0
    while waiting and looked < MOST_IN_DIRECTORY:
        below = waiting.pop()
        try:
            with os.scandir(top + below) as entries:
                for entry in entries:
                    looked += 1
                    if looked > MOST_IN_DIRECTORY:
                        break
                    path = f"{below}/{entry.name}"
                    if entry.is_dir(follow_symlinks=False):
                        waiting.append(path)
                    elif entry.is_file(follow_symlinks=False):
                        about = _file(entry.path)
                        if about:
                            found.append((path, about))
        except OSError:
            continue
    return found
