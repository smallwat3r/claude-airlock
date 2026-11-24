"""Looking at what a session can write without being made to look
forever: hashing files, listing trees and finding the git directories of
submodules, each within a bound. Any number of files, of any size and at
any depth, is a session's to make, and the check of what it left behind
(see tamper.py) must end.

What a bound leaves out is never left unsaid. A look that was cut says so
in what it gives back (see Bounded), for whoever asked to pass on: into a
fingerprint, where it shows as a change when a session made it so."""

from __future__ import annotations

import hashlib
import os
from dataclasses import dataclass
from itertools import islice
from operator import attrgetter

from ..files import open_plain

# No more of a file than this is read. Which files are hashed is partly up
# to the session, and one could be made as large as the disk.
HASHED_BYTES = 64 * 1024 * 1024
# Nor more than this of all the files of one fingerprint: past it a file
# is told from one written since as file_stamp does, without reading it
MOST_HASHED_BYTES = 1024 * 1024 * 1024
# No more files of one tree are watched than this, of a tree whose files
# are hashed and of one whose files are only told apart (the plugins,
# thousands of files as they come): a session can write any number
MOST_TREE_FILES = 5000
MOST_STAMPED_FILES = 100_000
# Nor the submodules of more than this many git directories
MOST_MODULES = 1000
# What a fingerprint has in the place of a hash for what it does not
# watch, by a name that says what that is
UNWATCHED = "unwatched"


@dataclass(frozen=True)
class Bounded:
    """What a look within a bound found, and what it left out: the
    paths, and how the rest is said when there was more than the bound
    takes, empty when that is all there is. The two go together: the
    paths are had through into, which says the rest where a change to it
    will show."""

    found: list[str]
    rest: str = ""

    @property
    def cut(self) -> bool:
        """Whether there was more than was looked at."""
        return bool(self.rest)

    def into(self, fingerprint: dict[str, str]) -> list[str]:
        """What was found, with what was left out said in a fingerprint
        as unwatched: a session that made a tree larger than is watched,
        for a file to be lost in, has that show as a change."""
        if self.rest:
            fingerprint[self.rest] = UNWATCHED
        return self.found


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_hash(path: str) -> str:
    """Hash of a file, of a link where it points and what is there. Of a
    file past HASHED_BYTES, its start and its size. What is no plain file
    is unreadable, and is not opened to find out: a pipe would have the
    check wait for whoever writes to it."""
    digest = hashlib.sha256()
    try:
        if os.path.islink(path):
            digest.update(b"link:" + os.fsencode(os.readlink(path)) + b"\n")
            if not os.path.isfile(path):
                return digest.hexdigest()
        file = open_plain(path, links=True)
        if file is None:
            return "unreadable"
        with file:
            left = HASHED_BYTES
            while left > 0 and (chunk := file.read(min(left, 1024 * 1024))):
                digest.update(chunk)
                left -= len(chunk)
            if left == 0:
                digest.update(b"size:%d" % os.fstat(file.fileno()).st_size)
    except OSError:
        return "unreadable"
    return digest.hexdigest()


def hash_files(paths: list[str], fingerprint: dict[str, str]) -> None:
    """Add the hash of each file or link among the paths to a
    fingerprint, while no more than MOST_HASHED_BYTES were read for it.
    A file that would go past that is told apart as file_stamp does: any
    number of files of any size is a session's to make, and the check
    must end. The paths are in the same order at the start and the end
    of a session, so the same files are read both times unless one of
    them changed."""
    left = MOST_HASHED_BYTES
    for path in paths:
        if not (os.path.isfile(path) or os.path.islink(path)):
            continue
        try:
            size = min(os.path.getsize(path), HASHED_BYTES)
        except OSError:
            # A link to nothing, hashed as where it points
            size = 0
        if size > left:
            fingerprint[path] = "not read: " + file_stamp(path)
            continue
        left -= size
        fingerprint[path] = file_hash(path)


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


def tree_files(root: str, most: int = MOST_TREE_FILES) -> Bounded:
    """The files under a directory, no more than most of them: of a tree
    with more the rest is said to be left out, see Bounded. A link to a
    directory is
    listed and not entered, the root too: a session can point one at the
    whole disk, and the link itself is what changed then. In the order of
    their names, the files of a directory ahead of what is below it: the
    same ones at the start and the end of a session, where there are more
    than are watched. Without recursion, as module_git_dirs and for the
    same reason. No more directories are looked into than files are
    watched, and one that holds more than that is not listed whole: both
    leave files unseen that are no part of the count, a session can
    make any number of directories for one file to be lost among, so
    both have the rest said to be left out as well."""
    if os.path.islink(root):
        return Bounded([root])
    found: list[str] = []
    pending = [root]
    looked = 0
    cut = False
    while pending and len(found) <= most and looked <= most:
        looked += 1
        entries, more = listed(pending.pop(), most)
        cut |= more
        below = []
        for entry in entries:
            if entry.is_dir(follow_symlinks=False):
                below.append(entry.path)
            else:
                found.append(entry.path)
        # The first by its name is the next looked into
        pending += reversed(below)
    if cut or pending or len(found) > most:
        return Bounded(found[:most], f"{root}: more than {most} files, the rest")
    return Bounded(found)


def listed(directory: str, most: int) -> tuple[list[os.DirEntry[str]], bool]:
    """What a directory holds, in the order of the names, nothing for
    one that cannot be read, and whether it holds more than that. No
    more than could be watched and one: a session can put any number there, and
    which of them are left out is then the directory's own order, not
    that of the names. So whoever lists says when it was cut."""
    try:
        with os.scandir(directory) as entries:
            taken = list(islice(entries, most + 1))
    except OSError:
        return [], False
    return sorted(taken, key=attrgetter("name")), len(taken) > most


def module_git_dirs(directory: str) -> Bounded:
    """The git directories of the submodules kept under a directory, and of
    theirs, no more than MOST_MODULES of them and of the directories
    looked into for them: the rest is said to be left out, see Bounded.
    A submodule's name can hold slashes, so they sit at any
    depth. Without recursion: a session can nest directories deeper than
    Python calls, and the check must not be made to fail."""
    found: list[str] = []
    pending = [directory]
    looked = 0
    cut = False
    while pending and looked <= MOST_MODULES:
        looked += 1
        entries, more = listed(pending.pop(), MOST_MODULES)
        cut |= more
        for entry in entries:
            if not entry.is_dir(follow_symlinks=False):
                continue
            if os.path.isfile(os.path.join(entry.path, "HEAD")):
                found.append(entry.path)
                pending.append(os.path.join(entry.path, "modules"))
            else:
                pending.append(entry.path)
    if cut or pending or len(found) > MOST_MODULES:
        said = f"{directory}: more than {MOST_MODULES} submodules, the rest"
        return Bounded(found[:MOST_MODULES], said)
    return Bounded(found)
