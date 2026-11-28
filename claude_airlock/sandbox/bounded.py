"""Looking at what a session can write without being made to look
forever: hashing files, listing trees and finding the git directories of
submodules, each within a bound. Any number of files, of any size and at
any depth, is a session's to make, and the check of what it left behind
(see tamper.py) must end.

What a bound leaves out is never left unsaid. A look that was cut says so
in what it gives back (see Bounded), or in the Look of all the looks of a
fingerprint (see Look.into), for whoever asked to pass on: into a
fingerprint, where it shows as a change when a session made it so."""

from __future__ import annotations

import hashlib
import os
from collections.abc import Sequence
from dataclasses import dataclass
from itertools import islice
from operator import attrgetter
from typing import NamedTuple

from ..files import GONE, is_under, open_plain

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
# No more than this is looked at for one fingerprint, of all of its trees
# and git directories together: the files found, the directories looked
# into for them and the git directories whose config and hooks are read.
# Each of those has a bound of its own, and the bounds multiply: a session
# can make a thousand submodules with two hundred working trees each, all
# with hooks, for the check to list for days. See Look.
MOST_WATCHED = 20_000
# Nor is git run more than this many times for one fingerprint, to list a
# config: each run is a process, and a session can have every git
# directory it makes include a hundred configs
MOST_GIT_RUNS = 1000
# What a fingerprint has in the place of a hash for what it does not
# watch, by a name that says what that is
UNWATCHED = "unwatched"


# How the entry of what a count left out ends, see Bounded
LEFT_OUT = ", the rest"


def left_out(fingerprint: dict[str, str]) -> list[str]:
    """What a fingerprint says it left out past a count, in the order of
    the names: a tree, a list or a chain larger than is watched. Not a
    directory that could not be looked into, see closed_entry."""
    return sorted(
        path
        for path, stamp in fingerprint.items()
        if stamp == UNWATCHED and path.endswith(LEFT_OUT)
    )


def closed_entry(directory: str) -> str:
    """What a fingerprint has, as unwatched, for a directory that is there
    and cannot be looked into: a session can take the right to list one
    away, and what it left there is found by its name all the same, by
    make, git and Claude. Said where it is, so one it closed shows as a
    change, and one that was so already does not."""
    return f"{directory}: cannot be looked into, what is in it"


@dataclass(frozen=True)
class Bounded:
    """What a look within a bound found, and what it left out: the
    paths, and how the rest is said when there was more than the bound
    takes, empty when that is all there is. The two go together: the
    paths are had through into, which says the rest where a change to it
    will show."""

    found: list[str]
    rest: str = ""
    # The directories that could not be looked into, see closed_entry
    closed: tuple[str, ...] = ()

    @property
    def cut(self) -> bool:
        """Whether there was more than was looked at."""
        return bool(self.rest)

    def into(self, fingerprint: dict[str, str]) -> list[str]:
        """What was found, with what was left out said in a fingerprint
        as unwatched: a session that made a tree larger than is watched,
        for a file to be lost in, has that show as a change, and so does
        one that closed a directory of it."""
        if self.rest:
            fingerprint[self.rest] = UNWATCHED
        for directory in self.closed:
            fingerprint[closed_entry(directory)] = UNWATCHED
        return self.found


class _Budget:
    """How many more of one kind a fingerprint may take, none for no
    bound, and whether it refused one: what is past the bound is then
    said, see Look.into."""

    def __init__(self, most: int | None) -> None:
        self.most = most
        self._left = most
        self.refused = False

    @property
    def spent(self) -> bool:
        """Whether nothing more may be taken."""
        return self._left is not None and self._left <= 0

    def any_left(self) -> bool:
        """Whether more may be taken, without taking any: when not, it is
        refused as take refuses it."""
        if self.spent:
            self.refused = True
        return not self.spent

    def take(self) -> bool:
        """Whether one more may be taken, which then it is."""
        if not self.any_left():
            return False
        if self._left is not None:
            self._left -= 1
        return True


class Look:
    """What one fingerprint may still look at, and what it looked at
    already: no more than most of what is watched (see MOST_WATCHED) and
    runs of git (see MOST_GIT_RUNS), none for no such bound, and what is
    past either is said at the end, see into. The directories listed, by
    where each is, so that one reached by several paths, the hooks of
    every working tree of a repository through a link say, is listed
    once. And what git said of each config, by its path, so that one is
    listed once however often it is asked about, but for one that says
    too much to be kept (see git_listing). Taken anew for each
    fingerprint, in the same order at the start and at the end of a
    session: the same are past a bound both times, unless a session
    changed what comes before them."""

    def __init__(self, most: int | None = None, runs: int | None = None) -> None:
        self._watched = _Budget(most)
        self._runs = _Budget(runs)
        self.listed: set[str] = set()
        self.said: dict[str, bytes | None] = {}

    @classmethod
    def of_a_fingerprint(cls) -> Look:
        return cls(MOST_WATCHED, MOST_GIT_RUNS)

    def take(self) -> bool:
        """Whether one more may be looked at, which then it is."""
        return self._watched.take()

    def any_left(self) -> bool:
        """Whether more may be looked at, without taking any, see
        _Budget.any_left."""
        return self._watched.any_left()

    def run(self) -> bool:
        """Whether git may be run once more, which then it is."""
        return self._runs.take()

    def into(self, fingerprint: dict[str, str]) -> None:
        """Say in a fingerprint, as unwatched, what is past the bounds:
        one entry for what was not looked at, however many trees and git
        directories that cut, and one for the configs git was not run
        for, whose includes and the hooks they name are not watched. Each
        once the look refused one of its kind."""
        if self._watched.refused:
            past = f"more than {self._watched.most} files and git directories"
            fingerprint[past + LEFT_OUT] = UNWATCHED
        if self._runs.refused:
            past = f"more than {self._runs.most} git configs, what they include"
            fingerprint[past + LEFT_OUT] = UNWATCHED


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def file_hash(path: str) -> str:
    """Hash of a file, of a link where it points and what is there. Of a
    file past HASHED_BYTES, its start and what tells it from one written
    since, as file_stamp does of a file that is not read: its size alone
    would not tell of what was written over past the start. What is no
    plain file is unreadable, and is not opened to find out: a pipe would
    have the check wait for whoever writes to it."""
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
                # Of the file that was read, not of a link that led to it
                digest.update(_stamp(os.fstat(file.fileno())).encode())
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
        return _stamp(os.lstat(path))
    except OSError:
        return "unreadable"


def _stamp(about: os.stat_result) -> str:
    return f"{about.st_ino}:{about.st_size}:{about.st_mtime_ns}:{about.st_ctime_ns}"


def _leads_within(link: str, within: Sequence[str]) -> str:
    """Where a link to a directory leads, when that is in one of the
    directories given, empty when it leads elsewhere or to no directory."""
    real = os.path.realpath(link)
    if not os.path.isdir(real):
        return ""
    return real if any(is_under(real, root) for root in within) else ""


def tree_files(
    root: str,
    most: int = MOST_TREE_FILES,
    within: Sequence[str] = (),
    look: Look | None = None,
) -> Bounded:
    """The files under a directory, no more than most of them: of a tree
    with more the rest is said to be left out, see Bounded. A link to a
    directory is listed, and entered only when it leads into one of the
    directories within, those a session was given: a session can point
    one at the whole disk, and the link itself is what changed then, but
    what a link that was there leads to in the project it can change
    with the link as it was (hooks or skills kept in a repository of
    dotfiles). Each directory once, by where it is, however many links
    lead to it, in this tree and in the others of the same look. In the
    order of their names, the files of a directory ahead of what is below
    it: the same ones at the start and the end of a session, where there
    are more than are watched. Without recursion, as module_git_dirs and
    for the same reason. No more directories are looked into than files
    are watched, and one that holds more than that is not listed whole:
    both leave files unseen that are no part of the count, a session can
    make any number of directories for one file to be lost among, so
    both have the rest said to be left out as well. And each file and
    directory is one of what the look may still take, past which the
    rest is said by the look, see Look.into."""
    look = look or Look()
    roots = [os.path.realpath(directory) for directory in within]
    found: list[str] = []
    closed: list[str] = []
    if os.path.islink(root):
        if not look.take():
            return Bounded(found)
        found.append(root)
        if not _leads_within(root, roots):
            return Bounded(found)
    pending = [root]
    looked = 0
    cut = False
    while pending and len(found) <= most and looked <= most:
        looked += 1
        directory = pending.pop()
        real = os.path.realpath(directory)
        if real in look.listed:
            continue
        if not look.take():
            return Bounded(found[:most], closed=tuple(closed))
        look.listed.add(real)
        listing = listed(directory, most)
        cut |= listing.more
        if listing.closed:
            closed.append(directory)
        below = _entries_below(listing, roots, look, found)
        if below is None:
            return Bounded(found[:most], closed=tuple(closed))
        # The first by its name is the next looked into
        pending += reversed(below)
    if cut or pending or len(found) > most:
        rest = f"{root}: more than {most} files, the rest"
        return Bounded(found[:most], rest, tuple(closed))
    return Bounded(found, closed=tuple(closed))


def _entries_below(
    listing: Listing, roots: Sequence[str], look: Look, found: list[str]
) -> list[str] | None:
    """What of the listing of a directory of tree_files is looked into
    next, in the order of the names: the directories in it, and the links
    that lead into one of the roots. Its files and links are added to
    found, each one of what the look may still take. None once the look
    takes no more."""
    below = []
    for entry in listing.entries:
        if entry.is_dir(follow_symlinks=False):
            below.append(entry.path)
            continue
        if not look.take():
            return None
        found.append(entry.path)
        if entry.is_symlink() and _leads_within(entry.path, roots):
            below.append(entry.path)
    return below


class Listing(NamedTuple):
    """What listed found in a directory: its entries, whether it holds
    more than those, and whether it is there and could not be read."""

    entries: list[os.DirEntry[str]]
    more: bool = False
    closed: bool = False


def listed(directory: str, most: int) -> Listing:
    """What a directory holds, in the order of the names, nothing for
    one that cannot be read, and whether it holds more than that. No
    more than could be watched and one: a session can put any number there, and
    which of them are left out is then the directory's own order, not
    that of the names. So whoever lists says when it was cut, and when
    it could not be read, see closed_entry. Not for one that is not
    there, or is no directory."""
    try:
        with os.scandir(directory) as entries:
            taken = list(islice(entries, most + 1))
    except OSError as problem:
        return Listing([], closed=problem.errno not in GONE)
    return Listing(sorted(taken, key=attrgetter("name")), len(taken) > most)


def module_git_dirs(directory: str, look: Look | None = None) -> Bounded:
    """The git directories of the submodules kept under a directory, and of
    theirs, no more than MOST_MODULES of them and of the directories
    looked into for them: the rest is said to be left out, see Bounded.
    Each directory looked into is one of what the look may still take,
    past which the rest is said by the look, see Look.into. A
    submodule's name can hold slashes, so they sit at any depth. Without
    recursion: a session can nest directories deeper than Python calls,
    and the check must not be made to fail."""
    look = look or Look()
    found: list[str] = []
    closed: list[str] = []
    pending = [directory]
    looked = 0
    cut = False
    while pending and looked <= MOST_MODULES:
        looked += 1
        if not look.take():
            return Bounded(found[:MOST_MODULES], closed=tuple(closed))
        looked_into = pending.pop()
        listing = listed(looked_into, MOST_MODULES)
        cut |= listing.more
        if listing.closed:
            closed.append(looked_into)
        for entry in listing.entries:
            if not entry.is_dir(follow_symlinks=False):
                continue
            if os.path.isfile(os.path.join(entry.path, "HEAD")):
                found.append(entry.path)
                pending.append(os.path.join(entry.path, "modules"))
            else:
                pending.append(entry.path)
    if cut or pending or len(found) > MOST_MODULES:
        said = f"{directory}: more than {MOST_MODULES} submodules, the rest"
        return Bounded(found[:MOST_MODULES], said, tuple(closed))
    return Bounded(found, closed=tuple(closed))
