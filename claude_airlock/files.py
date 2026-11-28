"""The launcher's own files, and reading what a session can write.

Two kinds of care, each in one place. What the launcher keeps is for the
user alone, written whole or not at all, and locked where several
launchers work on it at once. What a session can write (a transcript, the
login of the sandbox, a line of a record that tells of it) is read without
trusting it: never through a link, never from a pipe, and a line that is
not what it should be is no line."""

from __future__ import annotations

import contextlib
import enum
import errno
import fcntl
import hashlib
import json
import os
import stat
import tempfile
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import IO, Any, BinaryIO

# Where a file goes on from a hole of a sparse file, and where the next
# hole starts, where the system can tell: none with it, a file is then
# read through its holes
SEEK_DATA = getattr(os, "SEEK_DATA", -1)
SEEK_HOLE = getattr(os, "SEEK_HOLE", -1)
# What a line is taken in as, for what stands for it, in the place of each
# hole that is in it, with how long the hole is, see digested_lines
HOLE_TAKEN_AS = b"\0a hole of %d bytes\0"
# What a session can write is read a line at a time, and no line longer
# than this is held in memory
LINE_LIMIT = 32 << 20
# A file that changed less long ago than this may not be told by its stamp
# from what is written next, see stat_stamp: a clock that ticks coarsely
# gives two writes the same time
STAMP_SETTLES_NS = 2 * 10**9
# The errors of what is gone since it was listed, by a build or a session,
# and of what is in a directory closed to the launcher
GONE = frozenset((errno.ENOENT, errno.ENOTDIR))
CLOSED = frozenset((errno.EACCES, errno.EPERM))
# Of a line longer than that, what is read at a time by what takes it in
# without holding it, see digested_lines
PIECE = 1 << 20
# What a line of JSON takes once read, see held_size: twice its bytes,
# for a text of characters that take several, and four times for a line
# with a byte past ASCII: a single character past the first 65536 has
# Python keep the whole text at four bytes for each character. Then so
# much for the line and for each value in it (an empty object in a list
# takes less, one nested in another about this). And how much one line
# may take: past it a line is not read, as one that is too long is not.
HELD_BY_BYTE = 2
HELD_BY_WIDE_BYTE = 4
HELD_BY_LINE = 200
HELD_BY_VALUE = 80
# Of a line of JSON, what held_size looks at: the quotes of its strings and
# what sets its values apart, all else is dropped before it is counted
_SET_APART = (b"{", b"[", b",", b":")
_NOT_COUNTED = bytes(set(range(256)) - set(b'"{[,:'))
MOST_LINE_HELD = 256 << 20
# A settings file of Claude Code past this is not read, the project's
# ones are a session's to write
SETTINGS_BYTES = 1024 * 1024
# The kind of the entry that stands for a line of a transcript that holds
# no entry, and how much of such a line is kept to be shown
UNREADABLE = "unreadable-line"
UNREADABLE_SHOWN = 2000
# What such an entry says of a line that was too long to read
TOO_LONG = "(a line too long to read)"
# How each mode of open_locked opens its file, which is made as needed
LOCKED_MODES = {
    "r+": os.O_RDWR,
    "a+": os.O_RDWR | os.O_APPEND,
    "ab": os.O_WRONLY | os.O_APPEND,
}


def private_dir(path: str) -> str:
    """Create a directory for the launcher's own records, with its parents,
    for the user alone: what is kept there says which hosts a session
    reached. Returns the path."""
    # One level at a time, makedirs gives its mode to the last one alone
    missing = []
    directory = path
    while directory and not os.path.isdir(directory):
        missing.append(directory)
        directory = os.path.dirname(directory)
    for directory in reversed(missing):
        try:
            os.mkdir(directory, 0o700)
        except FileExistsError:
            # Another launcher was first
            continue
    return path


def write_whole(
    path: str,
    content: str | bytes,
    *,
    durable: bool = False,
    replace: bool = True,
) -> bool:
    """Write a file whole or not at all, for the user alone: under another
    name of its directory first, then given its own. Whoever reads there
    meanwhile, another launcher or a session, never finds half a file. The
    other name ends in what no reader looks for.

    durable has it on the disk before it has its name, for what must not
    be lost with the power. Without replace a file that is already there
    is left as it is, another launcher was first: returns whether this
    one was written."""
    data = content.encode("utf-8") if isinstance(content, str) else content
    directory, name = os.path.split(path)
    descriptor, partial = tempfile.mkstemp(dir=directory, prefix=name + ".")
    try:
        with os.fdopen(descriptor, "wb") as file:
            file.write(data)
            if durable:
                file.flush()
                os.fsync(file.fileno())
        if replace:
            os.replace(partial, path)
            return True
        try:
            # A link fails where a rename would write over
            os.link(partial, path)
        except FileExistsError:
            return False
        finally:
            os.unlink(partial)
        return True
    except BaseException:
        Path(partial).unlink(missing_ok=True)
        raise


def lock_file(path: str, *, shared: bool = False) -> int:
    """Open a file of the launcher's, made as needed, and lock it, once
    whoever holds it has let go: alone, or shared with the others that
    ask for it so. Returns its descriptor, the lock is held until that is
    closed, and let go of with the launcher however it ends. The file
    stays: one that is removed could be locked by two."""
    descriptor = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_SH if shared else fcntl.LOCK_EX)
    except OSError:
        os.close(descriptor)
        raise
    return descriptor


@contextmanager
def locked(path: str) -> Iterator[None]:
    """Hold the lock of lock_file on a file, alone, for as long as the
    block lasts."""
    lock = lock_file(path)
    try:
        yield
    finally:
        os.close(lock)


@contextmanager
def open_locked(path: str | Path, mode: str) -> Iterator[IO[Any]]:
    """Open a file of the launcher's, made for the user alone as needed,
    with a mode of LOCKED_MODES, and lock it alone until it is closed:
    launchers of other sessions write there too. Text is UTF-8, what is
    not is replaced. The file locked is the one of that name: one that
    was given another's place while this waited (see append_kept) is let
    go of, and the one there now is asked for."""
    encoding, errors = (None, None) if "b" in mode else ("utf-8", "replace")
    while True:
        descriptor = os.open(path, LOCKED_MODES[mode] | os.O_CREAT, 0o600)
        file = os.fdopen(descriptor, mode, encoding=encoding, errors=errors)
        try:
            fcntl.flock(file, fcntl.LOCK_EX)
            if _still_named(file, path):
                break
        except BaseException:
            file.close()
            raise
        file.close()
    with file:
        yield file


def _still_named(file: IO[Any], path: str | Path) -> bool:
    """Whether an open file is the one its name leads to now."""
    try:
        named = os.stat(path)
    except OSError:
        return False
    opened = os.fstat(file.fileno())
    return (opened.st_dev, opened.st_ino) == (named.st_dev, named.st_ino)


def append_kept(path: str, line: str, kept: int) -> None:
    """Add a line to one of the launcher's records, a file of its state
    directory for the user alone, and let go of the oldest lines past
    kept. Those that stay are written under another name and given the
    record's, see write_whole: cut short where it is, a record would be
    left empty by a launcher that is killed, or a disk that is full,
    before they are written back."""
    private_dir(os.path.dirname(path))
    with open_locked(path, "a+") as record:
        record.write(line + "\n")
        record.flush()
        record.seek(0)
        lines = record.readlines()
        if len(lines) > kept:
            write_whole(path, "".join(lines[-kept:]))


def try_lock_file(path: str) -> int | None:
    """As lock_file, alone and without the wait: none when another holds
    a lock on it, shared or not."""
    descriptor = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        os.close(descriptor)
        return None
    except OSError:
        # Not held by another: a directory that takes no lock, which
        # must not read as a name that is taken
        os.close(descriptor)
        raise
    return descriptor


# How deep in a tree the directories are opened up, see open_up: each one
# further down holds a descriptor until it is done with
MOST_DEEP_OPENED = 64
# A directory as it is opened to be gone into: never through a link
_GONE_INTO = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC


def open_up(top: str, most: int) -> None:
    """Give a directory a session can write, and those in it, the mode of
    the user's alone (0700), for the launcher to read and empty them: a
    session owns them as the launcher does, and can take that away. Each
    by its name in the directory above it, opened as it is gone into: a
    session can put a link in the place of a directory between the two,
    and the mode of what a link leads to is never changed. No more
    directories than most, none deeper than MOST_DEEP_OPENED."""
    opened = _opened_up(top, None)
    if opened is None:
        return
    # The directories gone into, each with those in it still to go into
    seen = 1
    path = [(opened, _subdirectories(opened, most))]
    try:
        while path:
            directory, left = path[-1]
            if not left or seen >= most or len(path) > MOST_DEEP_OPENED:
                os.close(directory)
                path.pop()
                continue
            child = _opened_up(left.pop(), directory)
            if child is not None:
                seen += 1
                path.append((child, _subdirectories(child, most)))
    finally:
        for directory, _ in path:
            os.close(directory)


def _subdirectories(directory: int, most: int) -> list[str]:
    """The names of the directories in an open one, no more than most,
    none when it cannot be listed."""
    found: list[str] = []
    with contextlib.suppress(OSError), os.scandir(directory) as entries:
        for entry in entries:
            if len(found) >= most:
                break
            if entry.is_dir(follow_symlinks=False):
                found.append(entry.name)
    return found


def _opened_up(name: str, parent: int | None) -> int | None:
    """Give a directory the mode of the user's alone (see _made_own) and
    open it, by its name in an open parent (none for a path of the
    launcher's own), none when it cannot be opened. Its mode first: one
    of none cannot be opened."""
    _made_own(name, parent)
    try:
        return os.open(name, _GONE_INTO, dir_fd=parent)
    except OSError:
        return None


def _made_own(name: str, parent: int | None) -> None:
    """Give a directory the mode of the user's alone, by its name in an
    open parent (none for a path of the launcher's own). Never what a
    link leads to. Where the system cannot be told not to follow one
    (Linux), the name is opened as it is, a link too, and the mode of
    what was opened changed when it is a directory: through the place
    the system gives each open file (/proc/self/fd), which is that file
    and no other, as the C library itself does it. Nothing where neither
    can be had."""
    if os.chmod in os.supports_follow_symlinks:
        with contextlib.suppress(OSError):
            os.chmod(name, 0o700, dir_fd=parent, follow_symlinks=False)
        return
    as_it_is = getattr(os, "O_PATH", 0)
    if not as_it_is:
        return
    try:
        opened = os.open(name, as_it_is | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=parent)
    except OSError:
        return
    try:
        if stat.S_ISDIR(os.fstat(opened).st_mode):
            os.chmod(f"/proc/self/fd/{opened}", 0o700)
    except OSError:
        pass
    finally:
        os.close(opened)


def open_plain(path: str | Path, *, links: bool = False) -> BinaryIO | None:
    """A file a session can write, opened to be read, none when it is not
    there or is not a plain file. A session can put something else in its
    place, also after it was listed: never a link to something else on the
    host, nor a pipe that never ends, nor a directory. With links a link
    is followed, for what the user may keep as one, and what it leads to
    is still a plain file or none."""
    flags = os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC
    if not links:
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError:
        return None
    try:
        plain = stat.S_ISREG(os.fstat(descriptor).st_mode)
    except OSError:
        plain = False
    if not plain:
        os.close(descriptor)
        return None
    return os.fdopen(descriptor, "rb")


class NotRead(enum.Enum):
    """Why a file a session can write was not read, see read_plain."""

    # Not there, or no plain file
    ABSENT = enum.auto()
    UNREADABLE = enum.auto()
    TOO_LARGE = enum.auto()


def read_plain(path: str | Path, most: int, *, links: bool = False) -> bytes | NotRead:
    """All of a file a session can write, opened as open_plain has it, or
    why it was not read: it can be made as large as the disk, past most
    bytes it is not."""
    file = open_plain(path, links=links)
    if file is None:
        return NotRead.ABSENT
    try:
        with file:
            content = file.read(most + 1)
    except OSError:
        return NotRead.UNREADABLE
    return NotRead.TOO_LARGE if len(content) > most else content


def file_id(about: os.stat_result) -> tuple[int, int]:
    """Which file it is, whatever its name and however it changed: its
    device and its inode."""
    return (about.st_dev, about.st_ino)


def stat_stamp(about: os.stat_result) -> tuple[int, ...]:
    """What tells a file from the same written since, without reading
    it: which file it is, how long, when it was written, and when what is
    known of it last changed, which the system sets and no session can
    put back, as it can the time it was written. Two writes within a tick
    of a coarse clock can leave the same stamp, see stamp_settled."""
    return (*file_id(about), about.st_size, about.st_mtime_ns, about.st_ctime_ns)


def stamp_settled(about: os.stat_result) -> bool:
    """Whether the stamp of a file tells it from what may be written next:
    it last changed longer ago than STAMP_SETTLES_NS. One that did not is
    read again at the next look, whatever its stamp, see stat_stamp."""
    changed = max(about.st_mtime_ns, about.st_ctime_ns)
    return time.time_ns() - changed > STAMP_SETTLES_NS


def whole_lines(read: bytes, most: int) -> tuple[list[bytes], int]:
    """The lines a read of at most most bytes holds whole, each without
    its line feed, and how much of the read they take, to go on from
    there: what follows the last line feed is a line still being written,
    read again with what comes after it. Split at line feeds alone, as a
    record of lines of JSON is written: what else reads as the end of a
    line is the session's to put within one. A read of most bytes with no
    line feed is passed over whole: a line longer than is read at a time
    would be read again without end."""
    whole = read.rfind(b"\n") + 1
    if not whole:
        return [], len(read) if len(read) >= most else 0
    return read[: whole - 1].split(b"\n"), whole


def bounded_lines(file: IO[bytes], longest: int = LINE_LIMIT) -> Iterator[bytes | None]:
    """The lines of a file a session can write, each with its end, a last
    one without when that is how the file ends. None in the place of a
    line longer than longest, which is passed over and not held in
    memory: a file can be made one line as large as the disk. And of a
    line with a hole of a sparse file in it, which is not read (see
    _UpToAHole), as digested_lines has it: Claude Code writes no such
    line."""
    data = _UpToAHole(file)
    while True:
        line, _, found = _next_line(data, longest, _not_taken)
        if not found:
            return
        yield line


def last_lines(
    file: IO[bytes], most: int, longest: int = LINE_LIMIT
) -> Iterator[bytes | None]:
    """The lines of the end of a file a session can write, as bounded_lines
    has them: those that start in its last so many bytes, for what wants
    the latest of a file that can be made as long as the disk. Raises
    OSError for one that cannot be read or moved in."""
    size = os.fstat(file.fileno()).st_size
    file.seek(max(0, size - most))
    lines = bounded_lines(file, longest)
    if file.tell() > 0:
        # The end of a line whose start is not read
        next(lines, None)
    return lines


def _past_a_hole(file: IO[bytes]) -> None:
    """Move a file that is read past the hole of a sparse file it is in,
    if any, see _UpToAHole: a hole holds no line break, and a session can
    make one as large as the disk takes at no cost of its own, for
    whoever reads it to read through. Nothing where the file or the
    system has no such thing to tell, a pipe or gVisor."""
    try:
        file.seek(file.tell(), SEEK_DATA)
    except OSError as error:
        if error.errno == errno.ENXIO:
            # Nothing but a hole from here to the end
            file.seek(0, os.SEEK_END)
    except ValueError:
        # No such whence for this file, or no such file any more
        pass


class _UpToAHole:
    """A file a session can write, read no further at a time than the
    next hole of it, and moved past a hole with how long it was. A hole
    holds no line break, and a session can make one as large as the disk
    takes, and any number of them, at no cost of its own, for whoever
    reads the file to read through as zeros. Read as it is where the
    system cannot tell where a hole is, of a pipe or on gVisor."""

    def __init__(self, file: IO[bytes]) -> None:
        self._file = file
        self._hole = self._next_hole()

    def _next_hole(self) -> int | None:
        """Where the next hole starts, the end of the file when no hole is
        on the way, none when that cannot be told."""
        if SEEK_HOLE < 0:
            return None
        try:
            here = self._file.tell()
        except OSError:
            # A pipe, which is read as it comes
            return None
        try:
            hole = self._file.seek(here, SEEK_HOLE)
        except OSError as error:
            if error.errno != errno.ENXIO:
                return None
            # At the end, or past it
            hole = here
        except ValueError:
            return None
        self._file.seek(here)
        return hole

    def past(self) -> int:
        """Move past the hole the file is at: how long that was, nothing
        when it is at none. Where the system tells where a hole starts
        but not where it ends, the file is read as it is from there."""
        if self._hole is None:
            return 0
        here = self._file.tell()
        if here < self._hole:
            return 0
        _past_a_hole(self._file)
        gone = self._file.tell() - here
        self._hole = self._next_hole()
        if not gone and self._hole == here:
            self._hole = None
        return gone

    def readline(self, most: int) -> bytes:
        """A line, or as much of it as comes before the next hole, of no
        more than most bytes."""
        if self._hole is not None:
            most = min(most, max(self._hole - self._file.tell(), 0))
        return self._file.readline(most)


def digested_lines(
    file: BinaryIO, longest: int = LINE_LIMIT
) -> Iterator[tuple[bytes, bytes | None]]:
    """The whole lines of a file a session can write, each as what stands
    for it, its SHA-256, and the line itself. None in the place of a line
    longer than longest, as bounded_lines has it: that one is taken in a
    piece at a time for what stands for it and never held, so what
    compares two files line by line still tells it from any other. Not a
    last line without its end. A hole of a sparse file is not read (see
    _UpToAHole): a line with one is none Claude Code writes, it is taken
    in as how long each hole is (HOLE_TAKEN_AS) and passed on as None, as
    a line too long is. What stands for it is then not what would for
    the same line written out in zeros, which only a session makes."""
    data = _UpToAHole(file)
    while True:
        digest = hashlib.sha256()
        line, whole, _ = _next_line(data, longest, digest.update)
        if not whole:
            return
        yield digest.digest(), line


def _not_taken(_piece: bytes) -> None:
    """What takes in nothing of a line, see _next_line."""


def _next_line(
    data: _UpToAHole, longest: int, taken: Callable[[bytes], object]
) -> tuple[bytes | None, bool, bool]:
    """The next line of a file read up to its holes, see _UpToAHole: the
    line, none for one longer than longest or with a hole in it, which
    is not held, then whether it ends with a line feed, and whether there
    was any more of the file at all. What is read of it is given to
    taken a piece at a time, a hole as how long it is (HOLE_TAKEN_AS), no
    more of a line that is not held than PIECE at a time."""
    held: list[bytes] | None = []
    length = 0
    whole = found = False
    while not whole:
        if gone := data.past():
            taken(HOLE_TAKEN_AS % gone)
            held = None
            found = True
        piece = data.readline(longest + 1 - length if held is not None else PIECE)
        if not piece:
            break
        taken(piece)
        found = True
        length += len(piece)
        whole = piece.endswith(b"\n")
        if held is not None:
            held.append(piece)
            if length > longest and not whole:
                held = None
    return (None if held is None else b"".join(held)), whole, found


def held_size(line: bytes) -> int:
    """About how many bytes a line of JSON takes once it is read, and no
    fewer: its own, and so many for each value it holds, counted by what
    sets them apart. A line of nothing but small values takes dozens of
    times its length, which is the session's to write: what is bounded
    by the bytes read alone is not bounded in what it holds. Not what is
    within its strings: a comma or a brace there is a character of a
    text, and sets no value apart. A string a half written line leaves
    open is not one, what is in it counts as if it were outside. An
    escaped quote or backslash is taken out before the quotes are
    paired, then all but the quotes and what sets values apart, which
    leaves the strings in every other piece between quotes. Its bytes
    count for more where one of them is past ASCII, see
    HELD_BY_WIDE_BYTE."""
    bare = line.replace(b"\\\\", b"").replace(b'\\"', b"")
    pieces = bare.translate(None, _NOT_COUNTED).split(b'"')
    outside = pieces[0::2]
    if len(pieces) % 2 == 0:
        outside.append(pieces[-1])
    values = sum(piece.count(mark) for piece in outside for mark in _SET_APART)
    return held_by(line) * len(line) + HELD_BY_LINE + HELD_BY_VALUE * values


def held_by(text: str | bytes) -> int:
    """How many bytes each character or byte of a text takes once it is
    held as a string, at the most: Python keeps a string at the width of
    its widest character, and one past ASCII is counted as wide as any
    can be."""
    return HELD_BY_BYTE if text.isascii() else HELD_BY_WIDE_BYTE


def held_object(line: bytes) -> tuple[dict | None, int]:
    """The JSON object a line holds, with about how much it takes once
    read (see held_size). None for a line that holds none, and for one
    that would take more than MOST_LINE_HELD, which is not taken apart:
    the size says which. The one rule for what a session wrote, in a
    transcript, a body or what claude says to a chat."""
    held = held_size(line)
    return (json_object(line) if held <= MOST_LINE_HELD else None), held


def line_read(line: bytes | None) -> tuple[dict | None, int]:
    """A whole line of a transcript as the entry it holds, none for an
    empty one, with about how much that takes once read (see held_size).
    A line that holds none, or was not read, too long or with a hole in
    it (see bounded_lines), is an entry that says so, which takes no more
    than an empty line:
    Claude Code writes no such line, a session that writes half a line
    ahead of an entry does, and what it did there must not go without a
    word."""
    if line is None:
        return {"type": UNREADABLE, "text": TOO_LONG}, HELD_BY_LINE
    entry, held = held_object(line)
    if entry is not None:
        return entry, held
    if held > MOST_LINE_HELD:
        return {"type": UNREADABLE, "text": TOO_LONG}, HELD_BY_LINE
    if not line.strip():
        return None, 0
    shown = line[:UNREADABLE_SHOWN].decode("utf-8", "replace").rstrip("\n")
    return {"type": UNREADABLE, "text": shown}, HELD_BY_LINE


def line_entry(line: bytes | None) -> dict | None:
    """A whole line of a transcript as the entry it holds, see line_read."""
    return line_read(line)[0]


def json_object(text: str | bytes) -> dict | None:
    """The JSON object a text holds, none for anything else: a line cut
    off by a launcher that was killed or half written by a running
    session, one that holds another kind of value, and one nested too
    deep to read, which is a session's doing."""
    if isinstance(text, bytes):
        text = text.decode("utf-8", "replace")
    try:
        found = json.loads(text)
    except (ValueError, RecursionError):
        return None
    return found if isinstance(found, dict) else None


def settings_object(path: str | Path) -> dict:
    """What a settings file of Claude Code holds, nothing for one that is
    not there, not to be read, or that a session made too large or nested
    too deep to read. Through a link, as Claude Code reads it and as a
    user keeps the one of ~/.claude, but never from a pipe or a device a
    session put there, which would not end."""
    content = read_plain(path, SETTINGS_BYTES, links=True)
    return {} if isinstance(content, NotRead) else json_object(content) or {}


def expand_home(path: str, home: str) -> str:
    """A path with a leading ~ as the home directory it stands for. The
    shell does not expand it everywhere (--add-dir=~/x), and nothing else
    does in a config file or in what git and Claude Code keep."""
    if path == "~":
        return home
    return home + path[1:] if path.startswith("~/") else path


def is_under(path: str, directory: str) -> bool:
    """Whether a path is under a directory, not the directory itself. By
    both as they are written, neither is resolved: who asks resolves them
    first where a link counts. The root holds every other path."""
    return path.startswith(directory.rstrip(os.sep) + os.sep)


def leads_under(path: str, directory: str) -> bool:
    """Whether a path is under a directory as both are written, or by
    where they lead: a link into it is in it."""
    if is_under(path, directory):
        return True
    return is_under(os.path.realpath(path), os.path.realpath(directory))


def is_within(path: str, directory: str) -> bool:
    """Whether a path is a directory or under it, see is_under."""
    return path == directory or is_under(path, directory)


def overlap(one: str, other: str) -> bool:
    """Whether one of two directories is the other or is inside it,
    either way round, see is_within."""
    return is_within(one, other) or is_within(other, one)
