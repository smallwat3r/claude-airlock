"""The launcher's own files, and reading what a session can write.

Two kinds of care, each in one place. What the launcher keeps is for the
user alone, written whole or not at all, and locked where several
launchers work on it at once. What a session can write (a transcript, the
login of the sandbox, a line of a record that tells of it) is read without
trusting it: never through a link, never from a pipe, and a line that is
not what it should be is no line."""

from __future__ import annotations

import enum
import errno
import fcntl
import hashlib
import json
import os
import stat
import tempfile
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import IO, Any, BinaryIO

# Where a file goes on from a hole of a sparse file, where the system
# can tell: none with it, a file is then read through its holes
SEEK_DATA = getattr(os, "SEEK_DATA", -1)
# What a session can write is read a line at a time, and no line longer
# than this is held in memory
LINE_LIMIT = 32 << 20
# Of a line longer than that, what is read at a time by what takes it in
# without holding it, see digested_lines
PIECE = 1 << 20
# What a line of JSON takes once read, see held_size: twice its bytes,
# for a text of characters that take several, then so much for the line
# and for each value in it (an empty object in a list takes less, one
# nested in another about this). And how much one line may take: past
# it a line is not read, as one that is too long is not.
HELD_BY_LINE = 200
HELD_BY_VALUE = 80
MOST_LINE_HELD = 256 << 20
# A settings file of Claude Code past this is not read, the project's
# ones are a session's to write
SETTINGS_BYTES = 1024 * 1024
# The kind of the entry that stands for a line of a transcript that holds
# no entry, and how much of such a line is kept to be shown
UNREADABLE = "unreadable-line"
UNREADABLE_SHOWN = 2000
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


def bounded_lines(file: IO[bytes], longest: int = LINE_LIMIT) -> Iterator[bytes | None]:
    """The lines of a file a session can write, each with its end, a last
    one without when that is how the file ends. None in the place of a
    line longer than longest, which is passed over and not held in
    memory: a file can be made one line as large as the disk, a hole
    that takes no room on it."""
    while True:
        line = file.readline(longest + 1)
        if not line:
            return
        if len(line) <= longest or line.endswith(b"\n"):
            yield line
            continue
        # The rest of it, a piece at a time, past what is a hole
        while line and not line.endswith(b"\n"):
            _past_a_hole(file)
            line = file.readline(longest)
        yield None


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
    """Move a file that is read through a line too long to take past the
    hole of a sparse file it is in, if any: a hole holds no line break,
    and a session can make one as large as the disk takes at no cost of
    its own, for whoever reads it to read through. Nothing where the file
    or the system has no such thing to tell, a pipe or gVisor."""
    try:
        file.seek(file.tell(), SEEK_DATA)
    except OSError as error:
        if error.errno == errno.ENXIO:
            # Nothing but a hole from here to the end
            file.seek(0, os.SEEK_END)
    except ValueError:
        # No such whence for this file, or no such file any more
        pass


def digested_lines(
    file: BinaryIO, longest: int = LINE_LIMIT
) -> Iterator[tuple[bytes, bytes | None]]:
    """The whole lines of a file a session can write, each as what stands
    for it, its SHA-256, and the line itself. None in the place of a line
    longer than longest, as bounded_lines has it: that one is taken in a
    piece at a time for what stands for it and never held, so what
    compares two files line by line still tells it from any other. Not a
    last line without its end."""
    while True:
        line: bytes | None = file.readline(longest + 1)
        if not line:
            return
        digest = hashlib.sha256(line)
        whole = line.endswith(b"\n")
        if len(line) > longest and not whole:
            line = None
            while piece := file.readline(PIECE):
                digest.update(piece)
                if piece.endswith(b"\n"):
                    whole = True
                    break
        if whole:
            yield digest.digest(), line


def held_size(line: bytes) -> int:
    """About how many bytes a line of JSON takes once it is read, and no
    fewer: its own, and so many for each value it holds, counted by what
    sets them apart. A line of nothing but small values takes dozens of
    times its length, which is the session's to write: what is bounded
    by the bytes read alone is not bounded in what it holds."""
    values = sum(map(line.count, (b"{", b"[", b",", b":")))
    return 2 * len(line) + HELD_BY_LINE + HELD_BY_VALUE * values


def line_entry(line: bytes | None) -> dict | None:
    """A whole line of a transcript as the entry it holds, none for an
    empty one. A line that holds none, or was too long to read (see
    bounded_lines), is an entry that says so: Claude Code writes no such
    line, a session that writes half a line ahead of an entry does, and
    what it did there must not go without a word."""
    if line is None or held_size(line) > MOST_LINE_HELD:
        return {"type": UNREADABLE, "text": "(a line too long to read)"}
    if not line.strip():
        return None
    entry = json_object(line)
    if entry is not None:
        return entry
    shown = line[:UNREADABLE_SHOWN].decode("utf-8", "replace").rstrip("\n")
    return {"type": UNREADABLE, "text": shown}


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


def is_within(path: str, directory: str) -> bool:
    """Whether a path is a directory or under it, see is_under."""
    return path == directory or is_under(path, directory)


def overlap(one: str, other: str) -> bool:
    """Whether one of two directories is the other or is inside it,
    either way round, see is_within."""
    return is_within(one, other) or is_within(other, one)
