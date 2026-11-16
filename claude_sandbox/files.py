"""The launcher's own files, and reading what a session can write.

Two kinds of care, each in one place. What the launcher keeps is for the
user alone, written whole or not at all, and locked where several
launchers work on it at once. What a session can write (a transcript, the
login of the sandbox, a line of a record that tells of it) is read without
trusting it: never through a link, never from a pipe, and a line that is
not what it should be is no line."""

from __future__ import annotations

import fcntl
import json
import os
import stat
import tempfile
from pathlib import Path
from typing import BinaryIO


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


def try_lock_file(path: str) -> int | None:
    """As lock_file, alone and without the wait: none when another holds
    a lock on it, shared or not."""
    descriptor = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except OSError:
        os.close(descriptor)
        return None
    return descriptor


def open_plain(path: str | Path) -> BinaryIO | None:
    """A file a session can write, opened to be read, none when it is not
    there or is not a plain file. A session can put something else in its
    place, also after it was listed: never a link to something else on the
    host, nor a pipe that never ends, nor a directory."""
    flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
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


def expand_home(path: str, home: str) -> str:
    """A path with a leading ~ as the home directory it stands for. The
    shell does not expand it everywhere (--add-dir=~/x), and nothing does
    in a config file or in what git and Claude Code keep."""
    if path == "~":
        return home
    return home + path[1:] if path.startswith("~/") else path
