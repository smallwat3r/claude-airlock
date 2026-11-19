"""One login for the host and the sandboxed sessions.

The sessions' ~/.claude is not the host's (see home.py), and the login is
a file in it, .credentials.json. It cannot be mounted from the host on its
own: Claude Code writes it to a temporary file and renames that over it,
on the host too, each time it renews the login. A mount of one file is a
mount of the file as it was when the session started, so the first renewal
on the host would leave every running session with a login that is no
longer good, and what a session then wrote would go to a file nothing
else reads.

So the base has a login file of its own, which the sandboxed sessions
share as they shared the host's, and while a session runs its launcher
keeps the two the same: what one side writes is carried to the other a
moment later, a logout too. Which side changed is told from the login the
two last had in common, noted in the state directory. When both did, or
nothing is noted yet, the one written last is kept.

What this does not give: Claude Code renews a login under a lock in its
config directory, which the host and the sandbox no longer share. Two that
renew in the same moment, one on each side, both use the login of before.
Claude Code reads the file again when that is refused, and finds the
other's.

Not a boundary: a session can read and replace the login, as it could
before. Hence the care with what is read from the base, which is a
session's to write."""

from __future__ import annotations

import hashlib
import os
import threading
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from .background import in_background
from .files import open_plain, private_dir, write_whole
from .settings import Host

LOGIN = ".credentials.json"
# Seconds between two looks at the two files
LOOK_EVERY = 0.2
# No login is this large, and the one in the base could be made so
MOST_READ = 1024 * 1024
# What is noted when the two last agreed that there is no login
ABSENT = "absent"


@dataclass(frozen=True)
class Login:
    """A login file as it was found."""

    path: str
    # None when there is none
    content: bytes | None = None
    # What tells this file from one written since
    version: tuple[int, ...] = ()

    @property
    def noted(self) -> str:
        """What the state directory keeps of it, not the login itself."""
        if self.content is None:
            return ABSENT
        return hashlib.sha256(self.content).hexdigest()


def version_of(found: os.stat_result) -> tuple[int, ...]:
    return (found.st_ino, found.st_mtime_ns, found.st_size)


def read_login(path: str) -> Login:
    """The login at a path. One that is not a regular file of a sane size
    is none: a session could leave a link or a pipe in the base."""
    file = open_plain(path)
    if file is None:
        return Login(path)
    with file:
        found = os.fstat(file.fileno())
        if found.st_size > MOST_READ:
            return Login(path)
        return Login(path, file.read(MOST_READ), version_of(found))


def unchanged(login: Login) -> bool:
    """Whether a file is still the one that was read."""
    try:
        found = os.lstat(login.path)
    except OSError:
        return login.content is None
    return login.content is not None and version_of(found) == login.version


def carry(source: Login, target: Login) -> bool:
    """Make the target the same as the source, whole or not at all: by a
    rename, as Claude Code writes it, or by removing it. Not when the
    target was written since it was read, the next look settles that."""
    if not unchanged(target):
        return False
    if source.content is None:
        os.unlink(target.path)
        return True
    return write_whole(target.path, source.content, durable=True)


def last_shared(host: Host) -> str | None:
    """What was noted of the login the two last had in common, none when
    nothing was."""
    try:
        return Path(host.login_synced_file).read_text(encoding="ascii").strip() or None
    except (OSError, ValueError):
        return None


def note_shared(host: Host, login: Login) -> None:
    private_dir(host.state_dir)
    write_whole(host.login_synced_file, login.noted + "\n")


def written_last(one: Login, other: Login) -> Login:
    """Of two that differ, the one to keep when nothing says which of
    them changed: a login over none, then the later one."""
    if one.content is None or other.content is None:
        return other if one.content is None else one
    return one if one.version[1] >= other.version[1] else other


class LoginPair:
    """The host's login file and the base's."""

    def __init__(self, host: Host):
        self.host = host
        self.host_file = os.path.join(host.claude_dir, LOGIN)
        self.base_file = os.path.join(host.sandbox_claude_dir, LOGIN)
        # What this launcher knows to be noted, to note it once
        self.noted: str | None = None

    def settle(self) -> None:
        """Make the two the same, from the one that changed."""
        ours, theirs = read_login(self.host_file), read_login(self.base_file)
        if ours.content == theirs.content:
            self.note(ours)
            return
        shared = last_shared(self.host)
        if shared == theirs.noted:
            source, target = ours, theirs
        elif shared == ours.noted:
            source, target = theirs, ours
        else:
            source = written_last(ours, theirs)
            target = theirs if source is ours else ours
        if carry(source, target):
            self.note(source)

    def note(self, login: Login) -> None:
        if self.noted != login.noted:
            note_shared(self.host, login)
            self.noted = login.noted

    def settle_quietly(self) -> None:
        """A look that failed (a full disk, a directory that is gone) is
        not the session's end, the next one tries again."""
        try:
            self.settle()
        except OSError:
            pass


def keep_settled(pair: LoginPair, stop: threading.Event) -> None:
    while not stop.wait(LOOK_EVERY):
        pair.settle_quietly()
    # What the session wrote as it ended
    pair.settle_quietly()


@contextmanager
def login_shared(host: Host) -> Iterator[None]:
    """Keep the login of the host and of the sandboxed sessions the same
    for as long as the block lasts, from before the session starts: it
    starts logged in when the host is."""
    pair = LoginPair(host)
    pair.settle_quietly()
    with in_background(keep_settled, pair):
        yield
