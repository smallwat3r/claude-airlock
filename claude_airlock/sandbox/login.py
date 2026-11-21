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

On macOS the host's login is no file: Claude Code keeps it in the login
Keychain, and in the file only when the Keychain refuses it. So the host's
side is there what Claude Code reads, the item of the Keychain and the
file when there is none, read and written with security as Claude Code
does. security prints an item that is more than one line of text as hex
digits, so a login goes into the Keychain as one line of JSON, and two
logins are the same when they say the same, however they are written.

Not a boundary: a session can read and replace the login, as it could
before, with that of another account too, which then is the host's.
Hence the care with what is read from the base, which is a session's
to write: what does not read as a login is never carried to the host."""

from __future__ import annotations

import calendar
import hashlib
import json
import os
import pwd
import re
import shutil
import subprocess
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from functools import cached_property
from pathlib import Path
from typing import Protocol

from ..background import in_background
from ..files import json_object, open_plain, private_dir, write_whole
from ..settings import Host

LOGIN = ".credentials.json"
# Seconds between two looks at the two logins
LOOK_EVERY = 0.2
# No login is this large, and the one in the base could be made so
MOST_READ = 1024 * 1024
# What a login holds of the account at claude.ai, and what of that is
# always text
ACCOUNT_LOGIN = "claudeAiOauth"
TOKENS = ("accessToken", "refreshToken")
# What is noted when the two last agreed that there is no login
ABSENT = "absent"
# What reads and writes the Keychain of macOS, and the item Claude Code
# keeps its login in there
SECURITY = "security"
KEYCHAIN_ITEM = "Claude Code-credentials"
# The account of the item is the user's name, this one when the name is
# not made of such characters alone: as Claude Code has it
ACCOUNT = re.compile(r"[a-zA-Z0-9._-]+")
NO_ACCOUNT = "claude-code-user"
# How security ends when the Keychain has no such item
NO_ITEM = 44
# Seconds security is given, it waits for the user where the Keychain asks
SECURITY_WAIT = 10
# Seconds until the Keychain is asked again once it refused or said nothing
ASK_AGAIN_AFTER = 30
# The longest line security takes on its input, past which what it is to
# write is among its arguments, where other processes can read it: as
# Claude Code has it
MOST_TYPED = 4032
# What security takes between quotes on its input as it is, when it is
# ASCII too: a path with other characters goes among the arguments
TYPED_AS_IS = re.compile(r'[^"\\\n]*')
# How security prints an item that is not one line of text
HEX = re.compile(rb"(?:[0-9a-fA-F]{2})+")
# When the item was last written, among what security says of it
ITEM_WRITTEN = re.compile(rb'"mdat"<timedate>=\S+\s+"(\d{14})Z')


def as_one_line(content: bytes) -> bytes:
    """A login as one line of JSON, in characters security prints as they
    are. One that is no JSON object is left as it is, and one nested
    too deep to write, which is a session's doing."""
    held = json_object(content)
    if held is None:
        return content
    try:
        return json.dumps(held, separators=(",", ":")).encode("ascii")
    except (ValueError, RecursionError):
        return content


def reads_as_login(content: bytes) -> bool:
    """Whether what a file holds is a login as Claude Code writes one: a
    JSON object, its account at claude.ai, when it has one, an object
    with its tokens as text. Not whose login it is, which nothing in it
    says."""
    held = json_object(content)
    if held is None:
        return False
    if ACCOUNT_LOGIN not in held:
        return True
    account = held[ACCOUNT_LOGIN]
    return isinstance(account, dict) and all(
        isinstance(account.get(token), str) and account[token] for token in TOKENS
    )


@dataclass(frozen=True)
class Login:
    """A login as it was found."""

    # None when there is none
    content: bytes | None = None
    # What tells what holds it from the same written since
    version: tuple[int, ...] = ()
    # When it was written, in nanoseconds
    written: int = 0

    @cached_property
    def said(self) -> bytes | None:
        """What it says, the same for two that differ in how they are
        written alone."""
        return None if self.content is None else as_one_line(self.content)

    @cached_property
    def fit(self) -> bool:
        """Whether it can be another store's: no login, or what reads
        as one."""
        return self.content is None or reads_as_login(self.content)

    @cached_property
    def noted(self) -> str:
        """What the state directory keeps of it, not the login itself."""
        said = self.said
        return ABSENT if said is None else hashlib.sha256(said).hexdigest()


class LoginStore(Protocol):
    """What holds a login, the host's or the base's."""

    def read(self) -> Login:
        """The login it holds, one without content when it holds none.
        OSError when that cannot be told: a store that does not answer
        is not a store without a login, which would be a logout."""

    def unchanged(self, login: Login) -> bool:
        """Whether it still holds the login that was read, nothing was
        written to it since."""

    def write(self, content: bytes | None) -> bool:
        """Make it hold a login, whole or not at all, None removes it.
        Whether it then holds what it was given."""


@dataclass(frozen=True)
class Held:
    """A login and the store it was read from."""

    store: LoginStore
    login: Login

    def take(self, other: Login) -> bool:
        """Make the store hold another login in the place of this one.
        Not when it was written since this one was read, the next look
        settles that."""
        return self.store.unchanged(self.login) and self.store.write(other.content)


def version_of(found: os.stat_result) -> tuple[int, ...]:
    return (found.st_ino, found.st_mtime_ns, found.st_size)


def as_typed(words: list[str]) -> str | None:
    """The line that has security take a command and its arguments on
    its input, the options as they are and what they are given between
    quotes. None when it cannot be typed: a word with what the quotes do
    not take, or a line longer than security reads."""
    if not all(word.isascii() and TYPED_AS_IS.fullmatch(word) for word in words):
        return None
    given = (word if word.startswith("-") else f'"{word}"' for word in words[1:])
    line = " ".join([words[0], *given]) + "\n"
    return line if len(line) <= MOST_TYPED else None


class LoginFile:
    """A login kept in a file: the base's, and the host's but on macOS."""

    def __init__(self, path: str):
        self.path = path

    def read(self) -> Login:
        """The login in the file. One that is not a regular file of a sane
        size is none: a session could leave a link or a pipe in the base."""
        file = open_plain(self.path)
        if file is None:
            return Login()
        with file:
            found = os.fstat(file.fileno())
            if found.st_size > MOST_READ:
                return Login()
            return Login(file.read(MOST_READ), version_of(found), found.st_mtime_ns)

    def unchanged(self, login: Login) -> bool:
        """Whether the file is still the one that was read."""
        try:
            found = os.lstat(self.path)
        except OSError:
            return login.content is None
        return login.content is not None and version_of(found) == login.version

    def write(self, content: bytes | None) -> bool:
        """Make the file hold a login, whole or not at all: by a rename,
        as Claude Code writes it. None removes it."""
        if content is None:
            Path(self.path).unlink(missing_ok=True)
            return True
        return write_whole(self.path, content, durable=True)


class Keychain:
    """The login in the login Keychain of macOS, through security.

    The Keychain is a file that is written anew with each change to any
    of its items, so it is asked for the login again only once that file
    is another: a look every LOOK_EVERY is then no process each time."""

    def __init__(self, path: str, user: str):
        self.path = path
        self.account = user if ACCOUNT.fullmatch(user) else NO_ACCOUNT
        # What was last read, for as long as the Keychain is the same
        self._read: Login | None = None
        # When the Keychain may be asked again after it refused, by the
        # clock of time.monotonic
        self._ask_again = 0.0

    def _item(self) -> list[str]:
        return ["-a", self.account, "-s", KEYCHAIN_ITEM]

    def _ask(self, *args: str, typed: str | None = None) -> tuple[int, bytes]:
        """Run security, for how it ended and what it printed. A Keychain
        that does not answer is not asked again for a while: each time
        is a process, and can be a question to the user."""
        if time.monotonic() < self._ask_again:
            raise OSError("the Keychain is not asked again yet")
        try:
            done = subprocess.run(
                [SECURITY, *args],
                input=typed.encode("ascii") if typed is not None else None,
                stdin=subprocess.DEVNULL if typed is None else None,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                timeout=SECURITY_WAIT,
                check=False,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            self._refused()
            raise OSError(f"security did not answer: {error}") from error
        return done.returncode, done.stdout

    def _refused(self) -> None:
        self._read = None
        self._ask_again = time.monotonic() + ASK_AGAIN_AFTER

    def read(self) -> Login:
        """The login in the Keychain, none when it has no such item. A
        Keychain that cannot be read (locked, or the user said no) is an
        error, not a Keychain without a login: that would be a logout."""
        version = version_of(os.stat(self.path))
        if self._read is not None and self._read.version == version:
            return self._read
        status, printed = self._ask(
            "find-generic-password", *self._item(), "-w", self.path
        )
        content = None
        if status == 0:
            content = printed[:-1] if printed.endswith(b"\n") else printed
            if HEX.fullmatch(content):
                # A login is JSON, never hex digits alone
                content = bytes.fromhex(content.decode("ascii"))
        elif status != NO_ITEM:
            self._refused()
            raise OSError(f"security could not read the Keychain: {status}")
        if not content:
            self._read = Login(None, version)
        else:
            self._read = Login(content, version, self._written(version[1]))
        return self._read

    def _written(self, at_most: int) -> int:
        """When the item was last written, to the second. When the
        Keychain itself was, for an item that does not say."""
        status, printed = self._ask("find-generic-password", *self._item(), self.path)
        found = ITEM_WRITTEN.search(printed) if status == 0 else None
        if found is None:
            return at_most
        try:
            at = time.strptime(found.group(1).decode("ascii"), "%Y%m%d%H%M%S")
        except ValueError:
            return at_most
        return min(calendar.timegm(at) * 10**9, at_most)

    def unchanged(self, login: Login) -> bool:
        """Whether the Keychain is still the one that was read: no item
        of it was written since."""
        try:
            return version_of(os.stat(self.path)) == login.version
        except OSError:
            return False

    def write(self, content: bytes | None) -> bool:
        """Make the item hold a login, None removes it. Whether the
        Keychain then holds what it was given: it is read again, a login
        thought carried that was not would later pass for the host's own
        change, and be carried back over the newer one."""
        self._read = None
        if content is None:
            status, _ = self._ask("delete-generic-password", *self._item(), self.path)
            taken = status in (0, NO_ITEM)
        else:
            line = as_one_line(content)
            taken = self._add(line.hex()) == 0 and self.read().said == line
        if not taken:
            self._refused()
        return taken

    def _add(self, digits: str) -> int:
        """Have security write the item, given as hex digits, for how it
        ended. On its input where that can be: its arguments are for
        every process of the host to read."""
        add = ["add-generic-password", "-U", *self._item(), "-X", digits, self.path]
        typed = as_typed(add)
        if typed is not None:
            return self._ask("-i", typed=typed)[0]
        return self._ask(*add)[0]


class HostLogin:
    """The host's login on macOS, where Claude Code reads it: the item of
    the Keychain, and the file when the Keychain has none."""

    def __init__(self, keychain: Keychain, file: LoginFile):
        self.keychain = keychain
        self.file = file

    def _held(self) -> Held:
        """The login, and which of the two holds it."""
        found = self.keychain.read()
        if found.content is not None:
            return Held(self.keychain, found)
        in_file = self.file.read()
        if in_file.content is not None:
            return Held(self.file, in_file)
        return Held(self.keychain, found)

    def read(self) -> Login:
        return self._held().login

    def unchanged(self, login: Login) -> bool:
        try:
            held = self._held()
        except OSError:
            return False
        return held.login.version == login.version and held.store.unchanged(login)

    def write(self, content: bytes | None) -> bool:
        """Where the login is, a new one in the Keychain. A logout is of
        both, the file would else be the login again."""
        if content is None:
            return self.keychain.write(None) and self.file.write(None)
        return self._held().store.write(content)


def user_name() -> str:
    """The user's name as Claude Code takes it for the account of its
    item, empty when there is none to be had."""
    try:
        return os.environ.get("USER") or pwd.getpwuid(os.getuid()).pw_name
    except KeyError:
        return ""


def host_login(host: Host, user: str) -> LoginStore:
    """Where the host's login is kept: in the file, and on macOS (a home
    with a login Keychain, and security to read it with) where Claude
    Code keeps it there."""
    file = LoginFile(os.path.join(host.claude_dir, LOGIN))
    if os.path.isfile(host.keychain_file) and shutil.which(SECURITY):
        return HostLogin(Keychain(host.keychain_file, user), file)
    return file


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


def written_last(one: Held, other: Held) -> Held:
    """Of two that differ, the one to keep when nothing says which of
    them changed: a login over none, then the later one."""
    if one.login.content is None or other.login.content is None:
        return other if one.login.content is None else one
    return one if one.login.written >= other.login.written else other


class LoginPair:
    """The host's login and the base's."""

    def __init__(self, host: Host):
        self.host = host
        self.ours = host_login(host, user_name())
        self.theirs = LoginFile(os.path.join(host.sandbox_claude_dir, LOGIN))
        # What this launcher knows to be noted, to note it once
        self.noted: str | None = None

    def settle(self) -> None:
        """Make the two the same, from the one that changed. Never from
        the base when what is there does not read as a login: the base
        is a session's to write, and the host's own claude would be
        logged in with whatever was carried over. The host's is then
        put back in its place."""
        ours = Held(self.ours, self.ours.read())
        theirs = Held(self.theirs, self.theirs.read())
        if ours.login.said == theirs.login.said:
            self.note(ours.login)
            return
        shared = last_shared(self.host)
        if shared == theirs.login.noted or not theirs.login.fit:
            source = ours
        elif shared == ours.login.noted:
            source = theirs
        else:
            source = written_last(ours, theirs)
        target = theirs if source is ours else ours
        if target.take(source.login):
            self.note(source.login)

    def note(self, login: Login) -> None:
        if self.noted != login.noted:
            note_shared(self.host, login)
            self.noted = login.noted

    def settle_quietly(self) -> None:
        """A look that failed (a full disk, a directory that is gone, a
        locked Keychain) is not the session's end, the next one tries
        again."""
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
