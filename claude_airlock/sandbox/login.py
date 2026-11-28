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

Not all of the file is one for the two. Claude Code keeps the logins
to the MCP servers in it too (KEPT_APART): those of the host stay on the
host, a session is given none of the host's servers and is not to read
what logs into them, and those of the sessions stay in the base, see
_taken_from.

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
import stat
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
from ..files import (
    json_object,
    open_plain,
    private_dir,
    stamp_settled,
    stat_stamp,
    write_whole,
)
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
# What a login file holds that is not carried between the host and the
# sandbox, each side keeps its own: the logins to the MCP servers
KEPT_APART = ("mcpOAuth",)
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


def _as_one_line(content: bytes) -> bytes:
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


def _kept_apart(content: bytes | None) -> dict:
    """What a store holds that is its own and not the other's, see
    KEPT_APART: nothing when it holds no login, or one that is no JSON
    object."""
    held = json_object(content) if content is not None else None
    return {key: held[key] for key in KEPT_APART if key in held} if held else {}


def _shared_of(content: bytes | None) -> bytes | None:
    """What of a login is the host's and the sandbox's alike: all of it
    but what is kept apart, as one line of JSON that is the same however
    the login is written. None when nothing is left, one that is no JSON
    object as it is."""
    held = json_object(content) if content is not None else None
    if held is None:
        return content
    shared = {key: value for key, value in held.items() if key not in KEPT_APART}
    try:
        said = json.dumps(shared, separators=(",", ":"), sort_keys=True)
    except (ValueError, RecursionError):
        # Nested too deep to write again, a session's doing: as it is
        return content
    return said.encode("ascii") if shared else None


def _taken_from(own: bytes | None, other: bytes | None) -> bytes | None:
    """What a store is to hold once it takes the login of another: the
    other's, but for what is kept apart, of which it keeps its own and
    takes none. Where neither holds any of that, the other's as it is
    written. None when nothing is left to hold."""
    mine = _kept_apart(own)
    if not mine and not _kept_apart(other):
        return other
    held = json_object(other) if other is not None else {}
    if held is None:
        # No JSON object, there is nothing to put its own into
        return other
    theirs = {key: value for key, value in held.items() if key not in KEPT_APART}
    try:
        kept = json.dumps({**theirs, **mine}, separators=(",", ":"))
    except (ValueError, RecursionError):
        kept = json.dumps(theirs, separators=(",", ":"))
    return kept.encode("ascii") if theirs or mine else None


def _reads_as_login(content: bytes) -> bool:
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
    # Whether what holds it is a plain file to be read, or nothing. Not a
    # link, a directory, a pipe or a file too large to be a login, which
    # a session can leave in the place of its own: that is no login, and
    # no logout either.
    plain: bool = True

    @cached_property
    def said(self) -> bytes | None:
        """What it says, the same for two that differ in how they are
        written alone."""
        return None if self.content is None else _as_one_line(self.content)

    @cached_property
    def fit(self) -> bool:
        """Whether it can be another store's: no login, or what reads
        as one, in a plain file (see plain)."""
        if not self.plain:
            return False
        return self.content is None or _reads_as_login(self.content)

    @cached_property
    def shared(self) -> bytes | None:
        """What of it is carried between the host and the sandbox, see
        _shared_of: two logins are the same when this is."""
        return _shared_of(self.content)

    @cached_property
    def noted(self) -> str:
        """What the state directory keeps of it, not the login itself:
        of what the two have in common."""
        shared = self.shared
        return ABSENT if shared is None else hashlib.sha256(shared).hexdigest()


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
        """Make the store hold another login in the place of this one,
        but for what is kept apart, see _taken_from. Not when it was
        written since this one was read, the next look settles that."""
        kept = _taken_from(self.login.content, other.content)
        return self.store.unchanged(self.login) and self.store.write(kept)


def _version_of(found: os.stat_result) -> tuple[int, ...]:
    """What tells the Keychain from the same written since, see
    Keychain: a file that security writes anew with each change."""
    return (found.st_ino, found.st_mtime_ns, found.st_size)


def _as_typed(words: list[str]) -> str | None:
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
    """A login kept in a file: the base's, and the host's but on macOS.

    Looked at every LOOK_EVERY, it is read again only once it changed:
    what was read last is kept, with the stamp of the file it was read
    from as its version (see stat_stamp), and given again while the file
    has that stamp still. The inode, the size and when the file was
    written are not enough for that. A renewed login is as long as the
    one before, its tokens are of one length, so one written again in
    place within the time a file system keeps such times by has all
    three the same, and so has one a session writes and then gives back
    the time it was written. When what is known of the file last changed
    is the system's to set, and no session can put it back, but it is
    kept as coarsely: so a file read before its stamp settled (see
    stamp_settled) is read again at the next look. A file renamed into
    the place of another can be given the inode of the one it replaced,
    but it is written after that one was read, and so has another stamp.
    The same stamp tells whether the file is still the one that was read
    before another login is written over it, see unchanged."""

    def __init__(self, path: str):
        self.path = path
        # What was last read, while it can be taken as still there, see
        # read
        self._kept: Login | None = None

    def read(self) -> Login:
        """The login in the file, none when there is no file. What is no
        regular file of a sane size is no login, nor a logout (see
        Login.plain): a session could leave a link, a directory or a pipe
        in the base. What was read last while the file is the same, see
        LoginFile. OSError when what is there cannot be told, in a
        directory a session closed."""
        try:
            about = os.lstat(self.path)
        except FileNotFoundError:
            self._kept = None
            return Login()
        stamp = stat_stamp(about)
        if self._kept is not None and self._kept.version == stamp:
            return self._kept
        self._kept = None
        if not stat.S_ISREG(about.st_mode) or about.st_size > MOST_READ:
            return Login(version=stamp, plain=False)
        file = open_plain(self.path)
        if file is None:
            return self._unopened(stamp)
        with file:
            found = os.fstat(file.fileno())
            if found.st_size > MOST_READ:
                return Login(version=stat_stamp(found), plain=False)
            login = Login(file.read(MOST_READ), stat_stamp(found), found.st_mtime_ns)
        if stamp_settled(found):
            self._kept = login
        return login

    def _unopened(self, stamp: tuple[int, ...]) -> Login:
        """What a regular file that could not be opened is: no login, when
        it is still the one that was looked at, which is closed to the
        launcher. OSError when it is gone or another since, as a login
        renewed is: the next look tells which."""
        try:
            again = stat_stamp(os.lstat(self.path))
        except OSError:
            again = None
        if again != stamp:
            raise OSError(f"{self.path} was replaced as it was read")
        return Login(version=stamp, plain=False)

    def unchanged(self, login: Login) -> bool:
        """Whether the file is still the one that was read, by its stamp,
        see LoginFile, or still not there."""
        try:
            found = os.lstat(self.path)
        except OSError:
            return login.content is None and login.plain
        return bool(login.version) and stat_stamp(found) == login.version

    def write(self, content: bytes | None) -> bool:
        """Make the file hold a login, whole or not at all: by a rename,
        as Claude Code writes it. None removes it."""
        self._kept = None
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
        version = _version_of(os.stat(self.path))
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
            return _version_of(os.stat(self.path)) == login.version
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
            line = _as_one_line(content)
            taken = self._add(line.hex()) == 0 and self.read().said == line
        if not taken:
            self._refused()
        return taken

    def _add(self, digits: str) -> int:
        """Have security write the item, given as hex digits, for how it
        ended. On its input where that can be: its arguments are for
        every process of the host to read."""
        add = ["add-generic-password", "-U", *self._item(), "-X", digits, self.path]
        typed = _as_typed(add)
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


def _user_name() -> str:
    """The user's name as Claude Code takes it for the account of its
    item, empty when there is none to be had."""
    try:
        return os.environ.get("USER") or pwd.getpwuid(os.getuid()).pw_name
    except KeyError:
        return ""


def _host_login(host: Host, user: str) -> LoginStore:
    """Where the host's login is kept: in the file, and on macOS (a home
    with a login Keychain, and security to read it with) where Claude
    Code keeps it there."""
    file = LoginFile(os.path.join(host.claude_dir, LOGIN))
    if os.path.isfile(host.keychain_file) and shutil.which(SECURITY):
        return HostLogin(Keychain(host.keychain_file, user), file)
    return file


def _last_shared(host: Host) -> str | None:
    """What was noted of the login the two last had in common, none when
    nothing was."""
    try:
        return Path(host.login_synced_file).read_text(encoding="ascii").strip() or None
    except (OSError, ValueError):
        return None


def _note_shared(host: Host, login: Login) -> None:
    private_dir(host.state_dir)
    write_whole(host.login_synced_file, login.noted + "\n")


def _written_last(one: Held, other: Held) -> Held:
    """Of two that differ, the one to keep when nothing says which of
    them changed: a login over none, then the later one."""
    if one.login.shared is None or other.login.shared is None:
        return other if one.login.shared is None else one
    return one if one.login.written >= other.login.written else other


class LoginPair:
    """The host's login and the base's."""

    def __init__(self, host: Host):
        self.host = host
        self.ours = _host_login(host, _user_name())
        self.theirs = LoginFile(os.path.join(host.sandbox_claude_dir, LOGIN))
        # What this launcher knows to be noted, to note it once
        self.noted: str | None = None

    def settle(self) -> None:
        """Make the two the same, from the one that changed. Never from
        the base when what is there does not read as a login, nor is a
        plain file (see Login.plain): the base is a session's to write,
        and the host's own claude would be logged in with whatever was
        carried over, or logged out. The host's is then put back in its
        place. Nothing either way while the host's is no plain file, a
        link of the user's: it is theirs to put right."""
        ours = Held(self.ours, self.ours.read())
        if not ours.login.plain:
            return
        theirs = Held(self.theirs, self.theirs.read())
        if ours.login.shared == theirs.login.shared and theirs.login.plain:
            self.note(ours.login)
            return
        shared = _last_shared(self.host)
        if shared == theirs.login.noted or not theirs.login.fit:
            source = ours
        elif shared == ours.login.noted:
            source = theirs
        else:
            source = _written_last(ours, theirs)
        target = theirs if source is ours else ours
        if target.take(source.login):
            self.note(source.login)

    def note(self, login: Login) -> None:
        if self.noted != login.noted:
            _note_shared(self.host, login)
            self.noted = login.noted

    def settle_quietly(self) -> None:
        """A look that failed (a full disk, a directory that is gone, a
        locked Keychain) is not the session's end, the next one tries
        again."""
        try:
            self.settle()
        except OSError:
            pass


def _keep_settled(pair: LoginPair, stop: threading.Event) -> None:
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
    with in_background(_keep_settled, pair):
        yield
