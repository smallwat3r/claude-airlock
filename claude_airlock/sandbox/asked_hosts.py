"""Asking the user about a host the egress filter does not allow
(CLAUDE_AIRLOCK_NET_ASK): the launcher's side of it.

The filter refuses what is not on its list. With this, a request of the
session for such a host is held by the proxy instead, the user is asked
in line mode (see chat/hosts.py), and a yes lets it through. Nothing is
looked up or sent for the host before that.

The proxy is shared by every filtered session and knows a session by its
address alone. So the launcher of a session that asks keeps a directory
named after that address, where the proxy's helper finds it (see
docker/squid-ask-helper.sh, which says what is in it). A session without
one is not asked for: its requests are refused as before.

An answer holds for the host as it was asked about, not for the names
under it, and for as long as the session lasts: the directory goes with
the session. One that a killed launcher left would be found by the next
session given its address, with what was allowed there, so every filtered
session drops those before it starts (see drop_left_behind).

The helper is the proxy's and writes one thing here, the names of the
hosts that wait. They are read as names and nothing else, and only those
that could be a host's are taken."""

from __future__ import annotations

import contextlib
import ipaddress
import json
import os
import re
import shutil
import sys
import tempfile
import threading
from collections.abc import Iterator
from contextlib import contextmanager

from ..background import in_background, wait_for
from ..files import json_object, locked, private_dir, write_whole
from ..launcher import Launcher, session_alive
from ..settings import NAME, Host, Settings
from .network import asked_hosts_root, session_address

# In the directory of a session: the hosts a request waits for an answer
# about, written by the proxy's helper, and those the user allowed and
# refused, written here. Each host is an empty file of its name.
WAITING = "waiting"
ALLOWED = "allowed"
REFUSED = "refused"
# Whose the directory is: the session's container and its launcher
OWNER = "owner"
# A host as the helper takes one for a file name, see there, written the
# same in both: a name of the public DNS, labels with dots between them,
# the last one starting with a letter. So never a path, and never what
# the proxy would reach without asking the DNS for it, which the user
# cannot tell from a name: an address, in whatever notation, or the bare
# name of a container on the proxy's networks, another session's for one.
HOST_PATTERN = (
    r"^([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]([a-z0-9-]{0,61}[a-z0-9])?$"
)
HOST = re.compile(HOST_PATTERN)
# How long such a name is at most
LONGEST_HOST = 253
# The hosts taken of those that wait, the helper lets no more wait
MOST_WAITING = 8
# What a directory that is being made or dropped is named with first: no
# address, so the helper never looks into one
ASIDE = "."


@contextmanager
def _locked(host: Host) -> Iterator[None]:
    """One launcher at a time for making and dropping the directories:
    one that is being made is not taken for one left behind."""
    with locked(os.path.join(private_dir(host.state_dir), "asked-hosts.lock")):
        yield


def _drop(root: str, name: str) -> None:
    """Take a directory away, under another name first: the helper finds
    it whole or not at all, never with half of what was allowed."""
    try:
        aside = tempfile.mkdtemp(prefix=ASIDE, dir=root)
    except OSError:
        return
    # Nothing to move when it is not there
    with contextlib.suppress(OSError):
        os.rename(os.path.join(root, name), os.path.join(aside, name))
    shutil.rmtree(aside, ignore_errors=True)


def _owned(tree: str) -> bool:
    """Whether the session a directory was made for is still going."""
    try:
        with open(os.path.join(tree, OWNER), "rb") as file:
            owner = json_object(file.read(4096)) or {}
        launcher = Launcher.from_fields(owner)
        session = owner["session"]
    except (OSError, KeyError, ValueError, TypeError):
        return False
    return isinstance(session, str) and session_alive(launcher, session)


def drop_left_behind(host: Host) -> None:
    """Drop the directories of sessions that are over: their addresses
    are the next sessions' to take, which must not find what another was
    allowed. To be called before a filtered session starts, whether it
    asks or not."""
    root = host.asked_hosts_dir
    with _locked(host):
        try:
            names = os.listdir(root)
        except OSError:
            return
        for name in names:
            tree = os.path.join(root, name)
            if name.startswith(ASIDE):
                shutil.rmtree(tree, ignore_errors=True)
            elif not _owned(tree):
                _drop(root, name)


def is_host(name: str) -> bool:
    """Whether a name is one the user is asked about, see HOST_PATTERN."""
    return len(name) <= LONGEST_HOST and HOST.fullmatch(name) is not None


class AskedHosts:
    """What the egress filter asks the user about for one session, and
    what they said. There is nothing to ask about until the session's
    address is known (see open), and nothing more once it is over (see
    close)."""

    def __init__(self, host: Host, session: str):
        self._host = host
        # The session's container
        self._session = session
        self._address = ""
        self._opening = threading.Lock()
        self._closed = False

    def open(self, address: str) -> bool:
        """Have the proxy ask for the session at that address from now
        on. Whether it does: not for an address the helper takes none
        of, and not once the session is over."""
        try:
            ipaddress.IPv4Address(address)
        except ValueError:
            return False
        root = asked_hosts_root(self._host)
        owner = {"session": self._session, **Launcher.current().as_fields()}
        with self._opening, _locked(self._host):
            if self._closed:
                return False
            # Whatever a session that had the address before left there
            _drop(root, address)
            made = tempfile.mkdtemp(prefix=ASIDE, dir=root)
            write_whole(os.path.join(made, OWNER), json.dumps(owner))
            # The proxy runs as a user of its own: it reads all of this,
            # and writes the hosts that wait. Whatever the umask is.
            for name, mode in ((WAITING, 0o777), (ALLOWED, 0o755), (REFUSED, 0o755)):
                os.mkdir(os.path.join(made, name))
                os.chmod(os.path.join(made, name), mode)
            os.chmod(made, 0o755)
            os.rename(made, os.path.join(root, address))
            self._address = address
        return True

    def close(self) -> None:
        """The session is over: nothing it was allowed is left."""
        with self._opening, _locked(self._host):
            self._closed = True
            if self._address:
                _drop(self._host.asked_hosts_dir, self._address)
                self._address = ""

    def _path(self, kind: str, host: str = "") -> str:
        return os.path.join(self._host.asked_hosts_dir, self._address, kind, host)

    def waiting(self) -> list[str]:
        """The hosts a request of the session waits for an answer about."""
        if not self._address:
            return []
        try:
            names = os.listdir(self._path(WAITING))
        except OSError:
            return []
        return sorted(name for name in names if is_host(name))[:MOST_WAITING]

    def answer(self, host: str, allowed: bool | None) -> None:
        """Say whether the session may reach a host, for as long as it
        lasts. None says neither: the requests that wait are refused, and
        the next one for the host is asked about again."""
        if not self._address or not is_host(host):
            return
        with contextlib.suppress(OSError):
            if allowed is not None:
                kept = self._path(ALLOWED if allowed else REFUSED, host)
                flags = os.O_WRONLY | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC
                os.close(os.open(kept, flags, 0o644))
            # After the answer: the helper takes a host that no longer
            # waits and has none for refused
            os.unlink(self._path(WAITING, host))


def open_once_addressed(asked: AskedHosts, owner: str, stop: threading.Event) -> None:
    """Have the proxy ask for a session once its address is known, which
    is when its container is up. owner is the container the address
    belongs to: the session, or its capture sidecar."""
    address = wait_for(lambda: session_address(owner), stop)
    if address and not asked.open(address):
        print(
            f"{NAME}: the egress filter cannot ask for a session at {address},"
            " it refuses what is not on its list",
            file=sys.stderr,
        )


@contextmanager
def hosts_asked(
    settings: Settings, host: Host, name: str, owner: str, chat: bool
) -> Iterator[AskedHosts | None]:
    """While a session runs, what its filter asks the user about, none
    for a session that is not asked for: without the filter, and where
    there is no place to ask, which line mode alone has. The requests it
    makes before its address is known are refused as without this."""
    if settings.net_filter:
        drop_left_behind(host)
    wanted = settings.net_filter and settings.net_ask
    if not (wanted and chat):
        if wanted:
            print(
                f"{NAME}: CLAUDE_AIRLOCK_NET_ASK asks in line mode only, this"
                " session's filter refuses what is not on its list",
                file=sys.stderr,
            )
        yield None
        return
    asked = AskedHosts(host, name)
    try:
        with in_background(open_once_addressed, asked, owner):
            yield asked
    finally:
        asked.close()
