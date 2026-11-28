"""Noting the calls a session makes to the Docker socket
(CLAUDE_AIRLOCK_DOCKER_SOCKET).

The socket proxy logs every call it is asked for, with the address it came
from. While a session runs, the launcher reads that log and notes the
calls of the session's addresses, in the record of doors.py."""

from __future__ import annotations

import ipaddress
import re
import subprocess
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager

from ..background import wait_for
from ..docker import docker_popen
from ..notice import warn
from ..sandbox.networks import session_addresses
from ..sandbox.socket_proxy import has_socket_proxy, socket_proxy_name
from ..settings import Host, Settings
from .doors import Door, SessionUses
from .procwatch import unmapped

# A line of the socket proxy's log (HAProxy's httplog): the address and
# port it came from, then further on the status and, quoted, the request
_PROXY_LINE = re.compile(
    r"^(?P<address>[0-9a-fA-F.:]+):\d+ \[[^\]]*\] \S+ \S+ \S+ (?P<status>\d{3}) .*"
    r'"(?P<method>[A-Z]+) (?P<path>\S+)'
)
# The status of a call the proxy did not let through to the socket
DENIED = 403


def parse_proxy_call(line: str) -> tuple[str, str, str, int] | None:
    """The address, method, path and status of a line of the socket
    proxy's log, none for a line that is not a request."""
    found = _PROXY_LINE.match(line.strip())
    if not found:
        return None
    try:
        address = ipaddress.ip_address(found["address"])
    except ValueError:
        return None
    # The proxy listens on IPv4 and IPv6 with one socket, so it logs an
    # IPv4 caller as ::ffff:172.20.0.5. session_addresses gives 172.20.0.5.
    return (
        unmapped(address),
        found["method"],
        found["path"],
        int(found["status"]),
    )


class SocketWatch:
    """Reads the socket proxy's log while a session runs and notes the
    calls that came from one of the session's addresses."""

    def __init__(self, host: Host, session: str, owner: str, proxy: str) -> None:
        self._uses = SessionUses(host, session, Door.DOCKER)
        self._owner = owner
        self._proxy = proxy
        self._stop = threading.Event()
        # From when the calls are read: the log is only followed once the
        # session has an address, a moment after it started
        self._since = int(time.time())
        self._log: subprocess.Popen | None = None
        # Held to start following the log and to close the watch: the log
        # is not followed once the watch is closed, nobody would end it
        self._starting = threading.Lock()
        self._closed = False
        # Why the calls stopped being noted before the watch was closed,
        # empty when they did not
        self._stopped = ""
        # Why a call could not be noted, the last of them, empty when
        # they all were
        self._unnoted = ""
        self._thread = threading.Thread(target=self._watched, daemon=True)
        self._thread.start()

    def close(self) -> None:
        self._stop.set()
        # Give the last calls of the session the moment it takes to read them
        self._thread.join(timeout=1.0)
        with self._starting:
            self._closed = True
            if self._log and self._log.poll() is None:
                self._log.terminate()
        self._thread.join()
        self._uses.close()
        if self._stopped:
            warn(
                "the calls to the Docker socket were not all noted, the watch"
                f" on its proxy ended before the session did: {self._stopped}"
            )
        if self._unnoted:
            warn(
                "the calls to the Docker socket were not all noted, the record"
                f" of them could not be written: {self._unnoted}"
            )

    def _follow(self) -> subprocess.Popen | None:
        """Start following the proxy's log, none when that cannot be
        done or the watch is closed. The proxy outlives the session, so
        does a log that is followed and not ended."""
        with self._starting:
            if self._closed:
                return None
            try:
                self._log = docker_popen(
                    *("logs", "--follow", f"--since={self._since}", self._proxy),
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    errors="replace",
                )
            except OSError:
                return None
            return self._log

    def _watched(self) -> None:
        """Watch, and keep why it ended when that was not for the watch
        being closed: said then, see close."""
        try:
            self._stopped = self._watch()
        except Exception as error:  # noqa: BLE001
            self._stopped = repr(error)

    def _watch(self) -> str:
        """Note the calls of the session until the watch is closed.
        Returns why it ended when that was for something else, nothing
        when it was closed."""
        # Its addresses are only known once the container is up. Any of
        # them: it has one of IPv6 too where the daemon gives its networks
        # those, and calls from whichever it likes
        addresses = wait_for(lambda: session_addresses(self._owner), self._stop)
        if not addresses:
            return ""
        log = self._follow()
        if log is None:
            return self._ended_by("the log of the proxy could not be followed")
        with log:
            for line in log.stdout or ():
                call = parse_proxy_call(line)
                if call is None or call[0] not in addresses:
                    continue
                _, method, path, status = call
                try:
                    # A call that was denied costs a session nothing, and
                    # is kept apart from those it was let make
                    self._uses.note(
                        method,
                        refused=status == DENIED,
                        method=method,
                        path=path,
                        status=status,
                    )
                except OSError as problem:
                    # A full disk or the like. The call was already
                    # answered, all that is left is to say so, see close
                    self._unnoted = str(problem)
        return self._ended_by("the log of the proxy ended")

    def _ended_by(self, reason: str) -> str:
        """The reason the watch ended, nothing when it was closed."""
        return "" if self._stop.is_set() else reason


@contextmanager
def socket_proxy_watched(
    settings: Settings, host: Host, session: str, owner: str
) -> Iterator[None]:
    """While a session with a way to the Docker socket runs, note the
    calls it makes. owner is the container whose address the session has
    on its network: itself, or its capture sidecar."""
    if not has_socket_proxy(settings):
        yield
        return
    watch = SocketWatch(host, session, owner, socket_proxy_name(settings))
    try:
        yield
    finally:
        watch.close()
