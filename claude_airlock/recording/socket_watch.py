"""Noting the calls a session makes to the Docker socket
(CLAUDE_AIRLOCK_DOCKER_SOCKET).

The socket proxy logs every call it is asked for, with the address it came
from. While a session runs, the launcher reads that log and notes the
calls of the session's address, in the record of doors.py."""

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
from ..sandbox.networks import session_address
from ..sandbox.socket_proxy import has_socket_proxy, socket_proxy_name
from ..settings import Host, Settings
from .doors import Door, SessionUses

# A line of the socket proxy's log (HAProxy's httplog): the address and
# port it came from, then further on the status and, quoted, the request
_PROXY_LINE = re.compile(
    r"^(?P<address>[0-9a-fA-F.:]+):\d+ \[[^\]]*\] \S+ \S+ \S+ (?P<status>\d{3}) .*"
    r'"(?P<method>[A-Z]+) (?P<path>\S+)'
)


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
    # IPv4 caller as ::ffff:172.20.0.5. session_address gives 172.20.0.5.
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped:
        address = address.ipv4_mapped
    return (
        str(address),
        found["method"],
        found["path"],
        int(found["status"]),
    )


class SocketWatch:
    """Reads the socket proxy's log while a session runs and notes the
    calls that came from the session's address."""

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
            self._watch()
        except Exception as error:  # noqa: BLE001
            self._stopped = repr(error)

    def _watch(self) -> None:
        # The address is only known once the container is up
        address = wait_for(lambda: session_address(self._owner), self._stop)
        log = self._follow() if address else None
        if log is None:
            if address and not self._stop.is_set():
                self._stopped = "the log of the proxy could not be followed"
            return
        with log:
            for line in log.stdout or ():
                call = parse_proxy_call(line)
                if call is None or call[0] != address:
                    continue
                _, method, path, status = call
                try:
                    self._uses.note(method, method=method, path=path, status=status)
                except OSError:
                    continue
        if not self._stop.is_set():
            self._stopped = "the log of the proxy ended"


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
