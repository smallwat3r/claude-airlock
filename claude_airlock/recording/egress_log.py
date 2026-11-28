"""Reading the egress proxy's log: what the filtered sessions asked it
for, and what it refused them.

The proxy logs each request with the address it came from, which a
container without capabilities cannot forge: that is what tells the
sessions in the one log apart (see address.py). Read for --net-log, for
--trace and for the lines said when a session ends. The proxy itself, and
the volume its log is kept in, are egress_proxy.py's.

How much the log holds is a session's doing, a request it is refused is
a line too: no more of it is read than MOST_READ, its end, and a reader
that was given less than all of it says so."""

from __future__ import annotations

import ipaddress
import subprocess
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass
from urllib.parse import urlsplit

from ..docker import docker, docker_bytes, docker_ok
from ..errors import Fatal
from ..files import whole_lines
from ..notice import warn
from ..sandbox.egress_proxy import (
    EGRESS_ACCESS_LOG,
    EGRESS_LOG_DIR,
    EGRESS_LOG_VOLUME,
    SQUID_IMAGE,
)
from ..sandbox.networks import EGRESS_PROXY
from .records import TracedSession

# The fields of a line that says how much the session sent, the last of them
SENT_FIELDS = 11
# No more of the log is read than this, its end: of the rotated file and
# the current one together, which hold less as a rule (see EGRESS_LOG_LIMIT
# of egress_proxy.py). A session can have the proxy log faster than a
# launcher rotates, and what it made of the log would be held here whole,
# by every --trace and at the end of every session.
MOST_READ = 32 * 1024 * 1024
# What the proxy's log is said to be, ahead of what it holds, when it has
# a rotated file: no line of the log, which starts with when it was
# written
ROTATED = "# rotated"


@dataclass(frozen=True)
class ProxyRequest:
    """A line of the egress proxy's log."""

    ended: float
    seconds: float
    # Of the container that asked
    address: str
    denied: bool
    method: str
    url: str
    size: int
    # The bytes the session sent, of a tunnel what went up through it.
    # None for a line of a proxy started before its log said so.
    sent: int | None = None

    @property
    def began(self) -> float:
        return self.ended - self.seconds

    @property
    def host(self) -> str:
        """The host asked for, empty for a URL that cannot be read."""
        try:
            target = urlsplit(self.url if "://" in self.url else "//" + self.url)
            return target.hostname or ""
        except ValueError:
            return ""

    @property
    def port(self) -> int:
        """The port asked for, the usual one of the scheme when the URL
        names none, 0 for a URL that cannot be read."""
        try:
            # CONNECT names host:port, the other methods a whole URL
            target = urlsplit(self.url if "://" in self.url else "//" + self.url)
            return target.port or (443 if target.scheme == "https" else 80)
        except ValueError:
            return 0


def _as_recorded(address: str) -> str:
    """The address a request came from, written the way the record of a
    session has the addresses it was given (see session_addresses of
    networks.py): one of IPv6 can be written in more ways than one, and
    one of IPv4 inside IPv6 is the IPv4 address it is. As it stands when
    it is neither."""
    if ":" not in address:
        return address
    try:
        found = ipaddress.ip_address(address)
    except ValueError:
        return address
    return str(getattr(found, "ipv4_mapped", None) or found)


def parse_proxy_request(line: bytes) -> ProxyRequest | None:
    """A line of the proxy's log, none for anything else: squid's native
    format, then the bytes the session sent (see docker/squid.conf). Its
    fields are told apart by the whitespace of ASCII alone: the URL is
    the session's to write, and other whitespace in it would split it
    into more fields."""
    said = [field.decode("utf-8", "replace") for field in line.split()]
    try:
        ended, milliseconds, address, result, size, method, url = said[:7]
        return ProxyRequest(
            float(ended),
            float(milliseconds) / 1000,
            _as_recorded(address),
            "DENIED" in result,
            method,
            url,
            int(size),
            max(int(said[10]), 0) if len(said) == SENT_FIELDS else None,
        )
    except ValueError:
        return None


def _made_by(
    request: ProxyRequest, session: TracedSession, start: float, end: float
) -> bool:
    """Whether a session may have made a request between start and end:
    it came from the address this line of the session has (one that has
    several has a line for each) and was open at some point of that time,
    while the session ran."""
    return (
        session.ip == request.address
        and request.ended >= max(start, session.start)
        and request.began <= min(end, session.until)
    )


def _began_in(request: ProxyRequest, sessions: list[TracedSession]) -> TracedSession:
    """Of the sessions a request was open in, the one it began in: the
    last to start by then. The proxy logs a tunnel when it closes, which
    can be once its session ended and the address was given to the next.
    Of one that reads as begun before any of them, the first: the proxy
    has a clock of its own, which can be a little behind."""
    began = [session for session in sessions if session.start <= request.began]
    if began:
        return max(began, key=lambda session: session.start)
    return min(sessions, key=lambda session: session.start)


def requests_made(
    logged: list[ProxyRequest], sessions: list[TracedSession], start: float, end: float
) -> Iterator[tuple[ProxyRequest, TracedSession]]:
    """Each request of the log that one of the sessions made between
    start and end, see _made_by, with the session that made it, see
    _began_in."""
    for request in logged:
        made = [s for s in sessions if _made_by(request, s, start, end)]
        if made:
            yield request, _began_in(request, made)


def end_of_log(log: str, most: int, marked: bool = False) -> str:
    """What a shell in the proxy's container runs to give the end of its
    log: the rotated file then the current one, and of the two together
    the last so many bytes. It fails without a current file. When marked,
    a log that has a rotated file says so first, on a line of its own
    (see ROTATED)."""
    mark = f" [ -e {log}.0 ] && echo '{ROTATED}';" if marked else ""
    return (
        f"[ -r {log} ] || exit 1;{mark}"
        f" {{ cat {log}.0 2>/dev/null; cat {log}; }} | tail -c {most}"
    )


def _whole(log: bytes) -> bytes:
    """The lines of what end_of_log gave. A log that is longer than is
    read does not start with the start of a line: what there is of that
    one is left out, and it is said that not all was read, a session then
    has nothing in it of what it asked before."""
    if len(log) > MOST_READ:
        warn(
            f"the egress proxy's log is longer than the {MOST_READ >> 20} MB"
            " that are read of it: what was asked before those is not shown"
        )
        log = log[log.find(b"\n") + 1 :]
    return log


@dataclass(frozen=True)
class ProxyLog:
    """What was read of the egress proxy's log: its requests, and whether
    it may hold less than was logged. The proxy keeps one file besides
    the one it writes to, so what was logged before those two is gone,
    and no more than MOST_READ is read of them. A session has the log
    rotated by what it asks, as often as it likes: where the log begins
    after a session did, what the session asked before is not known."""

    requests: list[ProxyRequest]
    # Whether it was rotated, or is longer than was read
    shortened: bool = False

    @property
    def begins(self) -> float | None:
        """When the first request that is left of it ended, none for a
        log that holds no request or is all there, as far as is known."""
        if not self.shortened or not self.requests:
            return None
        return self.requests[0].ended


def raw_log(stderr: int | None = None) -> bytes | None:
    """The end of the egress proxy's log as end_of_log gives it, marked,
    None when it cannot be read. Read through the proxy's container, the
    volume it is in is not reachable from the host otherwise, and when
    the proxy is not running (no filtered session is) through one made
    for it."""
    # A byte more than is read, which tells a log that is longer
    script = end_of_log(EGRESS_ACCESS_LOG, MOST_READ + 1, marked=True)
    read = ("sh", "-c", script)
    log = docker(
        *("exec", EGRESS_PROXY, *read),
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=False,
    )
    if log.returncode == 0:
        return log.stdout
    # Not asked of a volume that is not there, docker would make it
    if not docker_ok("volume", "inspect", EGRESS_LOG_VOLUME):
        return None
    log = docker(
        "run",
        "--rm",
        "--network=none",
        f"--volume={EGRESS_LOG_VOLUME}:{EGRESS_LOG_DIR}:ro",
        f"--entrypoint={read[0]}",
        SQUID_IMAGE,
        *read[1:],
        stdout=subprocess.PIPE,
        stderr=stderr,
        text=False,
    )
    return log.stdout if log.returncode == 0 else None


def proxy_log(stderr: int | None = None) -> ProxyLog | None:
    """The egress proxy's log, the rotated file then the current one, as
    far back as MOST_READ (see _whole), None when it cannot be read."""
    raw = raw_log(stderr)
    if raw is None:
        return None
    mark = ROTATED.encode() + b"\n"
    rotated = raw.startswith(mark)
    raw = raw[len(mark) :] if rotated else raw
    shortened = rotated or len(raw) > MOST_READ
    # At the end of a line alone: what text takes for one besides is the
    # session's to put in a URL
    lines = _whole(raw).split(b"\n")
    return ProxyLog([r for r in map(parse_proxy_request, lines) if r], shortened)


def logged_requests(stderr: int | None = None) -> list[ProxyRequest] | None:
    """Every request in the egress proxy's log, None when the log cannot
    be read."""
    log = proxy_log(stderr)
    return None if log is None else log.requests


def log_since(most: int) -> str:
    """What a shell in the proxy's container runs to give what its log,
    the first thing it is given, holds past so many bytes, the second: the
    place it is read from, on a line, then no more than most bytes from
    there. From where the log ends when it is given no place, and from
    its start when it is shorter than the place, it was rotated since.
    The size is asked of wc, which is the same everywhere but for the
    spaces some put before it, stat is asked another way on macOS."""
    return (
        'size=$(wc -c <"$1") || exit 1; size=$((size)); from=${2:-$size};'
        ' [ "$size" -lt "$from" ] && from=0;'
        f' echo "$from"; tail -c +"$((from + 1))" "$1" | head -c {most}'
    )


def logged_since(offset: int | None) -> tuple[int, list[ProxyRequest]] | None:
    """The requests the egress proxy logged past the first offset bytes of
    its current log file, and the offset to ask with next time. Without an
    offset none, just where the log ends now. A log that was rotated since
    is read from its start. No more than MOST_READ at a time, the rest is
    for the next. None when the log cannot be read."""
    asked = [] if offset is None else [str(offset)]
    said = docker_bytes(
        *("exec", EGRESS_PROXY, "sh", "-c", log_since(MOST_READ)),
        *("sh", EGRESS_ACCESS_LOG, *asked),
    )
    if said is None:
        return None
    first, _, log = said.partition(b"\n")
    try:
        start = int(first)
    except ValueError:
        return None
    # A line still being written is left for the next time, see whole_lines
    lines, taken = whole_lines(log, MOST_READ)
    return start + taken, [r for r in map(parse_proxy_request, lines) if r]


def net_log() -> int:
    """Print the domains the egress filter refused, most frequent first. The
    quickest way to find what a project needs added to allowed-domains.txt."""
    requests = logged_requests(stderr=subprocess.DEVNULL)
    if requests is None:
        raise Fatal(
            "the egress filter has no log yet "
            "(start a CLAUDE_AIRLOCK_NET_FILTER=1 session first)"
        )
    denied = Counter(request.url for request in requests if request.denied)
    for url, count in sorted(denied.items(), key=lambda item: (-item[1], item[0])):
        print(f"{count:7d} {url}")
    return 0
