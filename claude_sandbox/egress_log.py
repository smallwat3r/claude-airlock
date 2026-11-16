"""Reading the egress proxy's log: what the filtered sessions asked it
for, and what it refused them.

The proxy logs each request with the address it came from, which a
container without capabilities cannot forge: that is what tells the
sessions in the one log apart (see session_address_recorded in
network.py). Read for --net-log, for --trace and for the lines said when
a session ends. The proxy itself, and the volume its log is kept in, are
network.py's."""

from __future__ import annotations

import subprocess
from collections import Counter
from dataclasses import dataclass
from urllib.parse import urlsplit

from .docker import docker, docker_bytes, docker_ok
from .network import EGRESS_LOG_DIR, EGRESS_LOG_VOLUME, EGRESS_PROXY, SQUID_IMAGE
from .records import NetSession
from .settings import Fatal


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

    @property
    def began(self) -> float:
        return self.ended - self.seconds

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


def parse_proxy_request(line: str) -> ProxyRequest | None:
    """A line of squid's native log format, none for anything else."""
    try:
        ended, milliseconds, address, result, sent, method, url = line.split()[:7]
        return ProxyRequest(
            float(ended),
            float(milliseconds) / 1000,
            address,
            "DENIED" in result,
            method,
            url,
            int(sent),
        )
    except ValueError:
        return None


def made_by(
    request: ProxyRequest, session: NetSession, start: float, end: float
) -> bool:
    """Whether a session made a request between start and end: it came
    from the session's address and was open at some point of that time.
    The proxy logs a tunnel when it closes, which can be much later."""
    return (
        session.ip == request.address
        and request.ended >= max(start, session.start)
        and request.began <= min(end, session.until)
    )


def access_log(stderr: int | None = None) -> str | None:
    """The egress proxy's log, the rotated file then the current one, None
    when it cannot be read. Read through the proxy's container, the volume
    it is in is not reachable from the host otherwise, and when the proxy
    is not running (no filtered session is) through one made for it."""
    current = f"{EGRESS_LOG_DIR}/access.log"
    read = ("sh", "-c", f"cat {current}.0 2>/dev/null; cat {current}")
    log = docker(
        "exec", EGRESS_PROXY, *read, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL
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
    )
    return log.stdout if log.returncode == 0 else None


def logged_requests(stderr: int | None = None) -> list[ProxyRequest] | None:
    """Every request in the egress proxy's log, None when the log cannot
    be read."""
    log = access_log(stderr)
    if log is None:
        return None
    return [r for r in map(parse_proxy_request, log.splitlines()) if r]


def logged_since(offset: int | None) -> tuple[int, list[ProxyRequest]] | None:
    """The requests the egress proxy logged past the first offset bytes of
    its current log file, and the offset to ask with next time. Without an
    offset none, just where the log ends now. A log that was rotated since
    is read from its start. None when the log cannot be read."""
    file = f"{EGRESS_LOG_DIR}/access.log"
    script = (
        'size=$(stat -c %s "$1") || exit 1; from=${2:-$size};'
        ' [ "$size" -lt "$from" ] && from=0;'
        ' echo "$from"; tail -c +"$((from + 1))" "$1"'
    )
    asked = [] if offset is None else [str(offset)]
    said = docker_bytes("exec", EGRESS_PROXY, "sh", "-c", script, "sh", file, *asked)
    if said is None:
        return None
    first, _, log = said.partition(b"\n")
    try:
        start = int(first)
    except ValueError:
        return None
    # A line still being written is left for the next time
    whole = log[: log.rfind(b"\n") + 1]
    lines = whole.decode("utf-8", "replace").splitlines()
    return start + len(whole), [r for r in map(parse_proxy_request, lines) if r]


def net_log() -> int:
    """Print the domains the egress filter refused, most frequent first. The
    quickest way to find what a project needs added to allowed-domains.txt."""
    requests = logged_requests(stderr=subprocess.DEVNULL)
    if requests is None:
        raise Fatal(
            "the egress filter has no log yet "
            "(start a CLAUDE_DOCKER_NET_FILTER=1 session first)"
        )
    denied = Counter(request.url for request in requests if request.denied)
    for url, count in sorted(denied.items(), key=lambda item: (-item[1], item[0])):
        print(f"{count:7d} {url}")
    return 0
