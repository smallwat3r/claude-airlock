"""The egress filter: the squid sidecar the filtered sessions reach the
outside through, which only lets the listed domains pass.

What it logged is read by egress_log.py, what it asks the user about is
kept by asked_hosts.py."""

from __future__ import annotations

import os
import threading
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from ..background import in_background
from ..docker import (
    docker_must,
    docker_ok,
    mount_arg,
)
from ..files import private_dir
from ..notice import warn
from ..settings import DOCKERFILE_DIR, EGRESS_PORT, Host
from .networks import EGRESS_PROXY, FILTER_NET, FILTER_NETS, ensure_network
from .shared_proxy import SharedProxy

# The image of the sidecar. It is the way out of the filtered sessions, so
# it is pinned by digest (the tag is informative only), refreshed by
# docker/update-pins.py.
SQUID_IMAGE = "ubuntu/squid:latest@sha256:6a097f68bae708cedbabd6188d68c7e2e7a38cedd05a176e1cc0ba29e3bbe029"
# The proxy's log is kept in a volume, so it outlives the proxy's container,
# as the current file and the one before it (logfile_rotate in squid.conf).
# The current one is rotated out once it is over the limit, which bounds the
# volume at about twice that. Squid only rotates when told to, the launcher
# does so when a filtered session starts and every ROTATE_EVERY seconds for
# as long as one runs: a session that floods the proxy with requests has
# the log overshoot by what is logged in that time, and no further.
EGRESS_LOG_VOLUME = "claude-egress-log"
EGRESS_LOG_DIR = "/var/log/squid"
# Where the proxy logs each request, in it
EGRESS_ACCESS_LOG = f"{EGRESS_LOG_DIR}/access.log"
EGRESS_LOG_LIMIT = 10 * 1024 * 1024
ROTATE_EVERY = 10.0
# How the proxy asks about a host that is not on its list, and where it
# finds what the launchers of the sessions that ask keep for it (see
# asked_hosts.py and docker/squid-ask-helper.sh)
ASK_HELPER = "squid-ask-helper.sh"
ASKED_HOSTS_MOUNT = "/var/lib/claude-airlock/asked"
# What the proxy reads of the checkout's docker directory, by where it
# reads it
SQUID_DIR = "/etc/squid"
SQUID_FILES = {
    ASK_HELPER: f"{SQUID_DIR}/ask-helper",
    "squid.conf": f"{SQUID_DIR}/squid.conf",
    "allowed-domains.txt": f"{SQUID_DIR}/allowed-domains.txt",
}


def asked_hosts_root(host: Host) -> str:
    """The directory the proxy is given to ask through, made as needed.
    The proxy runs as a user of its own and has to get into it, so it is
    not for the user alone as the rest of the launcher's state is: the
    state directory above it is, which keeps everyone else on the host
    out of it."""
    private_dir(host.state_dir)
    root = host.asked_hosts_dir
    os.makedirs(root, exist_ok=True)
    # Whatever the umask made of it
    os.chmod(root, 0o755)  # noqa: S103, the proxy's user reads it
    return root


def _egress_proxy(host: Host) -> SharedProxy:
    """The squid sidecar as it is to be started now, its files as they
    are on disk."""
    files = {
        target: Path(DOCKERFILE_DIR, name).read_bytes()
        for name, target in SQUID_FILES.items()
    }
    options = (
        # Written to by the proxy too: the hosts that wait for an answer
        mount_arg(asked_hosts_root(host), ASKED_HOSTS_MOUNT, "z"),
        f"--volume={EGRESS_LOG_VOLUME}:{EGRESS_LOG_DIR}",
    )
    return SharedProxy(EGRESS_PROXY, FILTER_NET, SQUID_IMAGE, files, options)


def start_egress_proxy(host: Host) -> None:
    """(Re)create the squid sidecar on the internal networks, then give it
    its other leg on the default bridge. Labelled with a hash of its config
    and image, so an edited allowlist is noticed (see egress_proxy_current).
    It reads copies of its files, what is edited while it runs is for the
    proxy that replaces it."""
    ensure_network(FILTER_NET, internal=True)
    _egress_proxy(host).start(host)
    docker_must("network", "connect", "bridge", EGRESS_PROXY)
    # The internal networks of the sessions with a socket proxy, those that
    # are there: sessions may be running on them
    for network in FILTER_NETS[1:]:
        docker_ok("network", "connect", network, EGRESS_PROXY)
    _wait_for_egress_proxy()


def _wait_for_egress_proxy(timeout: float = 15.0) -> None:
    """Wait until squid accepts connections. It takes a moment to listen
    after its container starts, and a session started sooner has its first
    requests refused."""
    probe = f"exec 3<>/dev/tcp/127.0.0.1/{EGRESS_PORT}"
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if docker_ok("exec", EGRESS_PROXY, "bash", "-c", probe):
            return
        time.sleep(0.2)
    warn(
        "the egress proxy is slow to start, the session's first requests may fail",
    )


def egress_proxy_current(host: Host) -> bool:
    """Running, and started from the config as it is on disk now. A stale
    proxy is replaced on the next filtered start, which briefly drops the
    connections of other filtered sessions."""
    return _egress_proxy(host).current()


def rotate_access_log() -> None:
    """Rotate the proxy's log out once it is over the limit. Best effort,
    a session is not held up over its proxy's housekeeping."""
    over_limit = f'[ "$(stat -c %s {EGRESS_ACCESS_LOG})" -gt {EGRESS_LOG_LIMIT} ]'
    docker_ok("exec", EGRESS_PROXY, "sh", "-c", f"{over_limit} && squid -k rotate")


def _keep_access_log_rotated(stop: threading.Event) -> None:
    """Rotate the proxy's log out whenever it is found over the limit,
    every ROTATE_EVERY seconds until told to stop."""
    while not stop.wait(ROTATE_EVERY):
        rotate_access_log()


@contextmanager
def access_log_rotated() -> Iterator[None]:
    """While a filtered session runs, keep the proxy's log within its
    limit. The session is what the log grows by: one that has request
    after request refused, each with a URL as long as the proxy takes,
    would have it grow for as long as it runs, and every reader of the
    log after it read all of that."""
    with in_background(_keep_access_log_rotated):
        yield
