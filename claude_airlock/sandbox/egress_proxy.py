"""The egress filter: the squid sidecar the filtered sessions reach the
outside through, which only lets the listed domains pass.

What it logged is read by egress_log.py, what it asks the user about is
kept by asked_hosts.py."""

from __future__ import annotations

import os
import time
from pathlib import Path

from ..docker import (
    docker_must,
    docker_ok,
    mount_arg,
)
from ..files import private_dir
from ..notice import warn
from ..settings import DOCKERFILE_DIR, EGRESS_PORT, Host
from .networks import EGRESS_PROXY, FILTER_NET, FILTER_NETS, ensure_network
from .shared_proxy import config_hash, proxy_current, start_shared_proxy

# The image of the sidecar. It is the way out of the filtered sessions, so
# it is pinned by digest (the tag is informative only), refreshed by
# docker/update-pins.py.
SQUID_IMAGE = "ubuntu/squid:latest@sha256:6a097f68bae708cedbabd6188d68c7e2e7a38cedd05a176e1cc0ba29e3bbe029"
# The proxy's log is kept in a volume, so it outlives the proxy's container,
# as the current file and the one before it (logfile_rotate in squid.conf).
# The current one is rotated out once it is over the limit, which bounds the
# volume at about twice that. Squid only rotates when told to, the launcher
# does so when a filtered session starts: one very long session can
# overshoot, a cron in the sidecar would be the fix if that ever matters.
EGRESS_LOG_VOLUME = "claude-egress-log"
EGRESS_LOG_DIR = "/var/log/squid"
# Where the proxy logs each request, in it
EGRESS_ACCESS_LOG = f"{EGRESS_LOG_DIR}/access.log"
EGRESS_LOG_LIMIT = 10 * 1024 * 1024
# How the proxy asks about a host that is not on its list, and where it
# finds what the launchers of the sessions that ask keep for it (see
# asked_hosts.py and docker/squid-ask-helper.sh)
ASK_HELPER = "squid-ask-helper.sh"
ASKED_HOSTS_MOUNT = "/var/lib/claude-airlock/asked"


def egress_config_hash() -> str:
    files = (
        Path(DOCKERFILE_DIR, name).read_bytes()
        for name in ("squid.conf", "allowed-domains.txt", ASK_HELPER)
    )
    return config_hash(SQUID_IMAGE.encode(), *files)


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
    os.chmod(root, 0o755)
    return root


def start_egress_proxy(host: Host) -> None:
    """(Re)create the squid sidecar on the internal networks, then give it
    its other leg on the default bridge. Labelled with a hash of its config
    and image, so an edited allowlist is noticed (see egress_proxy_current)."""
    ensure_network(FILTER_NET, internal=True)
    squid = "/etc/squid"
    options = [
        mount_arg(f"{DOCKERFILE_DIR}/{ASK_HELPER}", f"{squid}/ask-helper", "ro,z"),
        # Written to by the proxy too: the hosts that wait for an answer
        mount_arg(asked_hosts_root(host), ASKED_HOSTS_MOUNT, "z"),
        mount_arg(f"{DOCKERFILE_DIR}/squid.conf", f"{squid}/squid.conf", "ro,z"),
        mount_arg(
            f"{DOCKERFILE_DIR}/allowed-domains.txt",
            f"{squid}/allowed-domains.txt",
            "ro,z",
        ),
        f"--volume={EGRESS_LOG_VOLUME}:{EGRESS_LOG_DIR}",
    ]
    start_shared_proxy(
        EGRESS_PROXY, FILTER_NET, egress_config_hash(), options, SQUID_IMAGE
    )
    docker_must("network", "connect", "bridge", EGRESS_PROXY)
    # The internal networks of the sessions with a socket proxy, those that
    # are there: sessions may be running on them
    for network in FILTER_NETS[1:]:
        docker_ok("network", "connect", network, EGRESS_PROXY)
    wait_for_egress_proxy()


def wait_for_egress_proxy(timeout: float = 15.0) -> None:
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


def egress_proxy_current() -> bool:
    """Running, and started from the config as it is on disk now. A stale
    proxy is replaced on the next filtered start, which briefly drops the
    connections of other filtered sessions."""
    return proxy_current(EGRESS_PROXY, egress_config_hash())


def rotate_access_log() -> None:
    """Rotate the proxy's log out once it is over the limit. Best effort,
    a session is not held up over its proxy's housekeeping."""
    over_limit = f'[ "$(stat -c %s {EGRESS_ACCESS_LOG})" -gt {EGRESS_LOG_LIMIT} ]'
    docker_ok("exec", EGRESS_PROXY, "sh", "-c", f"{over_limit} && squid -k rotate")
