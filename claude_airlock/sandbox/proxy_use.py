"""Which sessions use the proxies they share, so that a proxy is removed
with the last of them: the socket proxy holds the host's Docker socket,
which is not left open for no one.

A launcher says that a session of its uses a proxy by a lock it holds, and
what is done to the proxies and their networks is done by one launcher at
a time (see sidecars_locked)."""

from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager

from ..docker import (
    docker_ok,
    running_containers,
)
from ..files import locked, private_dir, try_lock_file
from ..settings import Host, Settings
from .networks import EGRESS_PROXY, PROXY_NETWORKS, network_state
from .socket_proxy import has_socket_proxy, socket_proxy_name


@contextmanager
def sidecars_locked(host: Host) -> Iterator[None]:
    """One launcher at a time for what is done to the networks and the
    proxies, which the sessions of every project share: two that start
    together would each remove and start the same proxy, and one of them
    fail."""
    with locked(os.path.join(private_dir(host.state_dir), "sidecars.lock")):
        yield


def session_proxies(settings: Settings) -> list[str]:
    """The proxies a session with these settings goes through."""
    proxies = [EGRESS_PROXY] if settings.net_filter else []
    if has_socket_proxy(settings):
        proxies.append(socket_proxy_name(settings))
    return proxies


def proxy_use_file(host: Host, proxy: str) -> str:
    """The file a launcher holds a lock on for as long as a session of its
    uses a proxy, shared with the launchers of the other sessions that
    do."""
    directory = private_dir(os.path.join(host.state_dir, "proxies"))
    return os.path.join(directory, proxy)


def _proxy_in_use(host: Host, proxy: str) -> bool:
    """Whether a session uses a proxy: a launcher says so (it is starting
    one, whose container is not there yet, or has one running), or a
    session is on one of the proxy's networks, which one that outlived
    its launcher still is."""
    alone = try_lock_file(proxy_use_file(host, proxy))
    if alone is None:
        return True
    os.close(alone)
    states = (network_state(network) for network in PROXY_NETWORKS[proxy])
    return any(state.sessions for state in states if state)


def remove_idle_proxies(host: Host) -> None:
    """Remove each proxy that no session uses any more, whichever session
    started it: one left behind by a launcher that was killed too. To be
    called by the one launcher that may (see sidecars_locked)."""
    for proxy in sorted(running_containers().intersection(PROXY_NETWORKS)):
        if not _proxy_in_use(host, proxy):
            docker_ok("rm", "--force", proxy)
