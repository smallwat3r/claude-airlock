"""The network of a session, and what it goes through for as long as it
lasts: the egress filter in filtered mode, the Docker socket proxy when it
is given one.

The docker networks are those of networks.py, the two proxies those of
egress_proxy.py and socket_proxy.py. They are shared by every session, of
every project: who still uses a proxy is kept by proxy_use.py, and what is
done to them is done by one launcher at a time (see sidecars_locked
there)."""

from __future__ import annotations

import os
from collections.abc import Iterator
from contextlib import contextmanager

from ..docker import (
    docker_ok,
    env_arg,
)
from ..errors import Fatal
from ..files import lock_file
from ..settings import EGRESS_PORT, Host, Settings
from .egress_proxy import egress_proxy_current, rotate_access_log, start_egress_proxy
from .networks import EGRESS_PROXY, SOCKET_PROXY_NAMES, ensure_network
from .proxy_use import (
    proxy_use_file,
    remove_idle_proxies,
    session_proxies,
    sidecars_locked,
)
from .socket_proxy import (
    has_socket_proxy,
    network_name,
    socket_proxy_name,
    start_socket_proxy,
)


def namespace_args(settings: Settings) -> list[str]:
    """What sets up a session's network namespace, given to the container
    that owns it: the session, or its capture sidecar (see capture.py)."""
    network = f"--network={network_name(settings)}"
    if not settings.net_filter:
        return [network]
    # Blackhole external DNS: the proxy resolves hostnames (CONNECT
    # carries the name as a string), and squid only looks up domains
    # that pass the allowlist, so the container needs no external DNS.
    # Docker's embedded DNS still answers container names itself and
    # only forwards unknown names upstream, 127.0.0.1 dies on the host,
    # so exfiltration via DNS lookups never leaves the machine.
    return [network, "--dns=127.0.0.1"]


def _prepare_network(settings: Settings, host: Host) -> None:
    """Create the session's network as needed, and in filtered mode start
    the egress proxy, or replace one started from another config."""
    network = network_name(settings)
    on_it = ensure_network(network, internal=settings.net_filter)
    # Only the socket proxy of the session's mode belongs there. Another
    # is from before each mode had its network, and would be a way to the
    # Docker socket the session was not given.
    mine = socket_proxy_name(settings) if has_socket_proxy(settings) else ""
    for stray in on_it.intersection(SOCKET_PROXY_NAMES) - {mine}:
        docker_ok("network", "disconnect", "--force", network, stray)
    if not settings.net_filter:
        return
    if not egress_proxy_current():
        start_egress_proxy(host)
    # Not yet when the network was made since the proxy started, or made
    # anew (see _isolate_network). Refused when it has joined already.
    docker_ok("network", "connect", network, EGRESS_PROXY)
    rotate_access_log()


@contextmanager
def session_network(settings: Settings, host: Host) -> Iterator[None]:
    """For as long as a session lasts: its network, made as needed, and
    the proxies it goes through, started as needed and said to be in use.
    When it is over, the proxies no session uses any more are removed."""
    with sidecars_locked(host):
        _prepare_network(settings, host)
        start_socket_proxy(settings)
        uses = [
            lock_file(proxy_use_file(host, proxy), shared=True)
            for proxy in session_proxies(settings)
        ]
    try:
        yield
    finally:
        for use in uses:
            os.close(use)
        try:
            with sidecars_locked(host):
                remove_idle_proxies(host)
        except (OSError, Fatal):
            # Left for the next session to remove
            pass


def network_args(
    settings: Settings, capture: str = "", asked: bool = False
) -> list[str]:
    """Network: open egress by default, in the network namespace of the
    capture sidecar when one is named (see capture.py). In filtered mode
    the container joins an internal network with no route out, where
    egress goes through a squid sidecar (dual-homed on the internal net and
    the default bridge) that only allows domains listed in
    docker/allowed-domains.txt. Filtering is by the host named in the
    CONNECT request, so it survives CDN IP churn. The network and the
    sidecar are those of _prepare_network. asked says whether the user is
    asked about a host that is not listed, which the session is then
    told: only where there is a place to ask, see hosts_asked. Told all
    the same, a session would wait for an answer nobody is asked for."""
    namespace = (
        [f"--network=container:{capture}"] if capture else namespace_args(settings)
    )
    if not settings.net_filter:
        return namespace

    proxy = f"{EGRESS_PROXY}:{EGRESS_PORT}"
    no_proxy = f"localhost,127.0.0.1,{socket_proxy_name(settings)}"
    return [
        *namespace,
        env_arg("HTTP_PROXY", f"http://{proxy}"),
        env_arg("http_proxy", f"http://{proxy}"),
        env_arg("HTTPS_PROXY", f"http://{proxy}"),
        env_arg("https_proxy", f"http://{proxy}"),
        env_arg("NO_PROXY", no_proxy),
        env_arg("no_proxy", no_proxy),
        # Told to the session, see docker/CLAUDE-airlock.md
        *([env_arg("CLAUDE_AIRLOCK_NET_ASK", 1)] if settings.net_ask and asked else []),
        # Direct port 22 is blocked on the internal net, so tunnel
        # git-over-SSH through the proxy as a CONNECT to :22
        env_arg(
            "GIT_SSH_COMMAND",
            f'ssh -o ProxyCommand="nc -X connect -x {proxy} %h %p"',
        ),
    ]
