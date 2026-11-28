"""The docker networks the sessions are on, and which proxy is on which:
one network that is open, one that is internal with no route out for the
filtered sessions, and of each one more per mode of the Docker socket
proxy. Made as needed and shared by the sessions of every project."""

from __future__ import annotations

import ipaddress
from contextlib import suppress
from dataclasses import dataclass

from ..docker import (
    docker_ok,
    docker_output,
)
from ..errors import Fatal
from ..notice import warn
from ..settings import SocketAccess

# The container of the egress filter, by its name on the filtered networks
EGRESS_PROXY = "claude-egress-proxy"
# Filtered mode joins an internal network with no route out, open mode a
# plain bridge network. Both are user-defined so container names resolve.
# Each of the two is one network per socket mode, so that a session only
# shares a network with the socket proxy it was given: on a network, every
# container reaches every other by name.
FILTER_NET = "claude-airlock-net"
OPEN_NET = "claude-airlock-open-net"


@dataclass(frozen=True)
class SocketProxy:
    """The socket proxy of a mode: the name of its container, and what
    the names of the networks of its sessions end in."""

    name: str
    net_suffix: str

    @property
    def networks(self) -> tuple[str, str]:
        """The networks it can be on, the open one and the filtered."""
        return (OPEN_NET + self.net_suffix, FILTER_NET + self.net_suffix)


SOCKET_PROXIES = {
    SocketAccess.LIMITED: SocketProxy("claude-airlock-ps-proxy", "-ps"),
    SocketAccess.FULL: SocketProxy("claude-airlock-proxy", "-full"),
}
SOCKET_PROXY_NAMES = frozenset(proxy.name for proxy in SOCKET_PROXIES.values())
FILTER_NETS = (FILTER_NET, *(proxy.networks[1] for proxy in SOCKET_PROXIES.values()))
# The networks each proxy can be on, by its name: where a session that uses
# it would be found
PROXY_NETWORKS = {
    EGRESS_PROXY: FILTER_NETS,
    **{proxy.name: proxy.networks for proxy in SOCKET_PROXIES.values()},
}
# An internal network has no route out, but docker still gives its bridge
# an address on it, the gateway, which is the host: whatever the host
# listens on everywhere is reached through it, around the filter. In this
# mode (Docker 28 and later) the bridge is given none.
GATEWAY_MODES = (
    "com.docker.network.bridge.gateway_mode_ipv4",
    "com.docker.network.bridge.gateway_mode_ipv6",
)
ISOLATED = "isolated"
ISOLATED_SINCE = 28


@dataclass(frozen=True)
class NetworkState:
    """A network as docker has it: whether it is internal, whether the
    host is kept off it (see GATEWAY_MODES), and the containers on it."""

    internal: bool
    isolated: bool
    containers: frozenset[str]

    @property
    def sessions(self) -> frozenset[str]:
        """The containers on it that are not a proxy: the sessions, each
        by the container that owns its network namespace."""
        return self.containers - PROXY_NETWORKS.keys()


def network_state(name: str) -> NetworkState | None:
    """A network as docker has it, none for one that is not there."""
    mode = f'{{{{index .Options "{GATEWAY_MODES[0]}"}}}}'
    said = docker_output(
        "network",
        "inspect",
        # The mode with a mark, it is empty on a network without one. No
        # name of a container holds the mark.
        f"--format={{{{.Internal}}}} mode={mode}"
        " {{range .Containers}}{{.Name}} {{end}}",
        name,
    ).split()
    if not said:
        return None
    containers = frozenset(word for word in said[1:] if not word.startswith("mode="))
    return NetworkState(said[0] == "true", f"mode={ISOLATED}" in said, containers)


def _create_network(name: str, internal: bool) -> bool:
    """Create a network, an internal one with the host kept off it where
    docker can (see GATEWAY_MODES), as it is without where it cannot."""
    if not internal:
        return docker_ok("network", "create", name)
    isolated = [f"--opt={mode}={ISOLATED}" for mode in GATEWAY_MODES]
    return docker_ok("network", "create", "--internal", *isolated, name) or docker_ok(
        "network", "create", "--internal", name
    )


def _can_isolate() -> bool:
    """Whether the docker daemon can keep the host off a network."""
    version = docker_output("version", "--format={{.Server.Version}}")
    major = version.strip().split(".")[0]
    return major.isdigit() and int(major) >= ISOLATED_SINCE


def _isolate_network(name: str, state: NetworkState) -> NetworkState:
    """Make an internal network from before the host was kept off it anew,
    once no session is on it: docker sets this when a network is made. With
    a session on it, it is left as it is and that is said, and so it is
    without a word where docker cannot do this. The proxies on it are put
    back by those who start them."""
    if not _can_isolate():
        return state
    if state.sessions:
        warn(
            f"the docker network {name} lets a session reach what"
            " the host listens on. It is made anew, without that, by the first"
            " session started once none is on it.",
        )
        return state
    for proxy in state.containers:
        docker_ok("network", "disconnect", "--force", name, proxy)
    if docker_ok("network", "rm", name) and not _create_network(name, True):
        raise Fatal(f"the docker network {name} was not created")
    return network_state(name) or state


def ensure_network(name: str, internal: bool = False) -> set[str]:
    """Create a network as needed, and give the containers on it. One
    that is there is checked to be what was asked for: a filtered session
    on a network with a route out would not be filtered."""
    state = network_state(name)
    if state is None:
        created = _create_network(name, internal)
        # Another launcher may have been first
        state = network_state(name)
        if state is None and not created:
            raise Fatal(f"the docker network {name} was not created")
        if state is None:
            return set()
        return set(state.containers)
    if state.internal != internal:
        raise Fatal(
            f"the docker network {name} is {'not ' if internal else ''}internal,"
            f" which it has to be. Remove it once no session is on it, the"
            f" next one makes it anew: docker network rm {name}"
        )
    if internal and not state.isolated:
        state = _isolate_network(name, state)
    return set(state.containers)


def session_addresses(name: str) -> tuple[str, ...]:
    """Every address docker gave the container on its networks, none
    until it has one: the one of IPv4, and the one of IPv6 on a daemon
    that gives its networks both. A session asks a proxy from whichever
    of them it likes, and what it asked is told by the address it came
    from: known by the first alone, what it asked from the other would be
    nobody's."""
    addresses = (
        "{{range .NetworkSettings.Networks}}"
        "{{.IPAddress}} {{.GlobalIPv6Address}} {{end}}"
    )
    said = docker_output("container", "inspect", f"--format={addresses}", name)
    found: dict[str, None] = {}
    for address in said.split():
        with suppress(ValueError):
            found[str(ipaddress.ip_address(address))] = None
    return tuple(found)
