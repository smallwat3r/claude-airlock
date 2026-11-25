"""The Docker socket proxy: the sidecar that holds the host's Docker
socket for the sessions that are given it, and lets through only what
their mode allows. One per mode, with networks of its own, so that a
session only shares a network with the proxy it was given."""

from __future__ import annotations

import os
import stat
from pathlib import Path

from ..docker import (
    docker_ok,
    env_arg,
    mount_arg,
)
from ..settings import DOCKERFILE_DIR, Settings, SocketAccess
from .networks import FILTER_NET, OPEN_NET, SOCKET_PROXIES
from .shared_proxy import config_hash, proxy_current, start_shared_proxy

# The image of the sidecar. It holds the host's Docker socket, so it is
# pinned by digest (the tag is informative only), refreshed by
# docker/update-pins.py.
PROXY_IMAGE = "tecnativa/docker-socket-proxy:latest@sha256:fd989c12c74edb8424f53f31a2054459f286967c93e113e91ea95432f066493b"
# The rules of each mode, in the directory of the Dockerfile parts: what
# of the Docker API a session of that mode is let through to
PROXY_RULES = {
    SocketAccess.LIMITED: "docker-socket-proxy.cfg",
    SocketAccess.FULL: "docker-socket-proxy-full.cfg",
}
# Where the host has its Docker socket
DOCKER_SOCK = "/var/run/docker.sock"


def network_name(settings: Settings) -> str:
    """The network of a session: by whether it is filtered, and by the
    socket proxy it is given, if any."""
    name = FILTER_NET if settings.net_filter else OPEN_NET
    if not has_socket_proxy(settings):
        return name
    return name + SOCKET_PROXIES[settings.docker_socket].net_suffix


def socket_proxy_name(settings: Settings) -> str:
    """One sidecar per socket mode, so sessions in different modes never
    share. The limited one has its own name on purpose: a full-access sidecar
    left running must not be picked up as the limited one."""
    full = settings.docker_socket is SocketAccess.FULL
    return SOCKET_PROXIES[SocketAccess.FULL if full else SocketAccess.LIMITED].name


def _is_socket(path: str) -> bool:
    try:
        return stat.S_ISSOCK(os.stat(path).st_mode)
    except OSError:
        return False


def has_socket_proxy(settings: Settings) -> bool:
    """Whether the session gets a socket proxy: asked for, and there is
    a Docker socket on the host."""
    return settings.docker_socket in SOCKET_PROXIES and _is_socket(DOCKER_SOCK)


def _rules_path(settings: Settings) -> str:
    """The HAProxy rules of the session's mode, for a session that has a
    socket proxy."""
    return f"{DOCKERFILE_DIR}/{PROXY_RULES[settings.docker_socket]}"


def _socket_proxy_options(settings: Settings) -> list[str]:
    """What the socket proxy of the session's mode is started with, for a
    session that has one, see has_socket_proxy. A write call to the host
    daemon (which runs as root) would let the session spawn a sibling that
    mounts the host filesystem, escaping the sandbox entirely, so writes
    are blocked in both modes, each by HAProxy rules of our own:
      CLAUDE_AIRLOCK_DOCKER_SOCKET=1
          docker ps and docker logs only (docker-socket-proxy.cfg)
      CLAUDE_AIRLOCK_DOCKER_SOCKET=full
          adds the real inspect, stats and top (docker-socket-proxy-full.cfg).
          inspect shows the environment of every container on the host,
          secrets included.
    The image renders the rules, a template to it, into its HAProxy
    config. None of its allow switches is passed, in either mode: its
    CONTAINERS allows every GET under /containers, where attach/ws writes
    to a container and archive and export read its files. And should a
    future image ignore the template, its stock rules would deny
    containers rather than open them up."""
    return [
        mount_arg(DOCKER_SOCK, "/var/run/docker.sock", "ro"),
        mount_arg(
            _rules_path(settings), "/usr/local/etc/haproxy/haproxy.cfg.template", "ro,z"
        ),
        # Among what the stock rules allow unless told: should they be
        # used after all, they do not
        env_arg("EVENTS", 0),
    ]


def start_socket_proxy(settings: Settings) -> None:
    """Start the Docker socket proxy of the session's mode as needed, and
    put it on the session's network, which is that of its mode alone.
    Opt-in, nothing without it. One started from other rules or another
    image is replaced, which ends the calls other sessions have open."""
    if not has_socket_proxy(settings):
        return
    options = _socket_proxy_options(settings)
    name = socket_proxy_name(settings)
    network = network_name(settings)
    rules = Path(_rules_path(settings)).read_bytes()
    config = config_hash(PROXY_IMAGE.encode(), rules, *map(str.encode, options))
    if not proxy_current(name, config):
        start_shared_proxy(name, network, config, options, PROXY_IMAGE)
    # A proxy started by a session of the other network mode (filtered or
    # open) sits on that one's network, attach it to ours too
    docker_ok("network", "connect", network, name)


def socket_proxy_args(settings: Settings) -> list[str]:
    """What points the session's docker CLI (the docker feature) at the
    socket proxy of start_socket_proxy, nothing without one."""
    if not has_socket_proxy(settings):
        return []
    return [
        env_arg("DOCKER_HOST", f"tcp://{socket_proxy_name(settings)}:2375"),
        # Shown by bin/claude-statusline
        env_arg("CLAUDE_AIRLOCK_DOCKER_SOCKET", settings.docker_socket.value),
    ]
