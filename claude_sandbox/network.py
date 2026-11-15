"""The session's network and the two sidecars: the egress filter and the
Docker socket proxy."""

from __future__ import annotations

import hashlib
import os
import stat
import subprocess
from collections import Counter
from pathlib import Path

from .docker import docker, docker_must, docker_ok, docker_output, env_arg, mount_arg
from .settings import DOCKERFILE_DIR, Fatal, Settings

# Sidecar images. They hold the host Docker socket and the egress path, so
# they are pinned by digest (the tag is informative only), refreshed by
# docker/update-pins.py.
PROXY_IMAGE = "tecnativa/docker-socket-proxy:latest@sha256:1f5038b54f06c3e18422902cf00ba21803d1c97805aae032e5e6673d532d3459"
SQUID_IMAGE = "ubuntu/squid:latest@sha256:6a097f68bae708cedbabd6188d68c7e2e7a38cedd05a176e1cc0ba29e3bbe029"
EGRESS_PROXY = "claude-egress-proxy"
EGRESS_CONFIG_LABEL = "claude-sandbox.config"
# Filtered mode joins an internal network with no route out, open mode a
# plain bridge network. Both are user-defined so container names resolve.
FILTER_NET = "claude-docker-net"
OPEN_NET = "claude-docker-open-net"
DOCKER_SOCK = "/var/run/docker.sock"


def network_name(settings: Settings) -> str:
    return FILTER_NET if settings.net_filter else OPEN_NET


def socket_proxy_name(settings: Settings) -> str:
    """One sidecar per socket mode, so sessions in different modes never
    share. The limited one has its own name on purpose: a full-access sidecar
    left running must not be picked up as the limited one."""
    if settings.socket == "full":
        return "claude-docker-proxy"
    return "claude-docker-ps-proxy"


def ensure_network(name: str, *create_options: str) -> None:
    if not docker_ok("network", "inspect", name):
        docker_must("network", "create", *create_options, name)


def sidecar_running(name: str) -> bool:
    state = docker_output("container", "inspect", "--format={{.State.Running}}", name)
    return "true" in state


def start_sidecar(name: str, network: str, options: list[str], image: str) -> None:
    """(Re)create a sidecar on a network."""
    docker_ok("rm", "--force", name)
    docker_must(
        "run",
        "--detach",
        f"--name={name}",
        f"--network={network}",
        "--restart=unless-stopped",
        *options,
        image,
    )


def egress_config_hash() -> str:
    config = b"".join(
        Path(DOCKERFILE_DIR, name).read_bytes()
        for name in ("squid.conf", "allowed-domains.txt")
    )
    return hashlib.sha256(config).hexdigest()[:16]


def start_egress_proxy() -> None:
    """(Re)create the squid sidecar on the internal network, then give it
    its second leg on the default bridge. Labelled with a hash of its config,
    so an edited allowlist is noticed (see egress_proxy_current)."""
    ensure_network(FILTER_NET, "--internal")
    squid = "/etc/squid"
    options = [
        f"--label={EGRESS_CONFIG_LABEL}={egress_config_hash()}",
        mount_arg(f"{DOCKERFILE_DIR}/squid.conf", f"{squid}/squid.conf", "ro,z"),
        mount_arg(
            f"{DOCKERFILE_DIR}/allowed-domains.txt",
            f"{squid}/allowed-domains.txt",
            "ro,z",
        ),
    ]
    start_sidecar(EGRESS_PROXY, FILTER_NET, options, SQUID_IMAGE)
    docker_must("network", "connect", "bridge", EGRESS_PROXY)


def egress_proxy_current() -> bool:
    """Running, and started from the config as it is on disk now. A stale
    proxy is replaced on the next filtered start, which briefly drops the
    connections of other filtered sessions."""
    if not sidecar_running(EGRESS_PROXY):
        return False
    label = docker_output(
        "container",
        "inspect",
        f'--format={{{{index .Config.Labels "{EGRESS_CONFIG_LABEL}"}}}}',
        EGRESS_PROXY,
    )
    return label.strip() == egress_config_hash()


def net_log() -> int:
    """Print the domains the egress filter refused, most frequent first. The
    quickest way to find what a project needs added to allowed-domains.txt."""
    if not sidecar_running(EGRESS_PROXY):
        raise Fatal(
            "the egress proxy is not running "
            "(start a CLAUDE_DOCKER_NET_FILTER=1 session first)"
        )
    log = docker(
        "exec", EGRESS_PROXY, "cat", "/var/log/squid/access.log", stdout=subprocess.PIPE
    )
    if log.returncode != 0:
        return log.returncode
    # Squid's native log: field 4 is the result code, field 7 the URL
    entries = (line.split() for line in log.stdout.splitlines())
    denied = Counter(f[6] for f in entries if len(f) >= 7 and "DENIED" in f[3])
    for url, count in sorted(denied.items(), key=lambda item: (-item[1], item[0])):
        print(f"{count:7d} {url}")
    return 0


def network_args(settings: Settings) -> list[str]:
    """Network: open egress by default. In filtered mode the container joins
    an internal network with no route out, where egress goes through a squid
    sidecar (dual-homed on the internal net and the default bridge) that only
    allows domains listed in docker/allowed-domains.txt.
    Filtering is by the host named in the CONNECT request, so it survives CDN
    IP churn. Creates the network and starts the sidecar as needed."""
    network = network_name(settings)
    ensure_network(network)
    if not settings.net_filter:
        return [f"--network={network}"]

    if not egress_proxy_current():
        start_egress_proxy()
    proxy = f"{EGRESS_PROXY}:3128"
    no_proxy = f"localhost,127.0.0.1,{socket_proxy_name(settings)}"
    return [
        f"--network={network}",
        # Blackhole external DNS: the proxy resolves hostnames (CONNECT
        # carries the name as a string), and squid only looks up domains
        # that pass the allowlist, so the container needs no external DNS.
        # Docker's embedded DNS still answers container names itself and
        # only forwards unknown names upstream, 127.0.0.1 dies on the host,
        # so exfiltration via DNS lookups never leaves the machine.
        "--dns=127.0.0.1",
        env_arg("HTTP_PROXY", f"http://{proxy}"),
        env_arg("http_proxy", f"http://{proxy}"),
        env_arg("HTTPS_PROXY", f"http://{proxy}"),
        env_arg("https_proxy", f"http://{proxy}"),
        env_arg("NO_PROXY", no_proxy),
        env_arg("no_proxy", no_proxy),
        # Direct port 22 is blocked on the internal net, so tunnel
        # git-over-SSH through the proxy as a CONNECT to :22
        env_arg(
            "GIT_SSH_COMMAND",
            f'ssh -o ProxyCommand="nc -X connect -x {proxy} %h %p"',
        ),
    ]


def is_socket(path: str) -> bool:
    try:
        return stat.S_ISSOCK(os.stat(path).st_mode)
    except OSError:
        return False


def socket_proxy_args(settings: Settings) -> list[str]:
    """Docker socket proxy, opt-in (and the docker feature for the CLI). A
    write call to the host daemon (which runs as root) would let this
    container spawn a sibling that mounts the host filesystem, escaping the
    sandbox entirely, so writes are blocked in both modes:
      CLAUDE_DOCKER_SOCKET=1     docker ps and docker logs only, through our
                                 own HAProxy rules (docker-socket-proxy.cfg)
      CLAUDE_DOCKER_SOCKET=full  every read under /containers, which adds
                                 inspect, stats and top. inspect shows the
                                 environment of every container on the host,
                                 secrets included.
    Starts the sidecar as needed."""
    if settings.socket == "1":
        # The image renders this template into its HAProxy config. No allow
        # switches are passed, so if a future image ignored the template, its
        # stock rules would deny containers rather than open them up.
        mode_options = [
            mount_arg(
                f"{DOCKERFILE_DIR}/docker-socket-proxy.cfg",
                "/usr/local/etc/haproxy/haproxy.cfg.template",
                "ro,z",
            ),
            env_arg("EVENTS", 0),
        ]
    elif settings.socket == "full":
        allowed = ("CONTAINERS", "LOG", "INFO")
        blocked = (
            *("EXEC", "POST", "IMAGES", "NETWORKS", "VOLUMES"),
            *("SERVICES", "TASKS", "BUILD", "COMMIT", "SWARM"),
        )
        mode_options = [env_arg(name, 1) for name in allowed]
        mode_options += [env_arg(name, 0) for name in blocked]
    else:
        return []
    if not is_socket(DOCKER_SOCK):
        return []

    name = socket_proxy_name(settings)
    network = network_name(settings)
    if not sidecar_running(name):
        socket_mount = mount_arg(DOCKER_SOCK, "/var/run/docker.sock", "ro")
        start_sidecar(name, network, [socket_mount, *mode_options], PROXY_IMAGE)
    # A proxy left over from a previous run may sit on another network
    # (e.g. after toggling CLAUDE_DOCKER_NET_FILTER), attach it to ours
    docker_ok("network", "connect", network, name)
    return [
        env_arg("DOCKER_HOST", f"tcp://{name}:2375"),
        # Shown by bin/claude-statusline
        env_arg("CLAUDE_DOCKER_SOCKET", settings.socket),
    ]
