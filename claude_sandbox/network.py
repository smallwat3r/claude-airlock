"""The session's network and the two sidecars: the egress filter and the
Docker socket proxy."""

from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import stat
import subprocess
import sys
import threading
import time
from collections import Counter
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from .docker import docker, docker_must, docker_ok, docker_output, env_arg, mount_arg
from .settings import DOCKERFILE_DIR, Fatal, Host, Settings, private_dir

# Sidecar images. They hold the host Docker socket and the egress path, so
# they are pinned by digest (the tag is informative only), refreshed by
# docker/update-pins.py.
PROXY_IMAGE = "tecnativa/docker-socket-proxy:latest@sha256:1f5038b54f06c3e18422902cf00ba21803d1c97805aae032e5e6673d532d3459"
SQUID_IMAGE = "ubuntu/squid:latest@sha256:6a097f68bae708cedbabd6188d68c7e2e7a38cedd05a176e1cc0ba29e3bbe029"
EGRESS_PROXY = "claude-egress-proxy"
EGRESS_PORT = 3128
EGRESS_CONFIG_LABEL = "claude-sandbox.config"
# The proxy's log is kept in a volume, so it outlives the proxy's container,
# as the current file and the one before it (logfile_rotate in squid.conf).
# The current one is rotated out once it is over the limit, which bounds the
# volume at about twice that. Squid only rotates when told to, the launcher
# does so when a filtered session starts: one very long session can
# overshoot, a cron in the sidecar would be the fix if that ever matters.
EGRESS_LOG_VOLUME = "claude-egress-log"
EGRESS_LOG_DIR = "/var/log/squid"
EGRESS_LOG_LIMIT = 10 * 1024 * 1024
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
        f"--volume={EGRESS_LOG_VOLUME}:{EGRESS_LOG_DIR}",
    ]
    start_sidecar(EGRESS_PROXY, FILTER_NET, options, SQUID_IMAGE)
    docker_must("network", "connect", "bridge", EGRESS_PROXY)
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
    print(
        "claude-docker: the egress proxy is slow to start,"
        " the session's first requests may fail",
        file=sys.stderr,
    )


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


def access_log(stderr: int | None = None) -> str | None:
    """The egress proxy's log, the rotated file then the current one, None
    when it cannot be read. Read through the proxy's container, the volume
    it is in is not reachable from the host otherwise."""
    current = f"{EGRESS_LOG_DIR}/access.log"
    log = docker(
        "exec",
        EGRESS_PROXY,
        "sh",
        "-c",
        f"cat {current}.0 2>/dev/null; cat {current}",
        stdout=subprocess.PIPE,
        stderr=stderr,
    )
    return log.stdout if log.returncode == 0 else None


def rotate_access_log() -> None:
    """Rotate the proxy's log out once it is over the limit. Best effort,
    a session is not held up over its proxy's housekeeping."""
    over_limit = (
        f'[ "$(stat -c %s {EGRESS_LOG_DIR}/access.log)" -gt {EGRESS_LOG_LIMIT} ]'
    )
    docker_ok("exec", EGRESS_PROXY, "sh", "-c", f"{over_limit} && squid -k rotate")


def session_address(name: str) -> str:
    """The container's address on its network, empty until it has one."""
    addresses = "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}"
    found = docker_output("container", "inspect", f"--format={addresses}", name)
    try:
        return str(ipaddress.ip_address(found.split()[0]))
    except (IndexError, ValueError):
        return ""


def record_net_session(host: Host, session: dict) -> None:
    """Add a line to the launcher's record of sessions whose network use
    can be traced: the name and project of each, when it started, and its
    address on the filtered network or the file of its capture."""
    private_dir(host.state_dir)
    with open(host.net_sessions_file, "a", encoding="utf-8") as sessions:
        sessions.write(json.dumps(session) + "\n")


def record_address(
    name: str, owner: str, host: Host, started: float, stop: threading.Event
) -> None:
    while True:
        address = session_address(owner)
        if address:
            session = {
                "name": name,
                "project": host.project_dir,
                "ip": address,
                "start": started,
            }
            record_net_session(host, session)
            return
        if stop.wait(0.2):
            return


@contextmanager
def session_address_recorded(
    settings: Settings, host: Host, name: str, owner: str
) -> Iterator[None]:
    """While a filtered session runs, note the address it was given. The
    proxy logs each request with the address it came from, which a
    container without capabilities cannot forge, so this is what lets
    --trace tell the sessions in the shared log apart. The address is only
    known once the container is up, by when the launcher is waiting on it,
    hence the thread. owner is the container the address belongs to: the
    session, or its capture sidecar."""
    if not settings.net_filter:
        yield
        return
    stop = threading.Event()
    recorder = threading.Thread(
        target=record_address,
        args=(name, owner, host, time.time(), stop),
        daemon=True,
    )
    recorder.start()
    try:
        yield
    finally:
        stop.set()
        recorder.join()


def net_log() -> int:
    """Print the domains the egress filter refused, most frequent first. The
    quickest way to find what a project needs added to allowed-domains.txt."""
    if not sidecar_running(EGRESS_PROXY):
        raise Fatal(
            "the egress proxy is not running "
            "(start a CLAUDE_DOCKER_NET_FILTER=1 session first)"
        )
    log = access_log()
    if log is None:
        return 1
    # Squid's native log: field 4 is the result code, field 7 the URL
    entries = (line.split() for line in log.splitlines())
    denied = Counter(f[6] for f in entries if len(f) >= 7 and "DENIED" in f[3])
    for url, count in sorted(denied.items(), key=lambda item: (-item[1], item[0])):
        print(f"{count:7d} {url}")
    return 0


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


def network_args(settings: Settings, capture: str = "") -> list[str]:
    """Network: open egress by default, in the network namespace of the
    capture sidecar when one is named (see capture.py). In filtered mode
    the container joins
    an internal network with no route out, where egress goes through a squid
    sidecar (dual-homed on the internal net and the default bridge) that only
    allows domains listed in docker/allowed-domains.txt.
    Filtering is by the host named in the CONNECT request, so it survives CDN
    IP churn. Creates the network and starts the sidecar as needed."""
    ensure_network(network_name(settings))
    namespace = (
        [f"--network=container:{capture}"] if capture else namespace_args(settings)
    )
    if not settings.net_filter:
        return namespace

    if not egress_proxy_current():
        start_egress_proxy()
    rotate_access_log()
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
