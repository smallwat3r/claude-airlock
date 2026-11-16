"""The session's network and the two sidecars: the egress filter and the
Docker socket proxy."""

from __future__ import annotations

import hashlib
import ipaddress
import os
import stat
import subprocess
import sys
import threading
import time
from collections import Counter
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from .background import in_background
from .docker import (
    container_label,
    docker,
    docker_bytes,
    docker_must,
    docker_ok,
    docker_output,
    env_arg,
    mount_arg,
)
from .records import NetSession, record_net_session
from .settings import DOCKERFILE_DIR, EGRESS_PORT, Fatal, Host, Settings

# Sidecar images. They hold the host Docker socket and the egress path, so
# they are pinned by digest (the tag is informative only), refreshed by
# docker/update-pins.py.
PROXY_IMAGE = "tecnativa/docker-socket-proxy:latest@sha256:1f5038b54f06c3e18422902cf00ba21803d1c97805aae032e5e6673d532d3459"
SQUID_IMAGE = "ubuntu/squid:latest@sha256:6a097f68bae708cedbabd6188d68c7e2e7a38cedd05a176e1cc0ba29e3bbe029"
EGRESS_PROXY = "claude-egress-proxy"
# A hash of what a proxy sidecar was started from, so one started from
# something else (an edited rule, another image) is noticed and replaced
SIDECAR_CONFIG_LABEL = "claude-sandbox.config"
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
# Each of the two is one network per socket mode, so that a session only
# shares a network with the socket proxy it was given: on a network, every
# container reaches every other by name.
FILTER_NET = "claude-docker-net"
OPEN_NET = "claude-docker-open-net"
SOCKET_NET_SUFFIXES = {"1": "-ps", "full": "-full"}
FILTER_NETS = (FILTER_NET, *(FILTER_NET + s for s in SOCKET_NET_SUFFIXES.values()))
SOCKET_PROXIES = {"1": "claude-docker-ps-proxy", "full": "claude-docker-proxy"}
DOCKER_SOCK = "/var/run/docker.sock"


def network_name(settings: Settings) -> str:
    """The network of a session: by whether it is filtered, and by the
    socket proxy it is given, if any."""
    name = FILTER_NET if settings.net_filter else OPEN_NET
    if socket_proxy_options(settings) is None:
        return name
    return name + SOCKET_NET_SUFFIXES[settings.socket]


def socket_proxy_name(settings: Settings) -> str:
    """One sidecar per socket mode, so sessions in different modes never
    share. The limited one has its own name on purpose: a full-access sidecar
    left running must not be picked up as the limited one."""
    return SOCKET_PROXIES["full" if settings.socket == "full" else "1"]


def network_state(name: str) -> tuple[bool, set[str]] | None:
    """Whether a network is internal and the containers on it, none for
    one that is not there."""
    said = docker_output(
        "network",
        "inspect",
        "--format={{.Internal}} {{range .Containers}}{{.Name}} {{end}}",
        name,
    ).split()
    return (said[0] == "true", set(said[1:])) if said else None


def ensure_network(name: str, internal: bool = False) -> set[str]:
    """Create a network as needed, and give the containers on it. One
    that is there is checked to be what was asked for: a filtered session
    on a network with a route out would not be filtered."""
    state = network_state(name)
    if state is None:
        created = docker_ok(
            "network", "create", *(["--internal"] if internal else []), name
        )
        # Another launcher may have been first
        state = network_state(name)
        if state is None and not created:
            raise Fatal(f"claude-docker: the docker network {name} was not created")
        if state is None:
            return set()
    if state[0] != internal:
        raise Fatal(
            f"the docker network {name} is {'not ' if internal else ''}internal,"
            f" which it has to be. Remove it once no session is on it, the"
            f" next one makes it anew: docker network rm {name}"
        )
    return state[1]


def sidecar_running(name: str) -> bool:
    state = docker_output("container", "inspect", "--format={{.State.Running}}", name)
    return "true" in state


def sidecar_current(name: str, config: str) -> bool:
    """Running, and started from the config of that hash."""
    if not sidecar_running(name):
        return False
    return container_label(name, SIDECAR_CONFIG_LABEL) == config


def start_sidecar(
    name: str, network: str, config: str, options: list[str], image: str
) -> None:
    """(Re)create a sidecar on a network, labelled with the hash of what
    it is started from."""
    docker_ok("rm", "--force", name)
    docker_must(
        "run",
        "--detach",
        f"--name={name}",
        f"--network={network}",
        "--restart=unless-stopped",
        f"--label={SIDECAR_CONFIG_LABEL}={config}",
        *options,
        image,
    )


def config_hash(*parts: bytes) -> str:
    digest = hashlib.sha256()
    for part in parts:
        digest.update(len(part).to_bytes(8, "big") + part)
    return digest.hexdigest()[:16]


def egress_config_hash() -> str:
    files = (
        Path(DOCKERFILE_DIR, name).read_bytes()
        for name in ("squid.conf", "allowed-domains.txt")
    )
    return config_hash(SQUID_IMAGE.encode(), *files)


def start_egress_proxy() -> None:
    """(Re)create the squid sidecar on the internal networks, then give it
    its other leg on the default bridge. Labelled with a hash of its config
    and image, so an edited allowlist is noticed (see egress_proxy_current)."""
    ensure_network(FILTER_NET, internal=True)
    squid = "/etc/squid"
    options = [
        mount_arg(f"{DOCKERFILE_DIR}/squid.conf", f"{squid}/squid.conf", "ro,z"),
        mount_arg(
            f"{DOCKERFILE_DIR}/allowed-domains.txt",
            f"{squid}/allowed-domains.txt",
            "ro,z",
        ),
        f"--volume={EGRESS_LOG_VOLUME}:{EGRESS_LOG_DIR}",
    ]
    start_sidecar(EGRESS_PROXY, FILTER_NET, egress_config_hash(), options, SQUID_IMAGE)
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
    print(
        "claude-docker: the egress proxy is slow to start,"
        " the session's first requests may fail",
        file=sys.stderr,
    )


def egress_proxy_current() -> bool:
    """Running, and started from the config as it is on disk now. A stale
    proxy is replaced on the next filtered start, which briefly drops the
    connections of other filtered sessions."""
    return sidecar_current(EGRESS_PROXY, egress_config_hash())


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


def record_address(
    name: str, owner: str, host: Host, started: float, stop: threading.Event
) -> None:
    while True:
        address = session_address(owner)
        if address:
            session = NetSession(name, host.project_dir, started, ip=address)
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
    with in_background(record_address, name, owner, host, time.time()):
        yield


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
    if not sidecar_running(EGRESS_PROXY):
        raise Fatal(
            "the egress proxy is not running "
            "(start a CLAUDE_DOCKER_NET_FILTER=1 session first)"
        )
    requests = logged_requests()
    if requests is None:
        return 1
    denied = Counter(request.url for request in requests if request.denied)
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


def prepare_network(settings: Settings) -> None:
    """Create the session's network as needed, and in filtered mode start
    the egress proxy, or replace one started from another config."""
    network = network_name(settings)
    on_it = ensure_network(network, internal=settings.net_filter)
    # Only the socket proxy of the session's mode belongs there. Another
    # is from before each mode had its network, and would be a way to the
    # Docker socket the session was not given.
    given = socket_proxy_options(settings) is not None
    mine = socket_proxy_name(settings) if given else ""
    for stray in on_it.intersection(SOCKET_PROXIES.values()) - {mine}:
        docker_ok("network", "disconnect", "--force", network, stray)
    if not settings.net_filter:
        return
    if not egress_proxy_current():
        start_egress_proxy()
    if network != FILTER_NET:
        # Made since the proxy started, already joined otherwise
        docker_ok("network", "connect", network, EGRESS_PROXY)
    rotate_access_log()


def network_args(settings: Settings, capture: str = "") -> list[str]:
    """Network: open egress by default, in the network namespace of the
    capture sidecar when one is named (see capture.py). In filtered mode
    the container joins an internal network with no route out, where
    egress goes through a squid sidecar (dual-homed on the internal net and
    the default bridge) that only allows domains listed in
    docker/allowed-domains.txt. Filtering is by the host named in the
    CONNECT request, so it survives CDN IP churn. The network and the
    sidecar are those of prepare_network."""
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


def socket_proxy_options(settings: Settings) -> list[str] | None:
    """What the socket proxy of the session's mode is started with, None
    when the session gets none: not asked for, or no Docker socket on the
    host. A write call to the host daemon (which runs as root) would let
    the session spawn a sibling that mounts the host filesystem, escaping
    the sandbox entirely, so writes are blocked in both modes:
      CLAUDE_DOCKER_SOCKET=1     docker ps and docker logs only, through our
                                 own HAProxy rules (docker-socket-proxy.cfg)
      CLAUDE_DOCKER_SOCKET=full  every read under /containers, which adds
                                 inspect, stats and top. inspect shows the
                                 environment of every container on the host,
                                 secrets included."""
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
        return None
    if not is_socket(DOCKER_SOCK):
        return None
    return [mount_arg(DOCKER_SOCK, "/var/run/docker.sock", "ro"), *mode_options]


def start_socket_proxy(settings: Settings) -> None:
    """Start the Docker socket proxy of the session's mode as needed, and
    put it on the session's network, which is that of its mode alone.
    Opt-in, nothing without it. One started from other rules or another
    image is replaced, which ends the calls other sessions have open."""
    options = socket_proxy_options(settings)
    if options is None:
        return
    name = socket_proxy_name(settings)
    network = network_name(settings)
    rules = Path(DOCKERFILE_DIR, "docker-socket-proxy.cfg").read_bytes()
    config = config_hash(PROXY_IMAGE.encode(), rules, *map(str.encode, options))
    if not sidecar_current(name, config):
        start_sidecar(name, network, config, options, PROXY_IMAGE)
    # A proxy started by a session of the other network mode (filtered or
    # open) sits on that one's network, attach it to ours too
    docker_ok("network", "connect", network, name)


def socket_proxy_args(settings: Settings) -> list[str]:
    """What points the session's docker CLI (the docker feature) at the
    socket proxy of start_socket_proxy, nothing without one."""
    if socket_proxy_options(settings) is None:
        return []
    return [
        env_arg("DOCKER_HOST", f"tcp://{socket_proxy_name(settings)}:2375"),
        # Shown by bin/claude-statusline
        env_arg("CLAUDE_DOCKER_SOCKET", settings.socket),
    ]
