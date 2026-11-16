"""Recording what a session connects to (CLAUDE_DOCKER_NET_LOG, on unless
set to 0), and reading the capture of a running session for --trace
--follow. What a capture says is read by pcap.py.

The session's route out is left as it is, so nothing it could reach before
is cut off. A sidecar owns the session's network namespace instead and runs
tcpdump in it, on the few packets that say where a connection goes and how
it went: the start, the answer and the end of each TCP connection, the DNS
answers, the TLS hello with the server's name and the request of plain
HTTP. Of TCP never what is sent beyond those. Of anything else the session
sends (UDP, a ping) every packet, there is no telling the first of a
conversation from the rest: the start of each is in the file, and only
where it went and how long it was is read. The session joins that namespace,
so the capture is running before its first packet. It holds no capabilities
and is in another process namespace, so it can neither capture itself nor
see, stop or edit the capture, which stays in the sidecar until the
launcher copies it out."""

from __future__ import annotations

import subprocess
import sys
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path
from typing import ClassVar

from .docker import docker, docker_bytes, docker_ok
from .network import namespace_args, sidecar_running
from .pcap import HTTP_METHODS, Capture
from .records import NetSession, record_net_session
from .settings import Fatal, Host, Settings
from .sidecar import Sidecar, keep_latest

CAPTURE_SUFFIX = ".capture"
CAPTURE_LABEL = "claude-sandbox.capture"
CAPTURE_FILE = "/capture.pcap"
# tcpdump stops after this many packets, of at most SNAP_LENGTH bytes each,
# which bounds what a session can make the sidecar write. --trace says so
# when a capture ran into it.
PACKET_LIMIT = 100_000
SNAP_LENGTH = 1024
# Captures are a few kB each as a rule, the oldest go once there are more
KEPT_CAPTURES = 100
# The embedded resolver at 127.0.0.11 is reached through a port rewrite
# inside the namespace, so its packets do not show port 53: all UDP on
# loopback is taken and the reader tells what is DNS.
# Where the payload of a TCP packet starts, for the filter. The filter's
# tcp[] is of IPv4 alone, over IPv6 the same is spelled by where things
# are in a packet without headers between the two. One with such headers
# is taken whole when the session sends it, see the reader.
_PAYLOAD = "((tcp[12:1] & 0xf0) >> 2)"
_PAYLOAD6 = "(40 + ((ip6[52:1] & 0xf0) >> 2))"
_TCP6 = "ip6[6:1] = 6"


def _http_methods(load: str) -> str:
    """The part of the filter for a payload that starts with a method of
    HTTP, load being how its first four bytes are read."""
    return "".join(
        f" or {load} = {int.from_bytes(method.ljust(4).encode()[:4], 'big'):#x}"
        for method in HTTP_METHODS
    )


PACKET_FILTER = (
    # What starts, answers or ends a connection, but for the session's
    # own within itself
    "(tcp[tcpflags] & (tcp-syn|tcp-fin|tcp-rst) != 0"
    " and not dst net 127.0.0.0/8)"
    f" or ({_TCP6} and ip6[53:1] & 0x07 != 0 and not dst host ::1)"
    " or (udp and net 127.0.0.0/8)"
    " or port 53"
    # Whatever the session sends that is not TCP: UDP, a ping, anything
    # else over IP. There a connection has no start to pick out.
    " or (outbound and ip and not tcp and not dst net 127.0.0.0/8)"
    f" or (outbound and ip6 and not {_TCP6} and not dst host ::1)"
    # A TLS handshake record holding a client hello
    f" or (tcp[{_PAYLOAD}:1] = 0x16 and tcp[{_PAYLOAD} + 5:1] = 0x01)"
    # Last, a packet without that much payload ends the filter there
    + _http_methods(f"tcp[{_PAYLOAD}:4]")
    + f" or ({_TCP6} and ip6[{_PAYLOAD6}:1] = 0x16 and ip6[{_PAYLOAD6} + 5:1] = 0x01)"
    + f" or ({_TCP6} and ({_http_methods(f'ip6[{_PAYLOAD6}:4]')[4:]}))"
)


class CaptureSidecar(Sidecar):
    """The sidecar that owns the network namespace of one session and
    captures in it."""

    SUFFIX: ClassVar[str] = CAPTURE_SUFFIX
    LABEL: ClassVar[str] = CAPTURE_LABEL


def start_capture(
    settings: Settings, host: Host, session: str, image_tag: str
) -> CaptureSidecar:
    """Start the sidecar a session is about to join. It runs the sandbox
    image, which has tcpdump, as root with just what tcpdump needs: raw
    sockets, and the two capabilities its start-up change of user (to
    root, -Z, so that it can write its file) asks for."""
    sidecar = CaptureSidecar.for_session(session, host.project_dir)
    started = docker(
        "run",
        "--detach",
        "--init",
        f"--name={sidecar.name}",
        *namespace_args(settings),
        sidecar.label_arg,
        "--user=0:0",
        "--cap-drop=ALL",
        "--cap-add=NET_RAW",
        "--cap-add=SETUID",
        "--cap-add=SETGID",
        "--security-opt=no-new-privileges",
        "--memory=256m",
        "--pids-limit=16",
        "--entrypoint=tcpdump",
        image_tag,
        *("-i", "any", "-p", "-n", "-U", "-Z", "root"),
        *("-s", str(SNAP_LENGTH), "-c", str(PACKET_LIMIT)),
        *("-w", CAPTURE_FILE, PACKET_FILTER),
        stdout=subprocess.DEVNULL,
    )
    # tcpdump fails at once when it fails, and the session could not start
    # in the namespace of a sidecar that is gone. The wait also gives it the
    # moment it takes to listen, a session is slower to start than that.
    time.sleep(0.3)
    if started.returncode != 0 or not sidecar_running(sidecar.name):
        said = docker(
            "logs", sidecar.name, stdout=subprocess.PIPE, stderr=subprocess.STDOUT
        )
        sidecar.remove()
        raise Fatal(
            "the network capture did not start, CLAUDE_DOCKER_NET_LOG=0 runs"
            f" a session without it:\n{said.stdout.strip()}"
        )
    return sidecar


def collect_capture(host: Host, sidecar: CaptureSidecar) -> None:
    """Stop a sidecar, copy its capture to the host and note which project
    and time it covers, for --trace to find it by."""
    # tcpdump writes out what it holds when it is asked to stop
    docker_ok("stop", sidecar.name)
    try:
        target = sidecar.copy_out(CAPTURE_FILE, host.captures_dir, "pcap")
        if target:
            session = NetSession(
                sidecar.session,
                sidecar.project,
                sidecar.start,
                capture=target.name,
                end=time.time(),
            )
            record_net_session(host, session)
        keep_latest(Path(host.captures_dir), "*.pcap", KEPT_CAPTURES)
    except OSError as problem:
        # Said and passed over: this runs as a session ends, and what is
        # left to do then (the check of tamper.py) matters more
        print(f"claude-docker: the capture was not kept: {problem}", file=sys.stderr)
    finally:
        sidecar.remove()


def collect_ended_captures(host: Host) -> None:
    """Collect what sessions that ended without their launcher left
    behind: their sidecar is still there, capture included."""
    for sidecar in CaptureSidecar.left_behind():
        collect_capture(host, sidecar)


@contextmanager
def session_captured(
    settings: Settings, host: Host, session: str, image_tag: str
) -> Iterator[None]:
    if not settings.net_log:
        yield
        return
    sidecar = start_capture(settings, host, session, image_tag)
    try:
        yield
    finally:
        collect_capture(host, sidecar)


def cut_short(capture: Capture) -> bool:
    """Whether a capture ran into its packet limit, what came later is
    then missing."""
    return capture.packets >= PACKET_LIMIT


def running_captures(project_dir: str) -> list[tuple[str, float]]:
    """The sidecars of the sessions of a project that are running now, as
    the name of each and when it started."""
    return [
        (sidecar.name, sidecar.start)
        for sidecar in CaptureSidecar.listed()
        if sidecar.project == project_dir
    ]


def captured_since(sidecar: str, offset: int) -> bytes | None:
    """What the capture of a running session holds past its first offset
    bytes, None when it cannot be read: the session ended, or its sidecar
    is not there. tcpdump writes every packet out as it comes (-U), so
    this is the capture up to now. Read by a command of its own each time,
    one left to follow the file would stay behind in the sidecar."""
    return docker_bytes("exec", sidecar, "tail", "-c", f"+{offset + 1}", CAPTURE_FILE)
