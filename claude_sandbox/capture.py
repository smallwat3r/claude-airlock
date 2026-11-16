"""Recording what a session connects to (CLAUDE_DOCKER_NET_LOG, on unless
set to 0), and reading the capture of a running session for --trace
--follow. What a capture says is read by pcap.py.

The session's route out is left as it is, so nothing it could reach before
is cut off. A sidecar owns the session's network namespace instead and runs
tcpdump in it, on the few packets that say where a connection goes and how
it went: the start, the answer and the end of each TCP connection, the DNS
answers, the TLS hello with the server's name and the request of plain
HTTP. Never what is sent beyond those. The session joins that namespace,
so the capture is running before its first packet. It holds no capabilities
and is in another process namespace, so it can neither capture itself nor
see, stop or edit the capture, which stays in the sidecar until the
launcher copies it out."""

from __future__ import annotations

import json
import math
import subprocess
import sys
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

from .docker import (
    Launcher,
    docker,
    docker_bytes,
    docker_ok,
    docker_output,
    session_alive,
)
from .network import namespace_args, sidecar_running
from .pcap import HTTP_METHODS, Capture
from .records import NetSession, record_net_session
from .settings import Fatal, Host, Settings, private_dir

# A session's sidecar is named after it. Session names are stepped past
# the names in use (see container_name), a clash with a session of a project
# called x.capture is left to docker to refuse.
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
# IPv4 only, like Docker's networks unless set up otherwise. The embedded
# resolver at 127.0.0.11 is reached through a port rewrite inside the
# namespace, so its packets do not show port 53: all UDP on loopback is
# taken and the reader tells what is DNS.
# Where the payload of a TCP packet starts, for the filter
_PAYLOAD = "((tcp[12:1] & 0xf0) >> 2)"
PACKET_FILTER = (
    # What starts, answers or ends a connection, but for the session's
    # own within itself
    "(tcp[tcpflags] & (tcp-syn|tcp-fin|tcp-rst) != 0"
    " and not dst net 127.0.0.0/8)"
    " or (udp and net 127.0.0.0/8)"
    " or port 53"
    # A TLS handshake record holding a client hello
    f" or (tcp[{_PAYLOAD}:1] = 0x16 and tcp[{_PAYLOAD} + 5:1] = 0x01)"
    # Last, a packet without that much payload ends the filter there
    + "".join(
        f" or tcp[{_PAYLOAD}:4] = {int.from_bytes(method.ljust(4).encode()[:4], 'big'):#x}"
        for method in HTTP_METHODS
    )
)


def capture_name(session: str) -> str:
    return session + CAPTURE_SUFFIX


def session_name(sidecar: str) -> str:
    return sidecar[: -len(CAPTURE_SUFFIX)]


@dataclass(frozen=True)
class Sidecar:
    """A capture sidecar as its label tells of it: the project and the
    start of its session, and the launcher that started it. The label is
    the launcher's, a session cannot set its own."""

    name: str
    project: str
    start: float
    launcher: Launcher

    @property
    def session(self) -> str:
        return session_name(self.name)

    @property
    def label(self) -> str:
        about = {
            "project": self.project,
            "start": self.start,
            "pid": self.launcher.pid,
            "launched": self.launcher.started,
        }
        return json.dumps(about)

    @classmethod
    def from_label(cls, name: str, label: str) -> Sidecar | None:
        """The sidecar of a name and a label, none for a container that
        is not one."""
        try:
            about = json.loads(label)
            project, start = str(about["project"]), float(about["start"])
            # Not in the label of an earlier version
            launcher = Launcher(int(about["pid"]), str(about.get("launched", "")))
        except (ValueError, KeyError, TypeError, AttributeError, OverflowError):
            return None
        if not name.endswith(CAPTURE_SUFFIX) or not math.isfinite(start):
            return None
        return cls(name, project, start, launcher)


def sidecars(ended_too: bool = False) -> list[Sidecar]:
    """The capture sidecars that are running, of every project, with
    those that have stopped when asked for."""
    listed = docker_output(
        "ps",
        *(["--all"] if ended_too else []),
        f"--filter=label={CAPTURE_LABEL}",
        f'--format={{{{.Names}}}}\t{{{{.Label "{CAPTURE_LABEL}"}}}}',
    )
    found = []
    for line in listed.splitlines():
        name, _, label = line.partition("\t")
        sidecar = Sidecar.from_label(name, label)
        if sidecar:
            found.append(sidecar)
    return found


def start_capture(
    settings: Settings, host: Host, session: str, image_tag: str
) -> Sidecar:
    """Start the sidecar a session is about to join. It runs the sandbox
    image, which has tcpdump, as root with just what tcpdump needs: raw
    sockets, and the two capabilities its start-up change of user (to
    root, -Z, so that it can write its file) asks for."""
    sidecar = Sidecar(
        capture_name(session), host.project_dir, time.time(), Launcher.current()
    )
    started = docker(
        "run",
        "--detach",
        "--init",
        f"--name={sidecar.name}",
        *namespace_args(settings),
        f"--label={CAPTURE_LABEL}={sidecar.label}",
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
        docker_ok("rm", "--force", sidecar.name)
        raise Fatal(
            "the network capture did not start, CLAUDE_DOCKER_NET_LOG=0 runs"
            f" a session without it:\n{said.stdout.strip()}"
        )
    return sidecar


def collect_capture(host: Host, sidecar: Sidecar) -> None:
    """Stop a sidecar, copy its capture to the host and note which project
    and time it covers, for --trace to find it by."""
    # tcpdump writes out what it holds when it is asked to stop
    docker_ok("stop", sidecar.name)
    try:
        directory = Path(private_dir(host.captures_dir))
        target = directory / f"{sidecar.name}-{int(sidecar.start)}.pcap"
        if docker_ok("cp", f"{sidecar.name}:{CAPTURE_FILE}", str(target)):
            session = NetSession(
                sidecar.session,
                sidecar.project,
                sidecar.start,
                capture=target.name,
                end=time.time(),
            )
            record_net_session(host, session)
        kept = sorted(directory.glob("*.pcap"), key=lambda file: file.stat().st_mtime)
        for old in kept[:-KEPT_CAPTURES]:
            old.unlink(missing_ok=True)
    except OSError as problem:
        # Said and passed over: this runs as a session ends, and what is
        # left to do then (the check of tamper.py) matters more
        print(f"claude-docker: the capture was not kept: {problem}", file=sys.stderr)
    finally:
        docker_ok("rm", "--force", sidecar.name)


def collect_ended_captures(host: Host) -> None:
    """Collect what sessions that ended without their launcher left behind
    (a killed Emacs buffer, a closed terminal): their sidecar is still
    there, capture included."""
    for sidecar in sidecars(ended_too=True):
        if not session_alive(sidecar.launcher, sidecar.session):
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
        for sidecar in sidecars()
        if sidecar.project == project_dir
    ]


def captured_since(sidecar: str, offset: int) -> bytes | None:
    """What the capture of a running session holds past its first offset
    bytes, None when it cannot be read: the session ended, or its sidecar
    is not there. tcpdump writes every packet out as it comes (-U), so
    this is the capture up to now. Read by a command of its own each time,
    one left to follow the file would stay behind in the sidecar."""
    return docker_bytes("exec", sidecar, "tail", "-c", f"+{offset + 1}", CAPTURE_FILE)
