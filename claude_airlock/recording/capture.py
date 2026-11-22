"""Recording what a session connects to (CLAUDE_AIRLOCK_NET_LOG, on unless
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
where it went and how long it was is read. Each of the three kinds, the
TCP, the DNS and what is not TCP, is captured by a tcpdump of its own,
with its own file and its own packet limit: a session that floods one
cannot use up what the others have. The session joins that namespace,
so the capture is running before its first packet. It holds no capabilities
and is in another process namespace, so it can neither capture itself nor
see, stop or edit the capture, which stays in the sidecar until the
launcher copies it out."""

from __future__ import annotations

import subprocess
import tempfile
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar

from ..docker import container_running, docker, docker_bytes, docker_ok
from ..errors import Fatal
from ..sandbox.network import namespace_args
from ..settings import Host, Settings
from .pcap import HTTP_METHODS, Capture, read_capture
from .records import TracedSession
from .sidecar import Sidecar

CAPTURE_SUFFIX = ".capture"
CAPTURE_LABEL = "claude-airlock.capture"
CAPTURE_FILE = "/capture.pcap"
# tcpdump stops after this many packets, of at most SNAP_LENGTH bytes each,
# which bounds what a session can make the sidecar write. --trace says so
# when a capture ran into it. The limit is each part's own.
PACKET_LIMIT = 100_000
SNAP_LENGTH = 1024
# Captures are a few kB each as a rule, the oldest go once there are more
KEPT_CAPTURES = 100
# The embedded resolver of docker, in every container
RESOLVER_ADDRESS = "127.0.0.11"
# Where the TCP of the capture is told apart from the rest, for the filter.
# The filter's tcp[] is of IPv4 alone, over IPv6 the same is spelled by
# where things are in a packet without headers between the two. One with
# such headers is taken whole when the session sends it, see the reader.
_PAYLOAD = "((tcp[12:1] & 0xf0) >> 2)"
_PAYLOAD6 = "(40 + ((ip6[52:1] & 0xf0) >> 2))"
_TCP6 = "ip6[6:1] = 6"


@dataclass(frozen=True)
class Part:
    """One of the captures a session has, by what it takes: the file in the
    sidecar, the name its copy is given on the host (a suffix of the
    main one's, none for the main) and the filter of its tcpdump."""

    name: str
    file: str
    suffix: str
    filter: str


def _http_methods(load: str) -> str:
    """The part of the filter for a payload that starts with a method of
    HTTP, load being how its first four bytes are read."""
    return "".join(
        f" or {load} = {int.from_bytes(method.ljust(4).encode()[:4], 'big'):#x}"
        for method in HTTP_METHODS
    )


# No packet is in two parts: what is DNS by its port or by the resolver's
# address is the DNS part's alone, its TCP too. The reader would take a
# packet it is given twice for one sent twice.
_NOT_DNS = f"not port 53 and not host {RESOLVER_ADDRESS}"
TCP_FILTER = (
    f"{_NOT_DNS} and ("
    # What starts, answers or ends a connection, but for the session's
    # own within itself
    "(tcp[tcpflags] & (tcp-syn|tcp-fin|tcp-rst) != 0"
    " and not dst net 127.0.0.0/8)"
    f" or ({_TCP6} and ip6[53:1] & 0x07 != 0 and not dst host ::1)"
    # A TLS handshake record holding a client hello
    f" or (tcp[{_PAYLOAD}:1] = 0x16 and tcp[{_PAYLOAD} + 5:1] = 0x01)"
    # Last, a packet without that much payload ends the filter there
    + _http_methods(f"tcp[{_PAYLOAD}:4]")
    + f" or ({_TCP6} and ip6[{_PAYLOAD6}:1] = 0x16 and ip6[{_PAYLOAD6} + 5:1] = 0x01)"
    + f" or ({_TCP6} and ({_http_methods(f'ip6[{_PAYLOAD6}:4]')[4:]}))"
    + ")"
)
# The resolver at 127.0.0.11 is reached through a port rewrite inside the
# namespace, so its packets do not show port 53: all there is to and from
# its address is taken, and the reader tells what is DNS. Not the rest of
# loopback, which a session can fill with whatever it likes.
DNS_FILTER = f"port 53 or host {RESOLVER_ADDRESS}"
# Whatever the session sends that is not TCP: UDP, a ping, anything else
# over IP. There a connection has no start to pick out.
FLOWS_FILTER = (
    f"{_NOT_DNS} and ("
    "(outbound and ip and not tcp and not dst net 127.0.0.0/8)"
    f" or (outbound and ip6 and not {_TCP6} and not dst host ::1)"
    ")"
)
PARTS = (
    Part("tcp", CAPTURE_FILE, "", TCP_FILTER),
    Part("dns", "/dns.pcap", ".dns", DNS_FILTER),
    Part("flows", "/flows.pcap", ".flows", FLOWS_FILTER),
)
# What is added to the file of a part for the one it leaves its exit status
# in, when tcpdump ends before it is told to, see CAPTURE_SCRIPT
STATUS_SUFFIX = ".status"
# What the sidecar runs: a tcpdump for each part, with the filters it is
# given in the order of PARTS, then a look every second at whether each is
# still there, until it is told to stop. The sidecar owns the session's
# network namespace, and docker takes the session's way out with it when
# it ends, so it must not end with a tcpdump that stopped at its packet
# limit or died. A tcpdump that ends is noted by its status, in a file
# next to its own: 0 is its packet limit, any other that it died, which
# the record of the session says (see CaptureSidecar.noted). One that
# never got to write its file failed to start, which is said by ending
# with its status (see start_capture).
CAPTURE_SCRIPT = f"""common="-i any -p -n -U -Z root --immediate-mode -s {SNAP_LENGTH} -c {PACKET_LIMIT}"
tcpdump $common -w {PARTS[0].file} "$1" &
tcp=$!
tcpdump $common -w {PARTS[1].file} "$2" &
dns=$!
tcpdump $common -w {PARTS[2].file} "$3" &
flows=$!
trap 'kill "$tcp" "$dns" "$flows" 2>/dev/null; wait; exit 0' TERM INT
check() {{
  [ -e "$2{STATUS_SUFFIX}" ] && return
  # A process that ended stays in the table, as a zombie, until waited for
  state=
  read -r _ _ state _ 2>/dev/null <"/proc/$3/stat"
  case "$state" in Z|"") ;; *) return ;; esac
  wait "$3"
  status=$?
  echo "$status" >"$2{STATUS_SUFFIX}"
  [ -e "$2" ] || exit "$status"
}}
while :; do
  check tcp {PARTS[0].file} "$tcp"
  check dns {PARTS[1].file} "$dns"
  check flows {PARTS[2].file} "$flows"
  sleep 1 &
  wait $!
done"""


class CaptureSidecar(Sidecar):
    """The sidecar that owns the network namespace of one session and
    captures in it. Told to stop, it passes that on to tcpdump, which
    writes out what it holds when it is asked to."""

    SUFFIX: ClassVar[str] = CAPTURE_SUFFIX
    LABEL: ClassVar[str] = CAPTURE_LABEL
    RECORD: ClassVar[str] = "capture"
    FILE: ClassVar[str] = CAPTURE_FILE
    EXTENSION: ClassVar[str] = "pcap"
    KEPT: ClassVar[int] = KEPT_CAPTURES
    MEMORY: ClassVar[str] = "256m"
    # Raw sockets, and what the start-up change of user of tcpdump asks for
    CAPABILITIES: ClassVar[tuple[str, ...]] = ("NET_RAW", "SETUID", "SETGID")

    def directory(self, host: Host) -> str:
        return host.captures_dir

    def noted(self, file: str, end: float) -> TracedSession:
        return TracedSession(
            self.session,
            self.project,
            self.start,
            capture=file,
            end=end,
            stopped=self.stopped_early(),
        )

    def stopped_early(self) -> str:
        """What the sidecar says of a tcpdump that ended before it was
        told to, other than at its packet limit: empty when none did. The
        sidecar is stopped by now, and still there to be read from."""
        statuses = {}
        with tempfile.TemporaryDirectory() as directory:
            for part in PARTS:
                target = Path(directory, part.name)
                source = f"{self.name}:{part.file}{STATUS_SUFFIX}"
                if not docker_ok("cp", source, str(target)):
                    continue
                try:
                    statuses[part.name] = target.read_text()
                except OSError:
                    continue
        return died(statuses)

    def copy_out(self, directory: str) -> Path | None:
        """The main capture, and the others next to it under the same
        name, each with its suffix. What a part did not write is left out."""
        main = super().copy_out(directory)
        if main is None:
            return None
        for part in PARTS[1:]:
            target = main.with_suffix(main.suffix + part.suffix)
            if not docker_ok("cp", f"{self.name}:{part.file}", str(target)):
                target.unlink(missing_ok=True)
        return main

    def pruned(self, directory: Path) -> None:
        """Let go of the parts whose main capture is gone, and keep the
        others by the same count: they go with it, not on their own."""
        for part in PARTS[1:]:
            for file in directory.glob(f"*.{self.EXTENSION}{part.suffix}"):
                if not file.with_suffix("").exists():
                    file.unlink(missing_ok=True)


def died(statuses: dict[str, str]) -> str:
    """The parts whose tcpdump died, by the status each part that ended
    left, as it is said: empty when none did. 0 is a packet limit, which
    is not a death."""
    return ", ".join(
        f"{part.name} (status {statuses[part.name].strip()[:8]})"
        for part in PARTS
        if statuses.get(part.name, "0").strip() not in ("0", "")
    )


def died_so_far(sidecar: str) -> str:
    """The parts of the capture of a running session whose tcpdump has
    died, as died says them. Empty when none has, and when the sidecar
    cannot be asked."""
    files = {part.file + STATUS_SUFFIX: part.name for part in PARTS}
    # Each file that is there with what it holds, as file:status
    said = docker_bytes(
        "exec", sidecar, "sh", "-c", 'grep -Hs . "$@"; true', "sh", *files
    )
    statuses = {}
    for line in (said or b"").decode("ascii", "replace").splitlines():
        file, _, status = line.partition(":")
        if file in files:
            statuses[files[file]] = status
    return died(statuses)


def start_capture(
    settings: Settings, host: Host, session: str, image_tag: str
) -> CaptureSidecar:
    """Start the sidecar a session is about to join. It runs the sandbox
    image, which has tcpdump, as root with just what tcpdump needs: raw
    sockets, and the two capabilities its start-up change of user (to
    root, -Z, so that it can write its file) asks for. It outlives its
    tcpdump, see CAPTURE_SCRIPT."""
    sidecar = CaptureSidecar.for_session(session, host.project_dir)
    started = docker(
        "run",
        "--detach",
        "--init",
        *sidecar.run_args(),
        *namespace_args(settings),
        "--entrypoint=sh",
        image_tag,
        # The script, the name it goes by, then the filters of the parts.
        # Each packet is handed over as it comes (--immediate-mode): the
        # kernel holds them back for up to a second otherwise, and tcpdump
        # does not read what is held when it is told to stop, so the last
        # connections of a session would be missing.
        *("-c", CAPTURE_SCRIPT, "sh"),
        *(part.filter for part in PARTS),
        stdout=subprocess.DEVNULL,
    )
    # tcpdump fails at once when it fails, its sidecar then ends with it,
    # and the session could not start in the namespace of a sidecar that is
    # gone. The wait also gives it the moment it takes to listen, a session
    # is slower to start than that.
    time.sleep(0.3)
    if started.returncode != 0 or not container_running(sidecar.name):
        said = sidecar.last_said()
        sidecar.remove()
        raise Fatal(
            "the network capture did not start, CLAUDE_AIRLOCK_NET_LOG=0 runs"
            f" a session without it:\n{said}"
        )
    return sidecar


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
        sidecar.collect(host)


def cut_short(capture: Capture) -> bool:
    """Whether a capture ran into the packet limit of one of its parts,
    what came later of that kind is then missing."""
    return any(count >= PACKET_LIMIT for count in capture.part_packets.values())


def session_capture(host: Host, session: TracedSession) -> Capture | None:
    """The capture of a session, none when it has none or it is no
    longer kept."""
    if not session.capture:
        return None
    try:
        return read_parts(Path(host.captures_dir, session.capture))
    except OSError:
        return None


def read_parts(main: Path) -> Capture:
    """What a capture says, by its main file and the files of its other
    parts next to it. Raises OSError when the main one cannot be read."""
    others = [main.with_name(main.name + part.suffix) for part in PARTS[1:]]
    return read_capture(main, others)


def captured_since(sidecar: str, offset: int, file: str = CAPTURE_FILE) -> bytes | None:
    """What the capture of a running session holds past its first offset
    bytes of a file of the sidecar, the main capture unless told which,
    None when it cannot be read: the session ended, or its sidecar is not
    there. tcpdump writes every packet out as it comes (-U), so
    this is the capture up to now. Read by a command of its own each time,
    one left to follow the file would stay behind in the sidecar."""
    return docker_bytes("exec", sidecar, "tail", "-c", f"+{offset + 1}", file)
