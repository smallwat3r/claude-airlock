"""Recording what a session connects to (CLAUDE_AIRLOCK_NET_LOG, on unless
set to 0), and reading the capture of a running session for --trace
--follow. What a capture says is read by pcap.py.

The session's route out is left as it is, so nothing it could reach before
is cut off. A sidecar owns the session's network namespace instead and runs
tcpdump in it, on the few packets that say where a connection goes and how
it went: the start, the answer and the end of each TCP connection, the DNS
answers, the TLS hello with the server's name and the request of plain
HTTP. Of TCP never what is sent beyond those, but for a packet of every
gigabyte a connection carries, for how much went over it to be counted
(see SAMPLED). Of anything else the session sends (UDP, a ping) every
packet, there is no telling the first of a conversation from the rest:
the start of each is in the file, and only where it went and how long it
was is read. Each of the kinds, the TCP, what docker's resolver is asked
and says, what goes to port 53 anywhere else and what is not TCP, is
captured by a tcpdump of its own, with its own file and its own packet
limit: a session that floods one cannot use up what the others have,
whatever it sends to port 53 leaves the lookups it has the resolver make
recorded. The session joins that namespace,
so the capture is running before its first packet. It holds no capabilities
and is in another process namespace, so it can neither capture itself nor
see, stop or edit the capture, which stays in the sidecar until the
launcher copies it out."""

from __future__ import annotations

import re
import subprocess
import tempfile
import time
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar

from ..docker import container_running, docker, docker_bytes, docker_ok
from ..errors import Fatal
from ..sandbox.network import namespace_args
from ..settings import Host, Settings
from .packets import RESOLVER
from .payloads import HTTP_METHODS
from .pcap import Capture, read_capture
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
# Where the TCP of the capture is told apart from the rest, for the filter.
# The filter's tcp[] is of IPv4 alone, over IPv6 the same is spelled by
# where things are in a packet without headers between the two. One with
# such headers is taken whole when the session sends it, see the reader.
_PAYLOAD = "((tcp[12:1] & 0xf0) >> 2)"
_PAYLOAD6 = "(40 + ((ip6[52:1] & 0xf0) >> 2))"
_TCP6 = "ip6[6:1] = 6"
# What starts, answers or ends a connection, over IPv4 and over IPv6
_ENDS = "tcp[tcpflags] & (tcp-syn|tcp-fin|tcp-rst) != 0"
_ENDS6 = f"({_TCP6} and ip6[53:1] & 0x07 != 0)"
# How much a connection carried is counted from its sequence numbers,
# which start over every four gigabytes (see Stream of pcap.py): the first
# and the last alone would have a long upload read as a short one. So a
# packet that carries something is taken when its number is in the first
# 64 kB of a gigabyte, the two top bits aside: at least one each time a
# connection gets there, a packet holds no more than that, and of most
# connections none. By the two bytes of the number that say so, then by
# what is left of the packet's length once its headers are taken off. Not
# of the session's own within itself, as of what starts a connection.
SAMPLED_BITS = 0x3FFF
_SAMPLED = (
    f"(tcp[4:2] & {SAMPLED_BITS:#x} = 0"
    f" and ip[2:2] - ((ip[0:1] & 0x0f) << 2) - {_PAYLOAD} != 0"
    " and not dst net 127.0.0.0/8)"
)
_SAMPLED6 = (
    f"({_TCP6} and ip6[44:2] & {SAMPLED_BITS:#x} = 0"
    " and ip6[4:2] - ((ip6[52:1] & 0xf0) >> 2) != 0 and not dst host ::1)"
)


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


# No packet is in two parts: what goes to and from the resolver's address
# is the resolver part's alone. Of port 53 anywhere else, what starts and
# ends a connection is the TCP part's, as of any port, and the rest the
# part's of what is asked there directly. The reader would take a packet
# it is given twice for one sent twice.
_NOT_RESOLVER = f"not host {RESOLVER}"
_NOT_DNS = f"not port 53 and {_NOT_RESOLVER}"
TCP_FILTER = (
    f"{_NOT_RESOLVER} and ("
    # What starts, answers or ends a connection, but for the session's
    # own within itself
    f"({_ENDS} and not dst net 127.0.0.0/8)"
    f" or ({_ENDS6} and not dst host ::1)"
    " or (not port 53 and ("
    # A packet of every gigabyte, see SAMPLED_BITS
    f"{_SAMPLED} or {_SAMPLED6}"
    # A TLS handshake record holding a client hello
    f" or (tcp[{_PAYLOAD}:1] = 0x16 and tcp[{_PAYLOAD} + 5:1] = 0x01)"
    # Last, a packet without that much payload ends the filter there
    + _http_methods(f"tcp[{_PAYLOAD}:4]")
    + f" or ({_TCP6} and ip6[{_PAYLOAD6}:1] = 0x16 and ip6[{_PAYLOAD6} + 5:1] = 0x01)"
    + f" or ({_TCP6} and ({_http_methods(f'ip6[{_PAYLOAD6}:4]')[4:]}))"
    + ")))"
)
# The resolver at 127.0.0.11 is reached through a port rewrite inside the
# namespace, so its packets do not show port 53: all there is to and from
# its address is taken, and the reader tells what is DNS. Not the rest of
# loopback, which a session can fill with whatever it likes. Nor port 53
# anywhere else, see DIRECT_FILTER: what a session sends there is its own
# to make a lot of, and is not to use up what the lookups it has the
# resolver make are recorded with.
DNS_FILTER = f"host {RESOLVER}"
# What goes to and from port 53 anywhere but at the resolver: a server
# asked directly, over UDP or over TCP, or whatever else a session sends
# there. All of it but what starts and ends a connection, which the TCP
# part has: when this one is at its limit, the connections to port 53 are
# still recorded.
DIRECT_FILTER = f"port 53 and {_NOT_RESOLVER} and not ({_ENDS}) and not {_ENDS6}"
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
    Part("direct", "/direct.pcap", ".direct", DIRECT_FILTER),
    Part("flows", "/flows.pcap", ".flows", FLOWS_FILTER),
)
# What is added to the file of a part for the one it leaves its exit status
# in, when tcpdump ends before it is told to, see CAPTURE_SCRIPT
STATUS_SUFFIX = ".status"
# What a tcpdump says when it ends of the packets it was to take and did
# not get: they came faster than it took them, the kernel had no room left
# to hold them for it. A session can send that fast, and what the dropped
# ones told of, a connection it made meanwhile, is then in no part. Not
# by the line: the tcpdumps end together and write a line in pieces, the
# one of another can come before its end. Among the last lines of the
# sidecar's output, each tcpdump says a few when it starts and ends.
_DROPPED = re.compile(r"(?<!\d)(\d{1,15}) packets? dropped by kernel")
SAID_LINES = 100
# What the sidecar runs: a tcpdump for each part, with the filters it is
# given in the order of PARTS, then a look every second at whether each is
# still there, until it is told to stop. The sidecar owns the session's
# network namespace, and docker takes the session's way out with it when
# it ends, so it must not end with a tcpdump that stopped at its packet
# limit or died. A tcpdump that ends is noted by its status, in a file
# next to its own: 0 is its packet limit, any other that it died, which
# the record of the session says (see CaptureSidecar.noted). One that
# never got to write its file failed to start, which is said by ending
# with its status (see _start_capture).
_COMMON = f"-i any -p -n -U -Z root --immediate-mode -s {SNAP_LENGTH} -c {PACKET_LIMIT}"
_STARTED = "\n".join(
    f'tcpdump $common -w {part.file} "${number}" &\n{part.name}=$!'
    for number, part in enumerate(PARTS, 1)
)
_STOPPED = " ".join(f'"${part.name}"' for part in PARTS)
_CHECKED = "\n".join(
    f'  check {part.name} {part.file} "${part.name}"' for part in PARTS
)
CAPTURE_SCRIPT = f"""common="{_COMMON}"
{_STARTED}
trap 'kill {_STOPPED} 2>/dev/null; wait; exit 0' TERM INT
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
{_CHECKED}
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
            dropped=dropped_packets(self.last_said(SAID_LINES)),
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
        return _died(statuses)

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

    def last_wrote(self, copied: Path) -> float:
        """By the part that was written to last: each has the packets of
        its kind as they came, the last of the session in any of them."""
        latest = super().last_wrote(copied)
        for part in PARTS[1:]:
            with suppress(OSError):
                other = copied.with_name(copied.name + part.suffix)
                latest = max(latest, super().last_wrote(other))
        return latest

    def pruned(self, directory: Path) -> None:
        """Let go of the parts whose main capture is gone, and keep the
        others by the same count: they go with it, not on their own."""
        for part in PARTS[1:]:
            for file in directory.glob(f"*.{self.EXTENSION}{part.suffix}"):
                if not file.with_suffix("").exists():
                    file.unlink(missing_ok=True)


def dropped_packets(said: str) -> int:
    """How many packets were dropped before a tcpdump took them, by what
    the sidecar wrote to its output: each tcpdump says how many of its
    own as it ends. None when they did not get to say."""
    return sum(int(count) for count in _DROPPED.findall(said))


def _died(statuses: dict[str, str]) -> str:
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
    died, as _died says them. Empty when none has, and when the sidecar
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
    return _died(statuses)


def _start_capture(
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
    sidecar = _start_capture(settings, host, session, image_tag)
    try:
        yield
    finally:
        sidecar.collect(host)


def parts_cut_short(capture: Capture) -> list[str]:
    """The parts of a capture that ran into their packet limit, by their
    names: what came later of that kind is missing, of the others not."""
    return [
        part.name
        for part in PARTS
        if capture.part_packets.get(part.name, 0) >= PACKET_LIMIT
    ]


def cut_short(capture: Capture) -> bool:
    """Whether a capture ran into the packet limit of one of its parts,
    what came later of that kind is then missing."""
    return bool(parts_cut_short(capture))


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
