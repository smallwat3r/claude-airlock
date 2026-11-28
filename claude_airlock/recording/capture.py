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
recorded. Two parts more have the headers of what the session sends over
TCP, and nothing of what that carries: one of what goes to the model's
API, one of what goes anywhere else. When each thing was sent, how long it
was and over which connection is told by them, a request to the model as
a push to a repository (see uploads.py). And two the headers of some of
what comes in: of all that the model's API sends back, for when each
answer began and how long it was, and of one packet of every 16 MB a
connection brings in from anywhere else, for how far a download has got
while it still runs (see answers.py). The session joins that namespace,
so the capture is running before its first packet. It holds no capabilities
and is in another process namespace, so it can neither capture itself nor
see, stop or edit the capture, which stays in the sidecar until the
launcher copies it out."""

from __future__ import annotations

import re
import subprocess
import tempfile
import time
from collections.abc import Iterator, Mapping
from contextlib import contextmanager, suppress
from dataclasses import dataclass
from pathlib import Path
from typing import ClassVar

from ..docker import container_running, docker, docker_bytes, docker_ok
from ..errors import Fatal
from ..sandbox.network import namespace_args
from ..settings import Host, Settings
from .answers import ANSWERS_PART, DOWNLOADS_PART
from .model_api import MODEL_API
from .packets import RESOLVER
from .payloads import HTTP_METHODS, TLS_CLIENT_HELLO, TLS_HANDSHAKE, TLS_MAJOR
from .pcap import Capture, read_capture
from .records import TracedSession
from .sidecar import Sidecar
from .uploads import ELSEWHERE_PART, UPLOADS_PART

CAPTURE_SUFFIX = "capture"
CAPTURE_LABEL = "claude-airlock.capture"
CAPTURE_FILE = "/capture.pcap"
# tcpdump stops after this many packets, of at most SNAP_LENGTH bytes each,
# which bounds what a session can make the sidecar write. --trace says so
# when a capture ran into it. The limit is each part's own.
PACKET_LIMIT = 100_000
SNAP_LENGTH = 1024
# Of the packets that start a connection, and with them its hello of TLS,
# the whole of one as a link of 1500 bytes carries it. A browser shuffles
# the parts of its hello and sends keys of more than a kilobyte, the name
# of the server is then past SNAP_LENGTH as often as not, and its hello
# would read as one that could not be read
HELLO_SNAP_LENGTH = 2048
# Of a packet taken for when it was sent and how long it was alone: its
# headers, with the options IP and TCP can have. Where those are shorter,
# as they are as a rule, the rest is the start of what it carries: some
# 90 bytes, of which the reader looks at the first of a connection alone,
# for what is spoken on it (see Capture.sent_too of pcap.py)
HEADERS_LENGTH = 160
# Of a packet taken for where it is in what its connection brings in: its
# headers as far as the numbers of TCP, whatever the options of IP
SEQUENCE_LENGTH = 96
# The model sends what it makes back in many small packets: the part that
# has them takes more than the others before it stops
ANSWERS_LIMIT = 200_000
# Captures are a few kB each as a rule, and some hundred with the headers
# of what a session sent: the oldest go once there are more
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
# A packet of TCP that carries something: what is left of its length
# once its headers are taken off
_CARRIED = f"ip[2:2] - ((ip[0:1] & 0x0f) << 2) - {_PAYLOAD}"
_CARRIED6 = "ip6[4:2] - ((ip6[52:1] & 0xf0) >> 2)"
_CARRIES = f"{_CARRIED} != 0"
_CARRIES6 = f"{_CARRIED6} != 0"
_SAMPLED = (
    f"(tcp[4:2] & {SAMPLED_BITS:#x} = 0 and {_CARRIES} and not dst net 127.0.0.0/8)"
)
_SAMPLED6 = (
    f"({_TCP6} and ip6[44:2] & {SAMPLED_BITS:#x} = 0"
    f" and {_CARRIES6} and not dst host ::1)"
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
    # How much of each packet is kept, that of the others when 0
    snap: int = 0
    # How many packets it stops after, as many as the others when 0
    limit: int = 0

    @property
    def most(self) -> int:
        """The packets it takes before it stops."""
        return self.limit or PACKET_LIMIT

    @property
    def started(self) -> str:
        """What starts its tcpdump in the script of the sidecar, given
        its filter as the argument of that number. A length or a limit
        of its own comes after that of the others, and is the one that
        counts."""
        number = PARTS.index(self) + 1
        own = f" -s {self.snap}" if self.snap else ""
        own += f" -c {self.limit}" if self.limit else ""
        return f'tcpdump $common{own} -w {self.file} "${number}" &\n{self.name}=$!'


def _http_methods(load: str) -> str:
    """The part of the filter for a payload that starts with a method of
    HTTP, load being how its first four bytes are read."""
    return "".join(
        f" or {load} = {int.from_bytes(method.ljust(4).encode()[:4], 'big'):#x}"
        for method in HTTP_METHODS
    )


# No packet is in two parts: what goes to and from the resolver's address
# is the resolver part's alone. Of port 53 anywhere else, what starts and
# ends a connection and carries nothing is the TCP part's, as of any port,
# and the rest the part's of what is asked there directly: a message over
# TCP comes in as many packets as its sender likes, and is read from them
# in their turn, the last too when it ends the connection. The reader
# would take a packet it is given twice for one sent twice.
_NOT_RESOLVER = f"not host {RESOLVER}"
_NOT_DNS = f"not port 53 and {_NOT_RESOLVER}"
_DNS_CARRIED = f"port 53 and ((ip and {_CARRIES}) or ({_TCP6} and {_CARRIES6}))"


def _hello_starts(header: str, payload: str, carried: str) -> str:
    """The part of the filter for a packet that starts a hello of TLS, by
    the header its payload is read through, where in that the payload
    starts and how long it is: a record of the handshake that holds the
    start of a client hello. Or one that has its first bytes alone, of
    a client that sends them a few at a time: the five of a record's
    header, or the start of a client hello without one, with the length
    of a hello and the version of TLS after it. A packet with fewer bytes
    than a part reads ends the filter there, those that read further
    come later."""

    def at(place: int) -> str:
        return f"{header}[{payload}{f' + {place}' if place else ''}:1]"

    record, major, hello = (
        f"{byte:#04x}" for byte in (TLS_HANDSHAKE, TLS_MAJOR, TLS_CLIENT_HELLO)
    )
    return (
        f"({carried} = 5 and {at(0)} = {record} and {at(1)} = {major})"
        f" or ({at(0)} = {hello} and {at(1)} = 0x00 and {at(4)} = {major})"
        f" or ({at(0)} = {record} and {at(5)} = {hello})"
    )


TCP_FILTER = (
    f"{_NOT_RESOLVER} and not ({_DNS_CARRIED}) and ("
    # What starts, answers or ends a connection, but for the session's
    # own within itself
    f"({_ENDS} and not dst net 127.0.0.0/8)"
    f" or ({_ENDS6} and not dst host ::1)"
    " or (not port 53 and ("
    # A packet of every gigabyte, see SAMPLED_BITS
    f"{_SAMPLED} or {_SAMPLED6}"
    # The start of a client hello
    f" or {_hello_starts('tcp', _PAYLOAD, _CARRIED)}"
    # Last, a packet without that much payload ends the filter there
    + _http_methods(f"tcp[{_PAYLOAD}:4]")
    + f" or ({_TCP6} and ({_hello_starts('ip6', _PAYLOAD6, _CARRIED6)}))"
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
# there. All of it but what starts and ends a connection and carries
# nothing, which the TCP part has: when this one is at its limit, the
# connections to port 53 are still recorded.
DIRECT_FILTER = (
    f"port 53 and {_NOT_RESOLVER} and"
    f" ((not ({_ENDS}) and not {_ENDS6}) or ({_DNS_CARRIED}))"
)
# Whatever the session sends that is not TCP: UDP, a ping, anything else
# over IP. There a connection has no start to pick out.
FLOWS_FILTER = (
    f"{_NOT_DNS} and ("
    "(outbound and ip and not tcp and not dst net 127.0.0.0/8)"
    f" or (outbound and ip6 and not {_TCP6} and not dst host ::1)"
    ")"
)
# What the session sends to the model's API that carries something, by
# the addresses of that (see model_api.py): every packet of it, for when
# each request went and how long it was. No more of each than its start,
# see HEADERS_LENGTH. Not what comes back, which has a part of its own.
# Of a session behind the egress proxy this part has nothing, its packets
# all go to the proxy.
_TO_THE_MODEL = {
    version: " or ".join(
        f"dst net {network}" for network in MODEL_API if network.version == version
    )
    for version in (4, 6)
}
UPLOADS_FILTER = (
    "outbound and ("
    f"(ip and tcp and ({_TO_THE_MODEL[4]}) and {_CARRIES})"
    f" or ({_TCP6} and ({_TO_THE_MODEL[6]}) and {_CARRIES6})"
    ")"
)
# And what it sends over TCP to anywhere else, the same of it: a push, a
# file sent somewhere, whatever goes to the egress proxy. In a part of its
# own, a session can send any amount of it and what tells of its requests
# to the model is not to be used up by that. Not within itself, nor to
# port 53, which has its part.
ELSEWHERE_FILTER = (
    f"outbound and {_NOT_DNS} and ("
    f"(ip and tcp and not ({_TO_THE_MODEL[4]}) and not dst net 127.0.0.0/8"
    f" and {_CARRIES})"
    f" or ({_TCP6} and not ({_TO_THE_MODEL[6]}) and not dst host ::1"
    f" and {_CARRIES6})"
    ")"
)
# What the model's API sends back that carries something, by the same
# addresses: every packet of it, for when each answer began and how long
# it was. As far as the numbers of TCP, see SEQUENCE_LENGTH. Whatever
# else has it: what ends a connection is the TCP part's too, and read
# there for another thing.
_FROM_THE_MODEL = {
    version: " or ".join(
        f"src net {network}" for network in MODEL_API if network.version == version
    )
    for version in (4, 6)
}
ANSWERS_FILTER = (
    "inbound and ("
    f"(ip and tcp and ({_FROM_THE_MODEL[4]}) and {_CARRIES})"
    f" or ({_TCP6} and ({_FROM_THE_MODEL[6]}) and {_CARRIES6})"
    ")"
)
# And of what comes in over TCP from anywhere else, a packet of every
# 16 MB of each connection: one that carries something and whose number
# is in the first 64 kB of those, by the one byte of the number that
# says so. A packet holds no more than 64 kB, so one at least each time,
# and about one in 256 of them all. From those how far a download has
# got is known while it runs, a gigabyte is some thousand packets at
# most. Not the session's own within itself, over its loopback or from
# its own address to that, which it could fill the part with: a packet
# whose two addresses are the same. Nor port 53.
_SAMPLED_IN = "tcp[5:1] = 0"
_SAMPLED_IN6 = "ip6[45:1] = 0"
_FROM_ELSEWHERE = "ip[12:4] != ip[16:4]"
_FROM_ELSEWHERE6 = (
    "("
    + " or ".join(f"ip6[{8 + at}:4] != ip6[{24 + at}:4]" for at in range(0, 16, 4))
    + ")"
)
DOWNLOADS_FILTER = (
    f"inbound and {_NOT_DNS} and ("
    f"(ip and tcp and {_SAMPLED_IN} and not ({_FROM_THE_MODEL[4]})"
    f" and not src net 127.0.0.0/8 and {_FROM_ELSEWHERE} and {_CARRIES})"
    f" or ({_TCP6} and {_SAMPLED_IN6} and not ({_FROM_THE_MODEL[6]})"
    f" and not src host ::1 and {_FROM_ELSEWHERE6} and {_CARRIES6})"
    ")"
)
PARTS = (
    Part("tcp", CAPTURE_FILE, "", TCP_FILTER, snap=HELLO_SNAP_LENGTH),
    Part("dns", "/dns.pcap", ".dns", DNS_FILTER),
    Part("direct", "/direct.pcap", ".direct", DIRECT_FILTER),
    Part("flows", "/flows.pcap", ".flows", FLOWS_FILTER),
    Part(
        UPLOADS_PART,
        "/uploads.pcap",
        f".{UPLOADS_PART}",
        UPLOADS_FILTER,
        snap=HEADERS_LENGTH,
    ),
    Part(
        ELSEWHERE_PART,
        "/elsewhere.pcap",
        f".{ELSEWHERE_PART}",
        ELSEWHERE_FILTER,
        snap=HEADERS_LENGTH,
    ),
    # After what the session sent: an answer is to the upload before it
    Part(
        ANSWERS_PART,
        "/answers.pcap",
        f".{ANSWERS_PART}",
        ANSWERS_FILTER,
        snap=SEQUENCE_LENGTH,
        limit=ANSWERS_LIMIT,
    ),
    Part(
        DOWNLOADS_PART,
        "/downloads.pcap",
        f".{DOWNLOADS_PART}",
        DOWNLOADS_FILTER,
        snap=SEQUENCE_LENGTH,
    ),
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
_STARTED = "\n".join(part.started for part in PARTS)
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
    # A tcpdump for each part, the script that looks after them, and what
    # reads the parts for whoever follows the session, two of them at once
    PIDS: ClassVar[int] = len(PARTS) + 24
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
        # A docker run that failed said why itself. What has the name then
        # can be another's, the name was in use, and is left alone: one
        # of this sidecar's that was made and never started is collected
        # by its label, as one left behind (see collect_left_behind)
        ran = started.returncode == 0
        said = sidecar.last_said() if ran else ""
        if ran:
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
        if capture.part_packets.get(part.name, 0) >= part.most
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
        # A recorder that ended early or lost packets may have lost
        # lookups, any of them
        whole = not session.stopped and not session.dropped
        return read_parts(Path(host.captures_dir, session.capture), whole)
    except OSError:
        return None


# The parts of a capture that have what the session looked up
LOOKUP_PARTS = frozenset({"dns", "direct"})


def lookups_whole(capture: Capture) -> bool:
    """Whether the lookups of a capture are all there, as far as its
    packets tell: not once a part that has them ran into its limit."""
    return not LOOKUP_PARTS.intersection(parts_cut_short(capture))


def read_parts(main: Path, whole: bool = True) -> Capture:
    """What a capture says, by its main file and the files of its other
    parts next to it. Raises OSError when the main one cannot be read.
    With whole, whether nothing of it is known to be missing: the hellos
    are held against what was looked up, which takes all the lookups
    (see Capture.look_at_hellos)."""
    others = [main.with_name(main.name + part.suffix) for part in PARTS[1:]]
    capture = read_capture(main, others)
    capture.lookups_whole = whole and lookups_whole(capture)
    capture.look_at_hellos(over=True)
    return capture


# What reads the parts of a capture from where each was read to, in one
# go: given the most bytes to write in all, then each part as
# file:offset, it writes for each how many bytes of it follow, on a line,
# then those bytes. How long a file is, is looked at first: it grows
# meanwhile, and no more of it is written out than was counted. Once the
# most is reached, the parts after that one are given none of: each is
# read after those before it, and is never further on than they are.
READ_SCRIPT = """left=$1
shift
for wanted; do
  file=${wanted%:*}
  size=$({ wc -c <"$file"; } 2>/dev/null)
  count=$((${size:-0} - ${wanted##*:}))
  [ "$count" -gt 0 ] || count=0
  [ "$count" -le "$left" ] || count=$left
  echo "$count"
  [ "$count" -gt 0 ] && tail -c "+$((${wanted##*:} + 1))" "$file" | head -c "$count"
  left=$((left - count))
done
true"""
# The most one reading of a capture takes in, of all its parts together:
# a session can fill every part to its limit, and whoever starts to
# follow it then is not to hold all of that at once
READ_MOST = 64 << 20


def captured_since(
    sidecar: str, offsets: Mapping[str, int]
) -> tuple[dict[str, bytes], bool]:
    """What the capture of a running session holds past the first so
    many bytes of each of its files in the sidecar, by the file: empty
    for one that has nothing more, and all of them when it cannot be
    read, the session ended or its sidecar is not there. And whether
    that is all there was: not when it came to READ_MOST, the rest is
    for the next time, the parts in their order. tcpdump writes every
    packet out as it comes (-U), so this is the capture up to now. Read
    by one command each time, for all the files: one left to follow them
    would stay behind in the sidecar."""
    wanted = [f"{file}:{offset}" for file, offset in offsets.items()]
    said = docker_bytes(
        "exec", sidecar, "sh", "-c", READ_SCRIPT, "sh", str(READ_MOST), *wanted
    )
    found = dict.fromkeys(offsets, b"")
    held = memoryview(said or b"")
    at = 0
    for file in offsets:
        end = (said or b"").find(b"\n", at)
        if said is None or end < 0 or not said[at:end].isdigit():
            break
        count = int(said[at:end])
        found[file] = bytes(held[end + 1 : end + 1 + count])
        at = end + 1 + count
    return found, sum(map(len, found.values())) < READ_MOST
