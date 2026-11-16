"""Recording what a session connects to (CLAUDE_DOCKER_NET_LOG, on unless
set to 0), and reading the record back for --trace.

The session's route out is left as it is, so nothing it could reach before
is cut off. A sidecar owns the session's network namespace instead and runs
tcpdump in it, on the few packets that say where a connection goes: the
start of each TCP connection, the DNS answers and the TLS hello with the
server's name. The session joins that namespace, so the capture is running
before its first packet. It holds no capabilities and is in another process
namespace, so it can neither capture itself nor see, stop or edit the
capture, which stays in the sidecar until the launcher copies it out."""

from __future__ import annotations

import enum
import json
import os
import socket
import struct
import subprocess
import sys
import time
from collections.abc import Iterator
from contextlib import contextmanager
from dataclasses import dataclass, field
from pathlib import Path

from .docker import docker, docker_ok, docker_output, session_alive
from .network import namespace_args, record_net_session, sidecar_running
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
PACKET_FILTER = (
    "(tcp[tcpflags] & (tcp-syn|tcp-ack) = tcp-syn)"
    " or (udp and net 127.0.0.0/8)"
    " or port 53"
    # A TLS handshake record holding a client hello
    " or (tcp[((tcp[12:1] & 0xf0) >> 2):1] = 0x16"
    " and tcp[((tcp[12:1] & 0xf0) >> 2) + 5:1] = 0x01)"
)
# A pcap file starts with one of these, which gives its byte order and what
# its timestamps count in: microseconds or nanoseconds
PCAP_FORMATS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1e6),
    b"\x4d\x3c\xb2\xa1": ("<", 1e9),
    b"\xa1\xb2\xc3\xd4": (">", 1e6),
    b"\xa1\xb2\x3c\x4d": (">", 1e9),
}
PCAP_HEADER = 24
PCAP_RECORD_HEADER = 16
# The longest frame tcpdump writes, a longer one means a damaged file
PCAP_LONGEST_FRAME = 262144
# In a cooked frame, the packet type of one the machine sent
COOKED_SENT = 4
ETHERTYPE_IPV4 = 0x0800
UDP_HEADER = 8
DNS_IS_RESPONSE = 0x8000
# The two top bits of a length that is a pointer to the rest of a name
DNS_POINTER = 0xC0
DNS_ADDRESS_RECORD = 1
# A name cannot have more labels than this, a longer walk is a loop
DNS_MOST_LABELS = 127
TLS_HANDSHAKE = 0x16
TLS_CLIENT_HELLO = 0x01
TLS_SERVER_NAME = 0
# Retransmitted connection attempts closer than this count as one
RETRY_SECONDS = 5.0


class LinkType(enum.IntEnum):
    """What the frames of a capture file are, as its header says
    (tcpdump.org/linktypes). tcpdump's "any" device gives Linux cooked
    frames, version 1 or 2 depending on its age: both carry whether the
    machine sent the packet, at a different place."""

    ETHERNET = 1
    COOKED = 113
    COOKED_2 = 276


class Protocol(enum.IntEnum):
    """The protocols over IPv4 that are read, by their number there."""

    TCP = 6
    UDP = 17


class TcpFlag(enum.IntFlag):
    """The flags of a TCP packet that tell how a connection starts."""

    SYN = 0x02
    ACK = 0x10


def capture_name(session: str) -> str:
    return session + CAPTURE_SUFFIX


def session_name(sidecar: str) -> str:
    return sidecar[: -len(CAPTURE_SUFFIX)]


def start_capture(settings: Settings, host: Host, session: str, image_tag: str) -> dict:
    """Start the sidecar a session is about to join. It runs the sandbox
    image, which has tcpdump, as root with just what tcpdump needs: raw
    sockets, and the two capabilities its start-up change of user (to
    root, -Z, so that it can write its file) asks for. Returns what the
    sidecar is labelled with, which collect_capture takes: the project,
    when it started and the launcher's process id."""
    sidecar = capture_name(session)
    about = {"project": host.project_dir, "start": time.time(), "pid": os.getpid()}
    started = docker(
        "run",
        "--detach",
        "--init",
        f"--name={sidecar}",
        *namespace_args(settings),
        f"--label={CAPTURE_LABEL}={json.dumps(about)}",
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
    if started.returncode != 0 or not sidecar_running(sidecar):
        said = docker("logs", sidecar, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        docker_ok("rm", "--force", sidecar)
        raise Fatal(
            "the network capture did not start, CLAUDE_DOCKER_NET_LOG=0 runs"
            f" a session without it:\n{said.stdout.strip()}"
        )
    return about


def collect_capture(host: Host, sidecar: str, about: dict) -> None:
    """Stop a sidecar, copy its capture to the host and note which project
    and time it covers, for --trace to find it by."""
    # tcpdump writes out what it holds when it is asked to stop
    docker_ok("stop", sidecar)
    try:
        directory = Path(private_dir(host.captures_dir))
        target = directory / f"{sidecar}-{int(about['start'])}.pcap"
        if docker_ok("cp", f"{sidecar}:{CAPTURE_FILE}", str(target)):
            session = {
                "name": session_name(sidecar),
                "project": about["project"],
                "start": about["start"],
                "end": time.time(),
                "capture": target.name,
            }
            record_net_session(host, session)
        kept = sorted(directory.glob("*.pcap"), key=lambda file: file.stat().st_mtime)
        for old in kept[:-KEPT_CAPTURES]:
            old.unlink(missing_ok=True)
    except OSError as problem:
        # Said and passed over: this runs as a session ends, and what is
        # left to do then (the check of tamper.py) matters more
        print(f"claude-docker: the capture was not kept: {problem}", file=sys.stderr)
    finally:
        docker_ok("rm", "--force", sidecar)


def collect_ended_captures(host: Host) -> None:
    """Collect what sessions that ended without their launcher left behind
    (a killed Emacs buffer, a closed terminal): their sidecar is still
    there, capture included."""
    listed = docker_output(
        "ps", "--all", f"--filter=label={CAPTURE_LABEL}", "--format={{.Names}}"
    )
    label = f'--format={{{{index .Config.Labels "{CAPTURE_LABEL}"}}}}'
    for sidecar in listed.split():
        if not sidecar.endswith(CAPTURE_SUFFIX):
            continue
        try:
            labelled = json.loads(docker_output("container", "inspect", label, sidecar))
            launcher = int(labelled["pid"])
            about = {
                "project": str(labelled["project"]),
                "start": float(labelled["start"]),
            }
        except (ValueError, KeyError, TypeError, OverflowError):
            continue
        if not session_alive(launcher, session_name(sidecar)):
            collect_capture(host, sidecar, about)


@contextmanager
def session_captured(
    settings: Settings, host: Host, session: str, image_tag: str
) -> Iterator[None]:
    if not settings.net_log:
        yield
        return
    about = start_capture(settings, host, session, image_tag)
    try:
        yield
    finally:
        collect_capture(host, capture_name(session), about)


class NotThis(Exception):
    """The bytes are not the kind of message they were read as."""


class Cursor:
    """Reads a message front to back, in network byte order. Reading past
    its end raises NotThis: a truncated or foreign message ends the read
    of that message, nothing more."""

    def __init__(self, data: bytes, at: int = 0) -> None:
        self.data = data
        self.at = at

    def take(self, count: int) -> bytes:
        taken = self.data[self.at : self.at + count]
        if count < 0 or len(taken) < count:
            raise NotThis
        self.at += count
        return taken

    def number(self, size: int) -> int:
        return int.from_bytes(self.take(size), "big")

    def skip(self, count: int) -> None:
        self.take(count)

    def rest(self) -> bytes:
        return self.data[self.at :]


@dataclass(frozen=True)
class Packet:
    """A captured TCP or UDP packet over IPv4."""

    when: float
    # By the session, as opposed to received by it
    sent: bool
    protocol: Protocol
    source: str
    destination: str
    source_port: int
    port: int
    # None of them for UDP
    tcp_flags: TcpFlag
    payload: bytes

    @property
    def opens_connection(self) -> bool:
        """The first packet of a TCP connection: SYN without ACK, the
        reply to one carries both."""
        return (
            self.protocol is Protocol.TCP
            and TcpFlag.SYN in self.tcp_flags
            and TcpFlag.ACK not in self.tcp_flags
        )


@dataclass
class Capture:
    """What a capture says a session reached."""

    # When, address and port of each TCP connection it opened
    connections: list[tuple[float, str, int]] = field(default_factory=list)
    # The name an address was looked up under, else the one the TLS hello
    # to it asked for. Both are the session's doing: the address is what
    # it reached, the name what it says it was after.
    names: dict[str, str] = field(default_factory=dict)
    # When and for which name it asked the resolver, answered or not
    lookups: list[tuple[float, str]] = field(default_factory=list)
    packets: int = 0
    # When each connection (source port, address, port) was last attempted
    _attempts: dict[tuple[int, str, int], float] = field(
        default_factory=dict, repr=False
    )

    @property
    def cut_short(self) -> bool:
        return self.packets >= PACKET_LIMIT

    def add(self, packet: Packet) -> None:
        """Take in what one packet tells."""
        if packet.protocol is Protocol.UDP:
            self._add_dns_answer(packet)
        elif packet.sent and not is_loopback(packet.destination):
            # Not what the session does within itself, nor what comes in
            if packet.opens_connection:
                self._add_connection(packet)
            else:
                self._add_server_name(packet)

    def _add_dns_answer(self, packet: Packet) -> None:
        # An answer comes in, or from the resolver on loopback. What the
        # session sends out in the shape of one is not an answer to it.
        if packet.sent and not is_loopback(packet.source):
            return
        try:
            name, addresses = dns_answer(packet.payload)
        except NotThis:
            return
        self.lookups.append((packet.when, name))
        self.names.update(dict.fromkeys(addresses, name))

    def _add_connection(self, packet: Packet) -> None:
        attempt = (packet.source_port, packet.destination, packet.port)
        last = self._attempts.get(attempt)
        if last is None or packet.when - last >= RETRY_SECONDS:
            self.connections.append((packet.when, packet.destination, packet.port))
        self._attempts[attempt] = packet.when

    def _add_server_name(self, packet: Packet) -> None:
        name = tls_server_name(packet.payload)
        if name:
            # What the resolver said, if anything, comes first
            self.names.setdefault(packet.destination, name)


def is_loopback(address: str) -> bool:
    return address.startswith("127.")


def dns_name(message: bytes, at: Cursor) -> str:
    """The name at a cursor in a DNS message, the cursor left after it.
    A name can end in a pointer to the rest of it, elsewhere in the
    message, which is followed without moving the cursor further."""
    labels: list[str] = []
    reader = at
    for _ in range(DNS_MOST_LABELS):
        length = reader.number(1)
        if length & DNS_POINTER == DNS_POINTER:
            target = (length & ~DNS_POINTER) << 8 | reader.number(1)
            reader = Cursor(message, target)
        elif length == 0:
            return ".".join(labels)
        else:
            labels.append(reader.take(length).decode("ascii", "replace"))
    raise NotThis


def dns_answer(message: bytes) -> tuple[str, list[str]]:
    """The name a DNS response is about and the IPv4 addresses it gives.
    Raises NotThis for anything else."""
    reader = Cursor(message)
    reader.skip(2)  # the id of the query
    flags, questions, answers = (reader.number(2) for _ in range(3))
    reader.skip(4)  # the counts of the two other sections
    if not flags & DNS_IS_RESPONSE or questions != 1:
        raise NotThis
    name = dns_name(message, reader)
    reader.skip(4)  # the type and class asked for
    addresses = []
    for _ in range(answers):
        dns_name(message, reader)
        kind = reader.number(2)
        reader.skip(6)  # class, time to live
        data = reader.take(reader.number(2))
        if kind == DNS_ADDRESS_RECORD and len(data) == 4:
            addresses.append(socket.inet_ntoa(data))
    if not name:
        raise NotThis
    return name, addresses


def tls_server_name(record: bytes) -> str:
    """The server name a TLS client hello asks for. Empty for anything
    else, and for a hello without one or longer than what was captured."""
    try:
        hello = Cursor(record)
        if hello.number(1) != TLS_HANDSHAKE:
            return ""
        hello.skip(4)  # record version and length
        if hello.number(1) != TLS_CLIENT_HELLO:
            return ""
        hello.skip(3 + 2 + 32)  # handshake length, version, random
        hello.skip(hello.number(1))  # session id
        hello.skip(hello.number(2))  # cipher suites
        hello.skip(hello.number(1))  # compression methods
        hello.skip(2)  # length of the extensions
        while True:
            kind, length = hello.number(2), hello.number(2)
            if kind == TLS_SERVER_NAME:
                hello.skip(3)  # list length, name type
                return hello.take(hello.number(2)).decode("ascii", "replace")
            hello.skip(length)
    except NotThis:
        return ""


def ipv4_in_frame(link_type: int, frame: bytes) -> tuple[bytes, bool]:
    """The IPv4 packet a captured frame carries and whether the session
    sent it. Raises NotThis for a frame that carries something else. An
    Ethernet frame does not say who sent it, it counts as sent."""
    reader = Cursor(frame)
    if link_type == LinkType.COOKED_2:
        ethertype = reader.number(2)
        reader.skip(8)  # reserved, interface, hardware type
        sent = reader.number(1) == COOKED_SENT
        reader.skip(9)  # address length and address
    elif link_type == LinkType.COOKED:
        sent = reader.number(2) == COOKED_SENT
        reader.skip(12)  # hardware type, address length and address
        ethertype = reader.number(2)
    elif link_type == LinkType.ETHERNET:
        reader.skip(12)  # the two addresses
        ethertype, sent = reader.number(2), True
    else:
        raise NotThis
    if ethertype != ETHERTYPE_IPV4:
        raise NotThis
    return reader.rest(), sent


def parse_packet(when: float, link_type: int, frame: bytes) -> Packet:
    """A captured frame as a packet. Raises NotThis unless it is TCP or
    UDP over IPv4, whole as far as its headers go."""
    datagram, sent = ipv4_in_frame(link_type, frame)
    ip = Cursor(datagram)
    header_length = (ip.number(1) & 0x0F) * 4
    ip.skip(8)  # service, lengths, fragment, time to live
    try:
        protocol = Protocol(ip.number(1))
    except ValueError:
        raise NotThis from None
    ip.skip(2)  # checksum
    source, destination = (socket.inet_ntoa(ip.take(4)) for _ in range(2))

    transport = Cursor(datagram, header_length)
    source_port, port = transport.number(2), transport.number(2)
    tcp_flags = TcpFlag(0)
    if protocol is Protocol.TCP:
        transport.skip(8)  # sequence and acknowledgement numbers
        tcp_header_length = (transport.number(1) >> 4) * 4
        tcp_flags = TcpFlag(transport.number(1))
        payload = datagram[header_length + tcp_header_length :]
    else:
        payload = datagram[header_length + UDP_HEADER :]
    return Packet(
        when, sent, protocol, source, destination, source_port, port, tcp_flags, payload
    )


def pcap_frames(path: Path) -> Iterator[tuple[float, int, bytes]]:
    """The frames of a capture file (pcap, as tcpdump writes it): when
    each was captured, the link type of the file and the frame. Ends at
    the first thing that is not as it should be, as a file cut off by a
    stopped tcpdump is. Raises OSError when the file cannot be read."""
    with open(path, "rb") as file:
        start = file.read(PCAP_HEADER)
        if len(start) < PCAP_HEADER or start[:4] not in PCAP_FORMATS:
            return
        byte_order, per_second = PCAP_FORMATS[start[:4]]
        (link_type,) = struct.unpack_from(byte_order + "I", start, 20)
        while True:
            record = file.read(PCAP_RECORD_HEADER)
            if len(record) < PCAP_RECORD_HEADER:
                return
            seconds, fraction, length, _ = struct.unpack(byte_order + "IIII", record)
            if length > PCAP_LONGEST_FRAME:
                return
            yield seconds + fraction / per_second, link_type, file.read(length)


def read_capture(path: Path) -> Capture:
    """What a capture file says a session reached. A packet that cannot be
    made sense of is counted and passed over. Raises OSError when the file
    cannot be read."""
    capture = Capture()
    for when, link_type, frame in pcap_frames(path):
        capture.packets += 1
        try:
            capture.add(parse_packet(when, link_type, frame))
        except NotThis:
            continue
    return capture
