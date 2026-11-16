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
from .network import namespace_args, record_net_session
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
# Retransmitted connection attempts closer than this count as one
RETRY_SECONDS = 5.0


def capture_name(session: str) -> str:
    return session + CAPTURE_SUFFIX


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
    running = docker_output(
        "container", "inspect", "--format={{.State.Running}}", sidecar
    )
    if started.returncode != 0 or "true" not in running:
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
                "name": sidecar[: -len(CAPTURE_SUFFIX)],
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
        if not session_alive(launcher, sidecar[: -len(CAPTURE_SUFFIX)]):
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

    @property
    def cut_short(self) -> bool:
        return self.packets >= PACKET_LIMIT


class NotThis(Exception):
    """The bytes are not the kind of message they were read as."""


def dns_name(message: bytes, offset: int) -> tuple[str, int]:
    """A name in a DNS message and the offset after it, following the
    pointers names are compressed with."""
    labels: list[str] = []
    after = None
    for _ in range(64):
        length = message[offset]
        if length & 0xC0 == 0xC0:
            if after is None:
                after = offset + 2
            offset = (length & 0x3F) << 8 | message[offset + 1]
            continue
        offset += 1
        if length == 0:
            return ".".join(labels), offset if after is None else after
        labels.append(message[offset : offset + length].decode("ascii", "replace"))
        offset += length
    raise NotThis


def dns_answer(message: bytes) -> tuple[str, list[str]]:
    """The name a DNS response is about and the IPv4 addresses it gives."""
    try:
        _, flags, questions, answers = struct.unpack_from("!HHHH", message)
        if not flags & 0x8000 or questions != 1:
            raise NotThis
        name, offset = dns_name(message, 12)
        offset += 4
        addresses = []
        for _ in range(answers):
            _, offset = dns_name(message, offset)
            kind, _, _, length = struct.unpack_from("!HHIH", message, offset)
            offset += 10
            if kind == 1 and length == 4:
                addresses.append(socket.inet_ntoa(message[offset : offset + 4]))
            offset += length
    except (IndexError, struct.error):
        raise NotThis from None
    if not name:
        raise NotThis
    return name, addresses


def tls_server_name(record: bytes) -> str:
    """The server name a TLS client hello asks for, empty without one, as
    when the hello is longer than what was captured of it."""
    try:
        if record[0] != 0x16 or record[5] != 0x01:
            return ""
        # Record and handshake headers, version, random, then three
        # length-prefixed fields before the extensions
        offset = 5 + 4 + 2 + 32
        offset += 1 + record[offset]
        offset += 2 + struct.unpack_from("!H", record, offset)[0]
        offset += 1 + record[offset]
        offset += 2
        while True:
            kind, length = struct.unpack_from("!HH", record, offset)
            offset += 4
            if kind == 0:
                (name_length,) = struct.unpack_from("!H", record, offset + 3)
                name = record[offset + 5 : offset + 5 + name_length]
                return name.decode("ascii", "replace")
            offset += length
    except (IndexError, struct.error):
        return ""


def ip_packet(link_type: int, frame: bytes) -> tuple[bytes, bool]:
    """The IPv4 packet in a captured frame, empty if it holds none, and
    whether the session sent it. tcpdump's "any" device gives Linux cooked
    frames, version 1 or 2 depending on its age, both of which say so."""
    try:
        if link_type == 276:
            protocol, sent, header = frame[0:2], frame[10] == 4, 20
        elif link_type == 113:
            protocol, sent, header = frame[14:16], frame[0:2] == b"\x00\x04", 16
        elif link_type == 1:
            protocol, sent, header = frame[12:14], True, 14
        else:
            return b"", False
    except IndexError:
        return b"", False
    return (frame[header:] if protocol == b"\x08\x00" else b""), sent


def read_packet(
    capture: Capture, when: float, packet: bytes, sent: bool, seen: dict
) -> None:
    """Add what one IPv4 packet tells to the capture. seen holds when each
    connection was last attempted."""
    header = (packet[0] & 0x0F) * 4
    protocol, body = packet[9], packet[header:]
    source, destination = (socket.inet_ntoa(packet[at : at + 4]) for at in (12, 16))
    source_port, port = struct.unpack_from("!HH", body)
    if protocol == 17:
        # An answer comes in, or from the resolver on loopback. What the
        # session sends out in the shape of one is not an answer to it.
        if sent and not source.startswith("127."):
            return
        try:
            name, addresses = dns_answer(body[8:])
        except NotThis:
            return
        capture.lookups.append((when, name))
        capture.names.update(dict.fromkeys(addresses, name))
    elif protocol == 6 and sent and not destination.startswith("127."):
        flags = body[13]
        if flags & 0x12 == 0x02:
            attempt = (source_port, destination, port)
            if when - seen.get(attempt, -RETRY_SECONDS) >= RETRY_SECONDS:
                capture.connections.append((when, destination, port))
            seen[attempt] = when
        else:
            name = tls_server_name(body[(body[12] >> 4) * 4 :])
            if name:
                capture.names.setdefault(destination, name)


def read_capture(path: Path) -> Capture:
    """Read a capture file (pcap, as tcpdump writes it), skipping what it
    cannot make sense of. Raises OSError when the file cannot be read."""
    capture = Capture()
    seen: dict[tuple[int, str, int], float] = {}
    with open(path, "rb") as file:
        start = file.read(24)
        if len(start) < 24 or start[:4] not in PCAP_FORMATS:
            return capture
        order, fraction = PCAP_FORMATS[start[:4]]
        (link_type,) = struct.unpack(order + "I", start[20:24])
        while True:
            record = file.read(16)
            if len(record) < 16:
                break
            seconds, part, length, _ = struct.unpack(order + "IIII", record)
            if length > 0x40000:
                break
            frame = file.read(length)
            capture.packets += 1
            packet, sent = ip_packet(link_type, frame)
            try:
                if packet:
                    read_packet(capture, seconds + part / fraction, packet, sent, seen)
            except (IndexError, struct.error):
                continue
    return capture
