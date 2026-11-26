"""Packets and capture files made for the checks, as a session sends and
is sent them and as tcpdump writes them: the address 172.20.0.5 is the
session's, 127.0.0.11 Docker's resolver."""

from __future__ import annotations

import socket
import struct
import tempfile
from pathlib import Path

from claude_airlock.recording import capture as capture_module
from claude_airlock.recording import pcap


def unnamed_port() -> int:
    """A port this host has no name for: which ones have is the host's
    services file to say, 8443 is pcsync-https to some."""
    for port in range(8443, 65536):
        try:
            socket.getservbyport(port, "tcp")
        except OSError:
            return port
    raise AssertionError("every port has a name here")


# A port without a known use, a connection to it shows as plain tcp
UNNAMED = unnamed_port()


def ipv4(protocol: int, source: str, destination: str, payload: bytes) -> bytes:
    addresses = socket.inet_aton(source) + socket.inet_aton(destination)
    length = 20 + len(payload)
    return struct.pack("!BBHHHBBH", 0x45, 0, length, 0, 0, 64, protocol, 0) + (
        addresses + payload
    )


def segment(
    ports: tuple[int, int], flags: int, sequence: int = 0, acknowledged: int = 0
) -> bytes:
    """A TCP header from the first port to the second, without options."""
    return struct.pack(
        "!HHIIBBHHH", *ports, sequence, acknowledged, 0x50, flags, 0, 0, 0
    )


def dns_name(name: str) -> bytes:
    """A name as DNS writes it in a question, its labels without the end."""
    return b"".join(bytes([len(part)]) + part.encode() for part in name.split("."))


def tcp(
    destination: str,
    port: int,
    flags: int = 0x02,
    payload: bytes = b"",
    sequence: int = 0,
    acknowledged: int = 0,
) -> bytes:
    """A packet the session sends, SYN alone unless told otherwise."""
    ports = (40000 + port, port)
    header = segment(ports, flags, sequence, acknowledged)
    return ipv4(6, "172.20.0.5", destination, header + payload)


def answer(
    address: str,
    port: int,
    flags: int = 0x12,
    sequence: int = 0,
    acknowledged: int = 0,
    payload: bytes = b"",
) -> bytes:
    """A packet of the other end of a connection made with tcp, SYN and
    ACK unless told otherwise."""
    ports = (port, 40000 + port)
    header = segment(ports, flags, sequence, acknowledged)
    return ipv4(6, address, "172.20.0.5", header + payload)


def knock(
    address: str, port: int, flags: int = 0x02, sequence: int = 0, acknowledged: int = 0
) -> bytes:
    """A packet of someone who connects to a port of the session from
    their port 50000, SYN alone unless told otherwise."""
    ports = (50000, port)
    header = segment(ports, flags, sequence, acknowledged)
    return ipv4(6, address, "172.20.0.5", header)


def taken_up(
    address: str,
    port: int,
    flags: int = 0x12,
    sequence: int = 0,
    acknowledged: int = 0,
    payload: bytes = b"",
) -> bytes:
    """A packet the session sends back to someone who connected to a
    port of it with knock, SYN and ACK unless told otherwise."""
    ports = (port, 50000)
    header = segment(ports, flags, sequence, acknowledged)
    return ipv4(6, "172.20.0.5", address, header + payload)


def dns_failure(name: str, kind: int = 1) -> bytes:
    """The resolver saying there is no such name."""
    labels = dns_name(name)
    question = labels + b"\x00" + struct.pack("!HH", kind, 1)
    message = struct.pack("!HHHHHH", 7, 0x8183, 1, 0, 0, 0) + question
    datagram = struct.pack("!HHHH", 41234, 50000, 8 + len(message), 0) + message
    return ipv4(17, "127.0.0.11", "127.0.0.1", datagram)


def dns_response(name: str, address: str) -> bytes:
    labels = dns_name(name)
    question = labels + b"\x00" + struct.pack("!HH", 1, 1)
    # The answer names the question by pointer, as resolvers do
    answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton(address)
    message = struct.pack("!HHHHHH", 7, 0x8180, 1, 1, 0, 0) + question + answer
    # From Docker's resolver, whose port is rewritten inside the namespace
    datagram = struct.pack("!HHHH", 41234, 50000, 8 + len(message), 0) + message
    return ipv4(17, "127.0.0.11", "127.0.0.1", datagram)


def client_hello(name: str, offered: tuple[str, ...] = ()) -> bytes:
    """The hello of a TLS client that asks for a server by name, none
    when the name is empty, and offers to speak what is given."""
    host = name.encode()
    server_name = struct.pack("!HBH", len(host) + 3, 0, len(host)) + host
    extensions = struct.pack("!HH", 0x000A, 2) + b"\x00\x1d"
    if name:
        extensions += struct.pack("!HH", 0, len(server_name)) + server_name
    if offered:
        listed = b"".join(bytes([len(one)]) + one.encode() for one in offered)
        listed = struct.pack("!H", len(listed)) + listed
        extensions += struct.pack("!HH", 16, len(listed)) + listed
    body = b"\x03\x03" + bytes(32) + b"\x00" + b"\x00\x02\x13\x01" + b"\x01\x00"
    body += struct.pack("!H", len(extensions)) + extensions
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


def ipv6(protocol: int, source: str, destination: str, payload: bytes) -> bytes:
    addresses = socket.inet_pton(socket.AF_INET6, source) + socket.inet_pton(
        socket.AF_INET6, destination
    )
    return struct.pack("!IHBB", 6 << 28, len(payload), protocol, 64) + (
        addresses + payload
    )


def udp(port: int, payload: bytes = b"x" * 100) -> bytes:
    """A datagram to a port, without the IP header."""
    return struct.pack("!HHHH", 50000, port, 8 + len(payload), 0) + payload


def tcp_header(port: int, flags: int, source_port: int = 0) -> bytes:
    ports = (source_port or 40000 + port, port)
    return segment(ports, flags)


def lookups_under(parent: str, count: int) -> list[bytes]:
    return [
        dns_response(f"n{number}.{parent}", "198.51.100.7") for number in range(count)
    ]


def dns_query(name: str, kind: int = 1, ident: int = 7) -> bytes:
    """The session asking Docker's resolver for a name."""
    labels = dns_name(name)
    question = labels + b"\x00" + struct.pack("!HH", kind, 1)
    message = struct.pack("!HHHHHH", ident, 0x0100, 1, 0, 0, 0) + question
    datagram = struct.pack("!HHHH", 50000, 41234, 8 + len(message), 0) + message
    return ipv4(17, "127.0.0.1", "127.0.0.11", datagram)


def asked_for(response: bytes) -> bytes | None:
    """The query a response from Docker's resolver answers, none for any
    other packet."""
    if response[9:10] != b"\x11" or response[12:16] != socket.inet_aton("127.0.0.11"):
        return None
    message = response[28:]
    at = 12
    while message[at]:
        at += message[at] + 1
    kind = struct.unpack("!H", message[at + 1 : at + 3])[0]
    labels = message[12:at]
    name = ".".join(
        labels[i + 1 : i + 1 + labels[i]].decode() for i in _label_starts(labels)
    )
    ident = struct.unpack("!H", message[:2])[0]
    return dns_query(name, kind, ident)


def _label_starts(labels: bytes) -> list[int]:
    starts, at = [], 0
    while at < len(labels):
        starts.append(at)
        at += labels[at] + 1
    return starts


def pcap_file(
    packets: list[tuple[float, bytes, bool]], link_type: int = 276, asked: bool = True
) -> bytes:
    """A capture file as tcpdump writes it for its "any" device: packets
    given as when, the IP packet and whether the session sent it. Each
    response of Docker's resolver is preceded by the query it answers,
    which is what makes it an answer, unless told not to (asked)."""
    data = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, link_type)
    if asked:
        withheld = [(when, packet, sent) for when, packet, sent in packets]
        packets = []
        for when, packet, sent in withheld:
            query = asked_for(packet)
            if query is not None:
                # As a capture has what is on loopback: once, as come in
                packets.append((when, query, False))
            packets.append((when, packet, sent))
    for when, packet, sent in packets:
        kind = 4 if sent else 0
        carries = 0x86DD if packet[:1] and packet[0] >> 4 == 6 else 0x0800
        if link_type == 276:
            frame = struct.pack("!HHIHBB8s", carries, 0, 2, 1, kind, 6, b"") + packet
        else:
            frame = struct.pack("!HHH8sH", kind, 1, 6, b"", carries) + packet
        seconds, micros = int(when), int(when % 1 * 1e6)
        data += struct.pack("<IIII", seconds, micros, len(frame), len(frame)) + frame
    return data


def sample_capture(now: float, link_type: int = 276) -> bytes:
    return pcap_file(
        [
            (now + 1, dns_response("good.test", "198.51.100.7"), False),
            (now + 2, tcp("198.51.100.7", 443), True),
            # The same attempt sent again, and the reply to it
            (now + 3, tcp("198.51.100.7", 443), True),
            (now + 3, answer("198.51.100.7", 443), False),
            (now + 4, tcp("10.0.0.7", 5432), True),
            (now + 5, tcp("203.0.113.9", UNNAMED), True),
            (
                now + 5,
                tcp("203.0.113.9", UNNAMED, 0x18, client_hello("sni.test")),
                True,
            ),
            # Within the session, and someone else connecting to it
            (now + 6, tcp("127.0.0.1", 8000), True),
            (now + 6, tcp("172.20.0.5", 9000), False),
            (now + 7, b"\x45garbage", True),
        ],
        link_type,
    )


def dns_over(
    source: str,
    destination: str,
    message: bytes,
    ports: tuple[int, int],
    flags: int = 0x18,
) -> bytes:
    """A DNS message in a TCP packet, after its length."""
    header = segment(ports, flags)
    return ipv4(
        6, source, destination, header + struct.pack("!H", len(message)) + message
    )


def dns_message_of(packet: bytes) -> bytes:
    """What a UDP packet made by the helpers above carries."""
    return packet[28:]


def read_parts(main: list, whole: bool = True, **parts: list) -> pcap.Capture:
    """What a capture of some packets says, with the other parts of it
    that are given by their names. Not whole, of a capture that is known
    to miss some of what there was."""
    with tempfile.TemporaryDirectory() as directory:
        file = Path(directory, "c.pcap")
        file.write_bytes(pcap_file(main))
        for name, frames in parts.items():
            Path(directory, f"c.pcap.{name}").write_bytes(
                pcap_file(frames, asked=False)
            )
        return capture_module.read_parts(file, whole)
