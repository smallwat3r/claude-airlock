#!/usr/bin/env python3
"""The network capture: reading a capture file, the sidecar a session joins,
and what --trace shows of it."""

from __future__ import annotations

import json
import os
import socket
import struct
import tempfile
import time
import unittest
from pathlib import Path

from harness import (
    LauncherTest,
    Result,
    capture,
    prompts_at,
    settings,
)


def ipv4(protocol: int, source: str, destination: str, payload: bytes) -> bytes:
    addresses = socket.inet_aton(source) + socket.inet_aton(destination)
    length = 20 + len(payload)
    return struct.pack("!BBHHHBBH", 0x45, 0, length, 0, 0, 64, protocol, 0) + (
        addresses + payload
    )


def tcp(destination: str, port: int, flags: int = 0x02, payload: bytes = b"") -> bytes:
    header = struct.pack("!HHIIBBHHH", 40000 + port, port, 0, 0, 0x50, flags, 0, 0, 0)
    return ipv4(6, "172.20.0.5", destination, header + payload)


def dns_response(name: str, address: str) -> bytes:
    labels = b"".join(bytes([len(part)]) + part.encode() for part in name.split("."))
    question = labels + b"\x00" + struct.pack("!HH", 1, 1)
    # The answer names the question by pointer, as resolvers do
    answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton(address)
    message = struct.pack("!HHHHHH", 7, 0x8180, 1, 1, 0, 0) + question + answer
    # From Docker's resolver, whose port is rewritten inside the namespace
    datagram = struct.pack("!HHHH", 41234, 50000, 8 + len(message), 0) + message
    return ipv4(17, "127.0.0.11", "127.0.0.1", datagram)


def client_hello(name: str) -> bytes:
    host = name.encode()
    server_name = struct.pack("!HBH", len(host) + 3, 0, len(host)) + host
    extensions = struct.pack("!HH", 0x000A, 2) + b"\x00\x1d"
    extensions += struct.pack("!HH", 0, len(server_name)) + server_name
    body = b"\x03\x03" + bytes(32) + b"\x00" + b"\x00\x02\x13\x01" + b"\x01\x00"
    body += struct.pack("!H", len(extensions)) + extensions
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


def pcap(packets: list[tuple[float, bytes, bool]], link_type: int = 276) -> bytes:
    """A capture file as tcpdump writes it for its "any" device: packets
    given as when, the IPv4 packet and whether the session sent it."""
    data = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, link_type)
    for when, packet, sent in packets:
        kind = 4 if sent else 0
        if link_type == 276:
            frame = struct.pack("!HHIHBB8s", 0x0800, 0, 2, 1, kind, 6, b"") + packet
        else:
            frame = struct.pack("!HHH8sH", kind, 1, 6, b"", 0x0800) + packet
        seconds, micros = int(when), int(when % 1 * 1e6)
        data += struct.pack("<IIII", seconds, micros, len(frame), len(frame)) + frame
    return data


def sample_capture(now: float, link_type: int = 276) -> bytes:
    return pcap(
        [
            (now + 1, dns_response("good.test", "198.51.100.7"), False),
            (now + 2, tcp("198.51.100.7", 443), True),
            # The same attempt sent again, and the reply to it
            (now + 3, tcp("198.51.100.7", 443), True),
            (now + 3, tcp("198.51.100.7", 443, flags=0x12), False),
            (now + 4, tcp("10.0.0.7", 5432), True),
            (now + 5, tcp("203.0.113.9", 8443), True),
            (now + 5, tcp("203.0.113.9", 8443, 0x18, client_hello("sni.test")), True),
            # Within the session, and someone else connecting to it
            (now + 6, tcp("127.0.0.1", 8000), True),
            (now + 6, tcp("172.20.0.5", 9000), False),
            (now + 7, b"\x45garbage", True),
        ],
        link_type,
    )


class CaptureFileTest(unittest.TestCase):
    def read(self, data: bytes):
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory, "capture.pcap")
            file.write_bytes(data)
            return capture.read_capture(file)

    def test_connections_names_and_lookups_are_read(self):
        for link_type in (276, 113):
            found = self.read(sample_capture(1000.0, link_type))
            self.assertEqual(
                found.connections,
                [
                    (1002.0, "198.51.100.7", 443),
                    (1004.0, "10.0.0.7", 5432),
                    (1005.0, "203.0.113.9", 8443),
                ],
            )
            self.assertEqual(
                found.names, {"198.51.100.7": "good.test", "203.0.113.9": "sni.test"}
            )
            self.assertEqual(found.lookups, [(1001.0, "good.test")])
            self.assertEqual(found.packets, 10)

    def test_an_answer_the_session_sent_out_names_nothing(self):
        forged = ipv4(
            17, "172.20.0.5", "192.0.2.1", dns_response("bank.test", "6.6.6.6")[20:]
        )
        found = self.read(pcap([(1.0, forged, True), (2.0, tcp("6.6.6.6", 443), True)]))
        self.assertEqual(found.names, {})
        self.assertEqual(found.connections, [(2.0, "6.6.6.6", 443)])

    def test_a_damaged_file_is_read_as_far_as_it_goes(self):
        whole = sample_capture(1000.0)
        self.assertEqual(len(self.read(whole[:-30]).connections), 3)
        self.assertEqual(self.read(b"not a capture at all, really").packets, 0)

    def test_a_dns_name_that_points_at_itself_ends(self):
        loop = struct.pack("!HHHHHH", 7, 0x8180, 1, 0, 0, 0) + b"\xc0\x0c"
        with self.assertRaises(capture.NotThis):
            capture.dns_answer(loop)


class CaptureSessionTest(LauncherTest):
    SIDECAR = "claude-proj.capture"

    def setUp(self):
        super().setUp()
        self.now = time.time()
        self.capture_file = self.work / "capture.pcap"
        self.capture_file.write_bytes(sample_capture(self.now))

    def captured(self, *args: str, **env: str) -> Result:
        return self.launch(
            *args, CLAUDE_DOCKER_NET_LOG="1", FAKE_CAPTURE=str(self.capture_file), **env
        )

    def test_the_session_joins_a_sidecar_that_captures(self):
        result = self.captured()
        self.assertIn(f"--network=container:{self.SIDECAR}", result.flags)
        sidecar = result.sidecar(self.SIDECAR)
        for flag in (
            "--network=claude-docker-open-net",
            "--cap-drop=ALL",
            "--cap-add=NET_RAW",
            "--entrypoint=tcpdump",
        ):
            self.assertIn(flag, sidecar)
        self.assertLess(
            result.calls.index(sidecar),
            next(
                i for i, c in enumerate(result.calls) if c[0] == "run" and c != sidecar
            ),
        )

    def test_a_filtered_session_is_captured_inside_the_filter(self):
        result = self.captured(CLAUDE_DOCKER_NET_FILTER="1", FAKE_IP="172.20.0.5")
        sidecar = result.sidecar(self.SIDECAR)
        self.assertIn("--network=claude-docker-net", sidecar)
        self.assertIn("--dns=127.0.0.1", sidecar)
        self.assertIn(f"--network=container:{self.SIDECAR}", result.flags)
        self.assertNotIn("--dns=127.0.0.1", result.flags)
        self.assertIn("--env=HTTPS_PROXY=http://claude-egress-proxy:3128", result.flags)
        sessions = (self.state / "net-sessions.jsonl").read_text()
        self.assertIn('"ip": "172.20.0.5"', sessions)

    def test_capturing_is_the_default(self):
        self.assertTrue(settings.load_settings({}, str(self.work / "none")).net_log)

    def test_switched_off_nothing_is_captured(self):
        result = self.launch()
        self.assertIsNone(result.sidecar(self.SIDECAR))
        self.assertIn("--network=claude-docker-open-net", result.flags)

    def test_the_capture_is_copied_out_and_the_sidecar_removed(self):
        result = self.captured()
        (copied,) = (self.state / "captures").glob("*.pcap")
        self.assertEqual(copied.read_bytes(), self.capture_file.read_bytes())
        (session,) = map(
            json.loads, (self.state / "net-sessions.jsonl").read_text().splitlines()
        )
        self.assertEqual(session["capture"], copied.name)
        self.assertEqual(session["project"], str(self.project))
        ending = [c[0] for c in result.calls if self.SIDECAR in c[-1] or c[0] == "cp"]
        self.assertEqual(ending[-3:], ["stop", "cp", "rm"])

    def test_what_is_kept_is_for_the_user_alone(self):
        self.captured()
        for directory in (self.state, self.state / "captures"):
            self.assertEqual(directory.stat().st_mode & 0o777, 0o700)

    def test_a_capture_left_by_a_killed_session_is_collected(self):
        about = {"project": "/elsewhere", "start": 5, "pid": 2**22 - 7}
        result = self.launch(
            FAKE_PS="claude-old.capture",
            FAKE_LABEL=json.dumps(about),
            FAKE_CAPTURE=str(self.capture_file),
        )
        self.assertIn(["rm", "--force", "claude-old.capture"], result.calls)
        self.assertTrue(
            (self.state / "captures" / "claude-old.capture-5.pcap").exists()
        )

    def test_the_capture_of_a_running_session_is_left_alone(self):
        about = {"project": "/elsewhere", "start": 5, "pid": os.getpid()}
        result = self.launch(FAKE_PS="claude-old.capture", FAKE_LABEL=json.dumps(about))
        self.assertEqual([c for c in result.calls if c[0] in ("stop", "cp", "rm")], [])

    def trace(self, *args: str) -> str:
        self.captured()
        self.write_transcript("0a", prompts_at(self.now, self.now + 10))
        result = self.launch("--trace", *args)
        self.assertEqual(result.status, 0, result.stderr)
        return result.stdout

    def test_the_trace_lists_what_was_reached(self):
        stdout = self.trace()
        for expected in (
            "#   captured in claude-proj from ",
            "#   tcp/https good.test (198.51.100.7):443 x1",
            "#   tcp/postgres 10.0.0.7:5432 x1",
            "#   tcp sni.test (203.0.113.9):8443 x1",
            "#   dns 1 names looked up",
            "sandbox  net       tcp/postgres 10.0.0.7:5432",
        ):
            self.assertIn(expected, stdout)
        self.assertNotIn(":8000", stdout)
        self.assertNotIn(":9000", stdout)
        self.assertNotIn("lookup", stdout)

    def test_full_adds_the_lookups(self):
        self.assertIn("sandbox  dns       lookup good.test", self.trace("--full"))

    def test_json_has_connections_and_lookups(self):
        events = [json.loads(line) for line in self.trace("--json").splitlines()]
        reached = [e for e in events if e["what"] == "net"]
        self.assertEqual(
            [(e["protocol"], e["name"], e["address"], e["port"]) for e in reached],
            [
                ("tcp/https", "good.test", "198.51.100.7", 443),
                ("tcp/postgres", None, "10.0.0.7", 5432),
                ("tcp", "sni.test", "203.0.113.9", 8443),
            ],
        )
        (lookup,) = (e for e in events if e["what"] == "dns")
        self.assertEqual((lookup["who"], lookup["name"]), ("sandbox", "good.test"))


if __name__ == "__main__":
    unittest.main()
