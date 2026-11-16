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
from datetime import datetime, timezone
from pathlib import Path

from harness import (
    LauncherTest,
    Result,
    launcher,
    pcap,
    prompts_at,
    records,
    settings,
)


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
    header = struct.pack(
        "!HHIIBBHHH", *ports, sequence, acknowledged, 0x50, flags, 0, 0, 0
    )
    return ipv4(6, "172.20.0.5", destination, header + payload)


def answer(
    address: str, port: int, flags: int = 0x12, sequence: int = 0, acknowledged: int = 0
) -> bytes:
    """A packet of the other end of a connection made with tcp, SYN and
    ACK unless told otherwise."""
    ports = (port, 40000 + port)
    header = struct.pack(
        "!HHIIBBHHH", *ports, sequence, acknowledged, 0x50, flags, 0, 0, 0
    )
    return ipv4(6, address, "172.20.0.5", header)


def dns_failure(name: str, kind: int = 1) -> bytes:
    """The resolver saying there is no such name."""
    labels = b"".join(bytes([len(part)]) + part.encode() for part in name.split("."))
    question = labels + b"\x00" + struct.pack("!HH", kind, 1)
    message = struct.pack("!HHHHHH", 7, 0x8183, 1, 0, 0, 0) + question
    datagram = struct.pack("!HHHH", 41234, 50000, 8 + len(message), 0) + message
    return ipv4(17, "127.0.0.11", "127.0.0.1", datagram)


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
    return struct.pack("!HHIIBBHHH", *ports, 0, 0, 0x50, flags, 0, 0, 0)


def lookups_under(parent: str, count: int) -> list[bytes]:
    return [
        dns_response(f"n{number}.{parent}", "198.51.100.7") for number in range(count)
    ]


def pcap_file(packets: list[tuple[float, bytes, bool]], link_type: int = 276) -> bytes:
    """A capture file as tcpdump writes it for its "any" device: packets
    given as when, the IP packet and whether the session sent it."""
    data = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, link_type)
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


class CaptureFileTest(unittest.TestCase):
    def read(self, data: bytes):
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory, "capture.pcap")
            file.write_bytes(data)
            return pcap.read_capture(file)

    def test_connections_names_and_lookups_are_read(self):
        for link_type in (276, 113):
            found = self.read(sample_capture(1000.0, link_type))
            self.assertEqual(
                [(c.when, c.address, c.port) for c in found.connections],
                [
                    (1002.0, "198.51.100.7", 443),
                    (1004.0, "10.0.0.7", 5432),
                    (1005.0, "203.0.113.9", UNNAMED),
                ],
            )
            self.assertEqual(
                found.names, {"198.51.100.7": "good.test", "203.0.113.9": "sni.test"}
            )
            looked_up = pcap.Lookup(1001.0, "good.test", "A", ("198.51.100.7",), "")
            self.assertEqual(found.lookups, [looked_up])
            self.assertEqual(found.packets, 10)

    def test_an_answer_the_session_sent_out_names_nothing(self):
        forged = ipv4(
            17, "172.20.0.5", "192.0.2.1", dns_response("bank.test", "6.6.6.6")[20:]
        )
        found = self.read(
            pcap_file([(1.0, forged, True), (2.0, tcp("6.6.6.6", 443), True)])
        )
        self.assertEqual(found.names, {})
        self.assertEqual([c.address for c in found.connections], ["6.6.6.6"])

    def test_a_connection_says_how_it_went(self):
        ok, shut, slow = "198.51.100.7", "198.51.100.8", "198.51.100.9"
        found = self.read(
            pcap_file(
                [
                    (10.0, tcp(ok, 443, sequence=1000), True),
                    (10.1, answer(ok, 443, sequence=5000, acknowledged=1001), False),
                    # 1500 bytes out by then, 20000 in, and 4 more with the FIN
                    (
                        12.0,
                        tcp(ok, 443, 0x11, b"last", sequence=2501, acknowledged=25001),
                        True,
                    ),
                    (12.1, answer(ok, 443, 0x11, sequence=25001), False),
                    (20.0, tcp(shut, 80), True),
                    (20.0, answer(shut, 80, flags=0x14), False),
                    (30.0, tcp(slow, 22), True),
                    (31.0, tcp(slow, 22), True),
                    (40.0, tcp(ok, 8080), True),
                    (40.1, answer(ok, 8080), False),
                ]
            )
        )
        closed, refused, unanswered, left = found.connections
        self.assertEqual((closed.outcome, closed.seconds), ("closed", 2.0))
        self.assertEqual((closed.sent, closed.received), (1504, 20000))
        self.assertEqual((refused.outcome, refused.failed), ("refused", True))
        self.assertEqual((unanswered.outcome, unanswered.failed), ("no answer", True))
        self.assertEqual((left.outcome, left.sent), ("open", None))
        self.assertEqual(
            [(what, c.address) for _, what, c in found.endings],
            [("closed", ok), ("refused", shut), ("no answer", slow)],
        )

    def test_a_connection_that_is_reset_still_says_how_much_went(self):
        there = "198.51.100.7"
        found = self.read(
            pcap_file(
                [
                    (1.0, tcp(there, 443, sequence=1000), True),
                    (1.1, answer(there, 443, sequence=5000, acknowledged=1001), False),
                    # Reset by the session in place of a FIN, 1500 bytes out
                    # and 20000 in by then
                    (
                        2.0,
                        tcp(there, 443, 0x14, sequence=2501, acknowledged=25001),
                        True,
                    ),
                    (3.0, tcp(there, 80, sequence=10), True),
                    (3.1, answer(there, 80, sequence=70, acknowledged=11), False),
                    # Reset by the other end, which says what it sent alone
                    (4.0, answer(there, 80, 0x04, sequence=171), False),
                ]
            )
        )
        mine, theirs = found.connections
        self.assertEqual(
            (mine.outcome, mine.sent, mine.received), ("closed", 1500, 20000)
        )
        self.assertEqual((theirs.sent, theirs.received), (None, 100))

    def test_the_other_end_closing_first_says_as_much(self):
        there = "198.51.100.7"
        found = self.read(
            pcap_file(
                [
                    (1.0, tcp(there, 443, sequence=2**32 - 10), True),
                    (1.1, answer(there, 443, sequence=70), False),
                    (
                        3.0,
                        answer(there, 443, 0x11, sequence=171, acknowledged=41),
                        False,
                    ),
                ]
            )
        )
        (closed,) = found.connections
        # 100 in, and 50 out across the wrap of the sequence numbers
        self.assertEqual((closed.sent, closed.received), (50, 100))

    def test_a_plain_http_request_is_read(self):
        asked = b"GET /a?b=1 HTTP/1.1\r\nUser-Agent: x\r\nhOst: plain.test\r\n\r\n"
        found = self.read(
            pcap_file(
                [
                    (1.0, tcp("198.51.100.7", 80, 0x18, asked), True),
                    (
                        2.0,
                        tcp("198.51.100.7", 80, 0x18, b"GET nothing of the kind"),
                        True,
                    ),
                    (
                        3.0,
                        tcp("198.51.100.7", 80, 0x18, b"BREW /pot HTTP/1.1\r\n"),
                        True,
                    ),
                    # To the egress proxy, whose log has it
                    (
                        4.0,
                        tcp("172.20.0.2", 3128, 0x18, b"GET http://x/ HTTP/1.1\r\n"),
                        True,
                    ),
                ]
            )
        )
        (request,) = found.requests
        self.assertEqual(request.url, "http://plain.test/a?b=1")
        self.assertEqual((request.method, request.address), ("GET", "198.51.100.7"))

    def test_a_lookup_says_what_was_asked_and_what_came_back(self):
        found = self.read(pcap_file([(1.0, dns_failure("nope.test", 28), False)]))
        self.assertEqual(
            found.lookups,
            [pcap.Lookup(1.0, "nope.test", "AAAA", (), "no such name")],
        )
        self.assertEqual(found.names, {})

    def test_a_damaged_file_is_read_as_far_as_it_goes(self):
        whole = sample_capture(1000.0)
        self.assertEqual(len(self.read(whole[:-30]).connections), 3)
        self.assertEqual(self.read(b"not a capture at all, really").packets, 0)

    def test_a_dns_name_that_points_at_itself_ends(self):
        loop = struct.pack("!HHHHHH", 7, 0x8180, 1, 0, 0, 0) + b"\xc0\x0c"
        with self.assertRaises(pcap.NotThis):
            pcap.dns_answer(0.0, loop)


class OtherTrafficTest(unittest.TestCase):
    """What is not TCP over IPv4: IPv6, and what a session sends by UDP or
    as a ping."""

    ME, THEM = "2001:db8::5", "2001:db8::9"

    def read(self, packets: list[tuple[float, bytes, bool]]):
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory, "capture.pcap")
            file.write_bytes(pcap_file(packets))
            return pcap.read_capture(file)

    def test_a_connection_over_ipv6_is_read(self):
        hello = tcp_header(443, 0x18) + client_hello("six.test")
        found = self.read(
            [
                (1.0, ipv6(6, self.ME, self.THEM, tcp_header(443, 0x02)), True),
                (1.1, ipv6(6, self.THEM, self.ME, tcp_header(40443, 0x12, 443)), False),
                (1.2, ipv6(6, self.ME, self.THEM, hello), True),
                # Within the session
                (2.0, ipv6(6, "::1", "::1", tcp_header(8000, 0x02)), True),
            ]
        )
        (connection,) = found.connections
        self.assertEqual((connection.address, connection.port), (self.THEM, 443))
        self.assertEqual(connection.outcome, "open")
        self.assertEqual(found.names, {self.THEM: "six.test"})

    def test_headers_ahead_of_the_transport_do_not_hide_it(self):
        options = bytes([6, 0, 1, 4, 0, 0, 0, 0])
        behind = ipv6(60, self.ME, self.THEM, options + tcp_header(443, 0x02))
        (connection,) = self.read([(1.0, behind, True)]).connections
        self.assertEqual((connection.address, connection.port), (self.THEM, 443))
        # A chain of them without an end is not followed for ever
        looped = ipv6(0, self.ME, self.THEM, bytes([0, 0, 1, 4, 0, 0, 0, 0]) * 20)
        self.assertEqual(self.read([(1.0, looped, True)]).flows, [])

    def test_what_is_sent_by_udp_is_one_flow_per_destination(self):
        quic = ipv4(17, "172.20.0.5", "198.51.100.7", udp(443))
        found = self.read(
            [
                (1.0, quic, True),
                (2.0, quic, True),
                (2.5, ipv6(17, self.ME, self.THEM, udp(443)), True),
                # Received, and within the session
                (3.0, ipv4(17, "198.51.100.7", "172.20.0.5", udp(50000)), False),
                (3.0, ipv4(17, "127.0.0.1", "127.0.0.1", udp(9999)), True),
            ]
        )
        self.assertEqual(
            [
                (f.when, f.transport, f.address, f.port, f.packets, f.sent)
                for f in found.flows
            ],
            [
                (1.0, "udp", "198.51.100.7", 443, 2, 216),
                (2.5, "udp", self.THEM, 443, 1, 108),
            ],
        )
        self.assertEqual(found.connections, [])

    def test_a_ping_is_a_flow_and_the_kernels_own_icmp_is_not(self):
        echo = ipv4(1, "172.20.0.5", "198.51.100.7", b"\x08\x00" + bytes(62))
        unreachable = ipv4(1, "172.20.0.5", "198.51.100.7", b"\x03\x01" + bytes(30))
        neighbour = ipv6(58, self.ME, "ff02::1", b"\x87\x00" + bytes(22))
        (flow,) = self.read(
            [(1.0, echo, True), (2.0, unreachable, True), (3.0, neighbour, True)]
        ).flows
        self.assertEqual((flow.transport, flow.port, flow.sent), ("icmp", 0, 64))

    def test_a_later_fragment_is_counted_without_ports(self):
        later = bytearray(ipv4(17, "172.20.0.5", "198.51.100.7", b"y" * 40))
        later[6:8] = struct.pack("!H", 185)
        (flow,) = self.read([(1.0, bytes(later), True)]).flows
        self.assertEqual((flow.port, flow.sent), (0, 40))

    def test_another_protocol_is_named_by_its_number(self):
        (flow,) = self.read(
            [(1.0, ipv4(99, "172.20.0.5", "198.51.100.7", b"z" * 10), True)]
        ).flows
        self.assertEqual((flow.transport, flow.port), ("ip-99", 0))

    def test_a_long_name_is_flagged_once(self):
        name = "a" * 50 + ".t.test"
        packets = [(float(at), dns_failure(name), False) for at in range(3)]
        found = self.read([*packets, (5.0, dns_failure("fine.t.test"), False)])
        self.assertEqual(
            [(why, lookup.name) for why, lookup in found.flagged],
            [("an unusually long name", name)],
        )

    def test_many_names_under_one_parent_are_flagged(self):
        count = pcap.DNS_MANY_NAMES
        few = [(1.0, packet, False) for packet in lookups_under("cdn.test", count - 1)]
        self.assertEqual(self.read(few).flagged, [])
        many = [(1.0, packet, False) for packet in lookups_under("t.test", count + 5)]
        # Not under a parent of one label, every name is under com
        many += [
            (2.0, dns_response(f"site{n}.test", "198.51.100.7"), False)
            for n in range(count + 5)
        ]
        ((why, lookup),) = self.read(many).flagged
        self.assertEqual(why, f"{count} names looked up under t.test")
        self.assertEqual(lookup.name, f"n{count - 1}.t.test")


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
            "--entrypoint=sh",
        ):
            self.assertIn(flag, sidecar)
        # It runs tcpdump and outlives it: the session's way out is the
        # sidecar's, and would go with one that ended at its packet limit
        script = sidecar[sidecar.index("-c") + 1]
        self.assertIn('tcpdump "$@" &', script)
        self.assertIn("sleep infinity", script)
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

    def left_behind(self, **launcher) -> Result:
        """A launch that finds the sidecar of an earlier session, started
        by the launcher its label names."""
        about = {"project": "/elsewhere", "start": 5, **launcher}
        return self.launch(
            FAKE_PS=f"claude-old.capture\t{json.dumps(about)}",
            FAKE_CAPTURE=str(self.capture_file),
        )

    def assert_collected(self, result: Result) -> None:
        self.assertIn(["rm", "--force", "claude-old.capture"], result.calls)
        self.assertTrue(
            (self.state / "captures" / "claude-old.capture-5.pcap").exists()
        )

    def test_a_capture_left_by_a_killed_session_is_collected(self):
        self.assert_collected(self.left_behind(pid=2**22 - 7))

    def test_the_capture_of_a_running_session_is_left_alone(self):
        me = os.getpid()
        for mine in (
            {"pid": me},
            {"pid": me, "launched": launcher.process_started(me)},
        ):
            result = self.left_behind(**mine)
            self.assertEqual(
                [c for c in result.calls if c[0] in ("stop", "cp", "rm")], []
            )

    def test_another_process_with_the_id_of_a_launcher_is_not_taken_for_it(self):
        self.assertTrue(launcher.process_started(os.getpid()))
        self.assert_collected(self.left_behind(pid=os.getpid(), launched="earlier"))

    def test_only_the_latest_sessions_stay_in_the_record(self):
        host = settings.detect_host({"HOME": str(self.home)})
        Path(host.state_dir).mkdir(parents=True)
        Path(host.net_sessions_file).write_text("cut off by a killed launch")
        for number in range(records.KEPT_SESSIONS + 5):
            session = records.NetSession(
                f"s{number}", "/p", float(number), ip="10.0.0.1"
            )
            records.record_net_session(host, session)
        kept = records.read_net_sessions(host)
        self.assertEqual(len(kept), records.KEPT_SESSIONS)
        self.assertEqual((kept[0].name, kept[-1].start), ("s5", kept[-1].start))
        self.assertEqual(kept[-1].name, f"s{records.KEPT_SESSIONS + 4}")

    def test_a_line_of_the_record_that_does_not_hold_up_is_passed_over(self):
        for line in (
            "[" * 100_000,
            '{"name": "a", "project": "/p", "start": 1e999, "ip": "10.0.0.1"}',
            '{"name": "a", "project": "/p", "start": 5, "capture": "a.pcap"}',
            '{"name": "a", "project": "/p", "start": 5}',
            '{"name": 1, "project": "/p", "start": 5, "ip": "10.0.0.1"}',
        ):
            self.assertIsNone(records.NetSession.from_line(line), line[:40])
        kept = records.NetSession.from_line(
            '{"name": "a", "project": "/p", "start": 5, "end": 9,'
            ' "capture": "../../etc/passwd"}'
        )
        self.assertEqual(kept.capture, "passwd")

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
            f"#   tcp sni.test (203.0.113.9):{UNNAMED} x1",
            "#   dns 1 names looked up",
            "sandbox  net         tcp/postgres 10.0.0.7:5432",
        ):
            self.assertIn(expected, stdout)
        self.assertNotIn(":8000", stdout)
        self.assertNotIn(":9000", stdout)
        self.assertNotIn("lookup", stdout)

    def test_the_trace_shows_what_was_sent_other_than_by_tcp(self):
        tunnel = "a" * 50 + ".t.test"
        self.capture_file.write_bytes(
            pcap_file(
                [
                    (self.now + 1, dns_response("quic.test", "198.51.100.8"), False),
                    (
                        self.now + 2,
                        ipv4(17, "172.20.0.5", "198.51.100.8", udp(443)),
                        True,
                    ),
                    (
                        self.now + 3,
                        ipv6(6, "2001:db8::5", "2001:db8::9", tcp_header(443, 0x02)),
                        True,
                    ),
                    (self.now + 4, dns_failure(tunnel), False),
                ]
            )
        )
        stdout = self.trace()
        for expected in (
            "#   udp/https quic.test (198.51.100.8):443  1 packet, 108 B out",
            "#   tcp/https [2001:db8::9]:443 x1",
            "#   dns 1 lookups FLAGGED, see --failed",
            "sandbox  net         udp/https quic.test (198.51.100.8):443  1 packet, 108 B out",
            "sandbox  net         tcp/https [2001:db8::9]:443",
            f"sandbox  dns         lookup {tunnel} A FLAGGED: an unusually long name",
        ):
            self.assertIn(expected, stdout)
        failed = self.launch("--trace", "--failed").stdout
        self.assertIn("FLAGGED", failed)
        self.assertNotIn("quic.test", failed.split("# time")[1])

    def test_verbose_adds_the_lookups(self):
        looked_up = "sandbox  dns         lookup good.test A -> 198.51.100.7"
        self.assertIn(looked_up, self.trace("--verbose"))

    def detailed(self, *args: str, **env: str) -> str:
        """The trace of a session that ran curl, with what the capture
        has of two connections during it and one after."""
        ok, shut = "198.51.100.7", "198.51.100.8"
        asked = b"GET /a HTTP/1.1\r\nHost: plain.test\r\n\r\n"
        packets = [
            (self.now + 2, tcp(ok, 80, sequence=1000), True),
            (self.now + 2, answer(ok, 80, sequence=5000), False),
            (self.now + 2, tcp(ok, 80, 0x18, asked, sequence=1001), True),
            (self.now + 3, tcp(ok, 80, 0x11, sequence=2501, acknowledged=25001), True),
            (self.now + 4, tcp(shut, 443), True),
            (self.now + 4, answer(shut, 443, flags=0x14), False),
            (self.now + 8, dns_failure("nope.test"), False),
            (self.now + 9, tcp(ok, 22), True),
        ]
        self.capture_file.write_bytes(pcap_file(packets))
        self.captured()
        first, last = prompts_at(self.now, self.now + 10)
        stamp = datetime.fromtimestamp
        ran = {"type": "tool_use", "id": "t1", "name": "Bash"}
        ran["input"] = {"command": "curl plain.test/a"}
        call = {"type": "assistant", "message": {"content": [ran]}}
        call["timestamp"] = stamp(self.now + 1, timezone.utc).isoformat()  # noqa: UP017
        done = {"type": "tool_result", "tool_use_id": "t1", "content": "ok"}
        result = {"type": "user", "message": {"content": [done]}}
        result["timestamp"] = stamp(self.now + 5, timezone.utc).isoformat()  # noqa: UP017
        self.write_transcript("0a", [first, call, result, last])
        traced = self.launch("--trace", *args, **env)
        self.assertEqual(traced.status, 0, traced.stderr)
        return traced.stdout

    def test_a_connection_says_how_it_went_and_during_which_call(self):
        stdout = self.detailed("--verbose")
        during = "  during: $ curl plain.test/a\n"
        for expected in (
            "tcp/http 198.51.100.7:80  closed after 1.0s, 2 kB out, 20 kB in" + during,
            "net         http GET http://plain.test/a" + during,
            "tcp/https 198.51.100.8:443  REFUSED" + during,
            "tcp/ssh 198.51.100.7:22  (no call running)\n",
            "dns         lookup nope.test A FAILED: no such name\n",
            "#   1 connections REFUSED or without an answer",
            "#   http 1 requests in the clear",
        ):
            self.assertIn(expected, stdout)

    def test_what_went_wrong_on_the_network_stands_out(self):
        coloured = self.detailed("--verbose", FORCE_COLOR="1")
        alert = "\x1b[1;31msandbox  "
        self.assertIn(
            alert + "net         tcp/https 198.51.100.8:443  REFUSED", coloured
        )
        self.assertIn(alert + "dns         lookup nope.test", coloured)

    def test_json_has_how_a_connection_went(self):
        events = [json.loads(line) for line in self.detailed("--json").splitlines()]
        closed, asked, refused, left = (e for e in events if e["what"] == "net")
        self.assertEqual((closed["outcome"], closed["seconds"]), ("closed", 1.0))
        self.assertEqual((closed["bytes_out"], closed["bytes_in"]), (1500, 20000))
        self.assertEqual((closed["during"], left["during"]), (["t1"], []))
        self.assertEqual(
            (asked["method"], asked["url"]), ("GET", "http://plain.test/a")
        )
        self.assertEqual((refused["outcome"], left.get("outcome")), ("refused", None))
        (call,) = (e for e in events if e.get("tool") == "Bash")
        self.assertEqual(call["id"], "t1")
        (failed,) = (e for e in events if e["what"] == "dns")
        self.assertEqual((failed["type"], failed["error"]), ("A", "no such name"))

    def test_json_has_connections_and_lookups(self):
        events = [json.loads(line) for line in self.trace("--json").splitlines()]
        reached = [e for e in events if e["what"] == "net"]
        self.assertEqual(
            [(e["protocol"], e["name"], e["address"], e["port"]) for e in reached],
            [
                ("tcp/https", "good.test", "198.51.100.7", 443),
                ("tcp/postgres", None, "10.0.0.7", 5432),
                ("tcp", "sni.test", "203.0.113.9", UNNAMED),
            ],
        )
        (lookup,) = (e for e in events if e["what"] == "dns")
        self.assertEqual((lookup["who"], lookup["name"]), ("sandbox", "good.test"))


if __name__ == "__main__":
    unittest.main()
