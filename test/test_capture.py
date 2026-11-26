#!/usr/bin/env python3
"""The network capture: reading a capture file, the sidecar a session joins,
and what --trace shows of it."""

from __future__ import annotations

import dataclasses
import json
import os
import shutil
import socket
import struct
import subprocess
import tempfile
import time
import unittest.mock
from datetime import UTC, datetime
from pathlib import Path

import pytest
from harness import LauncherTest, Result, prompts_at
from packets import (
    UNNAMED,
    answer,
    asked_for,
    client_hello,
    dns_failure,
    dns_message_of,
    dns_over,
    dns_query,
    dns_response,
    ipv4,
    ipv6,
    knock,
    lookups_under,
    pcap_file,
    read_parts,
    sample_capture,
    segment,
    taken_up,
    tcp,
    tcp_header,
    udp,
)

from claude_airlock import launcher, settings
from claude_airlock.reader import NotThis
from claude_airlock.recording import (
    address,
    egress_log,
    payloads,
    pcap,
    processes,
    records,
    sidecar,
)
from claude_airlock.recording import capture as capture_module
from claude_airlock.recording import lookups as lookups_module
from claude_airlock.recording.pcap_file import PcapReader
from claude_airlock.report import layout, net_events
from claude_airlock.sandbox import egress_proxy


class CaptureFileTest:
    def read(self, data: bytes):
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory, "capture.pcap")
            file.write_bytes(data)
            return pcap.read_capture(file)

    def test_connections_names_and_lookups_are_read(self):
        for link_type in (276, 113):
            found = self.read(sample_capture(1000.0, link_type))
            assert [(c.when, c.address, c.port) for c in found.connections] == [
                (1002.0, "198.51.100.7", 443),
                (1004.0, "10.0.0.7", 5432),
                (1005.0, "203.0.113.9", UNNAMED),
            ]
            assert found.names == {
                "198.51.100.7": "good.test",
                "203.0.113.9": "sni.test",
            }
            looked_up = payloads.Lookup(1001.0, "good.test", "A", ("198.51.100.7",), "")
            assert found.dns.lookups == [looked_up]
            assert found.packets == 11

    def test_an_answer_the_session_sent_out_names_nothing(self):
        forged = ipv4(
            17, "172.20.0.5", "192.0.2.1", dns_response("bank.test", "6.6.6.6")[20:]
        )
        found = self.read(
            pcap_file([(1.0, forged, True), (2.0, tcp("6.6.6.6", 443), True)])
        )
        assert found.names == {}
        assert [c.address for c in found.connections] == ["6.6.6.6"]

    def test_what_is_sent_after_the_other_side_closed_is_counted(self):
        there, port = "198.51.100.7", 443
        giga = 1 << 30
        sent = 5 * giga + 12345

        def number(count: int) -> int:
            """The sequence number after so many bytes from 1000."""
            return (1001 + count) % (1 << 32)

        packets = [
            (10.0, tcp(there, port, sequence=1000), True),
            (10.1, answer(there, port, sequence=5000, acknowledged=1001), False),
            # The server has nothing to say, and says so before the upload
            (10.2, answer(there, port, 0x11, sequence=5001, acknowledged=1001), False),
            # A packet of every gigabyte, as the capture takes them
            *(
                (
                    20.0 + at,
                    tcp(there, port, 0x10, b"x" * 1000, number(at * giga)),
                    True,
                )
                for at in range(1, 6)
            ),
            (90.0, tcp(there, port, 0x11, b"", number(sent), 5002), True),
        ]
        (upload,) = self.read(pcap_file(packets)).connections
        assert (upload.outcome, upload.seconds) == ("closed", 80.0)
        assert (upload.sent, upload.received) == (sent, 0)
        # As far as the first FIN told, while it is all there is
        (so_far,) = self.read(pcap_file(packets[:3])).connections
        assert (so_far.outcome, so_far.sent, so_far.received) == ("closed", 0, 0)
        # The acknowledgement of a FIN is no byte, and a reset ends it
        packets[-1] = (90.0, answer(there, port, 0x14, sequence=5002), False)
        (reset,) = self.read(pcap_file(packets)).connections
        assert (reset.sent, reset.received) == (5 * giga + 1000, 0)
        # The next connection from the same port is another
        again = [*packets[:3], (95.0, tcp(there, port, sequence=77), True)]
        first, following = self.read(pcap_file(again)).connections
        assert (first.sent, following.outcome) == (0, "")

    def test_the_filters_take_what_they_say(self):
        if not shutil.which("tcpdump"):
            pytest.skip("no tcpdump here")
        there, window = "198.51.100.7", 3 << 30
        direct = ipv4(17, "172.20.0.5", "9.9.9.9", udp(53))
        packets = {
            "tcp": [
                tcp(there, 443),
                tcp(there, 443, 0x11),
                tcp("9.9.9.9", 53),
                tcp(there, 443, 0x10, b"x" * 100, sequence=window + 65535),
                tcp(there, 443, 0x18, client_hello("sni.test")),
                tcp(there, 80, 0x18, b"GET / HTTP/1.1\r\n\r\n"),
            ],
            "dns": [dns_query("a.test"), dns_response("a.test", there)],
            "direct": [direct, tcp("9.9.9.9", 53, 0x18, b"\x00\x01x")],
            "flows": [ipv4(17, "172.20.0.5", there, udp(4433))],
            # What is sent to the model's API, outside what is sampled,
            # and the same to anywhere else
            "uploads": [
                tcp("160.79.104.10", 443, 0x10, b"x" * 100, sequence=window + 65536)
            ],
            "elsewhere": [tcp(there, 443, 0x10, b"x" * 100, sequence=window + 65536)],
            # A packet with nothing in it, and the session's own within
            # itself
            "": [
                tcp(there, 443, 0x10, b"", sequence=window),
                tcp("127.0.0.1", 8000, 0x10, b"x", sequence=window),
                tcp("127.0.0.1", 8000),
            ],
        }
        # And of what comes in: all the model's API sends back, and from
        # anywhere else what is in the first 64 kB of every 16 MB
        model, sampled = "160.79.104.10", 0x12005678
        came_in = {
            "answers": [
                answer(model, 443, 0x18, window + 70000, payload=b"y" * 100),
                answer(model, 443, 0x18, sampled, payload=b"y" * 100),
            ],
            "downloads": [answer(there, 443, 0x18, sampled, payload=b"y" * 100)],
            # Outside the sample, and with nothing in it. And what the
            # session sends to its own address, which is as much as it
            # likes. What it sends anywhere else is in the parts above
            "": [
                answer(there, 443, 0x18, sampled + 65536, payload=b"y" * 100),
                answer(there, 443, 0x10, sampled),
                answer("172.20.0.5", 443, 0x18, sampled, payload=b"y" * 100),
            ],
        }
        # What is sent anywhere is in its part whatever else has it: the
        # packets of that part are read for when they went and how long
        # they were alone, and not as those of the others are
        carrying = packets["tcp"][3:] + packets["elsewhere"]
        every = [(packet, True) for some in packets.values() for packet in some]
        every += [(packet, False) for some in came_in.values() for packet in some]
        frames = [(1.0 + at, *packet) for at, packet in enumerate(every)]
        packets.update({part: some for part, some in came_in.items() if part})
        with tempfile.TemporaryDirectory() as directory:
            whole = Path(directory, "all.pcap")
            whole.write_bytes(pcap_file(frames, link_type=113, asked=False))
            taken: dict[str, list[bytes]] = {}
            for part in capture_module.PARTS:
                kept = Path(directory, part.name)
                subprocess.run(
                    ["tcpdump", "-r", str(whole), "-w", str(kept), part.filter],
                    check=True,
                    capture_output=True,
                )
                taken[part.name] = [
                    frame[16:] for _, _, frame in PcapReader().feed(kept.read_bytes())
                ]
        # Each packet in the part that is to have it, and in no other
        assert taken.pop("elsewhere") == carrying
        del packets["elsewhere"]
        assert taken == {part: some for part, some in packets.items() if part}

    def test_the_name_of_an_address_is_found_among_any_number_of_answers(self):
        capture = pcap.Capture()
        count = 50_000
        for at in range(count):
            lookup = payloads.Lookup(
                float(at), f"n{at}.test", "A", ("198.51.100.7",), ""
            )
            capture.dns._keep(lookup)
        started = time.monotonic()
        for at in range(count):
            assert capture.name_of("198.51.100.7", at + 0.5) == f"n{at}.test"
        assert time.monotonic() - started < 10
        assert capture.name_of("198.51.100.7") == f"n{count - 1}.test"
        assert capture.name_of("198.51.100.7", -1.0) is None
        # One that comes out of its turn is put where its time is
        capture.dns._keep(payloads.Lookup(9.7, "late.test", "A", ("198.51.100.7",), ""))
        assert capture.name_of("198.51.100.7", 9.8) == "late.test"
        assert capture.name_of("198.51.100.7", 9.6) == "n9.test"

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
        # Closed once both sides have said so
        assert (closed.outcome, closed.seconds) == ("closed", 2.1)
        assert (closed.sent, closed.received) == (1504, 20000)
        assert (refused.outcome, refused.failed) == ("refused", True)
        assert (unanswered.outcome, unanswered.failed) == ("no answer", True)
        assert (left.outcome, left.sent) == ("open", None)
        assert [(what, c.address) for _, what, c in found.endings] == [
            ("closed", ok),
            ("refused", shut),
            ("no answer", slow),
        ]

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
        assert (mine.outcome, mine.sent, mine.received) == ("closed", 1500, 20000)
        assert (theirs.sent, theirs.received) == (None, 100)

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
        assert (closed.sent, closed.received) == (50, 100)

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
        assert request.url == "http://plain.test/a?b=1"
        assert (request.method, request.address) == ("GET", "198.51.100.7")

    def test_what_a_packet_carries_is_read_whatever_else_the_packet_is(self):
        there, fast = "198.51.100.7", "203.0.113.9"
        asked = b"POST /upload?x=1 HTTP/1.1\r\nHost: plain.test\r\n\r\n"
        found = self.read(
            pcap_file(
                [
                    (1.0, tcp(there, 80, sequence=1000), True),
                    (1.1, answer(there, 80, sequence=5000, acknowledged=1001), False),
                    # Sent whole with the end of its connection, as what is
                    # written and shut in one go is
                    (
                        1.2,
                        tcp(there, 80, 0x19, asked, sequence=1001, acknowledged=5001),
                        True,
                    ),
                    # And a hello with the start of one, opened fast
                    (2.0, tcp(fast, 443, 0x02, client_hello("fast.test")), True),
                ]
            )
        )
        (request,) = found.requests
        assert (request.method, request.url) == ("POST", "http://plain.test/upload?x=1")
        assert found.names == {fast: "fast.test"}
        closed, opened = found.connections
        assert (closed.outcome, closed.sent) == ("closed", len(asked))
        assert (opened.address, opened.outcome) == (fast, "")

    def test_a_lookup_says_what_was_asked_and_what_came_back(self):
        found = self.read(pcap_file([(1.0, dns_failure("nope.test", 28), False)]))
        assert found.dns.lookups == [
            payloads.Lookup(1.0, "nope.test", "AAAA", (), "no such name")
        ]
        assert found.names == {}

    def test_a_damaged_file_is_read_as_far_as_it_goes(self):
        whole = sample_capture(1000.0)
        assert len(self.read(whole[:-30]).connections) == 3
        assert self.read(b"not a capture at all, really").packets == 0

    def test_a_dns_name_that_points_at_itself_ends(self):
        loop = struct.pack("!HHHHHH", 7, 0x8180, 1, 0, 0, 0) + b"\xc0\x0c"
        with pytest.raises(NotThis):
            payloads.dns_message(0.0, loop)


class ToldOfConnectionsTest:
    """What a capture tells of a connection besides where it went: who
    made it, what it asked a proxy for, whether its hello asks for the
    name it was reached by, and what is spoken on it."""

    THEM = "172.20.0.9"
    THERE = "198.51.100.7"
    PROXY = "172.20.0.2"

    def test_a_connection_made_to_the_session_is_read(self):
        them = self.THEM
        found = read_parts(
            [
                (10.0, knock(them, 8080, sequence=700), False),
                (10.0, taken_up(them, 8080, sequence=900, acknowledged=701), True),
                # 500 bytes from them by then, and 300 back
                (12.0, knock(them, 8080, 0x11, 1201, acknowledged=1201), False),
                (12.1, taken_up(them, 8080, 0x11, 1201, acknowledged=1202), True),
                # A port nothing waits on, which the session's kernel refuses
                (20.0, knock(them, 9000), False),
                (20.0, taken_up(them, 9000, 0x14), True),
                # And one never answered
                (30.0, knock(them, 9001, sequence=5), False),
                (31.0, knock(them, 9001, sequence=5), False),
                # From its own loopback, which nobody else reaches
                (40.0, knock("127.0.0.1", 8080), False),
            ]
        )
        assert found.connections == []
        taken, refused, unanswered = found.inbound
        assert (taken.address, taken.port, taken.source_port) == (them, 8080, 50000)
        assert (taken.outcome, taken.seconds) == ("closed", 2.1)
        assert (taken.sent, taken.received) == (300, 500)
        assert (refused.outcome, unanswered.outcome) == ("refused", "no answer")
        assert [what for _, what, _ in found.endings] == [
            "closed",
            "refused",
            "no answer",
        ]
        # What the session did on the network counts both ways
        assert found.carried() == (300, 500)

    def test_who_reached_the_session_is_a_line_of_its_own(self):
        them = self.THEM
        capture = read_parts(
            [
                (1.0, dns_response("other.test", them), False),
                (10.0, knock(them, 8080, sequence=700), False),
                (10.0, taken_up(them, 8080, sequence=900, acknowledged=701), True),
                (20.0, knock("172.20.0.77", 9000), False),
                (20.0, taken_up("172.20.0.77", 9000, 0x14), True),
            ]
        )
        taken, refused = net_events.capture_events(capture, verbose=False)
        assert taken.details == [
            "tcp IN from other.test (172.20.0.9) to its port 8080  left open"
        ]
        assert taken.fields["inbound"] is True
        assert (taken.fields["port"], taken.fields["peer_port"]) == (8080, 50000)
        # Nothing went wrong for the session when it took none
        assert refused.details == ["tcp IN from 172.20.0.77 to its port 9000  refused"]
        assert not layout.went_wrong(refused)
        said = net_events.capture_summary(capture, verbose=False)
        assert "  tcp IN from other.test (172.20.0.9) to its port 8080 x1" in said
        # The process that took it is the one that holds its socket
        record = processes.ProcessRecord()
        for line in (
            {"t": 9.0, "pid": 812, "ppid": 1, "exe": "/usr/bin/node", "argv": ["n"]},
            {"t": 10.0, "port": 8080, "to": them, "to_port": 50000, "pids": [812]},
        ):
            record.take(json.dumps(line))
        net_events.name_processes([taken], record)
        assert taken.notes == ["by: [812] node"]

    def connected(self, *sent: bytes, port: int = 443, to: str = "") -> list:
        """A connection to a port and what the session then sent on it,
        each thing after the last."""
        there = to or self.THERE
        packets = [
            (2.0, tcp(there, port, sequence=100), True),
            (2.0, answer(there, port, sequence=500, acknowledged=101), False),
        ]
        at = 101
        for number, payload in enumerate(sent):
            packet = tcp(there, port, 0x18, payload, sequence=at)
            packets.append((2.1 + number / 10, packet, True))
            at += len(payload)
        return packets

    def test_what_a_connection_asked_a_proxy_for_is_read(self):
        asked = b"CONNECT good.test:443 HTTP/1.1\r\nHost: good.test:443\r\n\r\n"
        capture = read_parts(
            [
                (1.0, dns_response("claude-egress-proxy", self.PROXY), False),
                *self.connected(
                    asked,
                    client_hello("good.test"),
                    # Within the tunnel, what reads as another request
                    b"CONNECT evil.test:443 HTTP/1.1\r\n\r\n",
                    port=3128,
                    to=self.PROXY,
                ),
            ]
        )
        (tunnel,) = capture.connections
        assert (tunnel.asked, tunnel.speaks) == ("good.test:443", "http")
        assert capture.noticed == []
        (event,) = net_events.capture_events(capture, verbose=False)
        where = "tcp/proxy claude-egress-proxy (172.20.0.2):3128"
        assert event.details == [f"{where}  asked for good.test:443  left open"]
        assert event.fields["asked"] == "good.test:443"

    def test_a_hello_for_another_name_than_the_proxy_was_asked_for_is_noted(self):
        asked = b"CONNECT good.test:443 HTTP/1.1\r\n\r\n"
        capture = read_parts(
            self.connected(asked, client_hello("evil.test"), port=3128, to=self.PROXY)
        )
        ((when, what, tunnel),) = capture.noticed
        assert what == "its hello asks for evil.test, it was reached as good.test"
        assert (when, tunnel.asked) == (2.2, "good.test:443")
        _, flagged = net_events.capture_events(capture, verbose=False)
        assert flagged.details == [f"tcp/proxy 172.20.0.2:3128  FLAGGED: {what}"]
        assert layout.went_wrong(flagged)
        assert flagged.fields["opened"] == 2.0
        # Not when what was asked of the proxy was not seen: the name of
        # the proxy is no name a hello would ask for
        unseen = read_parts(
            [
                (1.0, dns_response("claude-egress-proxy", self.PROXY), False),
                *self.connected(client_hello("good.test"), port=3128, to=self.PROXY),
            ]
        )
        assert unseen.noticed == []

    def test_a_hello_is_held_against_the_name_its_address_was_looked_up_under(self):
        looked_up = (1.0, dns_response("good.test", self.THERE), False)
        for hello, noted in (
            (client_hello("good.test"), []),
            (client_hello("GOOD.test"), []),
            (
                client_hello("other.test"),
                ["its hello asks for other.test, it was reached as good.test"],
            ),
            (
                client_hello(""),
                ["its hello names no server, it was reached as good.test"],
            ),
            # Cut before its end: it may name its server past the cut
            (client_hello("", ("h2", "http/1.1"))[:-4], []),
        ):
            capture = read_parts([looked_up, *self.connected(hello)])
            assert [what for _, what, _ in capture.noticed] == noted
        # An address that was not looked up has no name to hold it
        # against, the hello is all that names it
        bare = read_parts(self.connected(client_hello("other.test")))
        assert bare.noticed == []
        assert bare.names == {self.THERE: "other.test"}
        # Under any of the names the address was given
        both = read_parts(
            [
                looked_up,
                (1.5, dns_response("cdn.test", self.THERE), False),
                *self.connected(client_hello("good.test")),
            ]
        )
        assert both.noticed == []
        # A name that was only looked up after the hello is not one
        late = read_parts(
            [
                looked_up,
                *self.connected(client_hello("other.test")),
                (9.0, dns_response("other.test", self.THERE), False),
            ]
        )
        assert len(late.noticed) == 1

    def test_the_lookups_of_another_part_are_known_when_a_hello_is_held_up(self):
        # The lookups are in a part of their own, read after the hellos
        answered = dns_response("good.test", self.THERE)
        capture = read_parts(
            self.connected(client_hello("other.test")),
            dns=[(1.0, asked_for(answered), False), (1.0, answered, False)],
        )
        assert [what for _, what, _ in capture.noticed] == [
            "its hello asks for other.test, it was reached as good.test"
        ]

    def test_a_hello_without_a_name_is_noted_on_the_port_of_https_alone(self):
        looked_up = (1.0, dns_response("db.test", self.THERE), False)
        capture = read_parts([looked_up, *self.connected(client_hello(""), port=5432)])
        assert capture.noticed == []

    def test_what_a_hello_offers_to_speak_is_read(self):
        hello = payloads.tls_hello(client_hello("sni.test", ("h2", "http/1.1")))
        assert hello == payloads.Hello("sni.test", ("h2", "http/1.1"), whole=True)
        assert payloads.tls_hello(client_hello("")) == payloads.Hello("", (), True)
        assert payloads.tls_hello(b"GET / HTTP/1.1") is None
        assert payloads.tls_hello(client_hello("sni.test")[:30]) is None
        capture = read_parts(self.connected(client_hello("a.test", ("h2",))))
        (event,) = net_events.capture_events(capture, verbose=False)
        assert (event.fields["hello"], event.fields["offered"]) == ("a.test", ["h2"])
        assert event.fields["speaks"] == "tls"

    def test_what_the_first_bytes_of_a_connection_speak_is_told(self):
        for sent, speaks in (
            (client_hello("a.test"), "tls"),
            (b"SSH-2.0-OpenSSH_9.6\r\n", "ssh"),
            (b"GET / HTTP/1.1\r\n", "http"),
            (b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n", "http"),
            (b"\x00\x00\x00\x08\x04\xd2\x16\x2f and more", "other"),
            # Something else that begins as a record of TLS does
            (b"\x16\x03\x01\x00\x05\x02 and more", "other"),
            # Too few bytes to tell
            (b"GET", ""),
            (b"\x16\x03", ""),
        ):
            assert payloads.spoken(sent) == speaks

    def test_a_port_that_speaks_something_else_than_its_use_is_noted(self):
        banner = b"SSH-2.0-OpenSSH_9.6\r\n"
        for port, sent, noted in (
            (443, banner, ["speaks SSH, not TLS"]),
            (443, b"here is what I found: " * 3, ["does not speak TLS"]),
            (80, banner, ["speaks SSH, not HTTP"]),
            (22, client_hello("a.test"), ["speaks TLS, not SSH"]),
            (22, banner, []),
            (80, b"GET / HTTP/1.1\r\n\r\n", []),
            # A port without a use that is beyond doubt
            (UNNAMED, banner, []),
        ):
            # What a connection sends first is in the part of what is
            # sent, by its headers and the bytes after them
            opened = self.connected(port=port)
            first = (2.1, tcp(self.THERE, port, 0x18, sent, sequence=101), True)
            capture = read_parts(opened, elsewhere=[first])
            assert [what for _, what, _ in capture.noticed] == noted, port
        # Only the first bytes are looked at, whatever comes later
        later = (2.1, tcp(self.THERE, 443, 0x18, banner, sequence=4000), True)
        capture = read_parts(self.connected(), elsewhere=[later])
        assert (capture.noticed, capture.connections[0].speaks) == ([], "")

    def test_what_is_spoken_is_said_where_the_port_does_not(self):
        port = UNNAMED
        capture = read_parts(self.connected(client_hello("a.test"), port=port))
        (event,) = net_events.capture_events(capture, verbose=False)
        assert event.details[0].startswith(
            f"tcp a.test (198.51.100.7):{port}  speaks TLS  left open"
        )
        # Not where the port says it
        usual = read_parts(self.connected(client_hello("a.test")))
        (event,) = net_events.capture_events(usual, verbose=False)
        assert "speaks" not in event.details[0]

    def test_a_connection_left_open_says_how_much_it_carried_at_least(self):
        there = self.THERE
        sent = [
            (
                3.0 + at / 100,
                tcp(there, 443, 0x18, b"x" * 1000, sequence=101 + at * 1000),
                True,
            )
            for at in range(5)
        ]
        came = [
            (4.0, answer(there, 443, 0x18, 501 + (1 << 24), 5101, b"y" * 400), False)
        ]
        capture = read_parts(self.connected(), elsewhere=sent, downloads=came)
        (left,) = capture.connections
        assert left.so_far == (5000, (1 << 24) + 400)
        (event, _) = net_events.capture_events(capture, verbose=False)
        said = "tcp/https 198.51.100.7:443  left open, at least 5 kB out, 17 MB in"
        assert event.details == [f"{said}, 1 uploads"]
        assert capture.carried() == (5000, (1 << 24) + 400)
        # What ended it says how much it carried, the packets before do not
        ended = [
            *self.connected(),
            (9.0, tcp(there, 443, 0x11, b"", 6101, 901), True),
            (9.1, answer(there, 443, 0x11, 901, 6102), False),
        ]
        closed = read_parts(ended, elsewhere=sent)
        assert closed.carried() == (6000, 400)

    def test_what_was_sent_early_is_not_read_as_gigabytes_further_on(self):
        # The parts are read one after the other, each from its start: a
        # packet of the first minute comes after those of every gigabyte
        there, giga = self.THERE, 1 << 30
        sampled = [
            (
                20.0 + at,
                answer(there, 443, 0x10, 501 + at * giga, 601, b"y" * 1000),
                False,
            )
            for at in range(1, 4)
        ]
        early = tcp(there, 443, 0x18, b"x" * 500, sequence=101, acknowledged=501)
        capture = read_parts(
            [*self.connected(), *sampled], elsewhere=[(3.0, early, True)]
        )
        (left,) = capture.connections
        assert left.so_far == (500, 3 * giga + 1000)
        assert capture.carried() == (500, 3 * giga + 1000)

    def test_a_hello_is_held_against_nothing_when_lookups_may_be_missing(self):
        # An address many sites share is looked up under one name, then
        # another: with the second lookup lost, a hello for it would
        # read as one for a name the address never had
        packets = [
            (1.0, dns_response("files.test", self.THERE), False),
            *self.connected(client_hello("pypi.test")),
        ]
        assert len(read_parts(packets).noticed) == 1
        # The recorder of the capture ended early, or lost packets
        assert read_parts(packets, whole=False).noticed == []
        # Or the part that has the lookups ran into its limit
        answered = dns_response("files.test", self.THERE)
        looked_up = [(1.0, asked_for(answered), False), (1.0, answered, False)]
        with unittest.mock.patch.object(capture_module, "PACKET_LIMIT", 2):
            cut = read_parts(packets[1:], dns=looked_up)
        assert (cut.lookups_whole, cut.noticed) == (False, [])
        assert cut.names == {self.THERE: "files.test"}

    def test_whether_an_address_had_a_name_is_told_without_going_through_them(self):
        looked_up = lookups_module.LookedUp()
        for at in range(50_000):
            looked_up.add(float(at), f"N{at}.Test.")
        started = time.monotonic()
        for at in range(50_000):
            assert looked_up.had(f"n{at}.test", at + 0.5)
        assert time.monotonic() - started < 5
        assert not looked_up.had("n7.test", 6.5)
        assert not looked_up.had("other.test", 1e9)

    def test_what_is_sent_before_its_connection_is_read_is_looked_at_again(self):
        # As a capture grows, the part that has what is sent is read a
        # moment after the one that has what starts a connection
        banner = tcp(self.THERE, 443, 0x18, b"SSH-2.0-OpenSSH_9.6\r\n", sequence=101)
        capture = pcap.Capture()

        def take(packets: list, part: str) -> None:
            frames = PcapReader().feed(pcap_file(packets, asked=False))
            pcap.take_frames(capture, frames, part)

        take([(2.1, banner, True)], "elsewhere")
        capture.look_at_hellos()
        assert capture.noticed == []
        take(self.connected(), "tcp")
        capture.look_at_hellos()
        assert [what for _, what, _ in capture.noticed] == ["speaks SSH, not TLS"]
        assert capture.connections[0].so_far == (21, 0)
        # No more of it is kept for that than a little, nor for long
        for port in range(1000, 1000 + 2 * pcap.MOST_UNPLACED):
            take([(3.0, tcp(self.THERE, port, 0x18, b"x" * 20, 1), True)], "elsewhere")
        assert len(capture._unplaced) == pcap.MOST_UNPLACED
        for _ in range(pcap.LATE_TRIES + 1):
            capture.look_at_hellos()
        assert capture._unplaced == []

    def test_what_the_session_sends_to_who_connected_to_it_is_counted(self):
        them = self.THEM
        sent = [
            (
                11.0 + at / 100,
                taken_up(them, 8080, 0x18, 901 + at * 1000, 701, b"x" * 1000),
                True,
            )
            for at in range(5)
        ]
        capture = read_parts(
            [
                (10.0, knock(them, 8080, sequence=700), False),
                (10.0, taken_up(them, 8080, sequence=900, acknowledged=701), True),
            ],
            elsewhere=sent,
        )
        (taken,) = capture.inbound
        assert taken.so_far == (5000, 0)
        assert capture.carried() == (5000, 0)
        (event,) = net_events.capture_events(capture, verbose=False)
        made = "tcp IN from 172.20.0.9 to its port 8080"
        assert event.details == [f"{made}  left open, at least 5 kB out, 1 uploads"]
        # What is spoken is told of the connections the session makes
        assert (taken.speaks, capture.noticed) == ("", [])


class DnsTrustTest:
    """What is taken for a name of an address: only what the resolver said
    of what the session asked it."""

    def read(self, packets: list[tuple[float, bytes, bool]], asked: bool = True):
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory, "capture.pcap")
            file.write_bytes(pcap_file(packets, asked=asked))
            return pcap.read_capture(file)

    def test_an_answer_from_somewhere_else_on_loopback_names_nothing(
        self, subtests: pytest.Subtests
    ):
        for source in ("127.0.0.1", "127.0.0.2"):
            forged = ipv4(
                17, source, "127.0.0.1", dns_response("a.test", "6.6.6.6")[20:]
            )
            for sent in (True, False):
                with subtests.test(source=source, sent=sent):
                    found = self.read(
                        [
                            (0.5, dns_query("a.test"), True),
                            (1.0, forged, sent),
                            (2.0, tcp("6.6.6.6", 443), True),
                        ],
                        asked=False,
                    )
                    assert found.names == {}
                    assert found.dns.lookups[0].error == "no answer"

    def test_no_more_lookups_are_kept_than_a_capture_may_have(self):
        packets = []
        for number in range(5):
            name = f"n{number}.test"
            packets += [
                (number + 0.1, dns_query(name), True),
                (number + 0.2, dns_response(name, "6.6.6.6"), False),
            ]
        with unittest.mock.patch.object(lookups_module, "MOST_LOOKUPS", 2):
            found = self.read(packets, asked=False)
        assert [lookup.name for lookup in found.dns.lookups] == ["n0.test", "n1.test"]
        # The messages past them are counted, and said
        assert found.dns.unread == 6
        said = net_events.capture_summary(found, False)
        assert (
            "  dns 6 more messages NOT READ, past the 2 lookups that are kept" in said
        )

    def test_no_more_messages_are_read_than_a_capture_may_have(self):
        def over(payload: bytes, sent: bool = True) -> bytes:
            ports, ends = (40053, 53), ("172.20.0.5", "9.9.9.9")
            if not sent:
                ports, ends = ports[::-1], ends[::-1]
            header = segment(ports, 0x18)
            return ipv4(6, *ends, header + payload)

        query = dns_message_of(dns_query("after.test"))
        response = dns_message_of(dns_response("after.test", "198.51.100.7"))
        # A hundred messages of no length at all ahead of a query: a
        # resolver passes them over and answers the query
        none = b"\0" * 200
        packets = [
            (1.0, over(none + struct.pack("!H", len(query)) + query), True),
            (1.1, over(struct.pack("!H", len(response)) + response, sent=False), False),
        ]
        found = self.read(packets, asked=False)
        assert found.name_of("198.51.100.7") == "after.test"
        assert found.dns.unread == 0
        # Past as many as are read, what is left of a packet is counted
        # as one message that was not, and no longer looked into
        with unittest.mock.patch.object(lookups_module, "MOST_DNS_READ", 50):
            found = self.read(packets, asked=False)
            assert (found.dns.lookups, found.dns.unread) == ([], 2)
            flood = pcap.parse_packet(
                1.0, 276, pcap_file([(1.0, over(none), True)])[40:]
            )
            capture = pcap.Capture()
            with unittest.mock.patch.object(
                lookups_module, "dns_message", wraps=payloads.dns_message
            ) as read:
                for _ in range(300):
                    capture.add(flood)
        assert read.call_count == 50
        assert capture.dns.unread == 300
        said = net_events.capture_summary(capture, False)
        assert (
            "  dns 300 more messages NOT READ, past the 0 lookups that are kept" in said
        )

    def test_the_addresses_of_an_answer_are_read_once_it_is_one_that_was_asked(self):
        response = dns_response("a.test", "6.6.6.6")
        message = dns_message_of(response)
        assert payloads.dns_message(1.0, message).lookup.addresses == ("6.6.6.6",)
        unread = payloads.dns_message(1.0, message, answered=False)
        assert (unread.lookup.name, unread.lookup.addresses) == ("a.test", ())
        with unittest.mock.patch.object(
            lookups_module, "dns_message", wraps=payloads.dns_message
        ) as read:
            # A session can send any number of answers nobody asked for
            self.read([(1.0, response, False)], asked=False)
            assert [call.kwargs for call in read.call_args_list] == [
                {"answered": False}
            ]
            found = self.read([(1.0, response, False)])
        assert found.name_of("6.6.6.6") == "a.test"

    def test_an_answer_nobody_asked_for_names_nothing(self):
        found = self.read(
            [(1.0, dns_response("a.test", "6.6.6.6"), False)], asked=False
        )
        assert found.names == {}
        assert found.dns.lookups == []
        # Nor one for another name, or with another id
        for query in (dns_query("b.test"), dns_query("a.test", ident=9)):
            found = self.read(
                [(0.5, query, True), (1.0, dns_response("a.test", "6.6.6.6"), False)],
                asked=False,
            )
            assert found.names == {}

    def test_what_is_looked_up_later_does_not_rename_what_was_reached(self):
        found = self.read(
            [
                (1.0, dns_response("good.test", "198.51.100.7"), False),
                (2.0, tcp("198.51.100.7", 443), True),
                (3.0, dns_response("github.com", "198.51.100.7"), False),
            ]
        )
        address = "198.51.100.7"
        assert found.name_of(address, 0.5) is None
        assert found.name_of(address, 2.0) == "good.test"
        assert found.name_of(address, 3.5) == "github.com"
        assert found.name_of(address) == "github.com"
        # What the hello says is only for what has no answer before it
        assert (
            self.read(
                [
                    (1.0, tcp("203.0.113.9", 443, 24, client_hello("sni.test")), True),
                    (2.0, dns_response("later.test", "203.0.113.9"), False),
                ]
            ).name_of("203.0.113.9", 1.0)
            == "sni.test"
        )

    def test_a_query_that_was_never_answered_is_a_lookup_without_one(self):
        found = self.read([(1.0, dns_query("lost.test", 28), True)], asked=False)
        (lookup,) = found.dns.lookups
        assert (
            lookup.when,
            lookup.name,
            lookup.kind,
            lookup.addresses,
            lookup.error,
        ) == (1.0, "lost.test", "AAAA", (), "no answer")

    def test_a_query_is_given_up_on_as_the_capture_goes_on(self):
        capture = pcap.Capture()
        pcap.take_frames(
            capture,
            PcapReader().feed(
                pcap_file([(1.0, dns_query("slow.test"), True)], asked=False)
            ),
        )
        assert capture.dns.lookups == []
        later = pcap_file([(20.0, dns_query("other.test"), True)], asked=False)
        pcap.take_frames(capture, PcapReader().feed(later))
        assert [lookup.name for lookup in capture.dns.lookups] == ["slow.test"]
        # The answer when it does come is still the answer
        late = pcap_file(
            [(21.0, dns_response("slow.test", "198.51.100.7"), False)], asked=False
        )
        pcap.take_frames(capture, PcapReader().feed(late))
        assert capture.name_of("198.51.100.7", 22.0) == "slow.test"

    def test_an_answer_cut_short_by_the_capture_keeps_what_came_before(self):
        name = "big.test"
        labels = b"".join(bytes([len(p)]) + p.encode() for p in name.split("."))
        question = labels + b"\x00" + struct.pack("!HH", 1, 1)
        addresses = [f"198.51.100.{n}" for n in range(1, 6)]
        records = b"".join(
            b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton(a)
            for a in addresses
        )
        message = struct.pack("!HHHHHH", 7, 0x8180, 1, 5, 0, 0) + question + records
        # Cut in the middle of the fourth record
        cut = message[: len(message) - 16 - 5]
        datagram = struct.pack("!HHHH", 41234, 50000, 8 + len(cut), 0) + cut
        found = self.read([(1.0, ipv4(17, "127.0.0.11", "127.0.0.1", datagram), False)])
        (lookup,) = found.dns.lookups
        assert lookup.addresses == tuple(addresses[:3])
        assert found.name_of(addresses[0]) == name

    def test_dns_over_tcp_is_read(self):
        query = dns_message_of(dns_query("tcp.test"))
        response = dns_message_of(dns_response("tcp.test", "198.51.100.7"))
        packets = [
            (1.0, dns_over("127.0.0.1", "127.0.0.11", query, (40000, 53)), True),
            (1.1, dns_over("127.0.0.11", "127.0.0.1", response, (53, 40000)), False),
        ]
        found = self.read(packets, asked=False)
        assert found.name_of("198.51.100.7") == "tcp.test"
        assert [lookup.name for lookup in found.dns.lookups] == ["tcp.test"]
        # The same from somewhere that is not a resolver, by no port of one
        elsewhere = [
            (1.0, dns_over("127.0.0.1", "127.0.0.1", query, (40000, 5353)), True),
            (1.1, dns_over("127.0.0.1", "127.0.0.1", response, (5353, 40000)), True),
        ]
        assert self.read(elsewhere, asked=False).dns.lookups == []

    def test_dns_over_tcp_is_read_however_it_is_cut_into_packets(self):
        def over(payload: bytes, ports: tuple[int, int], at: str, to: str) -> bytes:
            header = segment(ports, 0x18)
            return ipv4(6, at, to, header + payload)

        me, server = "172.20.0.5", "9.9.9.9"
        query = dns_message_of(dns_query("split.test"))
        second = dns_message_of(dns_query("second.test", ident=8))
        response = dns_message_of(dns_response("split.test", "198.51.100.7"))
        asked = struct.pack("!H", len(query)) + query
        asked += struct.pack("!H", len(second)) + second
        said = struct.pack("!H", len(response)) + response
        for cuts in ([2], [1, 2, 9], [2, len(query) + 2], [len(asked) - 3]):
            pieces = [
                asked[a:b] for a, b in zip([0, *cuts], [*cuts, None], strict=True)
            ]
            packets = [
                (1.0 + at, over(piece, (40053, 53), me, server), True)
                for at, piece in enumerate(pieces)
            ]
            # The answer too, its length on its own
            packets += [
                (9.0, over(said[:2], (53, 40053), server, me), False),
                (9.1, over(said[2:], (53, 40053), server, me), False),
            ]
            found = self.read(packets, asked=False)
            assert found.name_of("198.51.100.7") == "split.test", cuts
            assert [(lookup.name, lookup.error) for lookup in found.dns.lookups] == [
                ("split.test", ""),
                ("second.test", "no answer"),
            ], cuts
        # What is kept of a stream until its rest comes is bounded
        capture = pcap.Capture()
        for port in range(lookups_module.DNS_MOST_HELD + 50):
            frame = over(b"\x40\x00" + b"x" * 100, (1024 + port, 53), me, server)
            packet = pcap.parse_packet(1.0, 276, pcap_file([(1.0, frame, True)])[40:])
            capture.add(packet)
        assert len(capture.dns._held) == lookups_module.DNS_MOST_HELD
        # And each one let go of is counted: its query went unread
        assert capture.dns.cut == 50

    def test_dns_over_tcp_that_cannot_be_read_to_its_end_is_counted(self):
        def over(payload: bytes, ports: tuple[int, int], at: str, to: str) -> bytes:
            header = segment(ports, 0x18)
            return ipv4(6, at, to, header + payload)

        def packet_of(frame: bytes, sent: bool) -> pcap.Packet:
            return pcap.parse_packet(1.0, 276, pcap_file([(1.0, frame, sent)])[40:])

        me, server = "172.20.0.5", "9.9.9.9"
        query = dns_message_of(dns_query("harmless.test"))
        hidden = dns_message_of(dns_query("secret.evil.test", ident=8))
        first = struct.pack("!H", len(query) + 900) + query + b"\0" * 900
        second = struct.pack("!H", len(hidden)) + hidden
        # A query behind one that is padded past what the capture keeps
        # of a packet: only the first is seen, and that is said
        whole = packet_of(over(first + second, (40053, 53), me, server), True)
        kept = dataclasses.replace(whole, payload=whole.payload[:950])
        capture = pcap.Capture()
        capture.add(kept)
        capture.dns.finish()
        assert [lookup.name for lookup in capture.dns.lookups] == ["harmless.test"]
        assert capture.dns.cut == 1
        said = net_events.capture_summary(capture, False)
        assert (
            "  dns 1 times what was sent to a resolver over TCP was NOT READ to"
            " its end, too long for the capture: a lookup may be missing each time"
        ) in said
        # And a message longer than is held until its rest comes, sent a
        # little at a time
        long = struct.pack("!H", 6000) + hidden + b"\0" * (6000 - len(hidden))
        capture = pcap.Capture()
        for at in range(0, len(long), 900):
            capture.add(
                packet_of(over(long[at : at + 900], (40053, 53), me, server), True)
            )
        assert capture.dns.lookups == []
        assert capture.dns.cut >= 1
        # Not what comes back too long: its query was seen, and is a
        # lookup that says it has no answer
        capture = pcap.Capture()
        capture.add(packet_of(dns_over(me, server, query, (40053, 53)), True))
        back = packet_of(over(b"\x20\x00" + b"x" * 990, (53, 40053), server, me), False)
        capture.add(dataclasses.replace(back, payload=back.payload[:950]))
        capture.dns.finish()
        assert capture.dns.cut == 0
        assert [(found.name, found.error) for found in capture.dns.lookups] == [
            ("harmless.test", "no answer")
        ]
        # A hello is not held against lookups that are not all there
        assert (
            pcap.Capture(dns=lookups_module.Lookups(cut=1))._reached_otherwise(
                pcap.Connection(1.0, "198.51.100.7", 443, 40443, 0), "x.test", 2.0
            )
            == ""
        )

    def test_each_part_of_a_capture_counts_its_own_packets(self):
        capture = pcap.Capture()
        frames = list(PcapReader().feed(sample_capture(1000.0)))
        pcap.take_frames(capture, frames, "tcp")
        pcap.take_frames(capture, frames[:2], "dns")
        assert capture.part_packets == {"tcp": len(frames), "dns": 2}
        assert capture.packets == len(frames) + 2
        limit = capture_module.PACKET_LIMIT
        assert not capture_module.cut_short(capture)
        capture.part_packets["dns"] = limit
        assert capture_module.cut_short(capture)
        # Many packets in all, none of the parts at its limit
        capture.part_packets = {"tcp": limit - 1, "dns": limit - 1, "flows": limit - 1}
        assert not capture_module.cut_short(capture)

    def test_the_parts_are_read_together_and_one_that_is_missing_is_passed_over(self):
        with tempfile.TemporaryDirectory() as directory:
            main, dns = Path(directory, "a.pcap"), Path(directory, "a.pcap.dns")
            main.write_bytes(pcap_file([(2.0, tcp("198.51.100.7", 443), True)]))
            dns.write_bytes(
                pcap_file([(1.0, dns_response("good.test", "198.51.100.7"), False)])
            )
            found = pcap.read_capture(main, [dns, Path(directory, "a.pcap.flows")])
        assert found.name_of("198.51.100.7", 2.0) == "good.test"
        assert found.part_packets == {"tcp": 1, "dns": 2}

    def test_loopback_is_not_what_the_filter_takes_of_udp(self):
        filters = {part.name: part.filter for part in capture_module.PARTS}
        assert "udp and net 127" not in filters["dns"]
        assert "host 127.0.0.11" in filters["dns"]
        for name in ("tcp", "flows"):
            assert "(udp and net 127.0.0.0/8)" not in filters[name]
        # No packet is in two parts, the reader would take it for two
        assert "outbound" not in filters["tcp"]
        assert filters["flows"].startswith("not port 53 and not host 127.0.0.11 and (")
        # Of port 53 the TCP part has what starts and ends a connection,
        # the rest is the part's of what is asked there directly
        assert filters["tcp"].startswith("not host 127.0.0.11 and (")
        assert " or (not port 53 and (" in filters["tcp"]
        assert filters["direct"].startswith("port 53 and not host 127.0.0.11 and not")
        assert "tcp-syn|tcp-fin|tcp-rst" in filters["direct"]
        for name in ("tcp", "flows"):
            assert filters[name].endswith(")")

    def test_queries_never_answered_do_not_keep_later_answers_out(self):
        most = lookups_module.DNS_MOST_PENDING
        lost = [
            (1.0, dns_query(f"n{number}.lost.test", ident=number % 65536), True)
            for number in range(most + 5)
        ]
        found = self.read(
            [*lost, (2.0, dns_response("good.test", "198.51.100.7"), False)]
        )
        assert found.name_of("198.51.100.7") == "good.test"
        # Each of them is still said to have had no answer, once
        unanswered = [lookup for lookup in found.dns.lookups if lookup.error]
        assert len(unanswered) == most + 5


class OtherTrafficTest:
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
        assert (connection.address, connection.port) == (self.THEM, 443)
        assert connection.outcome == "open"
        assert found.names == {self.THEM: "six.test"}

    def test_headers_ahead_of_the_transport_do_not_hide_it(self):
        options = bytes([6, 0, 1, 4, 0, 0, 0, 0])
        behind = ipv6(60, self.ME, self.THEM, options + tcp_header(443, 0x02))
        (connection,) = self.read([(1.0, behind, True)]).connections
        assert (connection.address, connection.port) == (self.THEM, 443)
        # A chain of them without an end is not followed for ever
        looped = ipv6(0, self.ME, self.THEM, bytes([0, 0, 1, 4, 0, 0, 0, 0]) * 20)
        assert self.read([(1.0, looped, True)]).flows == []

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
        assert [
            (f.when, f.transport, f.address, f.port, f.packets, f.sent)
            for f in found.flows
        ] == [
            (1.0, "udp", "198.51.100.7", 443, 2, 216),
            (2.5, "udp", self.THEM, 443, 1, 108),
        ]
        assert found.connections == []

    def test_a_ping_is_a_flow_and_the_kernels_own_icmp_is_not(self):
        echo = ipv4(1, "172.20.0.5", "198.51.100.7", b"\x08\x00" + bytes(62))
        unreachable = ipv4(1, "172.20.0.5", "198.51.100.7", b"\x03\x01" + bytes(30))
        neighbour = ipv6(58, self.ME, "ff02::1", b"\x87\x00" + bytes(22))
        (flow,) = self.read(
            [(1.0, echo, True), (2.0, unreachable, True), (3.0, neighbour, True)]
        ).flows
        assert (flow.transport, flow.port, flow.sent) == ("icmp", 0, 64)

    def test_a_later_fragment_is_counted_without_ports(self):
        later = bytearray(ipv4(17, "172.20.0.5", "198.51.100.7", b"y" * 40))
        later[6:8] = struct.pack("!H", 185)
        (flow,) = self.read([(1.0, bytes(later), True)]).flows
        assert (flow.port, flow.sent) == (0, 40)

    def test_another_protocol_is_named_by_its_number(self):
        (flow,) = self.read(
            [(1.0, ipv4(99, "172.20.0.5", "198.51.100.7", b"z" * 10), True)]
        ).flows
        assert (flow.transport, flow.port) == ("ip-99", 0)

    def test_a_long_name_is_flagged_once(self):
        name = "a" * 50 + ".t.test"
        packets = [(float(at), dns_failure(name), False) for at in range(3)]
        found = self.read([*packets, (5.0, dns_failure("fine.t.test"), False)])
        assert [(why, lookup.name) for why, lookup in found.dns.flagged] == [
            ("an unusually long name", name)
        ]

    def test_many_names_under_one_domain_are_flagged_whatever_is_between(self):
        count = lookups_module.DNS_MANY_UNDER_DOMAIN

        def lookups(names: list[str]) -> list[tuple[float, bytes, bool]]:
            return [(1.0, dns_response(name, "198.51.100.7"), False) for name in names]

        # No two of them under one parent, all of them under one domain
        varied = [f"data{n}.part{n}.evil.test" for n in range(count + 5)]
        assert self.read(lookups(varied[: count - 1])).dns.flagged == []
        ((why, lookup),) = self.read(lookups(varied)).dns.flagged
        assert why == f"{count} names looked up under evil.test"
        assert lookup.name == varied[count - 1]
        # Under a country a domain has a label more: not every site of it
        sites = [f"www.site{n}.co.uk" for n in range(count + 5)]
        assert self.read(lookups(sites)).dns.flagged == []
        deeper = [f"a{n}.b{n}.evil.co.uk" for n in range(count)]
        ((why, _),) = self.read(lookups(deeper)).dns.flagged
        assert why == f"{count} names looked up under evil.co.uk"
        # Names right under their domain are counted once, by their parent
        flat = [f"n{n}.evil.test" for n in range(count + 5)]
        ((why, _),) = self.read(lookups(flat)).dns.flagged
        assert why == f"{lookups_module.DNS_MANY_NAMES} names looked up under evil.test"

    def test_many_names_under_one_parent_are_flagged(self):
        count = lookups_module.DNS_MANY_NAMES
        few = [(1.0, packet, False) for packet in lookups_under("cdn.test", count - 1)]
        assert self.read(few).dns.flagged == []
        many = [(1.0, packet, False) for packet in lookups_under("t.test", count + 5)]
        # Not under a parent of one label, every name is under com
        many += [
            (2.0, dns_response(f"site{n}.test", "198.51.100.7"), False)
            for n in range(count + 5)
        ]
        ((why, lookup),) = self.read(many).dns.flagged
        assert why == f"{count} names looked up under t.test"
        assert lookup.name == f"n{count - 1}.t.test"


class CaptureSessionTest(LauncherTest):
    SIDECAR = "claude-proj.capture"

    @pytest.fixture(autouse=True)
    def capture_file_made(self, sandbox: None) -> None:
        self.now = time.time()
        self.capture_file = self.work / "capture.pcap"
        self.capture_file.write_bytes(sample_capture(self.now))

    def captured(self, *args: str, **env: str) -> Result:
        return self.launch(
            *args,
            CLAUDE_AIRLOCK_NET_LOG="1",
            FAKE_CAPTURE=str(self.capture_file),
            **env,
        )

    def test_the_session_joins_a_sidecar_that_captures(self):
        result = self.captured()
        assert f"--network=container:{self.SIDECAR}" in result.flags
        sidecar = result.sidecar(self.SIDECAR)
        for flag in (
            "--network=claude-airlock-open-net",
            "--cap-drop=ALL",
            "--cap-add=NET_RAW",
            "--entrypoint=sh",
        ):
            assert flag in sidecar
        # It runs tcpdump and outlives it: the session's way out is the
        # sidecar's, and would go with one that ended at its packet limit
        script = sidecar[sidecar.index("-c") + 1]
        assert script.count("tcpdump $common") == len(capture_module.PARTS) == 8
        # Of what is sent somewhere the headers alone, and of what comes
        # in no more than says where a packet is in its stream. What the
        # model sends back comes in many packets, its part takes more
        own = {
            "uploads": " -s 160",
            "elsewhere": " -s 160",
            "answers": " -s 96 -c 200000",
            "downloads": " -s 96",
        }
        for number, part in enumerate(capture_module.PARTS, 1):
            started = f"tcpdump $common{own.get(part.name, '')} -w {part.file}"
            assert f'{started} "${number}" &' in script
            assert f'check {part.name} {part.file} "${part.name}"' in script
        stopped = '"$tcp" "$dns" "$direct" "$flows" "$uploads" "$elsewhere"'
        stopped += ' "$answers" "$downloads"'
        assert f"trap 'kill {stopped} 2>" in script
        assert "while :" in script
        # A tcpdump for each part, and the filter of each after the script
        filters = sidecar[sidecar.index("sh", sidecar.index("-c")) + 1 :]
        assert filters == [part.filter for part in capture_module.PARTS]
        assert result.calls.index(sidecar) < next(
            i for i, c in enumerate(result.calls) if c[0] == "run" and c != sidecar
        )

    def test_a_filtered_session_is_captured_inside_the_filter(self):
        result = self.captured(CLAUDE_AIRLOCK_NET_FILTER="1", FAKE_IP="172.20.0.5")
        sidecar = result.sidecar(self.SIDECAR)
        assert "--network=claude-airlock-net" in sidecar
        assert "--dns=127.0.0.1" in sidecar
        assert f"--network=container:{self.SIDECAR}" in result.flags
        assert "--dns=127.0.0.1" not in result.flags
        assert "--env=HTTPS_PROXY=http://claude-egress-proxy:3128" in result.flags
        sessions = (self.state / "net-sessions.jsonl").read_text()
        assert '"ip": "172.20.0.5"' in sessions

    def test_capturing_is_the_default(self):
        assert settings.load_settings({}, str(self.work / "none")).net_log

    def test_switched_off_nothing_is_captured(self):
        result = self.launch()
        assert result.sidecar(self.SIDECAR) is None
        assert "--network=claude-airlock-open-net" in result.flags

    def test_the_capture_is_copied_out_and_the_sidecar_removed(self):
        result = self.captured()
        (copied,) = (self.state / "captures").glob("*.pcap")
        assert copied.read_bytes() == self.capture_file.read_bytes()
        (session,) = map(
            json.loads, (self.state / "net-sessions.jsonl").read_text().splitlines()
        )
        assert session["capture"] == copied.name
        assert session["project"] == str(self.project)
        ending = [c[0] for c in result.calls if self.SIDECAR in c[-1] or c[0] == "cp"]
        stopped = ending.index("stop")
        # Copied out and asked what its tcpdumps said, once it is stopped
        after = ending[stopped + 1 : -1]
        assert sorted(after) == ["cp"] * (len(after) - 1) + ["logs"]
        assert ending[-1] == "rm"

    def test_the_other_parts_are_copied_out_beside_the_main_one(self):
        dns = self.work / "dns.pcap"
        dns.write_bytes(
            pcap_file([(self.now + 1, dns_response("a.test", "192.0.2.9"), False)])
        )
        self.captured(FAKE_CAPTURE_DNS=str(dns))
        (main,) = (self.state / "captures").glob("*.pcap")
        beside = sorted(p.name for p in (self.state / "captures").iterdir())
        # No file of the flows part: it wrote none
        assert beside == [main.name, main.name + ".dns"]
        assert (main.parent / (main.name + ".dns")).read_bytes() == dns.read_bytes()
        self.write_transcript("0a", prompts_at(self.now, self.now + 10))
        assert "lookup a.test" in self.launch("--trace", "--verbose").stdout

    def test_parts_whose_capture_was_let_go_of_are_let_go_of(self):
        captures = self.state / "captures"
        captures.mkdir(parents=True, exist_ok=True)
        (captures / "claude-gone-1.pcap.dns").write_bytes(b"x")
        (captures / "claude-kept-2.pcap").write_bytes(b"x")
        (captures / "claude-kept-2.pcap.dns").write_bytes(b"x")
        self.captured()
        assert not (captures / "claude-gone-1.pcap.dns").exists()
        assert (captures / "claude-kept-2.pcap.dns").exists()

    def test_a_tcpdump_that_died_is_said_in_the_record_and_the_trace(self):
        self.captured(FAKE_CAPTURE_DIED="dns:137")
        (session,) = map(
            json.loads, (self.state / "net-sessions.jsonl").read_text().splitlines()
        )
        assert session["stopped"] == "dns (status 137)"
        self.write_transcript("0a", prompts_at(self.now, self.now + 10))
        stdout = self.launch("--trace").stdout
        assert "INCOMPLETE, a recorder ended before the session did" in stdout
        assert "dns (status 137)" in stdout

    def test_packets_the_kernel_dropped_are_counted_in_the_record(self):
        # What each tcpdump says as it ends, the four of them together
        said = (
            "tcpdump: listening on any, link-type LINUX_SLL2 (Linux cooked v2),"
            " snapshot length 1024 bytes\n"
            "812 packets captured\n830 packets received by filter\n"
            "12 packets dropped by kernel\n"
            "3 packets captured\n3 packets received by filter\n"
            # One whose end came after the start of the next one's line
            "0 packets dropped by kernel40 packets captured\n\n"
            "41 packets received by filter\n1 packet dropped by kernel\n"
            "0 packets captured\n0 packets received by filter\n"
            "0 packets dropped by kernel\n"
        )
        assert capture_module.dropped_packets(said) == 13
        assert capture_module.dropped_packets("") == 0
        assert capture_module.dropped_packets("7 packets dropped by interface\n") == 0
        output = self.work / "said"
        output.write_text(said)
        self.captured(FAKE_PROXY_LOG=str(output))
        (session,) = records.read_traced_sessions(self.host)
        assert session.dropped == 13
        # Said in a trace of the session, and when it ends
        self.write_transcript("0a", prompts_at(self.now, self.now + 10))
        said = "its capture is INCOMPLETE, 13 packets came faster than they were taken"
        assert f"#   {said}: what they told of is missing\n" in (
            self.launch("--trace").stdout
        )
        (asked,) = (call for call in self.calls() if call[0] == "logs")
        assert asked[1:] == [f"--tail={capture_module.SAID_LINES}", self.SIDECAR]
        # Nothing of it for a capture that took all there was
        output.write_text("0 packets dropped by kernel\n" * 4)
        self.captured(FAKE_PROXY_LOG=str(output))
        line = (self.state / "net-sessions.jsonl").read_text().splitlines()[-1]
        assert "dropped" not in line
        # Nor from a line of the record that does not hold up
        for dropped in ('"many"', "-5", "true", "[13]"):
            kept = records.TracedSession.from_line(
                line[:-1] + f', "dropped": {dropped}' + "}"
            )
            assert kept is not None
            assert kept.dropped == 0

    def test_a_tcpdump_that_ended_at_its_limit_is_not_a_death(self):
        self.captured(FAKE_CAPTURE_DIED="dns:0")
        (session,) = map(
            json.loads, (self.state / "net-sessions.jsonl").read_text().splitlines()
        )
        assert "stopped" not in session

    def test_what_is_kept_is_for_the_user_alone(self):
        self.captured()
        for directory in (self.state, self.state / "captures"):
            assert directory.stat().st_mode & 511 == 448

    def left_behind(self, **launcher) -> Result:
        """A launch that finds the sidecar of an earlier session, started
        by the launcher its label names."""
        about = {"project": "/elsewhere", "start": 5, **launcher}
        return self.launch(
            FAKE_PS=f"claude-old.capture\t{json.dumps(about)}",
            FAKE_CAPTURE=str(self.capture_file),
        )

    def assert_collected(self, result: Result) -> None:
        assert ["rm", "--force", "claude-old.capture"] in result.calls
        assert (self.state / "captures" / "claude-old.capture-5.pcap").exists()

    def test_a_capture_left_by_a_killed_session_is_collected(self):
        self.assert_collected(self.left_behind(pid=2**22 - 7))

    def test_the_capture_of_a_running_session_is_left_alone(self):
        me = os.getpid()
        for mine in (
            {"pid": me},
            {"pid": me, "launched": launcher.process_started(me)},
        ):
            result = self.left_behind(**mine)
            # But for the container of the session that just ran
            touched = [c for c in result.calls if c[0] in ("stop", "cp", "rm")]
            assert {tuple(call) for call in touched} == {
                ("rm", "--force", "claude-proj")
            }

    def test_another_process_with_the_id_of_a_launcher_is_not_taken_for_it(self):
        assert launcher.process_started(os.getpid())
        self.assert_collected(self.left_behind(pid=os.getpid(), launched="earlier"))

    def test_a_capture_left_behind_ends_when_it_was_last_written_to(self):
        # Over an hour before the next launcher ran and collected it: its
        # last connection, then a last lookup
        ended = float(round(self.now - 3600))
        dns = self.work / "dns.pcap"
        dns.write_bytes(
            pcap_file([(ended, dns_response("a.test", "192.0.2.9"), False)])
        )
        os.utime(self.capture_file, (ended - 50, ended - 50))
        os.utime(dns, (ended, ended))
        docker_ok = sidecar.docker_ok

        def copied_as_docker_does(*args: str) -> bool:
            # With the time the file has in the sidecar, which docker cp
            # keeps and the fake docker does not
            done = docker_ok(*args)
            if done and args[0] == "cp":
                source = dns if args[1].endswith("/dns.pcap") else self.capture_file
                shutil.copystat(source, args[-1])
            return done

        about = {"project": str(self.project), "start": ended - 200, "pid": 2**22 - 7}
        environment = {
            "FAKE_PS": f"claude-old.capture\t{json.dumps(about)}",
            "FAKE_CAPTURE": str(self.capture_file),
            "FAKE_CAPTURE_DNS": str(dns),
        }
        with (
            unittest.mock.patch.dict(os.environ, environment),
            unittest.mock.patch.object(sidecar, "docker_ok", copied_as_docker_does),
            unittest.mock.patch.object(
                capture_module, "docker_ok", copied_as_docker_does
            ),
        ):
            capture_module.CaptureSidecar.collect_left_behind(self.host)
        (session,) = records.read_traced_sessions(self.host)
        assert (session.name, session.end) == ("claude-old", ended)

    def test_only_the_latest_sessions_stay_in_the_record(self):
        host = settings.detect_host({"HOME": str(self.home)})
        Path(host.state_dir).mkdir(parents=True)
        Path(host.net_sessions_file).write_text("cut off by a killed launch")
        for number in range(records.KEPT_SESSIONS + 5):
            session = records.TracedSession(
                f"s{number}", "/p", float(number), ip="10.0.0.1"
            )
            records.record_traced_session(host, session)
        kept = records.read_traced_sessions(host)
        assert len(kept) == records.KEPT_SESSIONS
        assert (kept[0].name, kept[-1].start) == ("s5", kept[-1].start)
        assert kept[-1].name == f"s{records.KEPT_SESSIONS + 4}"

    def test_a_line_of_the_record_that_does_not_hold_up_is_passed_over(self):
        for line in (
            "[" * 100_000,
            '{"name": "a", "project": "/p", "start": 1e999, "ip": "10.0.0.1"}',
            '{"name": "a", "project": "/p", "start": 5, "capture": "a.pcap"}',
            '{"name": "a", "project": "/p", "start": 5}',
            '{"name": 1, "project": "/p", "start": 5, "ip": "10.0.0.1"}',
        ):
            assert records.TracedSession.from_line(line) is None, line[:40]
        kept = records.TracedSession.from_line(
            '{"name": "a", "project": "/p", "start": 5, "end": 9,'
            ' "capture": "../../etc/passwd"}'
        )
        assert kept.capture == "passwd"

    def trace(self, *args: str) -> str:
        self.captured()
        self.write_transcript("0a", prompts_at(self.now, self.now + 10))
        result = self.launch("--trace", *args)
        assert result.status == 0, result.stderr
        return result.stdout

    def test_the_trace_lists_what_was_reached(self):
        stdout = self.trace()
        for expected in (
            "#   captured in claude-proj from ",
            "#   tcp/https good.test (198.51.100.7):443 x1",
            "#   tcp/postgres 10.0.0.7:5432 x1",
            f"#   tcp sni.test (203.0.113.9):{UNNAMED} x1",
            "#   dns 1 names looked up",
            # The second connection that was made
            "sandbox  net         [n2] tcp/postgres 10.0.0.7:5432",
        ):
            assert expected in stdout
        assert ":8000" not in stdout
        assert ":9000" not in stdout
        assert "lookup" not in stdout

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
            "sandbox  net         [n1] tcp/https [2001:db8::9]:443",
            f"sandbox  dns         lookup {tunnel} A FLAGGED: an unusually long name",
        ):
            assert expected in stdout
        failed = self.launch("--trace", "--failed").stdout
        assert "FLAGGED" in failed
        assert "quic.test" not in failed.split("# time")[1]

    def test_verbose_adds_the_lookups(self):
        looked_up = "sandbox  dns         lookup good.test A -> 198.51.100.7"
        assert looked_up in self.trace("--verbose")

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
        ran: dict[str, object] = {"type": "tool_use", "id": "t1", "name": "Bash"}
        ran["input"] = {"command": "curl plain.test/a"}
        call = {"type": "assistant", "message": {"content": [ran]}}
        call["timestamp"] = stamp(self.now + 1, UTC).isoformat()
        done = {"type": "tool_result", "tool_use_id": "t1", "content": "ok"}
        result = {"type": "user", "message": {"content": [done]}}
        result["timestamp"] = stamp(self.now + 5, UTC).isoformat()
        self.write_transcript("0a", [first, call, result, last])
        traced = self.launch("--trace", *args, **env)
        assert traced.status == 0, traced.stderr
        return traced.stdout

    def test_a_connection_says_how_it_went_and_during_which_call(self):
        stdout = self.detailed("--verbose")
        during = "  during: $ curl plain.test/a\n"
        for expected in (
            # Each connection by its number, in the order they were made
            "[n1] tcp/http 198.51.100.7:80  closed after 1.0s, 2 kB out, 20 kB in"
            + during,
            "net         http GET http://plain.test/a" + during,
            "[n2] tcp/https 198.51.100.8:443  REFUSED" + during,
            "[n3] tcp/ssh 198.51.100.7:22  (no call running)\n",
            "dns         lookup nope.test A FAILED: no such name\n",
            "#   1 connections REFUSED or without an answer",
            "#   http 1 requests in the clear",
        ):
            assert expected in stdout

    def test_what_went_wrong_on_the_network_stands_out(self):
        coloured = self.detailed("--verbose", FORCE_COLOR="1")
        alert = "\x1b[1;31msandbox  "
        assert (
            alert + "net         [n2] tcp/https 198.51.100.8:443  REFUSED" in coloured
        )
        assert alert + "dns         lookup nope.test" in coloured

    def test_json_has_how_a_connection_went(self):
        events = [json.loads(line) for line in self.detailed("--json").splitlines()]
        closed, asked, refused, left = (e for e in events if e["what"] == "net")
        assert (closed["outcome"], closed["seconds"]) == ("closed", 1.0)
        assert (closed["bytes_out"], closed["bytes_in"]) == (1500, 20000)
        assert (closed["during"], left["during"]) == (["t1"], [])
        assert (asked["method"], asked["url"]) == ("GET", "http://plain.test/a")
        assert (refused["outcome"], left.get("outcome")) == ("refused", None)
        (call,) = (e for e in events if e.get("tool") == "Bash")
        assert call["id"] == "t1"
        (failed,) = (e for e in events if e["what"] == "dns")
        assert (failed["type"], failed["error"]) == ("A", "no such name")

    def test_json_has_connections_and_lookups(self):
        events = [json.loads(line) for line in self.trace("--json").splitlines()]
        reached = [e for e in events if e["what"] == "net"]
        assert [
            (e["protocol"], e["name"], e["address"], e["port"]) for e in reached
        ] == [
            ("tcp/https", "good.test", "198.51.100.7", 443),
            ("tcp/postgres", None, "10.0.0.7", 5432),
            ("tcp", "sni.test", "203.0.113.9", UNNAMED),
        ]
        (lookup,) = (e for e in events if e["what"] == "dns")
        assert (lookup["who"], lookup["name"]) == ("sandbox", "good.test")


class EgressLogTest(LauncherTest):
    """The egress proxy's log: read within bounds, and kept within its
    limit for as long as a filtered session adds to it."""

    @pytest.fixture(autouse=True)
    def access_log(self, sandbox: None) -> None:
        self.log = self.work / "access.log"
        self.lines = [
            f"{1000 + n}.000 0 172.20.0.5 TCP_DENIED/403 9 CONNECT n{n}.test:443 - -\n"
            for n in range(40)
        ]
        self.log.write_text("".join(self.lines[20:]))
        self.rotated = self.work / "access.log.0"
        self.rotated.write_text("".join(self.lines[:20]))

    def end_of_log(self, most: int) -> subprocess.CompletedProcess:
        """What the proxy's container would give of the log."""
        script = egress_log.end_of_log(str(self.log), most)
        return subprocess.run(["sh", "-c", script], capture_output=True, check=False)

    def test_no_more_than_the_end_of_the_log_is_read(self):
        whole = "".join(self.lines).encode()
        assert self.end_of_log(len(whole) + 1).stdout == whole
        # The end of the two files together, the rotated one first
        most = len(whole) // 2 + 30
        assert self.end_of_log(most).stdout == whole[-most:]
        self.rotated.unlink()
        assert self.end_of_log(len(whole)).stdout == self.log.read_bytes()
        self.log.unlink()
        assert self.end_of_log(len(whole)).returncode != 0

    def test_the_proxy_is_asked_for_no_more_than_is_read(
        self, capsys: pytest.CaptureFixture[str]
    ):
        with unittest.mock.patch.dict(os.environ, {"FAKE_ACCESS_LOG": str(self.log)}):
            requests = egress_log.logged_requests()
        assert requests is not None
        assert [request.host for request in requests] == [
            f"n{n}.test" for n in range(20, 40)
        ]
        (asked,) = (call for call in self.calls() if call[0] == "exec")
        assert asked[-1].endswith(f"| tail -c {egress_log.MOST_READ + 1}")
        assert capsys.readouterr().err == ""

    def test_a_log_longer_than_is_read_is_said_to_be(
        self, capsys: pytest.CaptureFixture[str]
    ):
        most = len("".join(self.lines)) // 2 + 30
        # A byte more than is read is asked for, which tells
        given = self.end_of_log(most + 1).stdout
        with unittest.mock.patch.object(egress_log, "MOST_READ", most):
            read = egress_log.whole_lines(given)
            assert egress_log.whole_lines(given[1:]) == given[1:].decode()
        # From the first line that is all there
        assert read.splitlines(keepends=True) == self.lines[-len(read.splitlines()) :]
        assert 15 < len(read.splitlines()) < 25
        said = capsys.readouterr().err
        assert said.count("the egress proxy's log is longer than") == 1

    def test_what_was_logged_since_is_read_a_bounded_piece_at_a_time(self):
        logged = self.log.read_bytes()

        def since(*offset: str, most: int = 10**6) -> bytes:
            script = egress_log.log_since(most)
            asked = ["sh", "-c", script, "sh", str(self.log), *offset]
            return subprocess.run(asked, capture_output=True, check=True).stdout

        assert since() == f"{len(logged)}\n".encode()
        assert since("100") == b"100\n" + logged[100:]
        assert since("100", most=250) == b"100\n" + logged[100:350]
        # Rotated since: from its start
        assert since(str(len(logged) + 5), most=250) == b"0\n" + logged[:250]

        with (
            unittest.mock.patch.object(egress_log, "MOST_READ", 250),
            unittest.mock.patch.object(egress_log, "docker_bytes") as given,
        ):
            given.return_value = b"100\n" + logged[100:350]
            offset, requests = egress_log.logged_since(100)
            # As far as the last line that is all there
            assert offset == 100 + logged[100:350].rfind(b"\n") + 1
            assert len(requests) == logged[100:offset].count(b"\n") - 1
            # What is no line at all is passed over, not asked for again
            given.return_value = b"100\n" + b"x" * 250
            assert egress_log.logged_since(100) == (350, [])
            given.return_value = b"100\n" + b"x" * 249
            assert egress_log.logged_since(100) == (100, [])

    def test_a_log_that_was_rotated_says_so_ahead_of_what_it_holds(self):
        whole = "".join(self.lines).encode()
        script = egress_log.end_of_log(str(self.log), len(whole), marked=True)

        def given(_stderr: int | None = None) -> bytes:
            asked = ["sh", "-c", script]
            return subprocess.run(asked, capture_output=True, check=True).stdout

        assert given() == b"# rotated\n" + whole
        with unittest.mock.patch.object(egress_log, "raw_log", given):
            read = egress_log.proxy_log()
        assert (len(read.requests), read.shortened) == (40, True)
        assert read.begins == 1000.0
        # One that was not holds all that was logged, as far as is known
        self.rotated.unlink()
        assert given() == self.log.read_bytes()
        with unittest.mock.patch.object(egress_log, "raw_log", given):
            read = egress_log.proxy_log()
        assert (len(read.requests), read.shortened, read.begins) == (20, False, None)

    def rotations(self) -> list[list[str]]:
        return [call for call in self.calls() if "squid -k rotate" in call[-1]]

    def test_the_log_is_kept_within_its_limit_while_a_filtered_session_runs(self):
        often = unittest.mock.patch.object(egress_proxy, "ROTATE_EVERY", 0.1)
        address_given = unittest.mock.patch.dict(os.environ, {"FAKE_IP": "172.20.0.5"})
        session = ("claude-proj", "claude-proj")
        # Not for a session the proxy logs nothing of
        unfiltered = settings.Settings(net_filter=False)
        recorded = address.session_address_recorded(unfiltered, self.host, *session)
        with often, address_given, recorded:
            time.sleep(0.4)
        assert self.rotations() == []
        filtered = settings.Settings(net_filter=True)
        recorded = address.session_address_recorded(filtered, self.host, *session)
        with often, address_given, recorded:
            deadline = time.monotonic() + 20
            while len(self.rotations()) < 3 and time.monotonic() < deadline:
                time.sleep(0.05)
        # Again and again for as long as it runs, when over the limit
        assert len(self.rotations()) >= 3
        assert f"-gt {egress_proxy.EGRESS_LOG_LIMIT} ]" in self.rotations()[0][-1]

    def test_a_session_is_known_by_every_address_it_was_given(self):
        # On a daemon that gives its networks IPv6 too a session has an
        # address of each kind, and asks the proxy from the one it likes
        began = time.time()
        self.launch(CLAUDE_AIRLOCK_NET_FILTER="1", FAKE_IP="172.20.0.5 FD00:0:0::5")
        sessions = records.recorded_sessions(self.host, began - 1, time.time() + 1)
        assert [(session.name, session.ip) for session in sessions] == [
            ("claude-proj", "172.20.0.5"),
            ("claude-proj", "fd00::5"),
        ]
        callers = {
            "172.20.0.5": "four",
            "fd00::5": "six",
            "fd00:0:0:0::5": "six-written-long",
            "fd00::9": "theirs",
        }
        # Asked once the session had started, however long that took
        asked = time.time()
        logged = [
            egress_log.parse_proxy_request(
                f"{asked:.3f} 0 {caller} TCP_DENIED/403 9 CONNECT {name}.test:443 - -"
            )
            for caller, name in callers.items()
        ]
        made = egress_log.requests_made(logged, sessions, began - 1, asked + 60)
        assert [request.host for request, _ in made] == [
            "four.test",
            "six.test",
            "six-written-long.test",
        ]
