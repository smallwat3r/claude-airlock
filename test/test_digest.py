#!/usr/bin/env python3
"""What the launcher says of a session when it ends."""

from __future__ import annotations

import json
import time
import unittest

from harness import LauncherTest, prompts_at
from test_capture import answer, dns_failure, dns_response, ipv4, pcap_file, tcp, udp

HEADING = "claude-airlock: of this session"


def uploaded(address: str, port: int, megabytes: int) -> list[bytes]:
    """A connection that sent so much before it was closed."""
    count = megabytes * 1_000_000
    return [
        tcp(address, port, sequence=1000),
        answer(address, port, sequence=5000, acknowledged=1001),
        tcp(address, port, 0x11, sequence=1001 + count, acknowledged=5001),
    ]


class DigestTest(LauncherTest):
    def setUp(self):
        super().setUp()
        self.capture_file = self.work / "capture.pcap"

    def session(
        self, *packets: tuple[bytes, bool], session: str = "", **env: str
    ) -> str:
        """What the launcher says after a session that put these packets
        on the wire, each given with whether the session sent it."""
        now = time.time()
        self.capture_file.write_bytes(
            pcap_file([(now, packet, sent) for packet, sent in packets])
        )
        return self.launch(
            session=session,
            CLAUDE_AIRLOCK_NET_LOG="1",
            FAKE_CAPTURE=str(self.capture_file),
            **env,
        ).stderr

    def known(self) -> list[tuple[bytes, bool]]:
        return [
            (dns_response("known.test", "198.51.100.7"), False),
            (tcp("198.51.100.7", 443), True),
        ]

    def test_the_first_session_of_a_project_has_nothing_to_compare_with(self):
        self.assertNotIn(HEADING, self.session(*self.known()))

    def test_a_destination_reached_for_the_first_time_is_said(self):
        self.session(*self.known())
        again = self.session(*self.known())
        self.assertNotIn(HEADING, again)
        # The same name at another address is the same destination
        moved = [
            (dns_response("known.test", "198.51.100.99"), False),
            (tcp("198.51.100.99", 443), True),
        ]
        self.assertNotIn(HEADING, self.session(*moved))
        new = self.session(
            *self.known(),
            (tcp("203.0.113.9", 443), True),
            (ipv4(17, "172.20.0.5", "203.0.113.9", udp(53)), True),
        )
        self.assertIn(HEADING, new)
        self.assertIn("  reached for the first time from this project:", new)
        self.assertIn("    tcp/https 203.0.113.9:443", new)
        self.assertIn("    udp/dns 203.0.113.9:53", new)
        self.assertNotIn("known.test", new)
        # And is known from then on
        self.assertNotIn(HEADING, self.session((tcp("203.0.113.9", 443), True)))

    def test_what_is_known_is_kept_per_project(self):
        self.session(*self.known())
        known = json.loads((self.state / "destinations.json").read_text())
        self.assertEqual(list(known), [str(self.project)])
        self.assertEqual(list(known[str(self.project)]), ["tcp known.test 443"])
        self.assertEqual(
            (self.state / "destinations.json").stat().st_mode & 0o777, 0o600
        )

    def test_a_large_upload_is_said_but_not_one_to_the_model(self):
        self.session(*self.known())
        packets = [
            *self.known(),
            *((p, i != 1) for i, p in enumerate(uploaded("198.51.100.7", 443, 14))),
        ]
        said = self.session(*packets)
        self.assertIn("  sent 14 MB to tcp/https known.test (198.51.100.7):443", said)
        small = [(p, i != 1) for i, p in enumerate(uploaded("198.51.100.7", 443, 2))]
        self.assertNotIn("sent", self.session(*self.known(), *small))
        model = [(p, i != 1) for i, p in enumerate(uploaded("160.79.104.10", 443, 90))]
        self.session(*model)
        self.assertNotIn("sent", self.session(*model))

    def test_a_name_does_not_make_an_address_the_models(self):
        posing = [
            (dns_response("api.anthropic.com", "203.0.113.9"), False),
            *((p, i != 1) for i, p in enumerate(uploaded("203.0.113.9", 443, 20))),
        ]
        self.session(*posing)
        self.assertIn(
            "sent 20 MB to tcp/https api.anthropic.com", self.session(*posing)
        )

    def test_lookups_that_stand_out_are_said(self):
        name = "a" * 60 + ".t.test"
        said = self.session((dns_failure(name), False))
        self.assertIn("  lookups that stand out:", said)
        self.assertIn(f"    {name}: an unusually long name", said)

    def test_a_write_outside_the_project_is_said(self):
        stamp = prompts_at(time.time())[0]["timestamp"]
        write = {"type": "tool_use", "id": "c1", "name": "Write"}
        write["input"] = {"file_path": "/home/me/.bashrc", "content": "x"}
        inside = {"type": "tool_use", "id": "c2", "name": "Write"}
        inside["input"] = {"file_path": str(self.project / "a.txt"), "content": "x"}
        entry = {"type": "assistant", "timestamp": stamp}
        entry["message"] = {"content": [write, inside]}
        transcript = self.write_transcript("0a", [])
        said = self.session(session=f"echo '{json.dumps(entry)}' >> '{transcript}'")
        self.assertIn("  written outside the project:\n    /home/me/.bashrc\n", said)

    def test_a_write_of_a_subagent_outside_the_project_is_said(self):
        stamp = prompts_at(time.time())[0]["timestamp"]
        write = {"type": "tool_use", "id": "c1", "name": "Write"}
        write["input"] = {"file_path": "/home/me/.profile", "content": "x"}
        entry = {"type": "assistant", "timestamp": stamp, "isSidechain": True}
        entry["message"] = {"content": [write]}
        transcript = self.write_transcript("0a", [])
        subagents = transcript.with_suffix("") / "subagents"
        subagents.mkdir(parents=True)
        theirs = subagents / "agent-a1.jsonl"
        said = self.session(session=f"echo '{json.dumps(entry)}' >> '{theirs}'")
        self.assertIn("  written outside the project:\n    /home/me/.profile\n", said)
        self.assertNotIn("a.txt", said)

    def test_a_transcript_changed_during_the_session_is_said(self):
        entries = prompts_at(time.time(), time.time() + 1, time.time() + 2)
        transcript = self.write_transcript("0abcdef012", entries)
        kept = json.dumps(entries[0])
        # Long enough for the launcher to have copied it before it is cut
        cut = f"sleep 1.5; echo '{kept}' > '{transcript}'"
        said = self.session(session=cut)
        self.assertIn(
            "  the transcript of 0abcdef0 was changed: 2 lines the launcher copied",
            said,
        )

    def test_nothing_is_said_without_a_record(self):
        self.assertNotIn(HEADING, self.launch().stderr)


if __name__ == "__main__":
    unittest.main()
