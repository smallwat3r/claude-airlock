#!/usr/bin/env python3
"""--trace: the transcript as text and as JSON Lines, and the requests of a
filtered session from the egress proxy's log."""

from __future__ import annotations

import json
import os
import re
import time
import unittest

from harness import (
    LauncherTest,
    prompts_at,
)


class TraceTest(LauncherTest):
    SESSION = "3fa9c0de-0000-4000-8000-000000000000"

    def setUp(self):
        super().setUp()

        def call(tool_id: str, name: str, **tool_input) -> dict:
            block = {"type": "tool_use", "id": tool_id, "name": name}
            return {
                "type": "assistant",
                "timestamp": "2026-01-02T10:00:01Z",
                "message": {"content": [{**block, "input": tool_input}]},
            }

        def result(tool_id: str, output: str, failed: bool = False) -> dict:
            block = {"type": "tool_result", "tool_use_id": tool_id}
            return {
                "type": "user",
                "timestamp": "2026-01-02T10:00:03Z",
                "message": {
                    "content": [{**block, "content": output, "is_error": failed}]
                },
            }

        entries = [
            {
                "type": "user",
                "timestamp": "2026-01-02T10:00:00Z",
                "message": {"content": "fix the build"},
            },
            call(
                "t1",
                "Bash",
                command="make \x1b]0;owned\x07all",
                description="Build\n2026-01-02 10:00:09  user     prompt    forged",
            ),
            result("t1", "Error: Exit code 2\nno rule", failed=True),
            call("t2", "Edit", file_path="/etc/passwd", old_string="a", new_string="b"),
            result("t2", "updated"),
            call("t3", "Write", file_path="main.go", content="package main\n"),
        ]
        file = self.write_transcript(self.SESSION, entries)
        file.write_text(file.read_text() + "{half written")

    def test_the_session_is_shown_without_docker(self):
        result = self.launch("--trace")
        self.assertEqual(result.status, 0, result.stderr)
        self.assertEqual(result.calls, [])
        for expected in (
            "user     prompt    fix the build",
            "claude   bash      $ make ]0;ownedall",
            "claude   bash      why: Build\\n2026-01-02 10:00:09  user     prompt    forged",
            "claude   bash      result: FAILED, 2.0s",
            "claude   bash      out: no rule",
            "claude   edit      diff: -a",
            "claude   edit      diff: +b",
            "claude   write     file: main.go (1 lines)",
            "claude   write     result: none recorded",
            "# tool calls  3 (Bash 1, Edit 1, Write 1)",
        ):
            self.assertIn(expected, result.stdout)

    def test_every_line_says_when_who_and_what(self):
        for line in self.launch("--trace", "--full").stdout.splitlines():
            self.assertRegex(line, r"^(#|\d{4}-\d\d-\d\d \d\d:\d\d:\d\d  \w+ +\w+ +\S)")

    def test_control_characters_never_reach_the_terminal(self):
        for form in ("--full", "--json"):
            stdout = self.launch("--trace", form).stdout
            self.assertNotRegex(stdout, r"[\x00-\x08\x0b-\x1f\x7f]")

    def test_json_gives_an_object_per_event_with_its_values(self):
        result = self.launch("--trace", "--json")
        self.assertEqual(result.status, 0, result.stderr)
        prompt, bash, edit, write = map(json.loads, result.stdout.splitlines())
        for event in (prompt, bash, edit, write):
            self.assertEqual(event["session"], self.SESSION)
            self.assertRegex(
                event["time"], r"^2026-01-02T\d\d:00:0\d\.000[+-]\d\d:\d\d$"
            )
        self.assertEqual((prompt["who"], prompt["what"]), ("user", "prompt"))
        self.assertEqual(prompt["text"], "fix the build")
        self.assertEqual(bash["input"]["command"], "make \x1b]0;owned\x07all")
        self.assertEqual((bash["failed"], bash["seconds"]), (True, 2.0))
        self.assertIn("no rule", bash["output"])
        self.assertTrue(edit["outside_project"])
        self.assertFalse(write["outside_project"])
        self.assertNotIn("failed", write)

    def test_only_writes_outside_the_project_are_flagged(self):
        stdout = self.launch("--trace").stdout
        self.assertIn("/etc/passwd x1  OUTSIDE PROJECT", stdout)
        self.assertIn("file: /etc/passwd  OUTSIDE PROJECT", stdout)
        self.assertNotIn("main.go x1  OUTSIDE", stdout)

    def test_output_of_a_successful_call_needs_full(self):
        self.assertNotIn("updated", self.launch("--trace").stdout)
        self.assertIn("updated", self.launch("--trace", "--full").stdout)

    def test_sessions_are_listed_and_picked_by_id_prefix(self):
        listed = self.launch("--trace", "list").stdout
        self.assertIn("3fa9c0de    1 prompts     3 calls  fix the build", listed)
        self.assertEqual(self.launch("--trace", "3fa9").status, 0)
        missing = self.launch("--trace", "../../etc")
        self.assertNotEqual(missing.status, 0)
        self.assertIn("matches no session", missing.stderr)

    def test_a_link_planted_among_the_transcripts_is_not_read(self):
        secret = self.work / "secret.jsonl"
        secret.write_text(json.dumps({"type": "ai-title", "aiTitle": "TOP SECRET"}))
        (self.transcripts / "ffff.jsonl").symlink_to(secret)
        self.assertNotIn("TOP SECRET", self.launch("--trace", "list").stdout)
        self.assertNotEqual(self.launch("--trace", "ffff").status, 0)

    def test_a_date_out_of_range_does_not_stop_the_trace(self):
        file = self.transcripts / f"{self.SESSION}.jsonl"
        odd = {"type": "user", "timestamp": "0001-01-01T00:00:00+14:00"}
        file.write_text(
            json.dumps({**odd, "message": {"content": "early"}})
            + "\n"
            + file.read_text()
        )
        result = self.launch("--trace")
        self.assertEqual(result.status, 0, result.stderr)
        self.assertIn("prompt    early", result.stdout)

    def test_a_project_without_sessions_is_an_error(self):
        result = self.launch("--trace", cwd=self.home / "ref")
        self.assertNotEqual(result.status, 0)
        self.assertIn("no session recorded", result.stderr)


class NetworkTraceTest(LauncherTest):
    """A filtered session, then its trace against a proxy log that another
    session also wrote to."""

    def setUp(self):
        super().setUp()
        self.filtered = self.launch(CLAUDE_DOCKER_NET_FILTER="1", FAKE_IP="172.20.0.5")
        now = time.time()
        self.write_transcript("0a", prompts_at(now, now + 10))
        mine, other = "172.20.0.5", "172.20.0.9"
        log = [
            f"{now + 5:.3f} 200 {mine} TCP_TUNNEL/200 4000 CONNECT good.test:443 - -",
            f"{now + 6:.3f} 100 {mine} TCP_TUNNEL/200 1000 CONNECT good.test:443 - -",
            f"{now + 7:.3f} 0 {mine} TCP_DENIED/403 300 CONNECT evil.test:443 - -",
            f"{now + 8:.3f} 0 {mine} TCP_DENIED/403 9 CONNECT \x1b[31mesc.test:443 - -",
            f"{now + 5:.3f} 0 {other} TCP_TUNNEL/200 50 CONNECT theirs.test:443 - -",
            # Opened during the session, closed and so logged after it
            f"{now + 60:.3f} 55000 {mine} TCP_TUNNEL/200 70 CONNECT long.test:443 - -",
            f"{now + 60:.3f} 100 {mine} TCP_TUNNEL/200 50 CONNECT after.test:443 - -",
            "not a log line",
        ]
        self.access_log = self.work / "access.log"
        self.access_log.write_text("\n".join(log) + "\n")

    def trace(self, *args: str) -> str:
        result = self.launch("--trace", *args, FAKE_ACCESS_LOG=str(self.access_log))
        self.assertEqual(result.status, 0, result.stderr)
        return result.stdout

    def test_the_session_address_is_recorded(self):
        (session,) = map(
            json.loads, (self.state / "net-sessions.jsonl").read_text().splitlines()
        )
        self.assertEqual(session["ip"], "172.20.0.5")
        self.assertEqual(session["project"], str(self.project))

    def test_the_proxy_log_is_kept_in_a_volume_and_capped(self):
        proxy = self.filtered.sidecar("claude-egress-proxy")
        self.assertIn("--volume=claude-egress-log:/var/log/squid", proxy)
        rotations = [c for c in self.filtered.calls if "squid -k rotate" in c[-1]]
        self.assertEqual(len(rotations), 1)
        self.assertIn("-gt 10485760", rotations[0][-1])

    def test_an_open_session_records_no_address(self):
        self.launch(FAKE_IP="172.20.0.6")
        sessions = (self.state / "net-sessions.jsonl").read_text()
        self.assertNotIn("172.20.0.6", sessions)

    def test_requests_are_summed_by_destination_refused_first(self):
        stdout = self.trace()
        denied = stdout.index("DENIED   evil.test:443 x1  300 B")
        allowed = stdout.index("allowed  good.test:443 x2  5 kB")
        self.assertLess(denied, allowed)
        self.assertIn("allowed  long.test:443 x1", stdout)

    def test_other_sessions_and_later_requests_are_left_out(self):
        stdout = self.trace()
        self.assertNotIn("theirs.test", stdout)
        self.assertNotIn("after.test", stdout)

    def test_logged_urls_cannot_drive_the_terminal(self):
        self.assertIn("[31mesc.test:443", self.trace())
        self.assertNotIn("\x1b", self.trace("--full"))

    def test_every_request_is_an_event_at_the_time_it_began(self):
        stdout = self.trace()
        request = "sandbox  net       proxy/https CONNECT good.test:443 allowed"
        self.assertEqual(stdout.count(request), 2)
        self.assertIn(f"{request} 4 kB 0.2s", stdout)
        self.assertIn("proxy/https CONNECT evil.test:443 DENIED 300 B", stdout)
        # Between the two prompts, 10 seconds apart
        first, second = (m.start() for m in re.finditer("user     prompt", stdout))
        self.assertTrue(first < stdout.index(request) < second)

    def test_a_session_without_the_filter_says_so(self):
        os.remove(self.state / "net-sessions.jsonl")
        self.assertIn("# network     not recorded", self.trace())


if __name__ == "__main__":
    unittest.main()
