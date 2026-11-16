#!/usr/bin/env python3
"""The launcher's copy of a transcript, and what --trace makes of a
transcript that no longer says what the copy does."""

from __future__ import annotations

import json
import os
import time
import unittest

from harness import LauncherTest, prompts_at, settings

from claude_sandbox import recorder


def call(number: int, when: float, command: str) -> list[dict]:
    """The entries of a command that ran: its call and its result."""
    stamp = prompts_at(when)[0]["timestamp"]
    use = {"type": "tool_use", "id": f"c{number}", "name": "Bash"}
    use["input"] = {"command": command}
    result = {"type": "tool_result", "tool_use_id": f"c{number}", "content": "ok"}
    return [
        {"type": "assistant", "timestamp": stamp, "message": {"content": [use]}},
        {"type": "user", "timestamp": stamp, "message": {"content": [result]}},
    ]


class RecorderTest(LauncherTest):
    def setUp(self):
        super().setUp()
        self.host = settings.Host(
            str(self.home),
            str(self.project),
            str(self.home / ".config"),
            str(self.home / ".local" / "state"),
        )
        self.now = time.time()
        self.entries = [
            *prompts_at(self.now),
            *call(1, self.now + 1, "curl https://evil.test"),
            *call(2, self.now + 2, "make test"),
        ]
        self.transcript = self.write_transcript("0a", self.entries)
        self.copy = recorder.copy_path(self.host, self.transcript)

    def rewrite(self, entries: list[dict]) -> None:
        self.transcript.write_text("".join(json.dumps(e) + "\n" for e in entries))

    def test_a_transcript_is_copied_whenever_it_says_it_was_written(self):
        # A session that started later than the transcript was written
        copier = recorder.Copier(self.host, time.time() + 60)
        copier.look()
        self.assertFalse(self.copy.exists())
        with open(self.transcript, "a") as transcript:
            transcript.write(json.dumps(prompts_at(self.now + 5)[0]) + "\n")
        # The time it was written is the session's to set
        os.utime(self.transcript, (1, 1))
        copier.look()
        self.assertEqual(self.copy.read_bytes(), self.transcript.read_bytes())
        with open(self.transcript, "a") as transcript:
            transcript.write(json.dumps(prompts_at(self.now + 6)[0]) + "\n")
        os.utime(self.transcript, (1, 1))
        recorder.Copier(self.host, time.time() + 60).look()
        self.assertEqual(self.copy.read_bytes(), self.transcript.read_bytes())

    def test_a_copy_gains_what_its_transcript_gains(self):
        recorder.catch_up(self.transcript, self.copy)
        self.assertEqual(self.copy.read_bytes(), self.transcript.read_bytes())
        with open(self.transcript, "a") as transcript:
            transcript.write(json.dumps(prompts_at(self.now + 5)[0]) + "\n")
        recorder.catch_up(self.transcript, self.copy)
        recorder.catch_up(self.transcript, self.copy)
        self.assertEqual(self.copy.read_bytes(), self.transcript.read_bytes())
        self.assertEqual(self.copy.stat().st_mode & 0o777, 0o600)
        compared = recorder.compare(self.host, self.transcript)
        self.assertEqual((compared.copied, compared.gone), (True, []))

    def test_a_link_in_the_place_of_a_transcript_is_not_followed(self):
        secret = self.home / "secret"
        secret.write_text("a secret\n")
        self.transcript.unlink()
        self.transcript.symlink_to(secret)
        recorder.catch_up(self.transcript, self.copy)
        self.assertFalse(self.copy.exists())

    def test_what_was_edited_out_in_place_is_found(self):
        recorder.catch_up(self.transcript, self.copy)
        # The same length, a different command
        edited = self.transcript.read_text().replace("evil.test", "good.test")
        self.transcript.write_text(edited)
        recorder.catch_up(self.transcript, self.copy)
        compared = recorder.compare(self.host, self.transcript)
        self.assertEqual(len(compared.gone), 1)
        self.assertIn("evil.test", json.dumps(compared.gone))

    def test_a_transcript_rewritten_shorter_keeps_its_earlier_copy(self):
        recorder.catch_up(self.transcript, self.copy)
        self.rewrite([self.entries[0], *self.entries[3:]])
        recorder.catch_up(self.transcript, self.copy)
        recorder.catch_up(self.transcript, self.copy)
        compared = recorder.compare(self.host, self.transcript)
        self.assertEqual((compared.rewritten, len(compared.gone)), (1, 2))
        self.assertEqual(self.copy.read_bytes(), self.transcript.read_bytes())

    def test_only_so_many_earlier_copies_are_kept(self):
        for _ in range(recorder.MOST_PUT_ASIDE + 3):
            self.rewrite(self.entries)
            recorder.catch_up(self.transcript, self.copy)
            self.rewrite(self.entries[:1])
            recorder.catch_up(self.transcript, self.copy)
        self.assertEqual(len(recorder.put_aside(self.copy)), recorder.MOST_PUT_ASIDE)

    def test_a_copy_put_aside_meanwhile_is_not_added_to(self):
        recorder.catch_up(self.transcript, self.copy)
        with open(self.copy, "ab") as held:
            self.assertTrue(recorder.still_at(held.fileno(), self.copy))
            # What the launcher that had the lock did with it
            aside = self.copy.with_name(self.copy.name + ".1" + recorder.ASIDE_SUFFIX)
            os.replace(self.copy, aside)
            self.assertFalse(recorder.still_at(held.fileno(), self.copy))
            self.copy.write_bytes(b"")
            self.assertFalse(recorder.still_at(held.fileno(), self.copy))

    def test_a_session_is_copied_while_it_runs(self):
        added = json.dumps(prompts_at(time.time())[0])
        self.launch(session=f"echo '{added}' >> '{self.transcript}'")
        self.assertEqual(self.copy.read_bytes(), self.transcript.read_bytes())

    def test_a_transcript_no_session_wrote_to_is_not_copied(self):
        earlier = time.time() - 60
        os.utime(self.transcript, (earlier, earlier))
        self.launch()
        self.assertFalse(self.copy.exists())

    def test_the_trace_shows_what_was_removed(self):
        recorder.catch_up(self.transcript, self.copy)
        self.rewrite([self.entries[0], *self.entries[3:]])
        result = self.launch("--trace")
        self.assertIn("# transcript  CHANGED: 2 lines", result.stdout)
        self.assertIn(
            "$ curl https://evil.test  REMOVED FROM THE TRANSCRIPT", result.stdout
        )
        self.assertIn("$ make test\n", result.stdout)
        failed = self.launch("--trace", "--failed").stdout
        self.assertIn("evil.test", failed)
        self.assertNotIn("make test", failed)

    def test_the_trace_says_how_far_the_transcript_is_to_be_believed(self):
        without = self.launch("--trace").stdout
        self.assertIn("# transcript  as it is now, the launcher has no copy", without)
        recorder.catch_up(self.transcript, self.copy)
        self.assertIn(
            "# transcript  as the launcher copied it (5 lines)",
            self.launch("--trace").stdout,
        )

    def test_old_copies_go(self):
        recorder.catch_up(self.transcript, self.copy)
        long_ago = time.time() - (recorder.KEPT_DAYS + 1) * 86400
        os.utime(self.copy, (long_ago, long_ago))
        recorder.let_go_of_old_copies(self.host)
        self.assertFalse(self.copy.exists())


if __name__ == "__main__":
    unittest.main()
