#!/usr/bin/env python3
"""The launcher's copy of a transcript, and what --trace makes of a
transcript that no longer says what the copy does."""

from __future__ import annotations

import json
import os
import time
import unittest
import unittest.mock
from pathlib import Path

from harness import LauncherTest, prompts_at, settings

from claude_airlock.recording import recorder


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

    def test_a_transcript_of_too_many_lines_is_said_not_to_be_compared(self):
        recorder.catch_up(self.transcript, self.copy)
        edited = self.transcript.read_text().replace("evil.test", "good.test")
        self.transcript.write_text(edited)
        with unittest.mock.patch.object(recorder, "MOST_COMPARED", 2):
            compared = recorder.compare(self.host, self.transcript)
            said = "\n".join(compared.header())
        self.assertTrue(compared.uncompared)
        self.assertEqual((compared.copied, compared.gone), (True, []))
        self.assertEqual(compared.lines, len(self.entries))
        self.assertIn("NOT COMPARED: more than 2 lines", said)

    def test_of_the_lines_found_gone_only_so_much_is_held(self):
        recorder.catch_up(self.transcript, self.copy)
        self.rewrite(self.entries[:1])
        longest = max(len(json.dumps(entry)) for entry in self.entries) + 1
        with unittest.mock.patch.object(recorder, "MOST_GONE_BYTES", longest):
            compared = recorder.compare(self.host, self.transcript)
        gone = len(self.entries) - 1
        self.assertEqual(len(compared.gone), 1)
        self.assertEqual((compared.more_gone, compared.missing), (gone - 1, gone))
        self.assertIn(f"{gone} lines the launcher copied", compared.header()[0])

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

    def test_a_session_that_removed_its_transcript_is_still_traced(self):
        recorder.catch_up(self.transcript, self.copy)
        self.transcript.unlink()
        self.assertEqual(recorder.removed_transcripts(self.host), [self.transcript])
        result = self.launch("--trace")
        self.assertEqual(result.status, 0, result.stderr)
        self.assertIn("# session     0a  ", result.stdout)
        self.assertIn("# transcript  REMOVED, it is no longer there", result.stdout)
        self.assertIn(
            "$ curl https://evil.test  REMOVED FROM THE TRANSCRIPT", result.stdout
        )
        self.assertIn("# tool calls  2 (Bash 2)", result.stdout)
        listed = self.launch("--trace", "list").stdout
        self.assertRegex(listed, r"0a +1 prompts +2 calls  REMOVED  ")
        self.assertIn("evil.test", self.launch("--trace", "0a", "--failed").stdout)

    def test_a_removed_transcript_is_said_when_the_session_ends(self):
        # Written to, so that it is copied, then removed
        added = json.dumps(prompts_at(time.time())[0])
        gone = (
            f"echo '{added}' >> '{self.transcript}'; sleep 1.2; rm '{self.transcript}'"
        )
        result = self.launch(session=gone)
        self.assertIn("the transcript of 0a was removed", result.stderr)

    def test_a_subagent_that_removed_its_transcript_is_still_traced(self):
        ran = call(3, self.now + 3, "curl https://evil.test/sub")
        theirs = self.subagent([*prompts_at(self.now + 3), *ran])
        recorder.Copier(self.host, time.time() - 60).look()
        theirs.unlink()
        self.assertEqual(
            recorder.removed_subagents(self.host, self.transcript), [theirs]
        )
        result = self.launch("--trace")
        self.assertRegex(
            result.stdout,
            r"agent    bash        \$ curl https://evil.test/sub"
            r"  REMOVED FROM THE TRANSCRIPT",
        )

    def test_a_line_that_holds_no_entry_is_shown_as_unreadable(self):
        # Half a line ahead of the entry Claude Code writes next
        with open(self.transcript, "a") as transcript:
            transcript.write('{"x":"' + json.dumps(call(3, self.now + 3, "id")[0]))
            transcript.write("\n")
        recorder.catch_up(self.transcript, self.copy)
        result = self.launch("--trace")
        self.assertIn("# transcript  1 lines CANNOT BE READ", result.stdout)
        self.assertRegex(
            result.stdout,
            r"sandbox  transcript  UNREADABLE line of the transcript: \{\"x\":\"\{",
        )
        failed = self.launch("--trace", "--failed").stdout
        self.assertIn("UNREADABLE line of the transcript", failed)
        # Taken out again, it is gone as any line is
        self.rewrite(self.entries)
        recorder.catch_up(self.transcript, self.copy)
        gone = recorder.compare(self.host, self.transcript).gone
        self.assertEqual([entry["type"] for entry in gone], ["unreadable-line"])

    def test_a_copy_that_stopped_at_its_limit_is_not_said_to_be_whole(self):
        size = self.transcript.stat().st_size
        with unittest.mock.patch.object(recorder, "MOST_COPIED", size):
            recorder.catch_up(self.transcript, self.copy)
            whole = recorder.compare(self.host, self.transcript)
            self.assertFalse(whole.cut_short)
            with open(self.transcript, "a") as transcript:
                transcript.write(json.dumps(call(3, self.now + 3, "id")[0]) + "\n")
            recorder.catch_up(self.transcript, self.copy)
            compared = recorder.compare(self.host, self.transcript)
        self.assertEqual(self.copy.stat().st_size, size)
        self.assertTrue(compared.cut_short)
        self.assertIn("NOT ALL COPIED", compared.header()[0])
        self.assertNotIn("as the launcher copied it", "".join(compared.header()))

    def test_looks_that_failed_are_counted(self):
        copier = recorder.Copier(self.host, time.time() - 60)
        with unittest.mock.patch.object(
            recorder, "catch_up", side_effect=OSError(24, "Too many open files")
        ):
            copier.look()
        self.assertEqual(copier.failed, 1)
        self.assertIn("Too many open files", copier.problem)

    def test_old_copies_go(self):
        recorder.catch_up(self.transcript, self.copy)
        long_ago = time.time() - (recorder.KEPT_DAYS + 1) * 86400
        os.utime(self.copy, (long_ago, long_ago))
        recorder.let_go_of_old_copies(self.host)
        self.assertFalse(self.copy.exists())

    def subagent(self, entries: list[dict]) -> Path:
        """Leave the transcript of a subagent of the session, where Claude
        Code keeps it."""
        directory = self.transcripts / "0a" / "subagents"
        directory.mkdir(parents=True, exist_ok=True)
        file = directory / "agent-a1.jsonl"
        marked = [{**entry, "isSidechain": True} for entry in entries]
        file.write_text("".join(json.dumps(e) + "\n" for e in marked))
        return file

    def test_what_a_subagent_did_is_copied_and_compared_as_its_session_is(self):
        ran = call(3, self.now + 3, "curl https://evil.test/sub")
        theirs = self.subagent([*prompts_at(self.now + 3), *ran])
        copy = recorder.copy_path(self.host, theirs)
        # Kept apart from the copy of any transcript, which ends in .jsonl
        self.assertEqual(copy.parent.name, "0a.subagents")
        self.assertEqual(copy.parent.parent, self.copy.parent)
        recorder.Copier(self.host, time.time() - 60).look()
        self.assertEqual(copy.read_bytes(), theirs.read_bytes())
        self.assertEqual(self.copy.read_bytes(), self.transcript.read_bytes())
        # The subagent takes its command out of its own transcript
        self.subagent(prompts_at(self.now + 3))
        recorder.Copier(self.host, time.time() - 60).look()
        compared = recorder.compare(self.host, theirs)
        self.assertEqual(len(compared.gone), 2)
        result = self.launch("--trace")
        self.assertIn("# subagents   1, CHANGED: 2 lines", result.stdout)
        self.assertRegex(
            result.stdout,
            r"agent    bash        \$ curl https://evil.test/sub"
            r"  REMOVED FROM THE TRANSCRIPT",
        )

    def test_a_trace_has_what_the_subagents_of_its_session_did(self):
        write = {"type": "tool_use", "id": "w1", "name": "Write"}
        write["input"] = {"file_path": "/home/me/.bashrc", "content": "x"}
        stamp = prompts_at(self.now + 4)[0]["timestamp"]
        wrote = {
            "type": "assistant",
            "timestamp": stamp,
            "message": {"content": [write]},
        }
        self.subagent([*prompts_at(self.now + 3), wrote])
        recorder.Copier(self.host, time.time() - 60).look()
        traced = self.launch("--trace").stdout
        self.assertIn("# subagents   1, as the launcher copied them (2 lines)", traced)
        # In the summary of the session, and by who did it
        self.assertIn("#   /home/me/.bashrc x1  OUTSIDE PROJECT", traced)
        self.assertRegex(traced, r"agent    write       file: /home/me/.bashrc")
        # What it was asked is not a prompt of the user
        self.assertEqual(traced.count("user     prompt"), 1)
        # A session without any says nothing of them
        other = self.write_transcript("0b", prompts_at(self.now + 9))
        os.utime(other, (self.now + 99, self.now + 99))
        self.assertNotIn("# subagents", self.launch("--trace").stdout)

    def test_the_copies_of_subagents_go_when_they_are_old(self):
        theirs = self.subagent(prompts_at(self.now))
        copy = recorder.copy_path(self.host, theirs)
        recorder.catch_up(theirs, copy)
        recorder.catch_up(self.transcript, self.copy)
        long_ago = time.time() - (recorder.KEPT_DAYS + 1) * 86400
        os.utime(copy, (long_ago, long_ago))
        recorder.let_go_of_old_copies(self.host)
        self.assertFalse(copy.parent.exists())
        self.assertTrue(self.copy.exists())


if __name__ == "__main__":
    unittest.main()
