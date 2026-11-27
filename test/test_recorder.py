#!/usr/bin/env python3
"""The launcher's copy of a transcript, and what --trace makes of a
transcript that no longer says what the copy does."""

from __future__ import annotations

import json
import os
import re
import threading
import time
import unittest.mock
from pathlib import Path

import pytest
from harness import LauncherTest, prompts_at

from claude_airlock import files
from claude_airlock.recording import recorder


def call(number: int, when: float, command: str) -> list[dict]:
    """The entries of a command that ran: its call and its result."""
    stamp = prompts_at(when)[0]["timestamp"]
    use: dict[str, object] = {"type": "tool_use", "id": f"c{number}", "name": "Bash"}
    use["input"] = {"command": command}
    result = {"type": "tool_result", "tool_use_id": f"c{number}", "content": "ok"}
    return [
        {"type": "assistant", "timestamp": stamp, "message": {"content": [use]}},
        {"type": "user", "timestamp": stamp, "message": {"content": [result]}},
    ]


class RecorderTest(LauncherTest):
    @pytest.fixture(autouse=True)
    def transcript_written(self, sandbox: None) -> None:
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

    def decoy(self, name: str, size: int) -> Path:
        """Leave a transcript that is none: a hole of a length, which
        takes no room on the disk it is made on."""
        file = self.transcripts / f"{name}.jsonl"
        with open(file, "wb") as hole:
            hole.truncate(size)
        return file

    def host_copy(self, transcript: Path) -> Path:
        """Where the launcher keeps its copy of a transcript."""
        return recorder.copy_path(self.host, transcript)

    def test_a_transcript_is_copied_whenever_it_says_it_was_written(self):
        # A session that started later than the transcript was written
        copier = recorder.Copier(self.host, time.time() + 60)
        copier.look()
        assert not self.copy.exists()
        with open(self.transcript, "a") as transcript:
            transcript.write(json.dumps(prompts_at(self.now + 5)[0]) + "\n")
        # The time it was written is the session's to set
        os.utime(self.transcript, (1, 1))
        copier.look()
        assert self.copy.read_bytes() == self.transcript.read_bytes()
        with open(self.transcript, "a") as transcript:
            transcript.write(json.dumps(prompts_at(self.now + 6)[0]) + "\n")
        os.utime(self.transcript, (1, 1))
        recorder.Copier(self.host, time.time() + 60).look()
        assert self.copy.read_bytes() == self.transcript.read_bytes()

    def test_a_copy_gains_what_its_transcript_gains(self):
        recorder.catch_up(self.transcript, self.copy)
        assert self.copy.read_bytes() == self.transcript.read_bytes()
        with open(self.transcript, "a") as transcript:
            transcript.write(json.dumps(prompts_at(self.now + 5)[0]) + "\n")
        recorder.catch_up(self.transcript, self.copy)
        recorder.catch_up(self.transcript, self.copy)
        assert self.copy.read_bytes() == self.transcript.read_bytes()
        assert self.copy.stat().st_mode & 511 == 384
        compared = recorder.compare(self.host, self.transcript)
        assert (compared.copied, compared.gone) == (True, [])

    def test_a_link_in_the_place_of_a_transcript_is_not_followed(self):
        secret = self.home / "secret"
        secret.write_text("a secret\n")
        self.transcript.unlink()
        self.transcript.symlink_to(secret)
        recorder.catch_up(self.transcript, self.copy)
        assert not self.copy.exists()

    def test_what_was_edited_out_in_place_is_found(self):
        recorder.catch_up(self.transcript, self.copy)
        # The same length, a different command
        edited = self.transcript.read_text().replace("evil.test", "good.test")
        self.transcript.write_text(edited)
        recorder.catch_up(self.transcript, self.copy)
        compared = recorder.compare(self.host, self.transcript)
        assert len(compared.gone) == 1
        assert "evil.test" in json.dumps(compared.gone)

    def test_a_transcript_of_too_many_lines_is_said_not_to_be_compared(self):
        recorder.catch_up(self.transcript, self.copy)
        edited = self.transcript.read_text().replace("evil.test", "good.test")
        self.transcript.write_text(edited)
        with unittest.mock.patch.object(recorder, "MOST_COMPARED", 2):
            compared = recorder.compare(self.host, self.transcript)
            said = "\n".join(compared.header())
        assert compared.uncompared
        assert (compared.copied, compared.gone) == (True, [])
        assert compared.lines == len(self.entries)
        assert "NOT COMPARED: more than 2 lines" in said

    def test_of_the_lines_found_gone_only_so_much_is_held(self):
        recorder.catch_up(self.transcript, self.copy)
        self.rewrite(self.entries[:1])
        # By what they take once read, not by their length
        lines = [json.dumps(entry).encode() + b"\n" for entry in self.entries]
        most = max(map(files.held_size, lines)) + 1
        assert most > 2 * max(map(len, lines))
        with unittest.mock.patch.object(recorder, "MOST_GONE_HELD", most):
            compared = recorder.compare(self.host, self.transcript)
        gone = len(self.entries) - 1
        assert len(compared.gone) == 1
        assert (compared.more_gone, compared.missing) == (gone - 1, gone)
        assert f"{gone} lines the launcher copied" in compared.header()[0]

    def test_a_transcript_rewritten_shorter_keeps_its_earlier_copy(self):
        recorder.catch_up(self.transcript, self.copy)
        self.rewrite([self.entries[0], *self.entries[3:]])
        recorder.catch_up(self.transcript, self.copy)
        recorder.catch_up(self.transcript, self.copy)
        compared = recorder.compare(self.host, self.transcript)
        assert (compared.rewritten, len(compared.gone)) == (1, 2)
        assert self.copy.read_bytes() == self.transcript.read_bytes()

    def test_only_so_many_earlier_copies_are_kept(self):
        for _ in range(recorder.MOST_PUT_ASIDE + 3):
            self.rewrite(self.entries)
            recorder.catch_up(self.transcript, self.copy)
            self.rewrite(self.entries[:1])
            recorder.catch_up(self.transcript, self.copy)
        assert len(recorder.put_aside(self.copy)) == recorder.MOST_PUT_ASIDE

    def test_what_is_written_after_any_number_of_rewrites_is_still_copied(self):
        times = recorder.MOST_PUT_ASIDE + 3
        for _ in range(times):
            self.rewrite(self.entries)
            recorder.catch_up(self.transcript, self.copy)
            self.rewrite(self.entries[:1])
            recorder.catch_up(self.transcript, self.copy)
            recorder.catch_up(self.transcript, self.copy)
            assert self.copy.read_bytes() == self.transcript.read_bytes()
        late = prompts_at(self.now + 50)[0]
        with open(self.transcript, "a") as transcript:
            transcript.write(json.dumps(late) + "\n")
        recorder.catch_up(self.transcript, self.copy)
        assert self.copy.read_bytes() == self.transcript.read_bytes()
        # Taken out after that, it is still what the launcher copied
        self.rewrite(self.entries[:1])
        recorder.catch_up(self.transcript, self.copy)
        compared = recorder.compare(self.host, self.transcript)
        assert late in compared.gone
        assert compared.rewritten == times + 1
        assert (compared.dropped, len(compared.gone)) == (0, len(self.entries))
        assert f"rewritten {times + 1} times" in compared.header()[0]

    def test_what_has_no_room_left_after_many_rewrites_is_said(self):
        whole = len("".join(json.dumps(entry) + "\n" for entry in self.entries))
        with unittest.mock.patch.object(recorder, "MOST_COPIED", whole + 10):
            for _ in range(recorder.MOST_PUT_ASIDE + 2):
                self.rewrite(self.entries)
                recorder.catch_up(self.transcript, self.copy)
                self.rewrite(self.entries[:1])
                recorder.catch_up(self.transcript, self.copy)
                recorder.catch_up(self.transcript, self.copy)
            last = recorder.put_aside(self.copy)[-1]
            assert last.stat().st_size <= whole + 10
            compared = recorder.compare(self.host, self.transcript)
        assert compared.dropped > 0
        said = "\n".join(compared.header())
        assert f"NOT ALL KEPT: rewritten {compared.rewritten} times" in said
        assert f"{compared.dropped} bytes had no room" in said
        # A note that does not hold up says nothing
        Path(f"{self.copy}{recorder.BEYOND_SUFFIX}").write_text('{"rewrites": "9"')
        assert recorder.Beyond.of(self.copy) == recorder.Beyond()

    def test_a_copy_put_aside_meanwhile_is_not_added_to(self):
        recorder.catch_up(self.transcript, self.copy)
        before = self.copy.read_bytes()
        with self.transcript.open("a") as transcript:
            transcript.write(json.dumps(prompts_at(time.time())[0]) + "\n")
        aside = self.copy.with_name(self.copy.name + ".1" + recorder.ASIDE_SUFFIX)
        with files.open_locked(self.copy, "ab"):
            catching_up = threading.Thread(
                target=recorder.catch_up, args=(self.transcript, self.copy)
            )
            catching_up.start()
            time.sleep(0.2)
            # What the launcher that had the lock did with it
            os.replace(self.copy, aside)
            self.copy.write_bytes(b"")
        catching_up.join(10)
        assert aside.read_bytes() == before
        assert self.copy.read_bytes() == self.transcript.read_bytes()

    def test_a_session_is_copied_while_it_runs(self):
        added = json.dumps(prompts_at(time.time())[0])
        self.launch(session=f"echo '{added}' >> '{self.transcript}'")
        assert self.copy.read_bytes() == self.transcript.read_bytes()

    def test_a_transcript_no_session_wrote_to_is_not_copied(self):
        earlier = time.time() - 60
        os.utime(self.transcript, (earlier, earlier))
        self.launch()
        assert not self.copy.exists()

    def test_the_trace_shows_what_was_removed(self):
        recorder.catch_up(self.transcript, self.copy)
        self.rewrite([self.entries[0], *self.entries[3:]])
        result = self.launch("--trace")
        assert "# transcript  CHANGED: 2 lines" in result.stdout
        assert "$ curl https://evil.test  REMOVED FROM THE TRANSCRIPT" in result.stdout
        assert "$ make test\n" in result.stdout
        failed = self.launch("--trace", "--failed").stdout
        assert "evil.test" in failed
        assert "make test" not in failed

    def test_the_trace_says_how_far_the_transcript_is_to_be_believed(self):
        without = self.launch("--trace").stdout
        assert "# transcript  as it is now, the launcher has no copy" in without
        recorder.catch_up(self.transcript, self.copy)
        assert (
            "# transcript  as the launcher copied it (5 lines)"
            in self.launch("--trace").stdout
        )

    def test_a_session_that_removed_its_transcript_is_still_traced(self):
        recorder.catch_up(self.transcript, self.copy)
        self.transcript.unlink()
        assert recorder.removed_transcripts(self.host) == [self.transcript]
        result = self.launch("--trace")
        assert result.status == 0, result.stderr
        assert "# session     0a  " in result.stdout
        assert "# transcript  REMOVED, it is no longer there" in result.stdout
        assert "$ curl https://evil.test  REMOVED FROM THE TRANSCRIPT" in result.stdout
        assert "# tool calls  2 (Bash 2)" in result.stdout
        listed = self.launch("--trace", "list").stdout
        assert re.search(r"0a +1 prompts +2 calls  REMOVED  ", listed)
        assert "evil.test" in self.launch("--trace", "0a", "--failed").stdout

    def test_a_removed_transcript_is_said_when_the_session_ends(self):
        # Written to, so that it is copied, then removed
        added = json.dumps(prompts_at(time.time())[0])
        gone = (
            f"echo '{added}' >> '{self.transcript}'; sleep 1.2; rm '{self.transcript}'"
        )
        result = self.launch(session=gone)
        assert "the transcript of 0a was removed" in result.stderr

    def test_a_subagent_that_removed_its_transcript_is_still_traced(self):
        ran = call(3, self.now + 3, "curl https://evil.test/sub")
        theirs = self.subagent([*prompts_at(self.now + 3), *ran])
        recorder.Copier(self.host, time.time() - 60).look()
        theirs.unlink()
        assert recorder.removed_subagents(self.host, self.transcript) == [theirs]
        result = self.launch("--trace")
        assert re.search(
            r"agent    bash        \$ curl https://evil.test/sub"
            r"  REMOVED FROM THE TRANSCRIPT",
            result.stdout,
        )

    def test_a_line_that_holds_no_entry_is_shown_as_unreadable(self):
        # Half a line ahead of the entry Claude Code writes next
        with open(self.transcript, "a") as transcript:
            transcript.write('{"x":"' + json.dumps(call(3, self.now + 3, "id")[0]))
            transcript.write("\n")
        recorder.catch_up(self.transcript, self.copy)
        result = self.launch("--trace")
        assert "# transcript  1 lines CANNOT BE READ" in result.stdout
        assert re.search(
            r"sandbox  transcript  UNREADABLE line of the transcript: \{\"x\":\"\{",
            result.stdout,
        )
        failed = self.launch("--trace", "--failed").stdout
        assert "UNREADABLE line of the transcript" in failed
        # Taken out again, it is gone as any line is
        self.rewrite(self.entries)
        recorder.catch_up(self.transcript, self.copy)
        gone = recorder.compare(self.host, self.transcript).gone
        assert [entry["type"] for entry in gone] == ["unreadable-line"]

    def test_a_copy_that_stopped_at_its_limit_is_not_said_to_be_whole(self):
        size = self.transcript.stat().st_size
        with unittest.mock.patch.object(recorder, "MOST_COPIED", size):
            recorder.catch_up(self.transcript, self.copy)
            whole = recorder.compare(self.host, self.transcript)
            assert not whole.cut_short
            with open(self.transcript, "a") as transcript:
                transcript.write(json.dumps(call(3, self.now + 3, "id")[0]) + "\n")
            recorder.catch_up(self.transcript, self.copy)
            compared = recorder.compare(self.host, self.transcript)
        assert self.copy.stat().st_size == size
        assert compared.cut_short
        assert "NOT ALL COPIED" in compared.header()[0]
        assert "as the launcher copied it" not in "".join(compared.header())

    def test_a_line_too_long_to_hold_is_compared_like_any_other(self):
        # Half a line ahead of the entry Claude Code writes next, of more
        # than is held of a line
        glued = b"x" * 2000 + json.dumps(call(3, self.now + 3, "id")[0]).encode()
        with unittest.mock.patch.object(recorder, "LINE_LIMIT", 1000):
            with open(self.transcript, "ab") as transcript:
                transcript.write(glued + b"\n")
            recorder.catch_up(self.transcript, self.copy)
            as_copied = recorder.compare(self.host, self.transcript)
            assert (as_copied.lines, as_copied.gone) == (len(self.entries) + 1, [])
            # Taken out again, with blank lines for the length it had
            self.rewrite(self.entries)
            with open(self.transcript, "ab") as transcript:
                transcript.write(b"\n" * (len(glued) + 1))
            recorder.catch_up(self.transcript, self.copy)
            compared = recorder.compare(self.host, self.transcript)
        assert (compared.rewritten, compared.lines) == (0, len(self.entries) + 1)
        assert compared.gone == [
            {"type": "unreadable-line", "text": "(a line too long to read)"}
        ]
        assert "CHANGED: 1 lines the launcher copied" in compared.header()[0]

    def test_a_transcript_that_was_never_copied_is_not_read_to_be_compared(self):
        with unittest.mock.patch.object(recorder, "line_digests") as read:
            compared = recorder.compare(self.host, self.transcript)
        read.assert_not_called()
        assert (compared.copied, compared.lines) == (False, 0)

    def test_a_look_adds_no_more_to_a_copy_than_a_turn_takes(self):
        with unittest.mock.patch.object(recorder, "MOST_A_TURN", 100):
            copier = recorder.Copier(self.host, time.time() - 60)
            # More is left, which the next look is to take at once
            assert copier.look()
            assert self.copy.stat().st_size == 100
            other = self.decoy("0b", 1000)
            assert copier.look()
            sizes = [self.copy.stat().st_size, self.host_copy(other).stat().st_size]
            assert sizes == [200, 100]
            # A copy that is behind its transcript is not one that stopped
            behind = recorder.compare(self.host, self.transcript)
            assert not behind.no_room
            assert "NOT ALL COPIED" not in "\n".join(behind.header())
            # All there is of each once the session is over
            assert not copier.look(whole=True)
        assert self.copy.read_bytes() == self.transcript.read_bytes()
        assert self.host_copy(other).stat().st_size == 1000
        assert copier.stopped == 0

    def test_a_transcript_has_its_turn_in_the_order_it_was_first_written_to(self):
        size = self.transcript.stat().st_size
        added = json.dumps(prompts_at(self.now + 5)[0]) + "\n"
        with unittest.mock.patch.object(recorder, "MOST_A_SESSION", size + len(added)):
            copier = recorder.Copier(self.host, time.time() - 60)
            copier.look()
            # Made by what the session ran, after its transcript was there
            decoys = [self.decoy(name, 4000) for name in ("00", "zz")]
            with open(self.transcript, "a") as transcript:
                transcript.write(added)
            # However they are listed, the one seen first is served first
            listed = [*decoys, self.transcript]
            with unittest.mock.patch.object(
                recorder, "session_transcripts", return_value=listed
            ):
                copier.look()
        assert self.copy.read_bytes() == self.transcript.read_bytes()
        assert [self.host_copy(decoy).exists() for decoy in decoys] == [False, False]

    def test_no_more_is_copied_in_a_session_than_the_launcher_has_room_for(self):
        size = self.transcript.stat().st_size
        with unittest.mock.patch.object(recorder, "MOST_A_SESSION", size + 1000):
            copier = recorder.Copier(self.host, time.time() - 60)
            copier.look()
            decoys = [self.decoy(f"d{number}", 4000) for number in range(5)]
            assert not copier.look()
            copies = [self.host_copy(decoy) for decoy in decoys]
            assert sum(recorder.length(copy) or 0 for copy in copies) == 1000
            # Noted of each once its copy is found no longer by the next
            # look, nobody else is adding to it
            assert copier.stopped == 0
            assert not copier.look()
            assert sum(recorder.length(copy) or 0 for copy in copies) == 1000
            assert copier.stopped == len(decoys)
            # Said of each that stopped short, and of no other
            short = recorder.compare(self.host, decoys[0])
            assert short.no_room
            assert "NOT ALL COPIED: a launcher copies no more than" in "\n".join(
                short.header()
            )
            whole = recorder.compare(self.host, self.transcript)
            assert not whole.no_room
            assert whole.header() == [
                f"transcript  as the launcher copied it ({len(self.entries)} lines)"
            ]
            # What the session's own transcript gains from then on is not
            # copied either, which is said of it
            with open(self.transcript, "a") as transcript:
                transcript.write(json.dumps(call(3, self.now + 3, "id")[0]) + "\n")
            copier.look()
            copier.look(whole=True)
        assert self.copy.stat().st_size == size
        assert copier.stopped == len(decoys) + 1
        said = recorder.compare(self.host, self.transcript).header()
        assert "transcript  NOT ALL COPIED: a launcher copies no more than" in said[0]
        assert "as the launcher copied it" not in "\n".join(said)

    def test_a_rewrite_is_still_kept_once_there_is_no_room(self):
        size = self.transcript.stat().st_size
        with unittest.mock.patch.object(recorder, "MOST_A_SESSION", size):
            copier = recorder.Copier(self.host, time.time() - 60)
            copier.look()
            self.rewrite(self.entries[:1])
            for _ in range(3):
                copier.look()
        compared = recorder.compare(self.host, self.transcript)
        assert (compared.rewritten, len(compared.gone)) == (1, len(self.entries) - 1)
        # The copy that started anew has nothing of what is there now
        assert compared.no_room
        assert "NOT ALL COPIED" in "\n".join(compared.header())

    def test_a_copy_that_stopped_short_is_not_taken_up_by_a_later_session(self):
        size = self.transcript.stat().st_size
        with unittest.mock.patch.object(recorder, "MOST_A_SESSION", size + 100):
            copier = recorder.Copier(self.host, time.time() - 60)
            copier.look()
            decoy = self.decoy("d0", 4000)
            copier.look()
            copier.look()
        copy = self.host_copy(decoy)
        assert (copy.stat().st_size, copier.stopped) == (100, 1)
        # Neither for being behind, nor for when it says it was written:
        # what one session left would use up the room of those after it
        for since in (time.time() + 60, time.time() - 60):
            later = recorder.Copier(self.host, since)
            later.look()
            assert (copy.stat().st_size, later.stopped) == (100, 0)
        # Once it is written to again, as any other
        later = recorder.Copier(self.host, time.time() + 60)
        with open(decoy, "ab") as written:
            written.write(b"x")
        later.look()
        assert copy.stat().st_size == 4001
        assert recorder.compare(self.host, decoy).no_room

    def test_a_copy_another_launcher_adds_to_is_not_said_to_stop_short(self):
        def gains() -> None:
            with open(self.transcript, "a") as transcript:
                transcript.write(json.dumps(prompts_at(time.time())[0]) + "\n")

        with unittest.mock.patch.object(recorder, "MOST_A_SESSION", 0):
            copier = recorder.Copier(self.host, time.time() - 60)
        # A session of the project whose launcher has room copies it too,
        # between the looks of the one that has none
        for _ in range(3):
            gains()
            copier.look()
            recorder.catch_up(self.transcript, self.copy)
        assert copier.stopped == 0
        compared = recorder.compare(self.host, self.transcript)
        assert (compared.no_room, compared.gone) == (False, [])
        assert "NOT ALL COPIED" not in "\n".join(compared.header())
        # Until nobody does any more
        gains()
        copier.look()
        assert copier.stopped == 0
        copier.look()
        assert copier.stopped == 1
        assert recorder.compare(self.host, self.transcript).no_room

    def test_a_launcher_that_ran_out_of_room_says_so_when_the_session_ends(
        self, capsys: pytest.CaptureFixture[str]
    ):
        with (
            unittest.mock.patch.object(recorder, "MOST_A_SESSION", 10),
            recorder.transcripts_copied(self.host),
            open(self.transcript, "a") as transcript,
        ):
            transcript.write(json.dumps(prompts_at(self.now + 5)[0]) + "\n")
        said = capsys.readouterr().err
        assert "1 transcripts were not all copied" in said
        assert "--trace says NOT ALL COPIED of each" in said
        assert self.copy.stat().st_size == 10
        # Nothing of it to compare with, and why
        why = (
            "transcript  NOT ALL COPIED: a launcher copies no more than"
            f" {recorder.MOST_A_SESSION >> 20} MB in one session, what was taken"
            " out of it after that is not known"
        )
        assert recorder.compare(self.host, self.transcript).header() == [
            "transcript  as it is now, the launcher has no copy of it to compare",
            why,
        ]

    def test_a_transcript_that_gained_more_than_a_turn_takes_is_not_waited_on(self):
        added = json.dumps(prompts_at(self.now + 5)[0]) + "\n"
        with (
            unittest.mock.patch.object(recorder, "MOST_A_TURN", 20),
            unittest.mock.patch.object(recorder, "LOOK_EVERY", 0.3),
            recorder.transcripts_copied(self.host),
        ):
            with open(self.transcript, "a") as transcript:
                transcript.write(added)
            # Dozens of turns: with the wait between two looks ahead of
            # each, they would take far longer than this
            size = self.transcript.stat().st_size
            assert size > 30 * 20
            deadline = time.monotonic() + 3
            while time.monotonic() < deadline and recorder.length(self.copy) != size:
                time.sleep(0.05)
            assert self.copy.read_bytes() == self.transcript.read_bytes()

    def test_looks_that_failed_are_counted(self):
        copier = recorder.Copier(self.host, time.time() - 60)
        with unittest.mock.patch.object(
            recorder, "catch_up", side_effect=OSError(24, "Too many open files")
        ):
            copier.look()
        assert copier.failed == 1
        assert "Too many open files" in copier.problem

    def test_a_copy_does_not_grow_past_its_limit(self):
        size = self.transcript.stat().st_size
        with unittest.mock.patch.object(recorder, "MOST_COPIED", size - 10):
            recorder.catch_up(self.transcript, self.copy)
            recorder.catch_up(self.transcript, self.copy)
        assert self.copy.stat().st_size == size - 10

    def test_no_more_transcripts_are_followed_than_so_many(self):
        with (
            unittest.mock.patch.object(recorder, "MOST_FOLLOWED", 3),
            unittest.mock.patch.object(recorder, "MOST_CHECKED", 2),
        ):
            copier = recorder.Copier(self.host, time.time() - 60)
            copier.look()
            decoys = [self.decoy(f"d{number}", 10) for number in range(6)]
            looked_at = unittest.mock.patch.object(
                copier, "written_to", wraps=copier.written_to
            )
            # No more of those not followed are looked at than so many
            with looked_at as written_to:
                copier.look()
            assert written_to.call_count == 2
            copier.look()
            followed = [self.host_copy(decoy).exists() for decoy in decoys]
            assert sum(followed) == 2
            assert copier.unfollowed
            # Once that is said, none of them is looked at any more
            with unittest.mock.patch.object(copier, "written_to") as written_to:
                copier.look()
            written_to.assert_not_called()
            # The session's own still has its turn
            added = json.dumps(prompts_at(self.now + 5)[0]) + "\n"
            with open(self.transcript, "a") as transcript:
                transcript.write(added)
            copier.look()
        assert self.copy.read_bytes() == self.transcript.read_bytes()

    def test_one_of_many_older_transcripts_is_found_in_its_turn(self):
        older = [self.decoy(f"d{number}", 10) for number in range(5)]
        with unittest.mock.patch.object(recorder, "MOST_CHECKED", 2):
            copier = recorder.Copier(self.host, time.time() + 60)
            # A resumed session adds to one of them
            with open(older[3], "ab") as resumed:
                resumed.write(b"x")
            looks = 0
            while not self.host_copy(older[3]).exists() and looks < 5:
                copier.look()
                looks += 1
        assert self.host_copy(older[3]).read_bytes() == older[3].read_bytes()
        assert 1 < looks <= 3

    def test_a_launcher_that_followed_all_it_can_says_so(
        self, capsys: pytest.CaptureFixture[str]
    ):
        with (
            unittest.mock.patch.object(recorder, "MOST_FOLLOWED", 1),
            recorder.transcripts_copied(self.host),
        ):
            with open(self.transcript, "a") as transcript:
                transcript.write(json.dumps(prompts_at(self.now + 5)[0]) + "\n")
            time.sleep(recorder.LOOK_EVERY * 2)
            self.decoy("d0", 10)
        said = capsys.readouterr().err
        assert "more than the 1 a launcher follows in one session" in said

    def test_old_copies_go(self):
        recorder.catch_up(self.transcript, self.copy)
        long_ago = time.time() - (recorder.KEPT_DAYS + 1) * 86400
        os.utime(self.copy, (long_ago, long_ago))
        recorder.let_go_of_old_copies(self.host)
        assert not self.copy.exists()

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
        assert copy.parent.name == "0a.subagents"
        assert copy.parent.parent == self.copy.parent
        recorder.Copier(self.host, time.time() - 60).look()
        assert copy.read_bytes() == theirs.read_bytes()
        assert self.copy.read_bytes() == self.transcript.read_bytes()
        # The subagent takes its command out of its own transcript
        self.subagent(prompts_at(self.now + 3))
        recorder.Copier(self.host, time.time() - 60).look()
        compared = recorder.compare(self.host, theirs)
        assert len(compared.gone) == 2
        result = self.launch("--trace")
        assert "# subagents   1, CHANGED: 2 lines" in result.stdout
        assert re.search(
            r"agent    bash        \$ curl https://evil.test/sub"
            r"  REMOVED FROM THE TRANSCRIPT",
            result.stdout,
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
        assert "# subagents   1, as the launcher copied them (2 lines)" in traced
        # In the summary of the session, and by who did it
        assert "#   /home/me/.bashrc x1  OUTSIDE PROJECT" in traced
        assert re.search(r"agent    write       file: /home/me/.bashrc", traced)
        # What it was asked is not a prompt of the user
        assert traced.count("user     prompt") == 1
        # A session without any says nothing of them
        other = self.write_transcript("0b", prompts_at(self.now + 9))
        os.utime(other, (self.now + 99, self.now + 99))
        assert "# subagents" not in self.launch("--trace").stdout

    def test_the_copies_of_subagents_go_when_they_are_old(self):
        theirs = self.subagent(prompts_at(self.now))
        copy = recorder.copy_path(self.host, theirs)
        recorder.catch_up(theirs, copy)
        recorder.catch_up(self.transcript, self.copy)
        long_ago = time.time() - (recorder.KEPT_DAYS + 1) * 86400
        os.utime(copy, (long_ago, long_ago))
        recorder.let_go_of_old_copies(self.host)
        assert not copy.parent.exists()
        assert self.copy.exists()
