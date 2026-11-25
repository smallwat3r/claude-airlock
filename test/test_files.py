#!/usr/bin/env python3
"""The launcher's own files: written whole, locked between launchers, and
what a session can write read without trusting it."""

from __future__ import annotations

import errno
import hashlib
import io
import os
import threading
import time
import unittest.mock

import pytest
from harness import LauncherTest

from claude_airlock import background, files


class Pieces(io.BytesIO):
    """A file that keeps how much each read of a line gave."""

    def __init__(self, content: bytes) -> None:
        super().__init__(content)
        self.taken: list[int] = []

    def readline(self, size: int | None = -1) -> bytes:
        line = super().readline(size)
        self.taken.append(len(line))
        return line


class FilesTest(LauncherTest):
    def test_a_file_is_written_whole_and_for_the_user_alone(self):
        file = self.work / "record"
        for content in ("one", b"two"):
            assert files.write_whole(str(file), content, durable=True)
            assert list(self.work.glob("record*")) == [file]
        assert file.read_bytes() == b"two"
        assert file.stat().st_mode & 511 == 384

    def test_a_file_that_is_there_can_be_left_as_it_is(self):
        file = self.work / "record"
        assert files.write_whole(str(file), "first", replace=False)
        assert not files.write_whole(str(file), "second", replace=False)
        assert file.read_text() == "first"
        assert list(self.work.glob("record*")) == [file]

    def test_a_record_keeps_its_latest_lines(self):
        record = self.work / "state" / "record.jsonl"
        for number in range(5):
            files.append_kept(str(record), str(number), 3)
        assert record.read_text() == "2\n3\n4\n"
        assert list(record.parent.iterdir()) == [record]
        assert record.stat().st_mode & 511 == 384

    def test_a_record_that_cannot_be_cut_short_is_left_whole(self):
        record = self.work / "state" / "record.jsonl"
        for number in range(3):
            files.append_kept(str(record), str(number), 3)
        # A full disk as the lines that stay are written
        full = OSError(errno.ENOSPC, "No space left on device")
        with (
            unittest.mock.patch.object(files.os, "replace", side_effect=full),
            pytest.raises(OSError, match="No space"),
        ):
            files.append_kept(str(record), "3", 3)
        assert record.read_text() == "0\n1\n2\n3\n"
        assert list(record.parent.iterdir()) == [record]
        files.append_kept(str(record), "4", 3)
        assert record.read_text() == "2\n3\n4\n"

    def test_a_record_given_anothers_place_is_not_the_one_locked(self):
        record = self.work / "state" / "record.jsonl"
        files.append_kept(str(record), "0", 1)
        with files.open_locked(record, "a+") as held:
            waiting = threading.Thread(
                target=files.append_kept, args=(str(record), "2", 9)
            )
            waiting.start()
            time.sleep(0.2)
            # As append_kept does past its lines, under the lock
            files.write_whole(str(record), "1\n")
            assert held.fileno()
        waiting.join(10)
        assert record.read_text() == "1\n2\n"

    def test_work_that_fails_next_to_a_session_is_said(self, capsys):
        def keep_copying(_stop: threading.Event) -> None:
            raise ValueError("odd")

        def kept_up(stop: threading.Event) -> None:
            stop.wait()

        with background.in_background(keep_copying), background.in_background(kept_up):
            pass
        said = capsys.readouterr().err
        assert "FAILED (keep copying)" in said
        assert "ValueError('odd')" in said
        assert "kept up" not in said

    def test_a_lock_is_held_until_it_is_let_go_of(self):
        path = str(self.work / "lock")
        held = files.try_lock_file(path)
        assert held is not None
        assert files.try_lock_file(path) is None
        os.close(held)
        shared = [files.lock_file(path, shared=True) for _ in range(2)]
        # Shared among those who ask for it so, and with no one else
        assert files.try_lock_file(path) is None
        for descriptor in shared:
            os.close(descriptor)
        again = files.try_lock_file(path)
        assert again is not None
        os.close(again)

    def test_only_a_plain_file_is_opened(self):
        plain = self.work / "plain"
        plain.write_text("x")
        (self.work / "link").symlink_to(plain)
        os.mkfifo(self.work / "pipe")
        with files.open_plain(plain) as file:
            assert file.read() == b"x"
        for name in ("link", "pipe", "missing", "bin"):
            assert files.open_plain(self.work / name) is None, name

    def test_a_line_too_long_to_hold_still_has_what_stands_for_it(self):
        lines = [
            b"short\n",
            b"x" * 5000 + b"\n",
            # As long as a line may be, with its end
            b"y" * 1000 + b"\n",
            b"\n",
            b"z" * 3000,
        ]
        read = Pieces(b"".join(lines))
        with unittest.mock.patch.object(files, "PIECE", 64):
            found = list(files.digested_lines(read, 1000))
        # Not the last one, which has no end
        assert [line for _, line in found] == [lines[0], None, lines[2], lines[3]]
        assert [digest for digest, _ in found] == [
            hashlib.sha256(line).digest() for line in lines[:4]
        ]
        # Never more of a line at a time than may be held of one
        assert max(read.taken) == 1001

    def test_only_a_json_object_is_one(self):
        assert files.json_object('{"a": 1}\n') == {"a": 1}
        assert files.json_object(b'{"a": "\xff"}') == {"a": "�"}
        for text in ("", "{", "[1]", "1", "null", "[" * 100_000):
            assert files.json_object(text) is None, text[:10]

    def test_a_leading_tilde_is_the_home_directory(self):
        home = "/home/me"
        for path, expanded in (
            ("~", home),
            ("~/x", f"{home}/x"),
            ("~other/x", "~other/x"),
            ("/abs/~", "/abs/~"),
            ("rel", "rel"),
        ):
            assert files.expand_home(path, home) == expanded
