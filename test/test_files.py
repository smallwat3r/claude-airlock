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


class Sparse(Pieces):
    """A file with holes, as a system that tells where they are has it:
    each from its start to its end, where it reads as nothing but zeros.
    Where data goes on from a hole, and where the next one starts, the
    end of the file when none does."""

    def __init__(self, content: bytes, *holes: tuple[int, int]) -> None:
        super().__init__(content)
        self.holes = sorted(holes)

    def seek(self, offset: int, whence: int = os.SEEK_SET) -> int:
        if whence not in (files.SEEK_DATA, files.SEEK_HOLE):
            return super().seek(offset, whence)
        size = len(self.getbuffer())
        if offset >= size:
            raise OSError(errno.ENXIO, "No such device or address")
        inside = [(start, end) for start, end in self.holes if start <= offset < end]
        if whence == files.SEEK_HOLE:
            later = [start for start, _ in self.holes if start > offset]
            return super().seek(offset if inside else min([*later, size]))
        if inside:
            offset = inside[0][1]
            if offset >= size:
                raise OSError(errno.ENXIO, "No such device or address")
        return super().seek(offset)


class FilesTest(LauncherTest):
    def test_a_line_too_long_to_take_is_not_read_through_its_holes(self):
        hole = bytes(100_000)
        tail = b"y\n" + b'{"after": 1}\n'
        sparse = Sparse(b'{"a": 1}\n' + b"x" * 50 + hole + tail, (59, 100_059))
        assert list(files.bounded_lines(sparse, 30)) == [
            b'{"a": 1}\n',
            None,
            b'{"after": 1}\n',
        ]
        # The hole was not read, the data after it was
        assert sum(sparse.taken) < 200
        # Nor one that goes on to the end
        sparse = Sparse(b"x" * 50 + hole, (50, 100_050))
        assert list(files.bounded_lines(sparse, 30)) == [None]
        assert sum(sparse.taken) < 100
        # Where holes cannot be told, the line is read through
        with unittest.mock.patch.object(files, "SEEK_DATA", -1):
            dense = Pieces(b"x" * 50 + hole + tail)
            assert list(files.bounded_lines(dense, 30))[-1] == b'{"after": 1}\n'

    def test_a_line_with_a_hole_is_read_as_none_whatever_its_length(self):
        # Shorter than a line may be, as digested_lines has it: a line
        # Claude Code never writes, and the hole is not read as zeros
        line = b'{"a": 1}\n'
        holed = b'{"b": "' + bytes(1000) + b'"}\n'
        sparse = Sparse(line + holed + line, (16, 1016))
        assert list(files.bounded_lines(sparse, 2000)) == [line, None, line]
        assert sum(sparse.taken) < 100
        sparse = Sparse(line + holed + line, (16, 1016))
        found = [held for _, held in files.digested_lines(sparse, 2000)]
        assert found == [line, None, line]
        # And a last one without its end, a hole to the end of the file
        sparse = Sparse(line + b"x" + bytes(1000), (10, 1010))
        assert list(files.bounded_lines(sparse, 2000)) == [line, None]
        # Nor is a pipe asked where a hole is, it has none
        read, write = os.pipe()
        with os.fdopen(write, "wb") as written:
            written.write(holed + b"last")
        with os.fdopen(read, "rb") as piped:
            assert list(files.bounded_lines(piped, 2000)) == [holed, b"last"]

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

    def test_a_tree_is_opened_up_without_following_a_link(self):
        top = self.work / "drop"
        (top / "a" / "b").mkdir(parents=True)
        for closed in (top / "a" / "b", top / "a", top):
            closed.chmod(0)
            self.cleanup.callback(closed.chmod, 0o700)
        files.open_up(str(top), 100)
        for opened in (top, top / "a", top / "a" / "b"):
            assert opened.stat().st_mode & 0o777 == 0o700
        # Listed as a directory, then a link in its place: what it leads
        # to is not opened up, nor anything in it
        elsewhere = self.work / "elsewhere"
        (elsewhere / "b").mkdir(parents=True)
        for kept in (elsewhere / "b", elsewhere):
            kept.chmod(0o500)
            self.cleanup.callback(kept.chmod, 0o700)
        (top / "c").mkdir()
        listed = files._subdirectories

        def swapped(directory: int, most: int) -> list[str]:
            names = listed(directory, most)
            if "c" in names:
                (top / "c").rename(top / "moved")
                (top / "c").symlink_to(elsewhere)
            return names

        with unittest.mock.patch.object(files, "_subdirectories", swapped):
            files.open_up(str(top), 100)
        assert elsewhere.stat().st_mode & 0o777 == 0o500
        assert (elsewhere / "b").stat().st_mode & 0o777 == 0o500

    def test_a_link_into_a_directory_is_in_it(self):
        inner = self.project / "inner"
        inner.mkdir()
        link = self.home / "link"
        link.symlink_to(inner)
        assert files.leads_under(str(inner / "x"), str(self.project))
        assert files.leads_under(str(link / "x"), str(self.project))
        # A directory reached through a link the same
        assert files.leads_under(str(inner / "x"), str(link))
        assert not files.leads_under(str(self.project), str(self.project))
        assert not files.leads_under(str(self.home / "other"), str(self.project))

    def test_the_end_of_a_file_is_read_in_whole_lines(self):
        file = self.work / "lines"
        file.write_bytes(b"first\nsecond\nthird\n")
        with open(file, "rb") as read:
            # Starting in the middle of the second: it is not read
            assert list(files.last_lines(read, 9)) == [b"third\n"]
        with open(file, "rb") as read:
            assert list(files.last_lines(read, 100)) == [
                b"first\n",
                b"second\n",
                b"third\n",
            ]
        with open(file, "rb") as read:
            # A line too long is passed over as bounded_lines has it
            assert list(files.last_lines(read, 100, longest=5)) == [
                b"first\n",
                None,
                b"third\n",
            ]

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

    def test_what_stands_for_a_line_is_had_without_reading_its_holes(self):
        # A line then a hole to the end, as truncate -s 16T leaves it
        line = b'{"a": 1}\n'
        sparse = Sparse(line + b"x" + bytes(100_000), (10, 100_010))
        assert list(files.digested_lines(sparse, 1000)) == [
            (hashlib.sha256(line).digest(), line)
        ]
        assert sum(sparse.taken) < 100
        # Holes each shorter than a line may be, any number of them: a
        # line with one is none Claude Code writes, it stands for itself
        # as the holes it has, and is not held
        holed = b"x" + bytes(1000) + b"\n"
        holes = [(at + 1, at + 1001) for at in range(0, 50 * 1002, 1002)]
        sparse = Sparse(holed * 50 + line, *holes)
        found = list(files.digested_lines(sparse, 2000))
        assert [line for _, line in found] == [None] * 50 + [line]
        assert sum(sparse.taken) < 200
        assert len({digest for digest, _ in found}) == 2
        assert found[0][0] != hashlib.sha256(holed).digest()
        # Where holes cannot be told, the same lines are read through
        with unittest.mock.patch.object(files, "SEEK_HOLE", -1):
            dense = Pieces(holed + line)
            assert list(files.digested_lines(dense, 2000)) == [
                (hashlib.sha256(holed).digest(), holed),
                (hashlib.sha256(line).digest(), line),
            ]

    def test_a_line_past_ascii_is_held_at_four_bytes_a_byte(self):
        # One character past the first 65536 has Python keep the whole
        # text at four bytes for each
        ascii_line = b'"' + b"x" * 1000 + b'"'
        wide_line = b'"' + "\U0001f600".encode() + b"x" * 996 + b'"'
        assert len(wide_line) == len(ascii_line)
        assert files.held_size(ascii_line) >= 2 * len(ascii_line)
        assert files.held_size(wide_line) >= 4 * len(wide_line)
        assert files.held_size(wide_line) > files.held_size(ascii_line)

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


class ReadOnTest:
    def test_whole_lines_are_taken_and_a_line_still_written_is_left(self):
        read = b'{"a": 1}\n{"b": 2}\n{"c"'
        assert files.whole_lines(read, 64) == ([b'{"a": 1}', b'{"b": 2}'], 18)
        # Split at line feeds alone, what else ends a line is within one
        lines, _ = files.whole_lines(b"one\rtwo\xe2\x80\xa8three\n", 64)
        assert lines == [b"one\rtwo\xe2\x80\xa8three"]
        assert files.whole_lines(b"", 64) == ([], 0)
        assert files.whole_lines(b"not whole yet", 64) == ([], 0)
        # A read as long as is read at a time with no end of a line in
        # it is passed over, it would be read again without end
        assert files.whole_lines(b"x" * 64, 64) == ([], 64)

    def test_a_file_is_told_from_the_same_written_since(self, tmp_path):
        record = tmp_path / "record.jsonl"
        record.write_text("one\n")
        before = os.stat(record)
        assert files.stat_stamp(before) == files.stat_stamp(os.stat(record))
        assert files.file_id(before) == (before.st_dev, before.st_ino)
        # Written again to the same length and time: what the system
        # notes of it changed all the same
        record.write_text("two\n")
        os.utime(record, ns=(before.st_atime_ns, before.st_mtime_ns))
        now = os.stat(record)
        assert files.stat_stamp(now) != files.stat_stamp(before)
        # Only a stamp of a while ago is taken to tell it from what comes
        assert not files.stamp_settled(now)
        later = now.st_ctime_ns + 2 * files.STAMP_SETTLES_NS
        with unittest.mock.patch.object(time, "time_ns", return_value=later):
            assert files.stamp_settled(now)

    def test_a_text_past_ascii_is_held_wider(self):
        assert files.held_by("plain") == files.HELD_BY_BYTE
        assert files.held_by(b"plain") == files.HELD_BY_BYTE
        assert files.held_by("café") == files.HELD_BY_WIDE_BYTE
        assert files.held_by("café".encode()) == files.HELD_BY_WIDE_BYTE
