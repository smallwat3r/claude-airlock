#!/usr/bin/env python3
"""The launcher's own files: written whole, locked between launchers, and
what a session can write read without trusting it."""

from __future__ import annotations

import os

from harness import LauncherTest

from claude_airlock import files


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
