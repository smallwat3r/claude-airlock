#!/usr/bin/env python3
"""The launcher's own files: written whole, locked between launchers, and
what a session can write read without trusting it."""

from __future__ import annotations

import os
import unittest

from harness import LauncherTest

from claude_sandbox import files


class FilesTest(LauncherTest):
    def test_a_file_is_written_whole_and_for_the_user_alone(self):
        file = self.work / "record"
        for content in ("one", b"two"):
            self.assertTrue(files.write_whole(str(file), content, durable=True))
            self.assertEqual(list(self.work.glob("record*")), [file])
        self.assertEqual(file.read_bytes(), b"two")
        self.assertEqual(file.stat().st_mode & 0o777, 0o600)

    def test_a_file_that_is_there_can_be_left_as_it_is(self):
        file = self.work / "record"
        self.assertTrue(files.write_whole(str(file), "first", replace=False))
        self.assertFalse(files.write_whole(str(file), "second", replace=False))
        self.assertEqual(file.read_text(), "first")
        self.assertEqual(list(self.work.glob("record*")), [file])

    def test_a_lock_is_held_until_it_is_let_go_of(self):
        path = str(self.work / "lock")
        held = files.try_lock_file(path)
        self.assertIsNotNone(held)
        self.assertIsNone(files.try_lock_file(path))
        os.close(held)
        shared = [files.lock_file(path, shared=True) for _ in range(2)]
        # Shared among those who ask for it so, and with no one else
        self.assertIsNone(files.try_lock_file(path))
        for descriptor in shared:
            os.close(descriptor)
        again = files.try_lock_file(path)
        self.assertIsNotNone(again)
        os.close(again)

    def test_only_a_plain_file_is_opened(self):
        plain = self.work / "plain"
        plain.write_text("x")
        (self.work / "link").symlink_to(plain)
        os.mkfifo(self.work / "pipe")
        with files.open_plain(plain) as file:
            self.assertEqual(file.read(), b"x")
        for name in ("link", "pipe", "missing", "bin"):
            self.assertIsNone(files.open_plain(self.work / name), name)

    def test_only_a_json_object_is_one(self):
        self.assertEqual(files.json_object('{"a": 1}\n'), {"a": 1})
        self.assertEqual(files.json_object(b'{"a": "\xff"}'), {"a": "�"})
        for text in ("", "{", "[1]", "1", "null", "[" * 100_000):
            self.assertIsNone(files.json_object(text), text[:10])

    def test_a_leading_tilde_is_the_home_directory(self):
        home = "/home/me"
        for path, expanded in (
            ("~", home),
            ("~/x", f"{home}/x"),
            ("~other/x", "~other/x"),
            ("/abs/~", "/abs/~"),
            ("rel", "rel"),
        ):
            self.assertEqual(files.expand_home(path, home), expanded)


if __name__ == "__main__":
    unittest.main()
