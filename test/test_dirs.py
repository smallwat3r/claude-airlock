#!/usr/bin/env python3
"""The directories mounted next to the project."""

from __future__ import annotations

import unittest

from harness import LauncherTest


class ExtraDirsTest(LauncherTest):
    def setUp(self):
        super().setUp()
        self.ref = self.home / "ref"
        self.shared = self.home / "claude-shared"

    def test_read_only_dir(self):
        result = self.launch(
            "--add-dir-ro", "~/ref", "-p", "hello", CLAUDE_AIRLOCK_FEATURES=""
        )
        self.assertIn(f"--volume={self.ref}:{self.ref}:ro,z", result.flags)
        unasked = "--dangerously-skip-permissions"
        self.assertEqual(
            result.command, [f"--add-dir={self.ref}", unasked, "-p", "hello"]
        )

    def test_a_prompt_is_not_taken_for_a_directory(self):
        # --add-dir is variadic, as two arguments it would take the prompt
        result = self.launch("--add-dir", "~/ref", "hello", CLAUDE_AIRLOCK_FEATURES="")
        unasked = "--dangerously-skip-permissions"
        self.assertEqual(result.command, [f"--add-dir={self.ref}", unasked, "hello"])

    def test_read_write_dir_and_its_secrets(self):
        (self.ref / ".env").touch()
        flags = self.launch(f"--add-dir={self.ref}").flags
        self.assertIn(f"--volume={self.ref}:{self.ref}:z", flags)
        self.assertIn(f"--volume=/dev/null:{self.ref / '.env'}:ro", flags)

    def test_a_protected_path_is_read_only_inside_what_is_mounted(self):
        kit = self.shared / "kit"
        kit.mkdir(parents=True)
        (self.project / "docs").mkdir()
        self.write_config(f"CLAUDE_AIRLOCK_PROTECT=~/claude-shared/kit:{self.ref}")
        flags = self.launch(
            "--add-dir", "~/ref", CLAUDE_AIRLOCK_PROTECT="docs:~/not-mounted"
        ).flags
        # In the shared directory and in the project, on top of them
        self.assertIn(f"--volume={self.shared}:{self.shared}:z", flags)
        for inside in (kit, self.project / "docs"):
            self.assertIn(f"--volume={inside}:{inside}:ro,z", flags)
        # A mounted directory itself is mounted read-only, once
        self.assertIn(f"--volume={self.ref}:{self.ref}:ro,z", flags)
        self.assertNotIn(f"--volume={self.ref}:{self.ref}:z", flags)
        # What is not mounted is not brought in
        self.assertFalse([flag for flag in flags if "not-mounted" in flag])
        self.assertIn(
            f"--env=CLAUDE_AIRLOCK_PROTECT={kit}:{self.project / 'docs'}", flags
        )

    def test_a_protected_path_that_could_be_made_inside_is_refused(self):
        result = self.launch(CLAUDE_AIRLOCK_PROTECT="docs")
        self.assert_refused(result, "cannot protect docs: it does not exist")
        result = self.launch(CLAUDE_AIRLOCK_PROTECT=str(self.home / "proj"))
        self.assert_refused(result, "the project is in it")

    def test_home_directory_is_refused(self):
        result = self.launch(cwd=self.home)
        self.assert_refused(result, "it would defeat the sandbox")

    def test_a_link_to_the_home_directory_is_refused(self):
        link = self.work / "elsewhere"
        link.symlink_to(self.home)
        result = self.launch("--add-dir", str(link))
        self.assert_refused(result, "it would defeat the sandbox")

    def test_a_dir_inside_the_project_has_its_secrets_hidden_once(self):
        inside = self.project / "sub"
        inside.mkdir()
        (inside / ".env").touch()
        flags = self.launch("--add-dir", "./sub").flags
        hidden = f"--volume=/dev/null:{inside / '.env'}:ro"
        self.assertEqual(flags.count(hidden), 1)

    def test_a_secret_that_cannot_be_hidden_is_not_left_visible(self):
        (self.project / ".env.a:b").touch()
        self.assert_refused(self.launch(), "cannot hide")

    def test_filesystem_root_is_refused(self):
        result = self.launch("--add-dir", "/")
        self.assert_refused(result, "it would defeat the sandbox")

    def test_default_shared_dir_is_mounted(self):
        self.shared.mkdir()
        flags = self.launch().flags
        self.assertIn(f"--volume={self.shared}:{self.shared}:z", flags)

    def test_shared_dir_can_be_moved(self):
        self.shared.mkdir()
        flags = self.launch(CLAUDE_AIRLOCK_SHARED_DIR=str(self.ref)).flags
        self.assertIn(f"--volume={self.ref}:{self.ref}:z", flags)
        self.assertFalse([flag for flag in flags if "claude-shared" in flag])

    def test_empty_shared_dir_setting_mounts_none(self):
        self.shared.mkdir()
        flags = self.launch(CLAUDE_AIRLOCK_SHARED_DIR="").flags
        self.assertFalse([flag for flag in flags if "claude-shared" in flag])

    def test_a_missing_named_shared_dir_aborts(self):
        result = self.launch(CLAUDE_AIRLOCK_SHARED_DIR="/nonexistent")
        self.assert_refused(result, "not a directory: /nonexistent")


if __name__ == "__main__":
    unittest.main()
