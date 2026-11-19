#!/usr/bin/env python3
"""The names of before the rename, when the project was claude-sandbox
with a claude-docker command: each still works, and its user is told of
the name that replaced it."""

from __future__ import annotations

import importlib
import os
import subprocess
import sys
import unittest

from harness import ROOT, LauncherTest, settings

legacy = importlib.import_module("claude_airlock.legacy")


class LegacySettingsTest(LauncherTest):
    def test_a_setting_under_its_old_name_is_read_and_its_user_told(self):
        result = self.launch(CLAUDE_DOCKER_NET_FILTER="1")
        self.assertEqual(result.status, 0, result.stderr)
        self.assertIn("--env=CLAUDE_AIRLOCK_NET_FILTER=1", result.flags)
        self.assertIn(
            "CLAUDE_DOCKER_NET_FILTER is now CLAUDE_AIRLOCK_NET_FILTER",
            result.stderr,
        )

    def test_a_session_is_given_no_setting_under_its_old_name(self):
        flags = self.launch(CLAUDE_DOCKER_NET_FILTER="1").flags
        self.assertEqual([f for f in flags if "CLAUDE_DOCKER_" in f], [])

    def test_the_name_of_now_wins_over_the_old_one(self):
        result = self.launch(CLAUDE_DOCKER_MEMORY="1g", CLAUDE_AIRLOCK_MEMORY="2g")
        self.assertIn("--memory=2g", result.flags)
        self.assertIn("CLAUDE_DOCKER_MEMORY is not read", result.stderr)

    def test_a_value_that_is_refused_is_refused_under_the_old_name_too(self):
        result = self.launch(CLAUDE_DOCKER_NET_FILTER="true")
        self.assert_refused(result, "CLAUDE_AIRLOCK_NET_FILTER must be 0 or 1")

    def test_the_docker_socket_is_read_under_the_name_it_had(self):
        told: list[str] = []
        read = settings.load_settings(
            {"CLAUDE_DOCKER_SOCKET": "full"}, str(self.work / "no-config"), told
        )
        self.assertIs(read.docker_socket, settings.SocketAccess.FULL)
        self.assertEqual(len(told), 1)
        self.assertIn("is now CLAUDE_AIRLOCK_DOCKER_SOCKET", told[0])

    def test_nothing_is_told_of_the_names_of_now(self):
        result = self.launch(CLAUDE_AIRLOCK_NET_FILTER="1")
        self.assertNotIn("CLAUDE_DOCKER_", result.stderr)
        self.assertNotIn("claude-sandbox", result.stderr)

    def test_what_a_session_is_told_of_itself_is_no_setting(self):
        # The old launcher gave its sessions these, a launcher started
        # from inside one must not take them for settings
        result = self.launch(CLAUDE_DOCKER_SANDBOX="claude-proj")
        self.assertEqual(result.status, 0, result.stderr)
        self.assertNotIn("CLAUDE_DOCKER_", result.stderr)

    def test_the_config_file_takes_the_old_names(self):
        self.write_config("CLAUDE_DOCKER_MEMORY=3g", "CLAUDE_AIRLOCK_PIDS=99")
        result = self.launch()
        self.assertIn("--memory=3g", result.flags)
        self.assertIn("--pids-limit=99", result.flags)
        self.assertIn("CLAUDE_DOCKER_MEMORY is now", result.stderr)

    def test_the_config_file_still_refuses_what_is_no_setting(self):
        self.write_config("CLAUDE_DOCKER_NET_FILTR=1")
        self.assert_refused(self.launch(), "not a known setting")
        self.write_config("CLAUDE_DOCKER_EXTRA_DIRS=/tmp")
        self.assert_refused(self.launch(), "not a known setting")


class LegacyDirsTest(LauncherTest):
    def setUp(self):
        super().setUp()
        self.old_state = self.state.with_name("claude-sandbox")
        self.old_config = self.home / ".config" / "claude-sandbox"

    def test_the_config_directory_of_before_is_read_and_left_alone(self):
        self.old_config.mkdir(parents=True)
        (self.old_config / "config").write_text("CLAUDE_AIRLOCK_MEMORY=5g\n")
        result = self.launch()
        self.assertIn("--memory=5g", result.flags)
        self.assertIn(f"{self.old_config} is read for now", result.stderr)
        self.assertTrue(self.old_config.is_dir())
        self.assertFalse(self.old_config.with_name("claude-airlock").exists())

    def test_the_config_directory_of_now_is_the_one_read_when_both_exist(self):
        self.old_config.mkdir(parents=True)
        (self.old_config / "config").write_text("CLAUDE_AIRLOCK_MEMORY=5g\n")
        self.write_config("CLAUDE_AIRLOCK_MEMORY=6g")
        result = self.launch()
        self.assertIn("--memory=6g", result.flags)
        self.assertNotIn("claude-sandbox", result.stderr)

    def test_the_records_of_before_are_moved_once_and_a_link_is_left(self):
        (self.old_state / "captures").mkdir(parents=True)
        (self.old_state / "captures" / "kept.pcap").write_text("kept")
        result = self.launch()
        self.assertEqual(result.status, 0, result.stderr)
        self.assertEqual((self.state / "captures" / "kept.pcap").read_text(), "kept")
        self.assertTrue(self.old_state.is_symlink())
        self.assertEqual(self.old_state.resolve(), self.state)
        self.assertIn(f"are now in {self.state}", result.stderr)
        # The link is not taken for records to move again
        self.assertNotIn("claude-sandbox", self.launch().stderr)

    def test_the_records_of_before_stay_where_there_are_new_ones(self):
        self.old_state.mkdir(parents=True)
        (self.old_state / "old").write_text("old")
        self.state.mkdir(parents=True)
        result = self.launch()
        self.assertEqual(result.status, 0, result.stderr)
        self.assertEqual((self.old_state / "old").read_text(), "old")
        self.assertFalse(self.old_state.is_symlink())
        self.assertFalse((self.state / "old").exists())


class LegacyCommandTest(LauncherTest):
    def test_the_old_command_starts_the_launcher_and_says_its_name(self):
        process = subprocess.run(
            [sys.executable, str(ROOT / "bin" / "claude-docker"), "--dockerfile"],
            cwd=self.project,
            env={**self.fake_docker_env(), "HOME": str(self.home)},
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertIn("ENTRYPOINT", process.stdout)
        self.assertIn("claude-docker is now claude-airlock", process.stderr)

    def test_the_command_of_now_is_told_nothing(self):
        told: list[str] = []
        legacy.legacy_command(os.path.join("bin", "claude-airlock"), told)
        self.assertEqual(told, [])


if __name__ == "__main__":
    unittest.main()
