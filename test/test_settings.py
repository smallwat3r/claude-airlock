#!/usr/bin/env python3
"""The one list of the CLAUDE_DOCKER_* settings, and what has to keep up
with it: the fields their values are read into, --help, the README and
what a session is told of them."""

from __future__ import annotations

import dataclasses
import re
import unittest

from harness import ROOT, LauncherTest, settings

NAMED = re.compile(r"CLAUDE_DOCKER_[A-Z_]+")
# What a session is told that is not a setting: its container's name, and
# the directories mounted next to its project
TOLD_TO_A_SESSION = {"CLAUDE_DOCKER_SANDBOX", "CLAUDE_DOCKER_DIRS"}


class SettingsListTest(LauncherTest):
    def setUp(self):
        super().setUp()
        self.variables = {setting.variable for setting in settings.SETTINGS}

    def test_every_setting_has_its_field_and_no_field_is_without_one(self):
        fields = [field.name for field in dataclasses.fields(settings.Settings)]
        self.assertEqual([s.field for s in settings.SETTINGS], fields)

    def test_the_defaults_are_read_as_the_defaults(self):
        missing = str(self.work / "no-config")
        self.assertEqual(settings.load_settings({}, missing), settings.Settings())

    def test_the_config_file_takes_all_but_the_per_project_ones(self):
        left_out = {s.name for s in settings.SETTINGS} - settings.CONFIG_FILE_SETTINGS
        self.assertEqual(left_out, {"EXTRA_DIRS", "EXTRA_DIRS_RO"})

    def test_help_names_every_setting(self):
        said = self.launch("--help").stdout
        self.assertEqual(set(NAMED.findall(said)), self.variables)

    def test_the_readme_names_every_setting_and_no_other(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertEqual(set(NAMED.findall(readme)), self.variables)

    def test_a_session_is_told_of_no_setting_that_is_not_one(self):
        told = (ROOT / "docker" / "CLAUDE-sandbox.md").read_text(encoding="utf-8")
        named = set(NAMED.findall(told)) - TOLD_TO_A_SESSION
        self.assertLessEqual(named, self.variables)

    def test_a_session_is_told_of_every_setting_it_is_given(self):
        told = (ROOT / "docker" / "CLAUDE-sandbox.md").read_text(encoding="utf-8")
        (self.project / "docs").mkdir()
        flags = self.launch(
            "--add-dir-ro",
            "~/ref",
            SSH_AUTH_SOCK="/tmp/agent.sock",
            CLAUDE_DOCKER_SSH_AGENT="1",
            CLAUDE_DOCKER_RW_CONFIG="1",
            CLAUDE_DOCKER_SHARED_HISTORY="1",
            CLAUDE_DOCKER_PROTECT="docs",
        ).flags
        given = {
            NAMED.match(flag[len("--env=") :]).group()
            for flag in flags
            if flag.startswith("--env=CLAUDE_DOCKER_")
        }
        self.assertLessEqual({"CLAUDE_DOCKER_PROTECT", "CLAUDE_DOCKER_DIRS"}, given)
        self.assertLessEqual(
            given - {"CLAUDE_DOCKER_SANDBOX"}, set(NAMED.findall(told))
        )


if __name__ == "__main__":
    unittest.main()
