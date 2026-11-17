#!/usr/bin/env python3
"""The one list of the CLAUDE_DOCKER_* settings, and what has to keep up
with it: the fields their values are read into, --help, the README and
what a session is told of them."""

from __future__ import annotations

import dataclasses
import re
import unittest
from pathlib import Path

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

    def test_a_choice_is_read_as_what_it_names_and_no_other_is_taken(self):
        missing = str(self.work / "no-config")
        for said, access in (
            ("0", settings.SocketAccess.OFF),
            ("1", settings.SocketAccess.LIMITED),
            ("full", settings.SocketAccess.FULL),
        ):
            read = settings.load_settings({"CLAUDE_DOCKER_SOCKET": said}, missing)
            self.assertIs(read.socket, access)
        with self.assertRaises(settings.Fatal):
            settings.load_settings({"CLAUDE_DOCKER_SOCKET": "all"}, missing)

    def test_the_config_file_takes_all_but_the_per_project_ones(self):
        left_out = {s.name for s in settings.SETTINGS} - settings.CONFIG_FILE_SETTINGS
        self.assertEqual(left_out, {"EXTRA_DIRS", "EXTRA_DIRS_RO"})

    def test_help_names_every_setting(self):
        said = self.launch("--help").stdout
        self.assertEqual(set(NAMED.findall(said)), self.variables)

    def test_the_readme_names_every_setting_and_no_other(self):
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertEqual(set(NAMED.findall(readme)), self.variables)

    def test_the_docs_name_no_setting_that_is_not_one(self):
        for page in sorted((ROOT / "docs").glob("*.md")):
            named = set(NAMED.findall(page.read_text(encoding="utf-8")))
            self.assertLessEqual(named, self.variables, page.name)

    def test_every_link_between_the_docs_leads_somewhere(self):
        def anchors(page: Path) -> set[str]:
            text = re.sub(
                r"^```.*?^```", "", page.read_text(), flags=re.MULTILINE | re.DOTALL
            )
            headings = re.findall(r"^#{1,6} (.+)$", text, flags=re.MULTILINE)
            return {
                re.sub(r"[^\w\- ]", "", h.strip().lower()).replace(" ", "-")
                for h in headings
            }

        pages = [ROOT / "README.md", *sorted((ROOT / "docs").glob("*.md"))]
        for page in pages:
            for target, anchor in re.findall(
                r"\]\(([^)#\s]*)#([\w-]+)\)", page.read_text()
            ):
                linked = (page.parent / target).resolve() if target else page
                self.assertIn(
                    anchor, anchors(linked), f"{page.name}: {target}#{anchor}"
                )
            for target in re.findall(
                r"\]\(((?:\.\./)?(?:docs/)?[\w.-]+\.(?:md|png))\)", page.read_text()
            ):
                self.assertTrue(
                    (page.parent / target).exists(), f"{page.name}: {target}"
                )

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
