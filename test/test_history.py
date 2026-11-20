#!/usr/bin/env python3
"""What a session is left to see of what Claude Code remembers: its own
project's history, not that of the others."""

from __future__ import annotations

import json
import unittest

from harness import LauncherTest

CLAUDE = "/home/sandbox/.claude"


class HistoryTest(LauncherTest):
    def setUp(self):
        super().setUp()
        self.projects = self.home / ".claude" / "projects"
        self.own = self.transcripts.name
        for name in (
            self.own,
            f"{self.own}--claude-worktrees-fix",
            # Another project whose name starts like this one's
            f"{self.own}-other",
            "-somewhere-else",
            "odd:name",
        ):
            (self.projects / name).mkdir(parents=True)
        (self.projects / "a-file").touch()
        lines = [
            {"display": "mine", "project": str(self.project)},
            {"display": "theirs", "project": "/somewhere/else"},
        ]
        (self.home / ".claude" / "history.jsonl").write_text(
            "".join(json.dumps(line) + "\n" for line in lines) + "not json\n"
        )

    def covered(self, flags: list[str]) -> list[str]:
        """The directories of projects that an empty one is mounted over."""
        empty = f"--volume={self.state / 'history' / 'empty'}:{CLAUDE}/projects/"
        return [
            flag[len(empty) : -len(":ro,z")]
            for flag in flags
            if flag.startswith(empty) and flag.endswith(":ro,z")
        ]

    def test_the_transcripts_of_other_projects_are_covered(self):
        flags = self.launch().flags
        # In the order of their names, which that of the project's place decides
        others = sorted(["-somewhere-else", f"{self.own}-other"])
        self.assertEqual(self.covered(flags), others)

    def test_what_is_kept_per_project_is_mounted_in_place_of_the_shared(self):
        flags = self.launch().flags
        (store,) = (self.state / "history").glob("proj-*")
        for name in ("file-history", "paste-cache", "history.jsonl"):
            self.assertIn(f"--volume={store / name}:{CLAUDE}/{name}:z", flags)
        # What each is mounted over is there, docker would make it as root
        self.assertTrue((self.base / "file-history").is_dir())
        self.assertTrue((self.base / "history.jsonl").is_file())
        # And the host's are not made for it
        self.assertFalse((self.home / ".claude" / "file-history").exists())
        self.assertEqual(store.stat().st_mode & 0o777, 0o700)

    def test_the_prompt_history_starts_from_the_projects_own_lines(self):
        self.launch()
        (kept,) = (self.state / "history").glob("proj-*/history.jsonl")
        self.assertEqual(
            [json.loads(line)["display"] for line in kept.read_text().splitlines()],
            ["mine"],
        )
        # And is not started again by a later session
        kept.write_text("")
        self.launch()
        self.assertEqual(kept.read_text(), "")

    def test_a_directory_mounted_next_to_the_project_brings_no_history(self):
        flags = self.launch("--add-dir", str(self.home / "ref")).flags
        self.assertIn("-somewhere-else", self.covered(flags))

    def test_shared_when_asked_for(self):
        flags = self.launch(CLAUDE_AIRLOCK_SHARED_HISTORY="1").flags
        self.assertEqual(self.covered(flags), [])
        self.assertIn("--env=CLAUDE_AIRLOCK_SHARED_HISTORY=1", flags)
        # The host's, which are no longer there with all of its ~/.claude
        shared = self.home / ".claude"
        for name in ("file-history", "paste-cache", "history.jsonl"):
            self.assertIn(f"--volume={shared / name}:{CLAUDE}/{name}:z", flags)
        self.assertTrue((shared / "paste-cache").is_dir())
        self.assertFalse(list((self.state / "history").glob("proj-*")))


if __name__ == "__main__":
    unittest.main()
