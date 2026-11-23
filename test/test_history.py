#!/usr/bin/env python3
"""What a session is left to see of what Claude Code remembers: its own
project's history, not that of the others."""

from __future__ import annotations

import json

import pytest
from harness import LauncherTest

CLAUDE = "/home/sandbox/.claude"


class HistoryTest(LauncherTest):
    @pytest.fixture(autouse=True)
    def projects_kept(self, sandbox: None) -> None:
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
        assert self.covered(flags) == others

    def test_what_is_kept_per_project_is_mounted_in_place_of_the_shared(self):
        flags = self.launch().flags
        (store,) = (self.state / "history").glob("proj-*")
        for name in ("file-history", "paste-cache", "history.jsonl"):
            assert f"--volume={store / name}:{CLAUDE}/{name}:z" in flags
        # What each is mounted over is there, docker would make it as root
        assert (self.base / "file-history").is_dir()
        assert (self.base / "history.jsonl").is_file()
        # And the host's are not made for it
        assert not (self.home / ".claude" / "file-history").exists()
        assert store.stat().st_mode & 511 == 448

    def test_the_prompt_history_starts_from_the_projects_own_lines(self):
        self.launch()
        (kept,) = (self.state / "history").glob("proj-*/history.jsonl")
        assert [
            json.loads(line)["display"] for line in kept.read_text().splitlines()
        ] == ["mine"]
        # And is not started again by a later session
        kept.write_text("")
        self.launch()
        assert kept.read_text() == ""

    def test_a_directory_mounted_next_to_the_project_brings_no_history(self):
        flags = self.launch("--add-dir", str(self.home / "ref")).flags
        assert "-somewhere-else" in self.covered(flags)

    def test_shared_when_asked_for(self):
        flags = self.launch(CLAUDE_AIRLOCK_SHARED_HISTORY="1").flags
        assert self.covered(flags) == []
        assert "--env=CLAUDE_AIRLOCK_SHARED_HISTORY=1" in flags
        # The host's, which are no longer there with all of its ~/.claude
        shared = self.home / ".claude"
        for name in ("file-history", "paste-cache", "history.jsonl"):
            assert f"--volume={shared / name}:{CLAUDE}/{name}:z" in flags
        assert (shared / "paste-cache").is_dir()
        assert not list((self.state / "history").glob("proj-*"))
