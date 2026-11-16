#!/usr/bin/env python3
"""The check for files a session changed that can run commands on the host
or that Claude follows there, at the end of a session and for one that ended
without it."""

from __future__ import annotations

import json
import os
import subprocess
import unittest
from pathlib import Path

from harness import (
    LauncherTest,
    launcher,
)


class TamperingTest(LauncherTest):
    REPORT = "changed files that can run commands on the host"

    def test_a_new_git_hook_is_reported(self):
        result = self.launch(session="echo x > .git/hooks/pre-commit")
        self.assertIn(self.REPORT, result.stderr)
        self.assertIn(f"  {self.project}/.git/hooks/pre-commit\n", result.stderr)

    def test_a_git_config_change_is_reported(self):
        result = self.launch(
            session=r'printf "[core]\n\tfsmonitor = evil\n" >> .git/config'
        )
        self.assertIn(f"  {self.project}/.git/config\n", result.stderr)

    def test_new_project_claude_settings_are_reported(self):
        result = self.launch(session='mkdir .claude; echo "{}" > .claude/settings.json')
        self.assertIn(f"  {self.project}/.claude/settings.json\n", result.stderr)

    def test_a_hook_where_git_was_told_to_look_is_reported(self):
        (self.project / ".git" / "config").write_text("[core]\n\thooksPath = .husky\n")
        (self.project / ".husky").mkdir()
        result = self.launch(session="echo x > .husky/pre-commit")
        self.assertIn(f"  {self.project}/.husky/pre-commit\n", result.stderr)

    def test_a_submodule_hook_is_reported(self):
        module = self.project / ".git" / "modules" / "libs" / "one"
        (module / "hooks").mkdir(parents=True)
        (module / "HEAD").write_text("ref: refs/heads/main\n")
        result = self.launch(session="echo x > .git/modules/libs/one/hooks/post-merge")
        self.assertIn(f"  {module}/hooks/post-merge\n", result.stderr)

    def test_a_script_the_settings_name_is_reported(self):
        (self.project / ".claude").mkdir()
        (self.project / "tools").mkdir()
        (self.project / "tools" / "format.sh").write_text("true\n")
        hook = {"type": "command", "command": "$CLAUDE_PROJECT_DIR/tools/format.sh -q"}
        settings = {"hooks": {"PostToolUse": [{"hooks": [hook]}]}}
        (self.project / ".claude" / "settings.json").write_text(json.dumps(settings))
        result = self.launch(session="echo evil >> tools/format.sh")
        self.assertIn(f"  {self.project}/tools/format.sh\n", result.stderr)
        self.assertNotIn("settings.json", result.stderr)

    def test_changed_instructions_are_reported(self):
        result = self.launch(
            session="echo x > CLAUDE.md; mkdir -p .claude/skills/s;"
            ' echo x > .claude/skills/s/SKILL.md; echo x > "$HOME/.claude/CLAUDE.md"'
        )
        for path in (
            self.project / "CLAUDE.md",
            self.project / ".claude" / "skills" / "s" / "SKILL.md",
            self.home / ".claude" / "CLAUDE.md",
        ):
            self.assertIn(f"  {path}\n", result.stderr)

    def test_a_changed_plugin_is_reported_by_its_directory(self):
        # Plugins stay writable, Claude Code updates them itself
        plugin = self.home / ".claude" / "plugins" / "cache" / "market" / "tool"
        (plugin / "1.0" / "hooks").mkdir(parents=True)
        (plugin / "1.0" / "hooks" / "hooks.json").write_text("{}")
        (self.home / ".claude" / "plugins" / "installed_plugins.json").write_text("{}")
        result = self.launch(
            session=f'echo x > "{plugin}/1.0/hooks/hooks.json";'
            f' echo x > "{plugin}/1.0/hooks/run.sh";'
            ' echo x > "$HOME/.claude/plugins/installed_plugins.json"'
        )
        self.assertIn(self.REPORT, result.stderr)
        self.assertIn(f"  {plugin}/ (2 files)\n", result.stderr)
        self.assertIn(
            f"  {self.home}/.claude/plugins/installed_plugins.json\n", result.stderr
        )
        self.assertNotIn("hooks.json", result.stderr)

    def test_a_link_to_a_directory_is_reported_and_not_followed(self):
        result = self.launch(session="mkdir .claude; ln -s / .claude/skills")
        self.assertIn(f"  {self.project}/.claude/skills\n", result.stderr)
        self.assertNotIn("/etc/", result.stderr)

    def test_what_a_session_nests_too_deep_does_not_stop_the_check(self):
        # Deeper than Python can remove again, so rm clears it away
        modules = self.project / ".git" / "modules"
        self.addCleanup(subprocess.run, ["rm", "-rf", str(modules)], check=False)
        deep = "mkdir -p .git/modules/$(python3 -c \"print('a/' * 1500)\")"
        nested = "python3 -c \"print('[' * 100000 + ']' * 100000)\""
        result = self.launch(
            session=f"{deep}; mkdir .claude; {nested} > .claude/settings.json;"
            " echo x > .git/hooks/pre-commit"
        )
        self.assertNotIn("Traceback", result.stderr)
        self.assertIn(f"  {self.project}/.git/hooks/pre-commit\n", result.stderr)
        self.assertIn(f"  {self.project}/.claude/settings.json\n", result.stderr)

    def test_branch_tracking_is_not_reported(self):
        result = self.launch(
            session=r'printf "[branch \"main\"]\n\tremote = origin\n" >> .git/config'
        )
        self.assertNotIn(self.REPORT, result.stderr)

    def test_ordinary_edits_are_not_reported(self):
        result = self.launch(session="echo code > main.go")
        self.assertNotIn(self.REPORT, result.stderr)

    def test_the_session_status_is_passed_on(self):
        self.assertEqual(self.launch(session="exit 7").status, 7)


class UncheckedSessionTest(LauncherTest):
    LATE = "ended without its check"
    # The fake docker is the shell's parent and the launcher its parent,
    # killed the way a closed terminal ends it: before it can compare
    KILL_LAUNCHER = "kill -KILL $(ps -o ppid= -p $PPID)"

    def pending(self) -> list[Path]:
        return list(self.state.glob("pending-checks/*.json"))

    def test_a_killed_session_is_checked_by_the_next_launch(self):
        killed = self.launch(
            session=f"echo x > .git/hooks/pre-commit; {self.KILL_LAUNCHER}"
        )
        self.assertNotIn("pre-commit", killed.stderr)
        self.assertEqual(len(self.pending()), 1)

        following = self.launch()
        self.assertIn(self.LATE, following.stderr)
        self.assertIn(f"  {self.project}/.git/hooks/pre-commit\n", following.stderr)
        self.assertEqual(self.pending(), [])
        self.assertNotIn(self.LATE, self.launch().stderr)

    def test_a_killed_session_that_changed_nothing_is_not_reported(self):
        self.launch(session=self.KILL_LAUNCHER)
        self.assertNotIn(self.LATE, self.launch().stderr)
        self.assertEqual(self.pending(), [])

    def test_a_checked_session_leaves_nothing_pending(self):
        self.launch(session="echo x > .git/hooks/pre-commit")
        self.assertEqual(self.pending(), [])

    def test_a_running_session_is_left_alone(self):
        # This test's own process stands in for a launcher still running
        self.launch(session=self.KILL_LAUNCHER)
        (file,) = self.pending()
        mine = {"pid": os.getpid(), "launched": launcher.process_started(os.getpid())}
        file.write_text(json.dumps({**json.loads(file.read_text()), **mine}))
        (self.project / ".git" / "hooks" / "pre-commit").write_text("x")
        self.assertNotIn(self.LATE, self.launch(CLAUDE_BUFFER_NAME="*c:proj:b*").stderr)
        self.assertIn(file, self.pending())

    def test_an_unreadable_pending_check_is_dropped_out_loud(self):
        self.launch(session=self.KILL_LAUNCHER)
        (file,) = self.pending()
        file.write_text("{")
        self.assertIn("unreadable pending check", self.launch().stderr)
        self.assertEqual(self.pending(), [])


if __name__ == "__main__":
    unittest.main()
