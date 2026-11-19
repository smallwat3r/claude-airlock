#!/usr/bin/env python3
"""The image a session runs in, and an installed launcher."""

from __future__ import annotations

import json
import re
import subprocess
import sys
import unittest
from pathlib import Path

from harness import (
    LAUNCHER,
    ROOT,
    LauncherTest,
    image,
    settings,
)


class ImageTest(LauncherTest):
    def test_prune_removes_the_images_of_before(self):
        current = self.launch().image
        old, used = "claude-airlock:0ld", "claude-airlock:u5ed"
        result = self.launch(
            "--prune",
            FAKE_IMAGES=f"{old}\n{current}\n{used}",
            FAKE_RUNNING_IMAGES=used,
        )
        self.assertEqual(result.status, 0, result.stderr)
        removed = [call[1] for call in result.calls if call[0] == "rmi"]
        # Never the one the settings ask for now, never by force
        self.assertEqual(removed, [old, used])
        self.assertIn(f"removed  {old}", result.stdout)
        self.assertIn(f"kept     {used}, a container uses it", result.stdout)
        self.assertIn(f"1 images removed, kept as current: {current}", result.stdout)

    def test_feature_names_cannot_escape_the_directory(self):
        result = self.launch(CLAUDE_AIRLOCK_FEATURES="../../etc/passwd")
        self.assert_refused(result, "invalid feature name")

    def test_feature_selection_is_sorted_and_unique(self):
        host = settings.detect_host({"HOME": str(self.home)})
        selection = settings.Settings(features="typst,go go")
        self.assertEqual(image.selected_features(selection, host), ["go", "typst"])

    def test_claude_md_lists_what_was_built(self):
        self.launch(CLAUDE_AIRLOCK_FEATURES="go")
        claude_md = (self.work / "out" / "CLAUDE.md").read_text()
        self.assertRegex(claude_md, r"(?m)^- Go ")
        self.assertNotIn("KiCad", claude_md)
        self.assertNotIn("Placeholder", claude_md)

    def write_feature(self, name: str, *lines: str) -> Path:
        directory = self.home / ".config" / "claude-airlock" / "features"
        directory.mkdir(parents=True, exist_ok=True)
        (directory / f"{name}.Dockerfile").write_text("\n".join(lines) + "\n")
        return directory

    def test_a_feature_brings_those_it_requires(self):
        self.write_feature(
            "mine", "# claude-feat-requires: go", "# claude-feat-md: My tool"
        )
        self.launch(CLAUDE_AIRLOCK_FEATURES="mine")
        claude_md = (self.work / "out" / "CLAUDE.md").read_text()
        self.assertRegex(claude_md, r"(?m)^- Go ")
        self.assertRegex(claude_md, r"(?m)^- My tool$")

    def test_an_unknown_required_feature_aborts(self):
        self.write_feature("mine", "# claude-feat-requires: nothere")
        result = self.launch(CLAUDE_AIRLOCK_FEATURES="mine")
        self.assert_refused(result, "unknown feature: nothere")

    def test_claude_gets_the_language_servers_of_the_image(self):
        result = self.launch("-p", "hello", CLAUDE_AIRLOCK_FEATURES="go typst")
        self.assertEqual(result.command[:2], ["--plugin-dir", image.PLUGIN_DIR])
        manifest = (
            self.work / "out" / "claude.plugin" / ".claude-plugin" / "plugin.json"
        )
        servers = json.loads(manifest.read_text())["lspServers"]
        self.assertEqual(list(servers), ["gopls"])
        self.assertEqual(servers["gopls"]["command"], "gopls")

    def test_an_image_without_language_servers_gives_claude_no_plugin(self):
        result = self.launch(CLAUDE_AIRLOCK_FEATURES="typst")
        self.assertNotIn("--plugin-dir", result.command)

    def test_a_language_server_line_that_is_not_json_is_refused(self):
        self.write_feature("mine", "# claude-feat-lsp: {gopls}")
        result = self.launch(CLAUDE_AIRLOCK_FEATURES="mine")
        self.assert_refused(result, "is not JSON")

    def test_the_former_claude_md_marker_is_refused(self):
        self.write_feature("mine", "# claude: My tool")
        result = self.launch(CLAUDE_AIRLOCK_FEATURES="mine")
        self.assert_refused(result, 'are now written "# claude-feat-md: "')

    def test_a_feature_brings_its_files_to_the_build(self):
        tool = self.write_feature("mine", "COPY mine/tool /usr/local/bin/") / "mine"
        tool.mkdir()
        (tool / "tool").write_text("one\n")
        self.launch(CLAUDE_AIRLOCK_FEATURES="mine")
        self.assertEqual((self.work / "out" / "mine" / "tool").read_text(), "one\n")
        # An edited file is another image, like an edited fragment
        (tool / "tool").write_text("two\n")
        self.launch(CLAUDE_AIRLOCK_FEATURES="mine")
        built = {call[1] for call in self.calls() if call[0] == "build"}
        self.assertEqual(len(built), 2)

    def test_every_feature_assembles(self):
        result = self.launch("--dockerfile")
        self.assertEqual(result.status, 0)
        self.assertRegex(result.stdout, r"(?m)^ENTRYPOINT")

    def test_what_outlives_a_session_comes_last_in_the_path(self):
        # A command left in ~/.cache must not stand in for one of the image
        paths = re.findall(r'(?m)^ENV PATH="(.*)"$', self.launch("--dockerfile").stdout)
        kept = [path for path in paths if "/.cache/" in path]
        self.assertTrue(kept)
        for path in kept:
            before, _, after = path.partition("${PATH}")
            self.assertNotIn("/.cache/", before)
            self.assertIn("/.cache/", after)


class InstallTest(LauncherTest):
    STATUSLINE = ROOT / "bin" / "claude-statusline"

    def test_the_launcher_can_be_symlinked(self):
        link = self.work / "bin" / "claude-airlock"
        link.symlink_to(LAUNCHER)
        process = subprocess.run(
            [sys.executable, str(link), "--dockerfile"],
            cwd=self.project,
            env={**self.fake_docker_env(), "HOME": str(self.home)},
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(process.returncode, 0, process.stderr)
        self.assertRegex(process.stdout, r"(?m)^ENTRYPOINT")

    def test_help_is_the_launchers_own(self):
        # Also with a config file it would refuse, and without docker
        self.write_config("CLAUDE_AIRLOCK_NET_FILTR=1")
        for option in ("--help", "-h"):
            result = self.launch(option)
            self.assertEqual(result.status, 0, result.stderr)
            self.assertIn("claude-airlock --trace", result.stdout)
            self.assertIn("CLAUDE_AIRLOCK_NET_FILTER", result.stdout)
            self.assertEqual(result.calls, [])

    def test_statusline_is_mounted_at_its_host_path(self):
        self.assertIn(
            f"--volume={self.STATUSLINE}:{self.STATUSLINE}:ro,z", self.launch().flags
        )

    def test_statusline_is_also_mounted_where_settings_point(self):
        link = self.home / "statusline"
        link.symlink_to(self.STATUSLINE)
        settings_json = {"statusLine": {"type": "command", "command": "~/statusline"}}
        (self.home / ".claude" / "settings.json").write_text(json.dumps(settings_json))
        flags = self.launch().flags
        self.assertIn(f"--volume={self.STATUSLINE}:{link}:ro,z", flags)

    def test_another_statusline_is_left_alone(self):
        other = self.home / "other-statusline"
        other.touch()
        settings_json = {"statusLine": {"type": "command", "command": str(other)}}
        (self.home / ".claude" / "settings.json").write_text(json.dumps(settings_json))
        self.assertFalse([f for f in self.launch().flags if "other-statusline" in f])


if __name__ == "__main__":
    unittest.main()
