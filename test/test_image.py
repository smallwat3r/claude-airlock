#!/usr/bin/env python3
"""The image a session runs in, and an installed launcher."""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

from harness import LAUNCHER, LauncherTest

from claude_airlock import settings
from claude_airlock.sandbox import image


class ImageTest(LauncherTest):
    def test_prune_removes_the_images_of_before(self):
        current = self.launch().image
        old, used = "claude-airlock:0ld", "claude-airlock:u5ed"
        result = self.launch(
            "--prune",
            FAKE_IMAGES=f"{old}\n{current}\n{used}",
            FAKE_RUNNING_IMAGES=used,
        )
        assert result.status == 0, result.stderr
        removed = [call[1] for call in result.calls if call[0] == "rmi"]
        # Never the one the settings ask for now, never by force
        assert removed == [old, used]
        assert f"removed  {old}" in result.stdout
        assert f"kept     {used}, a container uses it" in result.stdout
        assert f"1 images removed, kept as current: {current}" in result.stdout

    def test_feature_names_cannot_escape_the_directory(self):
        result = self.launch(CLAUDE_AIRLOCK_FEATURES="../../etc/passwd")
        self.assert_refused(result, "invalid feature name")

    def test_feature_selection_is_sorted_and_unique(self):
        host = settings.detect_host({"HOME": str(self.home)})
        selection = settings.Settings(features="typst,go go")
        assert image.selected_features(selection, host) == ["go", "typst"]

    def test_claude_md_lists_what_was_built(self):
        self.launch(CLAUDE_AIRLOCK_FEATURES="go")
        claude_md = (self.work / "out" / "CLAUDE.md").read_text()
        assert re.search(r"(?m)^- Go ", claude_md)
        assert "KiCad" not in claude_md
        assert "Placeholder" not in claude_md

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
        assert re.search(r"(?m)^- Go ", claude_md)
        assert re.search(r"(?m)^- My tool$", claude_md)

    def test_an_unknown_required_feature_aborts(self):
        self.write_feature("mine", "# claude-feat-requires: nothere")
        result = self.launch(CLAUDE_AIRLOCK_FEATURES="mine")
        self.assert_refused(result, "unknown feature: nothere")

    def test_claude_gets_the_language_servers_of_the_image(self):
        result = self.launch("-p", "hello", CLAUDE_AIRLOCK_FEATURES="go typst")
        assert result.command[:2] == ["--plugin-dir", image.PLUGIN_DIR]
        manifest = (
            self.work / "out" / "claude.plugin" / ".claude-plugin" / "plugin.json"
        )
        servers = json.loads(manifest.read_text())["lspServers"]
        assert list(servers) == ["gopls"]
        assert servers["gopls"]["command"] == "gopls"

    def test_an_image_without_language_servers_gives_claude_no_plugin(self):
        result = self.launch(CLAUDE_AIRLOCK_FEATURES="typst")
        assert "--plugin-dir" not in result.command

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
        assert (self.work / "out" / "mine" / "tool").read_text() == "one\n"
        # An edited file is another image, like an edited fragment
        (tool / "tool").write_text("two\n")
        self.launch(CLAUDE_AIRLOCK_FEATURES="mine")
        built = {call[1] for call in self.calls() if call[0] == "build"}
        assert len(built) == 2

    def test_what_is_left_in_a_features_directory_is_not_the_features(self):
        tool = self.write_feature("mine", "COPY mine/ /opt/mine/") / "mine"
        (tool / "lib").mkdir(parents=True)
        (tool / "lib" / "tool").write_text("one\n")
        self.launch(CLAUDE_AIRLOCK_FEATURES="mine")
        # By Finder, Python and an editor, in it and under it
        (tool / ".DS_Store").write_text("finder")
        (tool / "lib" / "tool~").write_text("before")
        (tool / "lib" / "__pycache__").mkdir()
        (tool / "lib" / "__pycache__" / "tool.cpython-314.pyc").write_text("made")
        self.launch(CLAUDE_AIRLOCK_FEATURES="mine")
        out = self.work / "out" / "mine"
        assert sorted(str(path.relative_to(out)) for path in out.rglob("*")) == [
            "lib",
            "lib/tool",
        ]
        # The same image as without them
        built = {call[1] for call in self.calls() if call[0] == "build"}
        assert len(built) == 1

    def test_every_feature_assembles(self):
        result = self.launch("--dockerfile")
        assert result.status == 0
        assert re.search(r"(?m)^ENTRYPOINT", result.stdout)

    def test_what_outlives_a_session_comes_last_in_the_path(self):
        # A command left in ~/.cache must not stand in for one of the image
        paths = re.findall(r'(?m)^ENV PATH="(.*)"$', self.launch("--dockerfile").stdout)
        kept = [path for path in paths if "/.cache/" in path]
        assert kept
        for path in kept:
            before, _, after = path.partition("${PATH}")
            assert "/.cache/" not in before
            assert "/.cache/" in after


class InstallTest(LauncherTest):
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
        assert process.returncode == 0, process.stderr
        assert re.search(r"(?m)^ENTRYPOINT", process.stdout)

    def test_help_is_the_launchers_own(self):
        # Also with a config file it would refuse, and without docker
        self.write_config("CLAUDE_AIRLOCK_NET_FILTR=1")
        for option in ("--help", "-h"):
            result = self.launch(option)
            assert result.status == 0, result.stderr
            assert "claude-airlock --trace" in result.stdout
            assert "CLAUDE_AIRLOCK_NET_FILTER" in result.stdout
            assert result.calls == []

    def launched_with(self, command: str | None = None):
        """A launch with that command as the statusline of the settings,
        or as they are, and the calls of that launch alone."""
        if command is not None:
            settings_json = {"statusLine": {"type": "command", "command": command}}
            settings_file = self.home / ".claude" / "settings.json"
            settings_file.write_text(json.dumps(settings_json))
        (self.work / "log").unlink(missing_ok=True)
        return self.launch()

    def test_no_statusline_is_mounted_unless_settings_name_one(self):
        before = self.launched_with().flags
        assert not [f for f in before if "statusline" in f]
        assert self.launched_with("").flags == before

    def test_a_statusline_of_the_users_own_is_mounted_where_settings_name_it(self):
        own = self.home / "bin" / "own-statusline"
        own.parent.mkdir()
        own.touch()
        for command in (
            str(own),
            "~/bin/own-statusline --wide",
            f"bash -e {own}",
            "/bin/bash ~/bin/own-statusline",
        ):
            flags = self.launched_with(command).flags
            assert f"--volume={own}:/home/sandbox/bin/own-statusline:ro,z" in flags
            assert len([f for f in flags if "statusline" in f]) == 1

    def test_a_statusline_in_the_claude_directory_has_its_place_in_the_base(self):
        own = self.home / ".claude" / "status" / "line.sh"
        own.parent.mkdir(parents=True)
        own.write_text("#!/bin/sh\n")
        flags = self.launched_with("~/.claude/status/line.sh").flags
        assert f"--volume={own}:/home/sandbox/.claude/status/line.sh:ro,z" in flags
        # Made by the launcher, empty, for docker not to make it as root
        place = self.base / "status" / "line.sh"
        assert place.read_text() == ""
        # What a session left in the base where the file goes is not
        # mounted through
        place.unlink()
        place.symlink_to("/etc/passwd")
        assert not [f for f in self.launched_with().flags if "line.sh" in f]
        place.parent.rename(self.base / "kept")
        place.parent.symlink_to(self.base / "kept")
        assert not [f for f in self.launched_with().flags if "line.sh" in f]

    def test_what_is_mounted_already_is_not_mounted_as_a_statusline(self):
        # With ~/.claude, with the project, or as the settings themselves
        hook = self.home / ".claude" / "hooks" / "status.sh"
        hook.touch()
        inside = self.project / "status.sh"
        inside.touch()
        for command in (str(hook), str(inside), "~/.claude/settings.json"):
            flags = self.launched_with(command).flags
            assert not [f for f in flags if f.endswith("status.sh:ro,z")]
            assert len([f for f in flags if "/settings.json:" in f]) == 1

    def test_no_other_file_of_the_host_is_mounted_as_a_statusline(self):
        secrets = self.home / ".netrc"
        secrets.write_text("machine example.org password hunter2\n")
        (self.home / "linked").symlink_to(secrets)
        (self.home / "a:b").touch()
        (self.home / "dir").mkdir()
        outside = self.work / "outside-statusline"
        outside.touch()
        before = len(self.launched_with().flags)
        for command in (
            "~/.netrc",
            "~/linked",
            "~/a:b",
            "~/dir",
            "~/missing",
            str(outside),
            "/bin/sh ~/.netrc",
            "cat ~/dir",
            "npx -y some-statusline@latest",
            "bash -c 'echo \"unclosed",
            "",
        ):
            result = self.launched_with(command)
            assert result.status == 0, (command, result.stderr)
            assert len(result.flags) == before, command
        said = self.launched_with("~/.netrc").stderr
        assert "is not mounted: its name is one of secrets" in said

    def test_what_is_kept_out_of_every_session_is_no_statusline(self):
        # Where a session can write the settings, it names the file
        key = self.home / ".ssh" / "id_ed25519"
        key.parent.mkdir()
        key.write_text("a key\n")
        (self.home / "status").symlink_to(key)
        config = self.home / ".config" / "claude-airlock" / "config"
        config.parent.mkdir(parents=True, exist_ok=True)
        config.touch()
        before = len(self.launched_with().flags)
        for command in (
            "~/.ssh/id_ed25519",
            "cat ~/.ssh/id_ed25519",
            # By where it leads too
            "~/status",
            "bash ~/.config/claude-airlock/config",
        ):
            result = self.launched_with(command)
            assert result.status == 0, (command, result.stderr)
            assert len(result.flags) == before, command
            assert "is not a session's to have" in result.stderr, command
        said = self.launched_with("~/status").stderr
        assert (
            f"the statusline {self.home}/status is not mounted: {self.home}/.ssh"
            " is not a session's to have"
        ) in said
        # One of the user's own in ~/.claude is mounted as before
        own = self.home / ".claude" / "line.sh"
        own.touch()
        assert [f for f in self.launched_with(str(own)).flags if "line.sh" in f]
