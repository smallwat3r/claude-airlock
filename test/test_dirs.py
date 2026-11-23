#!/usr/bin/env python3
"""The directories mounted next to the project."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest
from harness import LauncherTest

from claude_airlock.docker import mount_arg
from claude_airlock.errors import Fatal


class ExtraDirsTest(LauncherTest):
    @pytest.fixture(autouse=True)
    def directories(self, sandbox: None) -> None:
        self.ref = self.home / "ref"
        self.shared = self.home / "claude-shared"

    def test_read_only_dir(self):
        result = self.launch(
            "--add-dir-ro", "~/ref", "-p", "hello", CLAUDE_AIRLOCK_FEATURES=""
        )
        assert f"--volume={self.ref}:{self.ref}:ro,z" in result.flags
        unasked = "--dangerously-skip-permissions"
        assert result.command == [f"--add-dir={self.ref}", unasked, "-p", "hello"]

    def test_a_prompt_is_not_taken_for_a_directory(self):
        # --add-dir is variadic, as two arguments it would take the prompt
        result = self.launch("--add-dir", "~/ref", "hello", CLAUDE_AIRLOCK_FEATURES="")
        unasked = "--dangerously-skip-permissions"
        assert result.command == [f"--add-dir={self.ref}", unasked, "hello"]

    def test_read_write_dir_and_its_secrets(self):
        (self.ref / ".env").touch()
        flags = self.launch(f"--add-dir={self.ref}").flags
        assert f"--volume={self.ref}:{self.ref}:z" in flags
        assert f"--volume=/dev/null:{self.ref / '.env'}:ro" in flags

    def test_a_protected_path_is_read_only_inside_what_is_mounted(self):
        kit = self.shared / "kit"
        kit.mkdir(parents=True)
        (self.project / "docs").mkdir()
        self.write_config(f"CLAUDE_AIRLOCK_PROTECT=~/claude-shared/kit:{self.ref}")
        flags = self.launch(
            "--add-dir", "~/ref", CLAUDE_AIRLOCK_PROTECT="docs:~/not-mounted"
        ).flags
        # In the shared directory and in the project, on top of them
        assert f"--volume={self.shared}:{self.shared}:z" in flags
        for inside in (kit, self.project / "docs"):
            assert f"--volume={inside}:{inside}:ro,z" in flags
        # A mounted directory itself is mounted read-only, once
        assert f"--volume={self.ref}:{self.ref}:ro,z" in flags
        assert f"--volume={self.ref}:{self.ref}:z" not in flags
        # What is not mounted is not brought in
        assert not [flag for flag in flags if "not-mounted" in flag]
        assert f"--env=CLAUDE_AIRLOCK_PROTECT={kit}:{self.project / 'docs'}" in flags

    def test_the_directories_above_a_protected_path_are_held_in_place(self):
        deep = self.project / "a" / "b" / "kit"
        deep.mkdir(parents=True)
        nested = self.ref / "x" / "y"
        nested.mkdir(parents=True)
        inner = self.project / "a" / "b" / "kit" / "inner" / "most"
        inner.mkdir(parents=True)
        flags = self.launch(
            "--add-dir-ro",
            str(self.ref),
            CLAUDE_AIRLOCK_PROTECT=f"a/b/kit:{nested}:{inner}",
        ).flags
        # Mounted on themselves, writable: a mount cannot be renamed
        for above in (self.project / "a", self.project / "a" / "b"):
            assert f"--volume={above}:{above}:z" in flags
        assert f"--volume={deep}:{deep}:ro,z" in flags
        # Nothing writable inside what is read-only, mounted or protected
        for read_only in (self.ref / "x", deep / "inner"):
            assert f"--volume={read_only}:{read_only}:z" not in flags
        # Nor on the project itself
        assert flags.count(f"--volume={self.project}:{self.project}:z") == 1

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

    def test_what_is_kept_out_of_every_session_is_refused(
        self, subtests: pytest.Subtests
    ):
        (self.home / ".ssh").mkdir()
        self.write_config("")
        kept = self.home / ".ssh"
        for directory, refused in (
            ("~/.ssh", kept),
            ("~/.claude/skills", self.home / ".claude"),
            # Around the launcher's settings, and in its records
            ("~/.config", self.home / ".config" / "claude-airlock"),
            (str(self.state), self.state),
        ):
            with subtests.test(directory=directory):
                Path(self.state).mkdir(parents=True, exist_ok=True)
                result = self.launch("--add-dir-ro", directory)
                self.assert_refused(result, f"{refused} is not a session's to have")
        # As the project too, and by where a link leads
        result = self.launch(cwd=self.home / ".claude" / "skills")
        self.assert_refused(result, "is not a session's to have")
        link = self.work / "keys"
        link.symlink_to(kept)
        result = self.launch("--add-dir", str(link))
        self.assert_refused(result, "is not a session's to have")

    def test_a_link_out_of_what_a_session_can_write_is_refused(self):
        # What a session could have left, to be given what it points to
        outside = self.home / "documents"
        outside.mkdir()
        (self.project / "vendor").symlink_to(outside)
        result = self.launch("--add-dir", "vendor")
        self.assert_refused(result, f"it is a link out of {self.project}")
        self.shared.mkdir()
        (self.shared / "notes").symlink_to(outside)
        result = self.launch("--add-dir-ro", "~/claude-shared/notes")
        self.assert_refused(result, f"it is a link out of {self.shared}")
        # Named by where it is, and a link the session cannot have made
        assert self.launch("--add-dir", str(outside)).status == 0
        mine = self.home / "mine"
        mine.symlink_to(outside)
        assert self.launch("--add-dir", str(mine)).status == 0
        # In a directory it can only read
        (self.ref / "more").symlink_to(outside)
        result = self.launch("--add-dir-ro", "~/ref", "--add-dir", "~/ref/more")
        assert result.status == 0, result.stderr

    def test_a_dir_inside_the_project_has_its_secrets_hidden_once(self):
        inside = self.project / "sub"
        inside.mkdir()
        (inside / ".env").touch()
        flags = self.launch("--add-dir", "./sub").flags
        hidden = f"--volume=/dev/null:{inside / '.env'}:ro"
        assert flags.count(hidden) == 1

    def test_a_secret_with_a_colon_in_its_name_is_hidden_the_long_way(self):
        # A session can make one: refused, every later launch would be
        for name in (".env.a:b", '.env.a:b,"c"'):
            (self.project / name).touch()
        flags = self.launch().flags
        hidden = "--mount=type=bind,source=/dev/null,"
        assert f"{hidden}target={self.project}/.env.a:b,readonly" in flags
        quoted = f'"target={self.project}/.env.a:b,""c"""'
        assert f"{hidden}{quoted},readonly" in flags

    def test_a_secret_that_cannot_be_hidden_is_not_left_visible(self):
        (self.project / ".env.a:b\nc").touch()
        self.assert_refused(self.launch(), "cannot hide")

    def test_filesystem_root_is_refused(self):
        result = self.launch("--add-dir", "/")
        self.assert_refused(result, "it would defeat the sandbox")

    def test_default_shared_dir_is_mounted(self):
        self.shared.mkdir()
        flags = self.launch().flags
        assert f"--volume={self.shared}:{self.shared}:z" in flags

    def test_shared_dir_can_be_moved(self):
        self.shared.mkdir()
        flags = self.launch(CLAUDE_AIRLOCK_SHARED_DIR=str(self.ref)).flags
        assert f"--volume={self.ref}:{self.ref}:z" in flags
        assert not [flag for flag in flags if "claude-shared" in flag]

    def test_empty_shared_dir_setting_mounts_none(self):
        self.shared.mkdir()
        flags = self.launch(CLAUDE_AIRLOCK_SHARED_DIR="").flags
        assert not [flag for flag in flags if "claude-shared" in flag]

    def test_a_missing_named_shared_dir_aborts(self):
        result = self.launch(CLAUDE_AIRLOCK_SHARED_DIR="/nonexistent")
        self.assert_refused(result, "not a directory: /nonexistent")


class MountArgTest:
    def test_a_bind_source_that_is_not_there_is_refused(self):
        # Docker would make a directory of it, owned by root
        with tempfile.TemporaryDirectory() as directory:
            missing = Path(directory, "moved.py")
            with pytest.raises(Fatal) as refused:
                mount_arg(str(missing), "/moved.py", "ro,z")
            assert "does not exist" in str(refused.value)
            assert not missing.exists()

    def test_a_source_that_is_there_and_a_volume_are_taken(self):
        with tempfile.TemporaryDirectory() as directory:
            there = Path(directory, "here.py")
            there.touch()
            assert (
                mount_arg(str(there), "/here.py", "ro,z")
                == f"--volume={there}:/here.py:ro,z"
            )
            # A link that leads nowhere is there as a link, docker follows it
            dangling = Path(directory, "link")
            dangling.symlink_to(Path(directory, "nowhere"))
            mount_arg(str(dangling), "/link")
        # Nor is a path of the machine docker runs in looked for on this one
        inside = "/run/host-services/ssh-auth.sock"
        assert (
            mount_arg(inside, "/tmp/agent.sock", daemons=True)
            == f"--volume={inside}:/tmp/agent.sock"
        )
        # A named volume has no path to be missing
        assert mount_arg("a-volume", "/data") == "--volume=a-volume:/data"
