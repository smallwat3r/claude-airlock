#!/usr/bin/env python3
"""The directories mounted next to the project."""

from __future__ import annotations

import os
import tempfile
import unittest.mock
from pathlib import Path

import pytest
from harness import LauncherTest

from claude_airlock.docker import covered_arg, mount_arg
from claude_airlock.errors import Fatal
from claude_airlock.sandbox import mounts

# Root lists and enters a directory whatever its mode says
closed_to_its_owner = pytest.mark.skipif(
    os.getuid() == 0, reason="no directory is closed to root"
)


class ExtraDirsTest(LauncherTest):
    @pytest.fixture(autouse=True)
    def directories(self, sandbox: None) -> None:
        self.ref = self.home / "ref"
        self.shared = self.home / "claude-shared"

    def launch_anew(self, *args: str, **env: str):
        """Launch with nothing noted of the launches before it, for a
        check that looks at the session of more than one."""
        (self.work / "log").unlink(missing_ok=True)
        return self.launch(*args, **env)

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

    def test_a_directory_mounted_from_inside_a_protected_path_is_read_only(self):
        kit = self.shared / "kit"
        (kit / "sub").mkdir(parents=True)
        result = self.launch(
            "--add-dir", str(kit / "sub"), CLAUDE_AIRLOCK_PROTECT="~/claude-shared/kit"
        )
        flags = result.flags
        # Not writable again by being mounted on its own
        assert f"--volume={kit / 'sub'}:{kit / 'sub'}:ro,z" in flags
        assert f"--volume={kit / 'sub'}:{kit / 'sub'}:z" not in flags
        assert f"--volume={kit}:{kit}:ro,z" in flags
        assert (
            f"{kit / 'sub'} is mounted read-only: it is in ~/claude-shared/kit,"
            " which CLAUDE_AIRLOCK_PROTECT protects"
        ) in result.stderr
        # The protected path itself, mounted on its own, the same
        flags = self.launch_anew(
            "--add-dir", str(kit), CLAUDE_AIRLOCK_PROTECT="~/claude-shared/kit"
        ).flags
        assert f"--volume={kit}:{kit}:z" not in flags

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

    def test_the_directories_above_a_hidden_file_are_held_in_place(self):
        # A session cannot read the file, but it could move a directory
        # above it into one that is not looked into for files to hide
        deep = self.project / "apps" / "api"
        deep.mkdir(parents=True)
        (deep / ".env").touch()
        (self.ref / "kept" / "more").mkdir(parents=True)
        (self.ref / "kept" / "more" / ".env").touch()
        flags = self.launch("--add-dir-ro", "~/ref").flags
        for hidden in (deep / ".env", self.ref / "kept" / "more" / ".env"):
            assert f"--volume=/dev/null:{hidden}:ro" in flags
        for above in (self.project / "apps", deep):
            assert flags.count(f"--volume={above}:{above}:z") == 1
        # Not what is read-only anyway, nor the project, held as a mount
        for other in (self.ref / "kept", self.ref / "kept" / "more"):
            assert f"--volume={other}:{other}:z" not in flags
        assert flags.count(f"--volume={self.project}:{self.project}:z") == 1

    def test_a_directory_with_a_colon_above_a_hidden_file_is_held_the_long_way(self):
        # A session can make one: refused, every later launch would be
        odd = self.project / 'a:b,"c"'
        odd.mkdir()
        (odd / ".env").touch()
        result = self.launch()
        assert result.status == 0, result.stderr
        held = f'"source={self.project}/a:b,""c""","target={self.project}/a:b,""c"""'
        assert f"--mount=type=bind,{held}" in result.flags
        hidden = f'"target={self.project}/a:b,""c""/.env"'
        assert f"--mount=type=bind,source=/dev/null,{hidden},readonly" in result.flags

    def test_a_directory_held_for_two_reasons_is_mounted_once(self):
        kit = self.project / "apps" / "kit"
        kit.mkdir(parents=True)
        (self.project / "apps" / ".env").touch()
        (self.project / "apps" / "api").mkdir()
        (self.project / "apps" / "api" / ".env").touch()
        flags = self.launch(CLAUDE_AIRLOCK_PROTECT="apps/kit").flags
        above = self.project / "apps"
        assert flags.count(f"--volume={above}:{above}:z") == 1

    def test_a_directory_mounted_inside_another_is_held_in_place(self):
        # Read-only or not, what is above it could be renamed, and the
        # path made again with other content
        for name in ("lib", "data"):
            (self.project / "vendor" / "deep" / name).mkdir(parents=True)
        flags = self.launch(
            "--add-dir-ro", "vendor/deep/lib", "--add-dir", "vendor/deep/data"
        ).flags
        deep = self.project / "vendor" / "deep"
        assert f"--volume={deep / 'lib'}:{deep / 'lib'}:ro,z" in flags
        assert f"--volume={deep / 'data'}:{deep / 'data'}:z" in flags
        for above in (self.project / "vendor", deep):
            assert flags.count(f"--volume={above}:{above}:z") == 1

    @closed_to_its_owner
    def test_a_directory_that_cannot_be_looked_into_is_hidden_whole(
        self, subtests: pytest.Subtests
    ):
        # A session can make one so, for the file in it to go unhidden
        # at the next launch, and open it again then
        closed = self.project / "backend"
        closed.mkdir()
        (closed / ".env").touch()
        (closed / "deeper").mkdir()
        self.cleanup.callback(closed.chmod, 0o755)
        empty = self.state / "history" / "empty"
        # Not to be listed, then to be listed and not entered
        for mode in (0o000, 0o400):
            with subtests.test(mode=oct(mode)):
                closed.chmod(mode)
                result = self.launch_anew()
                assert f"--volume={empty}:{closed}:ro,z" in result.flags
                assert "cannot be looked into for files of secrets" in result.stderr
                assert f"  {closed}\n" in result.stderr
                assert list(empty.iterdir()) == []
        closed.chmod(0o755)
        result = self.launch_anew()
        assert f"--volume=/dev/null:{closed / '.env'}:ro" in result.flags
        assert "cannot be looked into" not in result.stderr

    def test_a_closed_directory_of_another_user_is_left_as_it_is(self):
        # Neither the launcher nor a session can open it, or change that
        closed = self.project / "data"
        closed.mkdir()
        assert mounts.openable(str(closed))
        with unittest.mock.patch.object(os, "getuid", return_value=os.getuid() + 1):
            assert not mounts.openable(str(closed))
        assert not mounts.openable(str(self.project / "none"))
        assert not mounts.openable(str(self.project / ".env"))

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

    def test_a_link_named_as_a_secret_has_what_it_leads_to_hidden(self):
        kept = self.project / "config" / "production.env"
        kept.parent.mkdir()
        kept.write_text("SECRET=1\n")
        (self.project / "apps").mkdir()
        (self.project / "apps" / ".envrc").symlink_to(kept)
        # Out of what the session has, and to no file: nothing to hide
        outside = self.work / "elsewhere.env"
        outside.touch()
        (self.project / ".netrc").unlink()
        (self.project / ".netrc").symlink_to(outside)
        (self.project / ".pypirc").symlink_to(self.project / "config")
        flags = self.launch().flags
        assert f"--volume=/dev/null:{kept}:ro" in flags
        assert not [flag for flag in flags if "elsewhere.env" in flag]
        assert f"--volume=/dev/null:{self.project / 'config'}:ro" not in flags

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

    def test_a_path_protected_in_two_mounted_directories_is_mounted_once(self):
        kit = self.project / "sub" / "kit"
        kit.mkdir(parents=True)
        flags = self.launch(
            "--add-dir", "./sub", CLAUDE_AIRLOCK_PROTECT="sub/kit"
        ).flags
        assert flags.count(f"--volume={kit}:{kit}:ro,z") == 1

    def test_filesystem_root_is_refused(self):
        result = self.launch("--add-dir", "/")
        self.assert_refused(result, "it would defeat the sandbox")

    def test_a_directory_asked_for_read_only_is_read_only_whoever_else_names_it(
        self, subtests: pytest.Subtests
    ):
        # What one setting keeps a session from, another does not give back
        self.shared.mkdir()
        for args, env in (
            (["--add-dir-ro", "~/claude-shared"], {}),
            (["--add-dir", "~/claude-shared", "--add-dir-ro", "~/claude-shared"], {}),
            (["--add-dir-ro", "~/claude-shared", "--add-dir", "~/claude-shared"], {}),
            ([], {"CLAUDE_AIRLOCK_EXTRA_DIRS_RO": str(self.shared)}),
            (
                ["--add-dir", "~/claude-shared"],
                {"CLAUDE_AIRLOCK_EXTRA_DIRS_RO": str(self.shared)},
            ),
        ):
            with subtests.test(args=args, env=env):
                result = self.launch_anew(*args, **env)
                assert f"--volume={self.shared}:{self.shared}:ro,z" in result.flags
                assert f"--volume={self.shared}:{self.shared}:z" not in result.flags
                # Said to who asked for it writable after that
                last = [*env, *args][-2:-1] == ["--add-dir"]
                assert ("stays read-only" in result.stderr) == last

    def test_the_project_asked_for_read_only_is_refused(self):
        result = self.launch("--add-dir-ro", ".")
        self.assert_refused(result, "cannot mount . read-only: it is the project")
        # Asked for as it is mounted anyway, it is passed over
        assert self.launch("--add-dir", ".").status == 0

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
    def test_a_directory_with_a_colon_in_its_name_is_covered_the_long_way(self):
        # A session can make one: refused, every later launch would be
        with tempfile.TemporaryDirectory() as empty:
            assert covered_arg(empty, "/p/a") == f"--volume={empty}:/p/a:ro,z"
            long = f"--mount=type=bind,source={empty},target=/p/a:b,readonly"
            assert covered_arg(empty, "/p/a:b") == long
            with pytest.raises(Fatal):
                covered_arg(empty, "/p/a:b\nc")

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
