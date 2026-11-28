#!/usr/bin/env python3
"""The directories mounted next to the project."""

from __future__ import annotations

import os
import shutil
import tempfile
import unittest.mock
from pathlib import Path
from typing import Any

import pytest
from harness import CHOSEN, LauncherTest, Result

from claude_airlock import cli, notice, settings
from claude_airlock.action import Action
from claude_airlock.docker import covered_arg, mount_arg
from claude_airlock.errors import Fatal
from claude_airlock.sandbox import home, mounts, remembered, withheld
from claude_airlock.sandbox.ending import Ending
from claude_airlock.sandbox.hidden import Hidden, hidden_files, openable
from claude_airlock.sandbox.placed import Placed
from claude_airlock.sandbox.runtime import DOCKERS_OWN

# The bound of the files to hide, by its name for a patch: hidden is what
# the checks here call what a launch hides
MOST_HIDDEN = "claude_airlock.sandbox.hidden.MOST_HIDDEN"
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
        unasked = ["--dangerously-skip-permissions", *CHOSEN]
        assert result.command == [f"--add-dir={self.ref}", *unasked, "-p", "hello"]

    def test_a_prompt_is_not_taken_for_a_directory(self):
        # --add-dir is variadic, as two arguments it would take the prompt
        result = self.launch("--add-dir", "~/ref", "hello", CLAUDE_AIRLOCK_FEATURES="")
        unasked = ["--dangerously-skip-permissions", *CHOSEN]
        assert result.command == [f"--add-dir={self.ref}", *unasked, "hello"]

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
        assert openable(str(closed))
        with unittest.mock.patch.object(os, "getuid", return_value=os.getuid() + 1):
            assert not openable(str(closed))
        assert not openable(str(self.project / "none"))
        assert not openable(str(self.project / ".env"))

    def test_a_protected_path_named_through_a_link_elsewhere_is_refused_too(self):
        # A link of the user's into the shared directory, which is in no
        # mounted directory as it is written, and one in there that a
        # session could replace
        kit = self.shared / "kit"
        (kit / "real").mkdir(parents=True)
        (kit / "docs").symlink_to("real")
        (self.home / "kitlink").symlink_to(kit)
        result = self.launch(CLAUDE_AIRLOCK_PROTECT="~/kitlink/docs")
        self.assert_refused(
            result,
            "cannot protect ~/kitlink/docs: it is, or goes through, a link in"
            f" {self.shared}",
        )
        # Through the user's link alone, it is protected where it leads
        result = self.launch_anew(CLAUDE_AIRLOCK_PROTECT="~/kitlink/real")
        assert result.status == 0, result.stderr
        assert f"--volume={kit / 'real'}:{kit / 'real'}:ro,z" in result.flags

    def test_a_directory_to_hold_in_place_that_is_a_link_is_refused(self):
        # A mount over it would go where it leads, and hold nothing
        (self.project / "vendor" / "lib").mkdir(parents=True)
        (self.project / "v").symlink_to("vendor")
        result = self.launch("--add-dir", "v/lib")
        self.assert_refused(
            result,
            f"cannot mount at {self.project}/v: it goes through {self.project}/v,"
            " a link",
        )
        assert self.launch_anew("--add-dir", "vendor/lib").status == 0

    def test_a_protected_path_that_could_be_made_inside_is_refused(self):
        result = self.launch(CLAUDE_AIRLOCK_PROTECT="docs")
        self.assert_refused(result, "cannot protect docs: it does not exist")
        result = self.launch(CLAUDE_AIRLOCK_PROTECT=str(self.home / "proj"))
        self.assert_refused(result, "the project is in it")

    def test_home_directory_is_refused(self):
        result = self.launch(cwd=self.home)
        self.assert_refused(result, "it would defeat the sandbox")
        # And not remembered as a directory a session could write: every
        # later launch would hold back what leads into it, all of the home
        written = remembered.Remembered.load(self.host).written
        assert str(self.home) not in written

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
        self.assert_refused(
            result, f"it is, or goes through, a link out of {self.project}"
        )
        self.shared.mkdir()
        (self.shared / "notes").symlink_to(outside)
        result = self.launch("--add-dir-ro", "~/claude-shared/notes")
        self.assert_refused(
            result, f"it is, or goes through, a link out of {self.shared}"
        )
        # Named by where it is, and a link the session cannot have made
        assert self.launch("--add-dir", str(outside)).status == 0
        mine = self.home / "mine"
        mine.symlink_to(outside)
        assert self.launch("--add-dir", str(mine)).status == 0
        # In a directory it can only read
        (self.ref / "more").symlink_to(outside)
        result = self.launch("--add-dir-ro", "~/ref", "--add-dir", "~/ref/more")
        assert result.status == 0, result.stderr

    def test_a_link_into_what_a_session_can_write_that_leads_out_is_refused(self):
        # The user keeps a link into the project, where a session pointed
        # what it leads to elsewhere, for the next launch to mount that
        outside = self.home / "documents"
        outside.mkdir()
        (self.project / "kit").symlink_to(outside)
        kit = self.home / "kit"
        kit.symlink_to(self.project / "kit")
        result = self.launch("--add-dir", str(kit))
        refused = f"it is, or goes through, a link out of {self.project}"
        self.assert_refused(result, refused)
        assert "Name the directory it leads to" in result.stderr
        # Into the project and no further, it is the project's
        (self.project / "kit").unlink()
        (self.project / "kit").mkdir()
        result = self.launch("--add-dir", str(kit))
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


class TooManyMountsTest(LauncherTest):
    """What a session can make more of than docker can be given mounts
    for ends the launch in a line that names it."""

    def test_more_files_to_hide_than_can_be_mounted_end_the_launch(self):
        # The project has a .env and a .netrc
        found = hidden_files(self.launch_settings(), [str(self.project)])
        assert len(found.files) == 2
        with (
            unittest.mock.patch(MOST_HIDDEN, 1),
            pytest.raises(
                Fatal, match=f"more than 1 files of secrets .* in {self.project}"
            ),
        ):
            hidden_files(self.launch_settings(), [str(self.project)])

    @closed_to_its_owner
    def test_files_hidden_again_count_with_the_directories_that_are_covered(self):
        # The project has a .env and a .netrc, and a directory a session
        # closed: three, then a file hidden through a link at an earlier
        # launch, which a session can have removed since
        closed = self.project / "data"
        closed.mkdir()
        closed.chmod(0o000)
        self.cleanup.callback(closed.chmod, 0o755)
        again = self.project / "plain"
        again.touch()
        launch = self.launch_settings()
        with unittest.mock.patch(MOST_HIDDEN, 3):
            found = hidden_files(launch, [str(self.project)])
            assert (len(found.files), found.covered) == (2, [str(closed)])
            with pytest.raises(
                Fatal,
                match="more than 3 files of secrets to hide and directories that"
                f" cannot be looked into, {closed} among them",
            ):
                hidden_files(launch, [str(self.project)], [str(again)])

    def test_what_is_hidden_again_through_another_mount_counts_too(self):
        # The project has a .env and a .netrc: two, then the same two
        # again where a mount of the host's leads into the project
        found = hidden_files(self.launch_settings(), [str(self.project)])
        target = "/home/sandbox/.claude/plugins"
        with unittest.mock.patch.object(withheld, "MOST_HIDDEN", 4):
            from_host = withheld.HostMounts(
                self.host, roots=(str(self.project),), hidden=found
            )
            assert from_host.mount(str(self.project), target, "z") is None
        assert f"--volume=/dev/null:{target}/.env:ro" in from_host.args
        with (
            unittest.mock.patch.object(withheld, "MOST_HIDDEN", 3),
            pytest.raises(
                Fatal,
                match="more than 3 files of secrets to hide and directories covered,"
                f" with those under {self.project}",
            ),
        ):
            withheld.HostMounts(
                self.host, roots=(str(self.project),), hidden=found
            ).mount(str(self.project), target, "z")

    def test_more_directories_to_hold_than_can_be_mounted_end_the_launch(self):
        deep = self.project / "a" / "b" / "c"
        deep.mkdir(parents=True)
        (deep / ".env").touch()
        hidden = [str(deep / ".env")]
        assert len(mounts._held_in_place([], self.host, [], Hidden(hidden))) == 3
        with (
            unittest.mock.patch.object(mounts, "MOST_HELD", 2),
            pytest.raises(
                Fatal, match=f"more than 2 directories to hold .* {deep}/.env among"
            ),
        ):
            mounts._held_in_place([], self.host, [], Hidden(hidden))

    def test_a_directory_deeper_than_a_path_goes_ends_the_launch(self):
        # Neither hidden nor covered, a session would read what is in it,
        # and docker could not mount anything there either
        deep = os.open(self.project, os.O_RDONLY | os.O_DIRECTORY)
        try:
            for _ in range(18):
                os.mkdir("d" * 250, dir_fd=deep)
                below = os.open("d" * 250, os.O_RDONLY | os.O_DIRECTORY, dir_fd=deep)
                os.close(deep)
                deep = below
            os.close(os.open(".env", os.O_CREAT | os.O_WRONLY, 0o600, dir_fd=deep))
        finally:
            os.close(deep)
        with pytest.raises(
            Fatal, match=f"cannot tell what to hide in {self.project}/d+/.*File name"
        ):
            hidden_files(self.launch_settings(), [str(self.project)])

    def test_a_name_with_a_line_break_is_said_on_the_line_it_is_in(
        self, capsys: pytest.CaptureFixture[str]
    ):
        # What a session names a directory must not pass for a line of the
        # launcher's when the launch ends on it
        forged = self.project / "x\nclaude-airlock: all is well" / "deeper"
        forged.mkdir(parents=True)
        hidden = Hidden([str(forged / ".env")])
        with (
            unittest.mock.patch.object(mounts, "MOST_HELD", 1),
            pytest.raises(Fatal) as refused,
        ):
            mounts._held_in_place([], self.host, [], hidden)
        said = str(refused.value)
        assert "\n" not in said
        assert "x\\nclaude-airlock: all is well" in said
        # Nor through what says what ended it, a line under its name
        notice.warn("cannot go on: x\nclaude-airlock: all is well")
        assert capsys.readouterr().err.count("\n") == 1

    def launch_settings(self) -> settings.Settings:
        return settings.load_settings({}, os.devnull)


class MovedMeanwhileTest(LauncherTest):
    """What a session that runs meanwhile can move of what the mounts of
    another launch go from and to, between their plan and docker run."""

    @pytest.fixture(autouse=True)
    def planned(self, sandbox: None) -> None:
        self.deep = self.project / "a" / "b"
        self.deep.mkdir(parents=True)
        (self.deep / ".env").touch()

    def placed(self, dirs: list[mounts.ExtraDir] | None = None) -> Placed:
        dirs = dirs or []
        roots = mounts.mounted_dirs(dirs, self.host)
        hidden = hidden_files(settings.load_settings({}, os.devnull), roots)
        return Placed.of([], self.host, dirs, hidden)

    def test_a_directory_held_in_place_swapped_for_a_link_ends_the_launch(self):
        placed = self.placed()
        placed.refuse_moved()
        # For docker to mount the home writable where a was to be held
        (self.project / "a").rename(self.project / "moved")
        (self.project / "a").symlink_to(self.home)
        with pytest.raises(
            Fatal, match=f"cannot mount at {self.project}/a: it goes through"
        ):
            placed.refuse_moved()

    def test_another_directory_in_the_place_of_one_planned_ends_it_too(self):
        placed = self.placed()
        (self.project / "a").rename(self.project / "moved")
        self.deep.mkdir(parents=True)
        (self.deep / ".env").touch()
        with pytest.raises(Fatal, match="it is another than was planned"):
            placed.refuse_moved()

    def test_a_directory_mounted_that_leads_elsewhere_now_ends_it(self):
        vendor = self.project / "vendor"
        kit = self.home / "kit"
        for directory in (vendor, kit):
            directory.mkdir()
        placed = self.placed([mounts.ExtraDir(str(kit)), mounts.ExtraDir(str(vendor))])
        kit.rename(self.home / "old-kit")
        kit.symlink_to(self.home / "ref")
        with pytest.raises(Fatal, match=f"cannot mount at {kit}: it is another"):
            placed.refuse_moved()
        # And the rules it was mounted by asked again, of a link out of
        # the project in the place of a directory in it
        kit.unlink()
        (self.home / "old-kit").rename(kit)
        vendor.rmdir()
        vendor.symlink_to(self.home / "ref")
        with pytest.raises(Fatal, match=f"a link out of {self.project}"):
            placed.refuse_moved()

    def test_a_git_config_swapped_for_a_link_between_plan_and_run_ends_it(self):
        # ~/.gitconfig kept as a link into a repository of dotfiles, which
        # a session that runs meanwhile writes: swapped there for a link
        # to a key, docker would mount the key where the config was
        dotfiles = self.project / "dotfiles"
        dotfiles.mkdir()
        (dotfiles / "gitconfig").write_text("[user]\n\tname = me\n")
        gitconfig = self.home / ".gitconfig"
        gitconfig.symlink_to(dotfiles / "gitconfig")
        key = self.home / ".ssh" / "id_ed25519"
        key.parent.mkdir(exist_ok=True)
        key.write_text("secret\n")
        launch = settings.load_settings({}, os.devnull)
        image = unittest.mock.Mock(tag="img", language_servers=())
        plan = cli.Plan(launch, self.host, image, Action.RUN, [], [], [])
        home.prepare_home(self.host)
        planned = cli.session_run_args(plan, "claude-proj", DOCKERS_OWN, "")
        assert mount_arg(str(gitconfig), "/home/sandbox/.gitconfig", "ro,z") in (
            planned.args
        )
        planned.placed.refuse_moved()
        (dotfiles / "gitconfig").rename(dotfiles / "moved")
        (dotfiles / "gitconfig").symlink_to(key)
        with pytest.raises(Fatal, match="it leads elsewhere than was planned"):
            planned.placed.refuse_moved()
        # Nor another file in its place, as with what is held in place
        (dotfiles / "gitconfig").unlink()
        (dotfiles / "gitconfig").write_text("[user]\n\tname = me\n")
        with pytest.raises(Fatal, match="it is another than was planned"):
            planned.placed.refuse_moved()

    def test_a_part_of_claude_swapped_for_a_link_between_plan_and_run_ends_it(self):
        # CLAUDE.md and the plugins kept in a repository of dotfiles, linked
        # to from ~/.claude: a session that runs meanwhile swaps what is
        # there for a link to a key, to the home, for docker to mount that
        dotfiles = self.project / "dotfiles"
        (dotfiles / "plugins").mkdir(parents=True)
        (dotfiles / "CLAUDE.md").write_text("# Mine\n")
        claude = self.home / ".claude"
        (claude / "CLAUDE.md").unlink()
        (claude / "CLAUDE.md").symlink_to(dotfiles / "CLAUDE.md")
        (claude / "plugins").symlink_to(dotfiles / "plugins")
        key = self.home / ".ssh" / "id_ed25519"
        key.parent.mkdir(exist_ok=True)
        key.write_text("secret\n")
        launch = settings.load_settings({}, os.devnull)
        image = unittest.mock.Mock(tag="img", language_servers=())
        plan = cli.Plan(launch, self.host, image, Action.RUN, [], [], [])
        home.prepare_home(self.host)
        for name, leads_to, options in (
            ("CLAUDE.md", key, "ro,z"),
            ("plugins", self.home, "z"),
        ):
            planned = cli.session_run_args(plan, "claude-proj", DOCKERS_OWN, "")
            target = f"/home/sandbox/.claude/{name}"
            assert mount_arg(str(claude / name), target, options) in planned.args
            planned.placed.refuse_moved()
            (dotfiles / name).rename(dotfiles / f"old-{name}")
            (dotfiles / name).symlink_to(leads_to)
            with pytest.raises(
                Fatal, match=f"{claude / name}: it leads elsewhere than was planned"
            ):
                planned.placed.refuse_moved()
            (dotfiles / name).unlink()
            (dotfiles / f"old-{name}").rename(dotfiles / name)

    def test_every_path_of_the_home_mounted_is_looked_at_again(self):
        # Whatever mounts it: each part of ~/.claude, the shared history,
        # the git config and the statusline, all kept in a repository of
        # dotfiles a session writes. One that went round HostMounts would
        # not be looked at again before docker run.
        dotfiles = self.project / "dotfiles"
        dotfiles.mkdir()
        claude = self.home / ".claude"
        home.prepare_home(self.host)
        trees = (*settings.CONFIG_TREES, "plugins", "projects", "file-history")
        for name in (*trees, *settings.CONFIG_FILES, "paste-cache", "history.jsonl"):
            kept = dotfiles / name.replace("/", "-")
            if name.endswith((".json", ".md", ".jsonl")):
                kept.write_text("{}\n")
            else:
                kept.mkdir()
            shutil.rmtree(claude / name, ignore_errors=True)
            (claude / name).unlink(missing_ok=True)
            (claude / name).symlink_to(kept)
        (dotfiles / "gitconfig").write_text("[user]\n\tname = me\n")
        (self.home / ".gitconfig").symlink_to(dotfiles / "gitconfig")
        (dotfiles / "line.sh").write_text("#!/bin/sh\n")
        (self.home / "line.sh").symlink_to(dotfiles / "line.sh")
        (dotfiles / "settings.json").write_text(
            '{"statusLine": {"type": "command", "command": "~/line.sh"}}\n'
        )
        shared = {"CLAUDE_AIRLOCK_SHARED_HISTORY": "1"}
        launch = settings.load_settings(shared, os.devnull)
        image = unittest.mock.Mock(tag="img", language_servers=())
        plan = cli.Plan(launch, self.host, image, Action.RUN, [], [], [])
        planned = cli.session_run_args(plan, "claude-proj", DOCKERS_OWN, "")
        own = (str(self.project), str(self.state))
        sources = {
            arg.removeprefix("--volume=").split(":")[0]
            for arg in planned.args
            if arg.startswith(f"--volume={self.home}/")
        }
        from_home = {source for source in sources if not source.startswith(own)}
        assert len(from_home) == len(trees) + len(settings.CONFIG_FILES) + 4
        assert from_home == {led.path for led in planned.placed.led}

    def test_what_moves_between_the_plan_and_docker_run_ends_the_launch(self):
        planned = cli.session_run_args

        def then_moved(*args: Any) -> cli.RunArgs:
            run_args = planned(*args)
            (self.project / "a").rename(self.project / "moved")
            (self.project / "a").symlink_to(self.home)
            return run_args

        off = ("NET_LOG", "PROC_LOG", "LINE_MODE")
        launch = settings.load_settings(
            {f"CLAUDE_AIRLOCK_{name}": "0" for name in off}, os.devnull
        )
        image = unittest.mock.Mock(tag="img", language_servers=())
        plan = cli.Plan(launch, self.host, image, Action.RUN, [], [], [])
        home.prepare_home(self.host)
        with (
            unittest.mock.patch.object(cli, "session_run_args", then_moved),
            pytest.raises(Fatal, match="it goes through"),
        ):
            cli.recorded_session(
                plan, "claude-proj", Ending("claude-proj"), DOCKERS_OWN, ""
            )
        assert [call for call in self.calls() if call[0] == "run"] == []


def targets(flags: list[str]) -> list[str]:
    """Where each mount of a docker run goes, the short way and the long."""
    found = []
    for flag in flags:
        if flag.startswith("--volume="):
            found.append(flag.split(":")[1])
        elif flag.startswith("--mount="):
            found += [
                p[len("target=") :] for p in flag.split(",") if p.startswith("target=")
            ]
    return found


class AcrossLaunchesTest(LauncherTest):
    """What a session can undo of what keeps it in, for the next launch."""

    @pytest.fixture(autouse=True)
    def outside_made(self, sandbox: None) -> None:
        self.ref = self.home / "ref"
        self.outside = self.home / "documents"
        self.outside.mkdir()

    def launch(self, *args: str, **options: Any) -> Result:
        """Launch with nothing noted of the launches before it: these
        look at the session of more than one."""
        (self.work / "log").unlink(missing_ok=True)
        return super().launch(*args, **options)

    def test_a_file_hidden_through_a_link_stays_hidden_once_the_link_is_gone(self):
        secrets = self.project / "config" / "dev.secrets"
        secrets.parent.mkdir()
        secrets.write_text("KEY=1\n")
        (self.project / ".env").unlink()
        (self.project / ".env").symlink_to("config/dev.secrets")
        hidden = f"--volume=/dev/null:{secrets}:ro"
        assert hidden in self.launch().flags
        # What a session can do: nothing named it a secret then
        (self.project / ".env").unlink()
        assert hidden in self.launch().flags
        # Held where it is, as a file hidden by its own name
        held = f"--volume={secrets.parent}:{secrets.parent}:z"
        assert held in self.launch().flags
        # Gone, and made again by its name: it is no longer remembered
        secrets.unlink()
        assert hidden not in self.launch().flags
        secrets.write_text("KEY=1\n")
        assert hidden not in self.launch().flags

    def test_a_protected_path_through_a_link_a_session_can_replace_is_refused(self):
        vendor = self.project / "vendor" / "docs"
        vendor.mkdir(parents=True)
        (self.project / "docs").symlink_to("vendor/docs")
        (self.project / "v").symlink_to("vendor")
        for raw in ("docs", "v/docs"):
            result = self.launch(CLAUDE_AIRLOCK_PROTECT=raw)
            self.assert_refused(result, f"cannot protect {raw}: it is, or goes through")
        # Out of every mount, as well
        (self.project / "out").symlink_to(self.outside)
        result = self.launch(CLAUDE_AIRLOCK_PROTECT="out")
        self.assert_refused(result, "cannot protect out: it is, or goes through")
        # Named by where it leads, and a link in what is read-only
        assert self.launch(CLAUDE_AIRLOCK_PROTECT="vendor/docs").status == 0
        (self.ref / "docs").mkdir()
        (self.ref / "linked").symlink_to("docs")
        result = self.launch(
            "--add-dir-ro", "~/ref", CLAUDE_AIRLOCK_PROTECT="~/ref/linked"
        )
        assert result.status == 0, result.stderr

    def test_a_project_deep_in_a_directory_mounted_with_it_is_held_in_place(self):
        # Moved under node_modules, the next launch would not look in it
        mono = self.home / "mono"
        web = mono / "apps" / "web"
        web.mkdir(parents=True)
        (web / ".env").touch()
        flags = self.launch("--add-dir", str(mono), cwd=web).flags
        assert f"--volume={mono / 'apps'}:{mono / 'apps'}:z" in flags
        assert f"--volume=/dev/null:{web / '.env'}:ro" in flags

    @closed_to_its_owner
    def test_what_is_covered_is_mounted_at_once_only(self):
        closed = self.project / "closed"
        closed.mkdir()
        (closed / "secret").write_text("KEY=1\n")
        (self.project / ".env").unlink()
        (self.project / ".env").symlink_to("closed/secret")
        closed.chmod(0o300)
        try:
            result = self.launch(CLAUDE_AIRLOCK_PROTECT="closed")
        finally:
            closed.chmod(0o700)
        assert result.status == 0, result.stderr
        found = targets(result.flags)
        assert found.count(str(closed)) == 1
        assert str(closed / "secret") not in found
        # Remembered all the same, for once it is opened again
        (self.project / ".env").unlink()
        assert f"--volume=/dev/null:{closed / 'secret'}:ro" in self.launch().flags

    @closed_to_its_owner
    def test_a_file_hidden_before_where_nothing_looks_stays_hidden(self):
        # Under node_modules, which is not looked into, in a directory a
        # session closed to the launcher, for the file to be forgotten and
        # readable once it opens it again
        closed = self.project / "node_modules" / "kept"
        closed.mkdir(parents=True)
        secrets = closed / "dev.secrets"
        secrets.write_text("KEY=1\n")
        (self.project / ".env").unlink()
        (self.project / ".env").symlink_to(secrets)
        hidden = f"--volume=/dev/null:{secrets}:ro"
        assert hidden in self.launch().flags
        (self.project / ".env").unlink()
        closed.chmod(0)
        self.cleanup.callback(closed.chmod, 0o700)
        result = self.launch()
        assert result.status == 0, result.stderr
        assert hidden in result.flags
        closed.chmod(0o700)
        assert hidden in self.launch().flags

    def test_a_protected_path_that_is_hidden_is_mounted_once(self):
        result = self.launch(CLAUDE_AIRLOCK_PROTECT=".env")
        assert result.status == 0, result.stderr
        found = targets(result.flags)
        assert found.count(str(self.project / ".env")) == 1
        assert f"--volume=/dev/null:{self.project / '.env'}:ro" in result.flags

    def test_a_project_started_in_a_link_a_session_left_is_refused(self):
        # A session of the project made docs a link out of it, for the
        # next launch started there to mount what it leads to, writable
        assert self.launch().status == 0
        docs = self.project / "docs"
        docs.symlink_to(self.outside)
        result = self.launch(cwd=docs, PWD=str(docs))
        self.assert_refused(
            result,
            f"refusing to mount {docs}: it is, or goes through, a link out of"
            f" {self.project}",
        )
        assert "Start from the directory it leads to" in result.stderr
        # Nor remembered as a directory a session can write
        assert str(docs) not in remembered.Remembered.load(self.host).written
        # Started from where it leads, it is a project like any other
        result = self.launch(cwd=self.outside)
        assert result.status == 0, result.stderr

    def test_a_link_left_where_a_session_could_write_is_refused_later(self):
        # Writable at one launch, read-only at the next: the link is the
        # doing of a session all the same
        assert self.launch("--add-dir", "~/ref").status == 0
        (self.ref / "more").symlink_to(self.outside)
        result = self.launch("--add-dir-ro", "~/ref", "--add-dir", "~/ref/more")
        self.assert_refused(result, f"it is, or goes through, a link out of {self.ref}")
        result = self.launch("--add-dir-ro", "~/ref/more")
        self.assert_refused(result, f"it is, or goes through, a link out of {self.ref}")
