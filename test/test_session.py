#!/usr/bin/env python3
"""How a session is started: its mounts, hardening and limits, what it
is given of the home, and the socket proxy."""

from __future__ import annotations

import dataclasses
import errno
import os
import re
import stat
import subprocess
import time
from functools import partial
from pathlib import Path
from unittest import mock

import pytest
from harness import CHOSEN, LauncherTest, mounted_copy

from claude_airlock import docker, errors, launcher, settings
from claude_airlock.recording import capture, sidecar
from claude_airlock.sandbox import session, shared_proxy, socket_proxy
from claude_airlock.sandbox.ending import Ending


class SessionUserTest(LauncherTest):
    def test_a_user_the_image_does_not_know_is_given_an_entry_of_their_own(self):
        # Without one ssh refuses to run, and git over SSH with it
        passwd = self.state / "passwd"
        with mock.patch.multiple(os, getuid=lambda: 501, getgid=lambda: 20):
            args = session.user_args(self.host)
        assert args == ["--user=501:20", f"--volume={passwd}:/etc/passwd:ro,z"]
        entries = passwd.read_text().splitlines()
        assert "sandbox:x:501:20::/home/sandbox:/bin/bash" in entries
        assert "root:x:0:0:root:/root:/bin/bash" in entries
        assert passwd.stat().st_mode & 0o777 == 0o600
        # Made again for another user, and left alone for the same one
        with mock.patch.multiple(os, getuid=lambda: 1001, getgid=lambda: 1001):
            session.user_args(self.host)
            written = passwd.stat().st_mtime_ns
            session.user_args(self.host)
        assert "sandbox:x:1001:1001::/home/sandbox:/bin/bash" in passwd.read_text()
        assert passwd.stat().st_mtime_ns == written

    def test_the_users_the_image_knows_are_left_to_it(self):
        for uid in (0, session.IMAGE_UID):
            with mock.patch.multiple(os, getuid=lambda uid=uid: uid, getgid=lambda: 7):
                assert session.user_args(self.host) == [f"--user={uid}:7"]
        assert not (self.state / "passwd").exists()


class DefaultSessionTest(LauncherTest):
    @pytest.fixture(autouse=True)
    def launched(self, sandbox: None) -> None:
        self.result = self.launch(SSH_AUTH_SOCK="/tmp/agent.sock")
        self.flags = self.result.flags

    def test_project_is_mounted_read_write(self):
        assert f"--volume={self.project}:{self.project}:z" in self.flags

    def test_secret_files_are_shadowed(self):
        for name in (".env", ".netrc"):
            assert f"--volume=/dev/null:{self.project / name}:ro" in self.flags

    def test_templates_and_other_files_stay_readable(self):
        shadowed = [
            flag for flag in self.flags if flag.startswith("--volume=/dev/null:")
        ]
        assert len(shadowed) == 2

    def test_shared_config_is_read_only(self):
        claude = self.home / ".claude"
        for item in ("settings.json", "hooks", "CLAUDE.md", "skills", "agents"):
            assert (
                f"--volume={claude / item}:/home/sandbox/.claude/{item}:ro,z"
                in self.flags
            )

    def test_what_claude_keeps_for_one_session_is_the_sessions_own(self):
        # Sourced by every command of the session it is of, on the host too
        for name in ("shell-snapshots", "session-env"):
            options = f"exec,size=64m,uid={os.getuid()},gid={os.getgid()},mode=700"
            assert f"--tmpfs=/home/sandbox/.claude/{name}:{options}" in self.flags
            # What it goes over is there, docker would make it as root
            assert (self.base / name).is_dir()
        # The sessions that run, by a process number every container has,
        # each with the token another reaches it by, and the mailboxes of
        # a team, by a name every session's team can have
        options = f"size=64m,uid={os.getuid()},gid={os.getgid()},mode=700"
        for name in ("sessions", "teams"):
            assert f"--tmpfs=/home/sandbox/.claude/{name}:{options}" in self.flags
            assert (self.base / name).is_dir()

    def test_what_claude_keeps_outside_its_directory_is_the_sessions_own_too(self):
        # The host's is one directory for every project, and for whatever
        # else writes there: none of it is in a session, nor made for one
        options = f"size=64m,uid={os.getuid()},gid={os.getgid()},mode=700"
        assert f"--tmpfs=/home/sandbox/.local/state/claude:{options}" in self.flags
        assert not [
            flag
            for flag in self.flags
            if "state/claude:" in flag and "--volume" in flag
        ]
        assert not (self.home / ".local" / "state" / "claude").exists()

    def test_no_credentials_come_with_the_git_config(self):
        git = self.home / ".config" / "git"
        (git / "templates").mkdir(parents=True)
        # Relative, from the config that names it, as git takes it, and
        # what that one pulls in too
        (git / "config").write_text("[include]\n\tpath = work\n")
        for name in ("ignore", "credentials", "credentials-nas"):
            (git / name).write_text("\n")
        (git / "work").write_text('[includeIf "gitdir:~/w/"]\n\tpath = ~/w.gitconfig\n')
        (self.home / "w.gitconfig").write_text("[user]\n\tname = w\n")
        # The second session of this test, after the one of setUp
        calls = self.launch().calls
        flags = [call for call in calls if call[0] == "run"][-1]
        for name in ("config", "ignore", "templates"):
            mount = f"--volume={git / name}:/home/sandbox/.config/git/{name}:ro,z"
            assert mount in flags
        assert f"--volume={git / 'work'}:{git / 'work'}:ro,z" in flags
        nested = self.home / "w.gitconfig"
        assert f"--volume={nested}:{nested}:ro,z" in flags
        assert not [flag for flag in flags if "credentials" in flag]
        assert not [flag for flag in flags if flag.startswith(f"--volume={git}:")]

    def test_what_the_git_config_includes_is_not_what_no_session_is_to_have(self):
        # The config kept in a repository a session was given, which named
        # what it pleased for the next launch of any project to mount
        dotfiles = self.home / "dotfiles"
        dotfiles.mkdir()
        # Each read as a config, as git reads what is included: one that
        # is not would have git list none of them
        written = "[a]\n\tb = c\n"
        (self.home / ".ssh").mkdir()
        key = self.home / ".ssh" / "id_ed25519"
        key.write_text(written)
        os.symlink(key, dotfiles / "key")
        secret = self.home / ".netrc"
        secret.write_text(written)
        colon = self.home / "a:b"
        colon.write_text("[user]\n\tname = c\n")
        inner = self.home / "inner.gitconfig"
        inner.write_text("[user]\n\tname = i\n")
        # In the project already, and the config it includes is followed
        # no further: what is in the project is the session's to write
        beyond = self.home / "beyond.gitconfig"
        beyond.write_text("[user]\n\tname = b\n")
        (self.project / "own.gitconfig").write_text(f"[include]\n\tpath = {beyond}\n")
        kept = self.home / "kept.gitconfig"
        kept.write_text(f"[include]\n\tpath = {inner}\n")
        named = [key, dotfiles / "key", secret, colon, self.project / "own.gitconfig"]
        (dotfiles / "gitconfig").write_text(
            "".join(f"[include]\n\tpath = {path}\n" for path in [*named, kept])
        )
        os.symlink(dotfiles / "gitconfig", self.home / ".gitconfig")
        launched = self.launch()
        flags = [call for call in launched.calls if call[0] == "run"][-1]
        mounts = [flag for flag in flags if flag.startswith("--volume=")]
        for path in [*named, beyond]:
            assert not [flag for flag in mounts if str(path) in flag], path
        # What is no secret is mounted as before, and once
        assert mounts.count(f"--volume={kept}:{kept}:ro,z") == 1
        assert mounts.count(f"--volume={inner}:{inner}:ro,z") == 1
        said = launched.stderr
        ssh = self.home / ".ssh"
        assert f"{key}, which the git config includes, is not mounted: {ssh}" in said
        assert f"{dotfiles / 'key'}, which the git config includes" in said
        assert f"{secret}, which the git config includes, is not mounted: its" in said
        assert f"{colon}, which the git config includes, is not mounted: docker" in said
        assert "own.gitconfig, which" not in said
        assert launched.status == 0

    def test_what_a_config_a_session_can_write_includes_is_not_mounted(self):
        # A session was given the config kept in a repository: it can name
        # any file of the home, which reads as a valid git config
        dotfiles = self.home / "dotfiles"
        dotfiles.mkdir()
        credentials = self.home / ".aws" / "credentials"
        credentials.parent.mkdir()
        credentials.write_text("[default]\n\taws_secret_access_key = k\n")
        (dotfiles / "gitconfig").write_text(f"[include]\n\tpath = {credentials}\n")
        os.symlink(dotfiles / "gitconfig", self.home / ".gitconfig")
        mounted = f"--volume={credentials}:{credentials}:ro,z"
        launched = self.launch("--add-dir", str(dotfiles))
        assert launched.status == 0, launched.stderr
        assert mounted not in [c for c in launched.calls if c[0] == "run"][-1]
        assert (
            f"{credentials}, which the git config includes, is not mounted:"
            f" {self.home / '.gitconfig'}, which includes it, is a session's to"
            f" write (it leads to {dotfiles / 'gitconfig'})"
        ) in launched.stderr
        # Nor once it is no longer given: a session could have written it
        launched = self.launch()
        assert mounted not in [c for c in launched.calls if c[0] == "run"][-1]

    def test_a_git_config_that_leads_out_of_what_a_session_can_write_is_not_mounted(
        self,
    ):
        # Dotfiles kept in a repository a session was given, linked to from
        # the home: the session pointed what is there at a key, at a
        # directory of credentials, at a file of them that reads as a config
        dotfiles = self.home / "dotfiles"
        dotfiles.mkdir()
        key = self.home / ".ssh" / "id_ed25519"
        key.parent.mkdir()
        key.write_text("[a]\n\tb = c\n")
        credentials = self.home / ".aws" / "credentials"
        credentials.parent.mkdir()
        credentials.write_text("[default]\n\taws_secret_access_key = k\n")
        git = self.home / ".config" / "git"
        git.mkdir(parents=True)
        work = self.home / "work.gitconfig"
        (git / "config").write_text(f"[include]\n\tpath = {work}\n")
        for name, leads_to in (
            ("gitconfig", key),
            ("templates", credentials.parent),
            ("work", credentials),
        ):
            (dotfiles / name).symlink_to(leads_to)
        os.symlink(dotfiles / "gitconfig", self.home / ".gitconfig")
        os.symlink(dotfiles / "templates", git / "templates")
        os.symlink(dotfiles / "work", work)
        withheld = (self.home / ".gitconfig", git / "templates", work)
        for args in (("--add-dir", str(dotfiles)), ()):
            # Given, then once it no longer is: a session could have
            # written it
            launched = self.launch(*args)
            assert launched.status == 0, launched.stderr
            flags = [call for call in launched.calls if call[0] == "run"][-1]
            for path in withheld:
                assert not [flag for flag in flags if f"={path}:" in flag], path
            assert (
                f"--volume={git / 'config'}:/home/sandbox/.config/git/config:ro,z"
                in flags
            )
            said = launched.stderr
            out = f"it is, or goes through, a link out of {dotfiles}"
            for path in withheld[:2]:
                assert f"{path}, which git reads, is not mounted: {out}" in said
            assert (
                f"{work}, which the git config includes, is not mounted: {out}" in said
            )
        # What leads into the repository and stays there is mounted, as a
        # config kept in dotfiles is
        (dotfiles / "gitconfig").unlink()
        (dotfiles / "gitconfig").write_text("[user]\n\tname = d\n")
        flags = [call for call in self.launch().calls if call[0] == "run"][-1]
        home_config = self.home / ".gitconfig"
        assert f"--volume={home_config}:/home/sandbox/.gitconfig:ro,z" in flags

    def test_a_docker_that_does_not_answer_holds_the_launcher_no_longer(self, capsys):
        hung = self.work / "bin" / "docker"
        hung.write_text("#!/bin/sh\nexec sleep 30\n")
        started = time.monotonic()
        with mock.patch.object(docker, "DOCKER_SECONDS", 0.3):
            assert not docker.docker_ok("container", "inspect", "claude-proj")
            assert docker.docker_output("ps") == ""
            assert docker.docker_bytes("exec", "x", "cat", "y") is None
        assert time.monotonic() - started < 10
        said = capsys.readouterr().err
        assert "docker container inspect did not end within 0 seconds" in said
        # What may have an image fetched first is given longer, and what
        # runs for as long as it has to is given all the time it takes
        assert docker.patience(("run", "--detach", "x")) == docker.SLOW_SECONDS
        assert docker.patience(("ps",)) == docker.DOCKER_SECONDS

    def test_a_docker_that_cannot_be_started_is_said_in_a_line(
        self, monkeypatch: pytest.MonkeyPatch
    ):
        # The fake alone on PATH, no other docker is to be found past it
        fake = self.work / "bin" / "docker"
        fake.chmod(0o644)
        monkeypatch.setenv("PATH", str(fake.parent))
        with pytest.raises(errors.Fatal, match="docker on PATH cannot be run"):
            docker.docker("ps")
        # Given more than the system takes, which a session can bring about
        # with the files it makes, each mounted
        too_long = OSError(errno.E2BIG, os.strerror(errno.E2BIG))
        args = ("run", "--volume=/dev/null:/x:ro", "--mount=type=bind", "img")
        with (
            mock.patch.object(subprocess, "run", side_effect=too_long),
            pytest.raises(errors.Fatal, match="4 arguments of 0 kB, 2 of them mounts"),
        ):
            docker.docker(*args)

    def test_a_long_project_name_gives_a_name_files_take(self):
        # A file takes no more than 255 bytes for a name, and files are
        # named after the session and the project with more put after
        long = self.home / ("p" * 250)
        host = settings.Host(str(self.home), str(long), "", str(self.home / "state"))
        with session.container_name(
            host, {"CLAUDE_BUFFER_NAME": "*claude:x:2*"}
        ) as name:
            assert name == f"claude-{'p' * 250}"[: session.SESSION_NAME_WIDTH]
            assert (Path(host.names_dir) / name).exists()
        # Never with a dot, which the name of a sidecar has after that of
        # its session: a session of app.capture would have the name of the
        # capture of a session of app
        dotted = settings.Host(
            str(self.home), str(self.home / "app.capture"), "", str(self.home / "s")
        )
        with session.container_name(
            dotted, {"CLAUDE_BUFFER_NAME": "*c:x:a.procs*"}
        ) as name:
            assert name == "claude-app-capture-a-procs"
        slug = docker.project_slug(str(long))
        assert slug.startswith("p" * docker.SLUG_WIDTH + "-")
        assert len(slug) == docker.SLUG_WIDTH + 9

    def test_a_capture_that_docker_did_not_run_removes_nothing(self):
        # Its name was in use: what has it is another's, not the capture
        def started(code: int, running: bool) -> list[mock._Call]:
            ran = subprocess.CompletedProcess(["docker"], code, "", "")
            with (
                mock.patch.object(capture, "docker", return_value=ran),
                mock.patch.object(capture, "container_running", return_value=running),
                mock.patch.object(capture.time, "sleep"),
                mock.patch.object(sidecar, "docker", return_value=ran),
                mock.patch.object(sidecar, "docker_ok") as asked,
                pytest.raises(errors.Fatal, match="the network capture did not start"),
            ):
                capture._start_capture(settings.Settings(), self.host, "claude-a", "i")
            return asked.call_args_list

        removed = mock.call("rm", "--force", "claude-a.capture")
        assert removed not in started(125, running=True)
        # One that docker ran and that ended at once is its own, and goes
        assert removed in started(0, running=False)

    def test_a_session_docker_could_not_start_was_not_run(self):
        # Its check is dropped, nothing of it can have changed a file
        image = mock.Mock(tag="img")
        for raised in (
            docker.unstartable(FileNotFoundError(), ["run", "x", "img"]),
            docker.unstartable(OSError(errno.E2BIG, "too long"), ["run", "x", "img"]),
        ):
            ending = Ending("claude-a")
            with (
                mock.patch.object(session, "docker", side_effect=raised),
                pytest.raises(errors.Fatal),
            ):
                session.run_session(["x"], image, [], ending)
            assert not ending.session_was_run

        # Through a chat, by what it says once docker was started for it
        def chat(started: bool, docker_args: list[str], *, on_started) -> int:
            if started:
                on_started()
            raise errors.Fatal("what came after")

        for started in (False, True):
            ending = Ending("claude-a")
            with pytest.raises(errors.Fatal):
                session.run_session(["x"], image, [], ending, partial(chat, started))
            assert ending.session_was_run is started
        # Told to end before it got there
        ending = Ending("claude-a")
        ending.signal = 15
        assert session.run_session(["x"], image, [], ending) == 0
        assert not ending.session_was_run
        ending = Ending("claude-a")
        done = subprocess.CompletedProcess(["docker"], 0, "", "")
        with mock.patch.object(session, "docker", return_value=done):
            assert session.run_session(["x"], image, [], ending) == 0
        assert ending.session_was_run

    def test_a_container_is_gone_only_when_docker_says_so(self):
        def answering(code: int, listed: str = "") -> mock._patch:
            answer = subprocess.CompletedProcess(["docker"], code, listed, "")
            return mock.patch.object(docker, "docker", return_value=answer)

        with answering(0):
            assert docker.container_gone("claude-proj")
        # The filter takes every name that has this one in it
        with answering(0, "claude-proj-2\n"):
            assert docker.container_gone("claude-proj")
        with answering(0, "claude-proj-2\nclaude-proj\n"):
            assert not docker.container_gone("claude-proj")
        # A daemon that is down, and one that does not answer
        for failed in (1, docker.TIMED_OUT):
            with answering(failed):
                assert not docker.container_gone("claude-proj")
                gone = launcher.Launcher(0)
                assert launcher.session_alive(gone, "claude-proj")

    def test_docker_keeps_nothing_of_what_a_session_writes(self):
        # Kept, docker logs would give it to a session of another project
        assert "--log-driver=none" in self.flags

    def test_container_is_hardened(self):
        for flag in (
            "--cap-drop=ALL",
            "--read-only",
            "--security-opt=no-new-privileges",
            "--ulimit=core=0",
        ):
            assert flag in self.flags

    def command(self, *args: str, **env: str) -> list[str]:
        """What claude is run with by a launch of its own, after the
        plugin of the image's language servers."""
        (self.work / "log").unlink(missing_ok=True)
        command = self.launch(*args, **env).command
        return command[2:] if command[:1] == ["--plugin-dir"] else command

    def test_claude_does_not_ask_before_it_uses_a_tool_unless_told_to(self):
        unasked = "--dangerously-skip-permissions"
        assert self.command() == [unasked, *CHOSEN]
        assert self.command("-p", "hi") == [unasked, *CHOSEN, "-p", "hi"]
        # Asked for, in the environment or the config file
        assert self.command(CLAUDE_AIRLOCK_ASK="1") == CHOSEN
        self.write_config("CLAUDE_AIRLOCK_ASK=1")
        assert self.command("-p", "hi") == [*CHOSEN, "-p", "hi"]
        assert self.command(CLAUDE_AIRLOCK_ASK="0") == [unasked, *CHOSEN]

    def test_how_to_go_about_permissions_is_the_users_to_say(self):
        for args in (
            ["--permission-mode", "plan"],
            ["--permission-mode=acceptEdits", "-p", "hi"],
            ["--dangerously-skip-permissions"],
            ["--allow-dangerously-skip-permissions"],
        ):
            assert self.command(*args) == [*CHOSEN, *args]
        # No session: a command of claude's, and bash
        for args in (["mcp", "list"], ["update"]):
            assert self.command(*args) == args
        assert "--dangerously-skip-permissions" not in self.command("--shell")

    def test_claude_starts_on_opus_at_high_effort_unless_told_otherwise(self):
        unasked = "--dangerously-skip-permissions"
        assert CHOSEN == ["--model=opus", "--effort=high"]
        assert self.command(
            CLAUDE_AIRLOCK_MODEL="fable", CLAUDE_AIRLOCK_EFFORT="xhigh"
        ) == [unasked, "--model=fable", "--effort=xhigh"]
        # Empty leaves either to Claude Code, in the environment or the
        # config file, and the environment wins
        assert self.command(CLAUDE_AIRLOCK_MODEL="") == [unasked, "--effort=high"]
        self.write_config("CLAUDE_AIRLOCK_EFFORT=")
        assert self.command() == [unasked, "--model=opus"]
        assert self.command(CLAUDE_AIRLOCK_EFFORT="max") == [
            unasked,
            "--model=opus",
            "--effort=max",
        ]

    def test_the_model_and_the_effort_of_claudes_arguments_win(self):
        unasked = "--dangerously-skip-permissions"
        for args, kept in (
            (["--model", "sonnet"], "--effort=high"),
            (["--model=sonnet"], "--effort=high"),
            (["--effort", "low"], "--model=opus"),
            (["--effort=low", "-p", "hi"], "--model=opus"),
        ):
            assert self.command(*args) == [unasked, kept, *args]
        both = ["--model", "sonnet", "--effort", "low"]
        assert self.command(*both) == [unasked, *both]
        # A prompt that names an option is no option
        assert self.command("use --model") == [unasked, *CHOSEN, "use --model"]
        assert "--model=opus" not in self.command("--shell")

    def test_the_session_is_told_its_settings(self):
        for flag in (
            "--env=CLAUDE_AIRLOCK_NET_FILTER=0",
            "--env=CLAUDE_AIRLOCK_NET_LOG=0",
            "--env=CLAUDE_AIRLOCK_PROC_LOG=0",
            "--env=CLAUDE_AIRLOCK_CACHE=1",
            "--env=CLAUDE_AIRLOCK_MEMORY=16g",
            "--env=CLAUDE_AIRLOCK_PIDS=512",
        ):
            assert flag in self.flags

    def test_claude_code_reports_nothing_unless_allowed_to(self):
        off = [
            "--env=DISABLE_TELEMETRY=1",
            "--env=DISABLE_ERROR_REPORTING=1",
            "--env=DO_NOT_TRACK=1",
        ]
        for flag in off:
            assert flag in self.flags
        # The second session of this test, after the one of setUp
        calls = self.launch(CLAUDE_AIRLOCK_TELEMETRY="1").calls
        allowed = [call for call in calls if call[0] == "run"][-1]
        for flag in off:
            assert flag not in allowed

    def test_the_connectors_of_the_account_are_not_loaded_unless_asked_for(self):
        off = "--env=ENABLE_CLAUDEAI_MCP_SERVERS=false"
        assert off in self.flags
        calls = self.launch(CLAUDE_AIRLOCK_CONNECTORS="1").calls
        allowed = [call for call in calls if call[0] == "run"][-1]
        assert off not in allowed

    def test_default_limits(self):
        for flag in ("--memory=16g", "--memory-swap=16g", "--pids-limit=512"):
            assert flag in self.flags

    def test_every_cpu_unless_a_limit_is_set(self):
        assert "cpus" not in "\n".join(self.flags).lower()
        # The second session of this test, after the one of setUp
        calls = self.launch(CLAUDE_AIRLOCK_CPUS="1.5").calls
        limited = [call for call in calls if call[0] == "run"][-1]
        assert "--cpus=1.5" in limited
        assert "--env=CLAUDE_AIRLOCK_CPUS=1.5" in limited

    def test_opt_in_doors_are_closed(self):
        text = "\n".join(self.flags)
        for marker in (
            "SSH_AUTH_SOCK",
            "ssh-agent",
            "DOCKER_HOST",
            "--runtime",
            "--dns",
        ):
            assert marker not in text
        assert self.result.sidecar("claude-airlock-ps-proxy") is None
        assert self.result.sidecar("claude-egress-proxy") is None

    def test_egress_is_open(self):
        assert "--network=claude-airlock-open-net" in self.flags

    def test_cache_is_a_per_project_volume(self):
        pattern = r"^--volume=claude-cache-proj-[0-9a-f]{8}:/home/sandbox/\.cache$"
        assert any(re.match(pattern, flag) for flag in self.flags)

    def test_no_tty_without_a_terminal(self):
        assert "--tty" not in self.flags

    def test_image_tag_is_a_content_hash(self):
        assert re.search(r"^claude-airlock:[0-9a-f]{12}$", self.result.image)


class HomeTest(LauncherTest):
    """A session's ~/.claude is the launcher's, with named parts of the
    host's."""

    CLAUDE = "/home/sandbox/.claude"

    def mounted_at(self, flags: list[str], target: str) -> list[str]:
        return [
            flag
            for flag in flags
            if flag.startswith("--volume=") and flag.split(":")[1] == target
        ]

    def test_the_hosts_claude_directory_is_not_mounted(self):
        flags = self.launch().flags
        assert self.mounted_at(flags, self.CLAUDE) == [
            f"--volume={self.base}:{self.CLAUDE}:z"
        ]
        assert self.base.stat().st_mode & 511 == 448

    def test_only_what_is_named_comes_from_the_host(self):
        claude = self.home / ".claude"
        for name in ("sessions", "jobs", "daemon"):
            (claude / name).mkdir()
        (claude / ".credentials.json").write_text("{}")
        flags = self.launch().flags
        from_host = sorted(
            flag.split(":")[1][len(self.CLAUDE) + 1 :]
            for flag in flags
            if flag.startswith(f"--volume={claude}/")
        )
        assert from_host == sorted(
            (*settings.CONFIG_FILES, *settings.CONFIG_TREES, "plugins", "projects")
        )
        assert {"settings.json", "CLAUDE.md", "hooks", "skills"} <= set(from_host)
        for name in ("plugins", "projects"):
            assert f"--volume={claude / name}:{self.CLAUDE}/{name}:z" in flags

    def test_every_mount_in_it_has_something_to_go_over(self):
        for extra in ({}, {"CLAUDE_AIRLOCK_SHARED_HISTORY": "1"}):
            flags = self.launch(**extra).flags
            (self.work / "log").unlink()
            inside = [
                flag.split(":")
                for flag in flags
                if flag.startswith(("--volume=", "--tmpfs="))
                and flag.split(":")[1 if flag.startswith("--volume=") else 0]
                .removeprefix("--tmpfs=")
                .startswith(self.CLAUDE + "/")
            ]
            assert len(inside) > 12
            for parts in inside:
                if parts[0].startswith("--tmpfs="):
                    over = self.base / Path(parts[0].removeprefix("--tmpfs=")).name
                    assert over.is_dir(), over
                    continue
                source = Path(parts[0].removeprefix("--volume="))
                over = self.base / Path(parts[1]).relative_to(self.CLAUDE)
                assert source.exists(), source
                # A file where a file goes, docker would make a directory
                assert over.is_dir() == source.is_dir(), over

    def test_what_a_session_left_where_a_mount_goes_in_the_base_is_made_anew(self):
        # A mount over a link would land where it leads: the host's
        # settings under the plugins mounted after them, and every later
        # session would read what a session wrote in their place
        assert self.launch().status == 0
        settings_json = self.base / "settings.json"
        settings_json.unlink()
        settings_json.symlink_to("plugins/x/settings.json")
        hooks = self.base / "hooks"
        hooks.rmdir()
        hooks.write_text("echo planted\n")
        (self.base / "sessions").rmdir()
        (self.base / "sessions").symlink_to(self.home)
        (self.base / "history.jsonl").unlink()
        (self.base / "history.jsonl").mkdir()
        (self.base / "history.jsonl" / "kept").touch()
        (self.work / "log").unlink()
        result = self.launch()
        assert result.status == 0, result.stderr
        for name in ("settings.json", "history.jsonl"):
            assert stat.S_ISREG((self.base / name).lstat().st_mode), name
        for name in ("hooks", "sessions"):
            assert stat.S_ISDIR((self.base / name).lstat().st_mode), name
            assert list((self.base / name).iterdir()) == []
        assert f"{settings_json} was a link, where Claude Code keeps its" in (
            result.stderr
        )
        assert f"{hooks} was of another kind" in result.stderr
        # What the link led to is left as it was
        assert (self.home / ".claude" / "settings.json").read_text() == "{}\n"
        assert (self.home / "proj").is_dir()

    def test_a_link_of_the_users_own_in_the_hosts_claude_is_theirs(self):
        # The user's kit of skills kept elsewhere, as it is
        skills = self.home / ".claude" / "skills"
        skills.rmdir()
        kept = self.home / "kit" / "skills"
        kept.mkdir(parents=True)
        skills.symlink_to(kept)
        result = self.launch()
        assert result.status == 0, result.stderr
        assert skills.is_symlink()
        assert "was a link" not in result.stderr

    def test_a_file_where_a_directory_of_claude_goes_is_said_in_a_line(self):
        hooks = self.home / ".claude" / "hooks"
        hooks.rmdir()
        hooks.touch()
        result = self.launch()
        assert result.status == 1
        assert f"{hooks} is not a directory, where Claude Code keeps its hooks" in (
            result.stderr
        )
        assert "Traceback" not in result.stderr


class SharedProxyTest(LauncherTest):
    NAME = "claude-airlock-test-proxy"

    def proxy(self, files: dict[str, bytes]) -> shared_proxy.SharedProxy:
        return shared_proxy.SharedProxy(self.NAME, "a-net", "an-image", files)

    def start(self, files: dict[str, bytes]) -> list[str]:
        proxy = self.proxy(files)
        proxy.start(self.host)
        sidecar = [call for call in self.calls() if call[0] == "run"][-1]
        assert f"--label=claude-airlock.config={proxy.config}" in sidecar
        return sidecar

    def test_what_a_proxy_is_started_from_is_told_by_its_config(self):
        proxy = self.proxy({"/etc/one.conf": b"one"})
        others = [
            dataclasses.replace(proxy, image="another-image"),
            dataclasses.replace(proxy, files={"/etc/one.conf": b"edited"}),
            # The same rules, read from another place
            dataclasses.replace(proxy, files={"/etc/two.conf": b"one"}),
            dataclasses.replace(proxy, options=("--env=A=1",)),
        ]
        configs = {proxy.config, *(other.config for other in others)}
        assert len(configs) == len(others) + 1
        # Not its network, it joins those of other sessions as it runs
        assert dataclasses.replace(proxy, network="b-net").config == proxy.config

    def test_a_proxy_reads_copies_of_its_files_as_they_were_when_it_started(self):
        sidecar = self.start({"/etc/one.conf": b"one\n", "/etc/two": b"two\n"})
        one = mounted_copy(sidecar, "/etc/one.conf")
        two = mounted_copy(sidecar, "/etc/two")
        assert (one.read_bytes(), two.read_bytes()) == (b"one\n", b"two\n")
        assert one.parent == two.parent
        assert one.parent.parent == self.state / "proxy-files" / self.NAME
        # Read as the proxy's user, written to by nobody
        assert stat.S_IMODE(one.stat().st_mode) == 0o444
        # Before the image, each where the proxy reads it
        assert sidecar.index(f"--volume={one}:/etc/one.conf:ro,z") < sidecar.index(
            "an-image"
        )

    def test_a_proxy_started_anew_has_copies_of_its_own(self):
        first = mounted_copy(self.start({"/etc/one.conf": b"before"}), "/etc/one.conf")
        again = mounted_copy(self.start({"/etc/one.conf": b"after"}), "/etc/one.conf")
        assert again.parent != first.parent
        assert again.read_bytes() == b"after"
        # Those of the container it replaced go with it
        assert not first.parent.exists()
        assert list((self.state / "proxy-files" / self.NAME).iterdir()) == [
            again.parent
        ]


class SocketProxyTest(LauncherTest):
    """Called directly, the socket path is a constant of the socket_proxy module."""

    @pytest.fixture(autouse=True)
    def docker_socket(self, sandbox: None, unix_socket: str) -> None:
        # The checks need a socket file to exist, any will do
        self.cleanup.enter_context(
            mock.patch.object(socket_proxy, "DOCKER_SOCK", unix_socket)
        )

    def sidecar_for(self, mode: settings.SocketAccess) -> tuple[list[str], list[str]]:
        asked = settings.Settings(docker_socket=mode)
        socket_proxy.start_socket_proxy(asked, self.host)
        args = socket_proxy.socket_proxy_args(asked)
        sidecars = [call for call in self.calls() if call[0] == "run"]
        assert len(sidecars) == 1
        return args, sidecars[0]

    @staticmethod
    def assert_no_allow_switch(sidecar: list[str]) -> None:
        """The rules are ours in both modes. The image's own CONTAINERS
        allows every GET under /containers, attach/ws among them, which
        writes to a container."""
        assert not [arg for arg in sidecar if arg.startswith("--env=")][1:]
        assert "--env=EVENTS=0" in sidecar

    def assert_rules(self, sidecar: list[str], name: str) -> None:
        """The sidecar reads a copy of the rules of the checkout, kept
        with the launcher's records: a session that can write the
        checkout does not change them under it."""
        rules = mounted_copy(sidecar, socket_proxy.RULES_TEMPLATE)
        assert rules.is_relative_to(self.state / "proxy-files")
        assert rules.read_bytes() == Path(settings.DOCKERFILE_DIR, name).read_bytes()

    def test_mode_1_uses_the_limited_sidecar(self):
        args, sidecar = self.sidecar_for(settings.SocketAccess.LIMITED)
        assert "--name=claude-airlock-ps-proxy" in sidecar
        self.assert_rules(sidecar, "docker-socket-proxy.cfg")
        self.assert_no_allow_switch(sidecar)
        assert "--env=DOCKER_HOST=tcp://claude-airlock-ps-proxy:2375" in args

    def test_mode_full_uses_its_own_sidecar_and_rules(self):
        args, sidecar = self.sidecar_for(settings.SocketAccess.FULL)
        assert "--name=claude-airlock-proxy" in sidecar
        self.assert_rules(sidecar, "docker-socket-proxy-full.cfg")
        self.assert_no_allow_switch(sidecar)
        assert "--env=DOCKER_HOST=tcp://claude-airlock-proxy:2375" in args

    def test_the_socket_is_mounted_read_only(self):
        _, sidecar = self.sidecar_for(settings.SocketAccess.LIMITED)
        assert f"--volume={socket_proxy.DOCKER_SOCK}:/var/run/docker.sock:ro" in sidecar

    def test_off_by_default(self):
        assert socket_proxy.socket_proxy_args(settings.Settings()) == []
        assert self.calls() == []

    def test_a_host_without_the_socket_is_said_to_give_no_docker(self, capsys):
        # Nothing there, then a file that is not a socket
        plain = self.work / "plain"
        plain.write_text("not a socket\n")
        for path in (self.work / "none", plain):
            with mock.patch.object(socket_proxy, "DOCKER_SOCK", str(path)):
                for mode in (settings.SocketAccess.LIMITED, settings.SocketAccess.FULL):
                    asked = settings.Settings(docker_socket=mode)
                    socket_proxy.say_without_socket(asked)
                    said = capsys.readouterr().err
                    setting = f"CLAUDE_AIRLOCK_DOCKER_SOCKET={mode.value}"
                    assert f"{setting} gives this session no Docker" in said
                    # What the setting would need
                    assert f"the daemon's socket at {path}" in said
                    assert socket_proxy.socket_proxy_args(asked) == []

    def test_nothing_is_said_of_a_socket_that_is_there_or_not_asked_for(self, capsys):
        for mode in settings.SocketAccess:
            socket_proxy.say_without_socket(settings.Settings(docker_socket=mode))
        with mock.patch.object(socket_proxy, "DOCKER_SOCK", str(self.home / "none")):
            socket_proxy.say_without_socket(settings.Settings())
        assert capsys.readouterr().err == ""

    def test_a_session_only_shares_a_network_with_the_proxy_of_its_mode(self):
        names = {
            mode: socket_proxy.network_name(settings.Settings(docker_socket=mode))
            for mode in settings.SocketAccess
        }
        assert names == {
            settings.SocketAccess.OFF: "claude-airlock-open-net",
            settings.SocketAccess.LIMITED: "claude-airlock-open-net-ps",
            settings.SocketAccess.FULL: "claude-airlock-open-net-full",
        }
        _, sidecar = self.sidecar_for(settings.SocketAccess.FULL)
        assert "--network=claude-airlock-open-net-full" in sidecar
        assert [
            "network",
            "connect",
            "claude-airlock-open-net",
            "claude-airlock-proxy",
        ] not in self.calls()

    def test_a_proxy_is_labelled_with_what_it_was_started_from(self):
        _, sidecar = self.sidecar_for(settings.SocketAccess.LIMITED)
        assert [
            arg for arg in sidecar if arg.startswith("--label=claude-airlock.config=")
        ]
