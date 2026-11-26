#!/usr/bin/env python3
"""How a session is started: its mounts, hardening and limits, what it
is given of the home, and the socket proxy."""

from __future__ import annotations

import os
import re
import subprocess
import time
from pathlib import Path
from unittest import mock

import pytest
from harness import LauncherTest

from claude_airlock import docker, launcher, settings
from claude_airlock.sandbox import session, socket_proxy


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
        (git / "config").write_text("[include]\n\tpath = ~/.config/git/work\n")
        for name in ("ignore", "work", "credentials", "credentials-nas"):
            (git / name).write_text("\n")
        # The second session of this test, after the one of setUp
        calls = self.launch().calls
        flags = [call for call in calls if call[0] == "run"][-1]
        for name in ("config", "ignore", "templates"):
            mount = f"--volume={git / name}:/home/sandbox/.config/git/{name}:ro,z"
            assert mount in flags
        assert f"--volume={git / 'work'}:{git / 'work'}:ro,z" in flags
        assert not [flag for flag in flags if "credentials" in flag]
        assert not [flag for flag in flags if flag.startswith(f"--volume={git}:")]

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
        assert self.command() == [unasked]
        assert self.command("-p", "hi") == [unasked, "-p", "hi"]
        # Asked for, in the environment or the config file
        assert self.command(CLAUDE_AIRLOCK_ASK="1") == []
        self.write_config("CLAUDE_AIRLOCK_ASK=1")
        assert self.command("-p", "hi") == ["-p", "hi"]
        assert self.command(CLAUDE_AIRLOCK_ASK="0") == [unasked]

    def test_how_to_go_about_permissions_is_the_users_to_say(self):
        for args in (
            ["--permission-mode", "plan"],
            ["--permission-mode=acceptEdits", "-p", "hi"],
            ["--dangerously-skip-permissions"],
            ["--allow-dangerously-skip-permissions"],
            # No session: a command of claude's, and bash
            ["mcp", "list"],
            ["update"],
        ):
            assert self.command(*args) == args
        assert "--dangerously-skip-permissions" not in self.command("--shell")

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
            ("settings.json", "CLAUDE.md", "hooks", "commands", "skills")
            + ("agents", "rules", "plugins", "projects")
        )
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
        socket_proxy.start_socket_proxy(asked)
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

    def test_mode_1_uses_the_limited_sidecar(self):
        args, sidecar = self.sidecar_for(settings.SocketAccess.LIMITED)
        assert "--name=claude-airlock-ps-proxy" in sidecar
        assert any("/docker-socket-proxy.cfg:" in arg for arg in sidecar)
        self.assert_no_allow_switch(sidecar)
        assert "--env=DOCKER_HOST=tcp://claude-airlock-ps-proxy:2375" in args

    def test_mode_full_uses_its_own_sidecar_and_rules(self):
        args, sidecar = self.sidecar_for(settings.SocketAccess.FULL)
        assert "--name=claude-airlock-proxy" in sidecar
        assert any("/docker-socket-proxy-full.cfg:" in arg for arg in sidecar)
        self.assert_no_allow_switch(sidecar)
        assert "--env=DOCKER_HOST=tcp://claude-airlock-proxy:2375" in args

    def test_the_socket_is_mounted_read_only(self):
        _, sidecar = self.sidecar_for(settings.SocketAccess.LIMITED)
        assert f"--volume={socket_proxy.DOCKER_SOCK}:/var/run/docker.sock:ro" in sidecar

    def test_off_by_default(self):
        assert socket_proxy.socket_proxy_args(settings.Settings()) == []
        assert self.calls() == []

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
