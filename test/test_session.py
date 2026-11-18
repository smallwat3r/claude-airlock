#!/usr/bin/env python3
"""How a session is started: its mounts, hardening and limits, what it
is given of the home, and the socket proxy."""

from __future__ import annotations

import os
import re
import socket
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from harness import (
    LauncherTest,
    network,
    settings,
)


class DefaultSessionTest(LauncherTest):
    def setUp(self):
        super().setUp()
        self.result = self.launch(SSH_AUTH_SOCK="/tmp/agent.sock")
        self.flags = self.result.flags

    def test_project_is_mounted_read_write(self):
        self.assertIn(f"--volume={self.project}:{self.project}:z", self.flags)

    def test_secret_files_are_shadowed(self):
        for name in (".env", ".netrc"):
            self.assertIn(f"--volume=/dev/null:{self.project / name}:ro", self.flags)

    def test_templates_and_other_files_stay_readable(self):
        shadowed = [
            flag for flag in self.flags if flag.startswith("--volume=/dev/null:")
        ]
        self.assertEqual(len(shadowed), 2)

    def test_shared_config_is_read_only(self):
        claude = self.home / ".claude"
        for item in ("settings.json", "hooks", "CLAUDE.md", "skills", "agents"):
            self.assertIn(
                f"--volume={claude / item}:/home/sandbox/.claude/{item}:ro,z",
                self.flags,
            )

    def test_what_claude_keeps_for_one_session_is_the_sessions_own(self):
        # Sourced by every command of the session it is of, on the host too
        for name in ("shell-snapshots", "session-env"):
            options = f"exec,size=64m,uid={os.getuid()},gid={os.getgid()},mode=700"
            self.assertIn(f"--tmpfs=/home/sandbox/.claude/{name}:{options}", self.flags)
            # What it goes over is there, docker would make it as root
            self.assertTrue((self.base / name).is_dir())

    def test_container_is_hardened(self):
        for flag in (
            "--cap-drop=ALL",
            "--read-only",
            "--security-opt=no-new-privileges",
        ):
            self.assertIn(flag, self.flags)

    def command(self, *args: str, **env: str) -> list[str]:
        """What claude is run with by a launch of its own, after the
        plugin of the image's language servers."""
        (self.work / "log").unlink(missing_ok=True)
        command = self.launch(*args, **env).command
        return command[2:] if command[:1] == ["--plugin-dir"] else command

    def test_claude_does_not_ask_before_it_uses_a_tool_unless_told_to(self):
        unasked = "--dangerously-skip-permissions"
        self.assertEqual(self.command(), [unasked])
        self.assertEqual(self.command("-p", "hi"), [unasked, "-p", "hi"])
        # Asked for, in the environment or the config file
        self.assertEqual(self.command(CLAUDE_DOCKER_ASK="1"), [])
        self.write_config("CLAUDE_DOCKER_ASK=1")
        self.assertEqual(self.command("-p", "hi"), ["-p", "hi"])
        self.assertEqual(self.command(CLAUDE_DOCKER_ASK="0"), [unasked])

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
            self.assertEqual(self.command(*args), args)
        self.assertNotIn("--dangerously-skip-permissions", self.command("--shell"))

    def test_the_session_is_told_its_settings(self):
        for flag in (
            "--env=CLAUDE_DOCKER_NET_FILTER=0",
            "--env=CLAUDE_DOCKER_NET_LOG=0",
            "--env=CLAUDE_DOCKER_PROC_LOG=0",
            "--env=CLAUDE_DOCKER_CACHE=1",
            "--env=CLAUDE_DOCKER_MEMORY=16g",
            "--env=CLAUDE_DOCKER_PIDS=512",
        ):
            self.assertIn(flag, self.flags)

    def test_claude_code_reports_nothing_unless_allowed_to(self):
        off = [
            "--env=DISABLE_TELEMETRY=1",
            "--env=DISABLE_ERROR_REPORTING=1",
            "--env=DO_NOT_TRACK=1",
        ]
        for flag in off:
            self.assertIn(flag, self.flags)
        # The second session of this test, after the one of setUp
        calls = self.launch(CLAUDE_DOCKER_TELEMETRY="1").calls
        allowed = [call for call in calls if call[0] == "run"][-1]
        for flag in off:
            self.assertNotIn(flag, allowed)

    def test_the_connectors_of_the_account_are_not_loaded_unless_asked_for(self):
        off = "--env=ENABLE_CLAUDEAI_MCP_SERVERS=false"
        self.assertIn(off, self.flags)
        calls = self.launch(CLAUDE_DOCKER_CONNECTORS="1").calls
        allowed = [call for call in calls if call[0] == "run"][-1]
        self.assertNotIn(off, allowed)

    def test_default_limits(self):
        for flag in ("--memory=16g", "--memory-swap=16g", "--pids-limit=512"):
            self.assertIn(flag, self.flags)

    def test_every_cpu_unless_a_limit_is_set(self):
        self.assertNotIn("cpus", "\n".join(self.flags).lower())
        # The second session of this test, after the one of setUp
        calls = self.launch(CLAUDE_DOCKER_CPUS="1.5").calls
        limited = [call for call in calls if call[0] == "run"][-1]
        self.assertIn("--cpus=1.5", limited)
        self.assertIn("--env=CLAUDE_DOCKER_CPUS=1.5", limited)

    def test_opt_in_doors_are_closed(self):
        text = "\n".join(self.flags)
        for marker in (
            "SSH_AUTH_SOCK",
            "ssh-agent",
            "DOCKER_HOST",
            "--runtime",
            "--dns",
        ):
            self.assertNotIn(marker, text)
        self.assertIsNone(self.result.sidecar("claude-docker-ps-proxy"))
        self.assertIsNone(self.result.sidecar("claude-egress-proxy"))

    def test_egress_is_open(self):
        self.assertIn("--network=claude-docker-open-net", self.flags)

    def test_cache_is_a_per_project_volume(self):
        pattern = r"^--volume=claude-cache-proj-[0-9a-f]{8}:/home/sandbox/\.cache$"
        self.assertTrue(any(re.match(pattern, flag) for flag in self.flags))

    def test_no_tty_without_a_terminal(self):
        self.assertNotIn("--tty", self.flags)

    def test_image_tag_is_a_content_hash(self):
        self.assertRegex(self.result.image, r"^claude-code-sandbox:[0-9a-f]{12}$")


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
        self.assertEqual(
            self.mounted_at(flags, self.CLAUDE),
            [f"--volume={self.base}:{self.CLAUDE}:z"],
        )
        self.assertEqual(self.base.stat().st_mode & 0o777, 0o700)

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
        self.assertEqual(
            from_host,
            sorted(
                ("settings.json", "CLAUDE.md", "hooks", "commands", "skills")
                + ("agents", "rules", "plugins", "projects")
            ),
        )
        for name in ("plugins", "projects"):
            self.assertIn(f"--volume={claude / name}:{self.CLAUDE}/{name}:z", flags)

    def test_every_mount_in_it_has_something_to_go_over(self):
        for extra in ({}, {"CLAUDE_DOCKER_SHARED_HISTORY": "1"}):
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
            self.assertGreater(len(inside), 12)
            for parts in inside:
                if parts[0].startswith("--tmpfs="):
                    over = self.base / Path(parts[0].removeprefix("--tmpfs=")).name
                    self.assertTrue(over.is_dir(), over)
                    continue
                source = Path(parts[0].removeprefix("--volume="))
                over = self.base / Path(parts[1]).relative_to(self.CLAUDE)
                self.assertTrue(source.exists(), source)
                # A file where a file goes, docker would make a directory
                self.assertEqual(over.is_dir(), source.is_dir(), over)


class SocketProxyTest(LauncherTest):
    """Called directly, the socket path is a constant of the network module."""

    def setUp(self):
        super().setUp()
        # The checks need a socket file to exist, any will do. A short path,
        # socket paths are limited to about 100 bytes.
        socket_dir = tempfile.TemporaryDirectory(dir="/tmp")
        self.addCleanup(socket_dir.cleanup)
        socket_path = os.path.join(socket_dir.name, "docker.sock")
        server = socket.socket(socket.AF_UNIX)
        self.addCleanup(server.close)
        server.bind(socket_path)
        for patch in (
            mock.patch.object(network, "DOCKER_SOCK", socket_path),
            mock.patch.dict(os.environ, self.fake_docker_env()),
        ):
            patch.start()
            self.addCleanup(patch.stop)

    def sidecar_for(self, mode: settings.SocketAccess) -> tuple[list[str], list[str]]:
        asked = settings.Settings(socket=mode)
        network.start_socket_proxy(asked)
        args = network.socket_proxy_args(asked)
        sidecars = [call for call in self.calls() if call[0] == "run"]
        self.assertEqual(len(sidecars), 1)
        return args, sidecars[0]

    def test_mode_1_uses_the_limited_sidecar(self):
        args, sidecar = self.sidecar_for(settings.SocketAccess.LIMITED)
        self.assertIn("--name=claude-docker-ps-proxy", sidecar)
        self.assertTrue(any("docker-socket-proxy.cfg" in arg for arg in sidecar))
        # No allow switches, the stock rules deny containers
        self.assertNotIn("--env=CONTAINERS=1", sidecar)
        self.assertIn("--env=DOCKER_HOST=tcp://claude-docker-ps-proxy:2375", args)

    def test_mode_full_uses_its_own_sidecar_and_blocks_writes(self):
        args, sidecar = self.sidecar_for(settings.SocketAccess.FULL)
        self.assertIn("--name=claude-docker-proxy", sidecar)
        for switch in ("CONTAINERS=1", "POST=0", "EXEC=0"):
            self.assertIn(f"--env={switch}", sidecar)
        self.assertIn("--env=DOCKER_HOST=tcp://claude-docker-proxy:2375", args)

    def test_the_socket_is_mounted_read_only(self):
        _, sidecar = self.sidecar_for(settings.SocketAccess.LIMITED)
        self.assertIn(
            f"--volume={network.DOCKER_SOCK}:/var/run/docker.sock:ro", sidecar
        )

    def test_off_by_default(self):
        self.assertEqual(network.socket_proxy_args(settings.Settings()), [])
        self.assertEqual(self.calls(), [])

    def test_a_session_only_shares_a_network_with_the_proxy_of_its_mode(self):
        names = {
            mode: network.network_name(settings.Settings(socket=mode))
            for mode in settings.SocketAccess
        }
        self.assertEqual(
            names,
            {
                settings.SocketAccess.OFF: "claude-docker-open-net",
                settings.SocketAccess.LIMITED: "claude-docker-open-net-ps",
                settings.SocketAccess.FULL: "claude-docker-open-net-full",
            },
        )
        _, sidecar = self.sidecar_for(settings.SocketAccess.FULL)
        self.assertIn("--network=claude-docker-open-net-full", sidecar)
        self.assertNotIn(
            ["network", "connect", "claude-docker-open-net", "claude-docker-proxy"],
            self.calls(),
        )

    def test_a_proxy_is_labelled_with_what_it_was_started_from(self):
        _, sidecar = self.sidecar_for(settings.SocketAccess.LIMITED)
        self.assertTrue(
            [arg for arg in sidecar if arg.startswith("--label=claude-sandbox.config=")]
        )


if __name__ == "__main__":
    unittest.main()
