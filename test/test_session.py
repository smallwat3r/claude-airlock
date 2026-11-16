#!/usr/bin/env python3
"""How a session is started: its mounts, hardening, limits and options, the
socket proxy, the config file, the image and an installed launcher."""

from __future__ import annotations

import fcntl
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from harness import (
    LAUNCHER,
    ROOT,
    LauncherTest,
    Result,
    image,
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
                f"--volume={claude / item}:/home/node/.claude/{item}:ro,z", self.flags
            )

    def test_what_claude_keeps_for_one_session_is_the_sessions_own(self):
        # Sourced by every command of the session it is of, on the host too
        for name in ("shell-snapshots", "session-env"):
            options = f"exec,size=64m,uid={os.getuid()},gid={os.getgid()},mode=700"
            self.assertIn(f"--tmpfs=/home/node/.claude/{name}:{options}", self.flags)
            # What it goes over is there, docker would make it as root
            self.assertTrue((self.base / name).is_dir())

    def test_container_is_hardened(self):
        for flag in (
            "--cap-drop=ALL",
            "--read-only",
            "--security-opt=no-new-privileges",
        ):
            self.assertIn(flag, self.flags)

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
        off = ["--env=DISABLE_TELEMETRY=1", "--env=DISABLE_ERROR_REPORTING=1"]
        for flag in off:
            self.assertIn(flag, self.flags)
        # The second session of this test, after the one of setUp
        calls = self.launch(CLAUDE_DOCKER_TELEMETRY="1").calls
        allowed = [call for call in calls if call[0] == "run"][-1]
        for flag in off:
            self.assertNotIn(flag, allowed)

    def test_default_limits(self):
        for flag in ("--memory=16g", "--memory-swap=16g", "--pids-limit=512"):
            self.assertIn(flag, self.flags)

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
        pattern = r"^--volume=claude-cache-proj-[0-9a-f]{8}:/home/node/\.cache$"
        self.assertTrue(any(re.match(pattern, flag) for flag in self.flags))

    def test_no_tty_without_a_terminal(self):
        self.assertNotIn("--tty", self.flags)

    def test_image_tag_is_a_content_hash(self):
        self.assertRegex(self.result.image, r"^claude-code-sandbox:[0-9a-f]{12}$")


class OptionsTest(LauncherTest):
    def test_opt_ins(self):
        flags = self.launch(
            SSH_AUTH_SOCK="/tmp/agent.sock",
            CLAUDE_DOCKER_SSH_AGENT="1",
            CLAUDE_DOCKER_SHADOW="*.pem",
            CLAUDE_DOCKER_RW_CONFIG="1",
            CLAUDE_DOCKER_CACHE="0",
            CLAUDE_DOCKER_RUNTIME="runsc",
        ).flags
        self.assertIn("--env=SSH_AUTH_SOCK=/tmp/ssh-agent.sock", flags)
        # Not the agent's own socket, one of the launcher's in front of it
        (agent,) = (flag for flag in flags if flag.endswith(":/tmp/ssh-agent.sock:z"))
        self.assertIn(f"--volume={self.state / 'agents'}/", agent)
        self.assertIn(f"--volume=/dev/null:{self.project / 'key.pem'}:ro", flags)
        self.assertFalse(
            [flag for flag in flags if "/.claude/" in flag and flag.endswith(":ro,z")]
        )
        # The host's all the same, not one a session makes for the sandbox
        claude = self.home / ".claude"
        for item in ("settings.json", "hooks", "rules"):
            self.assertIn(
                f"--volume={claude / item}:/home/node/.claude/{item}:z", flags
            )
        self.assertIn("--tmpfs=/home/node/.cache:exec,size=2g", flags)
        self.assertIn("--runtime=runsc", flags)

    def test_a_flag_must_be_0_or_1(self):
        result = self.launch(CLAUDE_DOCKER_NET_FILTER="true")
        self.assert_refused(result, "CLAUDE_DOCKER_NET_FILTER must be 0 or 1")

    def test_shell_runs_bash_without_claude_arguments(self):
        result = self.launch("--shell", "--add-dir", str(self.home / "ref"), "-c", "ls")
        self.assertIn("--entrypoint=bash", result.flags)
        self.assertEqual(result.command, ["-c", "ls"])

    def test_filtered_egress(self):
        result = self.launch(CLAUDE_DOCKER_NET_FILTER="1")
        self.assertIn("--network=claude-docker-net", result.flags)
        self.assertIn("--dns=127.0.0.1", result.flags)
        self.assertIn("--env=HTTPS_PROXY=http://claude-egress-proxy:3128", result.flags)
        # Without the host on it, which would be a way around the filter
        isolated = [
            f"--opt=com.docker.network.bridge.gateway_mode_ipv{version}=isolated"
            for version in (4, 6)
        ]
        self.assertIn(
            ["network", "create", "--internal", *isolated, "claude-docker-net"],
            result.calls,
        )
        # Waited for, a session must not start ahead of its proxy
        self.assertTrue(
            [c for c in result.calls if c[:2] == ["exec", "claude-egress-proxy"]]
        )
        proxy = result.sidecar("claude-egress-proxy")
        self.assertIn("--network=claude-docker-net", proxy)
        self.assertTrue(any("allowed-domains.txt" in arg for arg in proxy))

    def test_the_filter_network_is_never_made_with_a_route_out(self):
        result = self.launch(CLAUDE_DOCKER_NET_FILTER="1")
        made = [call for call in result.calls if call[:2] == ["network", "create"]]
        self.assertTrue(made)
        for call in made:
            self.assertIn("--internal", call)

    def test_a_filter_network_with_a_route_out_is_refused(self):
        result = self.launch(CLAUDE_DOCKER_NET_FILTER="1", FAKE_NETWORK="false")
        self.assert_refused(result, "claude-docker-net is not internal")

    def test_a_socket_proxy_left_on_the_network_is_taken_off_it(self):
        result = self.launch(FAKE_NETWORK="false claude-docker-proxy claude-other")
        off = [call for call in result.calls if call[:2] == ["network", "disconnect"]]
        self.assertEqual(
            off,
            [
                [
                    *("network", "disconnect", "--force"),
                    *("claude-docker-open-net", "claude-docker-proxy"),
                ]
            ],
        )

    def test_a_filter_network_the_host_is_on_is_made_anew_once_free(self):
        made_anew = ["network", "rm", "claude-docker-net"]
        # From before the host was kept off it, with its proxy alone on it
        old = "true mode= claude-egress-proxy"

        def filtered(network: str, version: str) -> Result:
            (self.work / "log").unlink(missing_ok=True)
            result = self.launch(
                CLAUDE_DOCKER_NET_FILTER="1", FAKE_NETWORK=network, FAKE_VERSION=version
            )
            self.assertEqual(result.status, 0, result.stderr)
            return result

        calls = filtered(old, "29.1.0").calls
        self.assertIn(made_anew, calls)
        off = ["network", "disconnect", "--force", "claude-docker-net"]
        self.assertIn([*off, "claude-egress-proxy"], calls)
        # Not under a session, which is said
        busy = filtered(old + " claude-other.capture", "29.1.0")
        self.assertNotIn(made_anew, busy.calls)
        self.assertIn("lets a session reach what the host listens on", busy.stderr)
        # Not where docker cannot, and not when it is so already
        self.assertNotIn(made_anew, filtered(old, "27.5.1").calls)
        self.assertNotIn(made_anew, filtered("true mode=isolated", "29.1.0").calls)

    def test_a_proxy_is_removed_with_the_last_session_that_uses_it(self):
        proxies = "claude-docker-ps-proxy\nclaude-egress-proxy\nclaude-other"

        def removed(**env: str) -> list[str]:
            (self.work / "log").unlink(missing_ok=True)
            calls = self.launch(FAKE_PS=proxies, **env).calls
            return [call[-1] for call in calls if call[:2] == ["rm", "--force"]]

        # Whichever session started them, and nothing that is not a proxy
        self.assertEqual(removed(), ["claude-docker-ps-proxy", "claude-egress-proxy"])
        # Not under a session on a network of theirs
        self.assertEqual(removed(FAKE_NETWORK="false claude-other.capture"), [])
        # Nor while another launcher says it uses one, its session yet to start
        in_use = self.state / "proxies" / "claude-egress-proxy"
        with open(in_use, "w") as held:
            fcntl.flock(held, fcntl.LOCK_SH)
            self.assertEqual(removed(), ["claude-docker-ps-proxy"])

    def test_two_launchers_do_not_take_the_same_name(self):
        self.assertIn("--name=claude-proj", self.launch().flags)
        (self.work / "log").unlink()
        # Another launcher has the name, its container is yet to start
        with open(self.state / "names" / "claude-proj", "w") as held:
            fcntl.flock(held, fcntl.LOCK_EX)
            self.assertIn("--name=claude-proj-2", self.launch().flags)

    def test_what_claude_follows_cannot_be_written_or_created(self):
        flags = self.launch().flags
        claude = self.home / ".claude"
        for name in ("settings.json", "CLAUDE.md", "hooks", "skills", "agents"):
            self.assertIn(
                f"--volume={claude / name}:/home/node/.claude/{name}:ro,z", flags
            )
        # Not there before: made empty, so that a session cannot make them
        for name in ("commands", "rules"):
            self.assertEqual(list((claude / name).iterdir()), [])
            self.assertIn(
                f"--volume={claude / name}:/home/node/.claude/{name}:ro,z", flags
            )

    def test_the_seeded_config_leaves_the_other_projects_out(self):
        config = {
            "theme": "dark",
            "projects": {"/home/me/other": {"mcpServers": {}}},
            # With what they are started with, a token as often as not
            "mcpServers": {"tracker": {"command": "x", "env": {"TOKEN": "secret"}}},
        }
        (self.home / ".claude.json").write_text(json.dumps(config))
        self.launch()
        seeded = self.base / ".claude.json"
        self.assertEqual(json.loads(seeded.read_text()), {"theme": "dark"})
        self.assertEqual(seeded.stat().st_mode & 0o777, 0o600)
        self.assertEqual(seeded.stat().st_nlink, 1)
        # And is not seeded again over what the sessions made of it
        seeded.write_text("{}")
        self.launch()
        self.assertEqual(seeded.read_text(), "{}")

    def test_the_config_the_sandbox_had_is_carried_over_whole(self):
        # From when the host's ~/.claude was mounted whole
        had = {"theme": "light", "projects": {str(self.project): {"trusted": True}}}
        (self.home / ".claude" / ".claude.json").write_text(json.dumps(had))
        (self.home / ".claude.json").write_text(json.dumps({"theme": "dark"}))
        self.launch()
        self.assertEqual(json.loads((self.base / ".claude.json").read_text()), had)


class HomeTest(LauncherTest):
    """A session's ~/.claude is the launcher's, with named parts of the
    host's."""

    CLAUDE = "/home/node/.claude"

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

    def sidecar_for(self, mode: str) -> tuple[list[str], list[str]]:
        asked = settings.Settings(socket=mode)
        network.start_socket_proxy(asked)
        args = network.socket_proxy_args(asked)
        sidecars = [call for call in self.calls() if call[0] == "run"]
        self.assertEqual(len(sidecars), 1)
        return args, sidecars[0]

    def test_mode_1_uses_the_limited_sidecar(self):
        args, sidecar = self.sidecar_for("1")
        self.assertIn("--name=claude-docker-ps-proxy", sidecar)
        self.assertTrue(any("docker-socket-proxy.cfg" in arg for arg in sidecar))
        # No allow switches, the stock rules deny containers
        self.assertNotIn("--env=CONTAINERS=1", sidecar)
        self.assertIn("--env=DOCKER_HOST=tcp://claude-docker-ps-proxy:2375", args)

    def test_mode_full_uses_its_own_sidecar_and_blocks_writes(self):
        args, sidecar = self.sidecar_for("full")
        self.assertIn("--name=claude-docker-proxy", sidecar)
        for switch in ("CONTAINERS=1", "POST=0", "EXEC=0"):
            self.assertIn(f"--env={switch}", sidecar)
        self.assertIn("--env=DOCKER_HOST=tcp://claude-docker-proxy:2375", args)

    def test_the_socket_is_mounted_read_only(self):
        _, sidecar = self.sidecar_for("1")
        self.assertIn(
            f"--volume={network.DOCKER_SOCK}:/var/run/docker.sock:ro", sidecar
        )

    def test_off_by_default(self):
        self.assertEqual(network.socket_proxy_args(settings.Settings()), [])
        self.assertEqual(self.calls(), [])

    def test_a_session_only_shares_a_network_with_the_proxy_of_its_mode(self):
        names = {
            mode: network.network_name(settings.Settings(socket=mode))
            for mode in ("0", "1", "full")
        }
        self.assertEqual(
            names,
            {
                "0": "claude-docker-open-net",
                "1": "claude-docker-open-net-ps",
                "full": "claude-docker-open-net-full",
            },
        )
        _, sidecar = self.sidecar_for("full")
        self.assertIn("--network=claude-docker-open-net-full", sidecar)
        self.assertNotIn(
            ["network", "connect", "claude-docker-open-net", "claude-docker-proxy"],
            self.calls(),
        )

    def test_a_proxy_is_labelled_with_what_it_was_started_from(self):
        _, sidecar = self.sidecar_for("1")
        self.assertTrue(
            [arg for arg in sidecar if arg.startswith("--label=claude-sandbox.config=")]
        )


class ExtraDirsTest(LauncherTest):
    def setUp(self):
        super().setUp()
        self.ref = self.home / "ref"
        self.shared = self.home / "claude-shared"

    def test_read_only_dir(self):
        result = self.launch(
            "--add-dir-ro", "~/ref", "-p", "hello", CLAUDE_DOCKER_FEATURES=""
        )
        self.assertIn(f"--volume={self.ref}:{self.ref}:ro,z", result.flags)
        self.assertEqual(result.command, [f"--add-dir={self.ref}", "-p", "hello"])

    def test_a_prompt_is_not_taken_for_a_directory(self):
        # --add-dir is variadic, as two arguments it would take the prompt
        result = self.launch("--add-dir", "~/ref", "hello", CLAUDE_DOCKER_FEATURES="")
        self.assertEqual(result.command, [f"--add-dir={self.ref}", "hello"])

    def test_read_write_dir_and_its_secrets(self):
        (self.ref / ".env").touch()
        flags = self.launch(f"--add-dir={self.ref}").flags
        self.assertIn(f"--volume={self.ref}:{self.ref}:z", flags)
        self.assertIn(f"--volume=/dev/null:{self.ref / '.env'}:ro", flags)

    def test_a_protected_path_is_read_only_inside_what_is_mounted(self):
        kit = self.shared / "kit"
        kit.mkdir(parents=True)
        (self.project / "docs").mkdir()
        self.write_config(f"CLAUDE_DOCKER_PROTECT=~/claude-shared/kit:{self.ref}")
        flags = self.launch(
            "--add-dir", "~/ref", CLAUDE_DOCKER_PROTECT="docs:~/not-mounted"
        ).flags
        # In the shared directory and in the project, on top of them
        self.assertIn(f"--volume={self.shared}:{self.shared}:z", flags)
        for inside in (kit, self.project / "docs"):
            self.assertIn(f"--volume={inside}:{inside}:ro,z", flags)
        # A mounted directory itself is mounted read-only, once
        self.assertIn(f"--volume={self.ref}:{self.ref}:ro,z", flags)
        self.assertNotIn(f"--volume={self.ref}:{self.ref}:z", flags)
        # What is not mounted is not brought in
        self.assertFalse([flag for flag in flags if "not-mounted" in flag])
        self.assertIn(
            f"--env=CLAUDE_DOCKER_PROTECT={kit}:{self.project / 'docs'}", flags
        )

    def test_a_protected_path_that_could_be_made_inside_is_refused(self):
        result = self.launch(CLAUDE_DOCKER_PROTECT="docs")
        self.assert_refused(result, "cannot protect docs: it does not exist")
        result = self.launch(CLAUDE_DOCKER_PROTECT=str(self.home / "proj"))
        self.assert_refused(result, "the project is in it")

    def test_home_directory_is_refused(self):
        result = self.launch(cwd=self.home)
        self.assert_refused(result, "it would defeat the sandbox")

    def test_a_link_to_the_home_directory_is_refused(self):
        link = self.work / "elsewhere"
        link.symlink_to(self.home)
        result = self.launch("--add-dir", str(link))
        self.assert_refused(result, "it would defeat the sandbox")

    def test_a_dir_inside_the_project_has_its_secrets_hidden_once(self):
        inside = self.project / "sub"
        inside.mkdir()
        (inside / ".env").touch()
        flags = self.launch("--add-dir", "./sub").flags
        hidden = f"--volume=/dev/null:{inside / '.env'}:ro"
        self.assertEqual(flags.count(hidden), 1)

    def test_a_secret_that_cannot_be_hidden_is_not_left_visible(self):
        (self.project / ".env.a:b").touch()
        self.assert_refused(self.launch(), "cannot hide")

    def test_filesystem_root_is_refused(self):
        result = self.launch("--add-dir", "/")
        self.assert_refused(result, "it would defeat the sandbox")

    def test_default_shared_dir_is_mounted(self):
        self.shared.mkdir()
        flags = self.launch().flags
        self.assertIn(f"--volume={self.shared}:{self.shared}:z", flags)

    def test_shared_dir_can_be_moved(self):
        self.shared.mkdir()
        flags = self.launch(CLAUDE_DOCKER_SHARED_DIR=str(self.ref)).flags
        self.assertIn(f"--volume={self.ref}:{self.ref}:z", flags)
        self.assertFalse([flag for flag in flags if "claude-shared" in flag])

    def test_empty_shared_dir_setting_mounts_none(self):
        self.shared.mkdir()
        flags = self.launch(CLAUDE_DOCKER_SHARED_DIR="").flags
        self.assertFalse([flag for flag in flags if "claude-shared" in flag])

    def test_a_missing_named_shared_dir_aborts(self):
        result = self.launch(CLAUDE_DOCKER_SHARED_DIR="/nonexistent")
        self.assert_refused(result, "not a directory: /nonexistent")


class ConfigFileTest(LauncherTest):
    def test_sets_a_default(self):
        self.write_config("# limits", "", "CLAUDE_DOCKER_MEMORY=8g")
        self.assertIn("--memory=8g", self.launch().flags)

    def test_environment_wins(self):
        self.write_config("CLAUDE_DOCKER_MEMORY=8g")
        self.assertIn("--memory=4g", self.launch(CLAUDE_DOCKER_MEMORY="4g").flags)

    def test_an_empty_switch_does_not_undo_the_file(self):
        self.write_config("CLAUDE_DOCKER_NET_FILTER=1")
        flags = self.launch(CLAUDE_DOCKER_NET_FILTER="").flags
        self.assertIn("--network=claude-docker-net", flags)

    def test_what_the_file_hides_the_environment_does_not_show(self):
        (self.project / "notes.secret").touch()
        self.write_config("CLAUDE_DOCKER_SHADOW=*.pem")
        flags = self.launch(CLAUDE_DOCKER_SHADOW="*.secret").flags
        for name in ("key.pem", "notes.secret"):
            self.assertIn(f"--volume=/dev/null:{self.project / name}:ro", flags)

    def test_an_empty_list_does_not_undo_the_file(self):
        self.write_config("CLAUDE_DOCKER_SHADOW=*.pem")
        flags = self.launch(CLAUDE_DOCKER_SHADOW="").flags
        self.assertIn(f"--volume=/dev/null:{self.project / 'key.pem'}:ro", flags)

    def test_rejects_an_unknown_setting(self):
        self.write_config("CLAUDE_DOCKER_NET_FILTR=1")
        self.assert_refused(self.launch(), "not a known setting")

    def test_rejects_per_project_settings(self):
        self.write_config("CLAUDE_DOCKER_EXTRA_DIRS=/tmp")
        self.assert_refused(self.launch(), "not a known setting")

    def test_rejects_other_variables(self):
        self.write_config("PATH=/tmp/evil")
        self.assert_refused(self.launch(), "not a known setting")

    def test_values_are_not_evaluated(self):
        self.write_config("CLAUDE_DOCKER_RUNTIME=$(echo pwned)")
        self.assertIn("--runtime=$(echo pwned)", self.launch().flags)


class ImageTest(LauncherTest):
    def test_prune_removes_the_images_of_before(self):
        current = self.launch().image
        old, used = "claude-code-sandbox:0ld", "claude-code-sandbox:u5ed"
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
        result = self.launch(CLAUDE_DOCKER_FEATURES="../../etc/passwd")
        self.assert_refused(result, "invalid feature name")

    def test_feature_selection_is_sorted_and_unique(self):
        host = settings.detect_host({"HOME": str(self.home)})
        selection = settings.Settings(features="typst,go go")
        self.assertEqual(image.selected_features(selection, host), ["go", "typst"])

    def test_claude_md_lists_what_was_built(self):
        self.launch(CLAUDE_DOCKER_FEATURES="go")
        claude_md = (self.work / "out" / "CLAUDE.md").read_text()
        self.assertRegex(claude_md, r"(?m)^- Go ")
        self.assertNotIn("KiCad", claude_md)
        self.assertNotIn("Placeholder", claude_md)

    def write_feature(self, name: str, *lines: str) -> Path:
        directory = self.home / ".config" / "claude-sandbox" / "features"
        directory.mkdir(parents=True, exist_ok=True)
        (directory / f"{name}.Dockerfile").write_text("\n".join(lines) + "\n")
        return directory

    def test_a_feature_brings_those_it_requires(self):
        self.write_feature(
            "mine", "# claude-feat-requires: go", "# claude-feat-md: My tool"
        )
        self.launch(CLAUDE_DOCKER_FEATURES="mine")
        claude_md = (self.work / "out" / "CLAUDE.md").read_text()
        self.assertRegex(claude_md, r"(?m)^- Go ")
        self.assertRegex(claude_md, r"(?m)^- My tool$")

    def test_an_unknown_required_feature_aborts(self):
        self.write_feature("mine", "# claude-feat-requires: nothere")
        result = self.launch(CLAUDE_DOCKER_FEATURES="mine")
        self.assert_refused(result, "unknown feature: nothere")

    def test_claude_gets_the_language_servers_of_the_image(self):
        result = self.launch("-p", "hello", CLAUDE_DOCKER_FEATURES="go typst")
        self.assertEqual(result.command[:2], ["--plugin-dir", image.PLUGIN_DIR])
        manifest = (
            self.work / "out" / "claude.plugin" / ".claude-plugin" / "plugin.json"
        )
        servers = json.loads(manifest.read_text())["lspServers"]
        self.assertEqual(list(servers), ["gopls"])
        self.assertEqual(servers["gopls"]["command"], "gopls")

    def test_an_image_without_language_servers_gives_claude_no_plugin(self):
        result = self.launch(CLAUDE_DOCKER_FEATURES="typst")
        self.assertNotIn("--plugin-dir", result.command)

    def test_a_language_server_line_that_is_not_json_is_refused(self):
        self.write_feature("mine", "# claude-feat-lsp: {gopls}")
        result = self.launch(CLAUDE_DOCKER_FEATURES="mine")
        self.assert_refused(result, "is not JSON")

    def test_the_former_claude_md_marker_is_refused(self):
        self.write_feature("mine", "# claude: My tool")
        result = self.launch(CLAUDE_DOCKER_FEATURES="mine")
        self.assert_refused(result, 'are now written "# claude-feat-md: "')

    def test_a_feature_brings_its_files_to_the_build(self):
        tool = self.write_feature("mine", "COPY mine/tool /usr/local/bin/") / "mine"
        tool.mkdir()
        (tool / "tool").write_text("one\n")
        self.launch(CLAUDE_DOCKER_FEATURES="mine")
        self.assertEqual((self.work / "out" / "mine" / "tool").read_text(), "one\n")
        # An edited file is another image, like an edited fragment
        (tool / "tool").write_text("two\n")
        self.launch(CLAUDE_DOCKER_FEATURES="mine")
        built = {call[1] for call in self.calls() if call[0] == "build"}
        self.assertEqual(len(built), 2)

    def test_every_feature_assembles(self):
        result = self.launch("--dockerfile")
        self.assertEqual(result.status, 0)
        self.assertRegex(result.stdout, r"(?m)^ENTRYPOINT")


class InstallTest(LauncherTest):
    STATUSLINE = ROOT / "bin" / "claude-statusline"

    def test_the_launcher_can_be_symlinked(self):
        link = self.work / "bin" / "claude-docker"
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
        self.write_config("CLAUDE_DOCKER_NET_FILTR=1")
        for option in ("--help", "-h"):
            result = self.launch(option)
            self.assertEqual(result.status, 0, result.stderr)
            self.assertIn("claude-docker --trace", result.stdout)
            self.assertIn("CLAUDE_DOCKER_NET_FILTER", result.stdout)
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
