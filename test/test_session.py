#!/usr/bin/env python3
"""How a session is started: its mounts, hardening, limits and options, the
socket proxy, the config file, the image and an installed launcher."""

from __future__ import annotations

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
            "--env=CLAUDE_DOCKER_CACHE=1",
            "--env=CLAUDE_DOCKER_MEMORY=16g",
            "--env=CLAUDE_DOCKER_PIDS=512",
        ):
            self.assertIn(flag, self.flags)

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
        self.assertIn("--volume=/tmp/agent.sock:/tmp/ssh-agent.sock:z", flags)
        self.assertIn(f"--volume=/dev/null:{self.project / 'key.pem'}:ro", flags)
        self.assertFalse(
            [flag for flag in flags if "/.claude/" in flag and flag.endswith(":ro,z")]
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
        self.assertIn(
            ["network", "create", "--internal", "claude-docker-net"], result.calls
        )
        # Waited for, a session must not start ahead of its proxy
        self.assertTrue(
            [c for c in result.calls if c[:2] == ["exec", "claude-egress-proxy"]]
        )
        proxy = result.sidecar("claude-egress-proxy")
        self.assertIn("--network=claude-docker-net", proxy)
        self.assertTrue(any("allowed-domains.txt" in arg for arg in proxy))


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
        args = network.socket_proxy_args(settings.Settings(socket=mode))
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


class ExtraDirsTest(LauncherTest):
    def setUp(self):
        super().setUp()
        self.ref = self.home / "ref"
        self.shared = self.home / "claude-shared"

    def test_read_only_dir(self):
        result = self.launch("--add-dir-ro", "~/ref", "-p", "hello")
        self.assertIn(f"--volume={self.ref}:{self.ref}:ro,z", result.flags)
        # Ahead of the user's arguments, --add-dir is variadic
        self.assertEqual(result.command, ["--add-dir", str(self.ref), "-p", "hello"])

    def test_read_write_dir_and_its_secrets(self):
        (self.ref / ".env").touch()
        flags = self.launch(f"--add-dir={self.ref}").flags
        self.assertIn(f"--volume={self.ref}:{self.ref}:z", flags)
        self.assertIn(f"--volume=/dev/null:{self.ref / '.env'}:ro", flags)

    def test_home_directory_is_refused(self):
        result = self.launch(cwd=self.home)
        self.assert_refused(result, "it would defeat the sandbox")

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
