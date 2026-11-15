#!/usr/bin/env python3
"""Checks the launcher's security-relevant behaviour without Docker.

The launcher is run as a command against a throwaway home and project, with a
fake docker first on PATH that records every call and can play a session. A
few checks call the claude_sandbox package directly instead.

  test/launcher_test.py
"""

from __future__ import annotations

import importlib
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

ROOT = Path(__file__).resolve().parent.parent
LAUNCHER = ROOT / "bin" / "claude-docker"

# Records its arguments, fails the "does it exist" queries so everything gets
# created, keeps what a build was given, and runs FAKE_SESSION (a shell
# snippet) in place of the container
FAKE_DOCKER = f"""#!{sys.executable}
import json, os, shutil, subprocess, sys
args = sys.argv[1:]
with open(os.environ["FAKE_LOG"], "a") as log:
    log.write(json.dumps(args) + "\\n")
if args[1:2] == ["inspect"]:
    sys.exit(1)
if args[0] == "build":
    for name in ("Dockerfile", "CLAUDE.md"):
        shutil.copy(os.path.join(args[-1], name), os.environ["FAKE_OUT"])
if args[0] == "run" and "--detach" not in args and "FAKE_SESSION" in os.environ:
    sys.exit(subprocess.run(os.environ["FAKE_SESSION"], shell=True).returncode)
"""


sys.path.insert(0, str(ROOT))
image, network, settings = (
    importlib.import_module(f"claude_sandbox.{name}")
    for name in ("image", "network", "settings")
)


class Result:
    def __init__(self, process: subprocess.CompletedProcess, calls: list[list[str]]):
        self.status = process.returncode
        self.stdout = process.stdout
        self.stderr = process.stderr
        self.calls = calls

    def _session(self) -> list[str]:
        sessions = [c for c in self.calls if c[0] == "run" and "--detach" not in c]
        assert len(sessions) == 1, f"expected one session, got {self.calls}"
        return sessions[0][1:]

    @property
    def flags(self) -> list[str]:
        """The docker run options of the session, up to the image."""
        session = self._session()
        return session[: self._image_index(session)]

    @property
    def image(self) -> str:
        session = self._session()
        return session[self._image_index(session)]

    @property
    def command(self) -> list[str]:
        """What follows the image: the arguments for claude."""
        session = self._session()
        return session[self._image_index(session) + 1 :]

    @staticmethod
    def _image_index(session: list[str]) -> int:
        return next(i for i, arg in enumerate(session) if not arg.startswith("-"))

    def sidecar(self, name: str) -> list[str] | None:
        """The docker run call that started a sidecar, if any."""
        for call in self.calls:
            if call[0] == "run" and f"--name={name}" in call:
                return call
        return None


class LauncherTest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        # Resolved, on macOS the temporary directory sits behind a symlink
        self.work = Path(temp.name).resolve()
        self.home = self.work / "home"
        self.project = self.home / "proj"
        for directory in (
            self.home / ".claude" / "hooks",
            self.home / ".claude" / "skills",
            self.home / ".claude" / "agents",
            self.project / ".git" / "hooks",
            self.home / "ref",
            self.work / "bin",
            self.work / "out",
        ):
            directory.mkdir(parents=True)
        (self.home / ".claude" / "settings.json").write_text("{}\n")
        (self.home / ".claude" / "CLAUDE.md").write_text("# Rules\n")
        (self.project / ".git" / "config").write_text("[core]\n\tbare = false\n")
        for name in (".env", ".env.example", ".netrc", "key.pem"):
            (self.project / name).touch()
        fake = self.work / "bin" / "docker"
        fake.write_text(FAKE_DOCKER)
        fake.chmod(0o755)

    def fake_docker_env(self) -> dict[str, str]:
        return {
            "PATH": f"{self.work / 'bin'}{os.pathsep}{os.environ['PATH']}",
            "FAKE_LOG": str(self.work / "log"),
            "FAKE_OUT": str(self.work / "out"),
        }

    def calls(self) -> list[list[str]]:
        log = self.work / "log"
        if not log.exists():
            return []
        return [json.loads(line) for line in log.read_text().splitlines()]

    def launch(
        self, *args: str, cwd: Path | None = None, session: str = "", **env: str
    ):
        """Run the launcher. Keyword arguments are its environment."""
        environment = {**self.fake_docker_env(), "HOME": str(self.home), **env}
        if session:
            environment["FAKE_SESSION"] = session
        process = subprocess.run(
            [sys.executable, str(LAUNCHER), *args],
            cwd=cwd or self.project,
            env=environment,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            check=False,
        )
        return Result(process, self.calls())

    def write_config(self, *lines: str) -> None:
        directory = self.home / ".config" / "claude-sandbox"
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "config").write_text("\n".join(lines) + "\n")

    def assert_refused(self, result: Result, message: str) -> None:
        self.assertNotEqual(result.status, 0)
        self.assertIn(message, result.stderr)
        self.assertEqual([c for c in result.calls if c[0] == "run"], [])


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


class TamperingTest(LauncherTest):
    REPORT = "changed files that can run commands on the host"

    def test_a_new_git_hook_is_reported(self):
        result = self.launch(session="echo x > .git/hooks/pre-commit")
        self.assertIn(self.REPORT, result.stderr)
        self.assertIn(f"  {self.project}/.git/hooks/pre-commit\n", result.stderr)

    def test_a_git_config_change_is_reported(self):
        result = self.launch(
            session=r'printf "[core]\n\tfsmonitor = evil\n" >> .git/config'
        )
        self.assertIn(f"  {self.project}/.git/config\n", result.stderr)

    def test_new_project_claude_settings_are_reported(self):
        result = self.launch(session='mkdir .claude; echo "{}" > .claude/settings.json')
        self.assertIn(f"  {self.project}/.claude/settings.json\n", result.stderr)

    def test_branch_tracking_is_not_reported(self):
        result = self.launch(
            session=r'printf "[branch \"main\"]\n\tremote = origin\n" >> .git/config'
        )
        self.assertNotIn(self.REPORT, result.stderr)

    def test_ordinary_edits_are_not_reported(self):
        result = self.launch(session="echo code > main.go")
        self.assertNotIn(self.REPORT, result.stderr)

    def test_the_session_status_is_passed_on(self):
        self.assertEqual(self.launch(session="exit 7").status, 7)


if __name__ == "__main__":
    unittest.main()
