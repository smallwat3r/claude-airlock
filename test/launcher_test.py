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
import struct
import subprocess
import sys
import tempfile
import time
import unittest
from datetime import datetime, timezone
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
if args[1:2] == ["inspect"] and "IPAddress" in args[2] and "FAKE_IP" in os.environ:
    print(os.environ["FAKE_IP"])
    sys.exit(0)
if args[1:2] == ["inspect"] and "claude-sandbox.capture" in args[2]:
    print(os.environ.get("FAKE_LABEL", ""))
    sys.exit(0)
if args[1:2] == ["inspect"] and "Running" in args[2] and args[3].endswith(".capture"):
    print("true")
    sys.exit(0)
if args[1:2] == ["inspect"]:
    sys.exit(1)
if args[0] == "ps":
    print(os.environ.get("FAKE_PS", ""))
if args[0] == "cp" and "FAKE_CAPTURE" in os.environ:
    shutil.copy(os.environ["FAKE_CAPTURE"], args[-1])
if args[0] == "exec" and "cat " in args[-1] and "FAKE_ACCESS_LOG" in os.environ:
    with open(os.environ["FAKE_ACCESS_LOG"]) as access_log:
        sys.stdout.write(access_log.read())
if args[0] == "build":
    for name in ("Dockerfile", "CLAUDE.md"):
        shutil.copy(os.path.join(args[-1], name), os.environ["FAKE_OUT"])
if args[0] == "run" and "--detach" not in args and "FAKE_SESSION" in os.environ:
    sys.exit(subprocess.run(os.environ["FAKE_SESSION"], shell=True).returncode)
"""


sys.path.insert(0, str(ROOT))
capture, image, network, settings = (
    importlib.import_module(f"claude_sandbox.{name}")
    for name in ("capture", "image", "network", "settings")
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
        """Run the launcher. Keyword arguments are its environment. Without
        the network capture unless asked for, which is on by default and
        would give every session here a sidecar."""
        environment = {
            **self.fake_docker_env(),
            "HOME": str(self.home),
            "CLAUDE_DOCKER_NET_LOG": "0",
            **env,
        }
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


class UncheckedSessionTest(LauncherTest):
    LATE = "ended without its check"
    # The fake docker is the shell's parent and the launcher its parent,
    # killed the way a closed terminal ends it: before it can compare
    KILL_LAUNCHER = "kill -KILL $(ps -o ppid= -p $PPID)"

    def pending(self) -> list[Path]:
        state = self.home / ".local" / "state" / "claude-sandbox"
        return list(state.glob("pending-checks/*.json"))

    def test_a_killed_session_is_checked_by_the_next_launch(self):
        killed = self.launch(
            session=f"echo x > .git/hooks/pre-commit; {self.KILL_LAUNCHER}"
        )
        self.assertNotIn("pre-commit", killed.stderr)
        self.assertEqual(len(self.pending()), 1)

        following = self.launch()
        self.assertIn(self.LATE, following.stderr)
        self.assertIn(f"  {self.project}/.git/hooks/pre-commit\n", following.stderr)
        self.assertEqual(self.pending(), [])
        self.assertNotIn(self.LATE, self.launch().stderr)

    def test_a_killed_session_that_changed_nothing_is_not_reported(self):
        self.launch(session=self.KILL_LAUNCHER)
        self.assertNotIn(self.LATE, self.launch().stderr)
        self.assertEqual(self.pending(), [])

    def test_a_checked_session_leaves_nothing_pending(self):
        self.launch(session="echo x > .git/hooks/pre-commit")
        self.assertEqual(self.pending(), [])

    def test_a_running_session_is_left_alone(self):
        # This test's own process stands in for a launcher still running
        self.launch(session=self.KILL_LAUNCHER)
        (file,) = self.pending()
        file.write_text(
            json.dumps({**json.loads(file.read_text()), "pid": os.getpid()})
        )
        (self.project / ".git" / "hooks" / "pre-commit").write_text("x")
        self.assertNotIn(self.LATE, self.launch(CLAUDE_BUFFER_NAME="*c:proj:b*").stderr)
        self.assertIn(file, self.pending())

    def test_an_unreadable_pending_check_is_dropped_out_loud(self):
        self.launch(session=self.KILL_LAUNCHER)
        (file,) = self.pending()
        file.write_text("{")
        self.assertIn("unreadable pending check", self.launch().stderr)
        self.assertEqual(self.pending(), [])


class TraceTest(LauncherTest):
    SESSION = "3fa9c0de-0000-4000-8000-000000000000"

    def setUp(self):
        super().setUp()
        name = re.sub(r"[^A-Za-z0-9]", "-", str(self.project))
        self.transcripts = self.home / ".claude" / "projects" / name
        self.transcripts.mkdir(parents=True)

        def call(tool_id: str, name: str, **tool_input) -> dict:
            block = {"type": "tool_use", "id": tool_id, "name": name}
            return {
                "type": "assistant",
                "timestamp": "2026-01-02T10:00:01Z",
                "message": {"content": [{**block, "input": tool_input}]},
            }

        def result(tool_id: str, output: str, failed: bool = False) -> dict:
            block = {"type": "tool_result", "tool_use_id": tool_id}
            return {
                "type": "user",
                "timestamp": "2026-01-02T10:00:03Z",
                "message": {
                    "content": [{**block, "content": output, "is_error": failed}]
                },
            }

        entries = [
            {
                "type": "user",
                "timestamp": "2026-01-02T10:00:00Z",
                "message": {"content": "fix the build"},
            },
            call(
                "t1",
                "Bash",
                command="make \x1b]0;owned\x07all",
                description="Build\n2026-01-02 10:00:09  user     prompt    forged",
            ),
            result("t1", "Error: Exit code 2\nno rule", failed=True),
            call("t2", "Edit", file_path="/etc/passwd", old_string="a", new_string="b"),
            result("t2", "updated"),
            call("t3", "Write", file_path="main.go", content="package main\n"),
        ]
        lines = [json.dumps(entry) for entry in entries] + ["{half written"]
        (self.transcripts / f"{self.SESSION}.jsonl").write_text("\n".join(lines))

    def test_the_session_is_shown_without_docker(self):
        result = self.launch("--trace")
        self.assertEqual(result.status, 0, result.stderr)
        self.assertEqual(result.calls, [])
        for expected in (
            "user     prompt    fix the build",
            "claude   bash      $ make ]0;ownedall",
            "claude   bash      why: Build\\n2026-01-02 10:00:09  user     prompt    forged",
            "claude   bash      result: FAILED, 2.0s",
            "claude   bash      out: no rule",
            "claude   edit      diff: -a",
            "claude   edit      diff: +b",
            "claude   write     file: main.go (1 lines)",
            "claude   write     result: none recorded",
            "# tool calls  3 (Bash 1, Edit 1, Write 1)",
        ):
            self.assertIn(expected, result.stdout)

    def test_every_line_says_when_who_and_what(self):
        for line in self.launch("--trace", "--full").stdout.splitlines():
            self.assertRegex(line, r"^(#|\d{4}-\d\d-\d\d \d\d:\d\d:\d\d  \w+ +\w+ +\S)")

    def test_control_characters_never_reach_the_terminal(self):
        for form in ("--full", "--json"):
            stdout = self.launch("--trace", form).stdout
            self.assertNotRegex(stdout, r"[\x00-\x08\x0b-\x1f\x7f]")

    def test_json_gives_an_object_per_event_with_its_values(self):
        result = self.launch("--trace", "--json")
        self.assertEqual(result.status, 0, result.stderr)
        prompt, bash, edit, write = map(json.loads, result.stdout.splitlines())
        for event in (prompt, bash, edit, write):
            self.assertEqual(event["session"], self.SESSION)
            self.assertRegex(
                event["time"], r"^2026-01-02T\d\d:00:0\d\.000[+-]\d\d:\d\d$"
            )
        self.assertEqual((prompt["who"], prompt["what"]), ("user", "prompt"))
        self.assertEqual(prompt["text"], "fix the build")
        self.assertEqual(bash["input"]["command"], "make \x1b]0;owned\x07all")
        self.assertEqual((bash["failed"], bash["seconds"]), (True, 2.0))
        self.assertIn("no rule", bash["output"])
        self.assertTrue(edit["outside_project"])
        self.assertFalse(write["outside_project"])
        self.assertNotIn("failed", write)

    def test_only_writes_outside_the_project_are_flagged(self):
        stdout = self.launch("--trace").stdout
        self.assertIn("/etc/passwd x1  OUTSIDE PROJECT", stdout)
        self.assertIn("file: /etc/passwd  OUTSIDE PROJECT", stdout)
        self.assertNotIn("main.go x1  OUTSIDE", stdout)

    def test_output_of_a_successful_call_needs_full(self):
        self.assertNotIn("updated", self.launch("--trace").stdout)
        self.assertIn("updated", self.launch("--trace", "--full").stdout)

    def test_sessions_are_listed_and_picked_by_id_prefix(self):
        listed = self.launch("--trace", "list").stdout
        self.assertIn("3fa9c0de    1 prompts     3 calls  fix the build", listed)
        self.assertEqual(self.launch("--trace", "3fa9").status, 0)
        missing = self.launch("--trace", "../../etc")
        self.assertNotEqual(missing.status, 0)
        self.assertIn("matches no session", missing.stderr)

    def test_a_link_planted_among_the_transcripts_is_not_read(self):
        secret = self.work / "secret.jsonl"
        secret.write_text(json.dumps({"type": "ai-title", "aiTitle": "TOP SECRET"}))
        (self.transcripts / "ffff.jsonl").symlink_to(secret)
        self.assertNotIn("TOP SECRET", self.launch("--trace", "list").stdout)
        self.assertNotEqual(self.launch("--trace", "ffff").status, 0)

    def test_a_date_out_of_range_does_not_stop_the_trace(self):
        file = self.transcripts / f"{self.SESSION}.jsonl"
        odd = {"type": "user", "timestamp": "0001-01-01T00:00:00+14:00"}
        file.write_text(
            json.dumps({**odd, "message": {"content": "early"}})
            + "\n"
            + file.read_text()
        )
        result = self.launch("--trace")
        self.assertEqual(result.status, 0, result.stderr)
        self.assertIn("prompt    early", result.stdout)

    def test_a_project_without_sessions_is_an_error(self):
        result = self.launch("--trace", cwd=self.home / "ref")
        self.assertNotEqual(result.status, 0)
        self.assertIn("no session recorded", result.stderr)


class NetworkTraceTest(LauncherTest):
    """A filtered session, then its trace against a proxy log that another
    session also wrote to."""

    def setUp(self):
        super().setUp()
        self.filtered = self.launch(CLAUDE_DOCKER_NET_FILTER="1", FAKE_IP="172.20.0.5")
        now = time.time()
        stamps = [
            datetime.fromtimestamp(now + offset, timezone.utc).isoformat()  # noqa: UP017
            for offset in (0, 10)
        ]
        entries = [
            {"type": "user", "timestamp": stamp, "message": {"content": "hello"}}
            for stamp in stamps
        ]
        name = re.sub(r"[^A-Za-z0-9]", "-", str(self.project))
        transcripts = self.home / ".claude" / "projects" / name
        transcripts.mkdir(parents=True)
        (transcripts / "0a.jsonl").write_text("\n".join(map(json.dumps, entries)))
        mine, other = "172.20.0.5", "172.20.0.9"
        log = [
            f"{now + 5:.3f} 200 {mine} TCP_TUNNEL/200 4000 CONNECT good.test:443 - -",
            f"{now + 6:.3f} 100 {mine} TCP_TUNNEL/200 1000 CONNECT good.test:443 - -",
            f"{now + 7:.3f} 0 {mine} TCP_DENIED/403 300 CONNECT evil.test:443 - -",
            f"{now + 8:.3f} 0 {mine} TCP_DENIED/403 9 CONNECT \x1b[31mesc.test:443 - -",
            f"{now + 5:.3f} 0 {other} TCP_TUNNEL/200 50 CONNECT theirs.test:443 - -",
            # Opened during the session, closed and so logged after it
            f"{now + 60:.3f} 55000 {mine} TCP_TUNNEL/200 70 CONNECT long.test:443 - -",
            f"{now + 60:.3f} 100 {mine} TCP_TUNNEL/200 50 CONNECT after.test:443 - -",
            "not a log line",
        ]
        self.access_log = self.work / "access.log"
        self.access_log.write_text("\n".join(log) + "\n")

    def trace(self, *args: str) -> str:
        result = self.launch("--trace", *args, FAKE_ACCESS_LOG=str(self.access_log))
        self.assertEqual(result.status, 0, result.stderr)
        return result.stdout

    def test_the_session_address_is_recorded(self):
        state = self.home / ".local" / "state" / "claude-sandbox"
        (session,) = map(
            json.loads, (state / "net-sessions.jsonl").read_text().splitlines()
        )
        self.assertEqual(session["ip"], "172.20.0.5")
        self.assertEqual(session["project"], str(self.project))

    def test_the_proxy_log_is_kept_in_a_volume_and_capped(self):
        proxy = self.filtered.sidecar("claude-egress-proxy")
        self.assertIn("--volume=claude-egress-log:/var/log/squid", proxy)
        rotations = [c for c in self.filtered.calls if "squid -k rotate" in c[-1]]
        self.assertEqual(len(rotations), 1)
        self.assertIn("-gt 10485760", rotations[0][-1])

    def test_an_open_session_records_no_address(self):
        self.launch(FAKE_IP="172.20.0.6")
        state = self.home / ".local" / "state" / "claude-sandbox"
        self.assertNotIn("172.20.0.6", (state / "net-sessions.jsonl").read_text())

    def test_requests_are_summed_by_destination_refused_first(self):
        stdout = self.trace()
        denied = stdout.index("DENIED   evil.test:443 x1  300 B")
        allowed = stdout.index("allowed  good.test:443 x2  5 kB")
        self.assertLess(denied, allowed)
        self.assertIn("allowed  long.test:443 x1", stdout)

    def test_other_sessions_and_later_requests_are_left_out(self):
        stdout = self.trace()
        self.assertNotIn("theirs.test", stdout)
        self.assertNotIn("after.test", stdout)

    def test_logged_urls_cannot_drive_the_terminal(self):
        self.assertIn("[31mesc.test:443", self.trace())
        self.assertNotIn("\x1b", self.trace("--full"))

    def test_every_request_is_an_event_at_the_time_it_began(self):
        stdout = self.trace()
        request = "sandbox  net       proxy/https CONNECT good.test:443 allowed"
        self.assertEqual(stdout.count(request), 2)
        self.assertIn(f"{request} 4 kB 0.2s", stdout)
        self.assertIn("proxy/https CONNECT evil.test:443 DENIED 300 B", stdout)
        # Between the two prompts, 10 seconds apart
        first, second = (m.start() for m in re.finditer("user     prompt", stdout))
        self.assertTrue(first < stdout.index(request) < second)

    def test_a_session_without_the_filter_says_so(self):
        os.remove(
            self.home / ".local" / "state" / "claude-sandbox" / "net-sessions.jsonl"
        )
        self.assertIn("# network     not recorded", self.trace())


def ipv4(protocol: int, source: str, destination: str, payload: bytes) -> bytes:
    addresses = socket.inet_aton(source) + socket.inet_aton(destination)
    length = 20 + len(payload)
    return struct.pack("!BBHHHBBH", 0x45, 0, length, 0, 0, 64, protocol, 0) + (
        addresses + payload
    )


def tcp(destination: str, port: int, flags: int = 0x02, payload: bytes = b"") -> bytes:
    header = struct.pack("!HHIIBBHHH", 40000 + port, port, 0, 0, 0x50, flags, 0, 0, 0)
    return ipv4(6, "172.20.0.5", destination, header + payload)


def dns_response(name: str, address: str) -> bytes:
    labels = b"".join(bytes([len(part)]) + part.encode() for part in name.split("."))
    question = labels + b"\x00" + struct.pack("!HH", 1, 1)
    # The answer names the question by pointer, as resolvers do
    answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton(address)
    message = struct.pack("!HHHHHH", 7, 0x8180, 1, 1, 0, 0) + question + answer
    # From Docker's resolver, whose port is rewritten inside the namespace
    datagram = struct.pack("!HHHH", 41234, 50000, 8 + len(message), 0) + message
    return ipv4(17, "127.0.0.11", "127.0.0.1", datagram)


def client_hello(name: str) -> bytes:
    host = name.encode()
    server_name = struct.pack("!HBH", len(host) + 3, 0, len(host)) + host
    extensions = struct.pack("!HH", 0x000A, 2) + b"\x00\x1d"
    extensions += struct.pack("!HH", 0, len(server_name)) + server_name
    body = b"\x03\x03" + bytes(32) + b"\x00" + b"\x00\x02\x13\x01" + b"\x01\x00"
    body += struct.pack("!H", len(extensions)) + extensions
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


def pcap(packets: list[tuple[float, bytes, bool]], link_type: int = 276) -> bytes:
    """A capture file as tcpdump writes it for its "any" device: packets
    given as when, the IPv4 packet and whether the session sent it."""
    data = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 262144, link_type)
    for when, packet, sent in packets:
        kind = 4 if sent else 0
        if link_type == 276:
            frame = struct.pack("!HHIHBB8s", 0x0800, 0, 2, 1, kind, 6, b"") + packet
        else:
            frame = struct.pack("!HHH8sH", kind, 1, 6, b"", 0x0800) + packet
        seconds, micros = int(when), int(when % 1 * 1e6)
        data += struct.pack("<IIII", seconds, micros, len(frame), len(frame)) + frame
    return data


def sample_capture(now: float, link_type: int = 276) -> bytes:
    return pcap(
        [
            (now + 1, dns_response("good.test", "198.51.100.7"), False),
            (now + 2, tcp("198.51.100.7", 443), True),
            # The same attempt sent again, and the reply to it
            (now + 3, tcp("198.51.100.7", 443), True),
            (now + 3, tcp("198.51.100.7", 443, flags=0x12), False),
            (now + 4, tcp("10.0.0.7", 5432), True),
            (now + 5, tcp("203.0.113.9", 8443), True),
            (now + 5, tcp("203.0.113.9", 8443, 0x18, client_hello("sni.test")), True),
            # Within the session, and someone else connecting to it
            (now + 6, tcp("127.0.0.1", 8000), True),
            (now + 6, tcp("172.20.0.5", 9000), False),
            (now + 7, b"\x45garbage", True),
        ],
        link_type,
    )


class CaptureFileTest(unittest.TestCase):
    def read(self, data: bytes):
        with tempfile.TemporaryDirectory() as directory:
            file = Path(directory, "capture.pcap")
            file.write_bytes(data)
            return capture.read_capture(file)

    def test_connections_names_and_lookups_are_read(self):
        for link_type in (276, 113):
            found = self.read(sample_capture(1000.0, link_type))
            self.assertEqual(
                found.connections,
                [
                    (1002.0, "198.51.100.7", 443),
                    (1004.0, "10.0.0.7", 5432),
                    (1005.0, "203.0.113.9", 8443),
                ],
            )
            self.assertEqual(
                found.names, {"198.51.100.7": "good.test", "203.0.113.9": "sni.test"}
            )
            self.assertEqual(found.lookups, [(1001.0, "good.test")])
            self.assertEqual(found.packets, 10)

    def test_an_answer_the_session_sent_out_names_nothing(self):
        forged = ipv4(
            17, "172.20.0.5", "192.0.2.1", dns_response("bank.test", "6.6.6.6")[20:]
        )
        found = self.read(pcap([(1.0, forged, True), (2.0, tcp("6.6.6.6", 443), True)]))
        self.assertEqual(found.names, {})
        self.assertEqual(found.connections, [(2.0, "6.6.6.6", 443)])

    def test_a_damaged_file_is_read_as_far_as_it_goes(self):
        whole = sample_capture(1000.0)
        self.assertEqual(len(self.read(whole[:-30]).connections), 3)
        self.assertEqual(self.read(b"not a capture at all, really").packets, 0)

    def test_a_dns_name_that_points_at_itself_ends(self):
        loop = struct.pack("!HHHHHH", 7, 0x8180, 1, 0, 0, 0) + b"\xc0\x0c"
        with self.assertRaises(capture.NotThis):
            capture.dns_answer(loop)


class CaptureSessionTest(LauncherTest):
    SIDECAR = "claude-proj.capture"

    def setUp(self):
        super().setUp()
        self.now = time.time()
        self.capture_file = self.work / "capture.pcap"
        self.capture_file.write_bytes(sample_capture(self.now))
        self.state = self.home / ".local" / "state" / "claude-sandbox"

    def captured(self, *args: str, **env: str) -> Result:
        return self.launch(
            *args, CLAUDE_DOCKER_NET_LOG="1", FAKE_CAPTURE=str(self.capture_file), **env
        )

    def test_the_session_joins_a_sidecar_that_captures(self):
        result = self.captured()
        self.assertIn(f"--network=container:{self.SIDECAR}", result.flags)
        sidecar = result.sidecar(self.SIDECAR)
        for flag in (
            "--network=claude-docker-open-net",
            "--cap-drop=ALL",
            "--cap-add=NET_RAW",
            "--entrypoint=tcpdump",
        ):
            self.assertIn(flag, sidecar)
        self.assertLess(
            result.calls.index(sidecar),
            next(
                i for i, c in enumerate(result.calls) if c[0] == "run" and c != sidecar
            ),
        )

    def test_a_filtered_session_is_captured_inside_the_filter(self):
        result = self.captured(CLAUDE_DOCKER_NET_FILTER="1", FAKE_IP="172.20.0.5")
        sidecar = result.sidecar(self.SIDECAR)
        self.assertIn("--network=claude-docker-net", sidecar)
        self.assertIn("--dns=127.0.0.1", sidecar)
        self.assertIn(f"--network=container:{self.SIDECAR}", result.flags)
        self.assertNotIn("--dns=127.0.0.1", result.flags)
        self.assertIn("--env=HTTPS_PROXY=http://claude-egress-proxy:3128", result.flags)
        sessions = (self.state / "net-sessions.jsonl").read_text()
        self.assertIn('"ip": "172.20.0.5"', sessions)

    def test_capturing_is_the_default(self):
        self.assertTrue(settings.load_settings({}, str(self.work / "none")).net_log)

    def test_switched_off_nothing_is_captured(self):
        result = self.launch()
        self.assertIsNone(result.sidecar(self.SIDECAR))
        self.assertIn("--network=claude-docker-open-net", result.flags)

    def test_the_capture_is_copied_out_and_the_sidecar_removed(self):
        result = self.captured()
        (copied,) = (self.state / "captures").glob("*.pcap")
        self.assertEqual(copied.read_bytes(), self.capture_file.read_bytes())
        (session,) = map(
            json.loads, (self.state / "net-sessions.jsonl").read_text().splitlines()
        )
        self.assertEqual(session["capture"], copied.name)
        self.assertEqual(session["project"], str(self.project))
        ending = [c[0] for c in result.calls if self.SIDECAR in c[-1] or c[0] == "cp"]
        self.assertEqual(ending[-3:], ["stop", "cp", "rm"])

    def test_what_is_kept_is_for_the_user_alone(self):
        self.captured()
        for directory in (self.state, self.state / "captures"):
            self.assertEqual(directory.stat().st_mode & 0o777, 0o700)

    def test_a_capture_left_by_a_killed_session_is_collected(self):
        about = {"project": "/elsewhere", "start": 5, "pid": 2**22 - 7}
        result = self.launch(
            FAKE_PS="claude-old.capture",
            FAKE_LABEL=json.dumps(about),
            FAKE_CAPTURE=str(self.capture_file),
        )
        self.assertIn(["rm", "--force", "claude-old.capture"], result.calls)
        self.assertTrue(
            (self.state / "captures" / "claude-old.capture-5.pcap").exists()
        )

    def test_the_capture_of_a_running_session_is_left_alone(self):
        about = {"project": "/elsewhere", "start": 5, "pid": os.getpid()}
        result = self.launch(FAKE_PS="claude-old.capture", FAKE_LABEL=json.dumps(about))
        self.assertEqual([c for c in result.calls if c[0] in ("stop", "cp", "rm")], [])

    def trace(self, *args: str) -> str:
        self.captured()
        stamps = [
            datetime.fromtimestamp(self.now + offset, timezone.utc).isoformat()  # noqa: UP017
            for offset in (0, 10)
        ]
        entries = [
            {"type": "user", "timestamp": stamp, "message": {"content": "hello"}}
            for stamp in stamps
        ]
        name = re.sub(r"[^A-Za-z0-9]", "-", str(self.project))
        transcripts = self.home / ".claude" / "projects" / name
        transcripts.mkdir(parents=True, exist_ok=True)
        (transcripts / "0a.jsonl").write_text("\n".join(map(json.dumps, entries)))
        result = self.launch("--trace", *args)
        self.assertEqual(result.status, 0, result.stderr)
        return result.stdout

    def test_the_trace_lists_what_was_reached(self):
        stdout = self.trace()
        for expected in (
            "#   captured in claude-proj from ",
            "#   tcp/https good.test (198.51.100.7):443 x1",
            "#   tcp/postgres 10.0.0.7:5432 x1",
            "#   tcp sni.test (203.0.113.9):8443 x1",
            "#   dns 1 names looked up",
            "sandbox  net       tcp/postgres 10.0.0.7:5432",
        ):
            self.assertIn(expected, stdout)
        self.assertNotIn(":8000", stdout)
        self.assertNotIn(":9000", stdout)
        self.assertNotIn("lookup", stdout)

    def test_full_adds_the_lookups(self):
        self.assertIn("sandbox  dns       lookup good.test", self.trace("--full"))

    def test_json_has_connections_and_lookups(self):
        events = [json.loads(line) for line in self.trace("--json").splitlines()]
        reached = [e for e in events if e["what"] == "net"]
        self.assertEqual(
            [(e["protocol"], e["name"], e["address"], e["port"]) for e in reached],
            [
                ("tcp/https", "good.test", "198.51.100.7", 443),
                ("tcp/postgres", None, "10.0.0.7", 5432),
                ("tcp", "sni.test", "203.0.113.9", 8443),
            ],
        )
        (lookup,) = (e for e in events if e["what"] == "dns")
        self.assertEqual((lookup["who"], lookup["name"]), ("sandbox", "good.test"))


if __name__ == "__main__":
    unittest.main()
