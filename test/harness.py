"""What the launcher's tests share: the launcher run as a command against a
throwaway home and project, with a fake docker first on PATH that records
every call and can play a session."""

from __future__ import annotations

import importlib
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path

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
    shutil.copytree(args[-1], os.environ["FAKE_OUT"], dirs_exist_ok=True)
if args[0] == "run" and "--detach" not in args and "FAKE_SESSION" in os.environ:
    sys.exit(subprocess.run(os.environ["FAKE_SESSION"], shell=True).returncode)
"""


sys.path.insert(0, str(ROOT))
capture, image, network, settings = (
    importlib.import_module(f"claude_sandbox.{name}")
    for name in ("capture", "image", "network", "settings")
)


def prompts_at(*times: float) -> list[dict]:
    """Transcript entries for a prompt at each of the given times, enough
    for a transcript to span them."""
    return [
        {
            "type": "user",
            "timestamp": datetime.fromtimestamp(when, timezone.utc).isoformat(),  # noqa: UP017
            "message": {"content": "hello"},
        }
        for when in times
    ]


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
        # Where the launcher keeps its own records
        self.state = self.home / ".local" / "state" / "claude-sandbox"
        # Where Claude Code keeps the transcripts of the project
        name = re.sub(r"[^A-Za-z0-9]", "-", str(self.project))
        self.transcripts = self.home / ".claude" / "projects" / name
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

    def write_transcript(self, session: str, entries: list[dict]) -> Path:
        """Leave a transcript the way Claude Code does, a line per entry."""
        self.transcripts.mkdir(parents=True, exist_ok=True)
        file = self.transcripts / f"{session}.jsonl"
        file.write_text("\n".join(map(json.dumps, entries)) + "\n")
        return file

    def write_config(self, *lines: str) -> None:
        directory = self.home / ".config" / "claude-sandbox"
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "config").write_text("\n".join(lines) + "\n")

    def assert_refused(self, result: Result, message: str) -> None:
        self.assertNotEqual(result.status, 0)
        self.assertIn(message, result.stderr)
        self.assertEqual([c for c in result.calls if c[0] == "run"], [])
