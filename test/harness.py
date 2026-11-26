"""What the launcher's tests share: the launcher run as a command against a
throwaway home and project, with a fake docker first on PATH that records
every call and can play a session."""

from __future__ import annotations

import atexit
import contextlib
import importlib
import json
import os
import pty
import re
import select
import shutil
import signal
import subprocess
import sys
import tempfile
import time
from datetime import UTC, datetime
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
LAUNCHER = ROOT / "bin" / "claude-airlock"
# Where the launchers the checks start keep what Python compiles of the
# package, one place for all those of a worker: a launcher keeps it in the
# home it is given (see compile_apart of bin/claude-airlock), and every
# check has a home of its own, where all of it would be compiled again
COMPILED = tempfile.mkdtemp(prefix="claude-airlock-compiled-")
atexit.register(shutil.rmtree, COMPILED, ignore_errors=True)

# Records its arguments, fails the "does it exist" queries so everything gets
# created (but says the containers named in FAKE_RUNNING are up, and of every
# network what FAKE_NETWORK says: whether it is internal, then who is on it), keeps what
# a build was given, says it is the docker of FAKE_VERSION, answers docker info
# with FAKE_INFO, and runs FAKE_SESSION (a shell snippet) in place of the container
FAKE_DOCKER = f"""#!{sys.executable}
import json, os, shutil, subprocess, sys
args = sys.argv[1:]
# The parts of a capture that are not the main one have a file of their
# own, given by these, or none
OTHER_PARTS = {{
    "/dns.pcap": "FAKE_CAPTURE_DNS",
    "/direct.pcap": "FAKE_CAPTURE_DIRECT",
    "/flows.pcap": "FAKE_CAPTURE_FLOWS",
    "/uploads.pcap": "FAKE_CAPTURE_UPLOADS",
    "/elsewhere.pcap": "FAKE_CAPTURE_ELSEWHERE",
    "/answers.pcap": "FAKE_CAPTURE_ANSWERS",
    "/downloads.pcap": "FAKE_CAPTURE_DOWNLOADS",
}}
with open(os.environ["FAKE_LOG"], "a") as log:
    log.write(json.dumps(args) + "\\n")
if args[:2] == ["network", "inspect"] and "FAKE_NETWORK" in os.environ:
    print(os.environ["FAKE_NETWORK"])
    sys.exit(0)
if args[1:2] == ["inspect"] and "IPAddress" in args[2] and "FAKE_IP" in os.environ:
    print(os.environ["FAKE_IP"])
    sys.exit(0)
up = os.environ.get("FAKE_RUNNING", "").split()
if args[1:2] == ["inspect"] and "Running" in args[2]:
    if args[3].endswith(".capture") or args[3] in up:
        print("true")
        sys.exit(0)
# A container that is still there once it was removed
left = os.environ.get("FAKE_LEFT", "")
with open(os.environ["FAKE_LOG"]) as log:
    left = left if ["rm", "--force", left] in map(json.loads, log) else ""
if args[:2] == ["container", "inspect"] and args[2:] == [left]:
    sys.exit(0)
if args[1:2] == ["inspect"]:
    sys.exit(1)
if args[:2] == ["ps", "--all"] and args[2].startswith("--filter=name="):
    # Whether a container is still there, FAKE_DOWN is a daemon that
    # does not say
    if "FAKE_DOWN" in os.environ:
        sys.exit(1)
    print(left)
    sys.exit(0)
if args[0] == "ps":
    print(os.environ.get("FAKE_PS", ""))
if args[0] == "images":
    print(os.environ.get("FAKE_IMAGES", ""))
if args[0] == "rmi" and args[1] in os.environ.get("FAKE_RUNNING_IMAGES", ""):
    sys.exit(1)
if args[0] == "events":
    print(os.environ.get("FAKE_EVENTS", ""))
if args[0] == "info":
    print(os.environ.get("FAKE_INFO", ""))
if args[0] == "version":
    print(os.environ.get("FAKE_VERSION", ""))
if args[0] == "cp" and ".procs:" in args[1]:
    if "FAKE_PROCESSES" not in os.environ:
        sys.exit(1)
    shutil.copy(os.environ["FAKE_PROCESSES"], args[-1])
elif args[0] == "cp" and args[1].endswith(".status"):
    part, _, code = os.environ.get("FAKE_CAPTURE_DIED", "").partition(":")
    if not code or "/" + part + ".pcap.status" not in args[1]:
        sys.exit(1)
    open(args[-1], "w").write(code + "\\n")
elif args[0] == "cp" and "FAKE_CAPTURE" in os.environ:
    where = [env for path, env in OTHER_PARTS.items() if args[1].endswith(path)]
    source = os.environ.get(where[0]) if where else os.environ["FAKE_CAPTURE"]
    if source is None:
        sys.exit(1)
    shutil.copy(source, args[-1])
if args[0] == "logs" and "FAKE_PROXY_LOG" in os.environ:
    with open(os.environ["FAKE_PROXY_LOG"]) as proxy_log:
        sys.stdout.write(proxy_log.read())
if args[0] == "exec" and "cat " in args[-1] and "FAKE_ACCESS_LOG" in os.environ:
    with open(os.environ["FAKE_ACCESS_LOG"]) as access_log:
        sys.stdout.write(access_log.read())
reading = args[0] == "exec" and args[2:4] == ["sh", "-c"] and "for wanted" in args[4]
if reading and "FAKE_CAPTURE" not in os.environ:
    sys.exit(1)
if reading:
    # Each part from where it was read to, as the sidecar's script gives
    # them: how many bytes, then those bytes. After the most it is to
    # give in all, which no check comes near
    for wanted in args[7:]:
        file, _, start = wanted.rpartition(":")
        source = os.environ.get(OTHER_PARTS.get(file, "FAKE_CAPTURE"))
        held = b""
        if source is not None:
            with open(source, "rb") as captured:
                held = captured.read()[int(start) :]
        sys.stdout.buffer.write(str(len(held)).encode() + b"\\n" + held)
        sys.stdout.buffer.flush()
if args[0] == "exec" and "grep -Hs" in " ".join(args[2:5]):
    part, _, code = os.environ.get("FAKE_CAPTURE_DIED", "").partition(":")
    if code:
        print("/" + part + ".pcap.status:" + code)
if args[0] == "exec" and "wc -c" in args[4] and "FAKE_ACCESS_LOG" in os.environ:
    with open(os.environ["FAKE_ACCESS_LOG"], "rb") as access_log:
        logged = access_log.read()
    start = int(args[7]) if len(args) > 7 else len(logged)
    start = 0 if len(logged) < start else start
    sys.stdout.buffer.write(str(start).encode() + b"\\n" + logged[start:])
if args[0] == "build":
    shutil.copytree(args[-1], os.environ["FAKE_OUT"], dirs_exist_ok=True)
if args[0] == "run" and "--detach" not in args and "FAKE_SESSION" in os.environ:
    sys.exit(subprocess.run(os.environ["FAKE_SESSION"], shell=True).returncode)
"""


sys.path.insert(0, str(ROOT))
MODULES = (
    "recording.capture",
    "report.follow",
    "sandbox.image",
    "launcher",
    "sandbox.network",
    "recording.pcap",
    "recording.records",
)
capture, follow, image, launcher, network, pcap, records, settings, transcript = (
    importlib.import_module(f"claude_airlock.{name}")
    for name in (*MODULES, "settings", "report.transcript")
)


def prompts_at(*times: float) -> list[dict]:
    """Transcript entries for a prompt at each of the given times, enough
    for a transcript to span them."""
    return [
        {
            "type": "user",
            "timestamp": datetime.fromtimestamp(when, UTC).isoformat(),
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


# What only Linux has, and what Docker Desktop on macOS does not do
reads_proc = pytest.mark.skipif(sys.platform != "linux", reason="reads /proc")
mounts_host_sockets = pytest.mark.skipif(
    sys.platform == "darwin", reason="no socket of the host mounts there"
)


class Terminal:
    """A command run at a terminal of its own, typed to and read from
    until it is closed, as contextlib.closing does. All it reads has to
    come within the patience."""

    def __init__(
        self,
        command: list[str],
        environment: dict[str, str],
        patience: float,
        cwd: Path | None = None,
    ):
        self.seen = b""
        self._deadline = time.monotonic() + patience
        self._child, self._terminal = pty.fork()
        if self._child == 0:
            if cwd:
                os.chdir(cwd)
            os.execve(command[0], command, environment)

    def close(self) -> None:
        """End the command and give up its terminal."""
        with contextlib.suppress(OSError):
            os.kill(self._child, signal.SIGKILL)
        # Closed before the wait: on macOS a process does not end while
        # what it wrote to its terminal is yet to be read
        os.close(self._terminal)
        os.waitpid(self._child, 0)

    @property
    def text(self) -> str:
        """What was written in all, its line breaks as in a file."""
        return self.seen.decode(errors="replace").replace("\r\n", "\n")

    def type(self, text: str) -> None:
        os.write(self._terminal, text.encode())

    def read_until(self, wanted: str | tuple[str, ...], start: int = 0) -> int:
        """Read until something is written after a place, the first of
        several when it can be one or the other. The place after it, or
        what AssertionError says was written instead."""
        either = (wanted,) if isinstance(wanted, str) else wanted
        while True:
            found = [
                (at, at + len(one))
                for one in either
                if (at := self.seen.find(one.encode(), start)) >= 0
            ]
            if found:
                return min(found)[1]
            if not self._read():
                raise AssertionError(f"never wrote {wanted!r}: {self.seen!r}")

    def read_to_the_end(self) -> None:
        """Read until the command leaves its terminal."""
        while self._read():
            pass

    def _read(self) -> bool:
        """Read what is there within a moment. Not when the command has
        left or the patience is over."""
        if time.monotonic() > self._deadline:
            return False
        if select.select([self._terminal], [], [], 0.2)[0]:
            # A terminal its command has left fails the read on Linux
            # and reads as empty on macOS
            try:
                chunk = os.read(self._terminal, 65536)
            except OSError:
                return False
            if not chunk:
                return False
            self.seen += chunk
        return True


class LauncherTest:
    """A check that runs the launcher, in a home and a project of its own."""

    @pytest.fixture(autouse=True)
    def sandbox(
        self, monkeypatch: pytest.MonkeyPatch, cleanup: contextlib.ExitStack
    ) -> None:
        # For what a check undoes when it is over, see conftest.py
        self.cleanup = cleanup
        # Not pytest's tmp_path: that is named after the check, and the
        # words of a name are found in what the launcher says of a path,
        # and it is too long for the path of a socket. Resolved, on macOS
        # the temporary directory sits behind a symlink.
        temp = cleanup.enter_context(tempfile.TemporaryDirectory())
        self.work = Path(temp).resolve()
        self.home = self.work / "home"
        self.project = self.home / "proj"
        # Where the launcher keeps its own records
        self.state = self.home / ".local" / "state" / "claude-airlock"
        # The same as the launcher finds it, for the checks that call the
        # package directly
        self.host = settings.Host(
            str(self.home),
            str(self.project),
            str(self.home / ".config"),
            str(self.home / ".local" / "state"),
        )
        # The ~/.claude of the sandboxed sessions
        self.base = self.state / "home"
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
        # The checks that call the package directly reach the fake too, never
        # the docker of the machine the tests run on
        self._path = os.environ["PATH"]
        for name, value in self.fake_docker_env().items():
            monkeypatch.setenv(name, value)

    def fake_docker_env(self) -> dict[str, str]:
        return {
            "PATH": f"{self.work / 'bin'}{os.pathsep}{self._path}",
            "FAKE_LOG": str(self.work / "log"),
            "FAKE_OUT": str(self.work / "out"),
            "PYTHONPYCACHEPREFIX": COMPILED,
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
        the network capture and the record of processes unless asked for,
        which are on by default and would give every session here its
        sidecars, and without line mode, which would run claude with the
        arguments of a chat in place of those it was given."""
        environment = {
            **self.fake_docker_env(),
            "HOME": str(self.home),
            "CLAUDE_AIRLOCK_NET_LOG": "0",
            "CLAUDE_AIRLOCK_PROC_LOG": "0",
            "CLAUDE_AIRLOCK_LINE_MODE": "0",
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
        directory = self.home / ".config" / "claude-airlock"
        directory.mkdir(parents=True, exist_ok=True)
        (directory / "config").write_text("\n".join(lines) + "\n")

    def assert_refused(self, result: Result, message: str) -> None:
        assert result.status != 0
        assert message in result.stderr
        assert [c for c in result.calls if c[0] == "run"] == []
