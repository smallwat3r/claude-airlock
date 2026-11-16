#!/usr/bin/env python3
"""The record of what a session did through the SSH agent and the Docker
socket, and what --trace shows of it."""

from __future__ import annotations

import json
import os
import socket
import struct
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from harness import LauncherTest, network, prompts_at, settings

from claude_sandbox import doors

KEY = b"\x00\x00\x00\x0bssh-ed25519" + b"\x00\x00\x00\x20" + bytes(range(32))
PROXY_LOG = (
    "172.20.0.5:51234 [16/Nov/2026:19:02:11.123] dockerfrontend"
    " dockerbackend/dockersocket 0/0/0/1/1 200 1234 - - ---- 1/1/0/0/0 0/0"
    ' "GET /v1.47/containers/json HTTP/1.1"\n'
    "172.20.0.5:51236 [16/Nov/2026:19:02:12.001] dockerfrontend"
    " dockerfrontend/<NOSRV> 0/-1/-1/-1/0 403 192 - - PR-- 1/1/0/0/0 0/0"
    ' "POST /v1.47/containers/create HTTP/1.1"\n'
    # Another session's
    "172.20.0.9:40000 [16/Nov/2026:19:02:13.000] dockerfrontend"
    " dockerbackend/dockersocket 0/0/0/1/1 200 99 - - ---- 1/1/0/0/0 0/0"
    ' "GET /v1.47/containers/json HTTP/1.1"\n'
    "[NOTICE]   (1) : New worker (12) forked\n"
)


def string(data: bytes) -> bytes:
    return struct.pack("!I", len(data)) + data


def login(user: str) -> bytes:
    """What ssh asks an agent to sign to log in as a user."""
    return (
        string(b"session id")
        + b"\x32"
        + string(user.encode())
        + string(b"ssh-connection")
        + string(b"publickey")
    )


def sign_request(data: bytes) -> bytes:
    return b"\x0d" + string(KEY) + string(data) + struct.pack("!I", 0)


class FakeAgent:
    """An agent that lists one key and signs, or refuses, what it is
    asked."""

    def __init__(self, directory: str, refuse: bool = False):
        self.path = os.path.join(directory, "agent.sock")
        self.refuse = refuse
        self._listener = socket.socket(socket.AF_UNIX)
        self._listener.bind(self.path)
        self._listener.listen(4)
        threading.Thread(target=self._serve, daemon=True).start()

    def close(self) -> None:
        self._listener.close()

    def _serve(self) -> None:
        while True:
            try:
                client, _ = self._listener.accept()
            except OSError:
                return
            with client:
                while (request := doors.read_message(client)) is not None:
                    if request[:1] == b"\x0b":
                        answer = b"\x0c" + struct.pack("!I", 1)
                        answer += string(KEY) + string(b"me@laptop")
                    elif request[:1] == b"\x0d" and not self.refuse:
                        answer = b"\x0e" + string(b"a signature")
                    else:
                        answer = b"\x05"
                    client.sendall(string(answer))


class AgentDoorTest(LauncherTest):
    def setUp(self):
        super().setUp()
        self.host = settings.Host(
            str(self.home),
            str(self.project),
            str(self.home / ".config"),
            str(self.home / ".local" / "state"),
        )
        # A short path, socket paths are limited to about 100 bytes
        directory = tempfile.TemporaryDirectory(dir="/tmp")
        self.addCleanup(directory.cleanup)
        self.directory = directory.name

    def through_the_door(self, *requests: bytes, refuse: bool = False) -> list[bytes]:
        """What the agent answers to requests sent through a door, one
        connection for them all."""
        agent = FakeAgent(self.directory, refuse)
        self.addCleanup(agent.close)
        short = settings.Host(
            self.host.home, self.host.project_dir, self.host.config_home, self.directory
        )
        door = doors.AgentDoor(short, "claude-proj", agent.path)
        self.addCleanup(door.close)
        self.host = short
        answers = []
        with socket.socket(socket.AF_UNIX) as client:
            client.connect(door.path)
            for request in requests:
                client.sendall(string(request))
                answers.append(doors.read_message(client))
        return answers

    def uses(self) -> list[dict]:
        return doors.read_uses(self.host, 0, time.time() + 5)

    def test_requests_reach_the_agent_and_are_noted(self):
        answers = self.through_the_door(b"\x0b", sign_request(login("git")))
        self.assertEqual(answers[1], b"\x0e" + string(b"a signature"))
        listed, signed = self.uses()
        self.assertEqual((listed["did"], listed["keys"]), ("list", 1))
        self.assertEqual(signed["did"], "sign")
        self.assertEqual(signed["key"], doors.fingerprint(KEY))
        self.assertTrue(signed["key"].startswith("SHA256:"))
        self.assertEqual(signed["comment"], "me@laptop")
        self.assertEqual(signed["what"], "a login as git")
        self.assertEqual(
            (signed["project"], signed["session"]), (str(self.project), "claude-proj")
        )

    def test_a_signature_of_a_file_says_what_for(self):
        self.through_the_door(sign_request(b"SSHSIG" + string(b"git") + b"rest"))
        self.assertEqual(self.uses()[0]["what"], "a signature for git")

    def test_what_the_agent_refuses_is_noted_as_refused(self):
        answers = self.through_the_door(sign_request(b"anything"), refuse=True)
        self.assertEqual(answers, [b"\x05"])
        (asked,) = self.uses()
        self.assertEqual((asked["what"], asked["refused"]), ("a signature", True))
        event = doors.use_event(asked)
        self.assertIn("REFUSED by the agent", event.details[0])
        self.assertTrue(event.fields["error"])

    def test_a_request_that_is_not_what_it_says_is_noted_as_that(self):
        self.through_the_door(b"\x0d\x00\x00", b"\x11" + string(b"key"), b"\x1b")
        self.assertEqual(
            [use["what"] for use in self.uses()],
            ["sent a request that could not be read", "asked to add a key"],
        )

    def test_the_door_is_the_users_alone_and_gone_with_the_session(self):
        flags = self.launch(
            session="true",
            CLAUDE_DOCKER_SSH_AGENT="1",
            SSH_AUTH_SOCK=os.path.join(self.directory, "agent.sock"),
        ).flags
        (mount,) = (flag for flag in flags if flag.endswith(":/tmp/ssh-agent.sock:z"))
        door = mount[len("--volume=") : -len(":/tmp/ssh-agent.sock:z")]
        self.assertFalse(os.path.exists(door))
        self.assertEqual((self.state / "agents").stat().st_mode & 0o777, 0o700)

    def test_without_an_agent_nothing_is_forwarded(self):
        flags = self.launch(CLAUDE_DOCKER_SSH_AGENT="1").flags
        self.assertFalse([flag for flag in flags if "ssh-agent" in flag])

    def test_only_the_latest_uses_stay_in_the_record(self):
        with mock.patch.object(doors, "KEPT_USES", 3):
            for number in range(5):
                doors.note_use(self.host, "/p", "s", "docker", path=str(number))
        lines = Path(self.host.doors_file).read_text().splitlines()
        self.assertEqual([json.loads(line)["path"] for line in lines], ["2", "3", "4"])


class SocketWatchTest(LauncherTest):
    def setUp(self):
        super().setUp()
        directory = tempfile.TemporaryDirectory(dir="/tmp")
        self.addCleanup(directory.cleanup)
        self.docker_sock = os.path.join(directory.name, "docker.sock")
        server = socket.socket(socket.AF_UNIX)
        self.addCleanup(server.close)
        server.bind(self.docker_sock)
        self.proxy_log = self.work / "proxy.log"
        self.proxy_log.write_text(PROXY_LOG)

    def test_a_line_of_the_proxys_log_is_read(self):
        calls = [doors.parse_proxy_call(line) for line in PROXY_LOG.splitlines()]
        self.assertEqual(
            calls[:2],
            [
                ("172.20.0.5", "GET", "/v1.47/containers/json", 200),
                ("172.20.0.5", "POST", "/v1.47/containers/create", 403),
            ],
        )
        self.assertIsNone(calls[3])

    def watched(self) -> list[dict]:
        """The uses noted of a session whose proxy logged PROXY_LOG. Called
        directly, the socket path is a constant of the network module."""
        host = settings.Host(
            str(self.home),
            str(self.project),
            str(self.home / ".config"),
            str(self.home / ".local" / "state"),
        )
        environment = {
            **self.fake_docker_env(),
            "FAKE_IP": "172.20.0.5",
            "FAKE_PROXY_LOG": str(self.proxy_log),
        }
        with mock.patch.object(network, "DOCKER_SOCK", self.docker_sock):  # noqa: SIM117
            with mock.patch.dict(os.environ, environment):
                asked = settings.Settings(socket="1")
                with doors.socket_proxy_watched(
                    asked, host, "claude-proj", "claude-proj"
                ):
                    time.sleep(0.5)
        return doors.read_uses(host, 0, time.time() + 5)

    def test_the_calls_of_the_session_are_noted_and_no_other(self):
        uses = self.watched()
        self.assertEqual(
            [(use["method"], use["path"], use["status"]) for use in uses],
            [
                ("GET", "/v1.47/containers/json", 200),
                ("POST", "/v1.47/containers/create", 403),
            ],
        )
        (followed,) = (call for call in self.calls() if call[0] == "logs")
        self.assertEqual(
            (followed[1], followed[-1]), ("--follow", "claude-docker-ps-proxy")
        )

    def test_without_the_socket_nothing_is_watched(self):
        self.launch()
        self.assertFalse([call for call in self.calls() if call[0] == "logs"])

    def test_the_trace_shows_the_use_of_both_doors(self):
        now = time.time()
        host = settings.Host(
            str(self.home),
            str(self.project),
            str(self.home / ".config"),
            str(self.home / ".local" / "state"),
        )
        project = str(self.project)
        doors.note_use(
            host, project, "claude-proj", "docker", method="POST", path="/x", status=403
        )
        doors.note_use(
            host,
            project,
            "claude-proj",
            "ssh-agent",
            did="sign",
            key="SHA256:abc",
            comment="me@laptop\x1b[31m",
            what="a login as git",
        )
        doors.note_use(
            host, "/elsewhere", "claude-x", "docker", method="GET", path="/y"
        )
        self.write_transcript("0a", prompts_at(now - 5, now + 5))
        stdout = self.launch("--trace").stdout
        for expected in (
            "# ssh agent   1 requests, 1 signatures",
            "# docker      1 calls, 1 DENIED",
            "sandbox  docker      POST /x 403  DENIED",
            "sandbox  ssh-agent   signed a login as git with SHA256:abc (me@laptop[31m)",
        ):
            self.assertIn(expected, stdout)
        self.assertNotIn("/y", stdout)
        self.assertNotIn("\x1b", stdout)
        failed = self.launch("--trace", "--failed").stdout
        self.assertIn("POST /x", failed)
        self.assertNotIn("signed", failed)


if __name__ == "__main__":
    unittest.main()
