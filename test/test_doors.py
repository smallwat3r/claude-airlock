#!/usr/bin/env python3
"""The record of what a session did through the SSH agent and the Docker
socket, and what --trace shows of it."""

from __future__ import annotations

import errno
import json
import os
import socket
import struct
import sys
import tempfile
import threading
import time
from pathlib import Path
from unittest import mock

import pytest
from harness import (
    LauncherTest,
    follow,
    mounts_host_sockets,
    prompts_at,
    settings,
)

from claude_airlock import errors
from claude_airlock.recording import doors, socket_watch, ssh_agent, started
from claude_airlock.report import door_events
from claude_airlock.sandbox import socket_proxy

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
        # The kind of each request that reached it
        self.asked: list[bytes] = []
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
                while (request := ssh_agent.read_message(client)) is not None:
                    self.asked.append(request[:1])
                    if request[:1] == b"\x0b":
                        answer = b"\x0c" + struct.pack("!I", 1)
                        answer += string(KEY) + string(b"me@laptop")
                    elif request[:1] == b"\x0d" and not self.refuse:
                        answer = b"\x0e" + string(b"a signature")
                    else:
                        answer = b"\x05"
                    client.sendall(string(answer))


class AgentDoorTest(LauncherTest):
    @pytest.fixture(autouse=True)
    def agent_door(self, sandbox: None) -> None:
        # A short path, socket paths are limited to about 100 bytes
        self.directory = self.cleanup.enter_context(
            tempfile.TemporaryDirectory(dir="/tmp")
        )

    def through_the_door(self, *requests: bytes, refuse: bool = False) -> list[bytes]:
        """What the agent answers to requests sent through a door, one
        connection for them all."""
        agent = self.agent = FakeAgent(self.directory, refuse)
        self.cleanup.callback(agent.close)
        short = settings.Host(
            self.host.home, self.host.project_dir, self.host.config_home, self.directory
        )
        door = self.door = ssh_agent.AgentDoor(short, "claude-proj", agent.path)
        self.cleanup.callback(door.close)
        self.host = short
        answers = []
        with socket.socket(socket.AF_UNIX) as client:
            client.connect(door.path)
            for request in requests:
                client.sendall(string(request))
                answers.append(ssh_agent.read_message(client))
        return answers

    def uses(self) -> list[dict]:
        return doors.read_uses(self.host, 0, time.time() + 5)

    def test_a_session_cannot_hold_more_than_so_many_connections(self):
        answers = self.through_the_door(b"\x0b")
        assert len(answers) == 1
        path = self.door.path
        # /dev/fd is there on Linux and on macOS, /proc only on the first
        before = len(os.listdir("/dev/fd"))
        held = []
        self.cleanup.callback(lambda: [each.close() for each in held])
        for _ in range(ssh_agent.AGENT_CONNECTIONS * 4):
            client = socket.socket(socket.AF_UNIX)
            held.append(client)
            # As fast as the door takes them in
            for _ in range(200):
                try:
                    client.connect(path)
                    break
                except (BlockingIOError, ConnectionRefusedError):
                    # A door with too many waiting: Linux has the next
                    # one wait, macOS refuses it
                    time.sleep(0.01)
            client.settimeout(5)
        time.sleep(0.5)
        # Ours, and for each that was let in the door's two
        most = len(held) + 2 * ssh_agent.AGENT_CONNECTIONS
        assert len(os.listdir("/dev/fd")) - before <= most + 2
        # Those past the bound were closed at once, and the door still serves
        assert held[-1].recv(1) == b""
        for each in held:
            each.close()
        time.sleep(0.5)
        with socket.socket(socket.AF_UNIX) as client:
            client.connect(path)
            client.sendall(string(b"\x0b"))
            assert ssh_agent.read_message(client)[:1] == b"\x0c"

    def test_a_connection_that_asks_nothing_is_let_go(self):
        self.through_the_door(b"\x0b")
        path = self.door.path
        idle = mock.patch.object(ssh_agent, "AGENT_IDLE", 0.2)
        with idle, socket.socket(socket.AF_UNIX) as client:
            client.settimeout(5)
            client.connect(path)
            assert client.recv(1) == b""

    def test_requests_reach_the_agent_and_are_noted(self):
        answers = self.through_the_door(b"\x0b", sign_request(login("git")))
        assert answers[1] == b"\x0e" + string(b"a signature")
        listed, signed = self.uses()
        assert (listed["did"], listed["keys"]) == ("list", 1)
        assert signed["did"] == "sign"
        assert signed["key"] == ssh_agent.fingerprint(KEY)
        assert signed["key"].startswith("SHA256:")
        assert signed["comment"] == "me@laptop"
        assert signed["what"] == "a login as git"
        assert (signed["project"], signed["session"]) == (
            str(self.project),
            "claude-proj",
        )

    def test_what_cannot_be_noted_is_not_given(self):
        # A full disk, which a session can make of the one the record is on
        full = OSError(errno.ENOSPC, "No space left on device")
        with mock.patch.object(doors, "note_use", side_effect=full):
            answers = self.through_the_door(b"\x0b", sign_request(login("git")))
        assert answers == [b"\x05", b"\x05"]
        assert self.uses() == []

    @mounts_host_sockets
    def test_a_door_that_cannot_be_made_is_not_the_agents_own_instead(self):
        asked = settings.Settings(ssh_agent=True)
        env = {"SSH_AUTH_SOCK": os.path.join(self.directory, "agent.sock")}
        failing = mock.patch.object(
            ssh_agent, "AgentDoor", side_effect=OSError("AF_UNIX path too long")
        )
        door = ssh_agent.ssh_agent_door(asked, self.host, "claude-proj", env)
        with failing, pytest.raises(errors.Fatal, match="could not listen"), door:
            pytest.fail("the session was given the agent")

    def test_a_signature_of_a_file_says_what_for(self):
        self.through_the_door(sign_request(b"SSHSIG" + string(b"git") + b"rest"))
        assert self.uses()[0]["what"] == "a signature for git"

    def test_what_the_agent_refuses_is_noted_as_refused(self):
        answers = self.through_the_door(sign_request(b"anything"), refuse=True)
        assert answers == [b"\x05"]
        (asked,) = self.uses()
        assert (asked["what"], asked["refused"]) == ("a signature", True)
        event = door_events.use_event(asked)
        assert "REFUSED by the agent" in event.details[0]
        assert event.fields["error"]

    def test_a_request_that_is_not_what_it_says_is_noted_as_that(self):
        self.through_the_door(b"\x0d\x00\x00")
        (use,) = self.uses()
        assert use["what"] == "sent a request that could not be read"

    def test_what_would_change_the_agent_is_refused_and_never_reaches_it(self):
        bind = b"\x1b" + string(b"session-bind@openssh.com") + b"rest"
        answers = self.through_the_door(
            b"\x11" + string(b"key"),  # add a key
            b"\x13",  # remove every key
            b"\x16" + string(b"passphrase"),  # lock the agent
            b"\x1b" + string(b"other@example.com"),
            b"\x1b",
            bind,
            b"\x0b",
        )
        # The agent of these tests answers a list alone with the keys
        assert [answer[:1] for answer in answers[:5]] == [b"\x05"] * 5
        assert answers[6][:1] == b"\x0c"
        assert self.agent.asked == [b"\x1b", b"\x0b"]
        uses = self.uses()
        assert [(use["what"], use["refused"], use["by"]) for use in uses[:5]] == [
            (what, True, "launcher")
            for what in (
                "asked to add a key",
                "asked to remove every key",
                "asked to lock the agent",
                "asked for an extension",
                "asked for an extension",
            )
        ]
        # The extension ssh signs with is passed on and not noted
        assert [use["did"] for use in uses[5:]] == ["list"]
        event = door_events.use_event(uses[0])
        assert "REFUSED by the launcher" in event.details[0]
        assert event.fields["error"] == "refused by the launcher"

    @mounts_host_sockets
    def test_the_door_is_the_users_alone_and_gone_with_the_session(self):
        flags = self.launch(
            session="true",
            CLAUDE_AIRLOCK_SSH_AGENT="1",
            SSH_AUTH_SOCK=os.path.join(self.directory, "agent.sock"),
        ).flags
        (mount,) = (flag for flag in flags if flag.endswith(":/tmp/ssh-agent.sock:z"))
        door = mount[len("--volume=") : -len(":/tmp/ssh-agent.sock:z")]
        assert not os.path.exists(door)
        assert (self.state / "agents").stat().st_mode & 511 == 448

    def test_on_macos_the_agent_is_the_one_inside_the_machine(self):
        # Whatever the host has: the path is the machine's, not the host's
        for env in ({}, {"SSH_AUTH_SOCK": "/private/tmp/agent.sock"}):
            assert ssh_agent.agent_socket(env, "darwin") == (
                "/run/host-services/ssh-auth.sock",
                False,
            )

    def test_elsewhere_the_agent_is_the_hosts_behind_the_launcher(self):
        assert ssh_agent.agent_socket(
            {"SSH_AUTH_SOCK": "/tmp/agent.sock"}, "linux"
        ) == ("/tmp/agent.sock", True)
        assert ssh_agent.agent_socket({}, "linux") is None

    @pytest.mark.skipif(
        sys.platform == "darwin", reason="the agent is the machine's there"
    )
    def test_without_an_agent_nothing_is_forwarded(self):
        flags = self.launch(CLAUDE_AIRLOCK_SSH_AGENT="1").flags
        assert not [flag for flag in flags if "ssh-agent" in flag]

    def test_only_the_latest_uses_stay_in_the_record(self):
        with mock.patch.object(doors, "KEPT_USES", 3):
            for number in range(5):
                doors.note_use(self.host, "s", doors.Door.DOCKER, path=str(number))
        lines = Path(self.host.doors_file).read_text().splitlines()
        assert [json.loads(line)["path"] for line in lines] == ["2", "3", "4"]

    def test_no_more_kinds_are_counted_than_a_few(self):
        # The method of a call to the Docker socket is the session's to name
        uses = doors.SessionUses(self.host, "s", doors.Door.DOCKER)
        with mock.patch.object(doors, "MOST_SESSION_USES", 0):
            for number in range(doors.MOST_KINDS + 30):
                uses.note(f"M{number}", method=f"M{number}", path="/x", status=403)
            uses.note("M0", method="M0", path="/x", status=403)
        uses.close()
        (counted,) = [
            use["unrecorded"]
            for use in doors.read_uses(self.host, 0, time.time() + 1)
            if isinstance(use.get("unrecorded"), dict)
        ]
        assert len(counted) == doors.MOST_KINDS + 1
        assert counted["M0"] == 2
        assert counted[doors.OTHER_KINDS] == 30

    def test_a_session_cannot_fill_the_record_with_uses_that_cost_nothing(self):
        uses = doors.SessionUses(self.host, "s", doors.Door.SSH_AGENT)
        uses.note("sign", did="sign", key="SHA256:abc", what="a login as git")
        with mock.patch.object(doors, "MOST_ALIKE", 3):
            for _ in range(50):
                uses.note("list", did="list", keys=2)
            uses.note("sign", did="sign", key="SHA256:abc", what="a signature for x")
        with mock.patch.object(doors, "MOST_SESSION_USES", 5):
            uses.note("sign", did="sign", key="SHA256:abc", what="a signature for y")
        uses.close()
        noted = doors.read_uses(self.host, 0, time.time() + 1)
        # The first of them one by one, then that the rest is counted
        assert [use.get("did", "counted") for use in noted] == [
            "sign",
            "list",
            "list",
            "list",
            "counted",
            "sign",
            "counted",
        ]
        assert noted[-1]["unrecorded"] == {"list": 47, "sign": 1}
        rows, events = door_events.door_events(self.host, 0, time.time() + 1)
        assert rows == [
            ("ssh agent", "5 requests, 2 signatures, 48 more NOT RECORDED one by one")
        ]
        assert events[-1].details == [
            "48 more uses NOT RECORDED one by one: 47 list, 1 sign"
        ]
        assert "error" in events[4].fields

    def test_the_uses_of_one_session_can_be_told_from_another(self):
        for session in ("claude-proj", "claude-proj-2"):
            doors.note_use(self.host, session, doors.Door.DOCKER)
        mine = doors.read_uses(self.host, 0, time.time() + 1, "claude-proj-2")
        assert [use["session"] for use in mine] == ["claude-proj-2"]
        assert len(doors.read_uses(self.host, 0, time.time() + 1)) == 2

    def test_uses_noted_in_the_same_moment_are_all_followed(self):
        follower = follow.Follower(self.host, verbose=False)
        moment = time.time() + 5
        paths = ["/_ping", "/containers/json", "/version"]

        def note(path: str) -> None:
            with mock.patch.object(time, "time", return_value=moment):
                doors.note_use(self.host, "s", doors.Door.DOCKER, path=path)

        def followed() -> list[str]:
            found = follow.Round()
            follower._poll_notes(found)
            return [event.fields["path"] for _, event in found.events]

        note(paths[0])
        note(paths[1])
        assert followed() == paths[:2]
        note(paths[2])
        assert followed() == paths[2:]
        assert followed() == []


class SocketWatchTest(LauncherTest):
    @pytest.fixture(autouse=True)
    def docker_socket(self, sandbox: None, unix_socket: str) -> None:
        self.docker_sock = unix_socket
        self.proxy_log = self.work / "proxy.log"
        self.proxy_log.write_text(PROXY_LOG)

    def test_a_line_of_the_proxys_log_is_read(self):
        calls = [socket_watch.parse_proxy_call(line) for line in PROXY_LOG.splitlines()]
        assert calls[:2] == [
            ("172.20.0.5", "GET", "/v1.47/containers/json", 200),
            ("172.20.0.5", "POST", "/v1.47/containers/create", 403),
        ]
        assert calls[3] is None

    def test_an_ipv4_caller_logged_as_ipv6_is_read_as_ipv4(self):
        # What the proxy logs when one socket listens on IPv4 and IPv6
        line = (
            "::ffff:172.21.0.5:51848 [18/Nov/2026:23:29:05.413] dockerfrontend "
            "dockerfrontend/<NOSRV> 0/-1/-1/-1/0 403 0 - - PR-- 1/1/0/0/0 0/0 "
            '"GET /v1.56/volumes HTTP/1.1"'
        )
        assert socket_watch.parse_proxy_call(line) == (
            "172.21.0.5",
            "GET",
            "/v1.56/volumes",
            403,
        )
        assert (
            socket_watch.parse_proxy_call(line.replace("::ffff:172.21.0.5", "fd00::5"))[
                0
            ]
            == "fd00::5"
        )

    def watched(self) -> list[dict]:
        """The uses noted of a session whose proxy logged PROXY_LOG. Called
        directly, the socket path is a constant of the socket_proxy module."""
        host = self.host
        environment = {
            **self.fake_docker_env(),
            "FAKE_IP": "172.20.0.5",
            "FAKE_PROXY_LOG": str(self.proxy_log),
        }
        with mock.patch.object(socket_proxy, "DOCKER_SOCK", self.docker_sock):  # noqa: SIM117
            with mock.patch.dict(os.environ, environment):
                asked = settings.Settings(docker_socket=settings.SocketAccess.LIMITED)
                with socket_watch.socket_proxy_watched(
                    asked, host, "claude-proj", "claude-proj"
                ):
                    time.sleep(0.5)
        return doors.read_uses(host, 0, time.time() + 5)

    def test_the_calls_of_the_session_are_noted_and_no_other(self, capsys):
        uses = self.watched()
        # The fake's log ends at once, as that of a proxy that is gone:
        # said, the calls made from then on are not noted
        assert "ended before the session did: the log of the proxy ended" in (
            capsys.readouterr().err
        )
        assert [(use["method"], use["path"], use["status"]) for use in uses] == [
            ("GET", "/v1.47/containers/json", 200),
            ("POST", "/v1.47/containers/create", 403),
        ]
        (followed,) = (call for call in self.calls() if call[0] == "logs")
        assert (followed[1], followed[-1]) == ("--follow", "claude-airlock-ps-proxy")

    def test_an_address_found_after_the_watch_closed_follows_no_log(self):
        """The proxy outlives the session: a log followed once nobody
        ends it would keep the launcher from ending."""
        closing = threading.Event()

        def slow_address(_owner):
            # Asked once, and answered after the watch stopped waiting
            closing.wait(5)
            time.sleep(1.3)
            return "172.20.0.5"

        host = settings.Host(str(self.home), str(self.project), "", "")
        with (
            mock.patch.object(socket_watch, "session_address", slow_address),
            mock.patch.object(socket_watch, "docker_popen") as followed,
        ):
            watch = socket_watch.SocketWatch(host, "claude-proj", "claude-proj", "p")
            closing.set()
            watch.close()
        followed.assert_not_called()

    def test_without_the_socket_nothing_is_watched(self):
        self.launch()
        assert not [call for call in self.calls() if call[0] == "logs"]

    def test_a_door_used_after_the_last_line_of_the_transcript_is_shown(self):
        # A command left running asks the agent while the user reads the
        # reply: after all the transcript has, and while the session is there
        host = self.host
        record = started.start_record(host)
        record.add(host.project_dir, "claude-proj", did=started.STARTED)
        began = time.time()
        self.write_transcript("0a", prompts_at(began - 5, began + 0.001))
        time.sleep(0.05)
        doors.note_use(host, "claude-proj", doors.Door.SSH_AGENT, did="list", keys=2)
        started.note_end(host, "claude-proj")
        # And one of the session that took the name after it is not its own
        time.sleep(0.05)
        record.add(host.project_dir, "claude-proj", did=started.STARTED)
        doors.note_use(host, "claude-proj", doors.Door.DOCKER, method="GET", path="/z")
        stdout = self.launch("--trace").stdout
        assert "sandbox  ssh-agent   listed the keys, 2 of them" in stdout
        assert "/z" not in stdout
        assert started.stay_between(host, began - 5, began)[1] < time.time()

    def test_the_trace_shows_the_use_of_both_doors(self):
        now = time.time()
        host = self.host
        doors.note_use(
            host,
            "claude-proj",
            doors.Door.DOCKER,
            method="POST",
            path="/x",
            status=403,
        )
        doors.note_use(
            host,
            "claude-proj",
            doors.Door.SSH_AGENT,
            did="sign",
            key="SHA256:abc",
            comment="me@laptop\x1b[31m",
            what="a login as git",
        )
        doors.door_record(host).add(
            "/elsewhere",
            "claude-x",
            door=doors.Door.DOCKER.value,
            method="GET",
            path="/y",
        )
        self.write_transcript("0a", prompts_at(now - 5, now + 5))
        stdout = self.launch("--trace").stdout
        for expected in (
            "# ssh agent   1 requests, 1 signatures",
            "# docker      1 calls, 1 DENIED",
            "sandbox  docker      POST /x 403  DENIED",
            "sandbox  ssh-agent   signed a login as git with SHA256:abc (me@laptop[31m)",
        ):
            assert expected in stdout
        assert "/y" not in stdout
        assert "\x1b" not in stdout
        failed = self.launch("--trace", "--failed").stdout
        assert "POST /x" in failed
        assert "signed" not in failed
