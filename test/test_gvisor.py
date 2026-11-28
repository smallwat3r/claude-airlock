#!/usr/bin/env python3
"""What gVisor tells of what runs in a session: the messages of its sink
as the launcher reads them, the socket it listens on, the file a runtime
of gVisor reads, and what --trace makes of what was told."""

from __future__ import annotations

import fcntl
import json
import os
import socket
import threading
import time
from pathlib import Path
from unittest import mock

import pytest
from fakes import gvisor
from harness import LauncherTest, gvisor_socket

from claude_airlock import settings
from claude_airlock.recording import gvisor as told
from claude_airlock.recording import procwatch, secrets
from claude_airlock.sandbox import runtime

CONTAINER = "a" * 64
HOME = "/home/sandbox"
CLAUDE = secrets.CLAUDE_PROGRAM


def field(number: int, value: int | bytes | str) -> bytes:
    """A field as protobuf writes it: a number as a varint, below zero
    in 64 bits, text and messages by their length."""
    if isinstance(value, int):
        return varint(number << 3) + varint(value % (1 << 64))
    data = value.encode() if isinstance(value, str) else value
    return varint(number << 3 | 2) + varint(len(data)) + data


def varint(number: int) -> bytes:
    out = bytearray()
    while True:
        byte, number = number & 0x7F, number >> 7
        out.append(byte | (0x80 if number else 0))
        if not number:
            return bytes(out)


def message(*fields: bytes) -> bytes:
    return b"".join(fields)


def context(
    pid: int,
    thread: int | None = None,
    container: str = CONTAINER,
    cwd: str = "",
    parent: int = 0,
    when: float = 1000.0,
) -> bytes:
    """ContextData of common.proto."""
    said = [field(1, int(when * 1e9)), field(2, thread or pid), field(4, pid)]
    said += [field(6, container)] if container else []
    said += [field(8, cwd)] if cwd else []
    said += [field(10, parent)] if parent else []
    return field(1, message(*said))


def exited(result: int = 0, errno: int = 0) -> bytes:
    return field(2, message(field(1, result), field(2, errno)))


def execed(pid: int, program: str, *argv: str, parent: int = 0, **about) -> bytes:
    """ExecveInfo of sentry.proto."""
    return message(
        context(pid, parent=parent, **about),
        field(2, program),
        *(field(3, argument) for argument in argv),
    )


def cloned(parent: int, made: int, thread: int = 0) -> bytes:
    """CloneInfo of sentry.proto."""
    return message(context(parent), field(3, thread or made), field(4, made))


def opened(
    pid: int,
    pathname: str,
    fd: int = told.AT_FDCWD,
    cwd: str = "",
    fd_path: str = "",
    result: int = 3,
    errno: int = 0,
) -> bytes:
    """Open of syscall.proto."""
    said = [context(pid, cwd=cwd), exited(result, errno), field(3, 257), field(4, fd)]
    said += [field(5, fd_path)] if fd_path else []
    return message(*said, field(6, pathname))


def closed(pid: int, fd_path: str) -> bytes:
    """Close of syscall.proto."""
    return message(context(pid), exited(), field(3, 3), field(4, 3), field(5, fd_path))


def sockaddr(address: str, port: int) -> bytes:
    if ":" in address:
        packed = socket.inet_pton(socket.AF_INET6, address)
        return b"\x0a\x00" + port.to_bytes(2, "big") + bytes(4) + packed + bytes(4)
    packed = socket.inet_aton(address)
    return b"\x02\x00" + port.to_bytes(2, "big") + packed + bytes(8)


def connected(pid: int, to: bytes, errno: int = 0) -> bytes:
    """Connect of syscall.proto."""
    return message(
        context(pid), exited(0, errno), field(3, 42), field(4, 5), field(6, to)
    )


def started(*args: str, container: str = CONTAINER) -> bytes:
    """Start of container.proto."""
    return message(
        context(0, container=container),
        field(2, container),
        field(3, "/"),
        *(field(4, argument) for argument in args),
    )


def framed(kind: int, payload: bytes, dropped: int = 0) -> bytes:
    """A message of the sink: its header, then the message."""
    return told.HEADER.pack(told.HEADER.size, kind, dropped) + payload


def session_secrets() -> procwatch.Secrets:
    host = settings.Host("/home/me", "/home/me/proj", "/home/me/.config", "/s")
    return secrets.session_secrets(settings.Settings(), host, ["/home/me/proj"])


def said(lines: list[told.Line]) -> list[dict]:
    return [line for _, _, line in lines]


class MessageTest:
    def test_fields_are_read_by_their_number_as_protobuf_writes_them(self):
        read = told.Message.read(
            message(field(1, 7), field(2, -100), field(3, "text"), field(3, "more"))
        )
        assert read.number(1) == 7
        assert read.number(2) == -100
        assert read.text(3) == "more"
        assert read.texts(3) == [b"text", b"more"]
        # Not there, as protobuf has it
        assert (read.number(9), read.text(9)) == (0, "")
        assert (
            told.Message.read(field(1, message(field(4, 812)))).message(1).number(4)
            == 812
        )

    def test_a_message_that_does_not_hold_up_is_refused(self):
        for broken in (
            b"\x08",  # a number cut short
            b"\x08" + b"\xff" * 11,  # a number too long
            b"\x12\x05ab",  # a text longer than what is left
            b"\x0b",  # a group, which gVisor never writes
        ):
            with pytest.raises(told.NotThis):
                told.Message.read(broken)

    def test_an_address_is_read_of_ipv4_and_ipv6_alone(self):
        assert told.address(sockaddr("203.0.113.9", 443)) == ("203.0.113.9", 443)
        assert told.address(sockaddr("2001:db8::1", 22)) == ("2001:db8::1", 22)
        assert told.address(sockaddr("::ffff:203.0.113.9", 80)) == ("203.0.113.9", 80)
        assert told.address(b"\x01\x00/tmp/ssh-agent.sock") is None
        assert told.address(b"\x02") is None

    def test_a_path_is_read_from_where_the_process_named_it(self):
        assert told.opened_path("/etc/hosts", 5, "/x", "/y") == "/etc/hosts"
        assert (
            told.opened_path("hosts.yml", told.AT_FDCWD, "/c/gh", "")
            == "/c/gh/hosts.yml"
        )
        assert told.opened_path("id_rsa", 5, "/x", "/h/.ssh") == "/h/.ssh/id_rsa"
        assert told.opened_path("id_rsa", 5, "/x", "[err: FD not found]") == ""


class ToldTest:
    def told(self) -> told.Told:
        return told.Told(session_secrets())

    def test_a_process_made_is_the_program_its_parent_is_until_it_execs(self):
        sandbox = self.told()
        lines = sandbox.take(
            told.CONTAINER_START, started("/sbin/docker-init", "--", "claude")
        )
        lines += sandbox.take(told.SENTRY_EXEC, execed(2, CLAUDE, "claude", parent=1))
        lines += sandbox.take(told.SENTRY_CLONE, cloned(2, 40))
        # A thread is nothing new
        lines += sandbox.take(told.SENTRY_CLONE, cloned(40, 40, thread=41))
        lines += sandbox.take(
            told.SENTRY_EXEC, execed(40, "/usr/bin/curl", "curl", "x")
        )
        assert said(lines) == [
            {
                "pid": 1,
                "ppid": 0,
                "exe": "/sbin/docker-init",
                "argv": ["/sbin/docker-init", "--", "claude"],
            },
            {"pid": 2, "ppid": 1, "exe": CLAUDE, "argv": ["claude"]},
            {"pid": 40, "ppid": 2, "exe": CLAUDE, "argv": ["claude"]},
            {"pid": 40, "ppid": 2, "exe": "/usr/bin/curl", "argv": ["curl", "x"]},
        ]
        assert sandbox.container == CONTAINER
        # Each when the point was, of the part of the record of processes
        assert {(when, reserved) for when, reserved, _ in lines} == {(1000.0, False)}

    def test_a_long_command_line_is_cut_as_the_watcher_cuts_one(self):
        argv = ["x" * 600, *map(str, range(100))]
        (line,) = said(self.told().take(told.SENTRY_EXEC, execed(9, "/bin/x", *argv)))
        assert line["argv"] == procwatch.command_line("\0".join(argv).encode())

    def test_a_connection_is_told_by_where_it_went(self):
        sandbox = self.told()
        lines = [
            *sandbox.take(
                told.SYSCALL_CONNECT, connected(40, sockaddr("203.0.113.9", 443))
            ),
            # A socket that does not wait is connected later
            *sandbox.take(
                told.SYSCALL_CONNECT,
                connected(40, sockaddr("2001:db8::1", 22), errno=told.EINPROGRESS),
            ),
        ]
        assert said(lines) == [
            {"port": 0, "to": "203.0.113.9", "to_port": 443, "pids": [40]},
            {"port": 0, "to": "2001:db8::1", "to_port": 22, "pids": [40]},
        ]
        assert all(reserved for _, reserved, _ in lines)
        for passed in (
            connected(40, sockaddr("203.0.113.9", 443), errno=111),
            connected(40, sockaddr("127.0.0.1", 8080)),
            connected(40, sockaddr("::1", 8080)),
            connected(40, b"\x01\x00/tmp/ssh-agent.sock"),
        ):
            assert sandbox.take(told.SYSCALL_CONNECT, passed) == []

    def test_a_file_of_secrets_is_told_once_for_each_process(self):
        sandbox = self.told()
        login = f"{HOME}/.claude/.credentials.json"
        lines = [
            *sandbox.take(told.SYSCALL_OPEN, opened(40, login)),
            *sandbox.take(told.SYSCALL_OPEN, opened(40, login)),
            *sandbox.take(told.SYSCALL_CLOSE, closed(40, login)),
            # By the host's home, from the directory it is in
            *sandbox.take(
                told.SYSCALL_OPEN, opened(41, "hosts.yml", cwd="/home/me/.config/gh")
            ),
            # A key, by the directory it was opened from
            *sandbox.take(
                told.SYSCALL_OPEN,
                opened(41, "id_ed25519", fd=5, fd_path=f"{HOME}/.ssh"),
            ),
        ]
        assert said(lines) == [
            {"opened": login, "secret": "claude", "pids": [40]},
            {"opened": "/home/me/.config/gh/hosts.yml", "secret": "gh", "pids": [41]},
            {"opened": f"{HOME}/.ssh/id_ed25519", "secret": "ssh", "pids": [41]},
        ]
        # Again once the process is another program
        sandbox.take(told.SENTRY_EXEC, execed(40, "/bin/cat", "cat"))
        assert said(sandbox.take(told.SYSCALL_OPEN, opened(40, login))) == [
            {"opened": login, "secret": "claude", "pids": [40]}
        ]

    def test_a_file_opened_through_a_link_is_told_as_it_is_closed(self):
        sandbox = self.told()
        assert sandbox.take(told.SYSCALL_OPEN, opened(40, "/tmp/x")) == []
        assert said(
            sandbox.take(told.SYSCALL_CLOSE, closed(40, "/home/me/proj/.env"))
        ) == [{"opened": "/home/me/proj/.env", "secret": "hidden", "pids": [40]}]

    def test_what_is_no_file_of_secrets_is_not_told(self):
        sandbox = self.told()
        for passed in (
            opened(40, f"{HOME}/.ssh/known_hosts"),
            opened(40, f"{HOME}/.ssh/id_ed25519.pub"),
            opened(40, f"{HOME}/proj/.env.example"),
            opened(40, f"{HOME}/.claude/.credentials.json", result=0, errno=2),
            opened(40, "relative/.env", fd=5, fd_path="[err: FD not found]"),
        ):
            assert sandbox.take(told.SYSCALL_OPEN, passed) == []
        assert sandbox.take(told.SYSCALL_CLOSE, closed(40, "socket:[812]")) == []

    def test_what_has_none_of_the_marks_of_a_secret_is_passed_over_unread(self):
        sandbox = self.told()
        # Not a message at all, it is not read
        assert sandbox.take(told.SYSCALL_OPEN, b"\xff/usr/lib/libc.so.6") == []
        with pytest.raises(told.NotThis):
            sandbox.take(told.SYSCALL_OPEN, b"\xff/home/me/.env")

    def test_no_more_files_are_told_than_are_kept(self):
        sandbox = self.told()
        with mock.patch.object(procwatch, "MOST_OPENED", 2):
            lines = [
                line
                for pid in range(4)
                for line in sandbox.take(
                    told.SYSCALL_OPEN, opened(pid, "/home/me/proj/.netrc")
                )
            ]
        assert said(lines)[-1] == {"note": procwatch.Note.TOO_MANY_OPENED}
        assert len(lines) == 3
        # Of processes that become others too, which are told of again
        sandbox = self.told()
        with mock.patch.object(procwatch, "MOST_OPENED", 2):
            for _ in range(4):
                sandbox.take(told.SENTRY_EXEC, execed(9, "/bin/cat", "cat"))
                lines = sandbox.take(
                    told.SYSCALL_OPEN, opened(9, "/home/me/proj/.netrc")
                )
        assert said(lines) == []
        assert sandbox.too_many_opened


class PodInitConfigTest:
    # The points runsc release-20261123.1 lists (runsc trace metadata)
    KNOWN = frozenset(
        {
            "container/start",
            "sentry/clone",
            "sentry/execve",
            "sentry/task_exit",
            "syscall/connect/exit",
            "syscall/open/exit",
            "syscall/openat/exit",
            "syscall/close/exit",
        }
    )
    CONTEXT = frozenset(
        {
            "time",
            "thread_id",
            "task_start_time",
            "group_id",
            "thread_group_start_time",
            "container_id",
            "credentials",
            "cwd",
            "process_name",
            "parent_thread_group_id",
            "is_exec_session",
        }
    )

    def test_the_runtime_is_told_the_points_and_the_socket(self):
        config = told.pod_init_config("/s/gvisor/x.sock")
        session = config["trace_session"]
        assert session["name"] == "Default"
        assert session["ignore_missing"] is True
        assert {point["name"] for point in session["points"]} == self.KNOWN
        for point in session["points"]:
            assert set(point["context_fields"]) <= self.CONTEXT
        (sink,) = session["sinks"]
        assert sink["name"] == "remote"
        assert sink["config"]["endpoint"] == "/s/gvisor/x.sock"
        # A sandbox whose socket is gone starts all the same
        assert sink["ignore_setup_error"] is True
        json.dumps(config)


class RuntimeTest:
    def test_gvisor_tells_what_runs_when_registered_to_read_the_launchers_file(self):
        config = "/home/me/.local/state/claude-airlock/gvisor/pod-init.json"
        asked = settings.Settings(proc_log=True)
        registered = gvisor("--network=host", f"--pod-init-config={config}")
        assert registered.monitored(config)
        assert not [n for n in registered.notes(asked, config) if "not recorded" in n]
        for other in (gvisor("--network=host"), gvisor("--pod-init-config=/elsewhere")):
            assert not other.monitored(config)
            (note,) = [n for n in other.notes(asked, config) if "not recorded" in n]
            assert f"--pod-init-config={config}" in note
        # Of a shim, whose arguments are not visible, it is tried
        said = {"runtimeType": "io.containerd.runsc.v1"}
        shim = runtime.known_runtime(runtime.Registered.read("gv", said))
        assert shim.monitored(config)
        assert not registered.monitored("")
        # Docker's own needs none of it
        assert not runtime.DOCKERS_OWN.monitored(config)


class FakeRecord:
    """What the record of host_health.py is given, line by line."""

    def __init__(self) -> None:
        self.lines: list[tuple[float | None, bool, dict]] = []
        self.written = threading.Event()

    def note_at(self, when: float | None, reserved: bool, said: dict) -> None:
        self.lines.append((when, reserved, said))
        self.written.set()


@gvisor_socket
class MonitorTest(LauncherTest):
    def listening(self) -> told.Monitor:
        monitor = told.Monitor.listening(self.host, "claude-proj", session_secrets())
        self.cleanup.callback(monitor.close)
        return monitor

    def connect(self, monitor: told.Monitor, version: int = 1) -> socket.socket:
        """A sandbox of gVisor that connected, as its sink does."""
        sink = socket.socket(socket.AF_UNIX, socket.SOCK_SEQPACKET)
        self.cleanup.callback(sink.close)
        sink.settimeout(5)
        sink.connect(monitor.path)
        sink.send(field(1, version))
        return sink

    def wait_for(self, record: FakeRecord, lines: int) -> list[dict]:
        until = time.monotonic() + 5
        while len(record.lines) < lines and time.monotonic() < until:
            record.written.wait(0.05)
            record.written.clear()
        return [said for _, _, said in record.lines]

    def test_the_socket_is_the_users_alone(self):
        monitor = self.listening()
        assert Path(monitor.path).parent == Path(self.host.gvisor_dir)
        assert os.stat(monitor.path).st_mode & 0o777 == 0o600
        assert os.stat(self.host.gvisor_dir).st_mode & 0o777 == 0o700
        monitor.close()
        assert not Path(monitor.path).exists()

    def test_what_a_sandbox_tells_goes_to_the_record_once_it_has_begun(self):
        monitor = self.listening()
        sink = self.connect(monitor)
        assert sink.recv(64) == field(1, 1)
        sink.send(framed(told.CONTAINER_START, started("/sbin/docker-init")))
        sink.send(framed(told.SENTRY_EXEC, execed(2, CLAUDE, "claude", parent=1)))
        record = FakeRecord()
        monitor.attach(record, CONTAINER)
        sink.send(
            framed(told.SYSCALL_CONNECT, connected(2, sockaddr("203.0.113.9", 443)))
        )
        lines = self.wait_for(record, 4)
        assert lines[0] == {"note": procwatch.Note.MONITORED}
        assert [line.get("pid") for line in lines[1:3]] == [1, 2]
        assert lines[3]["to"] == "203.0.113.9"
        assert monitor.told

    def test_a_sandbox_of_another_container_is_let_go_of(self):
        monitor = self.listening()
        record = FakeRecord()
        monitor.attach(record, CONTAINER)
        sink = self.connect(monitor)
        sink.recv(64)
        sink.send(framed(told.CONTAINER_START, started("/bin/sh", container="b" * 64)))
        assert sink.recv(64) == b""
        assert record.lines == []
        assert not monitor.told

    def test_what_was_dropped_is_counted_in_the_record(self):
        monitor = self.listening()
        record = FakeRecord()
        monitor.attach(record, CONTAINER)
        sink = self.connect(monitor)
        sink.recv(64)
        sink.send(framed(told.SENTRY_EXEC, execed(2, CLAUDE, "claude"), dropped=7))
        lines = self.wait_for(record, 3)
        assert {"dropped": 7} in lines

    def test_a_sandbox_of_an_older_protocol_is_refused(self):
        monitor = self.listening()
        sink = self.connect(monitor, version=0)
        assert sink.recv(64) == b""


class PointedAtTest(LauncherTest):
    def test_the_file_of_the_runtime_points_at_the_socket_while_held(self):
        held = told.pointed_at(self.host, "/s/one.sock")
        assert held is not None
        config = json.loads(Path(self.host.pod_init_config).read_text())
        (sink,) = config["trace_session"]["sinks"]
        assert sink["config"]["endpoint"] == "/s/one.sock"
        # Another launcher waits, then goes without
        with mock.patch.object(told, "LOCK_WAIT", 0.3):
            assert told.pointed_at(self.host, "/s/two.sock") is None
        held.release()
        held.release()
        again = told.pointed_at(self.host, "/s/two.sock")
        assert again is not None
        again.release()
        config = json.loads(Path(self.host.pod_init_config).read_text())
        assert (
            config["trace_session"]["sinks"][0]["config"]["endpoint"] == "/s/two.sock"
        )
        assert not list(Path(self.host.gvisor_dir).glob("pod-init.json.*"))

    def test_the_lock_is_one_other_launchers_see(self):
        held = told.pointed_at(self.host, "/s/one.sock")
        assert held is not None
        lock = os.open(Path(self.host.gvisor_dir, "pod-init.lock"), os.O_RDWR)
        self.cleanup.callback(os.close, lock)
        with pytest.raises(BlockingIOError):
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        held.release()
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)

    def test_a_lock_that_cannot_be_opened_is_gone_without(self):
        # A directory where the lock goes, which cannot be opened to write
        Path(self.host.gvisor_dir, "pod-init.lock").mkdir(parents=True)
        assert told.pointed_at(self.host, "/s/one.sock") is None

    def test_waiting_for_another_launcher_is_said_once(self):
        held = told.pointed_at(self.host, "/s/one.sock")
        assert held is not None
        self.cleanup.callback(held.release)
        with (
            mock.patch.object(told, "LOCK_WAIT", 0.5),
            mock.patch.object(told, "ASK_EVERY", 0.05),
            mock.patch.object(told, "warn") as warned,
        ):
            assert told.pointed_at(self.host, "/s/two.sock") is None
        (said,) = warned.call_args_list
        assert self.host.pod_init_config in said.args[0]


class SessionMonitoredTest(LauncherTest):
    def monitored(self) -> runtime.Runtime:
        return gvisor(f"--pod-init-config={self.host.pod_init_config}")

    @gvisor_socket
    def test_a_sandbox_that_told_nothing_is_said_once_the_session_is_over(self):
        with (
            mock.patch.object(told, "SOON_OVER", 0),
            mock.patch.object(told, "warn") as warned,
            told.session_monitored(
                self.host, "claude-proj", self.monitored(), session_secrets()
            ) as monitor,
        ):
            assert monitor is not None
            monitor.sandbox_made()
            monitor.attach(FakeRecord(), CONTAINER)
        (said,) = warned.call_args_list
        assert "did not connect" in said.args[0]
        assert not Path(monitor.path).exists()

    @gvisor_socket
    def test_a_session_whose_record_never_began_is_not_said_to_be_untold(self):
        with (
            mock.patch.object(told, "SOON_OVER", 0),
            mock.patch.object(told, "warn") as warned,
            told.session_monitored(
                self.host, "claude-proj", self.monitored(), session_secrets()
            ) as monitor,
        ):
            assert monitor is not None
        assert warned.call_args_list == []

    def test_a_runtime_that_cannot_tell_is_not_listened_for(self):
        with told.session_monitored(
            self.host, "claude-proj", gvisor(), session_secrets()
        ) as monitor:
            assert monitor is None
