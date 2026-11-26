#!/usr/bin/env python3
"""The record of what runs in a session: the watcher, its sidecar, and
what --trace shows of it."""

from __future__ import annotations

import dataclasses
import io
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import types
from datetime import UTC, datetime
from pathlib import Path
from unittest import mock

import pytest
from harness import LauncherTest, prompts_at, reads_proc, records
from test_capture import pcap_file, tcp

from claude_airlock.events import Event, Who
from claude_airlock.recording import health, processes, procwatch, sidecar
from claude_airlock.recording.records import TracedSession
from claude_airlock.report import follow, net_events, unseen

SIDECAR = "claude-proj.procs"


def noted(*lines: dict) -> processes.ProcessRecord:
    record = processes.ProcessRecord()
    for line in lines:
        record.take(json.dumps(line))
    return record


def ran(when: float, pid: int, parent: int, *argv: str) -> dict:
    return {
        "t": when,
        "pid": pid,
        "ppid": parent,
        "exe": f"/usr/bin/{argv[0]}",
        "argv": list(argv),
    }


class WatcherTest:
    def test_addresses_are_read_as_the_kernel_writes_them(self):
        if sys.byteorder != "little":
            pytest.skip("written for a little-endian machine")
        for encoded, address in (
            ("0100007F", "127.0.0.1"),
            ("0A68A08E", "142.160.104.10"),
            ("00000000000000000000000001000000", "::1"),
            ("B80D0120000000000000000009000000", "2001:db8::9"),
            # IPv4 inside IPv6, as it goes over the wire
            ("0000000000000000FFFF00000A68A08E", "142.160.104.10"),
        ):
            assert procwatch.address(encoded) == address

    @reads_proc
    def test_a_process_and_the_holder_of_a_connection_are_seen(self):
        with socket.socket() as server:
            server.bind(("127.0.0.1", 0))
            server.listen(1)
            sleeper = subprocess.Popen(["sleep", "30"])
            try:
                with socket.create_connection(server.getsockname()) as client:
                    port = client.getsockname()[1]
                    key = (port, "127.0.0.1", server.getsockname()[1])
                    found, _ = procwatch.sockets()
                    assert key in found
                    holders = procwatch.Holders().of({found[key]}, [os.getpid()])
                    assert holders == {found[key]: [os.getpid()]}
                out = io.StringIO()
                procwatch.Watch(out).look()
                seen = [json.loads(line) for line in out.getvalue().splitlines()]
                (slept,) = (line for line in seen if line.get("pid") == sleeper.pid)
                assert slept["argv"] == ["sleep", "30"]
                assert slept["ppid"] == os.getpid()
                assert slept["exe"].endswith("sleep")
                # Not the watcher itself
                assert not [l for l in seen if l.get("pid") == os.getpid()]
            finally:
                sleeper.kill()
                sleeper.wait()

    def test_the_record_stops_at_its_size_limit(self):
        out = io.StringIO()
        watch = procwatch.Watch(out)
        big = "x" * (procwatch.MOST_BYTES // 4)
        for _ in range(6):
            watch.note(note=big)
        assert len(out.getvalue()) <= procwatch.MOST_BYTES + 100
        assert json.loads(out.getvalue().splitlines()[-1])["note"] == "full"

    def test_a_record_filled_by_what_is_reserved_says_so_as_its_last_line(self):
        out = io.StringIO()
        watch = procwatch.Watch(out)
        big = "x" * (procwatch.MOST_BYTES // 4)
        # Nothing but connections: the part of the processes never fills
        for port in range(6):
            watch.note(reserved=True, port=port, to=big, to_port=443, pids=[7])
        said = [json.loads(line) for line in out.getvalue().splitlines()]
        assert [line.get("note") for line in said[-2:]] == [None, "full"]
        assert noted(*said).full
        # And nothing after it, a word of the watcher's own neither
        watch.note(reserved=True, note=procwatch.Note.ALIVE)
        watch.note(pid=2, argv=["late"])
        assert len(out.getvalue().splitlines()) == len(said)
        assert len(out.getvalue()) <= procwatch.MOST_BYTES

    def test_sockets_on_its_own_loopback_leave_room_for_what_others_reach(self):
        out = io.StringIO()
        watch = procwatch.Watch(out)
        # As many as fill the record, opened and closed between two looks
        ports = range(20000, 22000)
        line = len(procwatch.stamped(listen=20000, on="127.0.0.1", pids=[]))
        with mock.patch.object(
            procwatch, "MOST_BYTES", procwatch.RESERVED + 50 * len(ports) * line
        ):
            for _ in range(60):
                watch._look_at_listeners(
                    {(p, "127.0.0.1", 0): str(p) for p in ports}, []
                )
                watch._look_at_listeners({}, [])
            watch._look_at_listeners({(8080, "0.0.0.0", 0): "1"}, [])
            watch._look_at_connections({(40212, "203.0.113.9", 443): "2"}, [])
            watch._look_at_connections({(40212, "203.0.113.9", 443): "2"}, [])
            watch._look_at_connections({(40212, "203.0.113.9", 443): "2"}, [])
            watch.note(reserved=True, note=procwatch.Note.ALIVE)
        said = [json.loads(line) for line in out.getvalue().splitlines()]
        assert sum(line.get("note") == "full" for line in said) == 1
        # All that came after the part of the processes was full is there
        after = said[[line.get("note") for line in said].index("full") + 1 :]
        assert [line["listen"] for line in after if "listen" in line] == [8080]
        assert [line["to"] for line in after if "to" in line] == ["203.0.113.9"]
        assert after[-1]["note"] == "alive"
        assert noted(*said).full

    def test_a_connection_on_its_own_loopback_is_not_noted(self):
        out = io.StringIO()
        watch = procwatch.Watch(out)
        local = {(40000, "127.0.0.1", 5432): "1", (40001, "::1", 5432): "2"}
        for _ in range(procwatch.MOST_TRIES + 1):
            watch._look_at_connections({**local, (40002, "203.0.113.9", 443): "3"}, [])
        said = [json.loads(line) for line in out.getvalue().splitlines()]
        assert [line["to"] for line in said if "to" in line] == ["203.0.113.9"]

    def test_a_process_cannot_fill_the_record_with_its_command_line(self):
        long = b"\0".join([b"x" * 5000] * 200) + b"\0"
        kept = procwatch.command_line(long)
        assert kept[-1] == procwatch.CUT
        assert sum(map(len, kept)) <= procwatch.MOST_COMMAND + 3
        # One that fits is left as it is, an empty argument too
        assert procwatch.command_line(b"sh\x00-c\x00\x00") == ["sh", "-c", ""]
        assert procwatch.command_line(b"") == []

    def test_room_is_kept_for_the_connections_once_the_processes_filled_theirs(self):
        out = io.StringIO()
        watch = procwatch.Watch(out)
        big = "x" * (procwatch.MOST_BYTES // 4)
        for _ in range(6):
            watch.note(pid=1, argv=[big])
        watch.note(reserved=True, port=40212, to="203.0.113.9", to_port=443, pids=[7])
        watch.note(pid=2, argv=["late"])
        said = [json.loads(line) for line in out.getvalue().splitlines()]
        assert [line.get("note") for line in said[-2:]] == ["full", None]
        assert said[-1]["to"] == "203.0.113.9"
        assert sum("note" in line for line in said) == 1
        # Until that room is used up too
        for _ in range(3):
            watch.note(reserved=True, note=big)
        assert len(out.getvalue()) <= procwatch.MOST_BYTES

    def test_running_into_the_limit_of_processes_is_noted_when_it_grows(self):
        with tempfile.TemporaryDirectory() as root:
            events = Path(root, "1", "root", "sys", "fs", "cgroup", "pids.events")
            events.parent.mkdir(parents=True)
            assert procwatch.limit_hits(1, root) is None
            events.write_text("max 3\n")
            assert procwatch.limit_hits(1, root) == 3
            events.write_text("nothing of the kind\n")
            assert procwatch.limit_hits(1, root) is None
        out = io.StringIO()
        watch = procwatch.Watch(out)
        for hits in (0, 2, 2, 5, None):
            with mock.patch.object(procwatch, "limit_hits", return_value=hits):
                watch._look_at_limits([1, 7])
        said = [json.loads(line) for line in out.getvalue().splitlines()]
        assert [line["hits"] for line in said] == [2, 5]
        assert noted(*said).process_limit == 5

    def test_looks_that_come_late_are_noted_with_how_late(self):
        out = io.StringIO()
        watch = procwatch.Watch(out)

        def slow() -> list[dict]:
            lines = map(json.loads, out.getvalue().splitlines())
            return [line["slow"] for line in lines if "slow" in line]

        # In time twice, then held up by what the session has it read
        now = 1000.0
        for apart in (0.0, procwatch.INTERVAL, 0.05, 0.5):
            now += apart
            watch._keep_pace(now)
        # Said at once
        assert slow() == [{"looks": 1, "seconds": 0.5, "longest": 0.5}]
        said_at = now
        for apart in (0.3, procwatch.INTERVAL, 0.9):
            now += apart
            watch._keep_pace(now)
        assert len(slow()) == 1
        # Then no more often than every so many seconds, with how many
        # came late since, and nothing more once they come in time
        while now < said_at + 2 * procwatch.SLOW_EVERY:
            now += procwatch.INTERVAL
            watch._keep_pace(now)
        assert slow()[1:] == [{"looks": 2, "seconds": 1.2, "longest": 0.9}]
        record = noted(*map(json.loads, out.getvalue().splitlines()))
        assert [(found.looks, found.seconds) for found in record.slowed] == [
            (1, 0.5),
            (2, 1.2),
        ]

    @reads_proc
    def test_every_look_is_held_against_the_one_before_it(self):
        watch = procwatch.Watch(io.StringIO())
        with mock.patch.object(watch, "_keep_pace") as paced:
            before = time.monotonic()
            watch.look()
            watch.look()
        first, second = (began for ((began,), _) in paced.call_args_list)
        assert before <= first <= second <= time.monotonic()

    @reads_proc
    def test_a_socket_that_waits_for_connections_is_noted_once(self):
        with socket.socket() as server:
            server.bind(("127.0.0.1", 0))
            server.listen(1)
            port = server.getsockname()[1]
            connected, waiting = procwatch.sockets()
            assert (port, "127.0.0.1", 0) in waiting
            assert port not in [key[0] for key in connected]
            out = io.StringIO()
            watch = procwatch.Watch(out)
            watch.look()
            watch.look()
        seen = [json.loads(line) for line in out.getvalue().splitlines()]
        ours = [line for line in seen if line.get("listen") == port]
        assert [line["on"] for line in ours] == ["127.0.0.1"]

    def holding(self, out: io.StringIO) -> procwatch.Watch:
        """A watcher that knows of a shell, of curl started by it, and
        finds curl to hold whatever socket it is asked about."""
        watch = procwatch.Watch(out)
        watch._processes = {
            640: (("1", "/bin/bash", ["bash"]), 0.0, 0.0),
            812: (("2", "/usr/bin/curl", ["curl", "-sS"]), 0.0, 0.0),
        }
        watch._parents = {640: 1, 812: 640}
        watch._holders.of = lambda inodes, pids: {inode: [812] for inode in inodes}
        return watch

    def test_who_holds_a_connection_is_said_aloud_with_those_it_comes_from(self):
        out, aloud = io.StringIO(), io.StringIO()
        watch = self.holding(out)
        with mock.patch.object(sys, "stdout", aloud):
            watch._look_at_connections({(40212, "203.0.113.9", 443): "7"}, [812])
            watch._look_at_connections(
                {(40212, "203.0.113.9", 443): "7", (40213, "203.0.113.9", 443): "8"},
                [812],
            )
            # On the session's own loopback, which nothing else reaches
            watch._look_at_listeners({(8000, "127.0.0.1", 0): "9"}, [812])
            watch._look_at_listeners({(8080, "0.0.0.0", 0): "10"}, [812])
        said = [json.loads(line) for line in aloud.getvalue().splitlines()]
        # The process and where it comes from, once, then each socket
        assert [(line.get("pid"), line.get("ppid")) for line in said[:2]] == [
            (812, 640),
            (640, 1),
        ]
        assert said[0]["argv"] == ["curl", "-sS"]
        assert [line.get("port") or line.get("listen") for line in said[2:]] == [
            40212,
            40213,
            8080,
        ]
        # And what follows the session reads it as the record is read
        record = noted(*said)
        (made,) = record.holder(40213, "203.0.113.9", 443, said[3]["t"])[:1]
        assert (made.pid, made.command) == (812, "curl -sS")
        assert [listener.port for listener in record.listeners] == [8080]
        # The record has the sockets, and no process twice for them
        kept = [json.loads(line) for line in out.getvalue().splitlines()]
        assert [line for line in kept if "pid" in line] == []
        assert len([line for line in kept if "port" in line]) == 2

    def test_a_process_that_became_another_program_is_said_again(self):
        out, aloud = io.StringIO(), io.StringIO()
        watch = self.holding(out)
        with mock.patch.object(sys, "stdout", aloud):
            watch._look_at_connections({(40212, "203.0.113.9", 443): "7"}, [812])
            watch._processes[812] = (("2", "/usr/bin/ssh", ["ssh"]), 0.0, 0.0)
            watch._look_at_connections(
                {(40212, "203.0.113.9", 443): "7", (40213, "203.0.113.9", 22): "8"},
                [812],
            )
        said = [json.loads(line) for line in aloud.getvalue().splitlines()]
        assert [line["exe"] for line in said if "exe" in line] == [
            "/usr/bin/curl",
            "/bin/bash",
            "/usr/bin/ssh",
        ]

    def test_no_more_is_said_aloud_of_connections_than_docker_is_to_keep(self):
        out, aloud = io.StringIO(), io.StringIO()
        watch = self.holding(out)
        with (
            mock.patch.object(sys, "stdout", aloud),
            mock.patch.object(procwatch, "MOST_ALOUD", 2000),
        ):
            for port in range(40000, 40100):
                watch._look_at_connections({(port, "203.0.113.9", 443): str(port)}, [])
            # How the session is doing is still said, every so often
            watch.say(health={"cpu": 1.0})
        said = [json.loads(line) for line in aloud.getvalue().splitlines()]
        assert len(aloud.getvalue()) < 2500
        assert [line.get("note") for line in said[-2:]] == ["hushed", None]
        assert "health" in said[-1]
        assert sum(line.get("note") == "hushed" for line in said) == 1
        assert noted(*said).hushed_at == said[-2]["t"]
        # The record has them all
        kept = [json.loads(line) for line in out.getvalue().splitlines()]
        assert len([line for line in kept if "port" in line]) == 100


class RecordTest:
    @pytest.fixture(autouse=True)
    def noted_record(self) -> None:
        self.record = noted(
            ran(10.0, 7, 1, "claude"),
            ran(20.0, 640, 7, "bash", "-c", "curl https://a.test"),
            # First seen as a copy of the shell, then as what it became
            ran(20.1, 812, 640, "bash", "-c", "curl https://a.test"),
            ran(20.2, 812, 640, "curl", "https://a.test"),
            {
                "t": 20.3,
                "port": 40443,
                "to": "198.51.100.7",
                "to_port": 443,
                "pids": [812],
            },
            {
                "t": 20.3,
                "port": 50000,
                "to": "10.0.0.1",
                "to_port": 80,
                "pids": [640, 7],
            },
        )

    def test_a_connection_is_tied_to_the_process_that_held_it(self):
        lineage = self.record.holder(40443, "198.51.100.7", 443, 20.25)
        assert [p.pid for p in lineage] == [812, 640, 7]
        assert (
            processes.shown_lineage(lineage)
            == "[812] curl https://a.test < bash < claude"
        )

    def test_of_several_that_hold_a_socket_it_is_the_one_started_last(self):
        (first, _) = self.record.holder(50000, "10.0.0.1", 80, 20.3)
        assert first.pid == 640

    def test_no_process_is_made_up_for_a_connection(self):
        assert self.record.holder(40443, "198.51.100.7", 80, 20.3) == []
        # The same ports long after are another connection
        assert self.record.holder(40443, "198.51.100.7", 443, 900.0) == []

    def test_a_process_is_named_by_its_program_not_by_what_it_says(self):
        record = noted(
            {"t": 1, "pid": 5, "ppid": 1, "exe": "/tmp/x", "argv": ["sshd", "-D"]}
        )
        assert record.processes[0].command == "x -D"

    def test_a_process_whose_program_cannot_be_read_is_named_as_its_own_word(self):
        # One that keeps its program from being read, and calls itself
        # git: its command line is all there is, and is said to be that
        record = noted(
            ran(1.0, 4, 1, "bash"),
            {"t": 2, "pid": 5, "ppid": 4, "exe": "", "argv": ["/usr/bin/git", "fetch"]},
            {"t": 3, "pid": 6, "ppid": 5, "exe": "/usr/bin/curl", "argv": ["curl"]},
        )
        hidden = record.processes[1]
        assert (hidden.name, hidden.command) == ("git?", "git? fetch")
        assert processes.shown_lineage(record.lineage(6, 4.0)) == (
            "[6] curl < git? < bash"
        )
        ran_then = net_events._process_events(record)
        assert ran_then[1].details == [
            "[5] git? fetch",
            "exe: NOT READABLE, it is named as it says itself",
            "parent: [4] bash",
        ]
        assert ran_then[2].details[1:] == ["exe: /usr/bin/curl", "parent: [5] git?"]

    def test_a_line_that_does_not_hold_up_is_passed_over(self):
        record = processes.ProcessRecord()
        for line in (
            "[" * 100_000,
            "{}",
            '{"t": 1, "pid": "x"}',
            '{"t": 1, "port": 1}',
        ):
            record.take(line)
        assert (record.processes, record.holders) == ([], {})
        record.take('{"t": 1, "note": "full"}')
        assert record.full

    def test_a_parent_that_names_itself_ends_the_line(self):
        record = noted(ran(1.0, 5, 5, "loop"))
        assert len(record.lineage(5, 2.0)) == 1

    def test_what_a_watcher_says_of_its_late_looks_is_read(self):
        record = noted(
            {"t": 5.0, "slow": {"looks": 3, "seconds": 1.5, "longest": 0.9}},
            # What does not hold up is passed over
            {"t": 6.0, "slow": {"looks": "many", "seconds": 1, "longest": 1}},
            {"t": 7.0, "slow": [3, 1.5, 0.9]},
            {"t": 8.0, "slow": {"looks": 1, "seconds": float("nan"), "longest": 1}},
            {"t": 9.0, "slow": {"looks": 0, "seconds": 0.0, "longest": 0.0}},
            {"t": 9.5, "slow": {"looks": 1, "seconds": 0.5, "longest": 0.9}},
        )
        assert record.slowed == [processes.Slowed(5.0, 3, 1.5, 0.9)]
        # A word of the watcher, as any other line is
        assert record.last_line == 9.5

    def test_a_watcher_that_was_slowed_is_said_once_it_tells(self):
        # A little late is how looks come under load, and is not said
        late = noted({"t": 5.0, "slow": {"looks": 3, "seconds": 1.5, "longest": 0.9}})
        assert net_events.slowed(late) == ""
        slowed = noted(
            ran(1.0, 812, 7, "make"),
            {"t": 5.0, "slow": {"looks": 3, "seconds": 1.5, "longest": 0.9}},
            {"t": 15.0, "slow": {"looks": 9, "seconds": 8.0, "longest": 2.25}},
            {"t": 25.0, "slow": {"looks": 4, "seconds": 6.0, "longest": 1.5}},
        )
        said = (
            "the record of its processes has GAPS, its watcher was slowed: its"
            " looks came up to 2.2s apart, for 14s in all, what ran for less"
            " then may be missing"
        )
        assert net_events.slowed(slowed) == said
        assert f"  {said}" in net_events.watched_summary(slowed, False)


GIB = 2**30


def command(when: float, seconds: float | None = 1.0, **fields: object) -> Event:
    """A command of a transcript, issued at a time, whose result came so
    many seconds later, none for one without a result."""
    took = {} if seconds is None else {"seconds": seconds}
    said = {"tool": "Bash", **took, **fields}
    # The call of a tool, as the transcript's side of a trace makes them
    return Event(when, Who.CLAUDE, "bash", ["$ true"], said, call=True)


class UnseenTest:
    @pytest.fixture(autouse=True)
    def watched_record(self) -> None:
        self.record = noted({"t": 100.0, "note": "started"}, ran(110.0, 812, 7, "make"))
        self.session = TracedSession(
            "claude-proj", "/proj", 99.0, processes="p", end=200.0, until=200.0
        )

    def marked(self, *events: Event, record: processes.ProcessRecord | None = None):
        watched = [(self.session, record or self.record)]
        return unseen.mark_unseen(events, watched), [
            unseen.UNSEEN in event.fields for event in events
        ]

    def test_a_command_no_process_was_seen_of_says_so(self):
        seen, missed = command(109.5), command(120.0, 0.01)
        assert self.marked(seen, missed) == (1, [False, True])
        assert missed.details[-1] == unseen.SAID
        assert unseen.SAID not in seen.details
        # Not something gone wrong: the line is not marked as that
        assert missed.alerts == set()

    def test_a_process_noted_a_moment_after_the_result_is_still_its(self):
        within = unseen.NOTED_WITHIN
        assert self.marked(command(109.0, 1 - within / 2))[0] == 0
        assert self.marked(command(110.0 + within / 2, 0.1))[0] == 0
        assert self.marked(command(108.0, 1.0))[0] == 1

    def test_what_is_not_known_to_have_run_is_left_alone(self):
        for event in (
            # Not let run, without a result, another tool, and a result
            # said to have come before its command
            command(120.0, refused=True),
            command(120.0, None),
            command(120.0, tool="Read"),
            command(120.0, -5.0),
        ):
            assert self.marked(event) == (0, [False])

    def test_nothing_is_said_where_the_record_cannot_tell(self):
        # Before the watcher was up, and after the session was over
        assert self.marked(command(99.5, 0.1))[0] == 0
        assert self.marked(command(199.5))[0] == 0
        # Once it had no room for processes, and up to then
        full = noted(
            {"t": 100.0, "note": "started"},
            ran(110.0, 812, 7, "make"),
            {"t": 150.0, "note": "full"},
        )
        assert self.marked(command(160.0), record=full)[0] == 0
        assert self.marked(command(120.0), record=full)[0] == 1
        # Written from outside the session, and by a watcher that never
        # got to watch
        outside = noted({"t": 100.0, "note": "started", "outside": "gVisor"})
        assert self.marked(command(120.0), record=outside)[0] == 0
        assert self.marked(command(120.0), record=noted())[0] == 0
        assert unseen.mark_unseen([command(120.0)], []) == 0

    def test_a_watcher_that_stopped_before_the_command_cannot_tell(self):
        # It says every 10 seconds that it is there, and said so until 130
        died = noted(
            {"t": 100.0, "note": "started", "beat": 10.0},
            {"t": 130.0, "note": "alive"},
            ran(110.0, 812, 7, "make"),
        )
        assert self.marked(command(120.0), record=died)[0] == 1
        assert self.marked(command(150.0), record=died)[0] == 1
        # Past what it would be silent for, nothing seen is not none ran
        assert self.marked(command(190.0), record=died)[0] == 0
        # One that never said it would is taken as it always was
        silent = noted({"t": 100.0, "note": "started"}, ran(110.0, 812, 7, "make"))
        assert self.marked(command(190.0), record=silent)[0] == 1
        # Any line is a sign of life, not only the beat
        busy = noted(
            {"t": 100.0, "note": "started", "beat": 10.0}, ran(180.0, 812, 7, "make")
        )
        assert self.marked(command(190.0), record=busy)[0] == 1

    def test_a_watcher_that_went_silent_before_its_session_ended_is_said(self):
        died = noted(
            {"t": 100.0, "note": "started", "beat": 10.0},
            {"t": 130.0, "note": "alive"},
            ran(110.0, 812, 7, "make"),
        )
        # To its end, and well before it
        assert died.silent_from(150.0) is None
        assert died.silent_from(500.0) == 130.0
        assert net_events.watched_summary(died, False, 150.0) == [
            "  processes 1 seen to run, each one shown with --verbose"
        ]
        last = f"{datetime.fromtimestamp(130.0):%H:%M:%S}"
        assert net_events.watched_summary(died, False, 500.0)[1] == (
            "  the record of its processes is INCOMPLETE, its watcher said"
            f" nothing after {last}: what ran later is missing"
        )
        # One that never said how often it would, or never got to watch
        assert noted({"t": 100.0, "note": "started"}).silent_from(500.0) is None
        assert noted().silent_from(500.0) is None

    def test_a_watcher_that_goes_silent_is_said_while_following(self):
        now = [1000.0]
        heard: list[health.Sample] = []
        with mock.patch.object(follow.time, "monotonic", lambda: now[0]):
            tail = follow.HealthTail("claude-proj", lambda _since: heard[:])
            now[0] += follow.SILENT_AFTER - 1
            assert tail.poll() == []
            assert tail.newly_silent() is None
            now[0] += 2
            assert tail.newly_silent() == follow.SILENT_AFTER + 1
            # Once, until it is heard again
            now[0] += 100
            assert tail.newly_silent() is None
            heard.append(health.Sample(time.time() + 5))
            assert len(tail.poll()) == 1
            assert tail.newly_silent() is None
            now[0] += follow.SILENT_AFTER + 1
            assert tail.newly_silent() is not None

    def test_a_process_of_any_session_that_ran_then_counts(self):
        other = dataclasses.replace(self.session, name="claude-proj-2", start=125.0)
        theirs = noted({"t": 125.0, "note": "started"}, ran(130.0, 9, 7, "true"))
        watched = [(self.session, self.record), (other, theirs)]
        assert unseen.mark_unseen([command(130.0, 0.1)], watched) == 0
        assert unseen.mark_unseen([command(140.0, 0.1)], watched) == 1
        # Before the other session ran it is not asked, and a command
        # that was running as it started may be its own
        assert unseen.mark_unseen([command(120.0, 0.1)], watched) == 1
        assert unseen.mark_unseen([command(124.5)], watched) == 0

    def test_the_header_counts_them(self):
        assert unseen.unseen_summary(0) == []
        assert "1 command ran with no process" in unseen.unseen_summary(1)[0]
        assert "3 commands ran with no process" in unseen.unseen_summary(3)[0]


class FakeSession:
    """What a watcher reads of a session, made up in a directory: the
    cgroup of its container and its processes."""

    def __init__(self, root: Path, cgroup: Path | None = None):
        self.proc = root
        self.first = root / "1"
        # Under the root of the first process, unless another place is given
        self.cgroup = cgroup or self.first / "root" / "sys" / "fs" / "cgroup"
        self.cgroup.mkdir(parents=True)
        (self.first / "root" / "tmp").mkdir(parents=True)
        (self.first / "mounts").write_text(
            "proc /proc proc rw 0 0\n"
            "tmpfs /dev tmpfs rw 0 0\n"
            "tmpfs /sys/fs/cgroup tmpfs ro 0 0\n"
            "tmpfs /tmp tmpfs rw,size=4194304k 0 0\n"
            "overlay / overlay ro 0 0\n"
        )
        self.set("memory.max", str(16 * GIB))
        self.set("pids.max", "512")
        self.set("cpu.max", "150000 100000")
        self.set("memory.events", "low 0\nhigh 0\nmax 0\noom 0\noom_kill 0")
        self.use()

    def set(self, name: str, said: str) -> None:
        (self.cgroup / name).write_text(said + "\n")

    def use(
        self,
        memory: float = 1.0,
        cpu_seconds: float = 0.0,
        throttled_seconds: float = 0.0,
        processes: int = 20,
        waited_for_memory: float = 0.0,
    ) -> None:
        """What the session has used by now: memory in GiB, the rest as
        it has added up since it started."""
        cached = GIB // 4
        self.set("memory.current", str(int(memory * GIB) + cached))
        self.set("memory.stat", f"anon 5\ninactive_file {cached}\nactive_file 7")
        self.set("pids.current", str(processes))
        self.set(
            "cpu.stat",
            f"usage_usec {int(cpu_seconds * 1e6)}\nuser_usec 1\nnr_throttled 3\n"
            f"throttled_usec {int(throttled_seconds * 1e6)}",
        )
        waited = int(waited_for_memory * 1e6)
        self.set("memory.pressure", f"some avg10=0.00 total={waited}\nfull total=0")
        self.set("cpu.pressure", "some avg10=0.00 avg60=0.00 avg300=0.00 total=0")

    def run(self, pid: int, megabytes: int) -> None:
        directory = self.proc / str(pid)
        directory.mkdir(exist_ok=True)
        pages = megabytes * 2**20 // procwatch.PAGE
        (directory / "statm").write_text(f"{pages * 2} {pages} 10 1 0 5 0\n")


class HealthWatchTest:
    @pytest.fixture(autouse=True)
    def watch_of_a_session(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        self.session = FakeSession(tmp_path)
        self.out = io.StringIO()
        # What it says aloud is not for the output of the tests
        monkeypatch.setattr(sys, "stdout", io.StringIO())
        # Its tmpfs is a directory of this machine, whose disk is as full
        # as it is: a quarter of the 4 GiB the session's is said to have
        block = 4096
        tmpfs = types.SimpleNamespace(
            f_frsize=block, f_blocks=4 * GIB // block, f_bfree=3 * GIB // block
        )
        monkeypatch.setattr(procwatch.os, "statvfs", lambda _place: tmpfs)
        self.watch = procwatch.Watch(self.out)
        self.watch._processes[812] = (
            ("9", "/usr/bin/node", ["node", "build.js"]),
            0,
            0,
        )
        self.health = self.reader()
        self.session.run(1, 1)
        self.session.run(812, 900)
        self.pids = [1, 812]

    def reader(self) -> procwatch.Health:
        return procwatch.Health(
            self.watch.say, self.watch.name_of, str(self.session.proc)
        )

    def said(self) -> list[dict]:
        return [json.loads(line) for line in self.out.getvalue().splitlines()]

    def test_how_the_session_is_doing_is_noted_every_so_often(self):
        self.health.look(self.pids, 100.0)
        # Nothing to compare with yet
        assert self.said() == []
        self.session.use(memory=2.0, cpu_seconds=3.0, throttled_seconds=0.5)
        self.health.look(self.pids, 102.0)
        (line,) = self.said()
        health = line["health"]
        # Without what the kernel keeps of files and gives back when asked
        assert health["mem"] == [2 * GIB, 16 * GIB]
        assert health["pids"] == [20, 512]
        assert (health["cpu"], health["cpus"]) == (150.0, 1.5)
        assert (health["throttled"], health["seconds"]) == (0.5, 2.0)
        assert health["stalled"] == {"memory": 0.0, "cpu": 0.0}
        # Of the tmpfs only the session's own, as large as it is
        assert health["tmpfs"] == {"/tmp": [GIB, 4 * GIB]}
        assert health["top"][0] == [812, 900 * 2**20, "node"]
        assert "rose" not in health
        # Not again before its time, then with what was used since
        self.session.use(memory=2.0, cpu_seconds=18.0)
        self.health.look(self.pids, 102.0 + procwatch.HEALTH_EVERY - 1)
        assert len(self.said()) == 1
        self.health.look(self.pids, 102.0 + procwatch.HEALTH_EVERY)
        assert self.said()[-1]["health"]["cpu"] == 50.0

    def test_coming_near_a_limit_is_noted_out_of_turn_and_not_over_and_over(self):
        self.health.look(self.pids, 100.0)
        self.health.look(self.pids, 101.0)
        for second, memory in enumerate((12.0, 11.5, 12.5, 15.0, 15.2, 9.0, 12.0)):
            self.session.use(memory=memory)
            self.health.look(self.pids, 110.0 + 6 * second)
        rose = [line["health"].get("rose") for line in self.said()]
        # Near at 12, at it at 15, and near again only once well below
        assert rose == [None, ["memory"], ["memory"], ["memory"]]
        self.session.use(memory=12.0, processes=500)
        self.health.look(self.pids, 152.0)
        assert self.said()[-1]["health"]["rose"] == ["pids"]
        # Found at a limit, which the first line says. Then to just under
        # the mark below it and up again: near once more is not news, at
        # it is
        steady = self.reader()
        for second, memory in enumerate((15.0, 10.6, 12.0, 15.0)):
            self.session.use(memory=memory)
            steady.look(self.pids, 300.0 + 40 * second)
        assert [line["health"].get("rose") for line in self.said()[-3:]] == [
            ["memory"],
            None,
            ["memory"],
        ]
        # No more often than that, however the session goes up and down
        before = len(self.said())
        for second in range(4):
            self.session.use(memory=9.0 if second % 2 else 12.0)
            self.health.look(self.pids, 153.0 + second)
        assert len(self.said()) == before

    def test_a_rise_that_came_too_soon_after_another_is_said_when_it_can_be(self):
        self.health.look(self.pids, 100.0)
        self.health.look(self.pids, 101.0)
        self.session.use(memory=12.0)
        self.health.look(self.pids, 102.0)
        self.session.use(memory=15.0)
        self.health.look(self.pids, 103.0)
        assert len(self.said()) == 2
        self.health.look(self.pids, 102.0 + procwatch.OUT_OF_TURN_EVERY)
        assert self.said()[-1]["health"]["rose"] == ["memory"]
        assert len(self.said()) == 3

    def test_the_watcher_and_the_trace_agree_on_what_is_near_a_limit(self):
        # The watcher stands alone in its sidecar, so each has its own
        assert procwatch.NEAR_LIMIT == (health.NEAR_LIMIT, health.AT_LIMIT)

    def test_a_process_ended_for_want_of_memory_is_noted_with_what_is_gone(self):
        self.health.look(self.pids, 100.0)
        self.session.set("memory.events", "oom 1\noom_kill 1")
        self.health.look([1], 101.0)
        ended = [line for line in self.said() if "oom" in line]
        assert ended == [{**ended[0], "oom": 1, "gone": [[812, 900 * 2**20, "node"]]}]
        # Once, and of one that was already counted nothing
        self.health.look([1], 102.0)
        assert sum("oom" in line for line in self.said()) == 1

    def test_what_cannot_be_read_is_left_out_and_the_rest_still_told(self):
        for name in ("memory.current", "cpu.stat", "memory.pressure", "cpu.max"):
            (self.session.cgroup / name).unlink()
        (self.session.first / "mounts").unlink()
        self.health.look(self.pids, 100.0)
        self.health.look(self.pids, 101.0)
        (line,) = self.said()
        assert set(line["health"]) == {"pids", "seconds", "stalled", "top"}, line[
            "health"
        ]

    def test_it_is_said_aloud_too_for_who_follows_the_session(self):
        aloud = io.StringIO()
        with mock.patch.object(sys, "stdout", aloud):
            self.watch.note(aloud=True, health={"cpu": 1.0})
            self.watch.note(pid=5, argv=["quiet"])
        assert aloud.getvalue() == self.out.getvalue().splitlines(True)[0]


class HealthShownTest:
    def sample(self, **said) -> health.Sample:
        found = health.read_health(5.0, {"t": 5.0, "health": said})
        assert isinstance(found, health.Sample)
        return found

    def test_a_sample_is_one_line_with_what_matters(self):
        sample = self.sample(
            mem=[3 * GIB + GIB // 10, 16 * GIB],
            pids=[87, 512],
            cpu=240.4,
            seconds=30.0,
            throttled=0.0,
            tmpfs={"/tmp": [GIB, 4 * GIB], "/home/sandbox/.npm": [GIB // 2, GIB]},
            stalled={"memory": 0.0, "cpu": 0.4, "io": 3.0},
            top=[[812, 2 * GIB, "node"], [7, GIB, "claude"]],
        )
        event = sample.event()
        assert (
            event.details[0] == "mem 3.1g of 16g (19%)  cpu 240%  pids 87 of 512"
            "  /home/sandbox/.npm 50%  waiting on the disk 3% of the time"
            "  top: [812] node 2g"
        )
        # Short of a CPU for some of the time, said with what it used
        busy = self.sample(cpu=348.0, stalled={"memory": 0.0, "cpu": 10.2}).event()
        assert busy.details == ["cpu 348%, short of it 10% of the time"]
        # And by its name when there is no figure of what was used
        bare = self.sample(stalled={"memory": 12.0, "cpu": 2.0}).event()
        assert bare.details[0].endswith(
            "short of memory 12% of the time  short of cpu 2% of the time"
        )
        assert event.what == "health"
        assert "flagged" not in event.fields
        assert event.fields["memory"] == {
            "used": 3 * GIB + GIB // 10,
            "limit": 16 * GIB,
        }
        assert event.fields["top"][0] == {"pid": 812, "rss": 2 * GIB, "name": "node"}

    def test_a_limit_that_is_near_and_one_that_is_reached_are_said(self):
        near = self.sample(mem=[12 * GIB, 16 * GIB], rose=["memory"]).event()
        assert near.details == ["running low on memory  mem 12g of 16g (75%)"]
        assert "flagged" not in near.fields
        reached = self.sample(
            mem=[15 * GIB, 16 * GIB],
            tmpfs={"/tmp": [39, 40]},
            stalled={"memory": 35.0},
            cpu=150.0,
            cpus=1.5,
            throttled=12.0,
            rose=["/tmp"],
        ).event()
        assert (
            reached.details[0]
            == "ALMOST OUT OF memory, /tmp, STALLED for want of memory"
            "  mem 15g of 16g (93%), short of it 35% of the time"
            "  cpu 150% of 1.5 cpus, held back 12.0s  /tmp 97%"
        )
        assert reached.fields["flagged"]

    def test_no_limit_is_no_share_and_a_name_is_the_sessions_to_choose(self):
        event = self.sample(
            mem=[GIB, None], pids=[5, None], top=[[9, GIB, "evil\x1b[31m\nname"]]
        ).event()
        assert event.details == ["mem 1g  pids 5  top: [9] evil[31m\\nname 1g"]

    def test_a_process_that_was_ended_is_said_with_the_likely_one(self):
        ended = health.read_health(
            7.0, {"t": 7.0, "oom": 2, "gone": [[812, 9 * GIB, "node"]]}
        )
        assert ended is not None
        assert ended.event().details == [
            "OUT OF MEMORY, a process was ended for it  gone since: [812] node 9g"
        ]
        unseen = health.read_health(7.0, {"t": 7.0, "oom": 3, "gone": []})
        assert unseen is not None
        assert "which one was not seen" in unseen.event().details[0]
        assert health.read_health(7.0, {"t": 7.0, "pid": 5}) is None

    def test_a_line_that_does_not_hold_up_is_passed_over(self):
        record = noted(
            {"t": 1, "health": {"mem": "lots"}},
            {"t": 1, "health": []},
            {"t": 1, "oom": "often"},
            {"t": 1, "health": {"top": [[1, 2]]}},
            {"t": 2, "health": {"mem": [1, 2]}},
        )
        assert [found.when for found in record.samples] == [2.0]
        assert record.ended == []

    def test_the_header_sums_it_up(self):
        samples = [
            self.sample(
                mem=[2 * GIB, 16 * GIB], cpu=100.0, seconds=30.0, pids=[10, 512]
            ),
            self.sample(
                mem=[9 * GIB, 16 * GIB],
                cpu=400.0,
                seconds=10.0,
                cpus=4,
                throttled=6.0,
                pids=[400, 512],
                tmpfs={"/tmp": [1, 100]},
                stalled={"memory": 22.0},
            ),
        ]
        ended = [health.Ended(8.0, 2)]
        assert health.health_summary(samples, ended) == [
            "  memory 9g of 16g (56%) at most",
            "  cpu 175% on average, 400% at most of 4 cpus, held back 6s in all",
            "  pids 78% of its limit at most",
            "  STALLED for want of memory, up to 22% of the time",
            "  OUT OF MEMORY, a process was ended for it 2 times",
        ]
        assert health.health_summary([], []) == []


class SidecarTest(LauncherTest):
    @pytest.fixture(autouse=True)
    def record_file(self, sandbox: None) -> None:
        self.now = time.time()
        self.record_file = self.work / "processes.jsonl"
        lines = [
            {"t": self.now, "note": "started"},
            ran(self.now + 1, 7, 1, "claude"),
            ran(self.now + 2, 812, 7, "curl", "-sS", "https://good.test"),
            {
                "t": self.now + 2,
                "port": 40443,
                "to": "198.51.100.7",
                "to_port": 443,
                "pids": [812],
            },
        ]
        self.record_file.write_text("".join(json.dumps(line) + "\n" for line in lines))
        self.capture_file = self.work / "capture.pcap"
        self.capture_file.write_bytes(
            pcap_file([(self.now + 2, tcp("198.51.100.7", 443), True)])
        )

    def watched(self, *args: str, session: str = "sleep 1", **env: str):
        return self.launch(
            *args,
            session=session,
            CLAUDE_AIRLOCK_PROC_LOG="1",
            FAKE_RUNNING="claude-proj",
            FAKE_PROCESSES=str(self.record_file),
            **env,
        )

    def test_a_sidecar_joins_the_session_once_it_is_up(self):
        result = self.watched()
        sidecar = result.sidecar(SIDECAR)
        for flag in (
            "--pid=container:claude-proj",
            "--network=container:claude-proj",
            "--user=0:0",
            "--cap-drop=ALL",
            "--security-opt=no-new-privileges",
            "--entrypoint=python3",
        ):
            assert flag in sidecar
        assert [flag for flag in sidecar if flag.startswith("--cap-add=")] == [
            "--cap-add=SETUID",
            "--cap-add=SETGID",
        ]
        assert sidecar[-2:] == [str(os.getuid()), str(os.getgid())]
        # The session is not made to wait for it, nor to depend on it
        assert SIDECAR not in " ".join(result.flags)

    def test_it_joins_the_network_of_the_capture(self):
        result = self.watched(
            CLAUDE_AIRLOCK_NET_LOG="1", FAKE_CAPTURE=str(self.capture_file)
        )
        assert "--network=container:claude-proj.capture" in result.sidecar(SIDECAR)

    def test_the_record_is_copied_out_and_the_sidecar_removed(self):
        result = self.watched()
        (copied,) = (self.state / "processes").glob("*.jsonl")
        assert copied.read_text() == self.record_file.read_text()
        assert ["rm", "--force", SIDECAR] in result.calls
        assert (
            f'"processes": "{copied.name}"'
            in (self.state / "net-sessions.jsonl").read_text()
        )

    def test_a_watcher_that_did_not_get_to_watch_is_said(self):
        self.record_file.write_text("")
        # What docker logs has of the watcher, as the fake docker plays it
        said = self.work / "said"
        said.write_text("OSError: could not take the identity\n")
        result = self.watched(session="sleep 6", FAKE_PROXY_LOG=str(said))
        assert "the processes of this session were not recorded" in result.stderr
        assert "could not take the identity" in result.stderr
        assert list((self.state / "processes").glob("*.jsonl")) == []
        assert not (self.state / "net-sessions.jsonl").exists()

    def test_switched_off_nothing_is_recorded(self):
        result = self.launch(session="sleep 0.5", FAKE_RUNNING="claude-proj")
        assert result.sidecar(SIDECAR) is None

    def test_a_record_left_by_a_killed_session_is_collected(self):
        about = {"project": "/elsewhere", "start": 5, "pid": 2**22 - 7}
        result = self.launch(
            FAKE_PS=f"claude-old.procs\t{json.dumps(about)}",
            FAKE_PROCESSES=str(self.record_file),
        )
        assert ["rm", "--force", "claude-old.procs"] in result.calls
        assert (self.state / "processes" / "claude-old.procs-5.jsonl").exists()

    def test_a_record_left_behind_ends_when_its_watcher_last_wrote(self):
        # Over an hour before the next launcher ran and collected it
        ended = float(round(self.now - 3600))
        said = [
            {"t": ended - 200, "note": "started", "beat": 30.0},
            ran(ended - 100, 7, 1, "claude"),
            {"t": ended, "note": "alive"},
        ]
        self.record_file.write_text("".join(json.dumps(line) + "\n" for line in said))
        os.utime(self.record_file, (ended, ended))
        docker_ok = sidecar.docker_ok

        def copied_as_docker_does(*args: str) -> bool:
            # With the time the file has in the sidecar, which docker cp
            # keeps and the fake docker does not
            done = docker_ok(*args)
            if done and args[0] == "cp":
                shutil.copystat(self.record_file, args[-1])
            return done

        about = {"project": str(self.project), "start": ended - 200, "pid": 2**22 - 7}
        environment = {
            "FAKE_PS": f"claude-old.procs\t{json.dumps(about)}",
            "FAKE_PROCESSES": str(self.record_file),
        }
        with (
            mock.patch.dict(os.environ, environment),
            mock.patch.object(sidecar, "docker_ok", copied_as_docker_does),
        ):
            processes.Watcher.collect_left_behind(self.host)
            (session,) = records.read_traced_sessions(self.host)
            assert (session.name, session.end) == ("claude-old", ended)
            # Its watcher is not said to have gone silent before the end
            record = processes.session_record(self.host, session)
            assert record is not None
            assert record.silent_from(session.end) is None
            # One collected by the launcher of its session ends with it
            mine = processes.Watcher.for_session("claude-proj", str(self.project))
            mine.collect(self.host)
        ends = [session.end or 0 for session in records.read_traced_sessions(self.host)]
        assert ends[0] == ended
        assert ends[1] >= self.now

    def trace(self, *args: str) -> str:
        self.watched(CLAUDE_AIRLOCK_NET_LOG="1", FAKE_CAPTURE=str(self.capture_file))
        self.write_transcript("0a", prompts_at(self.now, self.now + 10))
        result = self.launch("--trace", *args)
        assert result.status == 0, result.stderr
        return result.stdout

    def test_a_session_that_ran_into_its_limits_is_said_to(self):
        with open(self.record_file, "a") as record:
            record.write(json.dumps({"t": self.now + 3, "limit": "pids", "hits": 4}))
            record.write("\n")
        ended = self.watched(FAKE_EVENTS="oom\noom", CLAUDE_AIRLOCK_MEMORY="2g")
        assert "ran into its limit of processes 4 times" in ended.stderr
        assert "ran into its memory limit of 2g 2 times" in ended.stderr
        assert ["events", "--filter=container=claude-proj", "--filter=event=oom"] in [
            call[:3] for call in ended.calls
        ]
        self.write_transcript("0a", prompts_at(self.now, self.now + 10))
        assert (
            "its limit of processes was RUN INTO 4 times"
            in self.launch("--trace").stdout
        )
        # Nothing of either from a session that kept within them
        assert "memory limit" not in self.launch().stderr

    def test_a_socket_that_waits_for_connections_is_said(self):
        waits = [
            {"t": self.now + 3, "listen": 8080, "on": "0.0.0.0", "pids": [812]},
            {"t": self.now + 3, "listen": 9229, "on": "127.0.0.1", "pids": [7]},
            {"t": self.now + 4, "listen": 8080, "on": "0.0.0.0", "pids": [812]},
        ]
        with open(self.record_file, "a") as record:
            record.write("".join(json.dumps(line) + "\n" for line in waits))
        ended = self.watched()
        # Only what the other sessions on its network can reach, and once
        assert "waited for connections, open to the other" in ended.stderr
        assert ended.stderr.count("tcp 0.0.0.0:8080") == 1
        assert "9229" not in ended.stderr
        self.write_transcript("0a", prompts_at(self.now, self.now + 10))
        shown = self.launch("--trace").stdout
        assert re.search(
            r"sandbox  listen      tcp 0\.0\.0\.0:8080  OPEN to its network"
            r"  by: \[812\] curl -sS https://good.test < claude",
            shown,
        )
        assert re.search(r"listen      tcp 127\.0\.0\.1:9229  by: \[7\] claude", shown)
        assert "2 sockets waited for connections, OPEN" in shown

    def test_the_trace_says_how_the_session_was_doing(self):
        lines = [
            {
                "t": self.now + 3,
                "health": {
                    "mem": [2 * GIB, 16 * GIB],
                    "cpu": 80.0,
                    "seconds": 30.0,
                    "pids": [30, 512],
                    "top": [[812, GIB, "curl"]],
                },
            },
            {
                "t": self.now + 4,
                "health": {"mem": [15 * GIB, 16 * GIB], "rose": ["memory"]},
            },
            {"t": self.now + 5, "oom": 1, "gone": [[812, 14 * GIB, "curl"]]},
        ]
        with open(self.record_file, "a") as record:
            record.write("".join(json.dumps(line) + "\n" for line in lines))
        shown = self.trace()
        assert (
            "sandbox  health      mem 2g of 16g (12%)  cpu 80%  pids 30 of 512"
            "  top: [812] curl 1g" in shown
        )
        assert "health      ALMOST OUT OF memory  mem 15g of 16g (93%)" in shown
        assert "gone since: [812] curl 14g" in shown
        assert "#   memory 15g of 16g (93%) at most" in shown
        assert "#   cpu 80% on average, 80% at most" in shown
        assert "#   OUT OF MEMORY, a process was ended for it 1 times" in shown
        # What went wrong of it is what --failed keeps, and --only picks it
        failed = self.launch("--trace", "--failed").stdout
        assert failed.count("sandbox  health") == 2
        assert (
            self.launch("--trace", "--only", "health").stdout.count("  health  ") == 3
        )
        events = map(json.loads, self.launch("--trace", "--json").stdout.splitlines())
        (first, *_) = (e for e in events if e.get("what") == "health")
        assert first["memory"] == {"used": 2 * GIB, "limit": 16 * GIB}

    def test_the_trace_says_which_process_made_a_connection(self):
        stdout = self.trace()
        assert (
            "tcp/https 198.51.100.7:443  by: [812] curl -sS https://good.test < claude"
            in stdout
        )
        assert "#   processes 2 seen to run" in stdout
        assert "sandbox  exec" not in stdout

    def test_the_trace_says_which_command_no_process_was_seen_of(self):
        self.watched(session="sleep 1")
        (copied,) = (self.state / "processes").glob("*.jsonl")
        (line,) = (self.state / "net-sessions.jsonl").read_text().splitlines()
        start, end = (json.loads(line)[key] for key in ("start", "end"))
        # Within the time the session was recorded for, whatever that was
        step = (end - start) / 10
        lines = [{"t": start, "note": "started"}, ran(start + step, 812, 7, "make")]
        copied.write_text("".join(json.dumps(line) + "\n" for line in lines))

        def at(when: float) -> str:
            return datetime.fromtimestamp(when, UTC).isoformat()

        def called(tool_id: str, text: str, began: float) -> list[dict]:
            block = {"type": "tool_use", "id": tool_id, "name": "Bash"}
            given = {**block, "input": {"command": text}}
            back = {"type": "tool_result", "tool_use_id": tool_id, "content": "ok"}
            return [
                {
                    "type": "assistant",
                    "timestamp": at(began),
                    "message": {"content": [given]},
                },
                {
                    "type": "user",
                    "timestamp": at(began + step / 10),
                    "message": {"content": [back]},
                },
            ]

        entries = called("c1", "make all", start + step) + called(
            "c2", "true", start + 6 * step
        )
        self.write_transcript("0a", entries)
        shown = self.launch("--trace").stdout
        assert shown.count("processes: none seen while it ran") == 1
        assert re.search(
            r"\$ true\n.*result: ok.*\n.*bash +processes: none seen while it ran", shown
        )
        assert "#   1 command ran with no process seen" in shown
        # Not what --failed keeps, and a value of its own with --json
        assert "none seen" not in self.launch("--trace", "--failed").stdout
        events = map(json.loads, self.launch("--trace", "--json").stdout.splitlines())
        missed = [e["input"]["command"] for e in events if e.get("unseen")]
        assert missed == ["true"]

    def test_verbose_adds_the_processes(self):
        stdout = self.trace("--verbose")
        assert "sandbox  exec        [812] curl -sS https://good.test" in stdout
        assert "sandbox  exec        parent: [7] claude" in stdout

    def test_json_names_the_process(self):
        events = map(json.loads, self.trace("--json").splitlines())
        (made,) = (e["process"] for e in events if e.get("port") == 443)
        assert (made["pid"], made["parents"]) == (812, ["claude"])
