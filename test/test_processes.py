#!/usr/bin/env python3
"""The record of what runs in a session: the watcher, its sidecar, and
what --trace shows of it."""

from __future__ import annotations

import io
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

from harness import LauncherTest, prompts_at
from test_capture import pcap_file, tcp

from claude_sandbox import processes, procwatch

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


class WatcherTest(unittest.TestCase):
    def test_addresses_are_read_as_the_kernel_writes_them(self):
        if sys.byteorder != "little":
            self.skipTest("written for a little-endian machine")
        for encoded, address in (
            ("0100007F", "127.0.0.1"),
            ("0A68A08E", "142.160.104.10"),
            ("00000000000000000000000001000000", "::1"),
            ("B80D0120000000000000000009000000", "2001:db8::9"),
            # IPv4 inside IPv6, as it goes over the wire
            ("0000000000000000FFFF00000A68A08E", "142.160.104.10"),
        ):
            self.assertEqual(procwatch.address(encoded), address)

    @unittest.skipUnless(sys.platform == "linux", "reads /proc")
    def test_a_process_and_the_holder_of_a_connection_are_seen(self):
        with socket.socket() as server:
            server.bind(("127.0.0.1", 0))
            server.listen(1)
            sleeper = subprocess.Popen(["sleep", "30"])
            try:
                with socket.create_connection(server.getsockname()) as client:
                    port = client.getsockname()[1]
                    key = (port, "127.0.0.1", server.getsockname()[1])
                    found = procwatch.connections()
                    self.assertIn(key, found)
                    holders = procwatch.Holders().of({found[key]}, [os.getpid()])
                    self.assertEqual(holders, {found[key]: [os.getpid()]})
                out = io.StringIO()
                procwatch.Watch(out).look()
                seen = [json.loads(line) for line in out.getvalue().splitlines()]
                (slept,) = (line for line in seen if line.get("pid") == sleeper.pid)
                self.assertEqual(slept["argv"], ["sleep", "30"])
                self.assertEqual(slept["ppid"], os.getpid())
                self.assertTrue(slept["exe"].endswith("sleep"))
                # Not the watcher itself
                self.assertFalse([l for l in seen if l.get("pid") == os.getpid()])
            finally:
                sleeper.kill()
                sleeper.wait()

    def test_the_record_stops_at_its_size_limit(self):
        out = io.StringIO()
        watch = procwatch.Watch(out)
        big = "x" * (procwatch.MOST_BYTES // 4)
        for _ in range(6):
            watch.note(note=big)
        self.assertLessEqual(len(out.getvalue()), procwatch.MOST_BYTES + 100)
        self.assertEqual(json.loads(out.getvalue().splitlines()[-1])["note"], "full")


    def test_a_process_cannot_fill_the_record_with_its_command_line(self):
        long = b"\0".join([b"x" * 5000] * 200) + b"\0"
        kept = procwatch.command_line(long)
        self.assertEqual(kept[-1], procwatch.CUT)
        self.assertLessEqual(sum(map(len, kept)), procwatch.MOST_COMMAND + 3)
        # One that fits is left as it is, an empty argument too
        self.assertEqual(procwatch.command_line(b"sh\0-c\0\0"), ["sh", "-c", ""])
        self.assertEqual(procwatch.command_line(b""), [])

    def test_room_is_kept_for_the_connections_once_the_processes_filled_theirs(self):
        out = io.StringIO()
        watch = procwatch.Watch(out)
        big = "x" * (procwatch.MOST_BYTES // 4)
        for _ in range(6):
            watch.note(pid=1, argv=[big])
        watch.note(reserved=True, port=40212, to="203.0.113.9", to_port=443, pids=[7])
        watch.note(pid=2, argv=["late"])
        said = [json.loads(line) for line in out.getvalue().splitlines()]
        self.assertEqual([line.get("note") for line in said[-2:]], ["full", None])
        self.assertEqual(said[-1]["to"], "203.0.113.9")
        self.assertEqual(sum("note" in line for line in said), 1)
        # Until that room is used up too
        for _ in range(3):
            watch.note(reserved=True, note=big)
        self.assertLessEqual(len(out.getvalue()), procwatch.MOST_BYTES)

    def test_running_into_the_limit_of_processes_is_noted_when_it_grows(self):
        with tempfile.TemporaryDirectory() as root:
            events = Path(root, "1", "root", "sys", "fs", "cgroup", "pids.events")
            events.parent.mkdir(parents=True)
            self.assertIsNone(procwatch.limit_hits(1, root))
            events.write_text("max 3\n")
            self.assertEqual(procwatch.limit_hits(1, root), 3)
            events.write_text("nothing of the kind\n")
            self.assertIsNone(procwatch.limit_hits(1, root))
        out = io.StringIO()
        watch = procwatch.Watch(out)
        for hits in (0, 2, 2, 5, None):
            with mock.patch.object(procwatch, "limit_hits", return_value=hits):
                watch._look_at_limits([1, 7])
        said = [json.loads(line) for line in out.getvalue().splitlines()]
        self.assertEqual([line["hits"] for line in said], [2, 5])
        self.assertEqual(noted(*said).process_limit, 5)

    def test_a_socket_that_waits_for_connections_is_noted_once(self):
        with socket.socket() as server:
            server.bind(("127.0.0.1", 0))
            server.listen(1)
            port = server.getsockname()[1]
            self.assertIn((port, "127.0.0.1", 0), procwatch.connections(listening=True))
            self.assertNotIn(port, [key[0] for key in procwatch.connections()])
            out = io.StringIO()
            watch = procwatch.Watch(out)
            watch.look()
            watch.look()
        seen = [json.loads(line) for line in out.getvalue().splitlines()]
        ours = [line for line in seen if line.get("listen") == port]
        self.assertEqual([line["on"] for line in ours], ["127.0.0.1"])


class RecordTest(unittest.TestCase):
    def setUp(self):
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
        self.assertEqual([p.pid for p in lineage], [812, 640, 7])
        self.assertEqual(
            processes.shown_lineage(lineage),
            "[812] curl https://a.test < bash < claude",
        )

    def test_of_several_that_hold_a_socket_it_is_the_one_started_last(self):
        (first, _) = self.record.holder(50000, "10.0.0.1", 80, 20.3)
        self.assertEqual(first.pid, 640)

    def test_no_process_is_made_up_for_a_connection(self):
        self.assertEqual(self.record.holder(40443, "198.51.100.7", 80, 20.3), [])
        # The same ports long after are another connection
        self.assertEqual(self.record.holder(40443, "198.51.100.7", 443, 900.0), [])

    def test_a_process_is_named_by_its_program_not_by_what_it_says(self):
        record = noted(
            {"t": 1, "pid": 5, "ppid": 1, "exe": "/tmp/x", "argv": ["sshd", "-D"]}
        )
        self.assertEqual(record.processes[0].command, "x -D")

    def test_a_line_that_does_not_hold_up_is_passed_over(self):
        record = processes.ProcessRecord()
        for line in (
            "[" * 100_000,
            "{}",
            '{"t": 1, "pid": "x"}',
            '{"t": 1, "port": 1}',
        ):
            record.take(line)
        self.assertEqual((record.processes, record.holders), ([], {}))
        record.take('{"t": 1, "note": "full"}')
        self.assertTrue(record.full)

    def test_a_parent_that_names_itself_ends_the_line(self):
        record = noted(ran(1.0, 5, 5, "loop"))
        self.assertEqual(len(record.lineage(5, 2.0)), 1)


class SidecarTest(LauncherTest):
    def setUp(self):
        super().setUp()
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
            CLAUDE_DOCKER_PROC_LOG="1",
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
            self.assertIn(flag, sidecar)
        self.assertEqual(
            [flag for flag in sidecar if flag.startswith("--cap-add=")],
            ["--cap-add=SETUID", "--cap-add=SETGID"],
        )
        self.assertEqual(sidecar[-2:], [str(os.getuid()), str(os.getgid())])
        # The session is not made to wait for it, nor to depend on it
        self.assertNotIn(SIDECAR, " ".join(result.flags))

    def test_it_joins_the_network_of_the_capture(self):
        result = self.watched(
            CLAUDE_DOCKER_NET_LOG="1", FAKE_CAPTURE=str(self.capture_file)
        )
        self.assertIn(
            "--network=container:claude-proj.capture", result.sidecar(SIDECAR)
        )

    def test_the_record_is_copied_out_and_the_sidecar_removed(self):
        result = self.watched()
        (copied,) = (self.state / "processes").glob("*.jsonl")
        self.assertEqual(copied.read_text(), self.record_file.read_text())
        self.assertIn(["rm", "--force", SIDECAR], result.calls)
        self.assertIn(
            f'"processes": "{copied.name}"',
            (self.state / "net-sessions.jsonl").read_text(),
        )

    def test_a_watcher_that_did_not_get_to_watch_is_said(self):
        self.record_file.write_text("")
        # What docker logs has of the watcher, as the fake docker plays it
        said = self.work / "said"
        said.write_text("OSError: could not take the identity\n")
        result = self.watched(session="sleep 6", FAKE_PROXY_LOG=str(said))
        self.assertIn("the processes of this session were not recorded", result.stderr)
        self.assertIn("could not take the identity", result.stderr)
        self.assertEqual(list((self.state / "processes").glob("*.jsonl")), [])
        self.assertFalse((self.state / "net-sessions.jsonl").exists())

    def test_switched_off_nothing_is_recorded(self):
        result = self.launch(session="sleep 0.5", FAKE_RUNNING="claude-proj")
        self.assertIsNone(result.sidecar(SIDECAR))

    def test_a_record_left_by_a_killed_session_is_collected(self):
        about = {"project": "/elsewhere", "start": 5, "pid": 2**22 - 7}
        result = self.launch(
            FAKE_PS=f"claude-old.procs\t{json.dumps(about)}",
            FAKE_PROCESSES=str(self.record_file),
        )
        self.assertIn(["rm", "--force", "claude-old.procs"], result.calls)
        self.assertTrue(
            (self.state / "processes" / "claude-old.procs-5.jsonl").exists()
        )

    def trace(self, *args: str) -> str:
        self.watched(CLAUDE_DOCKER_NET_LOG="1", FAKE_CAPTURE=str(self.capture_file))
        self.write_transcript("0a", prompts_at(self.now, self.now + 10))
        result = self.launch("--trace", *args)
        self.assertEqual(result.status, 0, result.stderr)
        return result.stdout

    def test_a_session_that_ran_into_its_limits_is_said_to(self):
        with open(self.record_file, "a") as record:
            record.write(json.dumps({"t": self.now + 3, "limit": "pids", "hits": 4}))
            record.write("\n")
        ended = self.watched(FAKE_EVENTS="oom\noom", CLAUDE_DOCKER_MEMORY="2g")
        self.assertIn("ran into its limit of processes 4 times", ended.stderr)
        self.assertIn("ran into its memory limit of 2g 2 times", ended.stderr)
        self.assertIn(
            ["events", "--filter=container=claude-proj", "--filter=event=oom"],
            [call[:3] for call in ended.calls],
        )
        self.write_transcript("0a", prompts_at(self.now, self.now + 10))
        self.assertIn(
            "its limit of processes was RUN INTO 4 times", self.launch("--trace").stdout
        )
        # Nothing of either from a session that kept within them
        self.assertNotIn("memory limit", self.launch().stderr)

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
        self.assertIn("waited for connections, open to the other", ended.stderr)
        self.assertEqual(ended.stderr.count("tcp 0.0.0.0:8080"), 1)
        self.assertNotIn("9229", ended.stderr)
        self.write_transcript("0a", prompts_at(self.now, self.now + 10))
        shown = self.launch("--trace").stdout
        self.assertRegex(
            shown,
            r"sandbox  listen      tcp 0\.0\.0\.0:8080  OPEN to its network"
            r"  by: \[812\] curl -sS https://good.test < claude",
        )
        self.assertRegex(shown, r"listen      tcp 127\.0\.0\.1:9229  by: \[7\] claude")
        self.assertIn("2 sockets waited for connections, OPEN", shown)

    def test_the_trace_says_which_process_made_a_connection(self):
        stdout = self.trace()
        self.assertIn(
            "tcp/https 198.51.100.7:443  by: [812] curl -sS https://good.test < claude",
            stdout,
        )
        self.assertIn("#   processes 2 seen to run", stdout)
        self.assertNotIn("sandbox  exec", stdout)

    def test_verbose_adds_the_processes(self):
        stdout = self.trace("--verbose")
        self.assertIn("sandbox  exec        [812] curl -sS https://good.test", stdout)
        self.assertIn("sandbox  exec        parent: [7] claude", stdout)

    def test_json_names_the_process(self):
        events = map(json.loads, self.trace("--json").splitlines())
        (made,) = (e["process"] for e in events if e.get("port") == 443)
        self.assertEqual((made["pid"], made["parents"]), (812, ["claude"]))


if __name__ == "__main__":
    unittest.main()
