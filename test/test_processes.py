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

from claude_sandbox import health, processes, procwatch

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


GIB = 2**30


class FakeSession:
    """What a watcher reads of a session, made up in a directory: the
    cgroup of its container and its processes."""

    def __init__(self, root: Path):
        self.proc = root
        self.first = root / "1"
        self.cgroup = self.first / "root" / "sys" / "fs" / "cgroup"
        self.cgroup.mkdir(parents=True)
        (self.first / "root" / "tmp").mkdir()
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


class HealthWatchTest(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.session = FakeSession(Path(directory.name))
        self.out = io.StringIO()
        # What it says aloud is not for the output of the tests
        quiet = mock.patch.object(sys, "stdout", io.StringIO())
        quiet.start()
        self.addCleanup(quiet.stop)
        self.watch = procwatch.Watch(self.out)
        self.watch._processes[812] = (("9", "/usr/bin/node", ["node", "build.js"]), 0, 0)
        self.health = self.reader()
        self.session.run(1, 1)
        self.session.run(812, 900)
        self.pids = [1, 812]

    def reader(self) -> procwatch.Health:
        return procwatch.Health(
            self.watch.note, self.watch.name_of, str(self.session.proc)
        )

    def said(self) -> list[dict]:
        return [json.loads(line) for line in self.out.getvalue().splitlines()]

    def test_how_the_session_is_doing_is_noted_every_so_often(self):
        self.health.look(self.pids, 100.0)
        # Nothing to compare with yet
        self.assertEqual(self.said(), [])
        self.session.use(memory=2.0, cpu_seconds=3.0, throttled_seconds=0.5)
        self.health.look(self.pids, 102.0)
        (line,) = self.said()
        health = line["health"]
        # Without what the kernel keeps of files and gives back when asked
        self.assertEqual(health["mem"], [2 * GIB, 16 * GIB])
        self.assertEqual(health["pids"], [20, 512])
        self.assertEqual((health["cpu"], health["cpus"]), (150.0, 1.5))
        self.assertEqual((health["throttled"], health["seconds"]), (0.5, 2.0))
        self.assertEqual(health["stalled"], {"memory": 0.0, "cpu": 0.0})
        # Of the tmpfs only the session's own, as large as it is
        self.assertEqual(list(health["tmpfs"]), ["/tmp"])
        self.assertEqual(health["top"][0], [812, 900 * 2**20, "node"])
        self.assertNotIn("rose", health)
        # Not again before its time, then with what was used since
        self.session.use(memory=2.0, cpu_seconds=18.0)
        self.health.look(self.pids, 102.0 + procwatch.HEALTH_EVERY - 1)
        self.assertEqual(len(self.said()), 1)
        self.health.look(self.pids, 102.0 + procwatch.HEALTH_EVERY)
        self.assertEqual(self.said()[-1]["health"]["cpu"], 50.0)

    def test_coming_near_a_limit_is_noted_out_of_turn_and_not_over_and_over(self):
        self.health.look(self.pids, 100.0)
        self.health.look(self.pids, 101.0)
        for second, memory in enumerate((12.0, 11.5, 12.5, 15.0, 15.2, 9.0, 12.0)):
            self.session.use(memory=memory)
            self.health.look(self.pids, 110.0 + 6 * second)
        rose = [line["health"].get("rose") for line in self.said()]
        # Near at 12, at it at 15, and near again only once well below
        self.assertEqual(rose, [None, ["memory"], ["memory"], ["memory"]])
        self.session.use(memory=12.0, processes=500)
        self.health.look(self.pids, 152.0)
        self.assertEqual(self.said()[-1]["health"]["rose"], ["pids"])
        # Found at a limit, which the first line says. Then to just under
        # the mark below it and up again: near once more is not news, at
        # it is
        steady = self.reader()
        for second, memory in enumerate((15.0, 10.6, 12.0, 15.0)):
            self.session.use(memory=memory)
            steady.look(self.pids, 300.0 + 40 * second)
        self.assertEqual(
            [line["health"].get("rose") for line in self.said()[-3:]],
            [["memory"], None, ["memory"]],
        )
        # No more often than that, however the session goes up and down
        before = len(self.said())
        for second in range(4):
            self.session.use(memory=9.0 if second % 2 else 12.0)
            self.health.look(self.pids, 153.0 + second)
        self.assertEqual(len(self.said()), before)

    def test_a_rise_that_came_too_soon_after_another_is_said_when_it_can_be(self):
        self.health.look(self.pids, 100.0)
        self.health.look(self.pids, 101.0)
        self.session.use(memory=12.0)
        self.health.look(self.pids, 102.0)
        self.session.use(memory=15.0)
        self.health.look(self.pids, 103.0)
        self.assertEqual(len(self.said()), 2)
        self.health.look(self.pids, 102.0 + procwatch.OUT_OF_TURN_EVERY)
        self.assertEqual(self.said()[-1]["health"]["rose"], ["memory"])
        self.assertEqual(len(self.said()), 3)

    def test_the_watcher_and_the_trace_agree_on_what_is_near_a_limit(self):
        # The watcher stands alone in its sidecar, so each has its own
        self.assertEqual(procwatch.NEAR_LIMIT, (health.NEAR_LIMIT, health.AT_LIMIT))

    def test_a_process_ended_for_want_of_memory_is_noted_with_what_is_gone(self):
        self.health.look(self.pids, 100.0)
        self.session.set("memory.events", "oom 1\noom_kill 1")
        self.health.look([1], 101.0)
        ended = [line for line in self.said() if "oom" in line]
        self.assertEqual(ended, [{**ended[0], "oom": 1, "gone": [[812, 900 * 2**20, "node"]]}])
        # Once, and of one that was already counted nothing
        self.health.look([1], 102.0)
        self.assertEqual(sum("oom" in line for line in self.said()), 1)

    def test_what_cannot_be_read_is_left_out_and_the_rest_still_told(self):
        for name in ("memory.current", "cpu.stat", "memory.pressure", "cpu.max"):
            (self.session.cgroup / name).unlink()
        (self.session.first / "mounts").unlink()
        self.health.look(self.pids, 100.0)
        self.health.look(self.pids, 101.0)
        (line,) = self.said()
        self.assertEqual(
            set(line["health"]), {"pids", "seconds", "stalled", "top"}, line["health"]
        )

    def test_it_is_said_aloud_too_for_who_follows_the_session(self):
        aloud = io.StringIO()
        with mock.patch.object(sys, "stdout", aloud):
            self.watch.note(aloud=True, health={"cpu": 1.0})
            self.watch.note(pid=5, argv=["quiet"])
        self.assertEqual(aloud.getvalue(), self.out.getvalue().splitlines(True)[0])


class HealthShownTest(unittest.TestCase):
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
        self.assertEqual(
            event.details[0],
            "mem 3.1g of 16g (19%)  cpu 240%  pids 87 of 512"
            "  /home/sandbox/.npm 50%  waited for: io 3%  top: [812] node 2g",
        )
        self.assertEqual(event.what, "health")
        self.assertNotIn("flagged", event.fields)
        self.assertEqual(event.fields["memory"], {"used": 3 * GIB + GIB // 10, "limit": 16 * GIB})
        self.assertEqual(event.fields["top"][0], {"pid": 812, "rss": 2 * GIB, "name": "node"})

    def test_a_limit_that_is_near_and_one_that_is_reached_are_said(self):
        near = self.sample(mem=[12 * GIB, 16 * GIB], rose=["memory"]).event()
        self.assertEqual(
            near.details, ["running low on memory  mem 12g of 16g (75%)"]
        )
        self.assertNotIn("flagged", near.fields)
        reached = self.sample(
            mem=[15 * GIB, 16 * GIB],
            tmpfs={"/tmp": [39, 40]},
            stalled={"memory": 35.0},
            cpu=150.0,
            cpus=1.5,
            throttled=12.0,
            rose=["/tmp"],
        ).event()
        self.assertEqual(
            reached.details[0],
            "ALMOST OUT OF memory, /tmp, STALLED for want of memory"
            "  mem 15g of 16g (93%)  cpu 150% of 1.5 cpus, held back 12.0s"
            "  /tmp 97%  waited for: memory 35%",
        )
        self.assertTrue(reached.fields["flagged"])

    def test_no_limit_is_no_share_and_a_name_is_the_sessions_to_choose(self):
        event = self.sample(
            mem=[GIB, None], pids=[5, None], top=[[9, GIB, "evil\x1b[31m\nname"]]
        ).event()
        self.assertEqual(event.details, ["mem 1g  pids 5  top: [9] evil[31m\\nname 1g"])

    def test_a_process_that_was_ended_is_said_with_the_likely_one(self):
        ended = health.read_health(7.0, {"t": 7.0, "oom": 2, "gone": [[812, 9 * GIB, "node"]]})
        assert ended is not None
        self.assertEqual(
            ended.event().details,
            ["OUT OF MEMORY, a process was ended for it  gone since: [812] node 9g"],
        )
        unseen = health.read_health(7.0, {"t": 7.0, "oom": 3, "gone": []})
        assert unseen is not None
        self.assertIn("which one was not seen", unseen.event().details[0])
        self.assertIsNone(health.read_health(7.0, {"t": 7.0, "pid": 5}))

    def test_a_line_that_does_not_hold_up_is_passed_over(self):
        record = noted(
            {"t": 1, "health": {"mem": "lots"}},
            {"t": 1, "health": []},
            {"t": 1, "oom": "often"},
            {"t": 1, "health": {"top": [[1, 2]]}},
            {"t": 2, "health": {"mem": [1, 2]}},
        )
        self.assertEqual([found.when for found in record.samples], [2.0])
        self.assertEqual(record.ended, [])

    def test_the_header_sums_it_up(self):
        samples = [
            self.sample(mem=[2 * GIB, 16 * GIB], cpu=100.0, seconds=30.0, pids=[10, 512]),
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
        self.assertEqual(
            health.health_summary(samples, ended),
            [
                "  memory 9g of 16g (56%) at most",
                "  cpu 175% on average, 400% at most of 4 cpus, held back 6s in all",
                "  pids 78% of its limit at most",
                "  STALLED for want of memory, up to 22% of the time",
                "  OUT OF MEMORY, a process was ended for it 2 times",
            ],
        )
        self.assertEqual(health.health_summary([], []), [])


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
        self.assertIn(
            "sandbox  health      mem 2g of 16g (12%)  cpu 80%  pids 30 of 512"
            "  top: [812] curl 1g",
            shown,
        )
        self.assertIn("health      ALMOST OUT OF memory  mem 15g of 16g (93%)", shown)
        self.assertIn("gone since: [812] curl 14g", shown)
        self.assertIn("#   memory 15g of 16g (93%) at most", shown)
        self.assertIn("#   cpu 80% on average, 80% at most", shown)
        self.assertIn("#   OUT OF MEMORY, a process was ended for it 1 times", shown)
        # What went wrong of it is what --failed keeps, and --only picks it
        failed = self.launch("--trace", "--failed").stdout
        self.assertEqual(failed.count("sandbox  health"), 2)
        self.assertEqual(self.launch("--trace", "--only", "health").stdout.count("  health  "), 3)
        events = map(json.loads, self.launch("--trace", "--json").stdout.splitlines())
        (first, *_) = (e for e in events if e.get("what") == "health")
        self.assertEqual(first["memory"], {"used": 2 * GIB, "limit": 16 * GIB})

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
