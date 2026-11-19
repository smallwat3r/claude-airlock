#!/usr/bin/env python3
"""Sessions under gVisor: how the launcher recognises the runtime, what
it reports and refuses at launch, and the record of memory and CPU use it
writes from outside the session."""

from __future__ import annotations

import json
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from harness import LauncherTest, prompts_at, settings
from test_processes import GIB, FakeSession

from claude_sandbox import host_health, processes, runtime
from claude_sandbox.launcher import Launcher

HOSTNET = ["--network=host", "--host-uds=open"]
CONTAINER = "0a1b2c3d4e5f"


def docker_info(default: str = "runc", **runtimes: list[str] | None) -> str:
    """The answer of docker info to what session_runtime asks: the
    default runtime, then every runtime by name. Each keyword is a runsc
    runtime with the given arguments."""
    listed: dict[str, dict] = {"runc": {"path": "runc"}}
    for name, args in runtimes.items():
        about: dict = {"path": "/usr/local/bin/runsc"}
        if args:
            about["runtimeArgs"] = args
        listed[name.replace("_", "-")] = about
    return f"{json.dumps(default)}\n{json.dumps(listed)}"


INFO = docker_info(runsc=None, runsc_hostnet=HOSTNET)


def gvisor(*args: str, path: str = "/usr/local/bin/runsc") -> runtime.Runtime:
    """The runtime of a runsc registered under the name gv with these
    arguments."""
    return runtime.known_runtime(runtime.Registered("gv", path, args=args))


class RuntimeTest(unittest.TestCase):
    def test_a_flag_is_read_in_every_form_runsc_accepts(self):
        for args in (("--network=host",), ("-network=host",), ("--network", "host")):
            registered = runtime.Registered("gv", args=args)
            self.assertEqual(registered.flag("network"), "host")
        twice = runtime.Registered("gv", args=("--network=none", "--network=host"))
        self.assertEqual(twice.flag("network"), "host")
        other = runtime.Registered("gv", args=("--host-uds=open", "network"))
        self.assertIsNone(other.flag("network"))
        self.assertIsNone(runtime.Registered("gv").flag("network"))

    def test_an_unknown_runtime_is_handled_like_dockers_own(self):
        known = runtime.known_runtime(runtime.Registered("crun", "/usr/bin/crun"))
        self.assertEqual(known, runtime.Runtime("crun"))
        self.assertEqual(known.shown, "crun")
        self.assertTrue(known.JOINABLE)
        self.assertEqual(known.notes(settings.Settings()), [])
        self.assertEqual(known.process_limit("512"), "512")
        self.assertEqual(runtime.DOCKERS_OWN.shown, "docker's own runtime")

    def test_gvisor_is_recognised_by_its_program_and_read_from_its_arguments(self):
        plain = gvisor()
        self.assertIsInstance(plain, runtime.Gvisor)
        self.assertFalse(plain.JOINABLE)
        self.assertEqual(plain.shown, "gVisor (gv)")
        self.assertIn("--host-uds=open", plain.no_host_sockets)
        asked = settings.Settings()
        self.assertTrue([n for n in plain.notes(asked) if "do not resolve" in n])
        hostnet = gvisor(*HOSTNET, path="/opt/runsc")
        self.assertEqual((hostnet.JOINABLE, hostnet.no_host_sockets), (False, ""))
        self.assertFalse([n for n in hostnet.notes(asked) if "resolve" in n])
        self.assertTrue(gvisor("--host-uds=create").no_host_sockets)

    def test_arguments_that_are_not_visible_are_assumed_to_be_right(self):
        said = {"runtimeType": "io.containerd.runsc.v1"}
        shim = runtime.known_runtime(runtime.Registered.read("gv", said))
        self.assertIsInstance(shim, runtime.Gvisor)
        self.assertEqual(shim.no_host_sockets, "")
        self.assertFalse([n for n in shim.notes(settings.Settings()) if "resolve" in n])

    def test_gvisor_raises_the_process_limit_by_what_it_uses_itself(self):
        self.assertEqual(gvisor().process_limit("512"), "1088")
        # Docker reads anything that is not a positive number itself
        for unlimited in ("-1", "0", "many"):
            self.assertEqual(gvisor().process_limit(unlimited), unlimited)

    def test_unrecorded_processes_are_only_mentioned_when_recording_is_on(self):
        recording = gvisor().notes(settings.Settings(proc_log=True))
        self.assertTrue([n for n in recording if "processes are not recorded" in n])
        silent = gvisor().notes(settings.Settings(proc_log=False))
        self.assertFalse([n for n in silent if "processes are not recorded" in n])


class LaunchTest(LauncherTest):
    def test_under_another_runtime_nothing_changes(self):
        result = self.launch(CLAUDE_DOCKER_RUNTIME="runc", FAKE_INFO=INFO)
        self.assertIn("--pids-limit=512", result.flags)
        self.assertNotIn("gVisor", result.stderr)

    def test_under_gvisor_the_launcher_says_what_a_session_lacks(self):
        result = self.launch(
            CLAUDE_DOCKER_RUNTIME="runsc-hostnet",
            CLAUDE_DOCKER_PROC_LOG="1",
            FAKE_INFO=INFO,
            FAKE_RUNNING="claude-proj",
            session="sleep 0.5",
        )
        self.assertEqual(result.status, 0, result.stderr)
        self.assertIn("under gVisor (runsc-hostnet):", result.stderr)
        self.assertIn("processes are not recorded", result.stderr)
        self.assertIn("ended as a whole", result.stderr)
        self.assertNotIn("do not resolve", result.stderr)
        self.assertIn("--pids-limit=1088", result.flags)
        # The session is still told the limit from the setting
        self.assertIn("--env=CLAUDE_DOCKER_PIDS=512", result.flags)
        # No watcher is started: it would see gVisor's kernel, not the session
        self.assertIsNone(result.sidecar("claude-proj.procs"))

    def test_the_default_runtime_of_the_daemon_is_recognised_too(self):
        info = docker_info("runsc", runsc=HOSTNET)
        self.assertIn("under gVisor (runsc)", self.launch(FAKE_INFO=info).stderr)

    def test_the_launcher_warns_that_names_do_not_resolve_on_gvisors_own_stack(self):
        result = self.launch(CLAUDE_DOCKER_RUNTIME="runsc", FAKE_INFO=INFO)
        self.assertEqual(result.status, 0, result.stderr)
        self.assertIn("names do not resolve", result.stderr)
        self.assertIn("--network=host", result.stderr)

    def test_the_agent_is_refused_when_host_sockets_cannot_be_reached(self):
        agent = {"SSH_AUTH_SOCK": "/tmp/agent.sock", "CLAUDE_DOCKER_SSH_AGENT": "1"}
        refused = self.launch(CLAUDE_DOCKER_RUNTIME="runsc", FAKE_INFO=INFO, **agent)
        self.assert_refused(refused, "the SSH agent cannot be reached under gVisor")
        self.assertIn("--host-uds=open", refused.stderr)
        reached = self.launch(
            CLAUDE_DOCKER_RUNTIME="runsc-hostnet", FAKE_INFO=INFO, **agent
        )
        self.assertEqual(reached.status, 0, reached.stderr)

    def trace_of(self, lines: list[dict]) -> str:
        """The trace of a session whose record the launcher wrote from
        outside, with the given lines."""
        now = time.time()
        directory = self.state / "processes"
        directory.mkdir(parents=True)
        name = "claude-proj.procs-5.jsonl"
        started = {"t": now, "note": "started", "outside": "gVisor (runsc-hostnet)"}
        (directory / name).write_text(
            "".join(
                json.dumps({"t": now + 1, **line}) + "\n" for line in [started, *lines]
            )
        )
        session = {"name": "claude-proj", "project": str(self.project)}
        session.update(start=now, processes=name, end=now + 10)
        (self.state / "net-sessions.jsonl").write_text(json.dumps(session) + "\n")
        self.write_transcript("0a", prompts_at(now, now + 10))
        result = self.launch("--trace")
        self.assertEqual(result.status, 0, result.stderr)
        return result.stdout

    def test_the_trace_shows_health_and_says_processes_were_not_recorded(self):
        health = {"mem": [2 * GIB, 16 * GIB], "cpu": 80.0, "seconds": 30.0}
        shown = self.trace_of([{"health": health}])
        self.assertIn("#   processes not recorded under gVisor (runsc-hostnet)", shown)
        self.assertNotIn("seen to run", shown)
        self.assertIn("sandbox  health      mem 2g of 16g (12%)  cpu 80%", shown)
        self.assertIn("#   memory 2g of 16g (12%) at most", shown)


class HostHealthTest(LauncherTest):
    def setUp(self):
        super().setUp()
        self.host = settings.Host(
            str(self.home),
            str(self.project),
            str(self.home / ".config"),
            str(self.home / ".local" / "state"),
        )
        # A fake cgroup tree of a host, holding the cgroup of one container
        self.cgroups = self.work / "cgroup"
        self.cgroup = self.cgroups / "system.slice" / f"docker-{CONTAINER}.scope"
        self.session = FakeSession(self.work / "session", self.cgroup)
        self.proc = self.work / "proc"
        patched = mock.patch.object(host_health, "CGROUPS", str(self.cgroups))
        patched.start()
        self.addCleanup(patched.stop)

    def in_cgroup(self, pid: int, said: str) -> None:
        (self.proc / str(pid)).mkdir(parents=True, exist_ok=True)
        (self.proc / str(pid) / "cgroup").write_text(said)

    def test_the_cgroup_of_a_container_is_found_through_its_process(self):
        self.in_cgroup(7, f"0::/system.slice/docker-{CONTAINER}.scope\n")
        found = host_health.cgroup_of(7, CONTAINER, str(self.proc))
        self.assertEqual(found, str(self.cgroup))

    def test_a_cgroup_not_named_after_the_container_is_rejected(self):
        # An unrelated process of this host, as when the daemon runs elsewhere
        self.in_cgroup(7, "0::/user.slice\n")
        (self.cgroups / "user.slice").mkdir()
        self.assertEqual(host_health.cgroup_of(7, CONTAINER, str(self.proc)), "")
        # Cgroup version 1, which has one line per controller
        self.in_cgroup(8, f"4:memory:/docker/{CONTAINER}\n")
        self.assertEqual(host_health.cgroup_of(8, CONTAINER, str(self.proc)), "")
        # A path that would lead outside the cgroup tree
        self.in_cgroup(9, f"0::/../../{CONTAINER}\n")
        self.assertEqual(host_health.cgroup_of(9, CONTAINER, str(self.proc)), "")
        self.assertEqual(host_health.cgroup_of(10, CONTAINER, str(self.proc)), "")

    def sessions_noted(self) -> list[dict]:
        noted = Path(self.host.net_sessions_file).read_text()
        return [json.loads(line) for line in noted.splitlines()]

    def watched(self, looks: int) -> host_health.HealthRecord:
        """The record of a session after the given number of looks, with
        its use growing between them."""
        stop = threading.Event()
        used = iter(range(looks))

        def wait(seconds: float) -> bool:
            step = next(used, None)
            if step is None:
                return True
            self.session.use(memory=2.0 + step, cpu_seconds=3.0 * (step + 1))
            return False

        records: list[host_health.HealthRecord] = []
        with (
            mock.patch.object(
                host_health, "container_process", lambda name: (7, CONTAINER)
            ),
            mock.patch.object(
                host_health, "cgroup_of", lambda *found: str(self.cgroup)
            ),
            mock.patch.object(stop, "wait", wait),
        ):
            host_health.watch(self.host, "claude-proj", "gVisor (gv)", records, stop)
        (record,) = records
        return record

    def test_health_is_written_in_the_format_of_the_watcher(self):
        record = self.watched(looks=2)
        self.assertTrue(record.path.name.endswith(".jsonl.part"))
        self.assertEqual(record.path.stat().st_mode & 0o777, 0o600)
        self.assertTrue(processes.watcher_started(record.path))
        read = processes.read_record(record.path)
        self.assertEqual(read.outside, "gVisor (gv)")
        (sample,) = read.samples
        self.assertEqual(sample.memory, (2 * GIB, 16 * GIB))
        self.assertEqual(sample.cpus, 1.5)
        # No process count, because the cgroup counts the runtime's threads,
        # and nothing that is only visible from inside the session
        self.assertIsNone(sample.pids)
        self.assertEqual((sample.tmpfs, sample.largest), ({}, ()))

    def test_a_finished_record_is_listed_for_the_trace(self):
        record = self.watched(looks=1)
        self.assertEqual(
            host_health.running_health(self.host),
            [(str(record.path), "claude-proj", record.start)],
        )
        record.keep(self.host, record.start + 9)
        self.assertEqual(host_health.running_health(self.host), [])
        (noted,) = self.sessions_noted()
        self.assertEqual(noted["name"], "claude-proj")
        self.assertEqual(noted["end"], record.start + 9)
        kept = Path(self.host.process_records_dir, noted["processes"])
        self.assertTrue(kept.name.endswith(".jsonl"))
        self.assertEqual(processes.read_record(kept).outside, "gVisor (gv)")

    def test_readings_after_a_time_are_read_from_a_growing_record(self):
        record = self.watched(looks=2)
        (sample,) = host_health.said_in(str(record.path), record.start - 1)
        self.assertEqual(sample.memory, (2 * GIB, 16 * GIB))
        self.assertEqual(host_health.said_in(str(record.path), time.time() + 1), [])
        self.assertEqual(host_health.said_in(str(self.work / "none"), 0.0), [])

    def test_the_next_launcher_finishes_the_record_of_a_killed_one(self):
        record = self.watched(looks=1)
        # This launcher is alive, so its record is left alone
        host_health.collect_left_behind(self.host)
        self.assertTrue(record.path.exists())
        gone = Launcher(2**22 - 7, "long ago")
        with mock.patch.object(host_health.HealthRecord, "found", lambda path: record):
            record.launcher = gone
            host_health.collect_left_behind(self.host)
        self.assertFalse(record.path.exists())
        (noted,) = self.sessions_noted()
        self.assertEqual(noted["project"], str(self.project))

    def test_a_file_without_a_valid_first_line_is_not_a_record(self):
        directory = Path(self.host.process_records_dir)
        directory.mkdir(parents=True)
        for name, said in (
            ("a", ""),
            ("b", "{}"),
            ("c", '{"note": "started"}'),
            ("d", "["),
        ):
            (directory / f"{name}.jsonl.part").write_text(said + "\n")
        self.assertEqual(host_health.being_written(self.host), [])


if __name__ == "__main__":
    unittest.main()
