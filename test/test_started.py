#!/usr/bin/env python3
"""The record of how the sandbox of each session was started, and what
--trace and what follows the sessions show of it."""

from __future__ import annotations

import dataclasses
import json
import time
import unittest

from harness import LauncherTest, prompts_at, settings
from test_runtime import INFO, gvisor

from claude_airlock.events import Who
from claude_airlock.recording import started
from claude_airlock.report.noted import NewlyNoted, noted_events
from claude_airlock.sandbox import runtime
from claude_airlock.sandbox.mounts import ExtraDir


def note(when: float, session: str, did: str = started.STARTED) -> dict:
    return {"t": when, "session": session, "did": did}


class StartTest(unittest.TestCase):
    def test_a_start_is_of_the_session_and_not_of_the_settings(self):
        chosen = settings.Settings(
            memory="8g",
            pids="256",
            cpus="1.5",
            net_filter=True,
            ssh_agent=True,
            rw_config=True,
            telemetry=True,
        )
        dirs = [ExtraDir("/home/me/ref", read_only=True), ExtraDir("/srv/data")]
        start = started.Start.of(
            chosen,
            gvisor("--network=host"),
            "claude-airlock:1a2b",
            dirs,
            ssh_agent=False,
        )
        self.assertEqual(start.runtime, "gVisor (gv)")
        self.assertEqual((start.memory, start.pids, start.cpus), ("8g", "256", "1.5"))
        # No sidecar sees into a session under gVisor
        self.assertEqual(start.recorded, ("connections", "memory and CPU use"))
        # The host had no agent to forward
        self.assertEqual(start.open, ("config:rw", "telemetry"))
        self.assertEqual(start.dirs, ("/home/me/ref (ro)", "/srv/data"))

    def test_a_filter_that_asks_is_said_to_and_no_other(self):
        def network(start: started.Start) -> str:
            event = started.start_event(
                {**note(5.0, "claude-proj"), **dataclasses.asdict(start)}
            )
            return next(d for d in event.details if d.startswith("network: "))

        filtered = settings.Settings(net_filter=True, net_ask=True)
        asks = started.Start.of(
            filtered, runtime.DOCKERS_OWN, "", [], ssh_agent=False, net_ask=True
        )
        self.assertEqual(asks.network, "filtered, asks")
        self.assertEqual(
            network(asks),
            "network: filtered to the allowed domains, the user is asked about others",
        )
        # Asked for, where there was no place to ask: not of the settings
        silent = started.Start.of(
            filtered, runtime.DOCKERS_OWN, "", [], ssh_agent=False
        )
        self.assertEqual(silent.network, "filtered")
        self.assertEqual(network(silent), "network: filtered to the allowed domains")
        # A note of before there was this
        self.assertFalse(started.Start.from_note({"net_filter": True}).net_ask)

    def test_what_is_switched_off_is_not_said_to_be_recorded(self):
        chosen = settings.Settings(net_log=False, proc_log=False)
        start = started.Start.of(
            chosen, runtime.Runtime("runc"), "", [], ssh_agent=True
        )
        self.assertEqual(start.recorded, ())
        self.assertEqual(start.open, ("ssh-agent",))
        watched = started.Start.of(
            settings.Settings(), runtime.DOCKERS_OWN, "", [], ssh_agent=False
        )
        self.assertEqual(watched.recorded, ("connections", "processes"))
        self.assertEqual(watched.runtime, "docker's own runtime")

    def test_a_start_is_shown_with_its_limits_and_what_is_open(self):
        said = {
            **note(5.0, "claude-proj"),
            "runtime": "gVisor (runsc)",
            "image": "claude-airlock:1a2b",
            "memory": "8g",
            "pids": "256",
            "cpus": "",
            "net_filter": True,
            "recorded": ["connections"],
            "open": ["ssh-agent"],
            "dirs": ["/srv/\x1b[31mdata"],
            "plugins": ["tool@market 1.2.0", "other@market"],
            "servers": ["gopls", "pyright"],
        }
        event = started.start_event(said)
        self.assertEqual(
            (event.when, event.who, event.what), (5.0, Who.SANDBOX, "started")
        )
        self.assertEqual(
            event.details,
            [
                "claude-proj under gVisor (runsc), image claude-airlock:1a2b",
                "limits: memory 8g, processes 256, all CPUs",
                "network: filtered to the allowed domains",
                "recorded: connections",
                "open: ssh-agent",
                # Cleaned, a path is not the launcher's to choose
                "mounted: /srv/[31mdata",
                "plugins: tool@market 1.2.0, other@market",
                "language servers: gopls, pyright",
            ],
        )
        self.assertEqual(event.fields["container"], "claude-proj")
        self.assertEqual(
            started.start_summary(event),
            "claude-proj under gVisor (runsc), memory 8g, processes 256, all CPUs,"
            " network filtered",
        )
        # A note that holds less is still shown, one of an end is no event
        bare = started.start_event({**note(6.0, "claude-proj"), "cpus": 4, "open": "x"})
        self.assertEqual(bare.details[1], "limits: memory , processes , all CPUs")
        self.assertEqual(len(bare.details), 4)
        self.assertIsNone(started.start_event(note(7.0, "claude-proj", started.ENDED)))

    def test_the_sessions_that_ran_from_a_time_on_are_those_not_over_by_then(self):
        notes = [
            note(1.0, "claude-proj"),
            note(2.0, "claude-proj", started.ENDED),
            # Its launcher was killed, the next took the name
            note(3.0, "claude-proj"),
            note(4.0, "claude-proj"),
            note(5.0, "claude-proj-2"),
            note(6.0, "claude-proj-2", started.ENDED),
            note(7.0, "claude-proj-3"),
            note(9.0, "claude-proj-3", started.ENDED),
            note(11.0, "claude-proj-2"),
        ]
        running = started.running_between(notes, 8.0)
        self.assertEqual(
            [(found["t"], found["session"]) for found in running],
            [(4.0, "claude-proj"), (7.0, "claude-proj-3"), (11.0, "claude-proj-2")],
        )


class LaunchTest(LauncherTest):
    def setUp(self):
        super().setUp()
        self.host = settings.Host(
            str(self.home),
            str(self.project),
            str(self.home / ".config"),
            str(self.home / ".local" / "state"),
        )

    def noted(self) -> list[dict]:
        said = (self.state / "session-starts.jsonl").read_text()
        return [json.loads(line) for line in said.splitlines()]

    def test_a_session_is_noted_as_it_starts_and_when_it_is_over(self):
        result = self.launch(
            CLAUDE_AIRLOCK_RUNTIME="runsc",
            CLAUDE_AIRLOCK_CPUS="2",
            CLAUDE_AIRLOCK_MEMORY="4g",
            FAKE_INFO=INFO,
            session="exit 3",
        )
        self.assertEqual(result.status, 3)
        start, end = self.noted()
        self.assertEqual((start["did"], end["did"]), ("started", "ended"))
        self.assertEqual(start["session"], "claude-proj")
        self.assertEqual(start["project"], str(self.project))
        self.assertEqual(start["runtime"], "gVisor (runsc)")
        self.assertEqual(
            (start["memory"], start["pids"], start["cpus"]), ("4g", "512", "2")
        )
        self.assertEqual(start["image"], result.image)
        # Not worth a word when the session ends
        self.assertNotIn("of this session", result.stderr)

    def test_the_plugins_switched_on_are_noted_with_their_versions(self):
        claude = self.home / ".claude"
        (claude / "plugins").mkdir(parents=True, exist_ok=True)
        (claude / "settings.json").write_text(
            json.dumps(
                {
                    "enabledPlugins": {
                        "tool@market": True,
                        "off@market": False,
                        "local@market": True,
                        "gone@market": True,
                    }
                }
            )
        )
        installs = {
            "tool@market": [
                {"scope": "user", "version": "1.2.0"},
                {
                    "scope": "project",
                    "projectPath": str(self.project),
                    "version": "1.3.0",
                },
            ],
            "off@market": [{"scope": "user", "version": "2.0.0"}],
            "local@market": [{"scope": "user", "version": "0.1.0"}],
        }
        (claude / "plugins" / "installed_plugins.json").write_text(
            json.dumps({"version": 2, "plugins": installs})
        )
        # The project's settings are over the user's, its own over both
        (self.project / ".claude").mkdir(exist_ok=True)
        (self.project / ".claude" / "settings.json").write_text(
            json.dumps({"enabledPlugins": {"off@market": True, "local@market": True}})
        )
        (self.project / ".claude" / "settings.local.json").write_text(
            json.dumps({"enabledPlugins": {"local@market": False}})
        )
        self.launch()
        start, _ = self.noted()
        self.assertEqual(
            start["plugins"], ["gone@market", "off@market 2.0.0", "tool@market 1.3.0"]
        )

    def test_the_language_servers_of_the_image_are_noted(self):
        self.launch(CLAUDE_AIRLOCK_FEATURES="python go typst")
        self.assertEqual(self.noted()[0]["servers"], ["gopls", "pyright"])
        # None for an image without any, nor for bash, given no plugin
        for args, features in (((), "typst"), (("--shell",), "go")):
            (self.state / "session-starts.jsonl").unlink()
            self.launch(*args, CLAUDE_AIRLOCK_FEATURES=features)
            self.assertEqual(self.noted()[0]["servers"], [])

    def test_settings_that_cannot_be_read_switch_no_plugin_on(self):
        claude = self.home / ".claude"
        (claude / "plugins").mkdir(parents=True, exist_ok=True)
        (claude / "plugins" / "installed_plugins.json").write_text("[1, 2")
        (self.project / ".claude").mkdir(exist_ok=True)
        (self.project / ".claude" / "settings.json").write_text(
            json.dumps({"enabledPlugins": ["tool@market"]})
        )
        (self.project / ".claude" / "settings.local.json").write_text(
            json.dumps({"enabledPlugins": {"tool@market": "yes", "": True}})
        )
        self.launch()
        start, _ = self.noted()
        self.assertEqual(start["plugins"], [])

    def test_a_trace_shows_how_the_session_was_started(self):
        self.launch(CLAUDE_AIRLOCK_NET_FILTER="1", FAKE_INFO=INFO)
        record = self.state / "session-starts.jsonl"
        start, _ = record.read_text().splitlines()
        # As a session that still runs, or whose launcher was killed
        record.write_text(start + "\n")
        # The transcript begins after the session was started
        now = time.time()
        self.write_transcript("3fa9c0de", prompts_at(now + 60, now + 120))
        trace = self.launch("--trace").stdout
        summary = "claude-proj under runc, memory 16g, processes 512, all CPUs"
        self.assertIn(f"# sandbox     {summary}, network filtered\n", trace)
        self.assertRegex(
            trace, r"sandbox  started     claude-proj under runc, image \S+\n"
        )
        self.assertRegex(trace, r"sandbox  started     recorded: nothing\n")
        self.assertLess(
            trace.index("limits: memory 16g"), trace.index("prompt      hello")
        )
        as_json = self.launch("--trace", "--json").stdout.splitlines()
        first = json.loads(as_json[0])
        self.assertEqual((first["who"], first["what"]), ("sandbox", "started"))
        self.assertEqual(first["container"], "claude-proj")
        self.assertEqual((first["memory"], first["net_filter"]), ("16g", True))
        # The header is of the whole session, whatever is chosen of it
        failed = self.launch("--trace", "--failed").stdout
        self.assertIn("# sandbox     claude-proj", failed)
        self.assertNotIn("sandbox  started", failed)
        # Not one that started after the transcript ends
        self.write_transcript("3fa9c0de", prompts_at(now - 3600, now - 3540))
        self.assertNotIn("started", self.launch("--trace").stdout)
        # Nor one that was over before it begins
        started.note_end(self.host, "claude-proj")
        self.write_transcript("3fa9c0de", prompts_at(now + 60, now + 120))
        self.assertNotIn("started", self.launch("--trace").stdout)

    def test_a_start_is_followed_as_it_is_noted_and_of_its_session(self):
        mine = NewlyNoted(self.host, "claude-proj")
        others = NewlyNoted(self.host, "claude-other")
        # A note is of the thousandth of a second it was added in
        time.sleep(0.002)
        start = started.Start.of(
            settings.Settings(), runtime.DOCKERS_OWN, "", [], ssh_agent=False
        )
        said = started.note_start(self.host, "claude-proj", start)
        started.note_end(self.host, "claude-proj")
        (event,) = mine.poll()
        self.assertEqual(event.details, said.details)
        self.assertEqual(event.what, "started")
        self.assertEqual(others.poll() + mine.poll(), [])
        # In the header of a trace by what is made of the events
        rows, events = noted_events(self.host, 0, time.time())
        self.assertEqual(rows, [])
        self.assertEqual([found.details for found in events], [said.details])


if __name__ == "__main__":
    unittest.main()
