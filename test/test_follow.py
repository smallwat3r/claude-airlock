#!/usr/bin/env python3
"""--trace --follow: what a session does, shown as it does it, from its
transcript, its capture and the egress proxy's log as they grow."""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from datetime import datetime, timezone
from pathlib import Path
from unittest import mock

from harness import LAUNCHER, LauncherTest, follow, pcap
from test_capture import answer, pcap_file, sample_capture, tcp

from claude_airlock.events import Event, Kind, Stage, Who
from claude_airlock.report import stream
from claude_airlock.report.transcript import WalkOptions
from claude_airlock.settings import Host

# Marks the last thing a test wrote: what came before it has been shown
# once this is
DONE = "that is all"
# A test that waits for what never comes fails after this many seconds
PATIENCE = 30.0


def at(second: int) -> str:
    return f"2026-01-02T10:00:{second:02d}Z"


def prompt(text: str, second: int = 0) -> dict:
    return {"type": "user", "timestamp": at(second), "message": {"content": text}}


def call(tool_id: str, name: str, second: int = 1, **tool_input) -> dict:
    block = {"type": "tool_use", "id": tool_id, "name": name, "input": tool_input}
    return {
        "type": "assistant",
        "timestamp": at(second),
        "message": {"content": [block]},
    }


def result(tool_id: str, output: str, second: int = 3, failed: bool = False) -> dict:
    block = {"type": "tool_result", "tool_use_id": tool_id, "content": output}
    return {
        "type": "user",
        "timestamp": at(second),
        "message": {"content": [{**block, "is_error": failed}]},
    }


def add(file: Path, *entries: dict) -> None:
    with open(file, "a") as transcript:
        transcript.write("".join(json.dumps(entry) + "\n" for entry in entries))


class Following:
    """The launcher following, its output read a line at a time."""

    def __init__(self, test: LauncherTest, *args: str, **env: str):
        environment = {
            **test.fake_docker_env(),
            "HOME": str(test.home),
            "CLAUDE_AIRLOCK_NET_LOG": "0",
            **env,
        }
        self.process: subprocess.Popen = subprocess.Popen(
            [sys.executable, str(LAUNCHER), "--trace", "--follow", *args],
            cwd=test.project,
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        self._timer = threading.Timer(PATIENCE, self.process.kill)
        self._timer.start()
        test.addCleanup(self.stop)

    def until(self, text: str) -> str:
        """What is written up to and with the first line that has text."""
        lines = []
        assert self.process.stdout
        for line in self.process.stdout:
            lines.append(line)
            if text in line:
                return "".join(lines)
        raise AssertionError(f"ended without {text!r}:\n{''.join(lines)}")

    def stop(self) -> int:
        """Interrupt it, as Ctrl-C does. Returns its exit status."""
        self._timer.cancel()
        if self.process.poll() is None:
            self.process.send_signal(signal.SIGINT)
        try:
            return self.process.wait(timeout=PATIENCE)
        finally:
            for stream in (self.process.stdout, self.process.stderr):
                if stream:
                    stream.close()


class FollowTest(LauncherTest):
    SESSION = "3fa9c0de-0000-4000-8000-000000000000"

    def setUp(self):
        super().setUp()
        self.file = self.write_transcript(self.SESSION, [prompt("fix the build")])

    def test_a_call_shows_when_issued_and_its_result_when_it_comes(self):
        following = Following(self)
        shown = following.until("fix the build")
        self.assertIn("# session     3fa9c0de-0000-4000-8000-000000000000", shown)
        add(self.file, call("t1", "Bash", command="make", description="Build"))
        shown = following.until("why: Build")
        self.assertIn("claude   bash        [1] $ make", shown)
        self.assertNotIn("result:", shown)
        add(self.file, result("t1", "no rule", failed=True))
        shown = following.until("out: no rule")
        self.assertIn(
            "claude   bash        [1] result: FAILED, 2.0s, 1 line out", shown
        )
        self.assertNotIn("of: ", shown)
        self.assertEqual(following.stop(), 0)

    def test_a_result_names_its_call_when_another_came_between(self):
        following = Following(self)
        add(
            self.file,
            call("t1", "Bash", command="make"),
            call("t2", "Read", file_path="go.mod"),
            result("t1", "done"),
            result("t9", "of a call that was never seen"),
            prompt(DONE, 4),
        )
        shown = following.until(DONE)
        self.assertIn("claude   read        [2] file: go.mod\n", shown)
        self.assertIn("claude   bash        [1] of: $ make\n", shown)
        self.assertIn("claude   bash        result: ok, 2.0s, 1 line out\n", shown)
        self.assertEqual(shown.count("result:"), 1)

    def test_failed_shows_what_went_wrong_and_names_its_call(self):
        following = Following(self, "--failed")
        add(
            self.file,
            call("t1", "Bash", command="make"),
            result("t1", "no rule", failed=True),
            call("t2", "Bash", command="ls"),
            result("t2", "go.mod"),
            call("t3", "Write", 4, file_path="/etc/motd", content="hi"),
        )
        shown = following.until("OUTSIDE PROJECT")
        self.assertIn("# shown       only what went wrong\n", shown)
        self.assertIn("claude   bash        [1] of: $ make\n", shown)
        self.assertIn("claude   bash        result: FAILED, 2.0s, 1 line out\n", shown)
        self.assertNotIn("$ ls", shown)
        self.assertNotIn("prompt      fix the build", shown)

    def test_only_shows_the_kinds_named(self):
        following = Following(self, "--only=read", "--json")
        add(
            self.file,
            call("t1", "Bash", command="make"),
            call("t2", "Read", file_path="go.mod"),
            result("t2", "module x"),
        )
        shown = following.until('"stage": "result"')
        self.assertEqual(
            [json.loads(line)["what"] for line in shown.splitlines()], ["read", "read"]
        )

    def test_only_the_latest_of_what_came_before_is_shown(self):
        add(self.file, *(prompt(f"number {n}", n) for n in range(1, 21)))
        shown = Following(self).until("number 20")
        self.assertIn("# 11 earlier events, see claude-airlock --trace", shown)
        self.assertNotIn("number 10\n", shown)
        self.assertIn("number 11\n", shown)

    def test_a_session_that_starts_later_is_picked_up(self):
        old = self.write_transcript("0a", [prompt("long ago")])
        os.utime(old, (1, 1))
        following = Following(self)
        following.until("fix the build")
        self.write_transcript("0b", [prompt("a new session")])
        add(old, prompt("resumed", 5))
        shown = following.until("resumed")
        self.assertIn("# session     0b  a new session", shown)
        self.assertIn("# session     0a  long ago", shown)
        self.assertNotIn("prompt      long ago", shown)

    def test_what_a_subagent_did_before_is_not_shown_as_done_now(self):
        earlier = self.write_transcript("0e" + self.SESSION[2:], [prompt("earlier")])
        os.utime(earlier, (1, 1))
        old = earlier.with_suffix("") / "subagents" / "agent-a1.jsonl"
        old.parent.mkdir(parents=True)
        add(old, call("s1", "Bash", command="echo before the follow"))
        host = Host(str(self.home), str(self.project), "", str(self.state))
        follower = follow.Follower(host, verbose=False)
        with mock.patch.object(follow.CaptureSidecar, "running", return_value=[]):
            follower.poll()
            # The earlier session goes on, with a subagent of now
            add(earlier, prompt("go on"))
            add(old, call("s2", "Bash", command="echo during the follow"))
            shown = []
            for _ in range(follow.LOOK_EVERY + 1):
                shown += [event.details[0] for _, event in follower.poll().events]
        self.assertIn("go on", shown)
        self.assertIn("$ echo during the follow", shown)
        self.assertNotIn("$ echo before the follow", shown)

    def test_the_calls_remembered_are_bounded_without_a_capture(self):
        timeline = stream.Timeline()
        now = time.time()

        def said(number: int, stage: Stage, when: float) -> Event:
            fields = {"id": f"c{number}", "tool": "Bash", "stage": stage}
            return Event(when, Who.CLAUDE, "bash", ["$ make"], fields)

        with mock.patch.object(stream, "MOST_CALLS", 5):
            for number in range(50):
                when = now - 5000 + number * 100
                timeline.take(said(number, Stage.CALL, when))
                if number % 2:
                    timeline.take(said(number, Stage.RESULT, when + 1))
            # Those that ended long ago are let go of, and of those that
            # never did, the oldest
            self.assertLessEqual(len(timeline._calls), 5)
            self.assertIn("c48", timeline._calls)
        # One dated ahead does not make what is read after it too long ago
        timeline.take(said(60, Stage.CALL, now + 10**6))
        late = Event(now, Who.SANDBOX, Kind.NET, ["tcp"], {})
        timeline.take(late)
        self.assertIn("during", late.fields)

    def test_a_named_session_is_followed_alone(self):
        other = self.write_transcript("0a", [prompt("the other one")])
        following = Following(self, "3fa9")
        add(other, prompt("more of the other"))
        add(self.file, prompt(DONE, 4))
        self.assertNotIn("other", following.until(DONE))

    def test_json_tells_a_call_from_its_result(self):
        following = Following(self, "--json")
        add(self.file, call("t1", "Bash", command="make"), result("t1", "done"))
        add(self.file, prompt(DONE, 4))
        asked, issued, ended, _ = map(json.loads, following.until(DONE).splitlines())
        self.assertEqual((asked["what"], asked["session"]), ("prompt", self.SESSION))
        self.assertEqual((issued["stage"], issued["id"]), ("call", "t1"))
        self.assertEqual(issued["input"], {"command": "make"})
        self.assertNotIn("failed", issued)
        self.assertEqual((ended["stage"], ended["id"]), ("result", "t1"))
        self.assertEqual((ended["tool"], ended["what"]), ("Bash", "bash"))
        self.assertEqual((ended["failed"], ended["output"]), (False, "done"))

    def test_what_a_session_writes_cannot_drive_the_terminal(self):
        following = Following(self)
        add(self.file, call("t1", "Bash", command="make \x1b]0;owned\x07all"))
        add(self.file, call("t2", "Bash", command="a\nforged line"), prompt(DONE, 4))
        shown = following.until(DONE)
        self.assertIn("$ make ]0;ownedall", shown)
        self.assertNotRegex(shown, r"[\x00-\x08\x0b-\x1f\x7f]")
        self.assertIn("claude   bash        $   forged line", shown)

    def test_of_what_is_said_only_the_first_line_is_shown(self):
        for form in ((), ("--verbose",)):
            following = Following(self, *form)
            add(self.file, prompt("\n  \none\n\nand more\nlines", 4), prompt(DONE, 5))
            shown = following.until(DONE)
            self.assertIn("prompt      one\n", shown)
            self.assertNotIn("and more", shown)
            following.stop()

    def test_json_has_all_of_what_is_said(self):
        following = Following(self, "--json")
        add(self.file, prompt("one\n\ntwo", 4), prompt(DONE, 5))
        said = [json.loads(line) for line in following.until(DONE).splitlines()]
        self.assertEqual(said[1]["text"], "one\n\ntwo")

    def test_a_step_of_the_model_says_what_it_used_once_with_verbose(self):
        following = Following(self, "--verbose")
        usage = {"input_tokens": 500, "output_tokens": 90, "cache_read_input_tokens": 1}
        entries = [call("t1", "Bash", command="make"), call("t2", "Bash", command="ls")]
        for entry in entries:
            entry["message"].update(id="msg_1", usage=usage)
        add(self.file, *entries, prompt(DONE, 4))
        shown = following.until(DONE)
        self.assertEqual(
            shown.count("claude   step        90 tokens out, 501 in (500 new)"), 1
        )
        self.assertLess(shown.index("step        90"), shown.index("$ make"))
        entries[0]["message"]["id"] = entries[1]["message"]["id"] = "msg_2"
        add(self.file, *entries, prompt("once more", 5))
        self.assertNotIn("step", Following(self).until("once more"))

    def test_colour_marks_what_a_line_is(self):
        following = Following(self, FORCE_COLOR="1")
        fetch = call("t2", "WebFetch", url="https://good.test")
        add(self.file, call("t1", "Bash", command="make"), fetch, prompt(DONE, 4))
        shown = following.until(DONE)
        self.assertIn(
            "\x1b[34mclaude   webfetch    [2] url: https://good.test\x1b[0m", shown
        )
        self.assertIn("\x1b[2m# session", shown)
        self.assertIn("\x1b[33mclaude   bash        [1] $ make\x1b[0m", shown)
        self.assertIn("\x1b[2muser     prompt      fix the build\x1b[0m", shown)

    def test_without_a_session_it_waits_for_one(self):
        self.file.unlink()
        following = Following(self)
        following.until("# no session of this project yet")
        self.write_transcript("0b", [prompt("the first")])
        self.assertIn("# session     0b  the first", following.until("the first"))

    def test_a_list_cannot_be_followed(self):
        result = self.launch("--trace", "--follow", "list")
        self.assertEqual(result.status, 1)
        self.assertIn("usage: claude-airlock --trace", result.stderr)

    def test_nothing_is_asked_of_docker_about_another_project(self):
        about = {"project": "/elsewhere", "start": 5, "pid": 1}
        ps = "claude-other.capture\t" + json.dumps(about)
        following = Following(self, FAKE_PS=ps)
        shown = following.until("fix the build")
        following.stop()
        self.assertIn("# network     no session of this project is recorded", shown)
        self.assertEqual([c for c in self.calls() if c[0] != "ps"], [])


class FollowNetworkTest(LauncherTest):
    SIDECAR = "claude-proj.capture"

    def setUp(self):
        super().setUp()
        self.now = time.time()
        stamp = datetime.fromtimestamp(self.now + 20, timezone.utc).isoformat()  # noqa: UP017
        self.last = {"type": "user", "timestamp": stamp, "message": {"content": DONE}}
        self.file = self.write_transcript("0a", [prompt("long ago")])
        about = {"project": str(self.project), "start": self.now, "pid": os.getpid()}
        self.ps = f"{self.SIDECAR}\t{json.dumps(about)}"

    def test_connections_show_as_the_capture_grows(self):
        captured = self.work / "capture.pcap"
        captured.write_bytes(sample_capture(self.now))
        following = Following(self, FAKE_PS=self.ps, FAKE_CAPTURE=str(captured))
        shown = following.until("203.0.113.9")
        self.assertIn("# network     following the capture of claude-proj", shown)
        self.assertIn(
            "sandbox  net         tcp/https good.test (198.51.100.7):443", shown
        )
        self.assertNotIn("lookup", shown)
        more = pcap_file([(self.now + 9, tcp("192.0.2.44", 6379), True)])
        with open(captured, "ab") as growing:
            # Without the header of the file, and the packet in two parts
            growing.write(more[24:-10])
        add(self.file, prompt("in between"))
        self.assertNotIn("192.0.2.44", following.until("in between"))
        with open(captured, "ab") as growing:
            growing.write(more[-10:])
        add(self.file, self.last)
        shown = following.until(DONE)
        self.assertEqual(
            shown.count("sandbox  net         tcp/redis 192.0.2.44:6379"), 1
        )
        self.assertNotIn("198.51.100.7", shown)
        tails = [c for c in self.calls() if c[:1] == ["exec"]]
        self.assertEqual(
            tails[0], ["exec", self.SIDECAR, "tail", "-c", "+1", "/capture.pcap"]
        )

    def test_how_a_session_is_doing_shows_as_its_watcher_says_it(self):
        about = {"project": str(self.project), "start": self.now, "pid": os.getpid()}
        said = self.work / "said"
        lines = [
            # From before the following began, and not about its health
            {"t": self.now - 60, "health": {"mem": [1, 2**34]}},
            {"t": self.now + 60, "pid": 5, "ppid": 1, "exe": "/bin/x", "argv": ["x"]},
            {"t": self.now + 60, "health": {"mem": [2**31, 2**34], "cpu": 12.0}},
            {"t": self.now + 61, "oom": 1, "gone": [[812, 2**33, "node"]]},
            "not a line of it",
        ]
        said.write_text("".join(json.dumps(line) + "\n" for line in lines))
        following = Following(
            self,
            FAKE_PS=f"claude-proj.procs\t{json.dumps(about)}",
            FAKE_PROXY_LOG=str(said),
        )
        shown = following.until("OUT OF MEMORY")
        self.assertEqual(shown.count("sandbox  health"), 2)
        self.assertIn("sandbox  health      mem 2g of 16g (12%)  cpu 12%", shown)
        self.assertIn("gone since: [812] node 8g", shown)
        # Asked of the watcher from outside, nothing is run next to the session
        asked = [c for c in self.calls() if c[:1] == ["logs"]]
        self.assertEqual(asked[0][2], "claude-proj.procs")
        self.assertRegex(asked[0][1], r"^--since=\d+\.\d{3}$")
        self.assertEqual([c for c in self.calls() if c[:1] == ["exec"]], [])

    def test_what_becomes_of_a_connection_shows_when_it_does(self):
        captured = self.work / "capture.pcap"
        there = "198.51.100.7"
        opened = [
            (self.now + 1, tcp(there, 443, sequence=1000), True),
            (self.now + 1, answer(there, 443, sequence=5000), False),
        ]
        captured.write_bytes(pcap_file(opened))
        following = Following(
            self, "--json", FAKE_PS=self.ps, FAKE_CAPTURE=str(captured)
        )
        shown = map(json.loads, following.until(there).splitlines())
        (start,) = (event for event in shown if event["what"] == "net")
        self.assertEqual((start["stage"], start.get("outcome")), ("open", None))
        closing = tcp(there, 443, 0x11, sequence=1101, acknowledged=5201)
        with open(captured, "ab") as growing:
            growing.write(pcap_file([(self.now + 4, closing, True)])[24:])
        end = json.loads(following.until(there).splitlines()[-1])
        self.assertEqual((end["stage"], end["outcome"]), ("outcome", "closed"))
        self.assertEqual(
            (end["seconds"], end["bytes_out"], end["bytes_in"]), (3.0, 100, 200)
        )
        self.assertEqual(end["source_port"], start["source_port"])

    def test_a_connection_is_put_with_the_call_running_then(self):
        captured = self.work / "capture.pcap"
        captured.write_bytes(pcap_file([]))
        following = Following(self, FAKE_PS=self.ps, FAKE_CAPTURE=str(captured))
        following.until("long ago")
        now = datetime.fromtimestamp(time.time(), timezone.utc).isoformat()  # noqa: UP017
        running = call("t1", "Bash", command="curl good.test")
        add(self.file, {**running, "timestamp": now})
        following.until("$ curl good.test")
        with open(captured, "ab") as growing:
            growing.write(
                pcap_file([(time.time(), tcp("198.51.100.7", 443), True)])[24:]
            )
        shown = following.until("198.51.100.7")
        self.assertIn("198.51.100.7:443  during: [1] $ curl good.test\n", shown)

    def test_verbose_adds_the_lookups(self):
        captured = self.work / "capture.pcap"
        captured.write_bytes(sample_capture(self.now))
        following = Following(
            self, "--verbose", FAKE_PS=self.ps, FAKE_CAPTURE=str(captured)
        )
        shown = following.until("203.0.113.9")
        self.assertIn("sandbox  dns         lookup good.test", shown)

    def test_the_requests_of_a_filtered_session_show_as_they_are_logged(self):
        mine, other = "172.20.0.5", "172.20.0.9"
        sessions = [
            {"name": "claude-proj", "project": str(self.project), "ip": mine},
            {"name": "claude-gone", "project": str(self.project), "ip": other},
        ]
        self.state.mkdir(parents=True)
        (self.state / "net-sessions.jsonl").write_text(
            "".join(json.dumps({**s, "start": self.now}) + "\n" for s in sessions)
        )
        log = self.work / "access.log"
        log.write_text(
            f"{self.now:.3f} 0 {mine} TCP_DENIED/403 9 CONNECT before.test:443 - -\n"
        )
        following = Following(
            self, FAKE_PS="claude-proj\nclaude-egress-proxy", FAKE_ACCESS_LOG=str(log)
        )
        following.until("long ago")
        with open(log, "a") as logged:
            logged.write(
                f"{self.now + 5:.3f} 0 {mine} TCP_DENIED/403 300 CONNECT"
                " \x1b[31mevil.test:443 - -\n"
                f"{self.now + 6:.3f} 0 {other} TCP_TUNNEL/200 50 CONNECT"
                " theirs.test:443 - -\n"
                f"{self.now + 7:.3f} 200 {mine} TCP_TUNNEL/200 4000 CONNECT half"
            )
        add(self.file, self.last)
        shown = following.until(DONE)
        self.assertIn("net         proxy CONNECT [31mevil.test:443 DENIED 300 B", shown)
        for absent in ("before.test", "theirs.test", "half", "\x1b"):
            self.assertNotIn(absent, shown)

    def test_sessions_followed_together_are_told_apart_by_container(self):
        mine, other = "172.20.0.5", "172.20.0.9"
        sessions = [
            {"name": "claude-proj", "project": str(self.project), "ip": mine},
            {"name": "claude-proj-2", "project": str(self.project), "ip": other},
        ]
        self.state.mkdir(parents=True)
        (self.state / "net-sessions.jsonl").write_text(
            "".join(json.dumps({**s, "start": self.now}) + "\n" for s in sessions)
        )
        log = self.work / "access.log"
        log.touch()
        following = Following(
            self,
            FAKE_PS="claude-proj\nclaude-proj-2\nclaude-egress-proxy",
            FAKE_ACCESS_LOG=str(log),
        )
        following.until("long ago")
        with open(log, "a") as logged:
            logged.write(
                f"{self.now + 5:.3f} 0 {mine} TCP_TUNNEL/200 50 CONNECT"
                " mine.test:443 - -\n"
                f"{self.now + 6:.3f} 0 {other} TCP_TUNNEL/200 50 CONNECT"
                " theirs.test:443 - -\n"
            )
        add(self.file, self.last)
        shown = following.until(DONE)
        self.assertIn(
            "net         [claude-proj] proxy/https CONNECT mine.test:443", shown
        )
        self.assertIn(
            "net         [claude-proj-2] proxy/https CONNECT theirs.test:443", shown
        )


class TranscriptTailTest(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.file = Path(temp.name, "0a.jsonl")
        self.file.touch()

    def said(self, tail) -> list[str]:
        return [event.details[0] for event in tail.poll()]

    def test_a_line_is_read_once_it_is_whole(self):
        tail = follow.TranscriptTail(self.file, "/proj", WalkOptions(live=True))
        whole = json.dumps(prompt("hello")) + "\n"
        self.file.write_text(whole[:20])
        self.assertEqual(self.said(tail), [])
        self.file.write_text(whole + "{not json}\n[1]\n" + whole)
        # A whole line that holds no entry is not Claude Code's doing
        self.assertEqual(
            self.said(tail),
            [
                "hello",
                "UNREADABLE line of the transcript: {not json}",
                "UNREADABLE line of the transcript: [1]",
                "hello",
            ],
        )
        self.assertEqual(self.said(tail), [])

    def test_a_line_too_long_to_hold_is_dropped_and_said_to_be(self):
        tail = follow.TranscriptTail(self.file, "/proj", WalkOptions(live=True))
        with mock.patch.object(follow, "LINE_LIMIT", 100):
            add(self.file, prompt("x" * 500))
            # Still without its end, which the next look finds
            with open(self.file, "a") as transcript:
                transcript.write(json.dumps(prompt("y" * 500))[:400])
            too_long = "UNREADABLE line of the transcript: (a line too long to read)"
            self.assertEqual(self.said(tail), ["x" * 200 + "...", too_long])
            with open(self.file, "a") as transcript:
                transcript.write("the rest of it\n")
            add(self.file, prompt("after"))
            self.assertEqual(self.said(tail), ["after"])

    def test_a_line_many_times_too_long_is_said_once(self):
        tail = follow.TranscriptTail(self.file, "/proj", WalkOptions(live=True))
        too_long = "UNREADABLE line of the transcript: (a line too long to read)"
        with (
            mock.patch.object(follow, "LINE_LIMIT", 100),
            mock.patch.object(follow, "READ_SIZE", 64),
        ):
            # Read in pieces, and found again without its end every time
            with open(self.file, "a") as transcript:
                transcript.write(json.dumps(prompt("x" * 2000))[:1000])
            self.assertEqual(self.said(tail), [too_long])
            with open(self.file, "a") as transcript:
                transcript.write("y" * 1000)
            self.assertEqual(self.said(tail), [])
            with open(self.file, "a") as transcript:
                transcript.write("its end\n")
            add(self.file, prompt("after"))
            self.assertEqual(self.said(tail), ["after"])

    def test_a_transcript_written_anew_is_read_from_its_new_end(self):
        tail = follow.TranscriptTail(self.file, "/proj", WalkOptions(live=True))
        add(self.file, prompt("one"), prompt("two"))
        self.assertEqual(self.said(tail), ["one", "two"])
        self.file.write_text(json.dumps(prompt("anew")) + "\n")
        self.assertEqual(self.said(tail), [])
        add(self.file, prompt("three"))
        self.assertEqual(self.said(tail), ["three"])

    def test_a_link_or_a_pipe_in_its_place_is_not_read(self):
        secret = self.file.with_name("secret")
        secret.write_text(json.dumps(prompt("a secret")) + "\n")
        self.file.unlink()
        self.file.symlink_to(secret)
        tail = follow.TranscriptTail(self.file, "/proj", WalkOptions(live=True))
        self.assertEqual(self.said(tail), [])
        self.file.unlink()
        os.mkfifo(self.file)
        self.assertEqual(self.said(tail), [])


class PcapReaderTest(unittest.TestCase):
    def test_a_capture_fed_in_pieces_reads_as_the_whole(self):
        whole = sample_capture(1000.0)
        for size in (1, 7, 4096):
            reader, found = pcap.PcapReader(), pcap.Capture()
            for start in range(0, len(whole), size):
                pcap.take_frames(found, reader.feed(whole[start : start + size]))
            self.assertEqual(len(found.connections), 3)
            self.assertEqual(found.packets, 10)

    def test_nothing_is_read_past_what_is_not_a_capture(self):
        reader = pcap.PcapReader()
        self.assertEqual(list(reader.feed(b"not a capture at all, really")), [])
        self.assertEqual(list(reader.feed(sample_capture(1000.0))), [])


if __name__ == "__main__":
    unittest.main()
