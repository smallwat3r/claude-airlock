#!/usr/bin/env python3
"""--trace --follow: what a session does, shown as it does it, from its
transcript, its capture and the egress proxy's log as they grow."""

from __future__ import annotations

import json
import os
import re
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest import mock

import pytest
from harness import LAUNCHER, LauncherTest
from packets import (
    answer,
    dns_response,
    knock,
    pcap_file,
    read_parts,
    sample_capture,
    taken_up,
    tcp,
)
from transcribed import at, call, prompt, result

from claude_airlock import projects
from claude_airlock.events import Event, Kind, Stage, Who
from claude_airlock.recording import capture as capture_module
from claude_airlock.recording import pcap
from claude_airlock.recording.pcap_file import PcapReader
from claude_airlock.report import follow, stream, tails, transcript
from claude_airlock.report.layout import Layout
from claude_airlock.report.transcript import WalkOptions

# Marks the last thing a test wrote: what came before it has been shown
# once this is
DONE = "that is all"
# A test that waits for what never comes fails after this many seconds
PATIENCE = 30.0


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
        test.cleanup.callback(self.stop)

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

    @pytest.fixture(autouse=True)
    def transcript(self, sandbox: None) -> None:
        self.file = self.write_transcript(self.SESSION, [prompt("fix the build")])

    def test_a_call_shows_when_issued_and_its_result_when_it_comes(self):
        following = Following(self)
        shown = following.until("fix the build")
        assert "# session     3fa9c0de-0000-4000-8000-000000000000" in shown
        add(self.file, call("t1", "Bash", command="make", description="Build"))
        shown = following.until("why: Build")
        assert "claude   bash        [1] $ make" in shown
        assert "result:" not in shown
        add(self.file, result("t1", "no rule", 3, failed=True))
        shown = following.until("out: no rule")
        assert "claude   bash        [1] result: FAILED, 2.0s, 1 line out" in shown
        assert "of: " not in shown
        assert following.stop() == 0

    def test_a_result_names_its_call_when_another_came_between(self):
        following = Following(self)
        add(
            self.file,
            call("t1", "Bash", command="make"),
            call("t2", "Read", file_path="go.mod"),
            result("t1", "done", 3),
            result("t9", "of a call that was never seen", 3),
            prompt(DONE, 4),
        )
        shown = following.until(DONE)
        assert "claude   read        [2] file: go.mod\n" in shown
        assert "claude   bash        [1] of: $ make\n" in shown
        assert "claude   bash        result: ok, 2.0s, 1 line out\n" in shown
        assert shown.count("result:") == 1

    def test_failed_shows_what_went_wrong_and_names_its_call(self):
        following = Following(self, "--failed")
        add(
            self.file,
            call("t1", "Bash", command="make"),
            result("t1", "no rule", 3, failed=True),
            call("t2", "Bash", command="ls"),
            result("t2", "go.mod", 3),
            call("t3", "Write", 4, file_path="/etc/motd", content="hi"),
        )
        shown = following.until("OUTSIDE PROJECT")
        assert "# shown       only what went wrong\n" in shown
        assert "claude   bash        [1] of: $ make\n" in shown
        assert "claude   bash        result: FAILED, 2.0s, 1 line out\n" in shown
        assert "$ ls" not in shown
        assert "prompt      fix the build" not in shown

    def test_only_shows_the_kinds_named(self):
        following = Following(self, "--only=read", "--json")
        add(
            self.file,
            call("t1", "Bash", command="make"),
            call("t2", "Read", file_path="go.mod"),
            result("t2", "module x", 3),
        )
        shown = following.until('"stage": "result"')
        assert [json.loads(line)["what"] for line in shown.splitlines()] == [
            "read",
            "read",
        ]

    def test_only_the_latest_of_what_came_before_is_shown(self):
        add(self.file, *(prompt(f"number {n}", n) for n in range(1, 21)))
        shown = Following(self).until("number 20")
        assert "# 11 earlier events, see claude-airlock --trace" in shown
        assert "number 10\n" not in shown
        assert "number 11\n" in shown

    def test_a_session_that_starts_later_is_picked_up(self):
        old = self.write_transcript("0a", [prompt("long ago")])
        os.utime(old, (1, 1))
        following = Following(self)
        following.until("fix the build")
        self.write_transcript("0b", [prompt("a new session")])
        add(old, prompt("resumed", 5))
        shown = following.until("resumed")
        assert "# session     0b  a new session" in shown
        assert "# session     0a  long ago" in shown
        assert "prompt      long ago" not in shown

    def test_what_a_subagent_did_before_is_not_shown_as_done_now(self):
        earlier = self.write_transcript("0e" + self.SESSION[2:], [prompt("earlier")])
        os.utime(earlier, (1, 1))
        old = earlier.with_suffix("") / "subagents" / "agent-a1.jsonl"
        old.parent.mkdir(parents=True)
        add(old, call("s1", "Bash", command="echo before the follow"))
        follower = follow.Follower(self.host, verbose=False)
        with mock.patch.object(tails.CaptureSidecar, "running", return_value=[]):
            follower.poll()
            # The earlier session goes on, with a subagent of now
            add(earlier, prompt("go on"))
            add(old, call("s2", "Bash", command="echo during the follow"))
            shown = []
            for _ in range(follow.LOOK_EVERY + 1):
                shown += [event.details[0] for _, event in follower.poll().events]
        assert "go on" in shown
        assert "$ echo during the follow" in shown
        assert "$ echo before the follow" not in shown

    def test_what_a_subagent_does_says_which_subagent_it_is_of(self):
        theirs = self.file.with_suffix("") / "subagents"
        theirs.mkdir(parents=True)
        # One that did something before the following began, and no more
        add(theirs / "agent-a0.jsonl", call("s0", "Bash", command="echo before"))
        follower = follow.Follower(self.host, verbose=False)

        def of_agent(entry: dict) -> dict:
            return {**entry, "isSidechain": True}

        def says(text: str, second: int) -> dict:
            said = {"content": [{"type": "text", "text": text}]}
            return of_agent(
                {"type": "assistant", "timestamp": at(second), "message": said}
            )

        with mock.patch.object(tails.CaptureSidecar, "running", return_value=[]):
            follower.poll()
            # Two at work side by side, each in a transcript that counts
            # its calls from 1, as that of claude does
            add(self.file, call("t1", "Bash", command="make"))
            add(
                theirs / "agent-a1.jsonl",
                says("looking for the bug", 1),
                of_agent(call("s1", "Bash", 2, command="grep bug")),
                of_agent(result("s1", "found", 4)),
            )
            add(
                theirs / "agent-a2.jsonl",
                of_agent(call("s1", "Bash", 3, command="pytest")),
                of_agent(call("s2", "Read", 5, file_path="go.mod")),
            )
            shown = []
            for _ in range(follow.LOOK_EVERY + 1):
                shown += [event for _, event in follower.poll().events]
        said = "".join(line + "\n" for line in Layout().events(shown))
        for expected in (
            "claude   bash        [1] $ make\n",
            # Numbered when it first does something, not one that does
            # nothing: what it says by its number, its calls after that
            "agent    reply       [a1] looking for the bug\n",
            "agent    bash        [a1.1] $ grep bug\n",
            "agent    bash        [a1.1] of: $ grep bug\n",
            "agent    bash        [a2.1] $ pytest\n",
            "agent    read        [a2.2] file: go.mod\n",
        ):
            assert expected in said, said
        assert "echo before" not in said

    def test_subagents_past_those_that_are_followed_are_said_once(self):
        theirs = self.file.with_suffix("") / "subagents"
        theirs.mkdir(parents=True)
        for name in ("agent-!1.jsonl", "agent-!2.jsonl", "agent-a1.jsonl"):
            (theirs / name).touch()
        follower = follow.Follower(self.host, verbose=False)
        with (
            mock.patch.object(tails.CaptureSidecar, "running", return_value=[]),
            mock.patch.object(projects, "MOST_SUBAGENTS", 2),
            mock.patch.object(follow, "MOST_SUBAGENTS", 2),
        ):
            looks = [follower.poll() for _ in range(2 * follow.LOOK_EVERY + 1)]
        (said,) = (note for look in looks for note in look.notes if "past" in note)
        assert said == (
            f"subagents   NOT ALL FOLLOWED: 1 transcripts of {self.SESSION} past"
            " the first 2, what those subagents do is not shown"
        )

    def test_the_calls_remembered_are_bounded_without_a_capture(self):
        timeline = stream.Timeline()
        now = time.time()

        def said(number: int, stage: Stage, when: float) -> Event:
            fields = {"id": f"c{number}", "tool": "Bash", "stage": stage}
            return Event(when, Who.CLAUDE, "bash", ["$ make"], fields, call=True)

        with mock.patch.object(stream, "MOST_CALLS", 5):
            for number in range(50):
                when = now - 5000 + number * 100
                timeline.take(said(number, Stage.CALL, when))
                if number % 2:
                    timeline.take(said(number, Stage.RESULT, when + 1))
            # Those that ended long ago are let go of, and of those that
            # never did, the oldest
            assert len(timeline._calls) <= 5
            assert "c48" in timeline._calls
        # One dated ahead does not make what is read after it too long ago
        timeline.take(said(60, Stage.CALL, now + 10**6))
        late = Event(now, Who.SANDBOX, Kind.NET, ["tcp"], {})
        timeline.take(late)
        assert "during" in late.fields

    def test_a_call_the_session_went_on_without_does_not_run_for_ever(self):
        now = time.time()
        walk = transcript.Walk("/p", WalkOptions(live=True))
        timeline = stream.Timeline()

        def taken(ago: float, *entries: dict, step: str = "") -> list[Event]:
            """The events of entries of so long ago, each of that step of
            the model when one is named."""
            events = []
            for entry in entries:
                entry["timestamp"] = datetime.fromtimestamp(now - ago, UTC).isoformat()
                entry["message"].update({"id": step} if step else {})
                events += walk.take(entry)
            for event in events:
                timeline.take(event)
            return events

        def reached(ago: float) -> list[str]:
            """What a connection of so long ago is said to be made during."""
            made = Event(now - ago, Who.SANDBOX, Kind.NET, ["tcp"], {})
            timeline.take(made)
            return made.notes

        # Two calls of one step run side by side, and the result of one
        # says nothing of the other
        first = [call(name, "Bash", command=f"run {name}") for name in ("t1", "t2")]
        taken(86400, *first, step="m1")
        taken(86390, result("t2", "ok", 3))
        assert reached(86380) == ["during: [1] $ run t1"]
        # The session was ended there. A day later it goes on, and the
        # model takes its next step: no result of the call comes any more
        left, issued = taken(120, call("t3", "Bash", command="ls"), step="m2")
        assert (left.link, left.details) == ("1", ["of: $ run t1", transcript.WENT_ON])
        assert left.fields == {"stage": Stage.RESULT, "tool": "Bash", "id": "t1"}
        assert issued.details == ["$ ls"]
        assert reached(110) == ["during: [3] $ ls"]
        taken(100, result("t3", "ok", 3))
        assert reached(60) == ["(no call running)"]
        # Said once, and a result that comes after all is still told
        assert len(taken(50, call("t4", "Read", file_path="a"), step="m3")) == 1
        (late,) = taken(40, result("t1", "done", 3))
        assert late.details[0] == "of: $ run t1"
        # An entry that names no step tells nothing of the calls before
        taken(30, call("t5", "Bash", command="make"))
        assert len(taken(20, call("t6", "Bash", command="ls"))) == 1
        assert reached(10) == ["during: [6] $ ls (+2 more)"]

    def test_a_call_from_before_a_container_was_started_does_not_run_in_it(self):
        now = time.time()
        timeline = stream.Timeline()

        def issued(number: int, ago: float) -> Event:
            values = {"id": f"t{number}", "tool": "Bash", "stage": Stage.CALL}
            ran = ["$ make"]
            link = str(number)
            return Event(now - ago, Who.CLAUDE, "bash", ran, values, link, call=True)

        def reached(container: str) -> list[str]:
            values = {"container": container}
            made = Event(now - 5, Who.SANDBOX, Kind.NET, ["tcp"], values)
            timeline.take(made)
            return made.notes

        # Left without a result by a session that was ended while it ran
        timeline.take(issued(1, 86400))
        timeline.began("claude-proj", now - 60)
        assert reached("claude-proj") == ["(no call running)"]
        # In a container whose start is not known it may run
        assert reached("claude-proj-2") == ["during: [1] $ make"]
        timeline.take(issued(2, 30))
        assert reached("claude-proj") == ["during: [2] $ make"]
        # What goes on in another transcript has none of these calls
        timeline.let_go()
        assert reached("claude-proj-2") == ["(no call running)"]
        timeline.take(issued(3, 86400))
        assert reached("claude-proj") == ["(no call running)"]

    def test_a_named_session_is_followed_alone(self):
        other = self.write_transcript("0a", [prompt("the other one")])
        following = Following(self, "3fa9")
        add(other, prompt("more of the other"))
        add(self.file, prompt(DONE, 4))
        assert "other" not in following.until(DONE)

    def test_json_tells_a_call_from_its_result(self):
        following = Following(self, "--json")
        add(self.file, call("t1", "Bash", command="make"), result("t1", "done", 3))
        add(self.file, prompt(DONE, 4))
        said = map(json.loads, following.until(DONE).splitlines())
        asked, issued, ended, _ = (event for event in said if event["what"] != "record")
        assert (asked["what"], asked["session"]) == ("prompt", self.SESSION)
        assert (issued["stage"], issued["id"]) == ("call", "t1")
        assert issued["input"] == {"command": "make"}
        assert "failed" not in issued
        assert (ended["stage"], ended["id"]) == ("result", "t1")
        assert (ended["tool"], ended["what"]) == ("Bash", "bash")
        assert (ended["failed"], ended["output"]) == (False, "done")

    def test_what_a_session_writes_cannot_drive_the_terminal(self):
        following = Following(self)
        add(self.file, call("t1", "Bash", command="make \x1b]0;owned\x07all"))
        add(self.file, call("t2", "Bash", command="a\nforged line"), prompt(DONE, 4))
        shown = following.until(DONE)
        assert "$ make ]0;ownedall" in shown
        assert not re.search(r"[\x00-\x08\x0b-\x1f\x7f]", shown)
        assert "claude   bash        $   forged line" in shown

    def test_of_what_is_said_only_the_first_line_is_shown(self):
        for form in ((), ("--verbose",)):
            following = Following(self, *form)
            add(self.file, prompt("\n  \none\n\nand more\nlines", 4), prompt(DONE, 5))
            shown = following.until(DONE)
            assert "prompt      one\n" in shown
            assert "and more" not in shown
            following.stop()

    def test_json_has_all_of_what_is_said(self):
        following = Following(self, "--json")
        add(self.file, prompt("one\n\ntwo", 4), prompt(DONE, 5))
        said = [json.loads(line) for line in following.until(DONE).splitlines()]
        # What is said of the following and its records, then the events
        assert said[0]["what"] == "record"
        assert "no session of this project is recorded" in said[0]["lines"][0]
        told = [event for event in said if event["what"] != "record"]
        assert told[1]["text"] == "one\n\ntwo"

    def test_a_step_of_the_model_says_what_it_used_once_with_verbose(self):
        following = Following(self, "--verbose")
        usage = {"input_tokens": 500, "output_tokens": 90, "cache_read_input_tokens": 1}
        entries = [call("t1", "Bash", command="make"), call("t2", "Bash", command="ls")]
        for entry in entries:
            entry["message"].update(id="msg_1", usage=usage)
        add(self.file, *entries, prompt(DONE, 4))
        shown = following.until(DONE)
        assert shown.count("claude   step        90 tokens out, 501 in (500 new)") == 1
        assert shown.index("step        90") < shown.index("$ make")
        entries[0]["message"]["id"] = entries[1]["message"]["id"] = "msg_2"
        add(self.file, *entries, prompt("once more", 5))
        assert "step" not in Following(self).until("once more")

    def test_colour_marks_what_a_line_is(self):
        following = Following(self, FORCE_COLOR="1")
        fetch = call("t2", "WebFetch", url="https://good.test")
        add(self.file, call("t1", "Bash", command="make"), fetch, prompt(DONE, 4))
        shown = following.until(DONE)
        assert "\x1b[34mclaude   webfetch    [2] url: https://good.test\x1b[0m" in shown
        assert "\x1b[2m# session" in shown
        assert "\x1b[33mclaude   bash        [1] $ make\x1b[0m" in shown
        assert "\x1b[2muser     prompt      fix the build\x1b[0m" in shown

    def test_without_a_session_it_waits_for_one(self):
        self.file.unlink()
        following = Following(self)
        following.until("# no session of this project yet")
        self.write_transcript("0b", [prompt("the first")])
        assert "# session     0b  the first" in following.until("the first")

    def test_as_json_lines_the_events_are_walked_for_their_values_alone(self):
        for form, lines in (("--json", False), ("--verbose", True)):
            with mock.patch.object(follow, "Follower") as made:
                made.return_value.poll.side_effect = KeyboardInterrupt
                assert follow.follow(self.host, [form]) == 0
            assert made.call_args.kwargs["lines"] is lines

    def test_a_list_cannot_be_followed(self):
        result = self.launch("--trace", "--follow", "list")
        assert result.status == 1
        assert "usage: claude-airlock --trace" in result.stderr

    def test_nothing_is_asked_of_docker_about_another_project(self):
        about = {"project": "/elsewhere", "start": 5, "pid": 1}
        ps = "claude-other.capture\t" + json.dumps(about)
        following = Following(self, FAKE_PS=ps)
        shown = following.until("fix the build")
        following.stop()
        assert "# network     no session of this project is recorded" in shown
        assert [c for c in self.calls() if c[0] != "ps"] == []


class FollowNetworkTest(LauncherTest):
    SIDECAR = "claude-proj.capture"

    @pytest.fixture(autouse=True)
    def watched_session(self, sandbox: None) -> None:
        self.now = time.time()
        stamp = datetime.fromtimestamp(self.now + 20, UTC).isoformat()
        self.last = {"type": "user", "timestamp": stamp, "message": {"content": DONE}}
        self.file = self.write_transcript("0a", [prompt("long ago")])
        about = {"project": str(self.project), "start": self.now, "pid": os.getpid()}
        self.ps = f"{self.SIDECAR}\t{json.dumps(about)}"

    def test_what_the_other_parts_of_the_capture_hold_is_followed_too(self):
        main, dns = self.work / "capture.pcap", self.work / "dns.pcap"
        main.write_bytes(pcap_file([(self.now + 2, tcp("198.51.100.7", 443), True)]))
        answer_ = dns_response("good.test", "198.51.100.7")
        dns.write_bytes(pcap_file([(self.now + 1, answer_, False)]))
        following = Following(
            self,
            FAKE_PS=self.ps,
            FAKE_CAPTURE=str(main),
            FAKE_CAPTURE_DNS=str(dns),
        )
        shown = following.until("198.51.100.7")
        assert "tcp/https good.test (198.51.100.7):443" in shown

    def test_a_tcpdump_that_died_is_said_while_following(self):
        captured = self.work / "capture.pcap"
        captured.write_bytes(sample_capture(self.now))
        following = Following(
            self,
            FAKE_PS=self.ps,
            FAKE_CAPTURE=str(captured),
            FAKE_CAPTURE_DIED="dns:137",
        )
        shown = following.until("INCOMPLETE")
        assert (
            "# network     the capture of claude-proj is INCOMPLETE, a recorder"
            " ended before the session did: dns (status 137)" in shown
        )
        # Once, not at every look
        add(self.file, self.last)
        assert "INCOMPLETE" not in following.until(DONE)

    def test_a_tcpdump_at_its_packet_limit_is_not_said_to_have_died(self):
        captured = self.work / "capture.pcap"
        captured.write_bytes(sample_capture(self.now))
        following = Following(
            self, FAKE_PS=self.ps, FAKE_CAPTURE=str(captured), FAKE_CAPTURE_DIED="dns:0"
        )
        add(self.file, self.last)
        assert "INCOMPLETE" not in following.until(DONE)

    def test_connections_show_as_the_capture_grows(self):
        captured = self.work / "capture.pcap"
        captured.write_bytes(sample_capture(self.now))
        following = Following(self, FAKE_PS=self.ps, FAKE_CAPTURE=str(captured))
        shown = following.until("203.0.113.9")
        assert "# network     following the capture of claude-proj" in shown
        assert (
            "sandbox  net         [n1] tcp/https good.test (198.51.100.7):443" in shown
        )
        assert "lookup" not in shown
        # Made a while ago: a connection is shown once it has had the
        # moment in which what tells of it comes
        more = pcap_file([(time.time() - 1, tcp("192.0.2.44", 6379), True)])
        with open(captured, "ab") as growing:
            # Without the header of the file, and the packet in two parts
            growing.write(more[24:-10])
        add(self.file, prompt("in between"))
        assert "192.0.2.44" not in following.until("in between")
        with open(captured, "ab") as growing:
            growing.write(more[-10:])
        add(self.file, self.last)
        shown = following.until(DONE)
        # Numbered after those the capture had before
        assert shown.count("sandbox  net         [n4] tcp/redis 192.0.2.44:6379") == 1
        assert "198.51.100.7" not in shown
        # Every part of the capture is read by one command, from where
        # each was read to
        script = tails.captured_since.__globals__["READ_SCRIPT"]
        reads = [c for c in self.calls() if c[:1] == ["exec"] and script in c]
        assert reads[0][:6] == ["exec", self.SIDECAR, "sh", "-c", script, "sh"]
        assert reads[0][6] == str(capture_module.READ_MOST)
        assert reads[0][7:9] == ["/capture.pcap:0", "/dns.pcap:0"]
        assert len(reads[0][7:]) == len(tails.PARTS)
        assert f"/capture.pcap:{len(sample_capture(self.now))}" in reads[1]

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
        assert shown.count("sandbox  health") == 2
        assert "sandbox  health      mem 2g of 16g (12%)  cpu 12%" in shown
        assert "gone since: [812] node 8g" in shown
        # Asked of the watcher from outside, nothing is run next to the session
        # All it said at first, then its last lines from a little before
        # the last one that was read, none of which is shown again
        add(self.file, self.last)
        assert "health" not in following.until(DONE)
        asked = [c for c in self.calls() if c[:1] == ["logs"]]
        assert asked[0] == ["logs", "claude-proj.procs"]
        assert asked[-1][2:] == ["claude-proj.procs"]
        assert re.search(r"^--since=\d+\.\d{3}$", asked[-1][1])
        assert [c for c in self.calls() if c[:1] == ["exec"]] == []

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
        assert (start["stage"], start.get("outcome")) == ("open", None)
        closing = tcp(there, 443, 0x11, sequence=1101, acknowledged=5201)
        with open(captured, "ab") as growing:
            growing.write(pcap_file([(self.now + 4, closing, True)])[24:])
        end = json.loads(following.until(there).splitlines()[-1])
        assert (end["stage"], end["outcome"]) == ("outcome", "closed")
        assert (end["seconds"], end["bytes_out"], end["bytes_in"]) == (3.0, 100, 200)
        assert end["source_port"] == start["source_port"]

    def test_a_connection_is_put_with_the_call_running_then(self):
        captured = self.work / "capture.pcap"
        captured.write_bytes(pcap_file([]))
        following = Following(self, FAKE_PS=self.ps, FAKE_CAPTURE=str(captured))
        following.until("long ago")
        now = datetime.fromtimestamp(time.time(), UTC).isoformat()
        running = call("t1", "Bash", command="curl good.test")
        add(self.file, {**running, "timestamp": now})
        following.until("$ curl good.test")
        with open(captured, "ab") as growing:
            growing.write(
                pcap_file([(time.time(), tcp("198.51.100.7", 443), True)])[24:]
            )
        shown = following.until("198.51.100.7")
        assert "198.51.100.7:443  during: [1] $ curl good.test\n" in shown

    def test_a_call_from_before_the_session_was_started_is_not_running_in_it(self):
        # Left without a result by a session that was ended while it ran,
        # in a transcript the session of now goes on in
        add(self.file, call("t0", "Bash", command="npm install"))
        captured = self.work / "capture.pcap"
        captured.write_bytes(pcap_file([]))
        following = Following(self, FAKE_PS=self.ps, FAKE_CAPTURE=str(captured))
        following.until("$ npm install")
        with open(captured, "ab") as growing:
            growing.write(
                pcap_file([(time.time(), tcp("198.51.100.7", 443), True)])[24:]
            )
        shown = following.until("198.51.100.7")
        assert "198.51.100.7:443  (no call running)\n" in shown

    def test_verbose_adds_the_lookups(self):
        captured = self.work / "capture.pcap"
        captured.write_bytes(sample_capture(self.now))
        following = Following(
            self, "--verbose", FAKE_PS=self.ps, FAKE_CAPTURE=str(captured)
        )
        shown = following.until("203.0.113.9")
        assert "sandbox  dns         lookup good.test" in shown

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
        assert "net         proxy CONNECT [31mevil.test:443 DENIED 300 B" in shown
        for absent in ("before.test", "theirs.test", "half", "\x1b"):
            assert absent not in shown

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
        assert "net         [claude-proj] proxy/https CONNECT mine.test:443" in shown
        assert (
            "net         [claude-proj-2] proxy/https CONNECT theirs.test:443" in shown
        )

    def watched(self, *lines: dict) -> str:
        """The watcher of the session next to its capture, which says
        these lines aloud: what docker lists of the two."""
        about = {"project": str(self.project), "start": self.now, "pid": os.getpid()}
        said = self.work / "said"
        said.write_text("".join(json.dumps(line) + "\n" for line in lines))
        self.said = said
        return f"{self.ps}\nclaude-proj.procs\t{json.dumps(about)}"

    def test_a_connection_says_which_process_made_it_as_it_is_made(self):
        then = time.time() - 5
        captured = self.work / "capture.pcap"
        captured.write_bytes(pcap_file([(then, tcp("198.51.100.7", 443), True)]))
        both = self.watched(
            {"t": then - 1, "pid": 640, "ppid": 1, "exe": "/bin/bash", "argv": ["sh"]},
            {
                "t": then,
                "pid": 812,
                "ppid": 640,
                "exe": "/usr/bin/curl",
                "argv": ["curl", "-sS", "https://good.test"],
            },
            {
                "t": then,
                "port": 40443,
                "to": "198.51.100.7",
                "to_port": 443,
                "pids": [812],
            },
            {"t": then, "listen": 8080, "on": "0.0.0.0", "pids": [812]},
        )
        following = Following(
            self,
            FAKE_PS=both,
            FAKE_CAPTURE=str(captured),
            FAKE_PROXY_LOG=str(self.said),
        )
        add(self.file, self.last)
        shown = following.until(DONE)
        who = "by: [812] curl -sS https://good.test < bash"
        assert f"tcp/https 198.51.100.7:443  {who}" in shown
        assert f"listen      tcp 0.0.0.0:8080  OPEN to its network  {who}" in shown
        # Nothing is run next to the session for it, the watcher is heard
        assert [
            c[:2] for c in self.calls() if c[:1] == ["exec"] and "sh" not in c
        ] == []

    def test_a_watcher_that_says_no_more_aloud_is_said_once(self):
        captured = self.work / "capture.pcap"
        captured.write_bytes(pcap_file([]))
        both = self.watched({"t": time.time() - 5, "note": "hushed"})
        following = Following(
            self,
            FAKE_PS=both,
            FAKE_CAPTURE=str(captured),
            FAKE_PROXY_LOG=str(self.said),
        )
        shown = following.until("no longer said")
        assert (
            "# processes   which process makes a connection is no longer said as"
            " claude-proj runs" in shown
        )
        add(self.file, self.last)
        assert "no longer said" not in following.until(DONE)

    def test_a_destination_the_project_did_not_reach_before_is_said_to_be_new(self):
        captured = self.work / "capture.pcap"
        captured.write_bytes(sample_capture(self.now - 60))
        self.state.mkdir(parents=True)
        known = {str(self.project): {"tcp good.test 443": 1}}
        (self.state / "destinations.json").write_text(json.dumps(known))
        following = Following(self, FAKE_PS=self.ps, FAKE_CAPTURE=str(captured))
        add(self.file, self.last)
        shown = following.until(DONE)
        assert "tcp/postgres 10.0.0.7:5432  NEW for this project" in shown
        assert shown.count("NEW for this project") == 2
        known_ones = [line for line in shown.splitlines() if "good.test" in line]
        assert known_ones
        assert not [line for line in known_ones if "NEW" in line]

    def test_nothing_is_new_to_a_project_that_has_no_record_yet(self):
        captured = self.work / "capture.pcap"
        captured.write_bytes(sample_capture(self.now - 60))
        following = Following(self, FAKE_PS=self.ps, FAKE_CAPTURE=str(captured))
        add(self.file, self.last)
        assert "NEW" not in following.until(DONE)

    def test_who_connects_to_the_session_shows_as_they_do(self):
        then, them = time.time() - 5, "172.20.0.9"
        captured = self.work / "capture.pcap"
        captured.write_bytes(
            pcap_file(
                [
                    (then, knock(them, 8080), False),
                    (then, taken_up(them, 8080), True),
                ]
            )
        )
        following = Following(self, FAKE_PS=self.ps, FAKE_CAPTURE=str(captured))
        shown = following.until(them)
        assert (
            "sandbox  net         [n1] tcp IN from 172.20.0.9 to its port 8080" in shown
        )


class CaptureTailTest:
    """The capture of a running session as it is read, without docker:
    what it holds is given."""

    THERE = "198.51.100.7"

    def test_every_part_is_read_by_one_command_from_where_it_was_read_to(self):
        read = capture_module.captured_since
        offsets = {"/capture.pcap": 24, "/dns.pcap": 0, "/flows.pcap": 7}
        with mock.patch.object(capture_module, "docker_bytes") as asked:
            # How many bytes each has more, then those bytes
            asked.return_value = b"3\nab\n0\n5\n12345"
            found, whole = read("claude-proj.capture", offsets)
            assert found == {
                "/capture.pcap": b"ab\n",
                "/dns.pcap": b"",
                "/flows.pcap": b"12345",
            }
            assert whole
            (command,) = asked.call_args_list
            assert command.args[:3] == ("exec", "claude-proj.capture", "sh")
            assert command.args[-4:] == (
                str(capture_module.READ_MOST),
                "/capture.pcap:24",
                "/dns.pcap:0",
                "/flows.pcap:7",
            )
            # What is cut short, or is no such thing, is read as far as it
            # holds up, and a sidecar that cannot be asked has nothing
            asked.return_value = b"3\nabc9\nx"
            assert read("claude-proj.capture", offsets)[0]["/dns.pcap"] == b"x"
            for said in (b"nothing of the kind", b"", None):
                asked.return_value = said
                found, _ = read("claude-proj.capture", offsets)
                assert set(found.values()) == {b""}
            # As much as one reading takes: there is more to come
            with mock.patch.object(capture_module, "READ_MOST", 8):
                asked.return_value = b"8\n12345678" + b"0\n" * 2
                assert read("claude-proj.capture", offsets)[1] is False

    def test_one_reading_takes_no_more_than_it_is_to_and_the_parts_in_order(self):
        # A session can fill every part to its limit: whoever starts to
        # follow it then reads that in turns, and no part ahead of the
        # ones before it
        directory = Path(tempfile.mkdtemp())
        try:
            first, second = directory / "a.pcap", directory / "b.pcap"
            first.write_bytes(b"0123456789")
            second.write_bytes(b"abcdefghij")

            def read(most: int, *offsets: int) -> bytes:
                wanted = [
                    f"{file}:{at}"
                    for file, at in zip((first, second, "/none"), offsets, strict=True)
                ]
                return subprocess.run(
                    ["sh", "-c", capture_module.READ_SCRIPT, "sh", str(most), *wanted],
                    capture_output=True,
                    check=True,
                ).stdout

            assert read(100, 0, 0, 0) == b"10\n012345678910\nabcdefghij0\n"
            assert read(100, 4, 10, 0) == b"6\n4567890\n0\n"
            assert read(12, 0, 0, 0) == b"10\n01234567892\nab0\n"
            assert read(4, 0, 0, 0) == b"4\n01230\n0\n"
        finally:
            shutil.rmtree(directory)

    def tail(self, **more: Any) -> tails.CaptureTail:
        return tails.CaptureTail("claude-proj.capture", verbose=False, **more)

    def fed(self, tail: tails.CaptureTail, packets: list) -> list[Event]:
        """What a look gives when the capture has these packets more."""
        frames = pcap_file(packets, asked=False)
        offset = tail._offsets["tcp"]
        more = frames if not offset else frames[24:]
        read = {part.file: b"" for part in tails.PARTS}
        read["/capture.pcap"] = more
        with mock.patch.object(tails, "captured_since", return_value=(read, True)):
            return tail.poll()

    def test_a_connection_is_shown_once_it_has_had_its_moment(self):
        tail = self.tail()
        now = time.time()
        opening = [
            (now, tcp(self.THERE, 443, sequence=100), True),
            (now, answer(self.THERE, 443, sequence=500, acknowledged=101), False),
            (now, tcp(self.THERE, 443, 0x11, sequence=101, acknowledged=501), True),
            # One made a while ago is shown at once
            (now - 5, tcp("192.0.2.44", 6379), True),
        ]
        # Made this instant: what tells of it may be yet to come
        (old,) = self.fed(tail, [opening[3]])
        assert old.fields["address"] == "192.0.2.44"
        assert self.fed(tail, opening[:3]) == []
        # At the next look it is there, and what became of it after it
        opened, closed = self.fed(tail, [])
        assert (opened.fields["stage"], closed.fields["stage"]) == ("open", "outcome")
        assert closed.fields["opened"] == opened.when
        # What became of it is tied to the line that said it opened
        assert (old.link, opened.link, closed.link) == ("n1", "n2", "n2")
        assert self.fed(tail, []) == []

    def test_what_is_known_a_moment_later_is_on_the_line_of_the_connection(self):
        tail = self.tail()
        now = time.time()
        proxy = "172.20.0.2"
        asked = b"CONNECT good.test:443 HTTP/1.1\r\n\r\n"
        assert (
            self.fed(
                tail,
                [
                    (now, tcp(proxy, 3128, sequence=100), True),
                    (now, answer(proxy, 3128, sequence=500), False),
                ],
            )
            == []
        )
        (opened,) = self.fed(
            tail, [(now + 0.01, tcp(proxy, 3128, 0x18, asked, sequence=101), True)]
        )
        assert opened.details == ["tcp/proxy 172.20.0.2:3128  asked for good.test:443"]

    def test_a_connection_that_is_still_open_says_how_far_it_has_got(self):
        tail = self.tail()
        step = tails.PROGRESS_STEP
        opened = [
            (10.0, tcp(self.THERE, 443, sequence=100), True),
            (10.0, answer(self.THERE, 443, sequence=500, acknowledged=101), False),
        ]

        def came(reached: int) -> tuple:
            packet = answer(
                self.THERE, 443, 0x18, 501 + reached - 100, payload=b"y" * 100
            )
            return (11.0, packet, False)

        tail.capture = read_parts(opened, downloads=[came(step + 5_000)])
        now = [1000.0]
        with mock.patch.object(follow.time, "monotonic", lambda: now[0]):
            (event,) = tail._still_open()
            assert event.details[0].startswith(
                "tcp/https 198.51.100.7:443  still open after "
            )
            assert event.details[0].endswith("s, 0 B out, 17 MB in so far")
            assert (event.fields["stage"], event.fields["bytes_in"]) == (
                "progress",
                step + 5_000,
            )
            # Not again until it has carried as much more, and not sooner
            # than a while after
            assert tail._still_open() == []
            more = PcapReader().feed(pcap_file([came(3 * step)], asked=False))
            pcap.take_frames(tail.capture, more, "downloads")
            now[0] += tails.PROGRESS_EVERY - 1
            assert tail._still_open() == []
            now[0] += 2
            (later,) = tail._still_open()
            assert later.fields["bytes_in"] == 3 * step
            # Each by the number of the connection
            assert (event.link, later.link) == ("n1", "n1")
        # A line of its own is not what a call is said to have made
        timeline = stream.Timeline()
        timeline.take(event)
        assert event.notes == []

    def test_what_the_session_did_on_the_network_is_summed_since_it_was_asked(self):
        tail = self.tail()
        there, them = self.THERE, "172.20.0.9"
        sent = [
            (3.0 + at / 100, tcp(there, 443, 0x18, b"x" * 1000, 101 + at * 1000), True)
            for at in range(5)
        ]
        tail.capture = read_parts(
            [
                (1.0, dns_response("good.test", there), False),
                (2.0, tcp(there, 443, sequence=100), True),
                (2.0, answer(there, 443, sequence=500, acknowledged=101), False),
                (4.0, tcp("10.0.0.7", 5432), True),
                (4.0, answer("10.0.0.7", 5432, flags=0x14), False),
                (5.0, knock(them, 8080), False),
            ],
            elsewhere=sent,
        )
        summed = tail.traffic()
        assert summed == tails.Traffic(
            connections=2, hosts=2, failed=1, inbound=1, sent=5000
        )
        assert summed.said == (
            "2 connections to 2 hosts, 5 kB out, 0 B in, 1 FAILED,"
            " 1 made to it from outside"
        )
        # Nothing since
        assert not tail.traffic()
        assert tail.traffic().said == ""
        assert tails.Traffic(connections=1, hosts=1, denied=2).said == (
            "1 connection to 1 host, 2 DENIED"
        )

    def test_a_follower_sums_what_its_sessions_did(self):
        follower = follow.Follower(mock.Mock(project_dir="/proj"), verbose=False)
        tail = self.tail()
        tail.capture = read_parts([(2.0, tcp(self.THERE, 443), True)])
        follower._captures[(tail.sidecar, 1.0)] = tail
        follower._denied = 3
        assert follower.traffic() == tails.Traffic(connections=1, hosts=1, denied=3)
        assert not follower.traffic()

    def test_a_tunnel_to_the_model_has_no_line_of_how_far_it_got(self):
        proxy, step = "172.20.0.2", tails.PROGRESS_STEP

        def tunnel(port: int, host: str) -> list:
            asked = f"CONNECT {host}:443 HTTP/1.1\r\n\r\n".encode()
            return [
                (10.0, tcp(proxy, port, sequence=100), True),
                (10.0, answer(proxy, port, sequence=500, acknowledged=101), False),
                (10.1, tcp(proxy, port, 0x18, asked, sequence=101), True),
                (20.0, tcp(proxy, port, 0x10, b"x" * 1000, 101 + 2 * step), True),
            ]

        tail = self.tail(filtered=True)
        with mock.patch.object(follow, "EGRESS_PORT", 3128, create=True):
            tail.capture = read_parts(
                [*tunnel(3128, "api.anthropic.com"), *tunnel(3128 + 1, "big.test")]
            )
        # Both go to the proxy's address: one is told by what it asked for
        tail.capture.connections[1].port = 3128
        (event,) = tail._still_open()
        assert "asked for big.test:443  still open after" in event.details[0]
        assert event.fields["asked"] == "big.test:443"

    def test_what_a_watcher_said_is_not_taken_twice_after_a_look_that_gave_nothing(
        self,
    ):
        said = [
            json.dumps({"t": 100.0, "listen": 8080, "on": "0.0.0.0", "pids": []}),
            json.dumps({"t": 100.5, "health": {"mem": [1, 2]}}),
        ]
        heard = [said, [], said, [*said, json.dumps({"t": 101.0, "note": "hushed"})]]
        tail = tails.WatcherTail("claude-proj.procs")
        with mock.patch.object(tails, "said_lines", side_effect=heard) as asked:
            listening = [len(tail.poll()) for _ in heard]
        assert listening == [1, 0, 0, 0]
        assert len(tail.record.listeners) == len(tail.record.samples) == 1
        assert tail.newly_hushed()
        # All of it at first, then from a little before the last of it
        assert [call.args[1] for call in asked.call_args_list] == [
            0.0,
            98.5,
            98.5,
            98.5,
        ]

    def test_what_is_known_of_a_session_is_asked_again_as_it_comes_up(self):
        host = mock.Mock(project_dir="/proj")
        follower = follow.Follower(host, verbose=False)
        sidecar = [("claude-proj.capture", 5.0)]
        known = [frozenset({"tcp good.test 443"}), frozenset({"tcp new.test 443"})]
        with (
            mock.patch.object(tails.CaptureSidecar, "running", return_value=sidecar),
            mock.patch.object(follow.Follower, "_health_sources", return_value={}),
            mock.patch.object(follow.Follower, "_filtered_addresses") as addresses,
            mock.patch.object(follow, "known_destinations", side_effect=known),
            mock.patch.object(follow, "read_traced_sessions", return_value=[]),
        ):
            # The capture of a session is up before the session is
            addresses.return_value = {}
            follower._look_for_sessions(follow.Round())
            (tail,) = follower._captures.values()
            assert (tail.filtered, tail._known) == (False, known[0])
            addresses.return_value = {"172.20.0.5": "claude-proj"}
            follower._look_for_sessions(follow.Round())
            assert tail.filtered
            # And what the project is known to reach is as the session
            # before left it
            sidecar[0] = ("claude-proj.capture", 9.0)
            follower._look_for_sessions(follow.Round())
            later = follower._captures[sidecar[0]]
            assert later._known == known[1]

    def test_a_capture_that_ended_is_let_go_of_after_a_last_look(self, tmp_path: Path):
        host = mock.Mock(project_dir="/proj", captures_dir=str(tmp_path))
        follower = follow.Follower(host, verbose=False)
        sidecar = [("claude-proj.capture", 5.0)]
        with (
            mock.patch.object(tails.CaptureSidecar, "running") as running,
            mock.patch.object(follow.Follower, "_health_sources", return_value={}),
            mock.patch.object(follow.Follower, "_filtered_addresses", return_value={}),
            mock.patch.object(follow, "known_destinations", return_value=None),
            mock.patch.object(follow, "read_traced_sessions") as noted,
        ):
            running.return_value, noted.return_value = sidecar, []
            began = follow.Round()
            follower._look_for_sessions(began)
            assert [note.split(maxsplit=1)[1] for note in began.notes] == [
                "following the capture of claude-proj"
            ]
            (tail,) = follower._captures.values()
            # Past the first look, as poll counts them
            follower._rounds = 1
            # Docker did not answer: it is followed on as it was, not
            # taken to have ended and read again from its start
            running.return_value = None
            unanswered = follow.Round()
            follower._look_for_sessions(unanswered)
            assert unanswered.notes == []
            assert list(follower._captures.values()) == [tail]
            running.return_value = sidecar
            follower._look_for_sessions(follow.Round())
            assert list(follower._captures.values()) == [tail]
            # Its session is over, its sidecar stopped: kept until the
            # copy its launcher makes of it is noted
            sidecar.clear()
            stopped = follow.Round()
            follower._look_for_sessions(stopped)
            assert (stopped.notes, list(follower._captures.values())) == ([], [tail])
            # Which has what the sidecar did not give by then
            now = time.time()
            copy = tmp_path / "claude-proj.capture-5.pcap"
            there = "198.51.100.7"
            copy.write_bytes(
                pcap_file(
                    [
                        (now, tcp(there, 443), True),
                        (now, answer(there, 443), False),
                    ]
                )
            )
            noted.return_value = [mock.Mock(capture=copy.name)]
            ended = follow.Round()
            follower._look_for_sessions(ended)
        assert follower._captures == {}
        said = [note.split(maxsplit=1)[1] for note in ended.notes]
        assert said == ["the capture of claude-proj ended"]
        assert [event.kind for _, event in ended.events] == [Kind.NET]

    def test_what_goes_on_holds_back_none_of_what_is_over_after_it(self):
        over = [False, True, True]
        told = tails.NewlyOver[int]()
        items = [0, 1, 2]
        assert told.of(items, lambda item: over[item]) == [1, 2]
        # Each once, the one that goes on too when it is over
        over += [True]
        items.append(3)
        assert told.of(items, lambda item: over[item]) == [3]
        over[0] = True
        assert told.of(items, lambda item: over[item]) == [0]
        assert told.of(items, lambda item: over[item]) == []

    def test_a_capture_whose_copy_does_not_come_is_let_go_of_all_the_same(self):
        host = mock.Mock(project_dir="/proj")
        follower = follow.Follower(host, verbose=False)
        sidecar = [("claude-proj.capture", 5.0)]
        with (
            mock.patch.object(tails.CaptureSidecar, "running", return_value=sidecar),
            mock.patch.object(follow.Follower, "_health_sources", return_value={}),
            mock.patch.object(follow.Follower, "_filtered_addresses", return_value={}),
            mock.patch.object(follow, "known_destinations", return_value=None),
            mock.patch.object(follow, "read_traced_sessions", return_value=[]),
            mock.patch.object(follow, "LAST_LOOK_WAIT", 0.0),
        ):
            follower._look_for_sessions(follow.Round())
            sidecar.clear()
            ended = follow.Round()
            follower._look_for_sessions(ended)
        assert follower._captures == {}
        assert ended.events == []
        said = [note.split(maxsplit=1)[1] for note in ended.notes]
        assert "the capture of claude-proj ended" in said


class TranscriptTailTest:
    @pytest.fixture(autouse=True)
    def transcript(self, tmp_path: Path) -> None:
        self.file = tmp_path / "0a.jsonl"
        self.file.touch()

    def said(self, tail) -> list[str]:
        return [event.details[0] for event in tail.poll()]

    def test_a_line_is_read_once_it_is_whole(self):
        tail = tails.TranscriptTail(self.file, "/proj", WalkOptions(live=True))
        whole = json.dumps(prompt("hello")) + "\n"
        self.file.write_text(whole[:20])
        assert self.said(tail) == []
        self.file.write_text(whole + "{not json}\n[1]\n" + whole)
        # A whole line that holds no entry is not Claude Code's doing
        assert self.said(tail) == [
            "hello",
            "UNREADABLE line of the transcript: {not json}",
            "UNREADABLE line of the transcript: [1]",
            "hello",
        ]
        assert self.said(tail) == []

    def test_a_line_too_long_to_hold_is_dropped_and_said_to_be(self):
        tail = tails.TranscriptTail(self.file, "/proj", WalkOptions(live=True))
        with mock.patch.object(tails, "LINE_LIMIT", 100):
            add(self.file, prompt("x" * 500))
            # Still without its end, which the next look finds
            with open(self.file, "a") as transcript:
                transcript.write(json.dumps(prompt("y" * 500))[:400])
            too_long = "UNREADABLE line of the transcript: (a line too long to read)"
            assert self.said(tail) == ["x" * 200 + "...", too_long]
            with open(self.file, "a") as transcript:
                transcript.write("the rest of it\n")
            add(self.file, prompt("after"))
            assert self.said(tail) == ["after"]

    def test_a_line_many_times_too_long_is_said_once(self):
        tail = tails.TranscriptTail(self.file, "/proj", WalkOptions(live=True))
        too_long = "UNREADABLE line of the transcript: (a line too long to read)"
        with (
            mock.patch.object(tails, "LINE_LIMIT", 100),
            mock.patch.object(tails, "READ_SIZE", 64),
        ):
            # Read in pieces, and found again without its end every time
            with open(self.file, "a") as transcript:
                transcript.write(json.dumps(prompt("x" * 2000))[:1000])
            assert self.said(tail) == [too_long]
            with open(self.file, "a") as transcript:
                transcript.write("y" * 1000)
            assert self.said(tail) == []
            with open(self.file, "a") as transcript:
                transcript.write("its end\n")
            add(self.file, prompt("after"))
            assert self.said(tail) == ["after"]

    def test_a_look_takes_in_no_more_than_it_is_to(self):
        tail = tails.TranscriptTail(self.file, "/proj", WalkOptions(live=True))
        texts = [f"line {number}" for number in range(100)]
        add(self.file, *map(prompt, texts))
        count = tails.LATE_AFTER + 2
        most = self.file.stat().st_size // (2 * count)
        looks = []
        late = []
        while len(looks) < count:
            looks.append([event.details[0] for event in tail.poll(most)])
            late.append(tail.newly_behind())
            # Written to meanwhile, as fast as it is read
            add(self.file, prompt("more"))
        # Some of it each time, the rest left for the next
        assert all(0 < len(look) < 10 for look in looks)
        seen = [text for look in looks for text in look]
        assert seen == texts[: len(seen)]
        # Said once to be late, when it stays behind
        assert late.index(True) == tails.LATE_AFTER - 1
        assert late.count(True) == 1
        # All there is when there is no most, and no further than that
        rest = [event.details[0] for event in tail.poll(None)]
        assert seen + rest == texts + ["more"] * count
        assert not tail.newly_behind()
        assert tail.poll() == []

    def test_a_follower_says_when_a_transcript_is_written_faster_than_read(self):
        host = mock.Mock(project_dir="/proj")
        follower = follow.Follower(host, False, only=self.file)
        follower._docker = False
        add(self.file, *(prompt(f"before {number}") for number in range(30)))
        with (
            mock.patch.object(follow, "project_root", return_value="/proj"),
            mock.patch.object(follow, "subagent_files", return_value=[]),
            mock.patch.object(follow.NewlyNoted, "poll", return_value=[]),
            mock.patch.object(follow, "MOST_POLLED", 200),
        ):
            # What it held before it was followed is read whole
            first = follower.poll()
            assert any("earlier events" in note for note in first.notes)
            assert first.events[-1][1].details == ["before 29"]
            add(self.file, *(prompt(f"flood {number}") for number in range(60)))
            rounds = [follower.poll() for _ in range(tails.LATE_AFTER + 2)]
        assert all(0 < len(found.events) < 5 for found in rounds)
        notes = [note for found in rounds for note in found.notes]
        assert notes == [
            (
                "transcript  0a.jsonl is written faster than it is read,"
                " what is shown of it is LATE"
            )
        ]

    def test_a_follower_says_when_a_transcript_can_no_longer_be_read(self):
        host = mock.Mock(project_dir="/proj")
        follower = follow.Follower(host, False, only=self.file)
        follower._docker = False
        with (
            mock.patch.object(follow, "project_root", return_value="/proj"),
            mock.patch.object(follow, "subagent_files", return_value=[]),
            mock.patch.object(follow.NewlyNoted, "poll", return_value=[]),
        ):
            follower.poll()
            add(self.file, call("t1", "Bash", command="make"))
            assert [event.details for _, event in follower.poll().events] == [
                ["$ make"]
            ]
            # A session moves its transcript away and puts a link in its
            # place, which Claude Code goes on writing through: the link
            # is not followed, and that nothing more is shown is said
            moved = self.file.with_name("moved")
            self.file.rename(moved)
            self.file.symlink_to(moved)
            add(moved, call("t2", "Bash", command="curl evil.test"))
            rounds = [follower.poll() for _ in range(tails.UNREAD_AFTER + 3)]
            assert [found.events for found in rounds] == [[]] * len(rounds)
            notes = [note for found in rounds for note in found.notes]
            assert notes == [
                (
                    "transcript  0a.jsonl is no longer a file that can be read"
                    " (moved, removed, or a link put in its place): what its"
                    " session does from here on is NOT SHOWN"
                )
            ]
            assert rounds[tails.UNREAD_AFTER - 1].notes == notes
            # Back in its place, it is read on, and said again should
            # it go again
            self.file.unlink()
            moved.rename(self.file)
            assert [event.details for _, event in follower.poll().events] == [
                ["$ curl evil.test"]
            ]
            self.file.unlink()
            again = [follower.poll() for _ in range(tails.UNREAD_AFTER)]
            assert [note for found in again for note in found.notes] == notes

    def test_what_came_before_is_looked_for_in_the_end_of_a_transcript(self):
        texts = [f"before {number}" for number in range(200)]
        add(self.file, *map(prompt, texts))
        lines = self.file.read_bytes().splitlines(keepends=True)
        options = WalkOptions(live=True)
        # From within a line: the rest of that one is let go of, and is
        # no line that cannot be read
        within = sum(map(len, lines[-7:])) + 20
        with mock.patch.object(tails, "MOST_HISTORY", within):
            tail = tails.TranscriptTail.latest(self.file, "/proj", options)
        assert tail.cut
        assert self.said(tail) == texts[-7:]
        # From where a line starts, that line is whole
        with mock.patch.object(tails, "MOST_HISTORY", within - 20):
            tail = tails.TranscriptTail.latest(self.file, "/proj", options)
        assert self.said(tail) == texts[-7:]
        add(self.file, prompt("now"))
        assert self.said(tail) == ["now"]
        # One that is no longer than is looked at is read from its start
        whole = tails.TranscriptTail.latest(self.file, "/proj", options)
        assert not whole.cut
        assert len(whole.poll(None)) == len(texts) + 1

    def test_a_follower_says_when_it_looked_at_the_end_of_a_transcript_alone(self):
        host = mock.Mock(project_dir="/proj")
        add(self.file, *(prompt(f"before {number}") for number in range(300)))
        with (
            mock.patch.object(follow, "project_root", return_value="/proj"),
            mock.patch.object(follow, "subagent_files", return_value=[]),
            mock.patch.object(follow.NewlyNoted, "poll", return_value=[]),
            mock.patch.object(tails, "MOST_HISTORY", 3 << 10),
            mock.patch.object(follow, "MOST_HISTORY", 3 << 10),
        ):
            follower = follow.Follower(host, False, only=self.file)
            follower._docker = False
            first = follower.poll()
        assert first.events[-1][1].details == ["before 299"]
        assert len(first.events) == follow.HISTORY
        (note,) = first.notes
        assert re.search(
            r"^\d\d earlier events and what the transcript holds before its last"
            r" 0 MB, see claude-airlock --trace$",
            note,
        )

    def test_the_title_is_read_from_the_start_of_a_transcript_alone(self):
        late = {"type": "ai-title", "aiTitle": "named later"}
        add(self.file, prompt("the first prompt"), *map(prompt, "x" * 50), late)
        options = WalkOptions(live=True)
        ended = tails.TranscriptTail(
            self.file, "/proj", options, self.file.stat().st_size
        )
        with (
            mock.patch.object(tails, "TITLE_BYTES", 300),
            mock.patch.object(tails, "read_entries", wraps=tails.read_entries) as read,
        ):
            assert ended.title == "the first prompt"
        read.assert_called_once_with(self.file, 300)
        # One that an entry it followed gave a title has that one
        followed = tails.TranscriptTail(self.file, "/proj", options)
        followed.poll(None)
        assert followed.title == "named later"

    def test_a_transcript_written_anew_is_read_from_its_new_end(self):
        tail = tails.TranscriptTail(self.file, "/proj", WalkOptions(live=True))
        add(self.file, prompt("one"), prompt("two"))
        assert self.said(tail) == ["one", "two"]
        self.file.write_text(json.dumps(prompt("anew")) + "\n")
        assert self.said(tail) == []
        add(self.file, prompt("three"))
        assert self.said(tail) == ["three"]

    def test_a_link_or_a_pipe_in_its_place_is_not_read(self):
        secret = self.file.with_name("secret")
        secret.write_text(json.dumps(prompt("a secret")) + "\n")
        self.file.unlink()
        self.file.symlink_to(secret)
        tail = tails.TranscriptTail(self.file, "/proj", WalkOptions(live=True))
        assert self.said(tail) == []
        self.file.unlink()
        os.mkfifo(self.file)
        assert self.said(tail) == []


class PcapReaderTest:
    def test_a_capture_fed_in_pieces_reads_as_the_whole(self):
        whole = sample_capture(1000.0)
        for size in (1, 7, 4096):
            reader, found = PcapReader(), pcap.Capture()
            for start in range(0, len(whole), size):
                pcap.take_frames(found, reader.feed(whole[start : start + size]))
            assert len(found.connections) == 3
            assert found.packets == 11

    def test_nothing_is_read_past_what_is_not_a_capture(self):
        reader = PcapReader()
        assert list(reader.feed(b"not a capture at all, really")) == []
        assert list(reader.feed(sample_capture(1000.0))) == []
