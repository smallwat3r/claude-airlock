#!/usr/bin/env python3
"""--trace: the transcript as text and as JSON Lines, and the requests of a
filtered session from the egress proxy's log."""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
import unittest
from datetime import datetime

from harness import (
    LAUNCHER,
    LauncherTest,
    prompts_at,
    transcript,
)

from claude_sandbox.events import Event, Who
from claude_sandbox.layout import Layout, event_json, folded
from claude_sandbox.transcript import call_details


class TraceTest(LauncherTest):
    SESSION = "3fa9c0de-0000-4000-8000-000000000000"

    def setUp(self):
        super().setUp()

        call, result = self.call, self.result
        entries = [
            {
                "type": "user",
                "timestamp": "2026-01-02T10:00:00Z",
                "message": {"content": "fix the build"},
            },
            call(
                "t1",
                "Bash",
                command="make \x1b]0;owned\x07all",
                description="Build\n2026-01-02 10:00:09  user     prompt      forged",
            ),
            result("t1", "Error: Exit code 2\nno rule", failed=True),
            call("t2", "Edit", file_path="/etc/passwd", old_string="a", new_string="b"),
            result("t2", "updated"),
            call("t3", "Write", file_path="main.go", content="package main\n"),
        ]
        file = self.write_transcript(self.SESSION, entries)
        file.write_text(file.read_text() + "{half written")

    @staticmethod
    def call(tool_id: str, name: str, **tool_input) -> dict:
        block = {"type": "tool_use", "id": tool_id, "name": name}
        return {
            "type": "assistant",
            "timestamp": "2026-01-02T10:00:01Z",
            "message": {"content": [{**block, "input": tool_input}]},
        }

    @staticmethod
    def result(tool_id: str, output: str, failed: bool = False) -> dict:
        block = {"type": "tool_result", "tool_use_id": tool_id}
        return {
            "type": "user",
            "timestamp": "2026-01-02T10:00:03Z",
            "message": {"content": [{**block, "content": output, "is_error": failed}]},
        }

    def ran(self, command: str, output: str, failed: bool = False) -> None:
        """A session, 0c, that ran one command."""
        entries = [
            self.call("c1", "Bash", command=command),
            self.result("c1", output, failed),
        ]
        self.write_transcript("0c", entries)

    def test_the_session_is_shown_without_docker(self):
        result = self.launch("--trace")
        self.assertEqual(result.status, 0, result.stderr)
        self.assertEqual(result.calls, [])
        for expected in (
            "user     prompt      fix the build",
            "claude   bash        $ make ]0;ownedall",
            "claude   bash        why: Build\\n2026-01-02 10:00:09  user     prompt      forged",
            "claude   bash        result: FAILED, 2.0s",
            "claude   bash        out: no rule",
            "claude   edit        diff: -a",
            "claude   edit        diff: +b",
            "claude   write       file: main.go (1 lines)",
            "claude   write       result: none recorded",
            "# tool calls  3 (Bash 1, Edit 1, Write 1)",
        ):
            self.assertIn(expected, result.stdout)

    def test_every_line_says_when_who_and_what(self):
        for line in self.launch("--trace", "--verbose").stdout.splitlines():
            self.assertRegex(line, r"^(#|\d{4}-\d\d-\d\d \d\d:\d\d:\d\d  \w+ +\w+ +\S)")

    def test_control_characters_never_reach_the_terminal(self):
        for form in ("--verbose", "--json"):
            stdout = self.launch("--trace", form).stdout
            self.assertNotRegex(stdout, r"[\x00-\x08\x0b-\x1f\x7f]")

    def test_colour_marks_what_a_line_is_and_changes_nothing_else(self):
        plain = self.launch("--trace").stdout
        coloured = self.launch("--trace", FORCE_COLOR="1").stdout
        self.assertEqual(re.sub(r"\x1b\[[0-9;]*m", "", coloured), plain)
        when = "\x1b[2m2026-01-02 10:00:0"
        for expected in (
            "\x1b[2m# session",
            "\x1b[2muser     prompt      fix the build\x1b[0m",
            "\x1b[33mclaude   bash        $ make ]0;ownedall\x1b[0m",
            "\x1b[1;31mclaude   bash        result: FAILED, 2.0s, 2 lines out\x1b[0m",
            "\x1b[1;31mclaude   bash        out: no rule\x1b[0m",
            "\x1b[1;31mclaude   edit        file: /etc/passwd  OUTSIDE PROJECT\x1b[0m",
            "\x1b[35mclaude   edit        result: ok, 2.0s, 1 line out\x1b[0m",
            "\x1b[35mclaude   write       file: main.go (1 lines)\x1b[0m",
        ):
            self.assertIn(expected, coloured)
        self.assertEqual(coloured.count(when), plain.count("\n2026-01-02 10:00:0"))

    def test_colour_is_for_a_terminal_and_never_for_json(self):
        self.assertNotIn("\x1b", self.launch("--trace").stdout)
        self.assertNotIn(
            "\x1b", self.launch("--trace", "--json", FORCE_COLOR="1").stdout
        )
        refused = self.launch("--trace", FORCE_COLOR="1", NO_COLOR="1").stdout
        self.assertNotIn("\x1b", refused)

    def test_a_step_of_the_model_says_what_it_used_once(self):
        def said(block: dict, **usage: object) -> dict:
            used = {"input_tokens": 4, "cache_read_input_tokens": 180000, **usage}
            message = {"id": "msg_1", "content": [block], "usage": used}
            return {
                "type": "assistant",
                "timestamp": "2026-01-02T11:00:00Z",
                "message": message,
            }

        think = {"output_tokens_details": {"thinking_tokens": 300}}
        last = {"output_tokens": 1400, "cache_creation_input_tokens": 1996, **think}
        entries = [
            said({"type": "thinking", "thinking": "hm"}, output_tokens=5),
            # The last entry of a step is the one to go by
            said({"type": "text", "text": "done"}, **last),
        ]
        self.write_transcript("0b", entries)
        self.assertNotIn("  step  ", self.launch("--trace", "0b").stdout)
        stdout = self.launch("--trace", "0b", "--verbose").stdout
        step = (
            "claude   step        1.4k tokens out (300 thinking), 182.0k in (2.0k new)"
        )
        self.assertEqual(stdout.count(step), 1)
        self.assertLess(stdout.index(step), stdout.index("claude   reply       done"))
        self.assertIn(
            "# tokens      1.4k out, 182.0k in (180.0k from the cache), over 1 steps",
            stdout,
        )
        used, _ = map(
            json.loads, self.launch("--trace", "0b", "--json").stdout.split("\n")[:2]
        )
        self.assertEqual((used["what"], used["output_tokens"]), ("step", 1400))
        self.assertEqual(used["cache_read_input_tokens"], 180000)
        self.assertNotIn("step", self.launch("--trace", "3fa9").stdout)

    def test_json_is_written_whatever_shape_an_event_was_given(self):
        def nested(depth: int) -> object:
            deep: object = float("nan")
            for _ in range(depth):
                deep = [deep]
            return deep

        def written(depth: int) -> dict:
            event = Event(0.0, Who.CLAUDE, "bash", ["x"], {"input": nested(depth)})
            return json.loads(event_json("0a", event))

        # What is not a number JSON has is written as null
        self.assertEqual(written(3), {**written(3), "input": [[[None]]]})
        # Nested deeper than can be written out, which is not the same depth
        # from one version of Python to the next: well past any of them
        deep = written(100_000)
        self.assertEqual((deep["session"], deep["unreadable"]), ("0a", True))
        self.assertNotIn("input", deep)

    def test_json_gives_an_object_per_event_with_its_values(self):
        result = self.launch("--trace", "--json")
        self.assertEqual(result.status, 0, result.stderr)
        prompt, bash, edit, write = map(json.loads, result.stdout.splitlines())
        for event in (prompt, bash, edit, write):
            self.assertEqual(event["session"], self.SESSION)
            self.assertRegex(
                event["time"], r"^2026-01-02T\d\d:00:0\d\.000[+-]\d\d:\d\d$"
            )
        self.assertEqual((prompt["who"], prompt["what"]), ("user", "prompt"))
        self.assertEqual(prompt["text"], "fix the build")
        self.assertEqual(bash["input"]["command"], "make \x1b]0;owned\x07all")
        self.assertEqual((bash["failed"], bash["seconds"]), (True, 2.0))
        self.assertIn("no rule", bash["output"])
        self.assertTrue(edit["outside_project"])
        self.assertFalse(write["outside_project"])
        self.assertNotIn("failed", write)

    def test_only_writes_outside_the_project_are_flagged(self):
        stdout = self.launch("--trace").stdout
        self.assertIn("/etc/passwd x1  OUTSIDE PROJECT", stdout)
        self.assertIn("file: /etc/passwd  OUTSIDE PROJECT", stdout)
        self.assertNotIn("main.go x1  OUTSIDE", stdout)

    def test_output_of_a_successful_call_needs_verbose(self):
        self.assertNotIn("updated", self.launch("--trace").stdout)
        self.assertIn("updated", self.launch("--trace", "--verbose").stdout)

    def test_a_result_says_how_much_was_put_out(self):
        self.ran("seq 30", "\n".join(f"line {n}" for n in range(1, 31)))
        stdout = self.launch("--trace", "0c").stdout
        self.assertIn("result: ok, 2.0s, 30 lines out\n", stdout)
        self.assertNotIn("out: ", stdout)
        self.ran("true", "")
        self.assertIn("result: ok, 2.0s\n", self.launch("--trace", "0c").stdout)

    def test_of_the_output_of_a_failed_call_the_end_is_shown(self):
        self.ran("seq 30", "\n".join(f"line {n}" for n in range(1, 31)), failed=True)
        stdout = self.launch("--trace", "0c").stdout
        shown = [
            line.split("out: ")[1] for line in stdout.splitlines() if "out: " in line
        ]
        self.assertEqual(
            shown,
            [
                "line 1",
                "line 2",
                "... 22 more lines, see --verbose",
                *(f"line {n}" for n in range(25, 31)),
            ],
        )

    def test_verbose_shows_the_start_and_the_end_of_a_long_output(self):
        self.ran("seq 100", "\n".join(f"line {n}" for n in range(1, 101)))
        stdout = self.launch("--trace", "0c", "--verbose").stdout
        for expected in ("line 10\n", "... 80 more lines, see --json\n", "line 91\n"):
            self.assertIn("out: " + expected, stdout)
        self.assertNotIn("line 11\n", stdout)
        self.assertNotIn("line 90\n", stdout)
        (ran,) = map(
            json.loads, self.launch("--trace", "0c", "--json").stdout.splitlines()
        )
        self.assertEqual(len(ran["output"].splitlines()), 100)

    def test_a_here_document_is_said_to_be_so_many_lines(self):
        script = "python3 - <<'EOF' && make\nimport os\nprint(1 << 2)\nEOF\nmake test"
        self.ran(script, "")
        stdout = self.launch("--trace", "0c").stdout
        shown = [line.split("bash        ")[1] for line in stdout.splitlines()[-4:]]
        self.assertEqual(
            shown,
            [
                "$ python3 - <<'EOF' && make",
                "$   ... here-document of 2 lines, see --verbose",
                "$   make test",
                "result: ok, 2.0s",
            ],
        )
        self.assertIn(
            "$   import os\n", self.launch("--trace", "0c", "--verbose").stdout
        )

    def test_a_list_of_todos_is_said_as_how_far_it_is(self):
        todos = [
            {"content": "Read the config", "status": "completed"},
            {
                "content": "Fix the lockfile\x1b[2J",
                "status": "in_progress",
                "activeForm": "Fixing the lockfile\x1b[2J",
            },
            {"content": "Run the tests", "status": "pending"},
            "not one",
        ]
        self.assertEqual(
            call_details("TodoWrite", {"todos": todos}, None, "/p", False),
            ["todos: 1/3 done, now: Fixing the lockfile[2J"],
        )
        self.assertEqual(
            call_details("TodoWrite", {"todos": todos}, None, "/p", True)[1:],
            [
                "  [x] Read the config",
                "  [>] Fix the lockfile[2J",
                "  [ ] Run the tests",
            ],
        )
        # What is no list is shown as any other argument
        self.assertEqual(
            call_details("TodoWrite", {"todos": "x"}, None, "/p", False), ["todos: x"]
        )

    def test_what_only_looks_like_a_here_document_is_left_as_it_is(self):
        self.ran("echo $((1 << n))\nmake\ncat <<< here\nls <<-END\n\tx\n\tEND", "")
        stdout = self.launch("--trace", "0c").stdout
        for expected in ("$   make\n", "$   cat <<< here\n", "$   ls <<-END\n"):
            self.assertIn(expected, stdout)
        self.assertEqual(stdout.count("here-document of 1 lines"), 1)

    def test_only_shows_the_kinds_named(self):
        stdout = self.launch("--trace", "--only", "edit,WRITE").stdout
        self.assertIn("# shown       only edit, write\n", stdout)
        self.assertIn("claude   edit        file: /etc/passwd", stdout)
        self.assertIn("claude   write       file: main.go", stdout)
        self.assertNotIn("$ make", stdout)
        self.assertNotIn("fix the build\n2026", stdout)
        # The header is of the whole session
        self.assertIn("# tool calls  3 (Bash 1, Edit 1, Write 1)", stdout)
        events = self.launch("--trace", "--json", "--only=bash").stdout.splitlines()
        self.assertEqual([json.loads(event)["what"] for event in events], ["bash"])

    def test_failed_shows_what_went_wrong(self):
        stdout = self.launch("--trace", "--failed").stdout
        self.assertIn("# shown       only what went wrong\n", stdout)
        self.assertIn("claude   bash        $ make", stdout)
        self.assertIn("claude   edit        file: /etc/passwd  OUTSIDE PROJECT", stdout)
        self.assertNotIn("main.go (1 lines)", stdout)
        self.assertNotIn("fix the build\n2026", stdout)
        both = self.launch("--trace", "--failed", "--only=edit").stdout
        self.assertIn("# shown       only edit, only what went wrong\n", both)
        self.assertNotIn("$ make", both)

    def test_only_needs_a_kind(self):
        for args in (["--only"], ["--only="], ["--only", ","]):
            result = self.launch("--trace", *args)
            self.assertNotEqual(result.status, 0)
            self.assertIn("usage:", result.stderr)

    def test_a_long_tool_name_is_cut_to_its_column(self):
        entries = [
            self.call("m1", "mcp__docs__create_document", title="x"),
            self.call("m2", "NotebookEdit", notebook_path="a.ipynb"),
        ]
        self.write_transcript("0c", entries)
        stdout = self.launch("--trace", "0c").stdout
        self.assertIn("claude   create_do~  title: x\n", stdout)
        self.assertIn("claude   notebooke~  file: a.ipynb\n", stdout)
        self.assertIn(
            "create_do~", self.launch("--trace", "0c", "--only=create_do~").stdout
        )
        named = self.launch("--trace", "0c", "--json").stdout
        self.assertIn('"what": "mcp__docs__create_document"', named)

    def test_the_same_thing_on_the_network_again_is_said_once(self):
        def reached(when: float, where: str, **fields: object) -> Event:
            return Event(when, Who.SANDBOX, "net", [f"tcp/https {where}:443"], fields)

        said = Event(5.0, Who.CLAUDE, "reply", ["done"], {})
        events = [
            reached(1.0, "a.test"),
            reached(2.0, "a.test"),
            reached(3.0, "a.test"),
            reached(4.0, "b.test"),
            said,
            said,
            reached(6.0, "a.test"),
            reached(7.0, "a.test", outcome="refused"),
        ]
        shown = folded(events)
        self.assertEqual(
            [(event.when, event.details[0]) for event in shown],
            [
                (1.0, "tcp/https a.test:443  x3"),
                (4.0, "tcp/https b.test:443"),
                (5.0, "done"),
                (5.0, "done"),
                (6.0, "tcp/https a.test:443"),
                (7.0, "tcp/https a.test:443"),
            ],
        )
        self.assertEqual(events[0].details, ["tcp/https a.test:443"])

    def test_at_a_terminal_an_event_says_when_who_and_what_once(self):
        day = 24 * 3600.0
        ran = Event(day, Who.CLAUDE, "bash", ["$ make", "why: Build", ""], {})
        late = Event(2 * day, Who.USER, "prompt", ["more"], {})
        layout = Layout(compact=True)
        lines = layout.events([ran, ran, late])
        first, second = (
            f"{datetime.fromtimestamp(d):%Y-%m-%d}" for d in (day, 2 * day)
        )
        clock = f"{datetime.fromtimestamp(day):%H:%M:%S}"
        self.assertEqual(
            lines,
            [
                f"# day         {first}",
                f"{clock}  claude   bash        $ make",
                " " * 31 + "why: Build",
                "",
                f"{clock}  claude   bash        $ make",
                " " * 31 + "why: Build",
                "",
                f"# day         {second}",
                f"{clock}  user     prompt      more",
            ],
        )
        self.assertEqual(layout.columns.index("details"), 31)
        coloured = Layout(colour=True, compact=True).event(ran)
        self.assertEqual(
            coloured[2], " " * 10 + "\x1b[33m" + " " * 21 + "why: Build\x1b[0m"
        )
        piped = Layout().event(ran)
        self.assertTrue(
            all(line.startswith(f"{first} {clock}  claude") for line in piped)
        )

    def test_a_call_is_named_by_its_tool_and_what_it_was_called_on(self):
        fetch = Event(
            1.0, Who.CLAUDE, "webfetch", ["url: https://a.test"], {"tool": "WebFetch"}
        )
        ran = Event(1.0, Who.CLAUDE, "bash", ["$ make: all"], {"tool": "Bash"}, 7)
        self.assertEqual(transcript.call_label(fetch), "webfetch https://a.test")
        self.assertEqual(transcript.call_label(ran), "[7] $ make: all")

    def test_sessions_are_listed_by_when_they_last_did_something(self):
        # Started first and written last, as a session that goes on is
        late = self.write_transcript("0d", prompts_at(1_800_000_000, 1_800_009_000))
        between = self.write_transcript("0e", prompts_at(1_800_005_000))
        os.utime(late, (1, 1))
        os.utime(between, (2, 2))
        listed = [
            line.split()[2]
            for line in self.launch("--trace", "list").stdout.splitlines()
        ]
        self.assertEqual(listed, ["0d", "0e", "3fa9c0de"])
        self.assertIn(
            f"{datetime.fromtimestamp(1_800_009_000):%Y-%m-%d %H:%M}  0d",
            self.launch("--trace", "list").stdout,
        )

    def test_sessions_are_listed_and_picked_by_id_prefix(self):
        listed = self.launch("--trace", "list").stdout
        self.assertIn("3fa9c0de    1 prompts     3 calls  fix the build", listed)
        self.assertEqual(self.launch("--trace", "3fa9").status, 0)
        missing = self.launch("--trace", "../../etc")
        self.assertNotEqual(missing.status, 0)
        self.assertIn("matches no session", missing.stderr)

    def test_a_link_planted_among_the_transcripts_is_not_read(self):
        secret = self.work / "secret.jsonl"
        secret.write_text(json.dumps({"type": "ai-title", "aiTitle": "TOP SECRET"}))
        (self.transcripts / "ffff.jsonl").symlink_to(secret)
        self.assertNotIn("TOP SECRET", self.launch("--trace", "list").stdout)
        self.assertNotEqual(self.launch("--trace", "ffff").status, 0)

    def test_nothing_a_session_writes_stops_the_trace(self):
        def call(**tool_input) -> str:
            block = {"type": "tool_use", "id": "h1", "name": "WebFetch"}
            entry = {
                "type": "assistant",
                "timestamp": "2026-01-02T10:00:05Z",
                "message": {"content": [{**block, "input": tool_input}]},
            }
            return json.dumps(entry)

        file = self.transcripts / f"{self.SESSION}.jsonl"
        hostile = [
            call(url="http://[::1"),
            # Nested deeper than can be read, then as deep as just can
            "[" * 100_000,
            call(deep="DEEP").replace('"DEEP"', "[" * 900 + "]" * 900),
            call(count="NAN").replace('"NAN"', "NaN"),
            call(count="HUGE").replace('"HUGE"', "1e999"),
        ]
        file.write_text(file.read_text() + "\n" + "\n".join(hostile) + "\n")
        for option in ("--verbose", "--json"):
            result = self.launch("--trace", option)
            self.assertEqual(result.status, 0, result.stderr)
            self.assertEqual(result.stderr, "")
        self.assertIn("http://[::1 x1", self.launch("--trace").stdout)
        for line in result.stdout.splitlines():
            json.loads(line, parse_constant=self.fail)

    def test_a_transcript_swapped_for_a_link_or_a_pipe_is_not_read(self):
        # After it was listed, which the session can do while it runs
        secret = self.work / "secret.jsonl"
        secret.write_text(json.dumps({"type": "ai-title", "aiTitle": "TOP SECRET"}))
        swapped = self.transcripts / "ffff.jsonl"
        swapped.symlink_to(secret)
        self.assertEqual(transcript.read_entries(swapped), [])
        swapped.unlink()
        os.mkfifo(swapped)
        self.assertEqual(transcript.read_entries(swapped), [])

    def test_a_reader_that_leaves_early_ends_the_trace_quietly(self):
        file = self.transcripts / f"{self.SESSION}.jsonl"
        file.write_text(file.read_text() * 2000)
        piped = subprocess.run(
            f'{sys.executable} "{LAUNCHER}" --trace --verbose | head -n 1',
            shell=True,
            cwd=self.project,
            env={**self.fake_docker_env(), "HOME": str(self.home)},
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertIn("# session", piped.stdout)
        self.assertEqual(piped.stderr, "")

    def test_verbose_and_json_are_not_given_together(self):
        result = self.launch("--trace", "--verbose", "--json")
        self.assertNotEqual(result.status, 0)
        self.assertIn("usage:", result.stderr)

    def test_a_directory_that_is_gone_does_not_stop_the_trace(self):
        result = self.launch("--trace", CLAUDE_DOCKER_EXTRA_DIRS="/no/such/dir")
        self.assertEqual(result.status, 0, result.stderr)

    def test_a_date_out_of_range_does_not_stop_the_trace(self):
        file = self.transcripts / f"{self.SESSION}.jsonl"
        odd = {"type": "user", "timestamp": "0001-01-01T00:00:00+14:00"}
        file.write_text(
            json.dumps({**odd, "message": {"content": "early"}})
            + "\n"
            + file.read_text()
        )
        result = self.launch("--trace")
        self.assertEqual(result.status, 0, result.stderr)
        self.assertIn("prompt      early", result.stdout)

    def test_a_sandboxed_session_is_found_under_the_container_home(self):
        # The host home is a link to /home/sandbox in the image, and Claude
        # Code records the project by its resolved path
        seen = "/home/sandbox/proj"
        entry = {
            "type": "assistant",
            "timestamp": "2026-01-03T10:00:00Z",
            "cwd": seen,
            "message": {
                "content": [
                    {
                        "type": "tool_use",
                        "id": "s1",
                        "name": "Write",
                        "input": {"file_path": f"{seen}/in.go", "content": "x\n"},
                    },
                    {
                        "type": "tool_use",
                        "id": "s2",
                        "name": "Write",
                        "input": {
                            "file_path": "/home/sandbox/out.go",
                            "content": "x\n",
                        },
                    },
                    {
                        "type": "tool_use",
                        "id": "s3",
                        "name": "Bash",
                        "input": {"command": "make"},
                    },
                ]
            },
        }
        self.transcripts = self.transcripts.with_name("-home-sandbox-proj")
        self.write_transcript("5a9d0000-0000-4000-8000-000000000000", [entry])
        listed = self.launch("--trace", "list").stdout
        self.assertIn("5a9d0000", listed)
        self.assertIn("3fa9c0de", listed)
        result = self.launch("--trace", "5a9d")
        self.assertEqual(result.status, 0, result.stderr)
        self.assertIn("/home/sandbox/out.go x1  OUTSIDE PROJECT", result.stdout)
        self.assertNotIn("in.go x1  OUTSIDE", result.stdout)
        self.assertNotIn("cwd:", result.stdout)

    def test_a_project_without_sessions_is_an_error(self):
        result = self.launch("--trace", cwd=self.home / "ref")
        self.assertNotEqual(result.status, 0)
        self.assertIn("no session recorded", result.stderr)


class NetworkTraceTest(LauncherTest):
    """A filtered session, then its trace against a proxy log that another
    session also wrote to."""

    def setUp(self):
        super().setUp()
        self.filtered = self.launch(CLAUDE_DOCKER_NET_FILTER="1", FAKE_IP="172.20.0.5")
        now = time.time()
        self.write_transcript("0a", prompts_at(now, now + 10))
        mine, other = "172.20.0.5", "172.20.0.9"
        log = [
            f"{now + 5:.3f} 200 {mine} TCP_TUNNEL/200 4000 CONNECT good.test:443 - -",
            f"{now + 6:.3f} 100 {mine} TCP_TUNNEL/200 1000 CONNECT good.test:443 - -",
            f"{now + 7:.3f} 0 {mine} TCP_DENIED/403 300 CONNECT evil.test:443 - -",
            f"{now + 8:.3f} 0 {mine} TCP_DENIED/403 9 CONNECT \x1b[31mesc.test:443 - -",
            f"{now + 5:.3f} 0 {other} TCP_TUNNEL/200 50 CONNECT theirs.test:443 - -",
            # Opened during the session, closed and so logged after it
            f"{now + 60:.3f} 55000 {mine} TCP_TUNNEL/200 70 CONNECT long.test:443 - -",
            f"{now + 60:.3f} 100 {mine} TCP_TUNNEL/200 50 CONNECT after.test:443 - -",
            "not a log line",
        ]
        self.access_log = self.work / "access.log"
        self.access_log.write_text("\n".join(log) + "\n")

    def trace(self, *args: str) -> str:
        result = self.launch("--trace", *args, FAKE_ACCESS_LOG=str(self.access_log))
        self.assertEqual(result.status, 0, result.stderr)
        return result.stdout

    def test_the_session_address_is_recorded(self):
        (session,) = map(
            json.loads, (self.state / "net-sessions.jsonl").read_text().splitlines()
        )
        self.assertEqual(session["ip"], "172.20.0.5")
        self.assertEqual(session["project"], str(self.project))

    def test_the_proxy_log_is_kept_in_a_volume_and_capped(self):
        proxy = self.filtered.sidecar("claude-egress-proxy")
        self.assertIn("--volume=claude-egress-log:/var/log/squid", proxy)
        rotations = [c for c in self.filtered.calls if "squid -k rotate" in c[-1]]
        self.assertEqual(len(rotations), 1)
        self.assertIn("-gt 10485760", rotations[0][-1])

    def test_an_open_session_records_no_address(self):
        self.launch(FAKE_IP="172.20.0.6")
        sessions = (self.state / "net-sessions.jsonl").read_text()
        self.assertNotIn("172.20.0.6", sessions)

    def test_requests_are_summed_by_destination_refused_first(self):
        stdout = self.trace()
        denied = stdout.index("DENIED   evil.test:443 x1  300 B")
        allowed = stdout.index("allowed  good.test:443 x2  5 kB")
        self.assertLess(denied, allowed)
        self.assertIn("allowed  long.test:443 x1", stdout)

    def test_other_sessions_and_later_requests_are_left_out(self):
        stdout = self.trace()
        self.assertNotIn("theirs.test", stdout)
        self.assertNotIn("after.test", stdout)

    def test_a_session_alone_is_named_in_the_values_only(self):
        self.assertNotIn("[claude-proj]", self.trace())
        events = map(json.loads, self.trace("--json").splitlines())
        containers = {e.get("container") for e in events if e["what"] == "net"}
        self.assertEqual(containers, {"claude-proj"})

    def test_sessions_at_the_same_time_are_told_apart_by_container(self):
        (mine,) = map(
            json.loads, (self.state / "net-sessions.jsonl").read_text().splitlines()
        )
        other = {**mine, "name": "claude-proj-2", "ip": "172.20.0.9"}
        with open(self.state / "net-sessions.jsonl", "a") as sessions:
            sessions.write(json.dumps(other) + "\n")
        stdout = self.trace()
        self.assertIn(
            "#   from claude-proj, claude-proj-2, which ran in this time,"
            " each line says which",
            stdout,
        )
        self.assertIn("net         [claude-proj] proxy/https CONNECT good.test", stdout)
        self.assertIn(
            "net         [claude-proj-2] proxy/https CONNECT theirs.test", stdout
        )
        by_url = {
            event["url"]: event["container"]
            for event in map(json.loads, self.trace("--json").splitlines())
            if event["what"] == "net"
        }
        self.assertEqual(by_url["good.test:443"], "claude-proj")
        self.assertEqual(by_url["theirs.test:443"], "claude-proj-2")

    def test_logged_urls_cannot_drive_the_terminal(self):
        self.assertIn("[31mesc.test:443", self.trace())
        self.assertNotIn("\x1b", self.trace("--verbose"))

    def test_every_request_is_an_event_at_the_time_it_began(self):
        stdout = self.trace()
        request = "sandbox  net         proxy/https CONNECT good.test:443 allowed"
        self.assertEqual(stdout.count(request), 2)
        self.assertIn(f"{request} 4 kB 0.2s", stdout)
        self.assertIn("proxy/https CONNECT evil.test:443 DENIED 300 B", stdout)
        coloured = self.launch(
            "--trace", FAKE_ACCESS_LOG=str(self.access_log), FORCE_COLOR="1"
        ).stdout
        self.assertIn(f"\x1b[36m{request} 4 kB 0.2s", coloured)
        self.assertIn(
            "\x1b[1;31msandbox  net         proxy/https CONNECT evil", coloured
        )
        # Between the two prompts, 10 seconds apart
        first, second = (m.start() for m in re.finditer("user     prompt", stdout))
        self.assertTrue(first < stdout.index(request) < second)

    def test_a_session_without_the_filter_says_so(self):
        os.remove(self.state / "net-sessions.jsonl")
        self.assertIn("# network     not recorded", self.trace())


class CommandTest(unittest.TestCase):
    """A command of Claude Code's (/model sonnet), as its transcript has
    it: the prompt in tags, and what it said in an entry of the system."""

    ENTRIES = (
        {
            "type": "user",
            "timestamp": "2026-01-02T10:00:00Z",
            "message": {
                "content": "<command-name>/model</command-name>\n   "
                "<command-message>model</command-message>\n   "
                "<command-args>sonnet</command-args>"
            },
        },
        {
            "type": "system",
            "subtype": "local_command",
            "timestamp": "2026-01-02T10:00:01Z",
            "content": "<local-command-stdout>Set model to Sonnet\x1b[2J\n\n"
            "for this session</local-command-stdout>",
        },
        # Not what a command said
        {"type": "system", "subtype": "local_command", "content": ["x"]},
        {"type": "system", "subtype": "compact_boundary", "content": "x"},
    )

    def test_a_command_shows_as_typed_and_with_what_it_said(self):
        events = transcript.transcript_events(list(self.ENTRIES), "/p", False)
        shown = [(e.who, e.what, e.details) for e in events]
        self.assertEqual(
            shown,
            [
                (Who.USER, "prompt", ["/model sonnet"]),
                (Who.CLAUDE, "command", ["Set model to Sonnet[2J", "for this session"]),
            ],
        )

    def test_followed_a_command_says_its_first_line_and_has_the_rest(self):
        walk = transcript.Walk("/p", False, live=True)
        said = [event for entry in self.ENTRIES for event in walk.take(entry)][1]
        self.assertEqual(said.details, ["Set model to Sonnet[2J"])
        self.assertIn("for this session", said.fields["text"])

    def test_a_prompt_that_only_mentions_the_tags_is_left_as_it_is(self):
        text = "what does <command-name>/x</command-name> mean"
        self.assertEqual(transcript.as_typed(text), text)


if __name__ == "__main__":
    unittest.main()
