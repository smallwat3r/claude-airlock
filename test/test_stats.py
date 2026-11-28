"""--trace stats: what the sessions of a project did, summed up, each
session's transcripts counted as its header counts them and what the
launcher recorded of the sandbox counted once, and --since, which picks
the sessions for it, --trace list and --trace all."""

from __future__ import annotations

import dataclasses
import json
import os
import re
import time
from datetime import datetime

import pytest
from harness import LauncherTest, prompts_at
from packets import sample_capture
from transcribed import call, prompt, result

from claude_airlock.errors import Fatal
from claude_airlock.events import Event, Kind, Who
from claude_airlock.report import programs, stats, stats_shown, trace_args

STEP_USAGE = {
    "input_tokens": 10,
    "cache_creation_input_tokens": 20,
    "cache_read_input_tokens": 1000,
    "output_tokens": 50,
}


def step(step_id: str, second: int, **usage: int) -> dict:
    """An entry of a step of the model, with what the API said it used."""
    return {
        "type": "assistant",
        "timestamp": f"2026-01-02T10:00:{second:02d}Z",
        "message": {"id": step_id, "content": [], "usage": {**STEP_USAGE, **usage}},
    }


def cost(dollars: float) -> dict:
    return {"type": "cost-state", "totalCostUSD": dollars}


class ProgramsTest:
    @pytest.mark.parametrize(
        ("command", "ran"),
        [
            ("npm test", ["npm"]),
            ("cd web && FOO=1 npm run build 2>&1 | tail -20", ["cd", "npm", "tail"]),
            (
                "if [ -f x ]; then make; else ./configure; fi",
                ["[", "make", "configure"],
            ),
            ("for f in a b; do pytest $f; done", ["pytest"]),
            (
                "python3 - <<EOF\nimport os; os.system('x')\nEOF\ngit status",
                ["python3", "git"],
            ),
            ("/usr/bin/env node x.js > out.txt", ["node"]),
            ("make \\\n  all && ls", ["make", "ls"]),
            ("time nohup ./run.sh &", ["run.sh"]),
            ("(cd a; ls) && { git diff; }", ["cd", "ls", "git"]),
            ("cat < in.txt | grep -c x", ["cat", "grep"]),
            # One the shell would not read is taken a word at a time
            ('echo "unterminated', ["echo"]),
        ],
    )
    def test_a_command_is_counted_by_the_programs_it_runs(self, command, ran):
        assert list(programs.programs(command)) == ran

    def test_a_program_is_cleaned_and_cut(self):
        (program,) = programs.programs("\x1b[31m" + "x" * 100)
        assert "\x1b" not in program
        assert len(program) == programs.PROGRAM_WIDTH


class TallyTest:
    def test_names_past_those_kept_are_counted_as_left_out(self, monkeypatch):
        monkeypatch.setattr(stats, "MOST_KEPT", 2)
        tally: stats.Tally[str] = stats.Tally()
        for name in ("a", "b", "a", "c", "d"):
            tally.add(name, calls=1, failed=name == "a")
        assert dict(tally.counts["a"]) == {"calls": 2, "failed": 2}
        assert len(tally) == 2
        assert tally.left_out == 2
        # What was left out is in the totals
        assert dict(tally.totals) == {"calls": 5, "failed": 2}
        # The text says how many more there are than it names
        monkeypatch.setattr(stats_shown, "MOST_SHOWN", 1)
        lines = stats_shown._listed(tally, stats.by("calls"), lambda name, counts: name)
        assert lines == [
            "  a",
            "  ... 1 more, see --json",
            "  ... and 2 counted past the 2 kept",
        ]

    def test_each_kind_of_flag_is_said(self):
        named = {one.name for one in dataclasses.fields(stats.Flags)}
        assert set(stats_shown.FLAGS_SAID) == named
        every = stats.Flags(*range(1, len(named) + 1))
        said = stats_shown._flags_said(every)
        assert said.count(", ") == len(named)
        assert stats_shown._flags_said(stats.Flags()) == ""

    def test_names_are_ranked_highest_first_then_by_name(self):
        tally: stats.Tally[str] = stats.Tally()
        for name, outside in (("b", 0), ("a", 0), ("z", 1), ("b", 0)):
            tally.add(name, writes=1, outside=outside)
        assert [name for name, _ in tally.most(stats.by("writes"))] == ["b", "a", "z"]
        files = tally.most(stats_shown.FILES_RANK)
        assert [name for name, _ in files] == ["z", "b", "a"]

    def test_an_event_the_launcher_recorded_is_counted_once(self):
        network = stats.Network()
        fields = {
            "protocol": "tcp/https",
            "transport": "tcp",
            "name": "Good.Test",
            "address": "198.51.100.7",
            "port": 443,
            "source_port": 40443,
            "bytes_out": 5,
            "bytes_in": 7,
            "container": "claude-proj",
        }
        detail = ["tcp/https good.test (198.51.100.7):443  closed after 1s"]
        made = Event(1.0, Who.SANDBOX, Kind.NET, detail, fields, "n1")
        # As the trace of another session that ran at the time has it
        again = Event(1.0, Who.SANDBOX, Kind.NET, detail, dict(fields), "n7")
        other = Event(1.0, Who.SANDBOX, Kind.NET, detail, {**fields, "source_port": 1})
        for event in (made, again, other):
            network.add(event)
        assert dict(network.destinations.counts[("tcp/https", "good.test", 443)]) == {
            "connections": 2,
            "failed": 0,
            "bytes_out": 10,
            "bytes_in": 14,
        }


class SinceTest:
    def test_since_is_a_span_back_from_now_or_a_time(self):
        now = 1_800_000_000.0
        assert trace_args.since_time("30m", now) == now - 1800
        assert trace_args.since_time("7d", now) == now - 7 * 86400
        assert trace_args.since_time("2w", now) == now - 14 * 86400
        local = datetime(2026, 11, 20).timestamp()
        assert trace_args.since_time("2026-11-20", now) == local
        for wrong in ("", "7", "d", "-1d", "7y", "999999d", "tomorrow", "2026-13-01"):
            with pytest.raises(Fatal):
                trace_args.since_time(wrong, now)

    def test_since_is_given_once_and_to_what_is_of_several_sessions(self):
        for args in (
            ["stats", "--since", "7d"],
            ["list", "--since=2026-11-20"],
            ["all", "--json", "--since", "1h"],
        ):
            assert trace_args.trace_options(args, ("--json",)).since is not None
        for args in (
            ["--since", "7d"],
            ["3fa9", "--since", "7d"],
            ["stats", "--since", "7d", "--since", "1d"],
            ["stats", "--since"],
        ):
            with pytest.raises(Fatal):
                trace_args.trace_options(args, ())


class StatsTest(LauncherTest):
    @pytest.fixture(autouse=True)
    def sessions(self, sandbox: None) -> None:
        self.write_transcript(
            "0a",
            [
                prompt("fix the build"),
                step("s1", 1),
                call("c1", "Bash", command="npm test && git status"),
                result("c1", "failed", failed=True),
                step("s2", 3),
                # Each entry of a step says what the whole step used
                step("s2", 3),
                call("c2", "Bash", second=4, command="npm run lint"),
                result("c2", "ok", second=5),
                call("c3", "Write", second=6, file_path="/etc/hosts", content="x"),
                result("c3", "ok", second=7),
                call("c4", "WebFetch", second=8, url="https://docs.test/a"),
                cost(1.25),
            ],
        )
        self.write_transcript(
            "0b",
            [
                prompt("again", 20),
                step("s3", 21, output_tokens=5),
                call("c1", "Write", second=22, file_path="src/main.go", content="x"),
                call("c2", "Write", second=23, file_path="src/main.go", content="y"),
                call("c3", "Bash", second=24, command="\x1b]0;owned\x07npm ci"),
                cost(0.5),
            ],
        )

    def stats(self, *args: str) -> str:
        shown = self.launch("--trace", "stats", *args)
        assert shown.status == 0, shown.stderr
        return shown.stdout

    def test_the_sessions_are_summed_up_as_their_headers_count_them(self):
        shown = self.stats()
        for expected in (
            "# prompts     2\n",
            "# tool calls  7 (Bash 3, Write 3, WebFetch 1)\n",
            "# failed      1\n",
            "# tokens      105 out, 3.1k in (3.0k from the cache), over 3 steps",
            "# cost        $1.75\n",
            "# flagged     1 files written OUTSIDE PROJECT, see --trace SESSION --failed",
            "# commands    by the programs they run, of 3 calls of Bash",
            "#   npm x2, 1 of them FAILED\n",
            # Read as the shell reads it: the escape ahead of it ends in a ;
            "#   ownednpm x1\n",
            "#   git x1, 1 of them FAILED\n",
            "#   src/main.go x2\n",
            "#   /etc/hosts x1  OUTSIDE PROJECT\n",
            "#   docs.test x1\n",
        ):
            assert expected in shown, expected
        assert shown.index("  0b  ") < shown.index("  0a  ")
        assert re.search(
            r"#   \S+ \S+  0a        +1 prompts +4 calls +1 failed +\$1\.25"
            r"  1 FLAGGED  fix the build",
            shown,
        )
        # What the sessions wrote is cleaned
        assert not re.search(r"[\x00-\x08\x0b-\x1f\x7f]", shown)
        assert "]0;ownednpm" not in shown

    def test_the_stats_as_json_name_every_count(self):
        (line,) = self.stats("--json").splitlines()
        said = json.loads(line)
        assert said["what"] == "stats"
        assert (said["sessions"], said["prompts"], said["failed"]) == (2, 2, 1)
        assert said["calls"] == {"Bash": 3, "Write": 3, "WebFetch": 1}
        assert said["tokens"] == {"out": 105, "read": 3090, "cached": 3000, "steps": 3}
        assert (said["cost"], said["costed_sessions"]) == (1.75, 2)
        assert said["flagged"]["outside_project"] == 1
        assert said["commands"][0] == {"program": "npm", "calls": 2, "failed": 1}
        assert {"path": "/etc/hosts", "writes": 1, "outside": True} in said[
            "files_written"
        ]
        assert [one["session"] for one in said["per_session"]] == ["0b", "0a"]
        assert said["since"] is None

    def test_since_leaves_out_what_was_last_written_before(self):
        old = self.transcripts / "0a.jsonl"
        os.utime(old, (1, 1))
        (line,) = self.stats("--json", "--since", "1d").splitlines()
        said = json.loads(line)
        assert [one["session"] for one in said["per_session"]] == ["0b"]
        assert said["since"] is not None
        assert "# since       " in self.stats("--since", "1d")
        listed = self.launch("--trace", "list", "--since", "1d").stdout
        assert "0b" in listed
        assert "0a" not in listed
        every = self.launch("--trace", "all", "--json", "--since", "1d").stdout
        assert {json.loads(one)["session"] for one in every.splitlines()} == {"0b"}

    def test_stats_take_since_and_json_alone(self):
        for args in (("--only", "bash"), ("--failed",), ("--verbose",), ("--follow",)):
            refused = self.launch("--trace", "stats", *args)
            assert refused.status != 0, args
            assert "usage:" in refused.stderr

    def test_with_no_session_since_the_stats_say_so(self):
        for name in ("0a", "0b"):
            os.utime(self.transcripts / f"{name}.jsonl", (1, 1))
        assert (
            self.stats("--since", "1h")
            .splitlines()[0]
            .startswith("# stats       0 sessions of ")
        )


class NetworkStatsTest(LauncherTest):
    def test_what_two_sessions_at_the_same_time_reached_is_counted_once(
        self, sandbox: None
    ):
        self.now = time.time()
        capture = self.work / "capture.pcap"
        capture.write_bytes(sample_capture(self.now))
        self.launch(CLAUDE_AIRLOCK_NET_LOG="1", FAKE_CAPTURE=str(capture))
        self.write_transcript("0a", prompts_at(self.now, self.now + 10))
        alone = self.launch("--trace", "stats").stdout
        # Its trace has the same capture: a transcript does not say which
        # container wrote it
        self.write_transcript("0b", prompts_at(self.now - 5, self.now + 5))
        both = self.launch("--trace", "stats").stdout
        assert "tcp/https good.test" in self.launch("--trace", "0b").stdout
        assert "# network     3 connections to 3 destinations\n" in alone
        assert "# network     3 connections to 3 destinations\n" in both
        assert "#   tcp/https good.test:443 x1\n" in both
        (line,) = self.launch("--trace", "stats", "--json").stdout.splitlines()
        destinations = json.loads(line)["destinations"]
        assert {"protocol": "tcp/postgres", "name": "10.0.0.7", "port": 5432} == {
            key: destinations[-1][key] for key in ("protocol", "name", "port")
        }


class FilteredStatsTest(LauncherTest):
    def test_a_filtered_session_is_counted_by_what_it_asked_the_proxy_for(
        self, sandbox: None
    ):
        self.launch(CLAUDE_AIRLOCK_NET_FILTER="1", FAKE_IP="172.20.0.5")
        now = time.time()
        self.write_transcript("0a", prompts_at(now, now + 10))
        mine, other = "172.20.0.5", "172.20.0.9"
        log = [
            f"{now + 5:.3f} 200 {mine} TCP_TUNNEL/200 4000 CONNECT good.test:443 - -",
            f"{now + 6:.3f} 100 {mine} TCP_TUNNEL/200 1000 CONNECT good.test:443 - -",
            f"{now + 7:.3f} 0 {mine} TCP_DENIED/403 300 CONNECT evil.test:443 - -",
            f"{now + 8:.3f} 0 {mine} TCP_DENIED/403 9 CONNECT \x1b[31mesc.test:443 - -",
            # Of another session, which this one's trace does not have
            f"{now + 5:.3f} 0 {other} TCP_TUNNEL/200 50 CONNECT theirs.test:443 - -",
        ]
        access_log = self.work / "access.log"
        access_log.write_text("\n".join(log) + "\n")
        shown = self.launch("--trace", "stats", FAKE_ACCESS_LOG=str(access_log)).stdout
        assert (
            "# network     4 requests through the egress proxy to 3 destinations,"
            " 5 kB in, 2 DENIED\n" in shown
        )
        assert (
            "#   proxy/https good.test:443 2 requests through the egress proxy,"
            in shown
        )
        assert (
            "#   proxy/https evil.test:443 1 requests through the egress proxy,"
            " 300 B in, 1 DENIED\n" in shown
        )
        assert "theirs.test" not in shown
        assert "\x1b" not in shown
        (line,) = self.launch(
            "--trace", "stats", "--json", FAKE_ACCESS_LOG=str(access_log)
        ).stdout.splitlines()
        said = json.loads(line)
        assert said["reached"] == {
            "requests": 4,
            "denied": 2,
            "bytes_out": 0,
            "bytes_in": 5309,
        }
        good = said["destinations"][0]
        assert (good["name"], good["requests"], good["denied"]) == ("good.test", 2, 0)
