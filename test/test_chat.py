#!/usr/bin/env python3
"""--line-mode: a session talked to in the lines of a trace, claude spoken to
over pipes in the JSON Lines of its print mode. Here what a chat run
through the launcher says, with what the user types all there."""

from __future__ import annotations

import json
import os
import re
import time

from chat_harness import SESSION, LineModeTest, turns
from packets import answer, pcap_file, tcp

from claude_airlock.chat import pipe
from claude_airlock.chat import turn as turning
from claude_airlock.sandbox import claude_args


class ChatTest(LineModeTest):
    def test_a_turn_says_what_the_session_did_on_the_network(self):
        # A session whose capture is read as it runs: what it has when a
        # turn is over is summed under the line of the turn
        then, there = time.time() - 5, "198.51.100.7"
        captured = self.work / "capture.pcap"
        captured.write_bytes(
            pcap_file(
                [
                    (then, tcp(there, 443, sequence=1000), True),
                    (then, answer(there, 443, sequence=5000), False),
                    (then + 1, tcp(there, 443, 0x11, b"", 1101, 5201), True),
                    (then + 2, tcp("10.0.0.7", 5432), True),
                    (then + 2, answer("10.0.0.7", 5432, flags=0x14), False),
                ]
            )
        )
        about = {"project": str(self.project), "start": then, "pid": os.getpid()}
        done = self.chat(
            "hello\n",
            FAKE_PS=f"claude-proj.capture\t{json.dumps(about)}",
            FAKE_CAPTURE=str(captured),
        )
        assert done.returncode == 0, done.stderr
        said = "# network     2 connections to 2 hosts, 100 B out, 200 B in, 1 FAILED\n"
        assert said in done.stdout, done.stdout
        assert done.stdout.index("# turn ") < done.stdout.index(said)
        # Nothing of a session that is not captured
        assert " out, " not in self.chat("hello\n").stdout

    def test_a_chat_says_first_how_its_sandbox_was_started(self):
        done = self.chat("hello\n")
        assert done.returncode == 0, done.stderr
        said = done.stdout
        assert re.search(
            r"sandbox  started     claude-proj under .*, image \S+\n", said
        )
        assert "sandbox  started     limits: memory 16g, processes 512" in said
        assert said.index("limits: memory") < said.index("prompt      hello")
        # Once, it is not followed as what the session does is
        assert said.count("limits: memory") == 1

    def test_claude_is_run_in_print_mode_without_a_tty(self):
        done = self.chat("", "--model", "opus")
        assert done.returncode == 0, done.stderr
        call = self.session_call()
        assert "--tty" not in call
        assert "--interactive" in call
        for arg in pipe.CHAT_ARGS:
            assert arg in call
        # The user's own arguments come last
        assert call[-2:] == ["--model", "opus"]
        assert "--line-mode" not in call

    def test_the_setting_runs_every_conversation_in_line_mode(self):
        def launched(*args: str, **env: str) -> list[str]:
            (self.work / "log").unlink(missing_ok=True)
            self.launched(*args, **env)
            return self.session_call()

        on = {"CLAUDE_AIRLOCK_LINE_MODE": "1"}
        assert "--input-format=stream-json" in launched("--model", "opus", **on)
        assert "--input-format=stream-json" in launched(**on)
        # Not what has no conversation: claude is run as it is
        for args in (["-p", "hi"], ["mcp", "list"], ["--version"], ["--print=x"]):
            call = launched(*args, **on)
            assert "--input-format=stream-json" not in call, args
            assert call[-len(args) :] == args
        assert "--entrypoint=bash" in launched("--shell", **on)
        # On unless switched off, and --line-mode is one session with it
        # either way
        assert "--input-format=stream-json" in launched()
        off = {"CLAUDE_AIRLOCK_LINE_MODE": "0"}
        assert "--input-format=stream-json" not in launched(**off)
        assert "--input-format=stream-json" in launched("--line-mode", **off)

    def test_what_claude_writes_that_is_no_conversation_is_shown_as_it_is(self):
        said = "printf 'unknown command\\033[2J\\n'"
        done = self.chat("", "newthing", FAKE_SESSION=said)
        assert "unknown command[2J\n" in done.stdout

    def test_what_the_session_writes_to_its_errors_is_cleaned_too(self):
        said = r"printf 'docker: no such image\033[2J\033]0;owned\007\n' >&2; exit 125"
        done = self.chat("", FAKE_SESSION=said)
        assert "\x1b" not in done.stdout + done.stderr
        assert "\x07" not in done.stdout + done.stderr
        assert "docker: no such image[2J" in done.stdout + done.stderr
        assert done.returncode == 125

    def test_a_turn_is_shown_as_the_lines_of_a_trace(self):
        done = self.chat("hello there\n")
        assert done.returncode == 0, done.stderr
        assert re.search(r"user     prompt      hello there", done.stdout)
        # The reply whole, where following shows its first line
        assert re.search(r"claude   reply       first line", done.stdout)
        assert re.search(r"claude   reply       second line", done.stdout)
        assert re.search(r"# turn        \d+\.\ds, 0 calls", done.stdout)
        # Under it, that the prompt is the user's again
        assert re.search(
            r"# turn [^\n]*\n" + re.escape(f"# {turning.READY}\n"), done.stdout
        )

    def test_every_prompt_is_a_turn(self):
        done = self.chat("one\ntwo\n")
        assert turns(done.stdout) == 2
        assert re.search(r"user     prompt      two", done.stdout)

    def test_a_line_that_ends_with_a_backslash_takes_the_next(self):
        done = self.chat("one\\\ntwo\n")
        assert turns(done.stdout) == 1

    def test_a_tool_is_refused_unless_the_user_says_yes(self):
        done = self.chat("run the tests\n\n")
        assert "allow bash $ make test? [y/a/N]" in done.stdout
        assert "was told: deny" in done.stdout
        assert re.search(r"# turn        \d+\.\ds, 1 call, 10 in, 5 out\n", done.stdout)

    def test_a_tool_is_allowed_with_a_yes(self):
        done = self.chat("run the tests\ny\n")
        assert "was told: allow" in done.stdout

    def test_a_tool_allowed_for_the_session_is_not_asked_about_again(self):
        done = self.chat("run the tests\na\nrun them again\nrun once more\n")
        assert done.stdout.count("allow bash $ make test?") == 1
        assert done.stdout.count("was told: allow") == 3
        said = "# chat        a: not asked again in this session for every call of bash"
        assert said in done.stdout

    def test_a_yes_allows_one_call_only(self):
        done = self.chat("run the tests\ny\nrun them again\n\n")
        assert done.stdout.count("allow bash $ make test?") == 2
        assert "was told: deny" in done.stdout

    def test_a_tool_is_refused_when_the_input_ends(self):
        done = self.chat("run the tests\n")
        assert "was told: deny" in done.stdout

    def test_the_call_is_shown_before_it_is_asked_about(self):
        done = self.chat("run the tests\ny\n")
        shown = done.stdout.index("claude   bash        [1] $ make test")
        assert shown < done.stdout.index("allow bash")

    def test_the_mode_is_changed_by_asking_claude(self):
        done = self.chat("/mode plan\n/mode\n/mode nonsense\nhello\n")
        assert done.returncode == 0, done.stderr
        assert "# chat        mode plan\n" in done.stdout
        assert "# chat        mode plan, /mode NAME changes it" in done.stdout
        # What claude refuses with is cleaned, and the mode stays
        assert "mode not changed: must be one of[2J default, plan" in done.stdout
        # None of them is a prompt
        assert turns(done.stdout) == 1
        assert "prompt      /mode" not in done.stdout

    def test_the_status_shows_the_effort_claude_says_it_goes_by(self):
        done = self.chat("hello\n/status\n", FAKE_EFFORT="high")
        assert done.returncode == 0, done.stderr
        # Above the prompt, and in full when asked for
        assert "\n[claude-proj] net:open  effort:high\n> /status\n" in done.stdout
        assert "#   model     effort high\n" in done.stdout
        assert "CHANGED" not in done.stdout
        # A model that is told none
        done = self.chat("hello\n/status\n")
        assert "\n[claude-proj] net:open\n> /status\n" in done.stdout
        assert "effort" not in done.stdout
        assert "CHANGED" not in done.stdout

    def test_a_claude_that_says_no_settings_is_said_once_and_not_waited_for(self):
        done = self.chat("hello\nhello\n/status\n", FAKE_EFFORT="not known")
        assert done.returncode == 0, done.stderr
        assert turns(done.stdout) == 2
        changed = re.findall(r"CHANGED in what Claude Code says: (.*?)\.", done.stdout)
        assert changed == ["no settings in control_response"]
        assert "\n[claude-proj] net:open\n> /status\n" in done.stdout

    def test_a_session_without_an_id_is_still_followed(self):
        done = self.chat("hello\n", session="../somewhere")
        assert "claude did not say which session it is" in done.stdout
        assert re.search(r"claude   reply       first line", done.stdout)

    def test_the_subagents_of_claude_are_said_as_they_start_and_end(self):
        done = self.chat("agents\n")
        assert done.returncode == 0, done.stderr
        used = "2 calls, 1.5k tokens, 2s"
        lines = [
            "# agent       started: Map the code (Explore)\n",
            "# agent       started: Read the docs (Explore)  2 running\n",
            f"# agent       completed: Read the docs, {used}  1 running, 1 ended\n",
            f"# agent       completed: Map the code, {used}  all 2 ended\n",
            "claude   reply       they are back\n",
            f"# {turning.READY}\n",
        ]
        places = [done.stdout.find(line) for line in lines]
        assert -1 not in places, done.stdout
        assert places == sorted(places)
        # They ran for no time: how far they were is in no line of its own
        assert "# agents " not in done.stdout

    def test_a_command_that_used_nothing_has_no_turn_line(self):
        done = self.chat("/model sonnet\nhello\n")
        assert done.stdout.count("# ready ") == 2
        assert turns(done.stdout) == 1

    def test_a_guarded_chat_stops_the_turn_and_sends_no_line_after_it(self):
        done = self.chat("fetch\nhello\n", CLAUDE_AIRLOCK_INJECTION_STOP="1")
        assert done.returncode == 0, done.stderr
        said = done.stdout
        assert "POSSIBLE INJECTION in https://example.org: is written as a turn" in said
        assert (
            "# chat        STOPPED the turn: what claude was given to read in"
            " https://example.org is written as a turn of the conversation" in said
        )
        # Claude was told to stop, and the line written before is not sent
        assert "was stopped" in said
        assert "# chat        the lines left are not sent, leaving" in said
        assert "hello" not in said
        # Not asked to, a chat flags it and goes on
        done = self.chat("fetch\nhello\n")
        assert (
            "POSSIBLE INJECTION in https://example.org: is written as a turn"
            in done.stdout
        )
        assert "STOPPED" not in done.stdout
        assert "was went on" in done.stdout
        assert "prompt      hello" in done.stdout

    def test_a_host_is_refused_where_nobody_is_there_to_ask(self):
        done = self.chat("reach\n", **self.asking())
        assert done.returncode == 0, done.stderr
        assert (
            "REFUSED example.com on port 443 (https): not allowed, nobody to ask"
            in done.stdout
        )
        assert "was refused" in done.stdout
        assert "let the session reach" not in done.stdout

    def test_resuming_is_another_session_once_this_one_is_over(self):
        # Known to the launcher, a session of the project
        self.write_transcript(SESSION, [{"type": "user", "message": {"content": "hi"}}])
        done = self.chat(f"/resume {SESSION[:8]}\n", "--continue", "--model", "opus")
        assert done.returncode == 0, done.stderr
        assert f"resuming {SESSION}" in done.stdout
        assert "to go on with this session" not in done.stdout
        first, second = self.session_calls()
        assert "--continue" in first
        assert second[-3:] == ["--model", "opus", f"--resume={SESSION}"]
        assert "--continue" not in second

    def test_a_session_is_picked_to_resume_by_its_number(self):
        self.write_transcript(SESSION, [{"type": "user", "message": {"content": "hi"}}])
        done = self.chat("/resume\n1\n")
        assert re.search(r"#   1\. .*3fa9c0de    1 prompts", done.stdout)
        assert f"resuming {SESSION}" in done.stdout
        assert len([c for c in self.calls() if c[0] == "run"]) == 2


class ArgumentsTest:
    def test_claude_has_a_conversation_unless_its_arguments_say_otherwise(self):
        for args in (
            [],
            ["--model", "opus"],
            ["--resume"],
            ["--continue", "--verbose"],
        ):
            assert claude_args.has_a_conversation(args), args
        for args in (
            ["-p"],
            ["--model", "x", "--print"],
            ["doctor"],
            ["update"],
            ["-v"],
        ):
            assert not claude_args.has_a_conversation(args), args
        # Only as the first argument is a word a command of claude's
        assert claude_args.has_a_conversation(["--model", "mcp"])

    def test_the_arguments_of_a_resumed_session_name_it_alone(self):
        args = [
            "--model",
            "opus",
            "--resume",
            "old",
            "-c",
            "--session-id=x",
            "-r",
            "--verbose",
        ]
        assert claude_args.resumed_args(args, SESSION) == [
            "--model",
            "opus",
            "--verbose",
            f"--resume={SESSION}",
        ]
