#!/usr/bin/env python3
"""--line-mode: a session talked to in the lines of a trace, claude spoken to
over pipes in the JSON Lines of its print mode."""

from __future__ import annotations

import contextlib
import io
import json
import os
import pty
import re
import select
import signal
import subprocess
import sys
import threading
import time
import unittest
import unittest.mock
from datetime import datetime
from pathlib import Path

from harness import LAUNCHER, LauncherTest

from claude_airlock.chat import (
    asking,
    commands,
    console,
    drift,
    notices,
    pipe,
    shell,
    status,
    talk,
    turn,
)
from claude_airlock.chat import followed as following
from claude_airlock.chat import reply as replying
from claude_airlock.chat import said as saying
from claude_airlock.chat import screen as screens
from claude_airlock.events import Event, Who
from claude_airlock.recording import started
from claude_airlock.recording.changes import change_events
from claude_airlock.report import entries
from claude_airlock.report.follow import Follower, Round
from claude_airlock.report.layout import Layout
from claude_airlock.sandbox import claude_args
from claude_airlock.sandbox.mounts import ExtraDir
from claude_airlock.sandbox.runtime import DOCKERS_OWN
from claude_airlock.settings import Host, Settings, SocketAccess

SESSION = "3fa9c0de-1111-4222-8333-444455556666"
# A test at a terminal that waits for what never comes fails after this
PATIENCE = 30.0
# How far apart the bunches of what is typed are written, more than a
# terminal leaves between the chunks of a paste, as Emacs may between the
# bunches of a long input
BUNCH_GAP = 0.12

# Plays claude in its print mode: for each prompt it says which session it
# is, writes the transcript as Claude Code does and says the turn is over.
# A prompt that starts with "run" asks first whether Bash may be used, and
# replies with what it was told, one that starts with "later" after a
# moment. One that starts with "slow" is answered in pieces, a moment
# apart. A request for a permission mode is answered as claude does, for
# the two modes it knows here. A prompt that starts with a slash is a
# command of Claude Code's: the turn it ends used nothing.
FAKE_CLAUDE = """
import json, os, sys, time
from datetime import datetime, timezone

waiting = []

def told():
    if waiting:
        return waiting.pop(0)
    line = sys.stdin.readline()
    return json.loads(line) if line else None

def say(message):
    print(json.dumps(message), flush=True)

# What claude says of a session besides its id, nothing of it known here
ABOUT = {"model": "", "permissionMode": "", "claude_code_version": ""}
ABOUT.update(slash_commands=[], mcp_servers=[])

def record(kind, content):
    now = datetime.now(timezone.utc).isoformat()
    entry = {"type": kind, "timestamp": now, "message": {"content": content}}
    with open(os.environ["FAKE_TRANSCRIPT"], "a") as transcript:
        transcript.write(json.dumps(entry) + "\\n")

def piece(kind, **more):
    say({"type": "stream_event", "event": {"type": kind, **more}})

def reply(text, pieces=()):
    block = {"type": "text", "text": text}
    if pieces:
        piece("content_block_start", content_block={"type": "text"})
    for part in pieces:
        piece("content_block_delta", delta={"type": "text_delta", "text": part})
        time.sleep(0.7)
    record("assistant", [block])
    say({"type": "assistant", "message": {"content": [block]}})
    if pieces:
        piece("content_block_stop")

def allowed():
    call = {"type": "tool_use", "id": "t1", "name": "Bash"}
    call["input"] = {"command": "make test"}
    record("assistant", [call])
    say({"type": "assistant", "message": {"content": [call]}})
    ask = {"subtype": "can_use_tool", "tool_name": "Bash", "input": call["input"]}
    say({"type": "control_request", "request_id": "r1", "request": ask})
    held = []
    while True:
        answer = told()
        if answer is None or answer["type"] == "control_response":
            break
        # A prompt typed meanwhile, for the turn after this one
        held.append(answer)
    waiting.extend(held)
    return answer["response"]["response"]["behavior"] if answer else "nothing"

while True:
    said = told()
    if said is None:
        break
    if said["type"] == "control_request":
        mode = said["request"]["mode"]
        answer = {"request_id": said["request_id"], "subtype": "success"}
        if mode in ("default", "plan"):
            answer["response"] = {"mode": mode}
        else:
            answer.update(subtype="error", error="must be one of\x1b[2J default, plan")
        say({"type": "control_response", "response": answer})
        continue
    asked = said["message"]["content"][0]["text"]
    say({"type": "system", "subtype": "init", "session_id": os.environ["FAKE_ID"], **ABOUT})
    record("user", asked)
    if asked.startswith("later"):
        time.sleep(1.5)
    if asked.startswith(("run", "later")):
        reply("was told: " + allowed())
    elif asked.startswith("slow"):
        reply("one\\ntwo\\nthree", ["one\\n", "two\\n", "three"])
    else:
        reply("first line\\nsecond line")
    over = {"type": "result", "subtype": "success", "is_error": False}
    if not asked.startswith("/"):
        # The model was asked, not so for a command of Claude Code's
        over["usage"] = {"input_tokens": 10, "output_tokens": 5}
        over["modelUsage"] = {}
    say(over)
"""


def page(layout: Layout | None = None) -> console.Page:
    """Somewhere to write to, as a file is written to unless laid out
    otherwise."""
    return console.Page(console.Console("/nowhere"), layout or Layout())


def a_chat(host: Host, claude: object = None) -> talk.Chat:
    """A chat that is not run, with what stands for claude once it is."""
    sandbox = status.Sandbox("claude-test")
    return talk.Chat(host, sandbox, Layout(), lambda _on_end: claude)


@contextlib.contextmanager
def written():
    """What is written meanwhile, as its lines."""
    out = io.StringIO()
    lines: list[str] = []
    with contextlib.redirect_stdout(out):
        yield lines
        lines += out.getvalue().splitlines()


class ChatTest(LauncherTest):
    def environment(self, session: str = SESSION) -> dict[str, str]:
        """What a chat is run with for claude to be played by FAKE_CLAUDE,
        as a sandboxed session of that id."""
        script = self.work / "claude.py"
        script.write_text(FAKE_CLAUDE)
        # Where a sandboxed session knows the project, see project_roots
        name = re.sub(r"[^A-Za-z0-9]", "-", "/home/sandbox/proj")
        transcripts = self.home / ".claude" / "projects" / name
        transcripts.mkdir(parents=True, exist_ok=True)
        return {
            **self.fake_docker_env(),
            "HOME": str(self.home),
            "CLAUDE_AIRLOCK_NET_LOG": "0",
            "CLAUDE_AIRLOCK_PROC_LOG": "0",
            "FAKE_SESSION": f"{sys.executable} {script}",
            "FAKE_ID": session,
            "FAKE_TRANSCRIPT": str(transcripts / f"{SESSION}.jsonl"),
        }

    def chat(self, typed: str, *args: str, session: str = SESSION):
        """Run a chat with what the user types all there, as from a
        file."""
        return subprocess.run(
            [sys.executable, str(LAUNCHER), "--line-mode", *args],
            cwd=self.project,
            env=self.environment(session),
            input=typed,
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )

    def at_a_terminal(
        self, *steps: tuple[str, str | tuple[str, ...]], term: str = "xterm"
    ) -> str:
        """Run a chat at a terminal: for each step, wait for something to
        be written, then type, in bunches a moment apart when several, as
        Emacs sends what is long. What was written in all."""
        environment = {**self.environment(), "TERM": term, "COLUMNS": "100"}
        environment["NO_COLOR"] = "1"
        child, terminal = pty.fork()
        if child == 0:
            os.chdir(self.project)
            os.execve(
                sys.executable,
                [sys.executable, str(LAUNCHER), "--line-mode"],
                environment,
            )
        seen = b""
        deadline = time.monotonic() + PATIENCE

        def read_until(wanted: str, start: int) -> int:
            """Read until something is written after a place. The place
            after it, none when it never is."""
            nonlocal seen
            while wanted.encode() not in seen[start:]:
                if time.monotonic() > deadline:
                    return -1
                if select.select([terminal], [], [], 0.2)[0]:
                    try:
                        seen += os.read(terminal, 65536)
                    except OSError:
                        return -1
            return seen.index(wanted.encode(), start) + len(wanted)

        try:
            place = 0
            for wanted, typed in steps:
                place = read_until(wanted, place)
                if place < 0:
                    self.fail(f"never wrote {wanted!r}: {seen!r}")
                # Not before the chat reads again
                time.sleep(0.2)
                for i, bunch in enumerate(
                    (typed,) if isinstance(typed, str) else typed
                ):
                    if i:
                        time.sleep(BUNCH_GAP)
                    os.write(terminal, bunch.encode())
            # Until it leaves
            read_until("\0", len(seen))
        finally:
            with contextlib.suppress(OSError):
                os.kill(child, signal.SIGKILL)
            os.waitpid(child, 0)
            os.close(terminal)
        return seen.decode(errors="replace").replace("\r\n", "\n")

    def session_call(self) -> list[str]:
        return next(c for c in self.calls() if c[0] == "run" and "--detach" not in c)

    def host(self) -> Host:
        return Host(str(self.home), str(self.project), "", str(self.home / "state"))

    def test_a_chat_says_first_how_its_sandbox_was_started(self):
        done = self.chat("hello\n")
        self.assertEqual(done.returncode, 0, done.stderr)
        said = done.stdout
        self.assertRegex(
            said, r"sandbox  started     claude-proj under .*, image \S+\n"
        )
        self.assertIn("sandbox  started     limits: memory 16g, processes 512", said)
        self.assertLess(said.index("limits: memory"), said.index("prompt      hello"))
        # Once, it is not followed as what the session does is
        self.assertEqual(said.count("limits: memory"), 1)

    def test_claude_is_run_in_print_mode_without_a_tty(self):
        done = self.chat("", "--model", "opus")
        self.assertEqual(done.returncode, 0, done.stderr)
        call = self.session_call()
        self.assertNotIn("--tty", call)
        self.assertIn("--interactive", call)
        for arg in pipe.CHAT_ARGS:
            self.assertIn(arg, call)
        # The user's own arguments come last
        self.assertEqual(call[-2:], ["--model", "opus"])
        self.assertNotIn("--line-mode", call)

    def test_the_setting_runs_every_conversation_in_line_mode(self):
        def launched(*args: str, **env: str) -> list[str]:
            (self.work / "log").unlink(missing_ok=True)
            subprocess.run(
                [sys.executable, str(LAUNCHER), *args],
                cwd=self.project,
                env={**self.environment(), **env},
                input="",
                capture_output=True,
                text=True,
                timeout=60,
                check=False,
            )
            return self.session_call()

        on = {"CLAUDE_AIRLOCK_LINE_MODE": "1"}
        self.assertIn("--input-format=stream-json", launched("--model", "opus", **on))
        self.assertIn("--input-format=stream-json", launched(**on))
        # Not what has no conversation: claude is run as it is
        for args in (["-p", "hi"], ["mcp", "list"], ["--version"], ["--print=x"]):
            call = launched(*args, **on)
            self.assertNotIn("--input-format=stream-json", call, args)
            self.assertEqual(call[-len(args) :], args)
        self.assertIn("--entrypoint=bash", launched("--shell", **on))
        # On unless switched off, and --line-mode is one session with it
        # either way
        self.assertIn("--input-format=stream-json", launched())
        off = {"CLAUDE_AIRLOCK_LINE_MODE": "0"}
        self.assertNotIn("--input-format=stream-json", launched(**off))
        self.assertIn("--input-format=stream-json", launched("--line-mode", **off))

    def test_what_claude_writes_that_is_no_conversation_is_shown_as_it_is(self):
        environment = self.environment()
        environment["FAKE_SESSION"] = "printf 'unknown command\\033[2J\\n'"
        done = subprocess.run(
            [sys.executable, str(LAUNCHER), "--line-mode", "newthing"],
            cwd=self.project,
            env=environment,
            input="",
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        self.assertIn("unknown command[2J\n", done.stdout)

    def test_what_the_session_writes_to_its_errors_is_cleaned_too(self):
        environment = self.environment()
        said = r"printf 'docker: no such image\033[2J\033]0;owned\007\n' >&2; exit 125"
        done = subprocess.run(
            [sys.executable, str(LAUNCHER), "--line-mode"],
            cwd=self.project,
            env={**environment, "FAKE_SESSION": said},
            input="",
            capture_output=True,
            text=True,
            timeout=60,
            check=False,
        )
        self.assertNotIn("\x1b", done.stdout + done.stderr)
        self.assertNotIn("\x07", done.stdout + done.stderr)
        self.assertIn("docker: no such image[2J", done.stdout + done.stderr)
        self.assertEqual(done.returncode, 125)

    def test_a_turn_is_shown_as_the_lines_of_a_trace(self):
        done = self.chat("hello there\n")
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertRegex(done.stdout, r"user     prompt      hello there")
        # The reply whole, where following shows its first line
        self.assertRegex(done.stdout, r"claude   reply       first line")
        self.assertRegex(done.stdout, r"claude   reply       second line")
        self.assertRegex(done.stdout, r"# turn        \d+\.\ds, 0 calls")
        # Under it, that the prompt is the user's again
        self.assertRegex(
            done.stdout, r"# turn [^\n]*\n" + re.escape(f"# {talk.READY}\n")
        )

    def test_every_prompt_is_a_turn(self):
        done = self.chat("one\ntwo\n")
        self.assertEqual(len(re.findall(r"# turn ", done.stdout)), 2)
        self.assertRegex(done.stdout, r"user     prompt      two")

    def test_a_line_that_ends_with_a_backslash_takes_the_next(self):
        done = self.chat("one\\\ntwo\n")
        self.assertEqual(len(re.findall(r"# turn ", done.stdout)), 1)

    def test_a_tool_is_refused_unless_the_user_says_yes(self):
        done = self.chat("run the tests\n\n")
        self.assertIn("allow bash $ make test? [y/a/N]", done.stdout)
        self.assertIn("was told: deny", done.stdout)
        self.assertRegex(done.stdout, r"# turn        \d+\.\ds, 1 call, 10 in, 5 out\n")

    def test_a_tool_is_allowed_with_a_yes(self):
        done = self.chat("run the tests\ny\n")
        self.assertIn("was told: allow", done.stdout)

    def test_a_tool_allowed_for_the_session_is_not_asked_about_again(self):
        done = self.chat("run the tests\na\nrun them again\nrun once more\n")
        self.assertEqual(done.stdout.count("allow bash $ make test?"), 1)
        self.assertEqual(done.stdout.count("was told: allow"), 3)
        said = "# chat        a: not asked again in this session for every call of bash"
        self.assertIn(said, done.stdout)

    def test_a_yes_allows_one_call_only(self):
        done = self.chat("run the tests\ny\nrun them again\n\n")
        self.assertEqual(done.stdout.count("allow bash $ make test?"), 2)
        self.assertIn("was told: deny", done.stdout)

    def test_the_mode_is_changed_by_asking_claude(self):
        done = self.chat("/mode plan\n/mode\n/mode nonsense\nhello\n")
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn("# chat        mode plan\n", done.stdout)
        self.assertIn("# chat        mode plan, /mode NAME changes it", done.stdout)
        # What claude refuses with is cleaned, and the mode stays
        self.assertIn("mode not changed: must be one of[2J default, plan", done.stdout)
        # None of them is a prompt
        self.assertEqual(len(re.findall(r"# turn ", done.stdout)), 1)
        self.assertNotIn("prompt      /mode", done.stdout)

    def test_a_tool_is_refused_when_the_input_ends(self):
        done = self.chat("run the tests\n")
        self.assertIn("was told: deny", done.stdout)

    def test_the_call_is_shown_before_it_is_asked_about(self):
        done = self.chat("run the tests\ny\n")
        shown = done.stdout.index("claude   bash        [1] $ make test")
        self.assertLess(shown, done.stdout.index("allow bash"))

    def test_a_session_without_an_id_is_still_followed(self):
        done = self.chat("hello\n", session="../somewhere")
        self.assertIn("claude did not say which session it is", done.stdout)
        self.assertRegex(done.stdout, r"claude   reply       first line")

    def test_at_a_terminal_what_comes_while_a_line_is_typed_goes_above_it(self):
        said = self.at_a_terminal(
            ("> ", "slow\r"),
            # While the reply is written, the start of the next prompt
            ("two", "typ"),
            ("# turn", "ed\r"),
            ("first line", "\x04"),
        )
        # The reply line by line as it was made, once
        self.assertEqual(said.count("claude   reply"), 2)
        self.assertIn("claude   reply\none\n", said)
        # The line being typed was erased with the status above it, and
        # both written again under what came
        head = "[claude-proj] net:open\n"
        self.assertIn(f"> typ\x1b[1A\r\x1b[Jthree\n{head}> typ", said)
        self.assertRegex(said, r"# turn [^\n]*\n" + re.escape(head) + "> typ")
        self.assertRegex(said, r"user     prompt      typed\n")
        again = (
            f"to go on with this session: claude-airlock --line-mode --resume {SESSION}"
        )
        self.assertIn(again, said)

    def test_at_a_terminal_a_line_being_typed_is_not_the_answer_to_a_question(self):
        said = self.at_a_terminal(
            ("> ", "later\r"),
            # Typed before claude asks, entered after
            ("prompt      later", "y"),
            ("allow bash", "\r"),
            ("sent, claude takes it up", "y\r"),
            ("first line", "\x04"),
        )
        self.assertIn("what you were typing is not taken for the answer", said)
        # The question rang, and was put again under the line it was not for
        self.assertIn("\a", said)
        self.assertIn("was told: allow", said)
        self.assertEqual(len(re.findall(r"# turn ", said)), 2)
        self.assertRegex(said, r"user     prompt      y\n")

    def test_at_a_terminal_tab_completes_a_command(self):
        said = self.at_a_terminal(("> ", "/he\t\r"), ("drops the line", "\x04"))
        self.assertIn("> /help", said)

    def test_at_a_terminal_shift_enter_starts_a_new_line_of_the_prompt(self):
        said = self.at_a_terminal(
            ("> ", "one\x1b[13;2utwo\x1b[27;2;13~three\x1b\rfour\r"),
            ("first line", "\x04"),
        )
        # Each key a line of its own on the screen, all of them one prompt
        self.assertIn("> one\n\rtwo\n\rthree\n\rfour\n", said)
        self.assertEqual(said.count("user     prompt      one\n"), 1)
        self.assertEqual(len(re.findall(r"# turn ", said)), 1)

    def test_at_a_terminal_lines_pasted_unmarked_are_one_prompt(self):
        # Without the escapes of a bracketed paste, as a terminal that
        # does not mark one sends it
        said = self.at_a_terminal(
            ("> ", "one\rtwo\rthree\r"),
            # It waits for Enter, the line break at its end or not
            ("> one\r\n\rtwo\r\n\rthree", " four\r"),
            ("first line", "\x04"),
        )
        self.assertIn("> one\n\rtwo\n\rthree four\n", said)
        self.assertEqual(said.count("user     prompt      one\n"), 1)
        self.assertEqual(len(re.findall(r"# turn ", said)), 1)

    def test_at_a_terminal_an_unfinished_paste_is_typed_on(self):
        said = self.at_a_terminal(
            ("> ", "one\rtw"),
            # Written again as the start of the line, not entered yet
            ("> one\r\n\rtw", "o\r"),
            ("first line", "\x04"),
        )
        self.assertEqual(said.count("user     prompt      one\n"), 1)
        self.assertEqual(len(re.findall(r"# turn ", said)), 1)

    def test_in_a_shell_buffer_of_emacs_lines_sent_together_are_one_prompt(self):
        said = self.at_a_terminal(
            ("> ", "one\ntwo\nthree\n"), ("first line", "\x04"), term="dumb"
        )
        self.assertEqual(said.count("user     prompt      one\n"), 1)
        self.assertEqual(len(re.findall(r"# turn ", said)), 1)

    def test_in_a_shell_buffer_of_emacs_a_long_input_sent_in_bunches_is_one_prompt(
        self,
    ):
        said = self.at_a_terminal(
            ("> ", ("one\ntw", "o\nthree\n")), ("first line", "\x04"), term="dumb"
        )
        self.assertEqual(said.count("user     prompt      one\n"), 1)
        self.assertNotIn("user     prompt      o\n", said)
        self.assertEqual(len(re.findall(r"# turn ", said)), 1)

    def test_in_a_shell_buffer_of_emacs_no_prompt_is_written_while_a_turn_runs(self):
        said = self.at_a_terminal(
            ("> ", "slow\n"), ("# ready", "run it\n"), ("[y/a/N]", "\x04"), term="dumb"
        )
        # The reply as it is made, no prompt among its lines
        self.assertIn("claude   reply\none\ntwo\nthree\n", said)
        # One when the turn is over, under the status, and the question
        self.assertIn(
            "waiting for your input\n[claude-proj] net:open\n> run it\n", said
        )
        self.assertEqual(said.count("> "), 2, said)
        self.assertIn("\nallow bash $ make test? [y/a/N] ", said)

    def test_the_first_prompt_has_the_sandbox_above_it(self):
        said = self.at_a_terminal(("> ", "\x04"), term="dumb")
        self.assertIn("[claude-proj] net:open\n> ", said)

    def test_a_command_that_used_nothing_has_no_turn_line(self):
        done = self.chat("/model sonnet\nhello\n")
        self.assertEqual(done.stdout.count("# ready "), 2)
        self.assertEqual(len(re.findall(r"# turn ", done.stdout)), 1)

    def test_ctrl_c_interrupts_the_turn_that_runs(self):
        said = self.at_a_terminal(
            ("> ", "later\r"),
            ("prompt      later", "\x03"),
            ("interrupting", "\x03"),
            # The docker of the tests stops nothing: left the usual way
            ("stopping the session", "\x04"),
        )
        self.assertIn("# chat        interrupting, Ctrl-C again stops", said)
        # The second one stops the session, by its container
        self.assertIn("# chat        stopping the session", said)
        self.assertIn(["stop", "claude-proj"], self.calls())

    def test_resuming_is_another_session_once_this_one_is_over(self):
        # Known to the launcher, a session of the project
        self.write_transcript(SESSION, [{"type": "user", "message": {"content": "hi"}}])
        done = self.chat(f"/resume {SESSION[:8]}\n", "--continue", "--model", "opus")
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn(f"resuming {SESSION}", done.stdout)
        self.assertNotIn("to go on with this session", done.stdout)
        first, second = [
            c for c in self.calls() if c[0] == "run" and "--detach" not in c
        ]
        self.assertIn("--continue", first)
        self.assertEqual(second[-3:], ["--model", "opus", f"--resume={SESSION}"])
        self.assertNotIn("--continue", second)

    def test_a_session_is_picked_to_resume_by_its_number(self):
        self.write_transcript(SESSION, [{"type": "user", "message": {"content": "hi"}}])
        done = self.chat("/resume\n1\n")
        self.assertRegex(done.stdout, r"#   1\. .*3fa9c0de    1 prompts")
        self.assertIn(f"resuming {SESSION}", done.stdout)
        self.assertEqual(len([c for c in self.calls() if c[0] == "run"]), 2)

    def test_what_a_subagent_does_is_followed_with_its_session(self):
        session = self.write_transcript(SESSION, [])
        follower = Follower(self.host(), False, session, container="claude-test")
        follower.poll()
        subagents = self.transcripts / SESSION / "subagents"
        subagents.mkdir(parents=True)
        entries = [
            {"type": "user", "isSidechain": True, "message": {"content": "do it"}},
            {
                "type": "assistant",
                "isSidechain": True,
                "message": {"content": [{"type": "text", "text": "done"}]},
            },
        ]
        text = "".join(json.dumps(entry) + "\n" for entry in entries)
        (subagents / "agent-a1.jsonl").write_text(text)
        # Not what is no transcript of a subagent, or is one through a link
        (subagents / "agent-a1.meta.json").write_text("{}")
        (subagents / "agent-a2.jsonl").symlink_to(subagents / "agent-a1.jsonl")
        events = [event for _ in range(4) for event in follower.poll().events]
        # What it was asked is in the call that started it, not a prompt
        self.assertEqual(
            [(path, e.who, e.what, e.details) for path, e in events],
            [(session, Who.AGENT, "reply", ["done"])],
        )
        # Of the network, its own container alone
        self.assertTrue(follower._ours("claude-test"))
        self.assertFalse(follower._ours("claude-test-2"))

    def test_a_cleared_session_is_followed_in_its_new_transcript(self):
        chat = a_chat(self.host())
        other = SESSION.replace("3fa9", "4fa9")
        with written():
            for session in (SESSION, other, "../elsewhere"):
                chat._heard(
                    {"type": "system", "subtype": "init", "session_id": session}
                )
        # What is not an id changes nothing
        tails = chat._followed._follower._tails
        self.assertEqual([path.stem for path in tails], [other])

    def said_by(self, *messages: dict) -> list[str]:
        """What a chat writes of what claude says, the lines about what
        changed in it."""
        chat = a_chat(self.host())
        with written() as lines:
            for message in messages:
                chat._heard(message)
        return [line for line in lines if "CHANGED" in line]

    def test_a_chat_says_nothing_of_what_claude_says_as_it_reads_it(self):
        init = {"type": "system", "subtype": "init", "session_id": SESSION}
        init.update(model="claude-opus-5-5", permissionMode="default")
        init.update(claude_code_version="2.1.0", slash_commands=[], mcp_servers=[])
        usage = {"input_tokens": 10, "output_tokens": 5}
        limit = {"status": "allowed", "rateLimitType": "five_hour", "resetsAt": 9}
        windows = {"five_hour": {"utilization": 0.2}, "seven_day": {"utilization": 0.1}}
        over = {"type": "result", "subtype": "success", "is_error": False}
        changed = self.said_by(
            init,
            {"type": "system", "subtype": "status", "status": "compacting"},
            {"type": "keep_alive"},
            {"type": "stream_event", "event": {"type": "message_stop"}},
            # Of a subagent, whose pieces are not written
            {"type": "stream_event", "parent_tool_use_id": "t1"},
            {"type": "assistant", "message": {"content": [], "model": "<synthetic>"}},
            {
                "type": "assistant",
                "message": {"content": [], "model": "claude-opus-5-5", "usage": usage},
            },
            {"type": "user", "message": {"content": []}},
            {
                "type": "rate_limit_event",
                "rate_limit_info": {**limit, "utilization": 0.4},
            },
            {
                "type": "rate_limit_event",
                "rate_limit_info": {**limit, "unifiedWindows": windows},
            },
            # A window that is not shown says nothing of those that are
            {
                "type": "rate_limit_event",
                "rate_limit_info": {"status": "allowed", "rateLimitType": "overage"},
            },
            {
                **over,
                "usage": usage,
                "modelUsage": {"claude-opus-5-5": {"contextWindow": 200_000}},
            },
            # A command of Claude Code's, the model was not asked
            over,
            # Windows that are not shown say nothing of those that are
            {
                "type": "rate_limit_event",
                "rate_limit_info": {
                    "status": "allowed",
                    "unifiedWindows": {"overage": {"status": "allowed"}},
                },
            },
            # A turn that did not go well may not say what its model reads
            {"type": "result", "subtype": "error_during_execution", "usage": usage},
            {},
        )
        self.assertEqual(changed, [])

    def test_a_chat_says_what_changed_in_what_claude_says(self):
        usage = {"input_tokens": 10, "output_tokens": 5}
        for message, what in (
            ({"type": "new_thing"}, "a message line mode does not know, new_thing"),
            # As it came the day the status lost its limits
            (
                {
                    "type": "rate_limit_event",
                    "rate_limit_info": {
                        "status": "allowed",
                        "rateLimitType": "five_hour",
                    },
                },
                "no utilization in rate_limit_event",
            ),
            (
                {
                    "type": "rate_limit_event",
                    "rate_limit_info": {
                        "status": "allowed",
                        "unifiedWindows": {"seven_day": {"status": "allowed"}},
                    },
                },
                "no utilization in rate_limit_event",
            ),
            ({"type": "stream_event", "event": "x"}, "no event in stream_event"),
            ({"type": "stream_event", "event": {}}, "no event.type in stream_event"),
            ({"type": "assistant", "message": "x"}, "no message in assistant"),
            (
                {"type": "assistant", "message": {"content": [], "model": "claude-x"}},
                "no usage in assistant",
            ),
            (
                {
                    "type": "result",
                    "subtype": "success",
                    "is_error": False,
                    "usage": usage,
                },
                "no modelUsage in result success",
            ),
            (
                {
                    "type": "result",
                    "subtype": "success",
                    "is_error": False,
                    "usage": usage,
                    "modelUsage": {"m": {}},
                },
                "no contextWindow of a model in result success",
            ),
        ):
            # Twice, said once
            changed = self.said_by(message, message)
            self.assertEqual(len(changed), 1, message)
            self.assertIn(what, changed[0])
        init = {"type": "system", "subtype": "init", "session_id": SESSION}
        init.update(model=7, claude_code_version="2.2.0", slash_commands=[])
        (line,) = self.said_by(init)
        self.assertIn("Claude Code 2.2.0", line)
        for missing in ("model", "permissionMode", "mcp_servers"):
            self.assertIn(f"no {missing} in system init", line)
        self.assertNotIn("no slash_commands", line)
        # The mode is also said in between, where the rest is not
        self.assertEqual(self.said_by({"type": "system", "subtype": "status"}), [])

    def test_a_chat_notes_what_changed_for_a_trace_of_the_session(self):
        host = self.host()
        chat = a_chat(host)
        # A moment ago, as it is when claude first says something
        began = time.time() - 1
        mine = Follower(host, verbose=False, container="claude-test")
        others = Follower(host, verbose=False, container="claude-other")

        def followed(follower: Follower) -> list[Event]:
            found = Round()
            follower._poll_notes(found)
            return [event for _, event in found.events]

        # A note is of the thousandth of a second it was added in
        time.sleep(0.002)
        with written():
            for _ in range(2):
                chat._heard({"type": "new_thing", "text": "secret"})
        rows, events = change_events(host, 0, float("inf"))
        self.assertEqual(
            rows,
            [
                (
                    "claude code",
                    "CHANGED what it says, 1 noted: line mode may have shown less",
                )
            ],
        )
        (event,) = events
        self.assertEqual((event.who, event.what), (Who.CLAUDE, "changed"))
        self.assertIn("a message line mode does not know, new_thing", event.details[0])
        self.assertNotIn("secret", event.details[0])
        # Of that session, by its container
        self.assertEqual(change_events(host, 0, float("inf"), "claude-other")[1], [])
        self.assertEqual(len(change_events(host, 0, float("inf"), "claude-test")[1]), 1)
        # The chat said it itself, it is not written again as it follows
        self.assertTrue(following.told_over_the_pipe(event, began))
        # Nor is what was noted before a session is followed, a trace's
        time.sleep(0.002)
        self.assertEqual(followed(Follower(host, verbose=False)), [])
        with written():
            chat._heard({"type": "another_thing"})
        self.assertEqual([event.what for event in followed(mine)], ["changed"] * 2)
        self.assertEqual(followed(mine) + followed(others), [])

    def test_a_file_asked_about_is_outside_the_project_as_the_session_knows_it(self):
        chat = a_chat(self.host())
        asked: list[str] = []

        def ask(prompt: str) -> str | None:
            asked.append(prompt)
            return "y"

        chat._asker.ask = ask  # type: ignore[method-assign]
        # The project is under the home of the container for the session,
        # whose paths these are, wherever it is on the host
        for path in ("/home/sandbox/proj/a.py", "/etc/hosts"):
            edit = {"file_path": path, "old_string": "a", "new_string": "b"}
            with written():
                chat._asker.decide({"tool_name": "Edit", "input": edit})
        self.assertEqual(
            asked,
            [
                "allow edit file: /home/sandbox/proj/a.py? [y/a/N] ",
                "allow edit file: /etc/hosts  OUTSIDE PROJECT? [y/a/N] ",
            ],
        )

    def test_a_reply_of_before_the_chat_is_history_one_since_is_told_by_the_pipe(self):
        began = time.time()
        told = following.told_over_the_pipe
        now = Event(began + 1, Who.CLAUDE, "reply", ["x"], {})
        self.assertTrue(told(now, began))
        self.assertFalse(told(Event(1.0, Who.CLAUDE, "reply", ["x"], {}), began))
        # What a command said and what a subagent replied are the transcript's
        for who, what in ((Who.CLAUDE, "command"), (Who.AGENT, "reply")):
            self.assertFalse(told(Event(now.when, who, what, [], {}), began))

    def test_what_claude_says_of_the_session_live_is_not_said_again(self):
        began = time.time()
        told = following.told_over_the_pipe
        soon = began + 1
        # A retry, a compaction and a task that ended come over the pipe
        for what in ("api", "compact", "task"):
            self.assertTrue(told(Event(soon, Who.CLAUDE, what, ["x"], {}), began))
            self.assertFalse(told(Event(1.0, Who.CLAUDE, what, ["x"], {}), began))
        # What only the transcript has is shown from it
        for what in ("context", "mode", "model", "prompt"):
            self.assertFalse(told(Event(soon, Who.CLAUDE, what, ["x"], {}), began))

    def test_ctrl_c_is_for_the_turn_that_runs_else_for_the_line(self):
        chat = a_chat(self.host())
        chat._reading = True
        with self.assertRaises(KeyboardInterrupt):
            chat._on_interrupt(2, None)
        chat._turns.begin()
        chat._on_interrupt(2, None)
        self.assertTrue(chat._interrupt)

    def test_a_line_is_not_waited_for_once_claude_has_ended(self):
        chat = a_chat(self.host())
        chat._session_ended()
        with written(), self.assertRaises(KeyboardInterrupt):
            chat._read("> ")
        self.assertFalse(chat._reading)

    def test_a_turn_that_is_quiet_says_that_it_still_runs(self):
        shown, turns = page(), turn.Turns()
        heart = turn.Heartbeat(shown, turns, lambda: False)
        with written() as lines:
            # Not between two turns
            shown.wrote -= turn.QUIET
            heart.beat()
            self.assertEqual(lines, [])
            turns.begin()
            # Not while claude has just taken a step
            heart.beat()
            self.assertEqual(lines, [])
            turns.current.since -= turn.QUIET
            heart.beat()
            # Said once, the next one waits twice as long
            shown.wrote -= turn.QUIET
            heart.beat()
            shown.wrote -= turn.QUIET
            heart.beat()
            self.assertEqual(heart.wait, 4 * turn.QUIET)
            # What else is written only puts it off
            shown.say(["chat        something"])
            heart.beat()
            self.assertEqual(heart.wait, 4 * turn.QUIET)
            # A step of claude starts the wait over
            turns.current.stepped()
            heart.beat()
            self.assertEqual(heart.wait, turn.QUIET)
        self.assertEqual(sum("# working " in line for line in lines), 2)

    def test_a_turn_that_waits_for_the_user_is_not_said_to_run(self):
        shown, turns = page(), turn.Turns()
        asking_now = [True]
        heart = turn.Heartbeat(shown, turns, lambda: asking_now[0])
        with written() as lines:
            turns.begin()
            turns.current.since -= turn.QUIET
            shown.wrote -= turn.QUIET
            heart.beat()
            self.assertEqual(lines, [])
            asking_now[0] = False
            heart.beat()
        self.assertEqual(sum("# working " in line for line in lines), 1)

    def test_at_a_terminal_a_quiet_turn_is_said_to_run_in_one_line(self):
        terminal, turns = console.Console("/nowhere"), turn.Turns()
        terminal._redrawn = True
        heart = turn.Heartbeat(console.Page(terminal, Layout()), turns, lambda: False)
        with written() as lines:
            turns.begin()
            turns.current.since -= 2 * turn.QUIET + 1
            heart.beat()
            working = terminal._working
            self.assertRegex(working, r"^# working +10s, waiting for claude$")
            turns.current.stepped()
            heart.beat()
            self.assertEqual(terminal._working, "")
        self.assertEqual(lines, [])


class PipeTest(unittest.TestCase):
    def test_a_session_id_that_is_none_is_not_made_a_path_of(self):
        host = Host("/home/me", "/home/me/proj", "", "")
        for said in ("../../../etc/passwd", "x" * 36, None, 7, SESSION + "/.."):
            self.assertIsNone(saying.transcript_of(host, said))
        found = saying.transcript_of(host, SESSION)
        self.assertEqual(found.name, f"{SESSION}.jsonl")
        self.assertIn(Path("/home/me/.claude/projects"), found.parents)

    def test_what_claude_says_of_the_session_is_taken_when_it_is_what_it_should(self):
        session = saying.Session()
        self.assertFalse(session.heard({"subtype": "status", "permissionMode": "plan"}))
        self.assertEqual(session.mode, "plan")
        init = {
            "subtype": "init",
            "session_id": "../x",
            "model": "claude\x1b[2J-x",
            "slash_commands": [
                "compact",
                "/model",
                "a b",
                "x\x1b[2J",
                7,
                "plugin:skill",
            ],
            "mcp_servers": [{"name": "docs", "status": "connected"}, "x"],
        }
        self.assertTrue(session.heard(init))
        self.assertEqual(session.id, "")
        self.assertEqual(session.model, "claude[2J-x")
        self.assertEqual(session.commands, ["/compact", "/model", "/plugin:skill"])
        self.assertEqual(session.servers, [("docs", "connected")])
        session.heard({**init, "session_id": SESSION})
        self.assertEqual(session.id, SESSION)
        # The last server that goes is gone
        session.heard({**init, "mcp_servers": []})
        self.assertEqual(session.servers, [])

    def test_the_model_of_the_session_is_the_one_that_last_replied(self):
        session = saying.Session()
        session.heard({"subtype": "init", "model": "claude-fable-5-2"})
        # /model names the model it chose, the next reply is by it
        said = {
            "model": "<synthetic>",
            "content": [{"type": "text", "text": "Set model to `Opus 5.5` for now"}],
        }
        chose = {"local_command_run": {"command": "model", "args": "opus"}}
        session.replied({"message": said, **chose})
        self.assertEqual(
            (session.model, session.chosen), ("claude-fable-5-2", "Opus 5.5")
        )
        session.replied({"message": {"model": "claude-opus-5-5"}})
        self.assertEqual((session.model, session.chosen), ("claude-opus-5-5", ""))
        for odd in ({"model": "<synthetic>"}, {"model": 7}, {}, "x"):
            session.replied({"message": odd})
        self.assertEqual(session.model, "claude-opus-5-5")
        # What another command says, or /model when it chose nothing
        session.replied({"message": said, "local_command_run": {"command": "cost"}})
        session.replied({"message": {"content": "Usage: /model"}, **chose})
        self.assertEqual(session.chosen, "")
        # The start of the next turn names it by its id
        session.replied({"message": said, **chose})
        session.heard({"subtype": "init", "model": "claude-opus-5-5"})
        self.assertEqual((session.model, session.chosen), ("claude-opus-5-5", ""))

    def test_claude_has_a_conversation_unless_its_arguments_say_otherwise(self):
        for args in (
            [],
            ["--model", "opus"],
            ["--resume"],
            ["--continue", "--verbose"],
        ):
            self.assertTrue(claude_args.has_a_conversation(args), args)
        for args in (
            ["-p"],
            ["--model", "x", "--print"],
            ["doctor"],
            ["update"],
            ["-v"],
        ):
            self.assertFalse(claude_args.has_a_conversation(args), args)
        # Only as the first argument is a word a command of claude's
        self.assertTrue(claude_args.has_a_conversation(["--model", "mcp"]))

    def test_a_count_is_a_number_within_reason(self):
        for odd in (True, "1", -1, float("inf"), float("nan"), 10**400, None):
            self.assertIsNone(entries.measured(odd))
        self.assertEqual(entries.measured(3), 3.0)

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
        self.assertEqual(
            claude_args.resumed_args(args, SESSION),
            ["--model", "opus", "--verbose", f"--resume={SESSION}"],
        )

    def agent(self) -> pipe.Agent:
        """Claude played by what says again what it is told, in the place
        of the docker command that runs it. Ended with the test."""
        ran: list[subprocess.Popen] = []

        def run(*_args: str, **options) -> subprocess.Popen:
            ran.append(subprocess.Popen(["cat"], **options))
            return ran[-1]

        agent = pipe.Agent([], lambda: None, run)

        def end() -> None:
            agent.close()
            agent.status()
            # Once nothing reads them any more
            agent.ended.wait(PATIENCE)
            for process in ran:
                for piped in (process.stdout, process.stderr):
                    if piped:
                        piped.close()

        self.addCleanup(end)
        return agent

    def test_what_claude_is_told_is_a_line_each(self):
        agent = self.agent()
        agent.prompt("hello")
        asked = agent.request("set_permission_mode", mode="plan")
        agent.respond("r1", {"behavior": "allow"})
        agent.refuse("r2", "no")
        sent = [agent.messages.get(timeout=PATIENCE) for _ in range(4)]
        agent.close()
        self.assertEqual(agent.status(), 0)
        self.assertEqual(asked, "chat-1")
        self.assertEqual(sent[0]["message"]["content"][0]["text"], "hello")
        self.assertEqual(
            sent[1]["request"], {"subtype": "set_permission_mode", "mode": "plan"}
        )
        self.assertEqual(sent[2]["response"]["response"], {"behavior": "allow"})
        self.assertEqual(sent[3]["response"]["subtype"], "error")

    def test_what_claude_answers_is_told_to_what_asked_for_it(self):
        agent = self.agent()
        answers: list[dict] = []
        asked = agent.request("set_permission_mode", answers.append, mode="plan")
        # Nothing waits for the answer to an interrupt
        stopped = agent.request("interrupt")
        self.assertTrue(agent.pending)
        for odd in ("no", {"request_id": stopped}, {"request_id": [asked]}):
            agent.answered({"response": odd})
        self.assertEqual(answers, [])
        answer = {"request_id": asked, "subtype": "success"}
        agent.answered({"response": answer})
        self.assertFalse(agent.pending)
        # Told once
        agent.answered({"response": answer})
        self.assertEqual(answers, [answer])


def message(kind: str, *blocks: dict, **more) -> dict:
    return {"type": kind, "message": {"content": list(blocks)}, **more}


class TurnTest(unittest.TestCase):
    def test_a_turn_knows_the_calls_it_made_and_waits_for(self):
        ran = turn.Turn(time.monotonic() - 42)
        self.assertRegex(turn.working_line(ran), r"4\ds, waiting for claude$")
        self.assertRegex(turn.working_line(ran, 5), r" 40s, waiting for claude$")
        for call, tool in (("t1", "Bash"), ("t2", "Read"), ("t3", "Bash")):
            block = {"type": "tool_use", "id": call, "name": tool, "input": {}}
            ran.heard(message("assistant", block, {"type": "text", "text": "x"}))
        # Not those of a subagent, which are in a transcript of its own
        inner = {"type": "tool_use", "id": "t9", "name": "Grep", "input": {}}
        ran.heard(message("assistant", inner, parent_tool_use_id="t1"))
        ran.heard(message("assistant", {"type": "tool_use", "id": ["x"]}))
        self.assertEqual(ran.said, 4)
        self.assertRegex(turn.working_line(ran), r" 0s, waiting for bash, read$")
        for call in ("t1", "t3", ["x"]):
            ran.heard(message("user", {"type": "tool_result", "tool_use_id": call}))
        self.assertRegex(turn.working_line(ran), r"waiting for read$")
        ran.waiting.clear()
        ran.thinking = True
        self.assertRegex(turn.working_line(ran), r"waiting for claude, thinking$")

    def test_one_turn_runs_at_a_time(self):
        turns = turn.Turns()
        self.assertTrue(turns.begin())
        first = turns.current
        # A prompt typed while it runs is not a turn of its own
        self.assertFalse(turns.begin())
        self.assertIs(turns.current, first)
        turns.end()
        self.assertTrue(turns.begin())
        self.assertIsNot(turns.current, first)

    def test_a_turn_that_went_wrong_says_so(self):
        ran = turn.Turn(0.0)
        ended = {
            "subtype": "error_max_turns",
            "is_error": True,
            "result": "too\x1b[2J long",
        }
        self.assertTrue(
            turn.turn_line(ran, ended).endswith("ENDED error_max_turns: too[2J long")
        )
        ran.interrupted = True
        self.assertTrue(turn.turn_line(ran, ended).endswith("0 calls  interrupted"))

    def test_the_turn_line_says_what_was_used_and_what_is_new(self):
        usage = {
            "input_tokens": 10,
            "cache_read_input_tokens": 29990,
            "output_tokens": 5,
        }
        result = {
            "subtype": "success",
            "usage": usage,
            "total_cost_usd": 0.05,
            "modelUsage": {"claude-x": {"contextWindow": 200000}, "other": 7},
        }
        used = turn.Usage()
        used.step({"message": {"usage": usage}})
        first = used.parts(result, "claude-x")
        self.assertEqual(
            first, ["30.0k in", "5 out", "$0.0500", "context 15%", "claude-x"]
        )
        # The cost claude gives is the session's, and the model is named once
        second = used.parts({**result, "total_cost_usd": 0.0512}, "claude-x")
        self.assertEqual(second, ["30.0k in", "5 out", "$0.0012", "context 15%"])
        # A command of Claude Code's used nothing, and says nothing
        nothing = {
            "usage": {"input_tokens": 0, "output_tokens": 0},
            "total_cost_usd": 0.0512,
        }
        self.assertEqual(used.parts(nothing, "claude-y"), [])
        # What is not a count or a cost is left out
        odd = {"usage": {"input_tokens": True, "output_tokens": float("nan")}}
        for cost in ("1", -1, float("inf"), 10**400):
            self.assertEqual(turn.used({**odd, "total_cost_usd": cost}, 0.0), [])
        self.assertEqual(turn.used({"usage": []}, 0.0), [])


def piece(kind: str, **more) -> dict:
    return {"type": kind, **more}


class ReplyTest(unittest.TestCase):
    def stream(self, layout: Layout) -> tuple[replying.ReplyStream, list[str]]:
        before: list[str] = []
        return (
            replying.ReplyStream(page(layout), lambda: before.append("before")),
            before,
        )

    def test_at_a_terminal_a_reply_is_written_as_it_is_made(self):
        replies, before = self.stream(Layout(compact=True))
        with written() as lines:
            replies.piece(piece("content_block_start", content_block={"type": "text"}))
            self.assertTrue(replies.writing)
            replies.piece(piece("content_block_delta", delta={"text": "one\nt"}))
            # Its first line is out under when it started, the second not yet
            self.assertEqual(before, ["before"])
            replies.piece(piece("content_block_delta", delta={"text": "wo"}))
            # Its whole comes while its pieces do, and is not written again
            replies.whole(message("assistant", {"type": "text", "text": "one\ntwo"}))
            replies.piece(piece("content_block_stop"))
            self.assertFalse(replies.writing)
        self.assertRegex(lines[1], r"^\d\d:\d\d:\d\d  claude   reply$")
        self.assertEqual(lines[2:], ["one", "two", ""])

    def test_a_reply_that_was_not_told_in_pieces_is_written_whole(self):
        replies, before = self.stream(Layout(compact=True))
        with written() as lines:
            replies.whole(message("assistant", {"type": "text", "text": "all\nof it"}))
            # Not one without text, and not what a command said
            replies.whole(message("assistant", {"type": "text", "text": " \n"}))
            said = message("assistant", {"type": "text", "text": "Set model"})
            replies.whole({**said, "local_command_run": True})
        self.assertEqual(lines[2:], ["all", "of it", ""])
        self.assertEqual(before, ["before"])

    def test_the_whole_of_a_reply_that_comes_after_its_pieces_is_passed_over(self):
        replies, _ = self.stream(Layout(compact=True))
        with written() as lines:
            replies.piece(piece("content_block_start", content_block={"type": "text"}))
            replies.piece(piece("content_block_delta", delta={"text": "one"}))
            replies.piece(piece("content_block_stop"))
            replies.whole(message("assistant", {"type": "text", "text": "one"}))
            # The next one is owed nothing
            replies.whole(message("assistant", {"type": "text", "text": "two"}))
            # Nor is the one after a turn in which a whole never came
            replies.piece(piece("content_block_start", content_block={"type": "text"}))
            replies.piece(piece("content_block_delta", delta={"text": "three"}))
            replies.turn_over()
            replies.whole(message("assistant", {"type": "text", "text": "four"}))
        self.assertEqual(
            [l for l in lines if l in ("one", "two", "three", "four")],
            ["one", "two", "three", "four"],
        )

    def test_in_a_file_a_reply_is_written_once_it_is_whole(self):
        replies, before = self.stream(Layout())
        with written() as lines:
            replies.piece(piece("content_block_start", content_block={"type": "text"}))
            replies.piece(piece("content_block_delta", delta={"text": "one\ntwo"}))
            self.assertEqual(before, [])
            replies.piece(piece("content_block_stop"))
        self.assertEqual(len(lines), 2)
        for line, text in zip(lines, ("one", "two")):
            self.assertRegex(line, r"^\d{4}-.* claude   reply       " + text + "$")

    def test_what_was_said_is_shown_whole(self):
        said = "Set model to `Sonnet`\nfor this session only"
        event = Event(1_800_000_000.0, Who.CLAUDE, "command", ["Set"], {"text": said})
        lines = replying.said_whole(page(Layout(compact=True)), event)
        # Its day, then when and who, then the text from the left edge
        self.assertRegex(lines[1], r"^\d\d:\d\d:\d\d  claude   command$")
        self.assertEqual(
            lines[2:], ["Set model to `Sonnet`", "for this session only", ""]
        )
        # In a file every line says when and who
        lines = replying.said_whole(page(), event)
        self.assertEqual(len(lines), 2)
        self.assertRegex(lines[1], r"claude   command     for this session only$")

    def test_a_reply_is_wrapped_as_it_is_indented(self):
        lines = replying.wrapped("  - one two three four", 12)
        self.assertEqual(lines, ["  - one two", "  three four"])
        self.assertEqual(replying.wrapped("", 12), [""])

    def test_a_reply_without_colour_is_as_written_its_code_not_wrapped(self):
        text = "Run this now please:\n```sh\nmake test --keep-going\n```\n**done**"
        self.assertEqual(
            replying.reply_lines(text, 12, False),
            [
                "Run this now",
                "please:",
                "```sh",
                "make test --keep-going",
                "```",
                "**done**",
            ],
        )

    def test_a_reply_in_colour_has_styles_for_its_marks(self):
        code, bold = replying.CODE, replying.BOLD

        def lines(text: str, width: int | None = None) -> list[str]:
            return replying.reply_lines(text, width, True)

        # The fences are left out, and the code is not read as Markdown
        self.assertEqual(
            lines("```py\nx = '**a**'\n\n```\nafter"),
            [f"\x1b[{code}mx = '**a**'\x1b[0m", "", "after"],
        )
        self.assertEqual(
            lines("use `make` **now**"),
            [f"use \x1b[{code}mmake\x1b[0m \x1b[{bold}mnow\x1b[0m"],
        )
        self.assertEqual(
            lines("## The `x` plan"),
            [
                f"\x1b[{bold}mThe \x1b[0m\x1b[{bold};{code}mx\x1b[0m\x1b[{bold}m plan\x1b[0m"
            ],
        )
        # Not what only looks like a mark
        self.assertEqual(lines("2**3 and 4**5, a * b"), ["2**3 and 4**5, a * b"])
        self.assertEqual(lines("`a ** b ** c`"), [f"\x1b[{code}ma ** b ** c\x1b[0m"])
        # A span goes on in the line it is wrapped to
        self.assertEqual(
            lines("**one two three**", 9),
            [f"\x1b[{bold}mone two\x1b[0m", f"\x1b[{bold}mthree\x1b[0m"],
        )
        # A block that is never closed is code to its end
        self.assertEqual(lines("~~~\nls"), [f"\x1b[{code}mls\x1b[0m"])
        # What a session writes cannot pass for a mark or a style
        self.assertEqual(lines("a\x01b\x1b[2Jc"), ["ab[2Jc"])

    def test_a_reply_in_pieces_reads_as_the_whole(self):
        text = "\n\n  First.\n\n```\ncode\n\nmore\n```\nlast  \n\n"
        for colour in (False, True):
            whole = replying.reply_lines(text, 20, colour)
            writer = replying.ReplyWriter(20, colour)
            pieces = [line for char in text for line in writer.feed(char)]
            self.assertEqual(pieces + writer.end(), whole)
        self.assertEqual(replying.reply_lines(text, None, False)[0], "First.")


class AskingTest(unittest.TestCase):
    def asker(self, answers: list[str | None]) -> asking.Asker:
        """One whose questions are answered at once, with what is given."""
        asker = asking.Asker(
            page(), console.Console("/nowhere"), "/p", lambda: False, lambda: None
        )
        self.asked: list[str] = []

        def ask(prompt: str) -> str | None:
            self.asked.append(prompt)
            return answers.pop(0)

        asker.ask = ask  # type: ignore[method-assign]
        return asker

    def test_a_line_entered_before_a_question_could_be_read_is_no_answer(self):
        screen = console.Console("/nowhere")
        # A shell buffer of Emacs: someone types, and what is not known
        screen.interactive, screen._redrawn = True, False
        asker = asking.Asker(page(), screen, "/p", lambda: False, lambda: None)
        answers: list[str | None] = []
        asked = threading.Thread(target=lambda: answers.append(asker.ask("allow? ")))
        with written() as lines:
            asked.start()
            while not asker.asking:
                time.sleep(0.01)
            # Typed for claude, entered as the question came
            self.assertFalse(asker.take("yes"))
            self.assertTrue(asker.asking)
            with unittest.mock.patch.object(asking, "TOO_SOON", 0.0):
                self.assertTrue(asker.take("y"))
            asked.join(5)
        self.assertEqual(answers, ["y"])
        self.assertIn("came before the question could be read", "".join(lines))

    def test_an_answer_names_options_by_number_or_is_taken_as_said(self):
        options = [{"label": "Red"}, {"label": "Blue"}]
        self.assertEqual(asking.chosen("2", options), "Blue")
        self.assertEqual(asking.chosen("1, 2", options), "Red, Blue")
        self.assertEqual(asking.chosen("3", options), "3")
        self.assertEqual(asking.chosen(" green ", options), "green")
        # Digits that are no number to int
        self.assertEqual(asking.chosen("\u00b2", options), "\u00b2")
        self.assertFalse(saying.is_number("\u0662"))

    def test_a_question_is_answered_once_and_not_by_a_line_typed_before_it(self):
        asker = asking.Asker(
            page(), console.Console("/nowhere"), "/p", lambda: False, lambda: None
        )
        self.assertFalse(asker.take("hello"))
        asker._question = stale = asking.Question("allow? ", stale=True)
        with written():
            # Meant as a prompt
            self.assertFalse(asker.take("fix the build"))
            self.assertTrue(asker.take("y"))
        self.assertFalse(asker.asking)
        stale.answer(None)
        self.assertEqual(stale.said, "y")
        # Given up, it has no answer
        asker._question = left = asking.Question("allow? ", stale=False)
        asker.give_up()
        self.assertTrue(left.answered.is_set())
        self.assertIsNone(left.said)

    def test_a_question_without_anyone_to_ask_has_no_answer(self):
        asker = asking.Asker(
            page(), console.Console("/nowhere"), "/p", lambda: True, lambda: None
        )
        with written():
            self.assertIsNone(asker.ask("allow? "))
        self.assertFalse(asker.asking)

    def request(self, **more) -> dict:
        return {"tool_name": "Bash", "input": {"command": "git status"}, **more}

    def test_the_diff_of_an_edit_asked_about_is_coloured(self):
        edit = {
            "file_path": "/p/a.py",
            "old_string": "a\nb\nc",
            "new_string": "a\nB\nc",
        }
        for colour in (True, False):
            asker = asking.Asker(
                page(Layout(colour=colour)),
                console.Console("/nowhere"),
                "/p",
                lambda: False,
                lambda: None,
            )
            with written() as lines:
                asker._reviewed("Edit", edit, [])
            taken_out = next(line for line in lines if "diff: -b" in line)
            put_in = next(line for line in lines if "diff: +B" in line)
            self.assertEqual(taken_out.startswith("\x1b[31m"), colour)
            self.assertEqual(put_in.startswith("\x1b[32m"), colour)

    def test_a_tool_is_allowed_by_a_yes_alone(self):
        for typed, behaviour in (
            ("y", "allow"),
            (" YES ", "allow"),
            ("", "deny"),
            ("yes please", "deny"),
            (None, "deny"),
        ):
            with written():
                decision = self.asker([typed]).decide(self.request())
            self.assertEqual(decision["behavior"], behaviour, typed)
        self.assertEqual(self.asked, ["allow bash $ git status? [y/a/N] "])
        # What is allowed is what was shown
        self.assertEqual(decision.get("updatedInput"), None)

    def test_always_takes_the_rule_claude_suggests_for_this_session_alone(self):
        rule = {"toolName": "Bash", "ruleContent": "git status"}
        suggested = {"type": "addRules", "rules": [rule], "behavior": "allow"}
        asked = self.request(
            permission_suggestions=[
                {"type": "setMode", "mode": "acceptEdits"},
                {**suggested, "destination": "localSettings"},
            ]
        )
        with written() as lines:
            decision = self.asker(["a"]).decide(asked)
        self.assertIn(
            "# chat        a: not asked again in this session for Bash(git status)",
            lines,
        )
        self.assertEqual(decision["updatedInput"], {"command": "git status"})
        # Written to no settings, whatever claude suggested
        self.assertEqual(
            decision["updatedPermissions"], [{**suggested, "destination": "session"}]
        )

    def test_always_without_a_rule_is_for_the_whole_tool_and_remembered(self):
        asker = self.asker(["a"])
        long = {
            "type": "addRules",
            "behavior": "allow",
            "rules": [{"toolName": "Bash", "ruleContent": "x" * 600}],
        }
        with written() as lines:
            # A rule too long to be read is none
            first = asker.decide(self.request(permission_suggestions=[long]))
            second = asker.decide(self.request())
        self.assertIn(
            "# chat        a: not asked again in this session for every call of bash",
            lines,
        )
        self.assertNotIn("updatedPermissions", first)
        self.assertEqual(second["behavior"], "allow")
        self.assertEqual(len(self.asked), 1)

    def test_a_call_that_was_cut_is_shown_whole_before_it_is_asked_about(self):
        command = "\n".join(f"echo {n}" for n in range(30))
        with written() as lines:
            self.asker(["n"]).decide(
                {"tool_name": "Bash", "input": {"command": command}}
            )
        self.assertIn("# bash        the call whole:", lines)
        self.assertIn("  $   echo 29", lines)
        with written() as lines:
            plan = {"plan": "# Plan\n\n1. Do it\x1b[2J"}
            self.asker(["y"]).decide({"tool_name": "ExitPlanMode", "input": plan})
        self.assertIn("1. Do it[2J", lines)
        # One that was all there is not shown twice
        with written() as lines:
            self.asker(["y"]).decide(self.request())
        self.assertEqual(len(lines), 1)

    def test_the_questions_of_claude_are_put_with_their_options(self):
        questions = [
            {"question": "Which?", "options": [{"label": "Red"}, {"label": "Blue"}]},
            "x",
            {"question": "Why?"},
        ]
        with written() as lines:
            decision = self.asker(["2", "because"]).decide(
                {"tool_name": "AskUserQuestion", "input": {"questions": questions}}
            )
        self.assertEqual(
            lines[:3], ["# question    Which?", "#   1. Red", "#   2. Blue"]
        )
        self.assertEqual(
            decision["updatedInput"]["answers"], {"Which?": "Blue", "Why?": "because"}
        )
        with written():
            refused = self.asker([None]).decide(
                {"tool_name": "AskUserQuestion", "input": {"questions": questions}}
            )
        self.assertEqual(refused, asking.REFUSED)


class NoticesTest(unittest.TestCase):
    def test_what_claude_does_besides_answering_is_said(self):
        said = notices.Notices(page())

        def system(subtype: str, **more) -> dict:
            return {"type": "system", "subtype": subtype, **more}

        with written() as lines:
            said.system(system("status", status="requesting"))
            said.system(system("status", status="compacting"))
            about = {"pre_tokens": 29232, "post_tokens": 7898}
            said.system(system("compact_boundary", compact_metadata=about))
            said.system(system("api_retry", error="overloaded\x1b[2J"))
            said.system(system("task_started", task_id="a1", description="Run it"))
            still_running = said.running
            said.system(system("task_notification", task_id="a1", status="completed"))
            self.assertEqual((still_running, said.running), (1, 0))
            said.system(system("task_notification", task_id=["x"]))
            said.cleared()
        self.assertEqual(
            lines,
            [
                "# chat        compacting the conversation",
                "# chat        the conversation was compacted, 29.2k tokens to 7.9k",
                "# chat        the API did not answer, trying again  overloaded[2J",
                "# task        started: Run it",
                "# task        completed: Run it",
                "# chat        a new conversation, the one before is cleared",
            ],
        )

    def test_a_limit_of_the_account_is_said_once(self):
        said = notices.Notices(page())
        with written() as lines:
            said.limit(7)
            said.limit({"status": "allowed", "rateLimitType": "five_hour"})
            for _ in range(2):
                said.limit({"status": "allowed_warning", "rateLimitType": "five_hour"})
        self.assertEqual(
            lines, ["# chat        usage limit: allowed_warning five hour"]
        )


class ServersTest(unittest.TestCase):
    def test_the_mcp_servers_are_said_at_the_start_and_when_they_change(self):
        said = notices.Notices(page())
        servers = [("docs", "connected"), ("mail", "needs-auth"), ("db", "failed")]
        with written() as lines:
            said.servers([])
            said.servers(servers)
            said.servers(servers)
            said.servers([("docs", "connected"), ("mail", "connected")])
            said.servers([])
        others = "mail (needs-auth), db (failed)"
        self.assertEqual(
            lines,
            [
                f"# chat        MCP servers: 1 connected, NOT connected: {others}",
                "# chat        MCP servers: 2 connected",
                "# chat        MCP servers: none any more",
            ],
        )


def lines_now(lines: list[str]) -> str:
    """What was written so far, where written gives it at its end."""
    return sys.stdout.getvalue() + "\n".join(lines)


class CommandsTest(LauncherTest):
    def commands(
        self, handover: commands.Handover | None = None, status=lambda: None
    ) -> commands.Commands:
        host = Host(str(self.home), str(self.project), "", "")
        shown = page()
        self.session, self.turns = saying.Session(), turn.Turns()
        self.shell = shell.Shell(shown, "claude-test")
        # What claude was asked for, each with what is told its answer
        self.requests: list[tuple] = []
        resume = commands.Resume(shown, host, self.turns, lambda _: "1", handover)
        return commands.Commands(
            shown,
            self.session,
            lambda *asked, **more: self.requests.append((*asked, more)),
            self.shell.run,
            resume.resume,
            status,
        )

    def test_status_and_statusline_say_what_the_statusline_writes(self):
        asked: list[str] = []
        ours = self.commands(status=lambda: asked.append("status"))
        for line in ("/status", "/statusline"):
            self.assertIs(ours.do(line), commands.Did.DONE)
        self.assertEqual(asked, ["status", "status"])

    def test_what_a_command_of_the_users_writes_is_cleaned(self):
        ours = self.commands()
        script = "import sys; print('one\\x1b[2J', flush=True); print('two', file=sys.stderr)"
        ran = [sys.executable, "-c", script + "; sys.exit(3)"]
        seen: list[bool] = []

        def run(*_args: str, **options):
            seen.append(self.shell.running)
            return subprocess.Popen(ran, **options)

        with (
            unittest.mock.patch.object(shell, "docker_popen", run),
            written() as lines,
        ):
            self.assertIs(ours.do("!make test"), commands.Did.DONE)
        self.assertEqual(lines[1:3], ["one[2J", "two"])
        self.assertIn("ended with 3", lines[3])
        # Ctrl-C is for the command while it runs, and only then
        self.assertEqual(seen, [True])
        self.assertFalse(self.shell.running)

    def test_ctrl_c_ends_what_a_command_of_the_users_runs_in_the_container(self):
        ours = self.commands()
        # docker's end of it: it passes on what the command writes, and
        # what it started outlives it, as in a container
        client = (
            "import subprocess, sys\n"
            "out = {'stdout': subprocess.PIPE, 'stderr': subprocess.STDOUT}\n"
            "ran = subprocess.Popen(sys.argv[1:], **out)\n"
            "for line in ran.stdout:\n"
            "    sys.stdout.buffer.write(line)\n"
            "    sys.stdout.buffer.flush()\n"
        )
        killed: list[str] = []

        def run(*args: str, **options):
            self.assertEqual(args[:2], ("exec", "claude-test"))
            return subprocess.Popen(
                [sys.executable, "-c", client, *args[2:]], **options
            )

        def in_container(*args: str) -> bool:
            killed.append(args[-1])
            return subprocess.run(["bash", "-c", args[-1]], check=False).returncode == 0

        threading.Timer(1.0, self.shell.interrupt).start()
        started = time.monotonic()
        with (
            unittest.mock.patch.object(shell, "docker_popen", run),
            unittest.mock.patch.object(shell, "docker_ok", in_container),
            written() as lines,
        ):
            self.assertIs(ours.do("!echo up; sleep 60"), commands.Did.DONE)
        self.assertLess(time.monotonic() - started, 30)
        # Its group is not shown, what it wrote is
        self.assertEqual(lines[1], "up")
        self.assertIn("interrupted", lines[-1])
        self.assertNotIn("may still be running", lines[-1])
        (kill,) = killed
        group = int(kill.rsplit("-", 1)[1])
        for _ in range(50):
            try:
                with open(f"/proc/{group}/stat") as stat:
                    if stat.read().rsplit(")", 1)[1].split()[0] == "Z":
                        break
            except OSError:
                break
            time.sleep(0.1)
        else:
            self.fail("what the command ran was left running")

    def test_ctrl_c_is_for_a_command_of_the_users_while_it_runs(self):
        host = Host(str(self.home), str(self.project), "", "")
        chat = a_chat(host)
        chat._turns.begin()
        chat._shell.running = True
        chat._on_interrupt(signal.SIGINT, None)
        self.assertFalse(chat._interrupt)
        chat._shell.running = False
        chat._on_interrupt(signal.SIGINT, None)
        self.assertTrue(chat._interrupt)

    def test_claude_is_listened_to_while_a_question_waits(self):
        host = Host(str(self.home), str(self.project), "", "")
        chat = a_chat(host)
        said: list[tuple] = []

        class Claude:
            def respond(self, asked, decision):
                said.append((asked, decision["behavior"]))

            def refuse(self, asked, why):
                said.append((asked, "refused"))

        ask = {"subtype": "can_use_tool", "tool_name": "Bash", "input": {}}
        asking = {"type": "control_request", "request_id": "r1", "request": ask}
        with written():
            chat._asked.start(Claude())
            # Whoever listens is not kept by the question
            chat._heard(asking)
            chat._heard({**asking, "request_id": "r2"})
            deadline = time.monotonic() + PATIENCE
            while not chat._asker.asking and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertEqual((said, chat._asked.pending), ([], 2))
            # One question at a time, each answered by a line
            self.assertTrue(chat._asker.take("y"))
            while len(said) < 1 or not chat._asker.asking:
                self.assertLess(time.monotonic(), deadline)
                time.sleep(0.01)
            self.assertTrue(chat._asker.take("n"))
            self.assertTrue(chat._asked.answered_within(PATIENCE))
            chat._asked.close()
        self.assertEqual(said, [("r1", "allow"), ("r2", "deny")])
        self.assertEqual(chat._asked.pending, 0)

    def test_a_line_that_is_not_the_chats_is_for_claude(self):
        ours = self.commands()
        with written() as lines:
            self.assertIs(ours.do("fix the build"), commands.Did.NOTHING)
            self.assertIs(ours.do("/model sonnet"), commands.Did.NOTHING)
            # Not /mcp, before claude has listed its servers either
            self.assertIs(ours.do("/mcp"), commands.Did.DONE)
            self.assertIn("not known before the first turn", lines_now(lines))
            self.session.servers = [("docs", "connected")]
            self.assertIs(ours.do("/mcp"), commands.Did.DONE)
            self.assertIs(ours.do("/help"), commands.Did.DONE)
            self.assertIs(ours.do("/quit"), commands.Did.LEFT)
        self.assertIn("#   docs  connected", lines)
        self.assertIn(
            "#   !COMMAND       run a command in the sandbox, claude is not told", lines
        )

    def test_the_mode_is_asked_of_claude_and_said_when_it_answers(self):
        ours = self.commands()
        with written() as lines:
            self.assertIs(ours.do("/mode"), commands.Did.DONE)
            self.assertEqual(self.requests, [])
            self.assertIs(ours.do("/mode plan"), commands.Did.DONE)
            ((asked, answered, more),) = self.requests
            self.assertEqual((asked, more), ("set_permission_mode", {"mode": "plan"}))
            answered({"subtype": "error", "error": "no such\x1b[2J mode"})
            self.assertEqual(self.session.mode, "")
            answered({"subtype": "success", "response": {"mode": "plan"}})
        self.assertEqual(self.session.mode, "plan")
        self.assertEqual(
            lines,
            [
                "# chat        /mode NAME changes it, plan for one",
                "# chat        mode not changed: no such[2J mode",
                "# chat        mode plan",
            ],
        )

    def test_what_completes_and_what_help_says_are_the_same_commands(self):
        said = "\n".join(commands.HELP)
        for local in commands.LOCALS:
            for name in local.names:
                self.assertIs(commands.BY_NAME[name], local)
            if local.typed:
                self.assertIn(f"  {local.typed}", said)
        self.assertEqual(
            sorted(commands.LOCAL),
            ["/exit", "/help", "/mcp", "/mode", "/quit", "/resume", "/status"]
            + ["/statusline"],
        )

    def test_a_session_to_resume_is_left_for_the_launcher(self):
        self.write_transcript(SESSION, [{"type": "user", "message": {"content": "hi"}}])
        handover = commands.Handover()
        ours = self.commands(handover)
        with written() as lines:
            self.assertIs(ours.do("/resume nope"), commands.Did.DONE)
            self.assertEqual(handover.session, "")
            self.turns.begin()
            ours.do(f"/resume {SESSION[:6]}")
            self.assertIn(
                "# chat        not while a turn runs",
                lines or ["# chat        not while a turn runs"],
            )
            self.turns.end()
            self.assertIs(ours.do(f"/resume {SESSION[:6]}"), commands.Did.LEFT)
        self.assertEqual(handover.session, SESSION)
        # Nothing to leave it with: said, and not left
        with written() as lines:
            self.assertIs(self.commands().do("/resume"), commands.Did.DONE)
        self.assertEqual(lines, ["# chat        nothing here to resume a session with"])


class StatusTest(LauncherTest):
    def test_a_model_is_named_as_claude_code_names_it(self):
        self.assertEqual(status.display_name("claude-opus-5-5"), "Opus 5.5")
        self.assertEqual(
            status.display_name("claude-sonnet-4-5-20250929"), "Sonnet 4.5"
        )
        self.assertEqual(
            status.display_name("claude-opus-4-6[1m]"), "Opus 4.6 (1M context)"
        )
        self.assertEqual(status.display_name("claude-haiku-4"), "Haiku 4")
        self.assertEqual(status.display_name("something-else"), "something-else")

    def test_the_status_says_what_is_known_and_nothing_else(self):
        sandbox = status.Sandbox("claude-test")
        parts = status.status_parts(
            saying.Session(), turn.Usage(), status.Limits(), sandbox
        )
        self.assertEqual(
            status.status_line(parts, colour=False), "[claude-test] net:open"
        )
        session = saying.Session(model="claude-opus-5-5")
        usage = turn.Usage()
        limits = status.Limits()
        limits.heard({"rateLimitType": "five_hour", "utilization": 0.42, "resetsAt": 9})
        limits.heard({"rateLimitType": "seven_day", "utilization": 0.95})
        limits.heard({"rateLimitType": "overage", "utilization": 0.1})
        usage.step({"message": {"usage": {"input_tokens": 50_000}}})
        usage.parts(
            {"total_cost_usd": 0.5, "modelUsage": {"m": {"contextWindow": 200_000}}},
            "m",
        )
        parts = status.status_parts(session, usage, limits, sandbox)
        reset = f"{datetime.fromtimestamp(9):%H:%M}"
        self.assertEqual(
            status.status_line(parts, colour=False),
            f"Opus 5.5 ctx:25% 5h:42% used {reset} 7d:95% used $0.50"
            " [claude-test] net:open",
        )
        # A limit nearly used up stands out in red
        self.assertIn(("31", "7d:95% used"), parts)

    def test_the_mode_is_said_when_it_changed_and_of_plan_always(self):
        sandbox = status.Sandbox("claude-test")

        def shown(session: saying.Session) -> str:
            parts = status.status_parts(session, turn.Usage(), status.Limits(), sandbox)
            return status.status_line(parts, colour=False)

        session = saying.Session()
        session.heard({"subtype": "init", "permissionMode": "bypassPermissions"})
        self.assertNotIn("mode:", shown(session))
        session.heard({"subtype": "status", "permissionMode": "acceptEdits\x1b[2J"})
        self.assertIn(" mode:acceptEdits[2J ", " " + shown(session))
        session.heard({"subtype": "status", "permissionMode": "bypassPermissions"})
        self.assertNotIn("mode:", shown(session))
        # The one a prompt is not acted on in, started with or not
        planning = saying.Session()
        planning.heard({"subtype": "init", "permissionMode": "plan"})
        self.assertIn("mode:plan", shown(planning))

    def test_the_sandbox_is_shown_as_the_session_was_started(self):
        settings = Settings(
            net_filter=True,
            ssh_agent=True,
            docker_socket=SocketAccess.FULL,
            shared_history=True,
        )
        dirs = [
            ExtraDir(str(self.home / "shared")),
            ExtraDir("/srv/data", read_only=True),
        ]
        with unittest.mock.patch.object(started, "has_socket_proxy", return_value=True):
            start = started.Start.of(settings, DOCKERS_OWN, "", dirs, ssh_agent=True)
        sandbox = status.Sandbox.started("claude-x", start, str(self.home))
        self.assertEqual(
            [text for _, text in sandbox.parts()],
            [
                "[claude-x]",
                "net:filtered",
                "ssh-agent",
                "docker:full",
                "history:all",
                "dirs: ~/shared /srv/data (ro)",
            ],
        )
        # Asked for, but the host has no Docker socket: no door
        with unittest.mock.patch.object(
            started, "has_socket_proxy", return_value=False
        ):
            start = started.Start.of(settings, DOCKERS_OWN, "", [], ssh_agent=False)
        sandbox = status.Sandbox.started("claude-x", start, str(self.home))
        self.assertEqual(sandbox.open, ("history:all",))

    def test_it_heads_the_prompt_and_is_said_when_asked_for(self):
        shown = page()
        session, usage = saying.Session(), turn.Usage()
        line = status.StatusLine(shown, status.Sandbox("claude-test"), session, usage)
        with written() as lines:
            self.assertEqual(line.refresh(), "[claude-test] net:open")
            self.assertEqual(shown._console._head, ["[claude-test] net:open"])
            session.replied({"message": {"model": "claude-opus-5-5"}})
            line.show()
            self.assertEqual(shown._console._head, ["Opus 5.5 [claude-test] net:open"])
        self.assertEqual(lines, ["# status      Opus 5.5 [claude-test] net:open"])

    def test_the_limits_are_read_where_claude_now_says_them(self):
        # All the windows by name, the figures no longer beside the type
        limits = status.Limits()
        limits.heard(
            {
                "status": "allowed",
                "rateLimitType": "five_hour",
                "resetsAt": 9,
                "unifiedWindows": {
                    "five_hour": {"utilization": 0.24, "resetsAt": 9},
                    "seven_day": {"utilization": 0.22, "resetsAt": 99},
                    "overage": {"utilization": 0.5},
                    "opus": "not a window",
                },
            }
        )
        parts = status.status_parts(
            saying.Session(), turn.Usage(), limits, status.Sandbox("claude-test")
        )
        reset = f"{datetime.fromtimestamp(9):%H:%M}"
        self.assertEqual(
            status.status_line(parts, colour=False),
            f"5h:24% used {reset} 7d:22% used [claude-test] net:open",
        )
        self.assertEqual(set(limits.windows), {"five_hour", "seven_day"})
        # Not a set of windows: what is beside the type still counts
        limits.heard({"rateLimitType": "seven_day", "unifiedWindows": [1]})
        limits.heard({"rateLimitType": "seven_day", "utilization": 0.5})
        self.assertEqual(limits.windows["seven_day"]["used_percentage"], 50.0)

    def test_a_field_that_is_missed_is_said_once_with_the_shape_of_its_message(self):
        seen = drift.Drift()
        message = {"type": "result", "subtype": "success", "session_id": "secret"}
        message.update(usage={"output_tokens": 5}, model=7)
        self.assertEqual(seen.field(message, "usage", dict), {"output_tokens": 5})
        self.assertIsNone(seen.told(message, {"result"}))
        self.assertIsNone(seen.field(message, "modelUsage", dict))
        # There, and not of its kind
        self.assertIsNone(seen.field(message, "model", str))
        self.assertIsNone(seen.field("no message", "model", str))
        change = seen.told(message, {"result"}, "2.1.0")
        self.assertEqual(
            change.differs,
            ("no modelUsage in result success", "no model in result success"),
        )
        self.assertIn(
            "CHANGED in what Claude Code 2.1.0 says: no modelUsage", change.said
        )
        # Its fields and their kinds, none of what they hold
        self.assertIn("usage: {output_tokens: int}", change.shape)
        self.assertNotIn("secret", change.said)
        # Not said again, and what was missed of one message is not said
        # of the next
        seen.field(message, "modelUsage", dict)
        self.assertIsNone(seen.told(message, {"result"}))
        self.assertIsNone(seen.told({"type": "keep_alive"}, {"keep_alive"}))
        # What nobody asks about does not pile up
        for number in range(1000):
            seen.missed(f"field{number}")
        self.assertEqual(len(seen._missed), drift.MOST_MISSED)

    def test_a_message_of_no_known_kind_is_said_at_no_great_length(self):
        seen = drift.Drift()
        for message, what in (
            ({"type": "new_thing", "text": "x\x1b[2J"}, "does not know, new_thing"),
            ({"text": "x"}, "a message without a type"),
        ):
            said = seen.told(message, {"result"}).said
            self.assertIn(what, said)
            self.assertNotIn("\x1b", said)
        # A type that is no name is none, and not looked up as one
        change = drift.Drift().told({"type": ["x"]}, {"result"})
        self.assertEqual(change.differs, ("a message without a type",))
        # Its version as the message says it, cleaned
        init = {"type": "system", "subtype": "init", "claude_code_version": "2\x1b[2J"}
        seen.missed("model")
        said = seen.told(init, {"system"}, "1.0").said
        self.assertIn("Claude Code 2[2J says: no model in system init", said)
        self.assertNotIn("\x1b", said)
        said = seen.told({"type": "t" * 5000, "subtype": "s"}, ()).said
        self.assertLess(len(said), 400)
        deep = {"type": "odd", "a": {"b": {"c": {"d": 1}}}}
        deep.update({f"field{n}": n for n in range(200)})
        said = seen.told(deep, ()).said
        self.assertIn("a: {b: {c: dict}}", said)
        self.assertLess(len(said), 700)
        # Nor are changes without end
        many = [seen.told({"type": f"kind{n}"}, ()) for n in range(100)]
        self.assertLess(len(list(filter(None, many))), drift.MOST_SAID)
        self.assertEqual(len(seen._said), drift.MOST_SAID)
        self.assertIsNone(seen.told({"type": "one_more"}, ()))

    def test_no_limit_claude_tells_of_stops_the_status(self):
        limits = status.Limits()
        limits.heard({"rateLimitType": [], "utilization": 0.5})
        limits.heard({"rateLimitType": {"a": 1}})
        self.assertEqual(limits.windows, {})
        # A time no date can be made of
        limits.heard(
            {"rateLimitType": "five_hour", "utilization": 0.4, "resetsAt": 9e11}
        )
        parts = status.status_parts(
            saying.Session(), turn.Usage(), limits, status.Sandbox("claude-test")
        )
        self.assertIn("5h:40% used", status.status_line(parts, colour=False))

    def test_the_model_chosen_with_model_is_shown_before_it_replies(self):
        session = saying.Session(model="claude-fable-5-2", chosen="Opus 5.5")
        parts = status.status_parts(
            session, turn.Usage(), status.Limits(), status.Sandbox("claude-test")
        )
        self.assertEqual(parts[0], (status.BOLD, "Opus 5.5"))


class ConsoleTest(LauncherTest):
    def test_the_end_of_a_turn_is_said_in_bright_green_in_colour(self):
        self.assertEqual(talk.ready_line(False), f"# {talk.READY}")
        self.assertEqual(talk.ready_line(True), f"\x1b[1;92m# {talk.READY}\x1b[0m")

    def test_a_turn_that_ends_with_tasks_still_running_says_so(self):
        one, two = talk.ready_line(False, 1), talk.ready_line(False, 2)
        self.assertIn("claude has paused, 1 task still runs", one)
        self.assertIn("claude has paused, 2 tasks still run", two)
        self.assertNotIn("has finished", one)
        self.assertTrue(one.startswith("# ready "))

    def test_a_word_is_completed_to_a_command_or_a_file_of_the_project(self):
        (self.project / "src").mkdir()
        (self.project / "src" / "main.py").touch()
        (self.project / "setup.py").touch()
        root, names = str(self.project), ["/mode", "/model", "/mcp"]

        def offered(word: str, first: bool = True) -> list[str]:
            return console.completions(word, first, names, root)

        self.assertEqual(offered("/mo"), ["/mode", "/model"])
        # A command starts the line
        self.assertEqual(offered("/mo", first=False), [])
        self.assertEqual(offered("@s"), ["@setup.py", "@src/"])
        self.assertEqual(offered("@src/"), ["@src/main.py"])
        # Not the hidden ones unless asked for, and nothing out of the project
        self.assertNotIn("@.env", offered("@"))
        self.assertIn("@.env", offered("@.e"))
        self.assertEqual(offered("@../"), [])
        self.assertEqual(offered("@/etc/pas"), [])
        self.assertEqual(offered("plain"), [])

    def test_what_is_written_while_a_line_is_read_goes_before_the_prompt(self):
        screen = console.Console(str(self.project))
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            screen.write(["one"])
            # As if a line were being read, in a pipe nothing is erased
            screen._reading, screen._on_screen = "> ", True
            screen.write(["two"])
            screen.ask("allow? ")
            self.assertEqual(screen.typed(), "")
        self.assertEqual(out.getvalue(), "one\n\ntwo\n> \nallow? ")

    def test_the_head_is_above_the_prompt_and_written_again_when_it_changes(self):
        screen = console.Console(str(self.project))
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            screen.set_head(["model x"])
            # As _line would, in a pipe: the head with the prompt
            screen._headed, screen._reading, screen._shown = True, "> ", "model x\n"
            screen._on_screen = True
            screen.write(["one"])
            screen.set_head(["model y", "ctx 3%"])
            screen.write(["two"])
            # Not above a question
            screen.ask("allow? ")
        self.assertEqual(
            out.getvalue(),
            "\none\n> \nmodel y\nctx 3%\n> \ntwo\n> \nallow? ",
        )

    def test_a_line_without_a_head_has_none_above_its_prompt(self):
        screen = console.Console(str(self.project))
        screen.set_head(["model x"])
        self.assertEqual(screen._above(), "")
        screen._headed = True
        self.assertEqual(screen._above(), "model x\n")
        screen._asked = "allow? "
        self.assertEqual(screen._above(), "")

    def test_the_head_is_erased_with_the_line_being_typed(self):
        # Its colours take no column
        self.assertEqual(
            screens.erased("\x1b[2mmodel\x1b[0m\n> ", "abc", 10), "\x1b[1A\r\x1b[J"
        )
        # A line of it as wide as the terminal takes one row, a wider two
        self.assertEqual(screens.erased("x" * 10 + "\n> ", "", 10), "\x1b[1A\r\x1b[J")
        self.assertEqual(screens.erased("x" * 11 + "\n> ", "", 10), "\x1b[2A\r\x1b[J")

    def test_the_line_being_typed_is_erased_by_the_rows_it_takes(self):
        self.assertEqual(screens.erased("> ", "abc", 10), "\r\x1b[J")
        self.assertEqual(screens.erased("> ", "x" * 25, 10), "\x1b[2A\r\x1b[J")
        # A wide character takes two columns, what is put on one none
        self.assertEqual(screens.erased("> ", "\u4e2d" * 5, 10), "\x1b[1A\r\x1b[J")
        self.assertEqual(screens.erased("> ", "e\u0301" * 7, 10), "\r\x1b[J")
        # What was pasted with its line breaks, each line its own rows
        self.assertEqual(
            screens.erased("> ", "one\n" + "x" * 12, 10), "\x1b[2A\r\x1b[J"
        )
        # A terminal that says it has no column is taken to have one
        self.assertEqual(screens.erased("> ", "", 0), "\x1b[2A\r\x1b[J")

    def test_a_line_is_written_again_with_the_cursor_where_it_was(self):
        out = io.StringIO()
        screen = console.Console(str(self.project), out=out, columns=lambda: 10)
        screen._redrawn, screen._reading, screen._shown = True, "> ", "> "
        typed = "x" * 12
        with (
            unittest.mock.patch.object(console.readline, "get_line_buffer") as buffer,
            unittest.mock.patch.object(console, "_point", lambda: 3),
        ):
            buffer.return_value = typed
            # The cursor is on the first of its two rows: nothing above
            # it is erased, and it is put back after the third character
            screen.write(["one"])
        self.assertEqual(out.getvalue(), "\r\x1b[Jone\n> " + typed + "\x1b[1A\r\x1b[5C")
        back = screens.cursor_back
        # At its end it is where it was written to, on the next row
        # when that was to the edge
        self.assertEqual(back("> ", "abc", "abc", 10), "")
        self.assertEqual(back("head\n> ", "x" * 8, "x" * 8, 10), " \r")
        self.assertEqual(back("> ", "one\ntwo", "on", 10), "\x1b[1A\r\x1b[4C")

    def test_an_entered_line_is_written_again_in_its_style(self):
        out = io.StringIO()
        screen = console.Console(
            str(self.project), sent="1;7", out=out, columns=lambda: 10
        )
        screen._redrawn, screen._reading = True, "> "
        screen._entered("hi")
        # A line as wide as the terminal took a row more
        screen._entered("x" * 8)
        screen._entered("  ")
        self.assertEqual(
            out.getvalue(),
            "\x1b[1A\r\x1b[J\x1b[1;7m> hi\x1b[0m\n"
            "\x1b[1A\x1b[1A\r\x1b[J\x1b[1;7m> xxxxxxxx\x1b[0m\n",
        )

    def test_an_entered_line_leaves_no_working_line_above_it(self):
        out = io.StringIO()
        screen = console.Console(str(self.project), out=out, columns=lambda: 40)
        screen._redrawn, screen._reading, screen._headed = True, "> ", True
        screen._head, screen._working = ["model x"], "# working 5s"
        screen._shown = screen._above() + "> "
        screen._entered("hi")
        self.assertEqual(out.getvalue(), "\x1b[1A\x1b[2A\r\x1b[Jmodel x\n> hi\n")

    def test_an_entered_line_is_left_as_typed_without_a_style(self):
        screen = console.Console(str(self.project))
        screen._redrawn, screen._reading = True, "> "
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            screen._entered("hi")
        self.assertEqual(out.getvalue(), "")

    def test_a_reply_is_headed_in_its_style_and_a_reason_in_italics(self):
        layout = Layout(
            colour=True,
            compact=True,
            styles={"reply": "", "bash": "33"},
            heads={"reply": "1;96"},
            labels={"why": "3"},
        )
        said = Event(0, Who.CLAUDE, "reply", [""], {})
        head = layout.event(said)[-1]
        self.assertTrue(head.endswith("\x1b[1;96mclaude   reply\x1b[0m"))
        ran = Event(0, Who.CLAUDE, "bash", ["$ make", "why: Build it"], {})
        command, reason = layout.event(ran)
        self.assertTrue(command.endswith("\x1b[33mclaude   bash        $ make\x1b[0m"))
        self.assertEqual(
            reason,
            " " * 10
            + "\x1b[33m"
            + " " * 21
            + "\x1b[0m\x1b[33;1mwhy:\x1b[0m\x1b[33;3m Build it\x1b[0m",
        )


if __name__ == "__main__":
    unittest.main()
