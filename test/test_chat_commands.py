#!/usr/bin/env python3
"""--line-mode: the commands of the chat, and those of the user run in
the session."""

from __future__ import annotations

import signal
import subprocess
import sys
import threading
import time
import unittest.mock
from collections.abc import Iterator

import pytest
from chat_harness import (
    PATIENCE,
    SESSION,
    RecordedClaude,
    WaitingHosts,
    a_chat,
    before_the_user,
    lines_now,
    page,
    written,
)
from harness import LauncherTest, reads_proc

from claude_airlock.chat import asking, commands, shell, talk, turn
from claude_airlock.chat import said as saying
from claude_airlock.events import labelled
from claude_airlock.sandbox.asked_hosts import Destination


class AnsweredClaude:
    """What stands for claude where it is given answers to what it asked,
    and keeps each: the id it asked under, and what it was told."""

    def __init__(self) -> None:
        self.said: list[tuple[object, str]] = []

    def respond(self, asked: object, decision: dict) -> None:
        self.said.append((asked, decision["behavior"]))

    def refuse(self, asked: object, _why: str) -> None:
        self.said.append((asked, "refused"))


# What claude asks to be allowed a call
ASKS = {"subtype": "can_use_tool", "tool_name": "Bash", "input": {}}


class CommandsTest(LauncherTest):
    def commands(
        self,
        handover: commands.Handover | None = None,
        status=lambda: None,
        changed=lambda: None,
    ) -> commands.Commands:
        shown = page()
        self.session, self.turns = saying.Session(), turn.Turns()
        self.shell = shell.Shell(shown, "claude-test")
        # What claude was asked for, each with what is told its answer
        self.requests: list[tuple] = []
        resume = commands.Resume(shown, self.host, self.turns, lambda _: "1", handover)
        return commands.Commands(
            shown,
            self.session,
            lambda *asked, **more: self.requests.append((*asked, more)),
            self.shell.run,
            resume.resume,
            status,
            changed,
        )

    def test_status_and_statusline_say_what_the_statusline_writes(self):
        asked: list[str] = []
        ours = self.commands(status=lambda: asked.append("status"))
        for line in ("/status", "/statusline"):
            assert ours.do(line) is commands.Did.DONE
        assert asked == ["status", "status"]

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
            assert ours.do("!make test") is commands.Did.DONE
        assert lines[1:3] == ["one[2J", "two"]
        assert "ended with 3" in lines[3]
        # Ctrl-C is for the command while it runs, and only then
        assert seen == [True]
        assert not self.shell.running

    def test_ctrl_c_while_a_command_of_the_users_starts_ends_it(self):
        # It comes before there is a process to end: not lost, the
        # command is ended once there is one
        ours = self.commands()
        ran = [sys.executable, "-c", "import time; time.sleep(60)"]

        def run(*_args: str, **options):
            self.shell.interrupt()
            return subprocess.Popen(ran, **options)

        started = time.monotonic()
        with (
            unittest.mock.patch.object(shell, "docker_popen", run),
            written() as lines,
        ):
            assert ours.do("!sleep 60") is commands.Did.DONE
        assert time.monotonic() - started < 30
        assert "interrupted" in lines[-1]

    # And runs setsid, which macOS does not have
    @reads_proc
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
            assert args[:2] == ("exec", "claude-test")
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
            assert ours.do("!echo up; sleep 60") is commands.Did.DONE
        assert time.monotonic() - started < 30
        # Its group is not shown, what it wrote is
        assert lines[1] == "up"
        assert "interrupted" in lines[-1]
        assert "may still be running" not in lines[-1]
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
            pytest.fail("what the command ran was left running")

    def test_a_command_of_the_users_is_not_waited_for_while_they_are_asked(self):
        # What the command waits for is the answer: a request of its
        # for a host the egress filter does not allow
        answer = self.work / "answer"
        waits = (
            "import os, sys, time\n"
            "print('asking', flush=True)\n"
            "patience = time.monotonic() + 20\n"
            "while not os.path.exists(sys.argv[1]) and time.monotonic() < patience:\n"
            "    time.sleep(0.05)\n"
            "print('went on' if os.path.exists(sys.argv[1]) else 'gave up')\n"
        )

        def run(*_args: str, **options):
            return subprocess.Popen(
                [sys.executable, "-c", waits, str(answer)], **options
            )

        asked = threading.Event()
        ours = shell.Shell(page(), "claude-test", asked.is_set)
        threading.Timer(0.3, asked.set).start()
        with (
            unittest.mock.patch.object(shell, "docker_popen", run),
            written() as lines,
        ):
            ours.run("curl https://example.com")
            # Back for the line that answers, the command not over, and
            # Ctrl-C still for it. No other is run meanwhile
            assert ours.running
            ours.run("ls")
            asked.clear()
            answer.touch()
            ours.wait()
            assert not ours.running
        still = "# shell       not run: a command of yours still runs, Ctrl-C ends it"
        assert lines[1:] == ["asking", still, "went on"]

    def test_ctrl_c_is_for_a_command_of_the_users_while_it_runs(self):
        chat = a_chat(self.host)
        chat._turns.begin()
        chat._shell.running = True
        chat._on_interrupt(signal.SIGINT, None)
        assert not chat._interrupt
        chat._shell.running = False
        chat._on_interrupt(signal.SIGINT, None)
        assert chat._interrupt
        # A line is read while a command runs when the user is asked
        # something: once claude has ended the wait for it is ended, the
        # end is told as Ctrl-C is
        ended = a_chat(self.host)
        ended._shell.running = ended._reading = True
        ended._becomes(talk.Life.ended)
        ended._on_interrupt(signal.SIGINT, None)
        assert ended._console._interrupted
        assert not ended._shell._interrupted

    def test_claude_is_listened_to_while_a_question_waits(self):
        chat = a_chat(self.host)
        claude = AnsweredClaude()
        said = claude.said
        asking = {"type": "control_request", "request_id": "r1", "request": ASKS}
        with written():
            chat._asked.start(claude)
            # Whoever listens is not kept by the question
            chat._heard(asking)
            chat._heard({**asking, "request_id": "r2"})
            deadline = time.monotonic() + PATIENCE
            while not chat._asker.asking and time.monotonic() < deadline:
                time.sleep(0.01)
            assert (said, chat._asked._count) == ([], 2)
            # One question at a time, each answered by a line
            before_the_user(chat._asker)
            assert chat._asker.take("y")
            while len(said) < 1 or not chat._asker.asking:
                assert time.monotonic() < deadline
                time.sleep(0.01)
            # Not by one entered before it was on the screen
            assert not chat._asker.take("y")
            before_the_user(chat._asker)
            assert chat._asker.take("n")
            assert chat._asked.answered_within(PATIENCE)
            chat._asked.close()
        assert said == [("r1", "allow"), ("r2", "deny")]
        assert chat._asked._count == 0

    def test_what_waits_to_be_asked_is_refused_with_an_interrupted_turn(self):
        chat = a_chat(self.host)
        claude = AnsweredClaude()
        said = claude.said
        asking = {"type": "control_request", "request_id": "r1", "request": ASKS}
        with written() as lines:
            chat._asked.start(claude)
            chat._heard(asking)
            chat._heard({**asking, "request_id": "r2"})
            deadline = time.monotonic() + PATIENCE
            while not chat._asker.asking and time.monotonic() < deadline:
                time.sleep(0.01)
            # The one on the screen and the one behind it, neither put again
            chat._asker.give_up()
            assert chat._asked.answered_within(PATIENCE)
            assert not chat._asker.asking
            # What is asked after it is put as before
            chat._heard({**asking, "request_id": "r3"})
            while not chat._asker.asking:
                assert time.monotonic() < deadline
                time.sleep(0.01)
            before_the_user(chat._asker)
            assert chat._asker.take("y")
            assert chat._asked.answered_within(PATIENCE)
            chat._asked.close()
        assert said == [("r1", "deny"), ("r2", "deny"), ("r3", "allow")]
        assert "".join(lines).count("not asked again in this session") == 2

    def test_what_claude_withdraws_is_neither_put_nor_answered(self):
        chat = a_chat(self.host)
        claude = AnsweredClaude()
        said = claude.said
        asks = {"type": "control_request", "request_id": "r1", "request": ASKS}
        withdrawn = {"type": "control_cancel_request", "request_id": "r1"}
        with written() as lines:
            chat._asked.start(claude)
            chat._heard(asks)
            chat._heard({**asks, "request_id": "r2"})
            chat._heard({**asks, "request_id": "r3"})
            self.asked(chat)
            first = chat._asker._question
            # The one waiting for its turn is never put, the one on the
            # screen is put no longer
            chat._heard({**withdrawn, "request_id": "r2"})
            chat._heard(withdrawn)
            deadline = time.monotonic() + PATIENCE
            while chat._asker._question in (None, first):
                assert time.monotonic() < deadline
                time.sleep(0.01)
            assert list(chat._asked._unanswered) == ["r3"]
            # The one after them is put as before
            before_the_user(chat._asker)
            assert chat._asker.take("y")
            assert chat._asked.answered_within(PATIENCE)
            # Nothing of what claude did not ask, or asks no longer
            chat._heard(withdrawn)
            chat._heard({**withdrawn, "request_id": ["not", "an", "id"]})
            chat._asked.close()
        assert said == [("r3", "allow")]
        assert "".join(lines).count(asking.WITHDRAWN) == 1
        # A message the chat knows
        assert not any("CHANGED" in line for line in lines)

    def test_what_claude_asks_is_put_when_what_it_did_cannot_be_shown(self):
        # Claude waits for an answer, and its turn with it
        chat = a_chat(self.host)
        claude = AnsweredClaude()
        asks = {"type": "control_request", "request_id": "r1", "request": ASKS}
        unshown = unittest.mock.patch.object(
            chat._followed, "settle", side_effect=OSError("no records")
        )
        with written(), unshown:
            chat._asked.start(claude)
            with pytest.raises(OSError, match="no records"):
                chat._heard(asks)
            self.asked(chat)
            before_the_user(chat._asker)
            assert chat._asker.take("y")
            assert chat._asked.answered_within(PATIENCE)
            chat._asked.close()
        assert claude.said == [("r1", "allow")]

    def typing(self, chat: talk.Chat, typed: Iterator[str | None]) -> list[str]:
        """Have a chat read the lines someone types, each when the one
        before is done with, and do what they ask. What it wrote."""
        chat._read = lambda prompt, headed=False: next(typed)  # type: ignore[method-assign]
        with written() as lines:
            chat._converse()
        return lines

    def asked(self, chat: talk.Chat) -> None:
        """Wait for a chat to ask its user something."""
        deadline = time.monotonic() + PATIENCE
        while not chat._asker.asking:
            assert time.monotonic() < deadline
            time.sleep(0.01)

    def test_a_line_that_was_no_answer_is_not_sent_to_claude(self):
        claude, answered = RecordedClaude(), AnsweredClaude()
        chat = a_chat(self.host, claude, typed=True)
        asks = {"type": "control_request", "request_id": "r1", "request": ASKS}

        def typed() -> Iterator[str | None]:
            # A yes entered before the question was on the screen, then
            # as it came, sooner than it could be read
            yield "y"
            before_the_user(chat._asker)
            yield "y"
            assert (claude.prompts, answered.said) == ([], [])
            assert chat._asker.asking
            # And one entered as the question is given up on, a turn
            # was stopped for what claude read
            chat._asker.give_up()
            assert chat._asked.answered_within(PATIENCE)
            yield "y"
            assert claude.prompts == []
            # The line after it is a prompt as any other
            yield "go on"
            yield None

        with written():
            chat._asked.start(answered)
            chat._heard(asks)
            self.asked(chat)
        lines = self.typing(chat, typed())
        chat._asked.close()
        assert claude.prompts == ["go on"]
        assert answered.said == [("r1", "deny")]
        said = [line for line in lines if "that line" in line]
        early, late = (
            f"# {labelled('chat', why)}" for why in (asking.EARLY, asking.LATE)
        )
        assert said == [early, early, late]

    def test_ctrl_c_at_a_question_leaves_it_without_an_answer(self):
        com, org = Destination("example.com", 443), Destination("example.org", 22)
        hosts = WaitingHosts(com, org)
        chat = a_chat(self.host, RecordedClaude(), hosts=hosts, typed=True)

        def typed() -> Iterator[str | None]:
            # Ctrl-C at the question, no turn runs: the request that
            # waits is refused, and the next one is asked about
            raised = KeyboardInterrupt()
            yield raised  # type: ignore[misc]
            deadline = time.monotonic() + PATIENCE
            while not hosts.answers or not chat._asker.asking:
                assert time.monotonic() < deadline
                time.sleep(0.01)
            yield None

        def read(_prompt: str, headed: bool = False) -> str | None:
            line = next(lines_typed)
            if isinstance(line, KeyboardInterrupt):
                raise line
            return line

        lines_typed = typed()
        with written() as lines:
            chat._asked.start(AnsweredClaude())
            chat._hosts.look()
            self.asked(chat)
            chat._read = read
            chat._converse()
            chat._asker.give_up()
            assert chat._asked.answered_within(PATIENCE)
            chat._asked.close()
        assert hosts.answers == [(com, None), (org, None)]
        refused = (
            "# net         not answered: the request for example.com on port 443"
            " (https) is refused"
        )
        assert refused in lines
        assert "# chat        Ctrl-C again leaves" in lines

    def test_a_host_is_not_let_through_by_a_line_entered_before_it_is_asked_about(
        self,
    ):
        hosts = WaitingHosts(Destination("example.com", 443))
        chat = a_chat(self.host, RecordedClaude(), hosts=hosts, typed=True)
        with written() as lines:
            chat._asked.start(AnsweredClaude())
            chat._hosts.look()
            self.asked(chat)
            # As the question came, typed before it could be read
            before_the_user(chat._asker)
            assert chat._asker.take("y")
            assert (hosts.answers, chat._asker.asking) == ([], True)
            with unittest.mock.patch.object(asking, "TOO_SOON", 0.0):
                assert chat._asker.take("y")
            assert chat._asked.answered_within(PATIENCE)
            chat._asked.close()
        assert hosts.answers == [(Destination("example.com", 443), True)]
        assert f"# {labelled('chat', asking.EARLY)}" in lines

    def test_a_line_that_is_not_the_chats_is_for_claude(self):
        ours = self.commands()
        with written() as lines:
            assert ours.do("fix the build") is commands.Did.NOTHING
            assert ours.do("/model sonnet") is commands.Did.NOTHING
            # Not /mcp, before claude has listed its servers either
            assert ours.do("/mcp") is commands.Did.DONE
            assert "not known before the first turn" in lines_now(lines)
            self.session.servers = [("docs", "connected")]
            assert ours.do("/mcp") is commands.Did.DONE
            assert ours.do("/help") is commands.Did.DONE
            assert ours.do("/quit") is commands.Did.LEFT
        assert "#   docs  connected" in lines
        assert (
            "#   !COMMAND       run a command in the sandbox, claude is not told"
            in lines
        )

    def test_a_login_is_not_asked_of_claude_which_has_none_over_the_pipe(self):
        ours = self.commands()
        for line in ("/login", "/logout"):
            with written() as lines:
                assert ours.do(line) is commands.Did.DONE
            assert (
                lines[0]
                == "# chat        line mode cannot log in or out, do it one of two ways:"
            )
            assert "CLAUDE_AIRLOCK_LINE_MODE=0 claude-airlock" in lines[2]
        assert self.requests == []

    def test_the_mode_is_asked_of_claude_and_said_when_it_answers(self):
        # What was written by the time the status is told to have changed
        told: list[str] = []
        ours = self.commands(changed=lambda: told.append(sys.stdout.getvalue()))
        with written() as lines:
            assert ours.do("/mode") is commands.Did.DONE
            assert self.requests == []
            assert ours.do("/mode plan") is commands.Did.DONE
            ((asked, answered, more),) = self.requests
            assert (asked, more) == ("set_permission_mode", {"mode": "plan"})
            answered({"subtype": "error", "error": "no such\x1b[2J mode"})
            assert self.session.mode == ""
            assert told == []
            answered({"subtype": "success", "response": {"mode": "plan"}})
        assert self.session.mode == "plan"
        assert lines == [
            "# chat        /mode NAME changes it, plan for one",
            "# chat        mode not changed: no such[2J mode",
            "# chat        mode plan",
        ]
        # Once, before the line that says so: the status is under it
        assert len(told) == 1
        assert "mode not changed" in told[0]
        assert "mode plan" not in told[0]

    def test_what_completes_and_what_help_says_are_the_same_commands(self):
        said = "\n".join(commands.HELP)
        for local in commands.LOCALS:
            for name in local.names:
                assert commands.BY_NAME[name] is local
            if local.typed:
                assert f"  {local.typed}" in said
        assert sorted(commands.LOCAL) == [
            "/exit",
            "/help",
            "/login",
            "/logout",
            "/mcp",
            "/mode",
            "/quit",
        ] + ["/resume", "/status", "/statusline"]

    def test_a_session_to_resume_is_left_for_the_launcher(self):
        self.write_transcript(SESSION, [{"type": "user", "message": {"content": "hi"}}])
        handover = commands.Handover()
        ours = self.commands(handover)
        with written() as lines:
            assert ours.do("/resume nope") is commands.Did.DONE
            assert handover.session == ""
            self.turns.begin()
            ours.do(f"/resume {SESSION[:6]}")
            assert "# chat        not while a turn runs" in (
                lines or ["# chat        not while a turn runs"]
            )
            self.turns.end()
            assert ours.do(f"/resume {SESSION[:6]}") is commands.Did.LEFT
        assert handover.session == SESSION
        # Nothing to leave it with: said, and not left
        with written() as lines:
            assert self.commands().do("/resume") is commands.Did.DONE
        assert lines == ["# chat        nothing here to resume a session with"]

    def test_a_question_put_while_a_session_is_picked_is_answered_first(self):
        # A subagent of claude's asks while no turn runs: its question has
        # the place of the one for a number until it is answered
        self.write_transcript(SESSION, [{"type": "user", "message": {"content": "hi"}}])
        chat = a_chat(self.host)
        claude = AnsweredClaude()
        asks = {"type": "control_request", "request_id": "r1", "request": ASKS}
        handover = commands.Handover()
        picks = commands.Resume(
            chat._page, self.host, chat._turns, chat._read_line, handover
        )
        typed = iter(["y", "1"])

        def interrupted(_prompt: object, headed: bool = False) -> str:
            raise KeyboardInterrupt

        with written():
            chat._asked.start(claude)
            chat._heard(asks)
            self.asked(chat)
            before_the_user(chat._asker)
            chat._read = lambda prompt, headed=False: next(typed)
            assert picks.resume([])
            assert chat._asked.answered_within(PATIENCE)
            # Ctrl-C at it leaves the question without an answer too
            chat._heard({**asks, "request_id": "r2"})
            self.asked(chat)
            chat._read = interrupted
            assert not picks.resume([])
            assert chat._asked.answered_within(PATIENCE)
            chat._asked.close()
        assert handover.session == SESSION
        assert claude.said == [("r1", "allow"), ("r2", "deny")]
