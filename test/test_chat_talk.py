#!/usr/bin/env python3
"""--line-mode: a chat made in the test and not run, told what claude
says, and what it makes of the session it follows."""

from __future__ import annotations

import contextlib
import json
import queue
import re
import signal
import threading
import time
import unittest.mock
from pathlib import Path

import pytest
from chat_harness import (
    PATIENCE,
    SESSION,
    USED,
    RecordedClaude,
    WaitingHosts,
    a_chat,
    agent_started,
    got_on,
    lines_now,
    task_over,
    written,
)
from harness import LauncherTest

from claude_airlock.chat import commands, pipe, plain, talk
from claude_airlock.chat import followed as following
from claude_airlock.chat import said as saying
from claude_airlock.chat import tasks as tasking
from claude_airlock.events import Event, Who, labelled
from claude_airlock.recording.changes import change_events
from claude_airlock.report.follow import Follower, Round
from claude_airlock.settings import Host


class TalkTest(LauncherTest):
    def test_the_status_follows_what_claude_says_while_a_turn_runs(self):
        chat = a_chat(self.host)
        with written():
            chat._status.refresh()
            assert chat._console._head == ["[claude-test] net:open"]
            # Between the start of a turn and its end: the mode claude
            # goes into, the model that replied, a limit of the account
            chat._heard(
                {"type": "system", "subtype": "status", "permissionMode": "plan"}
            )
            chat._heard({"type": "assistant", "message": {"model": "claude-fable-5-2"}})
            limit = {"rateLimitType": "seven_day", "utilization": 0.95}
            chat._heard({"type": "rate_limit_event", "rate_limit_info": limit})
            # Made again with each look at what the session did
            chat._look()
        assert chat._console._head == [
            "[claude-test] net:open  Fable 5.2 mode:plan  7d:95% used"
        ]

    def test_a_prompt_waits_once_for_what_the_chat_asked_of_claude(self):
        claude = RecordedClaude()
        chat = a_chat(self.host, claude, typed=True)
        claude.pending = True

        def waited() -> float:
            began = time.monotonic()
            chat._wait_for_answer()
            return time.monotonic() - began

        with written(), unittest.mock.patch.object(talk, "ANSWER_WAIT", 0.5):
            # Nothing was asked for by a line: what waits is not waited for
            assert waited() < 0.2
            assert chat._commands.do("/mode plan") is commands.Did.DONE
            assert claude.asked == ["set_permission_mode"]
            # A moment, for the answer to be above the prompt. No longer,
            # and once: a claude that does not answer holds up no
            # prompt after the first
            assert waited() > 0.4
            assert waited() < 0.2
            # Not where lines are all there, which wait for the turn,
            # nor once the answer came
            chat._commands.do("/mode plan")
            chat._console.interactive = False
            assert waited() < 0.2
            chat._console.interactive = True
            claude.pending = False
            assert waited() < 0.2

    def test_a_chat_counts_the_subagents_and_says_how_far_they_are(self):
        chat = a_chat(self.host)
        heard = (
            agent_started("a1", "Map the code"),
            agent_started("a2", "Read the docs"),
            got_on("a1", 2, 1500, "Reading main.py"),
        )
        with written() as lines:
            for said in heard:
                chat._heard(said)
            chat._look()
            assert chat._status.refresh() == ["[claude-test] net:open  agents:2"]
            # Where lines stay, how far they are is said after a while.
            # Not into a reply of claude's that is being written
            assert chat._progress.since is not None
            chat._progress.since -= tasking.SAID_EVERY
            writing = {"type": "content_block_start", "content_block": {"type": "text"}}
            chat._heard({"type": "stream_event", "event": writing})
            chat._look()
            assert "# agents " not in lines_now(lines)
            chat._heard(
                {"type": "stream_event", "event": {"type": "content_block_stop"}}
            )
            chat._look()
            assert "# agents " in lines_now(lines)
            chat._heard(task_over("a2", usage=USED))
            # A turn that ends while one still runs says so
            chat._turns.begin()
            chat._heard({"type": "result", "subtype": "success", "is_error": False})
            chat._status.show()
        used = "2 calls, 1.5k tokens"
        ended = "completed: Read the docs, 2 calls, 20.5k tokens, 3s"
        paused = "claude has paused, 1 agent still runs, it goes on when one ends"
        assert lines[:7] == [
            "# agent       started: Map the code (Explore)",
            "# agent       started: Read the docs (Explore)  2 running",
            f"# agents      2 running: {used}",
            lines[3],
            lines[4],
            f"# agent       {ended}  1 running, 1 ended",
            f"# ready       {paused}",
        ]
        assert re.fullmatch(
            rf"#   Map the code: {used}, \ds, Reading main\.py", lines[3]
        )
        assert re.fullmatch(r"#   Read the docs: \ds", lines[4])
        assert lines[9] == (
            "#   agents    1 still runs, 1 ended, claude goes on when one ends"
        )
        whole = (
            rf"#             Map the code \(Explore\): {used}, \ds, Reading main\.py"
        )
        assert re.fullmatch(whole, lines[10])

    def test_a_result_ends_only_a_turn_that_runs_and_is_claudes(self):
        chat = a_chat(self.host)
        over = {"type": "result", "subtype": "success", "is_error": False}
        chat._turns.begin()
        with written() as lines:
            # Of a subagent: the turn goes on
            chat._heard({**over, "parent_tool_use_id": "t1"})
        assert chat._turns.running
        assert lines == []
        with written() as lines:
            chat._heard(over)
        assert not chat._turns.running
        assert lines
        # Once more: no turn runs to end, nothing is said again
        with written() as lines:
            chat._heard(over)
        assert lines == []

    def test_a_chat_is_over_or_left_by_who_ended_first(self):
        life = talk.Life
        # The user leaves, then claude ends for it
        left = life.RUNNING.leave()
        assert (left.leaving, left.over, left.left) == (True, False, True)
        assert (left.ended().over, left.ended().left) == (True, True)
        # Claude ends on its own, and the chat is left after it
        ended = life.RUNNING.ended()
        assert (ended.leaving, ended.over, ended.left) == (False, True, False)
        assert (ended.leave().leaving, ended.leave().left) == (True, False)
        # Neither is undone, nor counted twice
        for last in (left.ended(), ended.leave()):
            assert last.ended() is last
            assert last.leave() is last

    def test_ctrl_c_at_the_prompt_leaves_only_right_after_another(self):
        chat = a_chat(self.host)
        # Each read, with when it is: Ctrl-C, a line, Ctrl-C twice too far
        # apart, then twice in a row
        reads = iter(
            [
                (0.0, KeyboardInterrupt),
                (1.0, "   "),
                (2.0, KeyboardInterrupt),
                (2.0 + talk.LEAVE_WITHIN + 1, KeyboardInterrupt),
                (2.0 + talk.LEAVE_WITHIN + 2, KeyboardInterrupt),
                (99.0, "never read"),
            ]
        )
        clock = [0.0]

        def read(_prompt: str, headed: bool = False) -> str:
            clock[0], line = next(reads)
            if line is KeyboardInterrupt:
                raise KeyboardInterrupt
            return line

        chat._read = read
        chat._console.interactive = True
        with (
            written() as lines,
            unittest.mock.patch.object(talk.time, "monotonic", lambda: clock[0]),
        ):
            chat._converse()
        assert sum("Ctrl-C again leaves" in line for line in lines) == 3
        assert next(reads) == (99.0, "never read")

    def test_ctrl_c_is_for_the_turn_that_runs_else_for_the_line(self):
        chat = a_chat(self.host)
        chat._reading = True
        # Raised where the line is waited for, see Console.interrupt
        chat._on_interrupt(2, None)
        with written(), pytest.raises(KeyboardInterrupt):
            chat._console.read("> ")
        chat._turns.begin()
        chat._on_interrupt(2, None)
        assert chat._interrupt

    def test_ctrl_c_is_acted_on_however_fast_the_session_writes(self):
        claude, hosts = RecordedClaude(), WaitingHosts()
        chat = a_chat(self.host, claude, hosts=hosts)
        chat._turns.begin()
        stop = threading.Event()

        def flood() -> None:
            # A process of the session that writes to the errors of the
            # first: there is no moment in which nothing is said
            while not stop.is_set():
                with contextlib.suppress(queue.Full):
                    claude.messages.put("y\n", 2, timeout=0.1)

        with written() as lines:
            flooding = threading.Thread(target=flood, daemon=True)
            listener = threading.Thread(target=chat._listen, daemon=True)
            flooding.start()
            listener.start()
            time.sleep(0.2)
            chat._on_interrupt(signal.SIGINT, None)
            # While it writes on: the turn is interrupted, and the hosts
            # that wait are looked for as often as when it is quiet
            deadline = time.monotonic() + 5.0
            while not (claude.asked and hosts.looks > 2):
                if time.monotonic() > deadline:
                    break
                time.sleep(0.01)
            asked, looks = list(claude.asked), hosts.looks
            stop.set()
            flooding.join(PATIENCE)
            claude.messages.put(None)
            listener.join(PATIENCE)
        assert asked == ["interrupt"]
        assert looks > 2
        assert "# chat        interrupting, Ctrl-C again stops the session" in lines
        # And no more of what it wrote is on the screen than can be read,
        # in the window it started in and in the one after if it got there
        assert 0 < lines.count("y") <= plain.MOST + plain.FEW
        assert 1 <= sum("left out" in line for line in lines) <= 2

    def test_a_line_of_the_session_that_could_not_be_read_is_said(self):
        claude = RecordedClaude()
        chat = a_chat(self.host, claude)
        claude.messages.put(pipe.Unread.LINE)
        claude.messages.put(None)
        with written() as lines:
            chat._listen()
        assert lines == [
            f"# {labelled('chat', plain.UNREAD)}",
            "# chat        the session ended",
        ]

    def test_a_message_that_cannot_be_shown_is_said_and_the_next_one_is(self):
        claude = RecordedClaude()
        chat = a_chat(self.host, claude)
        shown: list[dict] = []

        def heard(message: dict) -> None:
            if message.get("type") == "odd":
                raise ValueError("odd")
            shown.append(message)

        for message in ({"type": "odd"}, {"type": "fine"}, None):
            claude.messages.put(message)
        with written() as lines, unittest.mock.patch.object(chat, "_heard", heard):
            chat._listen()
        assert lines == [
            "# chat        FAILED to show a message: ValueError('odd')",
            "# chat        the session ended",
        ]
        assert shown == [{"type": "fine"}]

    def test_messages_that_cannot_be_shown_in_a_row_end_what_is_shown(self):
        claude = RecordedClaude()
        chat = a_chat(self.host, claude)
        for _ in range(talk.MOST_FAILED + 2):
            claude.messages.put({"type": "odd"})
        failing = unittest.mock.Mock(side_effect=ValueError("odd"))
        with written() as lines, unittest.mock.patch.object(chat, "_heard", failing):
            chat._listen()
        # The user is told, and can leave: the chat holds the session as
        # ended, it is not waited for
        assert (
            lines[-1]
            == "# chat        FAILED, nothing more is shown: ValueError('odd')"
        )
        assert len(lines) == talk.MOST_FAILED
        assert failing.call_count == talk.MOST_FAILED
        with written(), pytest.raises(KeyboardInterrupt):
            chat._read("> ")

    def test_a_line_is_not_waited_for_once_claude_has_ended(self):
        chat = a_chat(self.host)
        chat._session_ended()
        with written(), pytest.raises(KeyboardInterrupt):
            chat._read("> ")
        assert not chat._reading

    def test_a_file_asked_about_is_outside_the_project_as_the_session_knows_it(self):
        chat = a_chat(self.host)
        asked: list[str] = []

        def ask(prompt: str) -> str | None:
            asked.append(prompt)
            return "y"

        chat._asker.ask = ask
        # The project is under the home of the container for the session,
        # whose paths these are, wherever it is on the host
        for path in ("/home/sandbox/proj/a.py", "/etc/hosts"):
            edit = {"file_path": path, "old_string": "a", "new_string": "b"}
            with written():
                chat._asker.decide({"tool_name": "Edit", "input": edit})
        assert asked == [
            "allow edit file: /home/sandbox/proj/a.py? [y/a/N] ",
            "allow edit file: /etc/hosts  OUTSIDE PROJECT? [y/a/N] ",
        ]

    def said_by(self, *messages: dict) -> list[str]:
        """What a chat writes of what claude says, the lines about what
        changed in it. Each within a turn, as claude says all of it: a
        result ends only a turn that runs."""
        chat = a_chat(self.host)
        with written() as lines:
            for message in messages:
                chat._turns.begin()
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
        assert changed == []

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
            assert len(changed) == 1, message
            assert what in changed[0]
        init = {"type": "system", "subtype": "init", "session_id": SESSION}
        init.update(model=7, claude_code_version="2.2.0", slash_commands=[])
        (line,) = self.said_by(init)
        assert "Claude Code 2.2.0" in line
        for missing in ("model", "permissionMode", "mcp_servers"):
            assert f"no {missing} in system init" in line
        assert "no slash_commands" not in line
        # The mode is also said in between, where the rest is not
        assert self.said_by({"type": "system", "subtype": "status"}) == []

    def test_a_chat_notes_what_changed_for_a_trace_of_the_session(self):
        host = self.host
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
        assert rows == [
            (
                "claude code",
                "CHANGED what it says, 1 noted: line mode may have shown less",
            )
        ]
        (event,) = events
        assert (event.who, event.what) == (Who.CLAUDE, "changed")
        assert "a message line mode does not know, new_thing" in event.details[0]
        assert "secret" not in event.details[0]
        # Of that session, by its container
        assert change_events(host, 0, float("inf"), "claude-other")[1] == []
        assert len(change_events(host, 0, float("inf"), "claude-test")[1]) == 1
        # The chat said it itself, it is not written again as it follows
        assert following.told_over_the_pipe(event, began)
        # Nor is what was noted before a session is followed, a trace's
        time.sleep(0.002)
        assert followed(Follower(host, verbose=False)) == []
        with written():
            chat._heard({"type": "another_thing"})
        assert [event.what for event in followed(mine)] == ["changed"] * 2
        assert followed(mine) + followed(others) == []


class FollowedTest(LauncherTest):
    def test_what_a_subagent_does_is_followed_with_its_session(self):
        session = self.write_transcript(SESSION, [])
        follower = Follower(self.host, False, session, container="claude-test")
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
        assert [(path, e.who, e.what, e.details) for path, e in events] == [
            (session, Who.AGENT, "reply", ["done"])
        ]
        # Of the network, its own container alone
        assert follower._ours("claude-test")
        assert not follower._ours("claude-test-2")

    def test_a_cleared_session_is_followed_in_its_new_transcript(self):
        chat = a_chat(self.host)
        other = SESSION.replace("3fa9", "4fa9")
        with written():
            for session in (SESSION, other, "../elsewhere"):
                chat._heard(
                    {"type": "system", "subtype": "init", "session_id": session}
                )
        # What is not an id changes nothing
        tails = chat._followed._follower._tails
        assert [path.stem for path in tails] == [other]

    def test_a_reply_of_before_the_chat_is_history_one_since_is_told_by_the_pipe(self):
        began = time.time()
        told = following.told_over_the_pipe
        now = Event(began + 1, Who.CLAUDE, "reply", ["x"], {})
        assert told(now, began)
        assert not told(Event(1.0, Who.CLAUDE, "reply", ["x"], {}), began)
        # What a command said and what a subagent replied are the transcript's
        for who, what in ((Who.CLAUDE, "command"), (Who.AGENT, "reply")):
            assert not told(Event(now.when, who, what, [], {}), began)

    def test_what_claude_says_of_the_session_live_is_not_said_again(self):
        began = time.time()
        told = following.told_over_the_pipe
        soon = began + 1
        # A retry, a compaction and a task that ended come over the pipe
        for what in ("api", "compact", "task"):
            assert told(Event(soon, Who.CLAUDE, what, ["x"], {}), began)
            assert not told(Event(1.0, Who.CLAUDE, what, ["x"], {}), began)
        # What only the transcript has is shown from it
        for what in ("context", "mode", "model", "prompt"):
            assert not told(Event(soon, Who.CLAUDE, what, ["x"], {}), began)


class SessionTest:
    def test_a_session_id_that_is_none_is_not_made_a_path_of(self):
        host = Host("/home/me", "/home/me/proj", "", "")
        for said in ("../../../etc/passwd", "x" * 36, None, 7, SESSION + "/.."):
            assert saying.transcript_of(host, said) is None
        found = saying.transcript_of(host, SESSION)
        assert found.name == f"{SESSION}.jsonl"
        assert Path("/home/me/.claude/projects") in found.parents

    def test_what_claude_says_of_the_session_is_taken_when_it_is_what_it_should(self):
        session = saying.Session()
        assert not session.heard({"subtype": "status", "permissionMode": "plan"})
        assert session.mode == "plan"
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
        assert session.heard(init)
        assert session.id == ""
        assert session.model == "claude[2J-x"
        assert session.commands == ["/compact", "/model", "/plugin:skill"]
        assert session.servers == [("docs", "connected")]
        session.heard({**init, "session_id": SESSION})
        assert session.id == SESSION
        # The last server that goes is gone
        session.heard({**init, "mcp_servers": []})
        assert session.servers == []

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
        assert (session.model, session.chosen) == ("claude-fable-5-2", "Opus 5.5")
        session.replied({"message": {"model": "claude-opus-5-5"}})
        assert (session.model, session.chosen) == ("claude-opus-5-5", "")
        for odd in ({"model": "<synthetic>"}, {"model": 7}, {}, "x"):
            session.replied({"message": odd})
        assert session.model == "claude-opus-5-5"
        # What another command says, or /model when it chose nothing
        session.replied({"message": said, "local_command_run": {"command": "cost"}})
        session.replied({"message": {"content": "Usage: /model"}, **chose})
        assert session.chosen == ""
        # The start of the next turn names it by its id
        session.replied({"message": said, **chose})
        session.heard({"subtype": "init", "model": "claude-opus-5-5"})
        assert (session.model, session.chosen) == ("claude-opus-5-5", "")
