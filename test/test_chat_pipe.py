#!/usr/bin/env python3
"""--line-mode: claude spoken to over the pipes of the docker command
that runs it, and the lines of the session that are no message."""

from __future__ import annotations

import contextlib
import errno
import queue
import subprocess
import sys
import threading
import time
import unittest.mock
from collections.abc import Iterator
from typing import Any

import pytest
from chat_harness import PATIENCE, page, written

from claude_airlock import files
from claude_airlock.chat import pipe, plain
from claude_airlock.errors import Fatal
from claude_airlock.events import labelled


@contextlib.contextmanager
def played(*command: str, late: pipe.Errors | None = None) -> Iterator[pipe.Agent]:
    """Claude played by a command, in the place of the docker command
    that runs it, what it writes to its errors once it has ended written
    where late says. Ended once done with, however it was left: stopped,
    what it still says let go of for what reads its pipes to end, and
    those pipes closed."""

    def run(*_args: str, **options) -> subprocess.Popen:
        return subprocess.Popen(command, **options)

    agent = pipe.Agent([], lambda: None, run, late)
    try:
        yield agent
    finally:
        agent.close()
        agent._process.kill()
        agent.status()
        while agent.drain():
            pass
        agent._errors.join(PATIENCE)
        for piped in (agent._process.stdout, agent._process.stderr):
            if piped:
                piped.close()


class PipeTest:
    @pytest.fixture
    def agent(self) -> Iterator[pipe.Agent]:
        """Claude played by what says again what it is told. Ended with
        the test."""
        with played("cat") as agent:
            yield agent

    def test_a_docker_that_cannot_be_started_is_said_in_a_line(self):
        for problem, said in (
            (FileNotFoundError(), "docker was not found"),
            (PermissionError(), "docker on PATH cannot be run"),
            (OSError(errno.E2BIG, "Argument list too long"), "more than the system"),
        ):
            run = unittest.mock.Mock(side_effect=problem)
            with pytest.raises(Fatal, match=said):
                pipe.Agent(["run", "img"], lambda: None, run)

    def test_a_session_that_reads_no_more_has_what_it_is_told_let_go_of(self):
        # Written when the chat ends, it would be said to have failed then
        with played(sys.executable, "-c", "pass") as agent:
            agent._process.wait(PATIENCE)
            agent.prompt("x" * 100_000)
            stdin = agent._process.stdin
            assert stdin is not None
            deadline = time.monotonic() + PATIENCE
            while not stdin.closed and time.monotonic() < deadline:
                time.sleep(0.05)
            assert stdin.closed

    def test_what_waits_to_be_taken_in_is_bounded_by_its_size_too(self):
        backlog = pipe.Backlog(most=3, most_bytes=100)
        backlog.put("a", 60)
        # Past the bytes, then past the count
        with pytest.raises(queue.Full):
            backlog.put("b", 60, timeout=0.01)
        backlog.put("b", 20)
        backlog.put("c", 10)
        with pytest.raises(queue.Full):
            backlog.put("d", 1, timeout=0.01)
        assert backlog.get(timeout=0.01) == "a"
        backlog.put("d", 60)
        assert [backlog.get(timeout=0.01) for _ in range(3)] == ["b", "c", "d"]
        with pytest.raises(queue.Empty):
            backlog.get(timeout=0.01)
        # One alone fits whatever its size, and what waits for room gets it
        backlog.put("large", 1000)
        waiting = threading.Thread(target=backlog.put, args=("next", 5))
        waiting.start()
        assert backlog.get(timeout=PATIENCE) == "large"
        waiting.join(PATIENCE)
        assert backlog.get(timeout=PATIENCE) == "next"

    def test_a_session_that_does_not_read_holds_nobody(self):
        # Claude played by what never reads what it is told
        with played("sleep", "30") as agent:
            started = time.monotonic()
            large = {"text": "x" * (1 << 20)}
            sent = [agent.send(large) for _ in range(pipe.SAID_BACKLOG + 50)]
            agent.refuse("r1", "no")
            agent.close()
            assert time.monotonic() - started < PATIENCE
            # Said to be unsent once as much waits as may
            assert sent[0]
            assert not sent[-1]

    def test_an_answer_is_said_however_much_else_waits_to_be(self):
        # Claude played by what never reads what it is told, and as much
        # waits to be said as may: what claude asked is answered all the
        # same, it waits for that. Until as many answers wait too, which
        # is said, the answer is not let go of without a word
        with (
            unittest.mock.patch.object(pipe, "SAID_BACKLOG", 4),
            unittest.mock.patch.object(pipe, "ANSWERS_ROOM", 3),
            played("sleep", "30") as agent,
        ):
            large = {"text": "x" * (1 << 20)}
            sent = [agent.send(large) for _ in range(8)]
            assert sent[0]
            assert not sent[-1]
            assert agent.respond("r1", {"behavior": "allow"})
            assert agent.refuse("r2", "no")
            # The room kept for answers is not taken by what else is told
            assert not agent.send({"type": "small"})
            answered = [agent.refuse(f"r{n}", "no") for n in range(3, 8)]
            assert answered[0]
            assert not answered[-1]
            assert not agent.respond("r8", {"behavior": "allow"})

    def test_a_line_that_holds_too_much_once_read_is_not_taken_in(self):
        small = b'{"type": "x"}\n'
        assert files.held_size(small) >= len(small)
        dense = b"[" + b"{}," * 1000 + b"{}]\n"
        # No fewer bytes than it takes, dozens of times its length
        assert files.held_size(dense) > 24 * len(dense)
        # What is within a string sets no value apart, an escaped quote
        # does not end it
        text = b'{"text": "\\"' + b",{[:" * 1000 + b'"}\n'
        assert files.held_size(text) < 3 * len(text)
        with (
            played("cat") as agent,
            unittest.mock.patch.object(pipe, "MOST_LINE_HELD", 1000),
        ):
            agent.send({"dense": [{} for _ in range(200)]})
            agent.send({"type": "small"})
            # Not without a word: what stands for it is, see Unread
            assert agent.messages.get(timeout=PATIENCE) is pipe.Unread.LINE
            assert agent.messages.get(timeout=PATIENCE) == {"type": "small"}

    def taken_in(self, script: str) -> list[object]:
        """All an agent takes in of what claude says, to its end, claude
        played by a script of Python."""
        said: list[object] = []
        with played(sys.executable, "-c", script) as agent:
            while (message := agent.messages.get(timeout=PATIENCE)) is not None:
                said.append(message)
        return said

    def test_a_line_too_long_to_read_is_said_to_be_once(self):
        # As a request of claude's is with all of a large file in it,
        # which it then waits for the answer to
        asks = '{"type": "control_request", "pad": "' + "x" * 5000 + '"}'
        long = f"print('{asks}'); print('{{\"type\": \"after\"}}')"
        with unittest.mock.patch.object(pipe, "LINE_LIMIT", 1000):
            assert self.taken_in(long) == [pipe.Unread.LINE, {"type": "after"}]
            # Without its end too, as long as the limit to the byte or not
            for length in (2000, 2500):
                cut = f"import sys; sys.stdout.write('x' * {length})"
                assert self.taken_in(cut) == [pipe.Unread.LINE], length

    def test_the_last_line_claude_wrote_is_taken_in_without_its_end(self):
        over = '{"type": "first"}\\n{"type": "result", "subtype": "success"}'
        said = self.taken_in(f"import sys; sys.stdout.write('{over}')")
        assert said == [{"type": "first"}, {"type": "result", "subtype": "success"}]
        # And what is no message, which is shown as it was written
        word = "import sys; sys.stdout.write('unknown command')"
        assert self.taken_in(word) == ["unknown command"]

    def test_what_a_session_writes_faster_than_is_listened_to_does_not_pile_up(
        self, capsys: pytest.CaptureFixture[str]
    ):
        # A process of the session that writes to its errors without end,
        # claude not having ended: its output stays open
        with played("sh", "-c", "exec yes 3>&1 >&2") as agent:
            deadline = time.monotonic() + PATIENCE
            while len(agent.messages._held) < pipe.BACKLOG:
                assert time.monotonic() < deadline
                time.sleep(0.01)
            # Nobody listens for a while: no more waits than may, and
            # the rest is left on its pipe, not written around whoever
            # listens, where no line would say that it is the session's
            time.sleep(1.5)
            assert len(agent.messages._held) == pipe.BACKLOG
            assert agent.messages._bytes <= pipe.BACKLOG * pipe.PLAIN_WIDTH
            assert capsys.readouterr().err == ""

    def test_what_a_session_leaves_on_its_errors_as_it_ends_is_not_all_shown(
        self, capsys: pytest.CaptureFixture[str]
    ):
        # claude has ended, its output is closed, and a process of the
        # session wrote more to its errors than was listened to
        with played("sh", "-c", "exec >&-; yes | head -n 5000 >&2") as agent:
            assert agent.status() == 0
            agent._errors.join(PATIENCE)
            assert not agent._errors.is_alive()
            # As many as may wait were passed on, for whoever listens to
            # count. Of the rest the first are shown, and a line says
            # that there was more. On the launcher's own errors where no
            # chat is to write them
            assert agent.ended.is_set()
            assert len(agent.messages._held) <= pipe.BACKLOG
            written = capsys.readouterr().err.splitlines()
            assert written.count("y") == pipe.LAST_WORDS
            assert written[pipe.LAST_WORDS :] == [f"claude-airlock: {pipe.NO_MORE}"]

    def test_what_a_session_leaves_on_its_errors_is_written_where_the_chat_writes(
        self, capsys: pytest.CaptureFixture[str]
    ):
        # Above the line being read, as the lines of the chat are: not
        # around it, where the next erase would be counted from a cursor
        # that is not where it was left
        script = "exec >&-; yes | head -n 5000 >&2"
        with written() as lines, played("sh", "-c", script, late=page()) as agent:
            assert agent.status() == 0
            agent._errors.join(PATIENCE)
        assert capsys.readouterr().err == ""
        assert lines.count("y") == pipe.LAST_WORDS
        assert lines[-1] == f"# {labelled('chat', pipe.NO_MORE)}"

    def test_a_thread_that_cannot_be_started_leaves_no_session_running(self):
        # As at the launcher's limit of them: the session it has started
        # is not left with nothing to talk to it
        started = threading.Thread.start
        threads: list[threading.Thread] = []
        ran: list[subprocess.Popen] = []

        def run(*_args: str, **options) -> subprocess.Popen:
            ran.append(subprocess.Popen(["cat"], **options))
            return ran[-1]

        def start(thread: threading.Thread) -> None:
            if thread.name.endswith("(_write)"):
                raise RuntimeError("can't start new thread")
            started(thread)
            threads.append(thread)

        with (
            unittest.mock.patch.object(threading.Thread, "start", start),
            pytest.raises(RuntimeError, match="can't start new thread"),
        ):
            pipe.Agent([], lambda: None, run)
        (process,) = ran
        assert process.poll() is not None
        # What read its pipes is over, the session having ended
        for thread in threads:
            thread.join(PATIENCE)
            assert not thread.is_alive()
        for piped in (process.stdout, process.stderr):
            if piped:
                piped.close()

    def test_an_answer_that_cannot_be_written_is_a_refusal(self, agent: pipe.Agent):
        # An input given back as claude gave it that cannot be written as
        # JSON: claude is not left waiting for an answer. One that holds
        # itself, which no Python writes, and one nested too deep, which
        # json raises for as deep as the Python it runs on can go: from
        # 3.14 on that is as deep as the stack it has, so it is raised here
        held: list = []
        held.append(held)
        assert not agent.send({"held": held})
        too_deep = unittest.mock.Mock(
            dumps=unittest.mock.Mock(side_effect=RecursionError)
        )
        with unittest.mock.patch.object(pipe, "json", too_deep):
            assert not agent.send({"deep": [[[]]]})
        agent.respond("r1", {"behavior": "allow", "updatedInput": {"x": held}})
        sent: Any = agent.messages.get(timeout=PATIENCE)
        assert sent["response"]["request_id"] == "r1"
        assert sent["response"]["subtype"] == "error"

    def test_what_claude_is_told_is_a_line_each(self, agent: pipe.Agent):
        agent.prompt("hello")
        asked = agent.request("set_permission_mode", mode="plan")
        agent.respond("r1", {"behavior": "allow"})
        agent.refuse("r2", "no")
        sent: list[Any] = [agent.messages.get(timeout=PATIENCE) for _ in range(4)]
        agent.close()
        assert agent.status() == 0
        assert asked == "chat-1"
        assert sent[0]["message"]["content"][0]["text"] == "hello"
        assert sent[1]["request"] == {"subtype": "set_permission_mode", "mode": "plan"}
        assert sent[2]["response"]["response"] == {"behavior": "allow"}
        assert sent[3]["response"]["subtype"] == "error"

    def test_what_claude_answers_is_told_to_what_asked_for_it(self, agent: pipe.Agent):
        answers: list[dict] = []
        asked = agent.request("set_permission_mode", answers.append, mode="plan")
        # Nothing waits for the answer to an interrupt
        stopped = agent.request("interrupt")
        assert agent.pending
        for odd in ("no", {"request_id": stopped}, {"request_id": [asked]}):
            agent.answered({"response": odd})
        assert answers == []
        answer = {"request_id": asked, "subtype": "success"}
        agent.answered({"response": answer})
        assert not agent.pending
        # Told once
        agent.answered({"response": answer})
        assert answers == [answer]
        # What the chat goes on without is told its answer, and holds
        # nothing up meanwhile
        quiet = agent.request("get_settings", answers.append, waited=False)
        assert not agent.pending
        answer = {"request_id": quiet, "subtype": "success"}
        agent.answered({"response": answer})
        assert answers[-1] == answer
        assert agent._unwaited == set()


class PlainTest:
    LEFT_OUT = "of the session, it writes them faster than they can be read"

    def test_no_more_lines_of_the_session_are_shown_than_can_be_read(self):
        clock = [0.0]
        said = plain.PlainLines(page())
        with (
            written() as lines,
            unittest.mock.patch.object(plain.time, "monotonic", lambda: clock[0]),
        ):
            for number in range(plain.MOST + 7):
                said.heard(f"line {number}\n")
            # Counted, and said once the window they came in is over
            said.say_left_out()
            clock[0] += plain.WINDOW
            said.say_left_out()
            # While they keep coming so fast a few of each window are
            # shown, for what is being written to be told
            for _ in range(plain.MOST + 1):
                said.heard("more\n")
            clock[0] += plain.WINDOW
            for _ in range(plain.FEW + 3):
                said.heard("fewer\n")
            # And all of them again once they do not
            clock[0] += plain.WINDOW
            for _ in range(plain.MOST):
                said.heard("again\n")
            said.heard("and again\n")
            # The session ended: said now
            said.say_left_out(now=True)
        squeezed = plain.MOST + 1 - plain.FEW
        assert lines == [
            *(f"line {number}" for number in range(plain.MOST)),
            f"# chat        left out 7 more lines {self.LEFT_OUT}",
            *["more"] * plain.FEW,
            f"# chat        left out {squeezed} more lines {self.LEFT_OUT}",
            *["fewer"] * plain.FEW,
            f"# chat        left out 3 more lines {self.LEFT_OUT}",
            *["again"] * plain.MOST,
            f"# chat        left out 1 more line {self.LEFT_OUT}",
        ]

    def test_a_line_that_could_not_be_read_is_said_whatever_else_is_written(self):
        clock = [0.0]
        said = plain.PlainLines(page())
        with (
            written() as lines,
            unittest.mock.patch.object(plain.time, "monotonic", lambda: clock[0]),
        ):
            for _ in range(plain.MOST + 1):
                said.heard("y\n")
            # Not left out for the lines a session writes around it, and
            # said once for those that come together
            for _ in range(3):
                said.unread()
            clock[0] += plain.WINDOW
            said.say_left_out()
        assert lines[plain.MOST :] == [
            f"# {labelled('chat', plain.UNREAD)}",
            f"# chat        left out 3 more lines {self.LEFT_OUT}",
        ]
        assert "Ctrl-C stops the turn" in plain.UNREAD
