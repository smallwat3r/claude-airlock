#!/usr/bin/env python3
"""--line-mode: the console the lines are read at and written to."""

from __future__ import annotations

import contextlib
import ctypes
import io
import sys
import unittest.mock

import pytest
from chat_harness import written
from harness import LauncherTest

from claude_airlock.chat import console, talk
from claude_airlock.chat import screen as screens
from claude_airlock.chat import tasks as tasking
from claude_airlock.events import Event, Who
from claude_airlock.report.layout import Layout


class ConsoleTest(LauncherTest):
    def test_the_end_of_a_turn_is_said_in_bright_green_in_colour(self):
        assert talk.ready_line(Layout()) == f"# {talk.READY}"
        assert (
            talk.ready_line(Layout(colour=True)) == f"\x1b[1;92m# {talk.READY}\x1b[0m"
        )

    def test_a_turn_that_ends_with_tasks_still_running_says_so(self):
        one = talk.ready_line(Layout(), tasking.Running(others=1))
        two = talk.ready_line(Layout(), tasking.Running(others=2))
        assert "claude has paused, 1 task still runs" in one
        assert "claude has paused, 2 tasks still run" in two
        assert "has finished" not in one
        assert one.startswith("# ready ")
        # Its subagents are named as that, next to what else it left
        agent = tasking.Task("Map the code", agent=True)
        both = talk.ready_line(Layout(), tasking.Running((agent, agent), (), 1))
        assert "claude has paused, 2 agents and 1 task still run, it goes" in both
        # Not one that has ended
        ended = talk.ready_line(Layout(), tasking.Running(ended=(agent,)))
        assert ended == f"# {talk.READY}"

    def test_a_word_is_completed_to_a_command_or_a_file_of_the_project(self):
        (self.project / "src").mkdir()
        (self.project / "src" / "main.py").touch()
        (self.project / "setup.py").touch()
        root, names = str(self.project), ["/mode", "/model", "/mcp"]

        def offered(word: str, first: bool = True) -> list[str]:
            return console.completions(word, first, names, root)

        assert offered("/mo") == ["/mode", "/model"]
        # A command starts the line
        assert offered("/mo", first=False) == []
        assert offered("@s") == ["@setup.py", "@src/"]
        assert offered("@src/") == ["@src/main.py"]
        # Not the hidden ones unless asked for, and nothing out of the project
        assert "@.env" not in offered("@")
        assert "@.env" in offered("@.e")
        assert offered("@../") == []
        assert offered("@/etc/pas") == []
        assert offered("plain") == []

    def test_no_more_files_are_looked_at_than_are_offered(self):
        # A directory is the session's to fill: not listed whole, sorted
        # and each name looked up for being one, for a Tab
        for number in range(10):
            (self.project / f"f{number}").mkdir()
        (self.project / "g").touch()
        looked: list[str] = []
        isdir = console.os.path.isdir

        def looked_up(path: str) -> bool:
            looked.append(path)
            return isdir(path)

        with (
            unittest.mock.patch.object(console, "NAMES_OFFERED", 3),
            unittest.mock.patch.object(console.os.path, "isdir", looked_up),
        ):
            offered = console.completions("@f", True, [], str(self.project))
        assert len(offered) == 3
        assert offered == sorted(offered)
        assert all(name.startswith("@f") and name.endswith("/") for name in offered)
        assert len(looked) == 3

    def test_a_name_that_is_not_shown_as_it_is_is_not_offered(self):
        # The names are a session's to choose, readline writes them out
        for name in ("plain.py", "es\x1b[2Jcape", "bi\u202edi", "line\nbreak"):
            (self.project / "made" / name).parent.mkdir(exist_ok=True)
            (self.project / "made" / name).touch()
        offered = console.completions("@made/", False, [], str(self.project))
        assert offered == ["@made/plain.py"]

    def test_a_link_out_of_the_project_is_not_gone_into(self):
        outside = self.home / "private"
        outside.mkdir()
        (outside / "secret").touch()
        (self.project / "out").symlink_to(outside)
        (self.project / "src2").mkdir()
        (self.project / "src2" / "a.py").touch()
        (self.project / "in").symlink_to(self.project / "src2")
        root = str(self.project)
        assert console.completions("@out/", False, [], root) == []
        assert console.completions("@in/", False, [], root) == ["@in/a.py"]
        # A root written with its last slash is the same root
        assert console.completions("@in/", False, [], root + "/") == ["@in/a.py"]

    def test_what_is_written_while_a_line_is_read_goes_before_the_prompt(self):
        screen = console.Console(str(self.project))
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            screen.write(["one"])
            # As if a line were being read, in a pipe nothing is erased
            screen._reading, screen._on_screen = "> ", True
            screen.write(["two"])
            screen.ask("allow? ")
            assert screen.typed() == ""
        assert out.getvalue() == "one\n\ntwo\n> \nallow? "

    def test_the_head_is_above_the_prompt_and_written_with_what_comes_next(self):
        screen = console.Console(str(self.project))
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            screen.set_head(["model x"])
            # As _line would, in a pipe: the head with the prompt
            screen._headed, screen._reading, screen._shown = True, "> ", "model x\n"
            screen._on_screen = True
            screen.write(["one"])
            # Nothing is written for a head that changed: no prompt
            # for each figure that moved
            screen.set_head(["model y", "ctx 3%"])
            assert out.getvalue() == "\none\n> "
            # What is written next has it under it, with the prompt
            screen.write(["two"])
            # Not above a question
            screen.ask("allow? ")
        assert out.getvalue() == "\none\n> \ntwo\nmodel y\nctx 3%\n> \nallow? "

    def test_at_a_terminal_the_head_is_written_again_in_its_place(self):
        out = io.StringIO()
        screen = console.Console(str(self.project), out=out, columns=lambda: 40)
        screen.set_head(["model x"])
        screen._redrawn, screen._headed = True, True
        screen._reading, screen._shown = "> ", "model x\n> "
        with unittest.mock.patch.object(console.readline, "get_line_buffer") as typed:
            typed.return_value = ""
            screen.set_head(["model y", "ctx 3%"])
            assert out.getvalue() == "\x1b[1A\r\x1b[Jmodel y\nctx 3%\n> "
            # Both of its rows are erased with the prompt the next time
            screen.set_head(["model z"])
        assert out.getvalue().endswith("\x1b[2A\r\x1b[Jmodel z\n> ")

    def test_editline_is_given_the_prompt_alone_and_the_head_is_written_for_it(self):
        head = "\x1b[1;32m[claude-x]\x1b[0m \x1b[33mnet:open\x1b[0m"
        given: list[str] = []

        def typed(prompt: str) -> str:
            given.append(prompt)
            return "hello"

        def read(editline: bool) -> str:
            out = io.StringIO()
            screen = console.Console(str(self.project), out=out, columns=lambda: 80)
            screen._redrawn, screen._hooked, screen._editline = True, False, editline
            screen.set_head([head])
            with (
                unittest.mock.patch("builtins.input", typed),
                unittest.mock.patch.object(
                    console.readline, "get_line_buffer"
                ) as buffer,
            ):
                buffer.return_value = ""
                assert screen.read(screens.as_prompt("> "), headed=True) == "hello"
            return out.getvalue()

        # Editline writes an escape with the character after it, and
        # neither before a line break: the head is not its to write.
        # Then the line as it was read, nobody typed it here
        assert read(editline=True) == head + "\nhello\n"
        assert given == ["> "]
        # GNU readline writes all of it, the escapes marked as taking
        # no column
        assert read(editline=False) == "hello\n"
        assert given[1] == screens.uncounted(head) + "\n> "

    def test_ctrl_c_ends_the_wait_for_a_line_with_the_console_let_go_of(self):
        screen = console.Console(str(self.project))

        def interrupted(_prompt: str) -> str:
            screen.interrupt()
            return "never"

        with written(), unittest.mock.patch("builtins.input", interrupted):
            with pytest.raises(KeyboardInterrupt):
                screen.read("> ")
            assert not screen._lock.locked()
            # Would wait forever for a lock that was left held
            screen.end_line()

    def test_a_line_that_is_no_text_in_its_encoding_is_read_all_the_same(self):
        # A file of prompts kept in Latin-1, read as every locale but C
        # has it: what is no UTF-8 is raised
        sent = io.BytesIO("résumé this\nsecond\n".encode("latin-1"))
        stdin = io.TextIOWrapper(sent, encoding="utf-8", errors="strict")
        self.cleanup.enter_context(unittest.mock.patch.object(sys, "stdin", stdin))
        screen = console.Console(str(self.project))
        with written() as lines:
            assert screen.read("> ") == "r\ufffdsum\ufffd this"
            assert screen.read("> ") == "second"
            assert screen.read("> ") is None
        # What could not be read shows in the line
        assert lines[0] == "> r\ufffdsum\ufffd this"
        # The chat after this one, of a session that is resumed, reads
        # the same input on
        console.Console(str(self.project))
        assert stdin.errors == "replace"

    def test_what_is_piped_in_is_written_back_without_its_escapes(self):
        # As gh issue view | claude-airlock gives a page someone wrote
        piped = "fix this\x1b]0;owned\x07\x1b[2J\u202e\n"
        stdin = io.TextIOWrapper(io.BytesIO(piped.encode()), encoding="utf-8")
        self.cleanup.enter_context(unittest.mock.patch.object(sys, "stdin", stdin))
        screen = console.Console(str(self.project))
        with written() as lines:
            # Claude is told what was written, the screen shows it
            assert screen.read("> ") == piped.removesuffix("\n")
        assert lines == ["> fix this^[]0;owned^G^[[2J"]
        # As readline shows them, a new line and a tab left as they are
        assert screens.shown_typed("a\tb\nc\x7f\x00") == "a\tb\nc^?^@"

    def test_a_paste_that_ctrl_c_drops_is_not_written_again_as_sent(self):
        out = io.StringIO()
        screen = console.Console(
            str(self.project), sent="1;7", out=out, columns=lambda: 40
        )
        screen.interactive = screen._redrawn = screen._hooked = True
        # Two lines pasted unmarked: the first is entered, the second
        # read with it and typed on, which Ctrl-C then ends
        entered = ["first"]

        def line(prompt: str, _headed: bool) -> str:
            screen._reading = prompt
            if entered:
                return entered.pop()
            raise KeyboardInterrupt

        pasted = iter(["second"])
        with (
            unittest.mock.patch.object(screen, "_line", line),
            unittest.mock.patch.object(screen, "_pasted", lambda: next(pasted)),
            pytest.raises(KeyboardInterrupt),
        ):
            screen.read("> ")
        # Nothing was sent, and nothing reads as if it had been
        assert "\x1b[1;7m" not in out.getvalue()
        # Nor is the next line typed on from what was dropped
        assert screen._filled == ""

    def test_ctrl_c_ahead_of_the_wait_for_a_line_is_raised_once_there(self):
        screen = console.Console(str(self.project))
        # Where the lock may be held: kept, not raised
        screen.interrupt()
        with written(), unittest.mock.patch("builtins.input", return_value="hello"):
            with pytest.raises(KeyboardInterrupt):
                screen.read("> ")
            # For that line alone
            assert screen.read("> ") == "hello"

    def test_ctrl_c_is_not_raised_while_readline_has_the_console_write(self):
        screen = console.Console(str(self.project))
        screen._entering, screen._waiting = "> ", True
        held = []

        def above() -> str:
            # As the handler of the signal would, with the lock held
            held.append(screen._lock.locked())
            screen.interrupt()
            return ""

        with written(), unittest.mock.patch.object(screen, "_above", above):
            screen._prompted()
        assert held
        assert all(held)
        assert not screen._lock.locked()
        # The wait goes on, and can be ended
        with pytest.raises(KeyboardInterrupt):
            screen.interrupt()

    def test_editline_takes_any_number_of_new_line_keys_in_a_line(self):
        # Each ends the line read, which goes on as the next: more of them
        # than Python calls a function within another
        keys = sys.getrecursionlimit() + 10
        screen = console.Console(str(self.project), out=io.StringIO())
        screen._redrawn, screen._editline = True, True
        buffers = iter([*[console.EDITLINE_NEW_LINE] * keys, ""])
        with (
            unittest.mock.patch.object(screen, "_typed", lambda _prompt: "x"),
            unittest.mock.patch.object(console, "readline") as readline,
        ):
            readline.get_line_buffer.side_effect = lambda: next(buffers)
            line = screen._line("> ", False)
        assert line == "\n".join(["x"] * (keys + 1))

    def test_ctrl_c_as_readline_calls_the_console_ends_the_line_for_it(self):
        # Come in the step before what readline called says that it does
        # not wait: raised there, readline would drop it, and the line
        # could no longer be interrupted. It is ended instead
        screen = console.Console(str(self.project), out=io.StringIO())
        screen._entering = "> "
        done = ctypes.c_int(0)
        raised: list[bool] = []

        def above() -> str:
            # The frame of the hook around _prompted, as the handler of the
            # signal is given it there. Not that of what it calls next
            hook = sys._getframe(2)
            if hook.f_code is console.Console._prompted.__code__:
                screen._waiting = True
                try:
                    screen.interrupt(hook)
                except KeyboardInterrupt:
                    raised.append(True)
            return ""

        with (
            written(),
            unittest.mock.patch.object(console, "_done", done),
            unittest.mock.patch.object(screen, "_above", above),
        ):
            screen._prompted()
        assert (raised, done.value, screen._ended_for_interrupt) == ([], 1, True)
        assert screen._waiting
        # Anywhere else in the wait it is raised as before
        with pytest.raises(KeyboardInterrupt):
            screen.interrupt(sys._getframe())

    def test_ctrl_c_in_what_a_readline_hook_calls_ends_the_line_too(self):
        # Deeper than the hook, as in what it calls once it says again
        # that it waits: readline would drop it there as well
        screen = console.Console(str(self.project), out=io.StringIO())
        screen._entering = "> "
        done = ctypes.c_int(0)

        def above() -> str:
            screen._waiting = True
            screen.interrupt(sys._getframe())
            return ""

        with (
            written(),
            unittest.mock.patch.object(console, "_done", done),
            unittest.mock.patch.object(screen, "_above", above),
        ):
            screen._prompted()
        assert (done.value, screen._ended_for_interrupt) == (1, True)

    def test_a_line_without_a_head_has_none_above_its_prompt(self):
        screen = console.Console(str(self.project))
        screen.set_head(["model x"])
        assert screen._above() == ""
        screen._headed = True
        assert screen._above() == "model x\n"
        screen._asked = "allow? "
        assert screen._above() == ""

    def test_the_head_is_erased_with_the_line_being_typed(self):
        # Its colours take no column
        assert screens.erased("\x1b[2mmodel\x1b[0m\n> ", "abc", 10) == "\x1b[1A\r\x1b[J"
        # A line of it as wide as the terminal takes one row, a wider two
        assert screens.erased("x" * 10 + "\n> ", "", 10) == "\x1b[1A\r\x1b[J"
        assert screens.erased("x" * 11 + "\n> ", "", 10) == "\x1b[2A\r\x1b[J"

    def test_the_line_being_typed_is_erased_by_the_rows_it_takes(self):
        assert screens.erased("> ", "abc", 10) == "\r\x1b[J"
        assert screens.erased("> ", "x" * 25, 10) == "\x1b[2A\r\x1b[J"
        # A wide character takes two columns, what is put on one none
        assert screens.erased("> ", "中" * 5, 10) == "\x1b[1A\r\x1b[J"
        assert screens.erased("> ", "é" * 7, 10) == "\r\x1b[J"
        # What was pasted with its line breaks, each line its own rows
        assert screens.erased("> ", "one\n" + "x" * 12, 10) == "\x1b[2A\r\x1b[J"
        # A terminal that says it has no column is taken to have one
        assert screens.erased("> ", "", 0) == "\x1b[2A\r\x1b[J"

    def test_what_takes_no_column_has_no_row_erased_for_it(self):
        # Counted as a column each, these would take three rows of ten:
        # the two above, which are not this line's, would be erased
        for unseen in ("\u200b", "\u2060", "\ufe0f", "\U000e0041", "\u0e31"):
            padded = "ab" + unseen * 25
            assert screens.columns_of(padded) == 2, f"U+{ord(unseen):04X}"
            assert screens.erased("> ", padded, 10) == "\r\x1b[J"

    def test_where_terminals_differ_on_a_width_the_fewer_rows_are_erased(self):
        # An emoji takes one column where a terminal has the widths of
        # before Unicode 9: counted two, a question of them would have the
        # rows above it erased, the call it shows whole among them
        emoji = "\U0001f600"
        assert screens.columns_of(emoji * 5) == 5
        assert screens.erased("> ", emoji * 5, 10) == "\r\x1b[J"
        # What every terminal shows wide is counted so
        assert screens.columns_of("中" * 5) == 10
        # Where readline has the cursor in its row, an emoji is as wide as
        # wcwidth has it now
        assert screens.columns_of(emoji * 5, fewest=False) == 10
        assert screens.cursor_back("> ", emoji * 2 + "ab", emoji * 2, 20) == "\r\x1b[6C"
        # And never on a row above the one it is on: the rows up to it
        # are those of all that was typed counted the fewest, less those
        # before it counted not
        typed = emoji * 4 + "abcdefg"
        assert screens.cursor_back("> ", typed, emoji * 4, 10) == "\r"

    def test_a_question_with_tabs_has_only_the_rows_it_takes_erased(self):
        # A terminal moves a tab to the next stop and at its edge by none:
        # written as they are, these would take two rows of sixty and be
        # counted for four, and the call shown whole above the question
        # would be erased a row at a time by what is written meanwhile
        out = io.StringIO()
        screen = console.Console(str(self.project), out=out, columns=lambda: 60)
        screen._redrawn, screen._reading, screen._shown = True, "> ", "> "
        asked = "allow bash $ echo hi" + "\t" * 190 + "? [y/a/N] "
        with unittest.mock.patch.object(console.readline, "get_line_buffer") as typed:
            typed.return_value = ""
            screen.ask(screens.as_prompt(asked))
            screen.write(["one"])
        assert "\t" not in out.getvalue()
        shown = asked.replace("\t", " ")
        # Each written as many columns as are counted for it, 220
        assert out.getvalue() == f"\r\x1b[J{shown}\x1b[3A\r\x1b[Jone\n{shown}"
        # Made so the one way there is: cleaned, and on one line
        assert screens.as_prompt("a\tb\nc\x1b[2J") == "a b\\nc[2J"
        assert screens.as_prompt("a", "1") == "\x1b[1ma\x1b[0m"

    def test_ctrl_c_while_readline_completes_ends_the_line(self):
        # GNU readline does not see it, the chat's own code ran: the line
        # is ended for it, and dropped as Ctrl-C drops one
        screen = console.Console(str(self.project), out=io.StringIO())
        done = ctypes.c_int(0)

        def completing(_prompt: str) -> str:
            # Ctrl-C within the completion, where nothing is raised
            screen._waiting = False
            screen.interrupt()
            screen._complete("/he", 0)
            # What readline gives back once it ended the line
            return "half" if done.value else "entered"

        with (
            unittest.mock.patch.object(console, "_done", done),
            unittest.mock.patch.object(console, "readline") as readline,
            unittest.mock.patch("builtins.input", completing),
        ):
            readline.get_begidx.return_value = 0
            readline.get_current_history_length.return_value = 1
            readline.get_history_item.return_value = "half"
            with pytest.raises(KeyboardInterrupt):
                screen._typed("> ")
            assert done.value == 1
            # Kept by readline among the lines typed, and taken out
            readline.remove_history_item.assert_called_once_with(0)
        assert not screen._ended_for_interrupt
        # Where readline cannot be had to, nothing is ended
        screen._interrupted = True
        with unittest.mock.patch.object(console, "_done", None):
            screen._end_for_interrupt()
        assert not screen._ended_for_interrupt

    def test_a_typed_tab_is_counted_to_the_next_stop(self):
        # Pasted, as Tab completes: to column 16 of the row, and what
        # follows ends at the edge of twenty, the cursor on the next row.
        # Counted one column, it would be on the first
        typed = "x" * 10 + "\tabcd"
        assert screens.erased("> ", typed, 20) == "\x1b[1A\r\x1b[J"
        assert screens.erased("> ", "x\ta", 20) == "\r\x1b[J"
        # No further than the last column of the row it is on, where a
        # terminal stops it: the fewer columns, see columns_of
        assert screens.erased("> ", "xxxxxxx\t", 10) == "\r\x1b[J"
        # The cursor put back after it, at its stop
        assert screens.cursor_back("> ", "\tab", "\t", 20) == "\r\x1b[8C"

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
            screen._editline = False
            screen.write(["one"])
            assert out.getvalue() == "\r\x1b[Jone\n> " + typed + "\x1b[1A\r\x1b[5C"
            # Editline does not keep where the cursor is: taken to be at
            # the end, on the second row, and left there
            out.seek(0)
            out.truncate()
            screen._editline = True
            screen.write(["one"])
            assert out.getvalue() == "\x1b[1A\r\x1b[Jone\n> " + typed
        back = screens.cursor_back
        # At its end it is where it was written to, on the next row
        # when that was to the edge
        assert back("> ", "abc", "abc", 10) == ""
        assert back("head\n> ", "x" * 8, "x" * 8, 10) == " \r"
        assert back("> ", "one\ntwo", "on", 10) == "\x1b[1A\r\x1b[4C"

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
        assert (
            out.getvalue() == "\x1b[1A\r\x1b[J\x1b[1;7m> hi\x1b[0m\n"
            "\x1b[1A\x1b[1A\r\x1b[J\x1b[1;7m> xxxxxxxx\x1b[0m\n"
        )

    def test_an_entered_line_leaves_no_working_line_above_it(self):
        out = io.StringIO()
        screen = console.Console(str(self.project), out=out, columns=lambda: 40)
        screen._redrawn, screen._reading, screen._headed = True, "> ", True
        screen._head, screen._working = ["model x"], ["# working 5s"]
        screen._shown = screen._above() + "> "
        screen._entered("hi")
        assert out.getvalue() == "\x1b[1A\x1b[2A\r\x1b[Jmodel x\n> hi\n"
        # Nor the rows that said how far the subagents were
        screen._working = ["# working 5s", "# agents 2 running", "#   Map it: 5s"]
        screen._reading = "> "
        screen._shown = screen._above() + "> "
        screen._entered("ho")
        assert out.getvalue().endswith("\x1b[1A\x1b[4A\r\x1b[Jmodel x\n> ho\n")

    def test_at_a_terminal_what_runs_is_written_again_above_the_head(self):
        out = io.StringIO()
        screen = console.Console(str(self.project), out=out, columns=lambda: 40)
        screen.set_head(["model x"])
        screen._redrawn, screen._headed = True, True
        screen._reading, screen._shown = "> ", "model x\n> "
        with unittest.mock.patch.object(console.readline, "get_line_buffer") as typed:
            typed.return_value = ""
            screen.set_working(["# working 5s", "# agents 2 running"])
            written = "\x1b[1A\r\x1b[J# working 5s\n# agents 2 running\nmodel x\n> "
            assert out.getvalue() == written
            # Not for what is the same as before
            screen.set_working(["# working 5s", "# agents 2 running"])
            assert out.getvalue() == written
            # All of its rows are erased with the prompt the next time
            screen.set_working(["# agents 1 running"])
            assert out.getvalue().endswith(
                "\x1b[3A\r\x1b[J# agents 1 running\nmodel x\n> "
            )
            screen.set_working([])
            assert out.getvalue().endswith("\x1b[2A\r\x1b[Jmodel x\n> ")
            # Not above a question, as the head is not
            screen.set_working(["# agents 2 running"])
            screen.ask("allow? ")
            assert out.getvalue().endswith("\x1b[2A\r\x1b[Jallow? ")

    def test_an_entered_line_is_left_as_typed_without_a_style(self):
        screen = console.Console(str(self.project))
        screen._redrawn, screen._reading = True, "> "
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            screen._entered("hi")
        assert out.getvalue() == ""

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
        assert head.endswith("\x1b[1;96mclaude   reply\x1b[0m")
        ran = Event(0, Who.CLAUDE, "bash", ["$ make", "why: Build it"], {})
        command, reason = layout.event(ran)
        assert command.endswith("\x1b[33mclaude   bash        $ make\x1b[0m")
        assert (
            reason
            == " " * 10
            + "\x1b[33m"
            + " " * 21
            + "\x1b[0m\x1b[33;1mwhy:\x1b[0m\x1b[33;3m Build it\x1b[0m"
        )

    def test_a_line_is_about_to_be_read_or_being_read_not_both(self):
        screen = console.Console("/nowhere")
        screen._entering = "> "
        assert (screen._entering, screen._reading) == ("> ", None)
        screen._reading = screen._entering
        assert (screen._entering, screen._reading) == (None, "> ")
        # A question has not come before the user until it is said to
        screen._asked = "allow? "
        screen._asked_at = 1.0
        screen._asked = "another? "
        assert screen._asked_at is None
        screen._asked = None
        screen._asked_at = 2.0
        assert screen._asked_at is None
