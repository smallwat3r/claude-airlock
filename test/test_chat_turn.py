#!/usr/bin/env python3
"""--line-mode: a turn, what it used and the reply claude makes in it."""

from __future__ import annotations

import re
import time
import unittest.mock

from chat_harness import lines_now, page, written

from claude_airlock.chat import console, turn
from claude_airlock.chat import reply as replying
from claude_airlock.chat import said as saying
from claude_airlock.events import Event, Who
from claude_airlock.report import entries
from claude_airlock.report.layout import Layout, Styled


def message(kind: str, *blocks: dict, **more) -> dict:
    return {"type": kind, "message": {"content": list(blocks)}, **more}


class TurnTest:
    def test_a_turn_knows_the_calls_it_made_and_waits_for(self):
        ran = turn.Turn(time.monotonic() - 42)
        assert re.search(r"4\ds, waiting for claude$", turn.working_line(ran))
        assert re.search(r" 40s, waiting for claude$", turn.working_line(ran, 5))
        for call, tool in (("t1", "Bash"), ("t2", "Read"), ("t3", "Bash")):
            block = {"type": "tool_use", "id": call, "name": tool, "input": {}}
            ran.heard(message("assistant", block, {"type": "text", "text": "x"}))
        # Not those of a subagent, which are in a transcript of its own
        inner = {"type": "tool_use", "id": "t9", "name": "Grep", "input": {}}
        ran.heard(message("assistant", inner, parent_tool_use_id="t1"))
        ran.heard(message("assistant", {"type": "tool_use", "id": ["x"]}))
        assert ran.said == 4
        assert re.search(r" 0s, waiting for bash, read$", turn.working_line(ran))
        for call in ("t1", "t3", ["x"]):
            ran.heard(message("user", {"type": "tool_result", "tool_use_id": call}))
        assert re.search(r"waiting for read$", turn.working_line(ran))
        ran.waiting.clear()
        ran.thinking = True
        assert re.search(r"waiting for claude, thinking$", turn.working_line(ran))

    def test_no_more_of_the_calls_waited_for_is_kept_than_so_much(self):
        ran = turn.Turn(time.monotonic())

        def called(call: str, tool: str = "Bash") -> None:
            block = {"type": "tool_use", "id": call, "name": tool, "input": {}}
            ran.heard(message("assistant", block))

        # An id that is too long to keep is no id, a name is cut
        called("x" * (saying.ID_WIDTH + 1))
        called("t1", "N" * 1000)
        assert ran.waiting == {"t1": "n" * saying.NAME_KEPT}
        # The oldest let go of, past so many
        with unittest.mock.patch.object(saying, "MOST_OPEN", 2):
            for call in ("t2", "t3"):
                called(call)
        assert list(ran.waiting) == ["t2", "t3"]
        assert ran.said == 4

    def test_one_turn_runs_at_a_time(self):
        turns = turn.Turns()
        assert turns.begin()
        first = turns.current
        # A prompt typed while it runs is not a turn of its own
        assert not turns.begin()
        assert turns.current is first
        turns.end()
        assert turns.begin()
        assert turns.current is not first

    def test_a_turn_that_went_wrong_says_so(self):
        ran = turn.Turn(0.0)
        ended = {
            "subtype": "error_max_turns",
            "is_error": True,
            "result": "too\x1b[2J long",
        }
        assert turn.turn_line(ran, ended).endswith("ENDED error_max_turns: too[2J long")
        # An error of the API, in a turn that is otherwise said to succeed
        refused = {"subtype": "success", "is_error": True, "result": "Credit low"}
        assert turn.turn_line(ran, refused).endswith("0 calls  ENDED: Credit low")
        # The reason of a subtype of claude's own is in its errors
        cut = {"subtype": "error_during_execution", "errors": ["a", 7, "b\nc"]}
        said = turn.turn_line(ran, cut)
        assert said.endswith("ENDED error_during_execution: a; b\\nc")
        ran.interrupted = True
        assert turn.turn_line(ran, ended).endswith("0 calls  interrupted")

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
        assert first == ["30.0k in", "5 out", "$0.0500", "context 15%", "claude-x"]
        # The cost claude gives is the session's, and the model is named once
        second = used.parts({**result, "total_cost_usd": 0.0512}, "claude-x")
        assert second == ["30.0k in", "5 out", "$0.0012", "context 15%"]
        # A command of Claude Code's used nothing, and says nothing
        nothing = {
            "usage": {"input_tokens": 0, "output_tokens": 0},
            "total_cost_usd": 0.0512,
        }
        assert used.parts(nothing, "claude-y") == []
        # What is not a count or a cost is left out
        odd = {"usage": {"input_tokens": True, "output_tokens": float("nan")}}
        for cost in ("1", -1, float("inf"), 10**400):
            assert turn.used({**odd, "total_cost_usd": cost}, 0.0) == []
        assert turn.used({"usage": []}, 0.0) == []

    def test_the_context_is_said_full_at_most_on_the_turn_line_as_in_the_status(self):
        usage = {"input_tokens": 230_000, "output_tokens": 5}
        result = {"usage": usage, "modelUsage": {"m": {"contextWindow": 200_000}}}
        used = turn.Usage()
        used.step({"message": {"usage": usage}})
        assert "context 100%" in used.parts(result, "m")
        assert used.context_used == 100
        # A window of less than a token is none: what is used of it would
        # be more than a number can hold, and the status is made of it
        # with every message claude says
        for window in (5e-324, 0.5, 0, -1):
            tiny = {"usage": usage, "modelUsage": {"m": {"contextWindow": window}}}
            fresh = turn.Usage()
            fresh.step({"message": {"usage": usage}})
            assert "context" not in " ".join(fresh.parts(tiny, "m"))
            assert fresh.context_used is None

    def test_a_turn_that_is_quiet_says_that_it_still_runs(self):
        shown, turns = page(), turn.Turns()
        heart = turn.Heartbeat(shown, turns, lambda: False)
        with written() as lines:
            # Not between two turns
            shown.wrote -= turn.QUIET
            heart.beat()
            assert lines == []
            turns.begin()
            # Not while claude has just taken a step
            heart.beat()
            assert lines == []
            turns.current.since -= turn.QUIET
            heart.beat()
            # Said once, the next one waits twice as long
            shown.wrote -= turn.QUIET
            heart.beat()
            shown.wrote -= turn.QUIET
            heart.beat()
            assert heart.wait == 4 * turn.QUIET
            # What else is written only puts it off
            shown.say(["chat        something"])
            heart.beat()
            assert heart.wait == 4 * turn.QUIET
            # A step of claude starts the wait over
            turns.current.stepped()
            heart.beat()
            assert heart.wait == turn.QUIET
        assert sum("# working " in line for line in lines) == 2

    def test_a_turn_that_waits_for_the_user_is_not_said_to_run(self):
        shown, turns = page(), turn.Turns()
        asking_now = [True]
        heart = turn.Heartbeat(shown, turns, lambda: asking_now[0])
        with written() as lines:
            turns.begin()
            turns.current.since -= turn.QUIET
            shown.wrote -= turn.QUIET
            heart.beat()
            assert lines == []
            asking_now[0] = False
            heart.beat()
        assert sum("# working " in line for line in lines) == 1

    def test_at_a_terminal_a_quiet_turn_is_said_to_run_in_one_line(self):
        terminal, turns = console.Console("/nowhere"), turn.Turns()
        terminal._redrawn = True
        heart = turn.Heartbeat(console.Page(terminal, Layout()), turns, lambda: False)
        with written() as lines:
            turns.begin()
            turns.current.since -= 2 * turn.QUIET + 1
            heart.beat()
            (working,) = terminal._working
            assert re.search(r"^# working +10s, waiting for claude$", working)
            turns.current.stepped()
            heart.beat()
            assert terminal._working == []
        assert lines == []

    def test_a_count_is_a_number_within_reason(self):
        for odd in (True, "1", -1, float("inf"), float("nan"), 10**400, None):
            assert entries.measured(odd) is None
        assert entries.measured(3) == 3.0


def piece(kind: str, **more) -> dict:
    return {"type": kind, **more}


class ReplyTest:
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
            assert replies.writing
            replies.piece(piece("content_block_delta", delta={"text": "one\nt"}))
            # Its first line is out under when it started, the second not yet
            assert before == ["before"]
            replies.piece(piece("content_block_delta", delta={"text": "wo"}))
            # Its whole comes while its pieces do, and is not written again
            replies.whole(message("assistant", {"type": "text", "text": "one\ntwo"}))
            replies.piece(piece("content_block_stop"))
            assert not replies.writing
        assert re.search(r"^\d\d:\d\d:\d\d  claude   reply$", lines[1])
        assert lines[2:] == ["one", "two", ""]

    def test_a_line_that_is_no_prose_is_cut_into_rows_not_wrapped(self):
        # Wrapped at its spaces, a line takes dozens of times its length
        # and seconds for some megabytes: one delta of a reply can be that
        long = "word " * 200_000
        rows = replying.reply_lines(long, 80, False)
        assert "".join(rows) == long
        assert {len(row) for row in rows[:-1]} == {80}
        # Each row under an indent of its own, no more of one than half a
        # row: the session makes it as long as it likes
        indented = "first\n" + " " * 1000 + "x" * 5000
        rows = replying.reply_lines(indented, 80, False)
        assert max(map(len, rows)) == 80
        assert len(rows) == 2 + (6000 - 80) // 40
        assert rows[-1] == " " * 40 + "x" * 40
        # A line of prose is wrapped at its spaces as it was
        prose = replying.reply_lines("a few words " * 20, 40, False)
        assert prose[0] == "a few words a few words a few words a"

    def test_in_a_file_no_more_of_a_reply_is_kept_than_so_much(self):
        # Written once it is whole, a reply whose end never comes would
        # be held as long as the session makes it
        replies, before = self.stream(Layout())
        with written() as lines:
            replies.piece(piece("content_block_start", content_block={"type": "text"}))
            many = "line\n" * (replying.KEPT_LINES + 10)
            replies.piece(piece("content_block_delta", delta={"text": many}))
            assert len(lines_now(lines).splitlines()) == replying.KEPT_LINES + 10
            long = "x" * replying.KEPT_CHARACTERS + "\n"
            replies.piece(piece("content_block_delta", delta={"text": long}))
            assert len(lines_now(lines).splitlines()) == replying.KEPT_LINES + 11
            replies.piece(piece("content_block_stop"))
        # Each line says when and who, as those of a reply written whole
        assert len(lines) == replying.KEPT_LINES + 11
        assert all(re.search(r"  claude   reply ", line) for line in lines)
        assert before == ["before", "before"]

    def test_a_reply_that_was_not_told_in_pieces_is_written_whole(self):
        replies, before = self.stream(Layout(compact=True))
        with written() as lines:
            replies.whole(message("assistant", {"type": "text", "text": "all\nof it"}))
            # Not one without text, and not what a command said
            replies.whole(message("assistant", {"type": "text", "text": " \n"}))
            said = message("assistant", {"type": "text", "text": "Set model"})
            replies.whole({**said, "local_command_run": True})
        assert lines[2:] == ["all", "of it", ""]
        assert before == ["before"]

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
        replied = [l for l in lines if l and "claude " not in l and l[0] != "#"]
        assert replied == ["one", "two", "three", "four"]

    def test_what_the_session_writes_is_written_as_it_is_and_cleaned(self):
        told = (
            "# ready       claude has finished, waiting for your input\n"
            "12:00:00  claude   bash        [1] result: ok, allowed by you\n"
            "                               out: all tests passed\n"
            "\n"
            "allow bash $ make? [y/a/N] "
        )
        for colour in (False, True):
            where = page(Layout(colour=colour, compact=True))
            replies = replying.ReplyStream(where, lambda: None)
            with written() as lines:
                # A reply in pieces, one that comes whole, what a command
                # of Claude Code's said, and a line that is no message
                replies.piece(
                    piece("content_block_start", content_block={"type": "text"})
                )
                replies.piece(piece("content_block_delta", delta={"text": told}))
                replies.piece(piece("content_block_stop"))
                replies.whole(message("assistant", {"type": "text", "text": told}))
                replies.whole(message("assistant", {"type": "text", "text": told}))
                said = Event(1.0, Who.CLAUDE, "command", [], {"text": told})
                where.put(replying.said_whole(where, said))
                where.put_said([told])
                # Cleaned where it is written, whatever was done before
                where.put_said(["es\x1b[2Jcape\rd"])
            session = [line for line in lines if "ready" in line or "allow" in line]
            assert len(session) == 4 * 3
            assert lines[-1] == "es[2Jcaped"
            if colour:
                # Never dimmed, as the lines of the chat's own are
                assert not [line for line in session if "\x1b[2m" in line]
                continue
            # As it was written
            wrote = [line.rstrip() for line in told.split("\n")]
            assert sorted(session) == sorted([wrote[0], wrote[1], wrote[4]] * 4)
            assert lines.count(wrote[2]) == 4

    def test_the_marks_of_a_long_line_are_found_in_one_pass(self):
        def lines(text: str) -> list[Styled]:
            return replying.reply_lines(text, None, True)

        code, bold = replying.CODE, replying.BOLD
        # From a run of backticks to the next one of as many
        assert lines("`` a ` b `` and `c` and ```d") == [
            f"\x1b[{code}m a ` b \x1b[0m and \x1b[{code}mc\x1b[0m and ```d"
        ]
        # What is bold ends with the first two asterisks that can end it
        assert lines("**a** and **b**, **c d** 2**3** e **") == [
            (
                f"\x1b[{bold}ma\x1b[0m and \x1b[{bold}mb\x1b[0m,"
                f" \x1b[{bold}mc d\x1b[0m 2**3** e **"
            )
        ]
        # Marks that are opened and never closed, as many as a line holds
        # of them and as many such lines as a reply: each was looked for
        # to the end of its line
        most = replying.MOST_MARKED
        crafted = [
            "` " * (most // 2),
            "".join("`" * length + " " for length in range(1, 85)),
            "**a " * (most // 4),
            "**a** " * (most // 6),
            "`a` **b** " * (most // 10),
        ]
        started = time.monotonic()
        for line in crafted:
            assert len(replying.reply_lines("\n".join([line] * 50), 80, True)) >= 50
        # And a line that comes in any number of pieces, never held whole:
        # given back a part at a time, all of it
        writer = replying.ReplyWriter(None, False)
        parts = []
        for _ in range(200_000):
            for part in writer.feed("x" * 20):
                assert len(part) <= replying.LONGEST_HELD + 20
                parts.append(part)
        parts += writer.end()
        assert "".join(parts) == "x" * 4_000_000
        assert time.monotonic() - started < 30

    def test_in_a_file_a_reply_is_written_once_it_is_whole(self):
        replies, before = self.stream(Layout())
        with written() as lines:
            replies.piece(piece("content_block_start", content_block={"type": "text"}))
            replies.piece(piece("content_block_delta", delta={"text": "one\ntwo"}))
            assert before == []
            replies.piece(piece("content_block_stop"))
        assert len(lines) == 2
        for line, text in zip(lines, ("one", "two"), strict=True):
            assert re.search(r"^\d{4}-.* claude   reply       " + text + "$", line)

    def test_in_a_file_in_colour_a_reply_keeps_its_marks(self):
        # Each of its lines is a detail of an event there, cleaned of every
        # escape: a style would be the text of its escape, and the marks it
        # took the place of gone
        told = "use `ls` and **bold**\n"
        replies, _ = self.stream(Layout(colour=True))
        said = Event(1.0, Who.CLAUDE, "command", [], {"text": told})
        with written() as lines:
            replies.piece(piece("content_block_start", content_block={"type": "text"}))
            replies.piece(piece("content_block_delta", delta={"text": told}))
            replies.piece(piece("content_block_stop"))
            replies._page.put(replying.said_whole(replies._page, said))
        assert len(lines) == 2
        for line in lines:
            # No escape but those of the layout, nothing of one as text
            assert "[" not in line.replace("\x1b[", "")
            text = told.strip()
            assert re.sub(r"\x1b\[[0-9;]*m", "", line).endswith(text)
        # At a terminal it is in colour, its marks taken out
        replies, _ = self.stream(Layout(colour=True, compact=True))
        with written() as lines:
            replies.whole(message("assistant", {"type": "text", "text": told}))
        assert f"\x1b[{replying.CODE}mls\x1b[0m" in lines[2]

    def test_what_was_said_is_shown_whole(self):
        said = "Set model to `Sonnet`\nfor this session only"
        event = Event(1_800_000_000.0, Who.CLAUDE, "command", ["Set"], {"text": said})
        lines = replying.said_whole(page(Layout(compact=True)), event)
        # Its day, then when and who, then the text as it was written
        assert re.search(r"^\d\d:\d\d:\d\d  claude   command$", lines[1])
        assert lines[2:] == ["Set model to `Sonnet`", "for this session only", ""]
        # In a file every line says when and who
        lines = replying.said_whole(page(), event)
        assert len(lines) == 2
        assert re.search(r"claude   command     for this session only$", lines[1])

    def test_a_reply_is_wrapped_as_it_is_indented(self):
        lines = replying.wrapped("  - one two three four", 12)
        assert lines == ["  - one two", "  three four"]
        assert replying.wrapped("", 12) == [""]

    def test_a_reply_without_colour_is_as_written_its_code_not_wrapped(self):
        text = "Run this now please:\n```sh\nmake test --keep-going\n```\n**done**"
        assert replying.reply_lines(text, 12, False) == [
            "Run this now",
            "please:",
            "```sh",
            "make test --keep-going",
            "```",
            "**done**",
        ]

    def test_a_reply_in_colour_has_styles_for_its_marks(self):
        code, bold = replying.CODE, replying.BOLD

        def lines(text: str, width: int | None = None) -> list[Styled]:
            return replying.reply_lines(text, width, True)

        # The fences are left out, and the code is not read as Markdown
        assert lines("```py\nx = '**a**'\n\n```\nafter") == [
            f"\x1b[{code}mx = '**a**'\x1b[0m",
            "",
            "after",
        ]
        # A span between three backticks at the start of a line opens no
        # block: the line is there, and what follows it is prose
        assert lines("```make``` builds it\nafter") == [
            f"\x1b[{code}mmake\x1b[0m builds it",
            "after",
        ]
        assert lines("~~~ `x`\ncode\n~~~") == [f"\x1b[{code}mcode\x1b[0m"]
        assert lines("use `make` **now**") == [
            f"use \x1b[{code}mmake\x1b[0m \x1b[{bold}mnow\x1b[0m"
        ]
        assert lines("## The `x` plan") == [
            f"\x1b[{bold}mThe \x1b[0m\x1b[{bold};{code}mx\x1b[0m\x1b[{bold}m plan\x1b[0m"
        ]
        # Not what only looks like a mark
        assert lines("2**3 and 4**5, a * b") == ["2**3 and 4**5, a * b"]
        assert lines("`a ** b ** c`") == [f"\x1b[{code}ma ** b ** c\x1b[0m"]
        # A span goes on in the line it is wrapped to
        assert lines("**one two three**", 9) == [
            f"\x1b[{bold}mone two\x1b[0m",
            f"\x1b[{bold}mthree\x1b[0m",
        ]
        # A block that is never closed is code to its end
        assert lines("~~~\nls") == [f"\x1b[{code}mls\x1b[0m"]
        # What a session writes cannot pass for a mark or a style
        assert lines("a\x01b\x1b[2Jc") == ["ab[2Jc"]

    def test_a_reply_in_pieces_reads_as_the_whole(self):
        text = "\n\n  First.\n\n```\ncode\n\nmore\n```\nlast  \n\n"
        for colour in (False, True):
            whole = replying.reply_lines(text, 20, colour)
            writer = replying.ReplyWriter(20, colour)
            pieces = [line for char in text for line in writer.feed(char)]
            assert pieces + writer.end() == whole
        assert replying.reply_lines(text, None, False)[0] == "First."
