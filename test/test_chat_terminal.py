#!/usr/bin/env python3
"""--line-mode at a terminal: what is typed as it is typed, and what is
written around the line being typed."""

from __future__ import annotations

import ast
import contextlib
import os
import re
import sys
import time

import pyte
import pytest
from chat_harness import (
    EDITLINE,
    NEW_ROW,
    PATIENCE,
    SESSION,
    LineModeTest,
    Paused,
    editline,
    turns,
)
from harness import ROOT, Terminal

from claude_airlock.chat import console, pipe, plain
from claude_airlock.chat import screen as screens


class TerminalTest(LineModeTest):
    def test_at_a_terminal_what_comes_while_a_line_is_typed_goes_above_it(self):
        said = self.at_a_terminal(
            ("> ", "slow\r"),
            # While the reply is written, the start of the next prompt
            ("two", "typ"),
            ("# turn", "ed\r"),
            ("first line", "\x04"),
        )
        # The reply line by line as it was made, once
        assert said.count("claude   reply") == 2
        assert "claude   reply\none\n" in said
        # The line being typed was erased with the status above it, and
        # both written again under what came
        head = "[claude-proj] net:open\n"
        assert f"> typ\x1b[1A\r\x1b[Jthree\n{head}> typ" in said
        assert re.search(r"# turn [^\n]*\n" + re.escape(head) + "> typ", said)
        assert re.search(r"user     prompt      typed\n", said)
        again = (
            f"to go on with this session: claude-airlock --line-mode --resume {SESSION}"
        )
        assert again in said

    def test_at_a_terminal_a_line_being_typed_is_not_the_answer_to_a_question(self):
        said = self.at_a_terminal(
            ("> ", "later\r"),
            # Typed before claude asks, entered after
            ("prompt      later", "y"),
            ("allow bash", "\r"),
            ("sent, claude takes it up", Paused("y\r")),
            ("first line", "\x04"),
        )
        assert "what you were typing is not taken for the answer" in said
        # The question rang, and was put again under the line it was not for
        assert "\x07" in said
        assert "was told: allow" in said
        assert turns(said) == 2
        assert re.search(r"user     prompt      y\n", said)

    def test_at_a_terminal_enter_pressed_twice_answers_one_question(self):
        said = self.at_a_terminal(
            ("> ", "twice\r"),
            ("[y/a/N] ", Paused("y\r")),
            # The second y comes as claude asks again, or a moment before:
            # sooner than that question is read, and too soon after the
            # first for a prompt. Once the next line is read, whichever
            # of the two it is for: sooner it would be a paste that came
            # with the first, however slow the machine
            (("\n> ", "[y/a/N] "), "y\r"),
            ("it is dropped", ""),
            ("[y/a/N] ", Paused("n\r")),
            ("was told: allow, deny", "\x04"),
        )
        # It allowed nothing, and claude was not told y either
        assert "was told: allow, deny" in said
        assert "prompt      y\n" not in said
        assert "sent, claude takes it up" not in said
        assert turns(said) == 1

    def test_at_a_terminal_tab_completes_a_command(self):
        # The help is written: the line was entered as the command it is
        said = self.at_a_terminal(("> ", "/he\t\r"), ("drops the line", "\x04"))
        if not EDITLINE:
            # Editline writes the rest of the word where the cursor is
            assert "> /help" in said
        assert "prompt      /he" not in said

    def test_at_a_terminal_shift_enter_starts_a_new_line_of_the_prompt(self):
        said = self.at_a_terminal(
            ("> ", "one\x1b[13;2utwo\x1b[27;2;13~three\x1b\rfour\r"),
            ("first line", "\x04"),
        )
        # Each key a line of its own on the screen, all of them one prompt
        rows = NEW_ROW.replace("\r\n", "\n")
        assert f"> one{rows}two{rows}three{rows}four\n" in said
        assert said.count("user     prompt      one\n") == 1
        assert turns(said) == 1

    @editline
    def test_at_a_terminal_of_editline_a_new_line_within_a_line_is_one_too(self):
        # The cursor moved back two (Ctrl-B) before the key: shown as
        # ^M there, and a line break of the prompt once it is entered
        said = self.at_a_terminal(
            ("> ", "onetwo\x02\x02\x02\x1b[13;2u"),
            ("^Mtwo", "\r"),
            ("first line", "\x04"),
        )
        assert said.count("user     prompt      one\n") == 1
        assert turns(said) == 1

    @editline
    def test_at_a_terminal_of_editline_a_new_line_key_erases_nothing_above(self):
        # Editline stays on the row of the key, where Enter moves to the
        # next: erased from the row below, each key took a row above
        said = self.at_a_terminal(
            ("> ", "one\x1b\r"),
            ("one^M", "two\x1b[13;2u"),
            ("two^M", "three"),
            ("three", "\x15\x04"),
        )
        head = "[claude-proj]"
        before = _screen(said[: said.index("> ")])
        after = _screen(said[: said.rindex("three") + len("three")])
        above = before[: before.index(next(r for r in before if r.startswith(head)))]
        assert after[: len(above)] == above
        assert after[len(above) :][:4] == [f"{head} net:open", "> one", "two", "three"]

    def test_at_a_terminal_lines_pasted_unmarked_are_one_prompt(self):
        # Without the escapes of a bracketed paste, as a terminal that
        # does not mark one sends it
        said = self.at_a_terminal(
            ("> ", "one\rtwo\rthree\r"),
            # It waits for Enter, the line break at its end or not
            (f"> one{NEW_ROW}two{NEW_ROW}three", " four\r"),
            ("first line", "\x04"),
        )
        rows = NEW_ROW.replace("\r\n", "\n")
        assert f"> one{rows}two{rows}three four\n" in said
        assert said.count("user     prompt      one\n") == 1
        assert turns(said) == 1

    def test_at_a_terminal_an_unfinished_paste_is_typed_on(self):
        said = self.at_a_terminal(
            ("> ", "one\rtw"),
            # Written again as the start of the line, not entered yet
            (f"> one{NEW_ROW}tw", "o\r"),
            ("first line", "\x04"),
        )
        assert said.count("user     prompt      one\n") == 1
        assert turns(said) == 1

    def test_in_a_shell_buffer_of_emacs_lines_sent_together_are_one_prompt(self):
        said = self.at_a_terminal(
            ("> ", "one\ntwo\nthree\n"), ("first line", "\x04"), term="dumb"
        )
        assert said.count("user     prompt      one\n") == 1
        assert turns(said) == 1

    def test_in_a_shell_buffer_of_emacs_a_long_input_sent_in_bunches_is_one_prompt(
        self,
    ):
        said = self.at_a_terminal(
            ("> ", ("one\ntw", "o\nthree\n")), ("first line", "\x04"), term="dumb"
        )
        assert said.count("user     prompt      one\n") == 1
        assert "user     prompt      o\n" not in said
        assert turns(said) == 1

    def test_in_a_shell_buffer_of_emacs_no_prompt_is_written_while_a_turn_runs(self):
        said = self.at_a_terminal(
            ("> ", "slow\n"), ("# ready", "run it\n"), ("[y/a/N]", "\x04"), term="dumb"
        )
        # The reply as it is made, no prompt among its lines
        assert "claude   reply\none\ntwo\nthree\n" in said
        # One when the turn is over, under the status, and the question
        assert "waiting for your input\n[claude-proj] net:open\n> run it\n" in said
        assert said.count("> ") == 2, said
        assert "\nallow bash $ make test? [y/a/N] " in said

    def test_the_first_prompt_has_the_sandbox_above_it(self):
        said = self.at_a_terminal(("> ", "\x04"), term="dumb")
        assert "[claude-proj] net:open\n> " in said

    def test_in_a_shell_buffer_of_emacs_the_first_prompt_waits_for_what_claude_goes_by(
        self,
    ):
        # Claude answers once it runs, a moment after the chat started
        said = self.at_a_terminal(
            ("> ", "\x04"),
            term="dumb",
            FAKE_EFFORT="high",
            FAKE_MODEL="claude-fable-5-2",
            FAKE_SETTINGS_AFTER="0.3",
        )
        # One prompt, under the status as it is by then
        assert "\n[claude-proj] net:open  Fable 5.2 effort:high\n> " in said
        assert said.count("> ") == 1, said

    def test_in_a_shell_buffer_of_emacs_a_change_of_mode_writes_one_prompt_with_it(
        self,
    ):
        said = self.at_a_terminal(
            ("> ", "/mode plan\n"), ("mode:plan\r\n> ", "\x04"), term="dumb"
        )
        # What claude answered, then the status as it now is: not a
        # prompt before the answer, nor one for the status alone
        changed = "# chat        mode plan\n[claude-proj] net:open  mode:plan\n> "
        assert f"> /mode plan\n{changed}" in said
        assert said.count("> ") == 2, said

    def test_at_a_terminal_in_colour_the_status_has_a_row_of_its_own(self):
        said = self.at_a_terminal(
            ("> ", "hello\r"),
            ("# ready", ""),
            ("> ", "\x04"),
            NO_COLOR="",
            FAKE_EFFORT="high",
        )
        assert "\x1b[1;32m[claude-proj]\x1b[0m" in said
        plain = screens.SGR.sub("", said)
        # Its last part is in colour, which ends where the row does:
        # editline writes neither that nor the line break when given
        # them, the status would share a row with the prompt
        assert "net:open> " not in plain
        assert "effort:high> " not in plain
        # The line typed is under it, as it was by then: claude said
        # what it goes by a moment after the chat started, or before
        assert re.search(r"net:open(  effort:high)?\s+> hello", plain)
        # And so is the prompt once the turn is over
        assert re.search(r"net:open  effort:high\s+> ", plain)

    def test_at_a_terminal_the_subagents_are_counted_above_the_prompt(self):
        said = self.at_a_terminal(
            ("> ", "agents\r"),
            ("# ready", ""),
            ("> ", "\x04"),
            FAKE_AGENTS_RUN="1.5",
        )
        # How far each is, over the status that counts them, while they
        # ran: written again in its place with each thing claude said
        rows = (
            r"# agents      2 running: 2 calls, 1\.5k tokens\n"
            r"#   Map the code: 2 calls, 1\.5k tokens, Reading main\.py\n"
            r"#   Read the docs\n"
            r"\[claude-proj\] net:open  agents:2\n"
        )
        assert re.search(rows, said), said
        alone = r"# agent       Map the code\n\[claude-proj\] net:open  agents:1"
        assert re.search(alone, said), said
        # Not above the prompt once they have ended, the last thing written
        after = said[said.rindex("# ready") :]
        assert "agents" not in after
        assert "[claude-proj] net:open\n> " in after

    def test_a_stopped_turn_asks_whether_to_go_on_and_remembers_a_yes(self):
        question = "go on with it in the conversation? [y/N] "
        said = self.at_a_terminal(
            ("> ", "fetch\r"),
            (question, Paused("y\r")),
            ("not asked again for what it read", Paused("fetch\r")),
            ("was went on", "\x04"),
            CLAUDE_AIRLOCK_INJECTION_STOP="1",
        )
        assert said.count("STOPPED the turn") == 1, said
        assert "stays in the conversation" not in said
        # The turn was stopped: what comes next is the user's to type
        assert said.count("# chat        nothing runs, claude waits") == 1
        # Flagged each time all the same
        assert said.count("POSSIBLE INJECTION in https://") == 2, said
        # The turn that was stopped is not said to have finished, the one
        # that went on is
        assert said.count("# ready ") == 1, said
        assert said.index("was went on") < said.index("# ready ")

    def test_a_stopped_turn_that_is_not_gone_on_with_is_cleared_once_confirmed(self):
        clear = "clear the conversation, and what claude read with it? [y/N] "
        said = self.at_a_terminal(
            ("> ", "fetch\r"),
            ("go on with it in the conversation? [y/N] ", Paused("\r")),
            (clear, Paused("y\r")),
            ("# ready ", Paused("fetch\r")),
            ("go on with it in the conversation? [y/N] ", "\x04"),
            CLAUDE_AIRLOCK_INJECTION_STOP="1",
        )
        assert "clearing the conversation, what claude read with it" in said
        assert "prompt      /clear" in said
        assert "nothing runs, claude waits" not in said
        # Nothing is remembered of what was not gone on with
        assert said.count("STOPPED the turn") == 2, said

    def test_a_conversation_is_not_cleared_without_a_yes_to_that(self):
        clear = "clear the conversation, and what claude read with it? [y/N] "
        said = self.at_a_terminal(
            ("> ", "fetch\r"),
            ("go on with it in the conversation? [y/N] ", Paused("n\r")),
            (clear, Paused("\r")),
            ("nothing runs, claude waits for you", Paused("fetch\r")),
            ("go on with it in the conversation? [y/N] ", "\x04"),
            CLAUDE_AIRLOCK_INJECTION_STOP="1",
        )
        assert "# chat        not cleared: what it read stays in the" in said
        assert "clearing the conversation" not in said
        assert "prompt      /clear" not in said
        # Kept, and not gone on with: it stops the next turn too
        assert said.count("STOPPED the turn") == 2, said

    def test_a_yes_typed_for_what_a_stopped_turn_asked_is_no_prompt(self):
        go_on = "go on with it in the conversation? [y/N] "
        said = self.at_a_terminal(
            ("> ", "both\r"),
            # Typed for the call claude asks about, and entered as the
            # turn is stopped for what a subagent read: the question went
            ("allow bash", "y"),
            (go_on, "\r"),
            ("it is dropped", ""),
            ("[y/N] ", Paused("y\r")),
            ("not asked again for what it read", "\x04"),
            CLAUDE_AIRLOCK_INJECTION_STOP="1",
        )
        assert "STOPPED the turn" in said
        assert "was stopped" in said
        assert "that line was typed for a question that is no longer asked" in said
        # Neither an answer to the question that came after it, nor told
        # to claude, which has just read what the turn was stopped for
        assert "prompt      y\n" not in said
        assert "sent, claude takes it up" not in said
        assert turns(said) == 1

    def test_a_host_the_filter_does_not_allow_goes_through_with_a_yes(self):
        said = self.at_a_terminal(
            ("> ", "reach\r"),
            ("let the session reach example.com? [y/N] ", Paused("y\r")),
            ("was let through", "\x04"),
            **self.asking(),
        )
        assert "network: filtered to the allowed domains, the user is" in said
        assert "# net         a request for example.com waits" in said
        assert "# net         allowed example.com until the session ends" in said
        assert "net:ask" in said
        # What was allowed goes with the session
        assert list((self.state / "asked-hosts").iterdir()) == []

    def test_a_host_the_filter_does_not_allow_is_refused_without_a_yes(self):
        said = self.at_a_terminal(
            ("> ", "reach\r"),
            ("let the session reach example.com? [y/N] ", Paused("\r")),
            ("was refused", "\x04"),
            **self.asking(),
        )
        assert "# net         REFUSED example.com until the session ends" in said

    def reaching(self) -> None:
        """Have the docker of the checks run what a chat runs for its
        user (!COMMAND), in the place of the container it would run it
        in, and leave a script there that asks for a host as the proxy's
        helper does and says what became of the request. Not for long,
        whatever becomes of the chat."""
        fake = self.work / "bin" / "docker"
        played = fake.rename(self.work / "bin" / "docker-played")
        fake.write_text(
            f"#!{sys.executable}\n"
            "import os, sys\n"
            "args = sys.argv[1:]\n"
            "if args[:1] == ['exec'] and 'setsid' in args:\n"
            "    os.execvp('bash', ['bash', '-c', args[-1]])\n"
            f"os.execv({str(played)!r}, [{str(played)!r}, *args])\n"
        )
        fake.chmod(0o755)
        (self.project / "reach.sh").write_text(
            'host="$FAKE_ASKED/waiting/example.com"\n'
            "looks=0\n"
            'until [ -d "${host%/*}" ] || [ $((looks += 1)) -gt 400 ]; do\n'
            "  sleep 0.05\n"
            "done\n"
            ': > "$host"\n'
            'while [ -e "$host" ] && [ $((looks += 1)) -le 400 ]; do sleep 0.05; done\n'
            'if [ -e "$FAKE_ASKED/allowed/example.com" ]; then\n'
            "  echo was let through\n"
            "else\n"
            "  echo was refused\n"
            "fi\n"
        )

    def test_a_host_a_command_of_the_users_asks_for_can_be_let_through(self):
        # The command waits for the answer, which is a line: one is read
        # while it runs
        self.reaching()
        said = self.at_a_terminal(
            ("> ", "!sh reach.sh\r"),
            ("let the session reach example.com? [y/N] ", Paused("y\r")),
            ("was let through", "\x04"),
            **self.asking(),
        )
        assert "# shell       $ sh reach.sh  (claude is not told)" in said
        assert "# net         allowed example.com until the session ends" in said
        assert "\nwas let through\n" in said

    def test_ctrl_c_at_a_host_that_is_asked_about_refuses_the_request(self):
        self.reaching()
        question = "let the session reach example.com? [y/N] "
        said = self.at_a_terminal(
            # Asked for by what the command left running: no turn runs,
            # and no command of the user's
            ("> ", "!sh reach.sh > reached 2>&1 &\r"),
            (question, "\x03"),
            ("not answered: the request for example.com is refused", "\x04"),
            **self.asking(),
        )
        assert "# chat        Ctrl-C again leaves" in said
        assert "stopping the session" not in said
        # What asked was told so, a moment after the chat was
        reached = self.project / "reached"
        deadline = time.monotonic() + PATIENCE
        while not reached.read_text() and time.monotonic() < deadline:
            time.sleep(0.05)
        assert reached.read_text() == "was refused\n"

    def test_ctrl_c_interrupts_the_turn_that_runs(self):
        said = self.at_a_terminal(
            ("> ", "later\r"),
            ("prompt      later", "\x03"),
            ("interrupting", "\x03"),
            # The docker of the tests stops nothing: left the usual way
            ("stopping the session", "\x04"),
        )
        assert "# chat        interrupting, Ctrl-C again stops" in said
        # The second one stops the session, by its container
        assert "# chat        stopping the session" in said
        assert ["stop", "claude-proj"] in self.calls()

    def test_ctrl_c_interrupts_a_turn_whose_session_floods_its_errors(self):
        said = self.at_a_terminal(
            ("> ", "flood\r"),
            ("\x1b[Jy\r\n", "\x03"),
            ("was stopped", "/exit\r"),
        )
        assert "# chat        interrupting, Ctrl-C again stops" in said
        # No more of it is on the screen than can be read, the rest is
        # counted. However it got there: what the session left on its
        # errors as it ended is written past what counts, a few lines
        shown = re.findall(r"(?:^|\x1b\[J)y$", said, re.MULTILINE)
        assert 0 < len(shown) <= plain.MOST + plain.FEW + pipe.LAST_WORDS
        assert re.search(r"# chat        left out \d+ more lines of the session", said)

    def test_ctrl_c_twice_at_the_prompt_leaves(self):
        said = self.at_a_terminal(
            ("> ", "typed\x03"),
            ("Ctrl-C again leaves", "\x03"),
        )
        assert said.count("# chat        Ctrl-C again leaves") == 1
        # Left as Ctrl-D leaves, the session is not stopped
        assert "prompt      typed" not in said
        assert "stopping the session" not in said
        assert ["stop", "claude-proj"] not in self.calls()


# Reads two lines at a terminal, and says what readline has of the second
# once some of it is typed: the line and where the cursor is in it
TYPING = r"""
import threading, time
from claude_airlock.chat import console

def look():
    typed = ""
    # Editline has the line before, its line break at the end, until a
    # key of the next is typed
    while typed in ("", "abcdef\n"):
        time.sleep(0.05)
        typed = console.readline.get_line_buffer()
    # What is typed comes a key at a time
    time.sleep(0.3)
    typed = console.readline.get_line_buffer()
    point = console._point() if console._point else None
    print(f"\nhad {(typed, point)!r} in all", flush=True)

input("first> ")
threading.Thread(target=look, daemon=True).start()
input("second> ")
"""


@pytest.mark.skipif(not console.readline, reason="this Python has no readline")
class ReadlineTest:
    """What the console takes from readline for granted, whichever
    library it is made with."""

    def test_readline_says_what_is_typed_of_a_line_while_it_is_typed(self):
        # The console writes the line being typed again under what comes
        # meanwhile: as readline has it, the line before it left behind
        environment = {**os.environ, "TERM": "xterm", "PYTHONPATH": str(ROOT)}
        reader = Terminal([sys.executable, "-c", TYPING], environment, PATIENCE)
        with contextlib.closing(reader) as shell:
            shell.read_until("first> ")
            shell.type("abcdef\r")
            shell.read_until("second> ")
            shell.type("xy")
            start = shell.read_until("had ")
            end = shell.read_until(" in all", start) - len(" in all")
        typed, point = ast.literal_eval(shell.seen[start:end].decode())
        library = "editline" if EDITLINE else "GNU readline"
        assert typed == "xy", f"with {library}, the cursor at {point}"
        if point is not None and not EDITLINE:
            # In bytes from the start of the line, where it can be read.
            # Editline leaves it where it was, the console does not ask
            assert point == 2, f"with {library}"


def _screen(written: str) -> list[str]:
    """The rows a terminal of the width a chat is run at shows of what was
    written, those that hold something, each without the blanks at its
    end: what was erased is not among them."""
    screen = pyte.Screen(100, 60)
    # A line feed starts the next row, as the terminal of the pty had it
    screen.set_mode(pyte.modes.LNM)
    pyte.Stream(screen).feed(written)
    return [row.rstrip() for row in screen.display if row.strip()]
