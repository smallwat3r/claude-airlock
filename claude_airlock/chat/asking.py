"""What claude asks the user while a turn runs: whether it may use a
tool, and the questions it has for them.

The one who listens to claude puts a question and waits. The line that
answers it is read by the one who reads every line, who may be reading
one already: a line that was being typed when the question came was meant
as a prompt, and is not taken for the answer.

A line that was typed for a question and is not its answer is dropped,
and said to be: entered before the question could be read, or once it
was no longer asked. It was no prompt for claude, a yes least of all.

What is allowed is what was read. The call is shown whole before it is
asked about, its input is given back as it was shown, and a rule to allow
such calls from now on is said in full before it can be taken.

Claude may ask again before it has an answer, a subagent of its does while
another waits: what it asked is put one question at a time, by a thread of
its own (see Asked), and whoever listens to claude goes on listening."""

from __future__ import annotations

import contextlib
import queue
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Protocol

from ..events import clean, flat, labelled
from ..files import HELD_BY_LINE, HELD_BY_VALUE, held_by
from ..report.calls import call_parts, call_whole
from ..report.layout import (
    BLANK,
    BOLD,
    CYAN,
    GREEN,
    HEADER_START,
    RED,
    WHAT_WIDTH,
    YELLOW,
    prefixed,
    together,
)
from .console import Console, Page
from .reply import reply_lines, wrapped
from .said import is_number
from .screen import as_prompt

# How a question that must not be missed is put in colour, bold yellow:
# something waits until the user has answered it
ASKED_STYLE = together(BOLD, YELLOW)
# What the question whether a tool may be used is answered with
YES = ("y", "yes")


def said_yes(typed: str | None) -> bool | None:
    """Whether what was typed to a question is a yes, none for no answer.
    Anything else is a no: what is not asked for is not allowed."""
    return None if typed is None else typed.strip().lower() in YES


ALWAYS = ("a", "always")
REFUSED = {"behavior": "deny", "message": "The user refused this call."}
# Of what a tool is asked to do, in the question whether it may
ABOUT_WIDTH = 200
# Of the name of a tool in a question
NAME_WIDTH = 80
# A rule longer than this is not offered: it could not be read whole
RULE_WIDTH = 500
# Seconds between two looks at whether there is still someone to ask
LOOK_EVERY = 0.2
# Where what is being typed cannot be seen (see sees_typing of Console), a
# line entered sooner than this after a question came before the user was
# typed before it could be read: it is not the answer, a yes among them
# would allow a tool unseen
TOO_SOON = 1.0
# Where it can be seen, what was typed before the question came is known
# (see meant_before): a line entered right after it is one whose keys
# were on their way, Enter pressed twice or a yes meant for the question
# before this one. Shorter there, for who answers one question after the
# other not to be held up: nobody reads one and types two keys in less,
# and a key pressed twice comes sooner
SEEN_TOO_SOON = 0.5
# What is said of a line that is dropped: entered before the question
# could be read, and typed for a question that is no longer asked, as
# far as can be told, so the user is told how it is a prompt after all
EARLY = (
    "that line came before the question could be read, it is dropped:"
    " neither the answer nor a prompt"
)
LATE = (
    "that line was typed for a question that is no longer asked, it is"
    " dropped: enter it again if it is a prompt"
)
# What is said of a question claude withdrew while it was before the user
WITHDRAWN = "claude no longer asks that, it is not answered"
# What is said of an answer to what claude asked that could not be said
# to it, a session that has long read nothing it is told: it waits for
# that answer, and its turn with it, until it is stopped
NOT_ANSWERED = (
    "the answer to claude was not sent, the session does not read what it"
    " is told: Ctrl-C stops it"
)
# The least room the text of a question or an option is wrapped to,
# however far in it starts
NARROWEST_TEXT = 20
# In colour, of the diff of an edit shown whole, the lines it takes out
# and those it puts in, by how they start
DIFF_STYLES = {"  diff: -": RED, "  diff: +": GREEN, "  diff: @": CYAN}
# No more of what claude asked than this waits for its turn to be put,
# the one being put too, nor more bytes of it than MOST_WAITING_BYTES as
# it is held (see waiting_size): what comes past either is refused at
# once. A session can ask any number of times while the first question
# waits for the user, each time with an input as large as a line may
# be. One alone is always kept, however large: it is bounded as a line
MOST_WAITING = 100
MOST_WAITING_BYTES = 256 << 20


class Question:
    """What the user is asked while a turn runs, and what they say to it."""

    def __init__(self, stale: str = ""):
        # What was typed of a line when the question was put, empty for
        # nothing: that line was meant as a prompt, and is not taken for
        # the answer, see meant_before
        self.stale = stale
        self.answered = threading.Event()
        # None for no answer: the input ended, or Ctrl-C
        self.said: str | None = None
        # When it was no longer asked, none while it is, and what was
        # typed for it of a line by then, see gone
        self.went: float | None = None
        self.left = ""

    def meant_before(self, line: str) -> bool:
        """Whether a line that was entered is the one that was being
        typed when the question was put, as it was or typed on: asked
        once, of the first line entered since. Not one that starts
        otherwise: what was being typed was dropped for it, and it was
        typed with the question to read. Nor when all that was typed
        was space, which any line can start with."""
        was, self.stale = self.stale, ""
        return bool(was.strip()) and line.startswith(was)

    def answer(self, said: str | None) -> bool:
        """Take what was said first, a question is answered once.
        Whether this was taken."""
        if self.answered.is_set():
            return False
        self.said = said
        self.answered.set()
        return True

    def gone(self, typed: str) -> None:
        """It is no longer asked: note when, and what was typed of a
        line by then, which was typed with the question to read. Unless
        it is the line that was being typed when the question was put,
        and still is."""
        self.went = time.monotonic()
        before = self.stale
        self.left = "" if before.strip() and typed.startswith(before) else typed

    def meant_after(self, line: str, moment: float) -> bool:
        """Whether a line that was entered once the question was no
        longer asked was typed for it all the same: the one that was
        being typed when it went, as it was or typed on, or one entered
        within a moment of that, sooner than anyone sees that it went.
        Not the line that was being typed when the question was put."""
        if self.went is None or self.meant_before(line):
            return False
        if self.left.strip() and line.startswith(self.left):
            return True
        return time.monotonic() - self.went < moment


def chosen(typed: str, options: list[dict]) -> str:
    """The answer to a question: the labels of the options named by their
    numbers, or what was typed as it is."""
    numbers = [part.strip() for part in typed.split(",")]
    if all(is_number(n) and 1 <= int(n) <= len(options) for n in numbers):
        return ", ".join(str(options[int(n) - 1].get("label", "")) for n in numbers)
    return typed.strip()


def _laid_out(start: str, text: str, width: int | None) -> list[str]:
    """A text after what it starts with, as the lines that fit a width,
    those that follow as far in as the first. A line as long as it is
    without a width, see Page.width. The lines are said as header lines,
    whose prefix takes room too."""
    if width is None or not text:
        return [(start + text).rstrip()]
    room = max(len(start) + NARROWEST_TEXT, width - len(HEADER_START))
    return wrapped(start + text, room, " " * len(start))


def _suggested_rule(request: dict) -> tuple[str, dict] | None:
    """The rule claude suggests to allow calls like the one it asks about
    from now on, as it is said and as it is given back: for this session,
    whatever claude suggested to write it to. None when it suggests none,
    or one too long to be read."""
    given = request.get("permission_suggestions")
    for suggestion in given if isinstance(given, list) else []:
        if not isinstance(suggestion, dict):
            continue
        rules = suggestion.get("rules")
        if (
            suggestion.get("type") != "addRules"
            or suggestion.get("behavior") != "allow"
        ):
            continue
        if not isinstance(rules, list) or not all(isinstance(r, dict) for r in rules):
            continue
        said = ", ".join(
            flat(rule.get("toolName", "?"))
            + (f"({flat(rule['ruleContent'])})" if rule.get("ruleContent") else "")
            for rule in rules
        )
        if not rules or len(said) > RULE_WIDTH:
            return None
        return said, {**suggestion, "destination": "session"}
    return None


def waiting_size(request: dict, most: int = MOST_WAITING_BYTES) -> int:
    """About how many bytes what claude asked takes as it waits, as
    held_size counts what was read: for each character of a text as
    many as held_by says of it, and so many for each value. Counted no
    further than past most: what is larger is not kept anyway, and one
    of a great many small values would else be gone through whole. A
    value at a time, not a level of it at a time by calling itself: what
    was read can be nested deeper than that goes."""
    held = HELD_BY_LINE
    left: list[object] = [request]
    while left and held <= most:
        value = left.pop()
        held += HELD_BY_VALUE
        if isinstance(value, str):
            held += held_by(value) * len(value)
        elif isinstance(value, dict):
            left += value.keys()
            left += value.values()
        elif isinstance(value, list):
            left += value
    return held


@dataclass(frozen=True)
class Unanswered:
    """What claude asked under an id and has no answer to yet, and
    whether it withdrew it since (control_cancel_request), which it then
    waits for no answer to. What it withdrew is not put while it waits
    for its turn, nor any longer while it is put, a line says so when
    its question was before the user, and it is not answered."""

    asked: str
    request: dict
    # How often the asker had given up when it was asked, see attend
    asked_at: int
    # How large it is as it waits, see waiting_size
    size: int
    withdrawn: threading.Event = field(default_factory=threading.Event)


class Asker:
    """Puts what claude asks to the user and makes of what they say the
    answer claude gets."""

    def __init__(
        self,
        page: Page,
        console: Console,
        project_dir: str,
        gone: Callable[[], bool],
        on_ask: Callable[[], None],
    ):
        self._page = page
        self._console = console
        self._project_dir = project_dir
        # Whether there is nobody left to ask, and what to do when a
        # question is put
        self._gone = gone
        self._on_ask = on_ask
        self._question: Question | None = None
        # Held to put a question and to let go of one: the thread that
        # reads what is typed lets go of the one it answers, and must not
        # take the next for it, which another thread has put meanwhile
        self._putting = threading.Lock()
        # The question that was last let go of, until a line is entered:
        # that line may have been typed for it, see _for_one_gone
        self._went: Question | None = None
        # How often what was asked was given up on, and how often it had
        # been when what is now put was asked, none for what the chat
        # asks itself: what claude asked before the last time is not put
        self._given_up = 0
        self._attended: int | None = None
        # What claude asked that is attended to, none for what the chat
        # asks itself, see Unanswered
        self._unanswered: Unanswered | None = None
        # The tools the user allowed until the session ends, where claude
        # had no rule to suggest
        self._allowed: set[str] = set()

    @property
    def asking(self) -> bool:
        return self._question is not None

    def take(self, line: str) -> bool:
        """Give a line the user entered to the question that waits for
        one. Whether the line is done with: the answer, or one that was
        typed for a question and is no answer, which is said and dropped
        (see the module). Not a line that was being typed when the
        question was put, nor one without a question to be for: those
        are for claude."""
        with self._putting:
            question = self._question
            went, self._went = self._went, None
        if question is None or question.meant_before(line):
            return self._for_one_gone(went, line)
        # Counted from when the question came before the user, not from
        # when it was put: a command of theirs can run in between, and
        # nothing is read then. A line entered before it came is none
        # for it wherever it was typed.
        shown = self._console.asked_for()
        if shown is None and not self._console.interactive:
            # Not typed: a line of a file was read before the question
            # was put, and is the prompt it was written as
            early = "that line came before the question could be read"
            self._page.note("chat", f"{early}, it is not taken for the answer")
            return False
        if shown is None or shown < self._too_soon():
            self._page.note("chat", EARLY)
            return True
        # Over before the next line is read, and before its answer wakes
        # the thread that puts the next question: that one must stay
        if not (self._let_go(question) and question.answer(line)):
            # Given up on meanwhile: the line was typed for it, and is
            # no answer to what is asked now
            question.left = ""
            self._page.note("chat", LATE)
        return True

    def _too_soon(self) -> float:
        """The seconds within which a line that is entered was not typed
        for what is before the user, see TOO_SOON: none where the lines
        are not typed, each is there for what comes next."""
        if not self._console.interactive:
            return 0.0
        return SEEN_TOO_SOON if self._console.sees_typing else TOO_SOON

    def _for_one_gone(self, went: Question | None, line: str) -> bool:
        """Whether a line that answers no question was typed for the
        one that was let go of before it, see meant_after: it is then
        said and dropped. A y typed for a question that was given up on
        in that moment is no prompt, nor is the second of two that were
        typed for one. Nothing is said of a line with nothing on it,
        which is no prompt anyway."""
        if went is None or not line.strip():
            return False
        if not went.meant_after(line, self._too_soon()):
            return False
        self._page.note("chat", LATE)
        return True

    def _let_go(self, question: Question) -> bool:
        """No longer ask a question, whether it was the one being asked:
        not when another has been put since, which stays."""
        with self._putting:
            if self._question is not question:
                return False
            self._question = None
            question.gone(self._console.typed())
            self._went = question
            self._console.ask(None)
            return True

    def line_dropped(self) -> None:
        """Ctrl-C dropped the line being typed, where no turn runs for
        it to interrupt. What was typed of that line for a question that
        went is gone with it, and the question that waits is left
        without an answer, which refuses what it asks: that one alone,
        what waits to be put after it is still put. Not for the handler
        of a signal, see give_up."""
        with self._putting:
            question, went = self._question, self._went
        if went:
            went.left = ""
        if question:
            question.answer(None)

    def give_up(self) -> None:
        """Leave the question that waits without an answer, and what
        claude asked that waits to be put (see attend): the user left or
        interrupted the turn. Not for the handler of a signal: a question
        is answered under a lock the thread it interrupts may hold."""
        self._given_up += 1
        question = self._question
        if question:
            question.answer(None)

    @property
    def given_up(self) -> int:
        """How often what was asked was given up on, to tell what was
        asked before the last time, see attend."""
        return self._given_up

    def attend(
        self, asked_at: int | None, unanswered: Unanswered | None = None
    ) -> bool:
        """Turn to what was asked when given_up was as said, none for
        what the chat asks itself, and with what claude asked, see
        Unanswered. Whether it is still to be put: not what claude asked
        of a turn that was interrupted since, nor what it withdrew, nor
        anything once nobody is left to ask."""
        self._attended = asked_at
        self._unanswered = unanswered
        return self._wanted()

    def _withdrawn(self) -> bool:
        """Whether claude withdrew what is attended to."""
        unanswered = self._unanswered
        return unanswered is not None and unanswered.withdrawn.is_set()

    def _wanted(self) -> bool:
        attended = self._attended in (None, self._given_up)
        return not self._gone() and not self._withdrawn() and attended

    def ask(self, prompt: str, style: str = "") -> str | None:
        """Put a question to the user and wait for what they say, none
        for no answer. In a style where there is colour, for a question
        that must not be missed. None without a word when it is no longer
        wanted, see attend."""
        if not self._wanted():
            return None
        shown = as_prompt(prompt, style if self._page.layout.colour else "")
        question = Question(stale=self._console.typed())
        if question.stale.strip():
            # It is written again after the question, where it looks like
            # the answer
            not_it = "what you were typing is not taken for the answer"
            self._page.say(
                [labelled("chat", f"{not_it}, enter it or drop it (Ctrl-U) first")]
            )
        with self._putting:
            self._question = question
            self._console.ask(shown)
        self._console.bell()
        self._on_ask()
        while not question.answered.wait(LOOK_EVERY):
            if self._gone():
                break
            if self._withdrawn() and question.answer(None):
                self._page.note("chat", WITHDRAWN)
        # Unless answered by a line, which has let go of it
        self._let_go(question)
        self._page.touched()
        return question.said

    def decide(self, request: dict) -> dict:
        """What claude is told about a tool it asks to use."""
        tool = clean(request.get("tool_name", "?"))
        given = request.get("input")
        tool_input = given if isinstance(given, dict) else {}
        if tool == "AskUserQuestion":
            return self._questions(tool_input)
        return self._permission(tool, tool_input, _suggested_rule(request))

    def _acted(self, tool: str, tool_input: dict, whole: list[str]) -> list[str]:
        """The lines of a call as it would be made, given those it is
        shown whole with. Not the reason claude gives for a command,
        which is no part of what runs."""
        if tool != "Bash":
            return whole
        acted = {key: said for key, said in tool_input.items() if key != "description"}
        return call_whole(tool, acted, self._project_dir)

    def _reviewed(self, tool: str, tool_input: dict) -> str:
        """Show the call that is asked about, and give what the question
        names it by: its first line. Shown whole, from what claude asks
        here, unless that line is all of it: a command of several lines,
        the diff of an edit, the arguments of a tool, the plan claude
        wants to act on. A command or a plan is claude's to write, and
        is written as its word is (see Page.said): the lines of a call
        under the line that says they are, a plan as a reply. What the
        transcript told of the call is not relied on for it, a line of a
        subagent's can come after the question. A plan comes with every
        other argument of its call, which a yes allows as well: those that
        grant what the plan needs (allowedPrompts) among them."""
        details, rest = call_parts(tool, tool_input, self._project_dir)
        acted = self._acted(tool, tool_input, details + rest)
        named = flat(acted[0]) if acted else ""
        plan = tool_input.get("plan")
        if tool == "ExitPlanMode" and isinstance(plan, str):
            width, colour = self._page.width, self._page.layout.colour
            self._page.note("plan", "what claude asks to go ahead with:")
            self._page.put(
                [*self._page.replied(reply_lines(plan, width, colour)), BLANK]
            )
            # Every other argument, and what does not show in any, the plan
            # too: its reply leaves that out
            besides = call_whole(tool, tool_input, self._project_dir, ("plan",))
            if besides:
                self._page.note("plan", "what else a yes allows with it:")
                self._page.put_said(prefixed("  ", besides))
        elif len(acted) > 1 or len(named) > ABOUT_WIDTH:
            # On one line: a name is claude's to give, and what followed
            # a line break in it would read as a line of the chat's own
            name = flat(tool).lower()[:WHAT_WIDTH]
            self._page.say([f"{name:<{WHAT_WIDTH}}  the call whole:"])
            # Of an Edit, what call_details tells of it has its diff, in
            # colour. Not the arguments it has besides, nor those of any
            # other tool, whatever they are named: one named diff would
            # pass for the diff, a line that is taken out for one that is
            # put in
            diffed, plain = (details, rest) if tool == "Edit" else ([], details + rest)
            diff = self._page.said(
                prefixed("  ", diffed), lambda line: DIFF_STYLES.get(line[:9], "")
            )
            self._page.put(diff + self._page.said(prefixed("  ", plain)))
        return named[:ABOUT_WIDTH]

    def _permission(
        self, tool: str, tool_input: dict, rule: tuple[str, dict] | None
    ) -> dict:
        """Ask whether a tool may be used as claude wants to. Anything
        but a yes or an always refuses, no answer too. Always takes the
        rule claude suggests, for this session, or without one the whole
        tool, which the chat then remembers itself."""
        allowed = {"behavior": "allow", "updatedInput": tool_input}
        if tool in self._allowed:
            return allowed
        call = self._reviewed(tool, tool_input)
        # On one line and no longer than a name: it is claude's to give
        name = flat(tool).lower()[:NAME_WIDTH]
        scope = rule[0] if rule else f"every call of {name}"
        self._page.note("chat", f"a: not asked again in this session for {scope}")
        typed = self.ask(f"allow {name} {call}? [y/a/N] ")
        answer = typed.strip().lower() if typed is not None else ""
        if answer in ALWAYS and rule:
            return {**allowed, "updatedPermissions": [rule[1]]}
        if answer in ALWAYS:
            self._allowed.add(tool)
            return allowed
        return allowed if said_yes(typed) else REFUSED

    def _questions(self, tool_input: dict) -> dict:
        """Put the questions claude has for the user, each with its
        options, and give it the answers."""
        asked = tool_input.get("questions")
        answers = {}
        for question in asked if isinstance(asked, list) else []:
            if not isinstance(question, dict):
                continue
            given = question.get("options")
            listed = given if isinstance(given, list) else []
            options = [option for option in listed if isinstance(option, dict)]
            text = str(question.get("question", ""))
            width = self._page.width
            lines = _laid_out(labelled("question", ""), flat(text), width)
            for number, option in enumerate(options, 1):
                start = f"  {number}. "
                lines += _laid_out(start, flat(option.get("label", "")), width)
                more = flat(option.get("description", ""))
                if more:
                    lines += _laid_out(" " * len(start), more, width)
            self._page.say(lines)
            typed = self.ask("answer (a number, several with commas, or in words): ")
            if typed is None:
                return REFUSED
            answers[text] = chosen(typed, options)
        return {"behavior": "allow", "updatedInput": {**tool_input, "answers": answers}}


class Answered(Protocol):
    """Who is given the answer to what it asked under an id, each time
    whether it could be: claude, see Agent."""

    def respond(self, asked: str, decision: dict) -> bool: ...

    def refuse(self, asked: str, why: str) -> bool: ...


class Asked:
    """What claude asked and has no answer to yet, put to the user one
    question after the other on a thread of its own, and each answer
    given to claude. No more of it waits than MOST_WAITING says: it is
    held until it is answered, and the user answers one at a time."""

    def __init__(self, asker: Asker, page: Page):
        self._asker = asker
        self._page = page
        # Each what claude asked, or what the chat itself has to ask, then
        # None when nothing more is asked
        self._waiting: queue.Queue[Unanswered | Callable[[], None] | None] = (
            queue.Queue()
        )
        # How many of them have no answer yet, the one being put too
        self._count = 0
        self._counting = threading.Lock()
        # What claude asked and has no answer yet, by the id it asked
        # under, for it to be withdrawn by, see cancel
        self._unanswered: dict[str, Unanswered] = {}
        # How many of what claude asked have no answer yet, and how large
        # they are together, see MOST_WAITING: counted apart from the
        # ids, claude can ask under one of them twice
        self._kept = 0
        self._kept_bytes = 0

    def start(self, claude: Answered) -> None:
        """Have what is asked from now on put, and claude given each
        answer, until nothing more is asked, see close."""
        threading.Thread(target=self._decide, args=(claude,), daemon=True).start()

    def put(self, asked: str, request: dict) -> bool:
        """Keep what claude asked under an id until its turn comes, and
        whether it is: not past MOST_WAITING, which claude is to be
        refused at once. Whoever listens to claude is not held up by it."""
        size = waiting_size(request)
        unanswered = Unanswered(asked, request, self._asker.given_up, size)
        with self._counting:
            full = self._kept >= MOST_WAITING
            if self._kept and (full or self._kept_bytes + size > MOST_WAITING_BYTES):
                return False
            self._kept += 1
            self._kept_bytes += size
            self._count += 1
            self._unanswered[asked] = unanswered
        self._waiting.put(unanswered)
        return True

    def cancel(self, asked: str) -> None:
        """Claude no longer asks what it asked under an id, and waits for
        no answer to it (control_cancel_request): see Unanswered."""
        with self._counting:
            unanswered = self._unanswered.get(asked)
        if unanswered is not None:
            unanswered.withdrawn.set()

    def then(self, ask: Callable[[], None]) -> None:
        """Have the chat ask something of its own when its turn comes,
        on the thread the questions of claude are put on: one question
        waits for a line at a time."""
        with self._counting:
            self._count += 1
        self._waiting.put(ask)

    def close(self) -> None:
        """Nothing more is asked: claude has ended."""
        self._waiting.put(None)

    def answered_within(self, seconds: float) -> bool:
        """Whether all that claude asked has its answer, once that long
        was waited for it at most."""
        patience = time.monotonic() + seconds
        while self._count and time.monotonic() < patience:
            time.sleep(0.05)
        return not self._count

    def _decide(self, claude: Answered) -> None:
        """Put each question and give claude its answer. One that cannot
        be put is refused: claude waits for an answer to each. Whatever
        becomes of one, the next is put: a thread that ended here would
        put no question again, of claude's or of the chat's own."""
        while True:
            waiting = self._waiting.get()
            if waiting is None:
                return
            try:
                if isinstance(waiting, Unanswered):
                    self._answered(claude, waiting)
                else:
                    self._own(waiting)
            except Exception as error:  # noqa: BLE001
                with contextlib.suppress(Exception):
                    self._page.note("chat", f"FAILED to answer: {flat(repr(error))}")
            finally:
                with self._counting:
                    self._count -= 1

    def _answered(self, claude: Answered, unanswered: Unanswered) -> None:
        """Put what claude asked and give it the answer. What it asked
        of a turn the user interrupted since is refused unseen, as the
        question that was on the screen then was: claude waits for an
        answer to each. Unless it withdrew what it asked, see Unanswered.
        An answer that could not be said to it is said not to be."""
        asked, withdrawn = unanswered.asked, unanswered.withdrawn
        try:
            wanted = self._asker.attend(unanswered.asked_at, unanswered)
            decision = self._asker.decide(unanswered.request) if wanted else REFUSED
            if not withdrawn.is_set() and not claude.respond(asked, decision):
                self._page.note("chat", NOT_ANSWERED)
        except Exception as error:  # noqa: BLE001
            self._page.note("chat", f"FAILED to ask, refused: {flat(repr(error))}")
            if not withdrawn.is_set() and not claude.refuse(
                asked, "the question could not be put"
            ):
                self._page.note("chat", NOT_ANSWERED)
        finally:
            with self._counting:
                self._kept -= 1
                self._kept_bytes -= unanswered.size
                if self._unanswered.get(asked) is unanswered:
                    del self._unanswered[asked]

    def _own(self, ask: Callable[[], None]) -> None:
        """Put what the chat itself asks. One that fails is said, the
        questions after it are still put."""
        try:
            self._asker.attend(None)
            ask()
        except Exception as error:  # noqa: BLE001
            self._page.note("chat", f"FAILED to ask: {flat(repr(error))}")
