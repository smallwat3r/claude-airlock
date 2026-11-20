"""What claude asks the user while a turn runs: whether it may use a
tool, and the questions it has for them.

The one who listens to claude puts a question and waits. The line that
answers it is read by the one who reads every line, who may be reading
one already: a line that was being typed when the question came was meant
as a prompt, and is not taken for the answer.

What is allowed is what was read. The call is shown whole before it is
asked about, its input is given back as it was shown, and a rule to allow
such calls from now on is said in full before it can be taken.

Claude may ask again before it has an answer, a subagent of its does while
another waits: what it asked is put one question at a time, by a thread of
its own (see Asked), and whoever listens to claude goes on listening."""

from __future__ import annotations

import queue
import threading
import time
from collections.abc import Callable
from typing import Protocol

from ..events import clean, flat, labelled
from ..report.calls import call_details
from ..report.layout import (
    BOLD,
    CYAN,
    GREEN,
    HEADER_START,
    RED,
    WHAT_WIDTH,
    YELLOW,
    painted,
    prefixed,
    together,
)
from .console import Console, Page
from .reply import reply_lines, wrapped
from .said import is_number

# How a question that must not be missed is put in colour, bold yellow:
# something waits until the user has answered it
ASKED_STYLE = together(BOLD, YELLOW)
# What the question whether a tool may be used is answered with
YES = ("y", "yes")
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
# line entered sooner than this after a question was put was typed before
# it could be read: it is not the answer, a yes among them would allow a
# tool unseen
TOO_SOON = 1.0
# The least room the text of a question or an option is wrapped to,
# however far in it starts
NARROWEST_TEXT = 20
# In colour, of the diff of an edit shown whole, the lines it takes out
# and those it puts in, by how they start
DIFF_STYLES = {"  diff: -": RED, "  diff: +": GREEN, "  diff: @": CYAN}


class Question:
    """What the user is asked while a turn runs, and what they say to it."""

    def __init__(self, prompt: str, stale: bool):
        self.prompt = prompt
        # Whether a line was being typed when the question was put: that
        # line was meant as a prompt, and is not taken for the answer
        self.stale = stale
        self.put = time.monotonic()
        self.answered = threading.Event()
        # None for no answer: the input ended, or Ctrl-C
        self.said: str | None = None

    def answer(self, said: str | None) -> None:
        """Take what was said first, a question is answered once."""
        if not self.answered.is_set():
            self.said = said
            self.answered.set()


def chosen(typed: str, options: list[dict]) -> str:
    """The answer to a question: the labels of the options named by their
    numbers, or what was typed as it is."""
    numbers = [part.strip() for part in typed.split(",")]
    if all(is_number(n) and 1 <= int(n) <= len(options) for n in numbers):
        return ", ".join(str(options[int(n) - 1].get("label", "")) for n in numbers)
    return typed.strip()


def laid_out(start: str, text: str, width: int | None) -> list[str]:
    """A text after what it starts with, as the lines that fit a width,
    those that follow as far in as the first. A line as long as it is
    without a width, see Page.width. The lines are said as header lines,
    whose prefix takes room too."""
    if width is None or not text:
        return [(start + text).rstrip()]
    room = max(len(start) + NARROWEST_TEXT, width - len(HEADER_START))
    return wrapped(start + text, room, " " * len(start))


def suggested_rule(request: dict) -> tuple[str, dict] | None:
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
        # The tools the user allowed until the session ends, where claude
        # had no rule to suggest
        self._allowed: set[str] = set()

    @property
    def asking(self) -> bool:
        return self._question is not None

    def take(self, line: str) -> bool:
        """Give a line the user typed to the question that waits for one.
        Whether it was its answer: not without a question, and not a line
        that was being typed when it was put."""
        question = self._question
        if question is None:
            return False
        if question.stale:
            question.stale = False
            return False
        unseen = self._console.interactive and not self._console.sees_typing
        if unseen and time.monotonic() - question.put < TOO_SOON:
            early = "that line came before the question could be read"
            self._page.say(
                [labelled("chat", f"{early}, it is not taken for the answer")]
            )
            return False
        # Over before the next line is read, and before its answer wakes
        # the thread that puts the next question: that one must stay
        self._question = None
        self._console.ask(None)
        question.answer(line)
        return True

    def give_up(self) -> None:
        """Leave the question that waits without an answer: the user left
        or interrupted the turn."""
        question = self._question
        if question:
            question.answer(None)

    def ask(self, prompt: str, style: str = "") -> str | None:
        """Put a question to the user and wait for what they say, none
        for no answer. In a style where there is colour, for a question
        that must not be missed."""
        if self._page.layout.colour:
            prompt = painted(style, prompt)
        question = Question(prompt, stale=bool(self._console.typed()))
        if question.stale:
            # It is written again after the question, where it looks like
            # the answer
            not_it = "what you were typing is not taken for the answer"
            self._page.say(
                [labelled("chat", f"{not_it}, enter it or drop it (Ctrl-U) first")]
            )
        self._question = question
        self._console.ask(prompt)
        self._console.bell()
        self._on_ask()
        while not question.answered.wait(LOOK_EVERY):
            if self._gone():
                break
        if self._question is question:
            # Not answered by a line, which would have let go of it
            self._question = None
            self._console.ask(None)
        self._page.touched()
        return question.said

    def decide(self, request: dict) -> dict:
        """What claude is told about a tool it asks to use."""
        tool = clean(request.get("tool_name", "?"))
        given = request.get("input")
        tool_input = given if isinstance(given, dict) else {}
        if tool == "AskUserQuestion":
            return self._questions(tool_input)
        return self._permission(tool, tool_input, suggested_rule(request))

    def _reviewed(self, tool: str, tool_input: dict, brief: list[str]) -> None:
        """Show a call whole when the line that told of it was cut: the
        plan claude wants to act on, the diff of an edit, a long
        command."""
        plan = tool_input.get("plan")
        if tool == "ExitPlanMode" and isinstance(plan, str):
            lines = reply_lines(plan, self._page.width, self._page.layout.colour)
            self._page.note("plan", "what claude asks to go ahead with:")
            self._page.put([*lines, ""])
            return
        whole = call_details(tool, tool_input, None, self._project_dir, True)
        if whole != brief:
            name = tool.lower()[:WHAT_WIDTH]
            self._page.say([f"{name:<{WHAT_WIDTH}}  the call whole:"])
            lines = prefixed("  ", whole)
            if self._page.layout.colour:
                lines = [painted(DIFF_STYLES.get(line[:9], ""), line) for line in lines]
            self._page.put(lines)

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
        details = call_details(tool, tool_input, None, self._project_dir, False)
        self._reviewed(tool, tool_input, details)
        # On one line and no longer than a name: it is claude's to give
        name = flat(tool).lower()[:NAME_WIDTH]
        scope = rule[0] if rule else f"every call of {name}"
        self._page.note("chat", f"a: not asked again in this session for {scope}")
        call = flat(details[0])[:ABOUT_WIDTH] if details else ""
        typed = self.ask(f"allow {name} {call}? [y/a/N] ")
        answer = typed.strip().lower() if typed is not None else ""
        if answer in ALWAYS and rule:
            return {**allowed, "updatedPermissions": [rule[1]]}
        if answer in ALWAYS:
            self._allowed.add(tool)
            return allowed
        return allowed if answer in YES else REFUSED

    def _questions(self, tool_input: dict) -> dict:
        """Put the questions claude has for the user, each with its
        options, and give it the answers."""
        asked = tool_input.get("questions")
        answers = {}
        for question in asked if isinstance(asked, list) else []:
            if not isinstance(question, dict):
                continue
            options = question.get("options")
            options = [o for o in options or [] if isinstance(o, dict)]
            text = str(question.get("question", ""))
            width = self._page.width
            lines = laid_out(labelled("question", ""), flat(text), width)
            for number, option in enumerate(options, 1):
                start = f"  {number}. "
                lines += laid_out(start, flat(option.get("label", "")), width)
                more = flat(option.get("description", ""))
                if more:
                    lines += laid_out(" " * len(start), more, width)
            self._page.say(lines)
            typed = self.ask("answer (a number, several with commas, or in words): ")
            if typed is None:
                return REFUSED
            answers[text] = chosen(typed, options)
        return {"behavior": "allow", "updatedInput": {**tool_input, "answers": answers}}


class Answered(Protocol):
    """Who is given the answer to what it asked under an id: claude, see
    Agent."""

    def respond(self, asked: object, decision: dict) -> None: ...

    def refuse(self, asked: object, why: str) -> None: ...


class Asked:
    """What claude asked and has no answer to yet, put to the user one
    question after the other on a thread of its own, and each answer
    given to claude."""

    def __init__(self, asker: Asker, page: Page):
        self._asker = asker
        self._page = page
        # Each the id claude asked under and the request, or what the chat
        # itself has to ask, then None when nothing more is asked
        self._waiting: queue.Queue[tuple[object, dict] | Callable[[], None] | None] = (
            queue.Queue()
        )
        # How many of them have no answer yet, the one being put too
        self._count = 0
        self._counting = threading.Lock()

    def start(self, claude: Answered) -> None:
        """Have what is asked from now on put, and claude given each
        answer, until nothing more is asked, see close."""
        threading.Thread(target=self._decide, args=(claude,), daemon=True).start()

    def put(self, asked: object, request: dict) -> None:
        """Keep what claude asked under an id until its turn comes. Whoever
        listens to claude is not held up by it."""
        with self._counting:
            self._count += 1
        self._waiting.put((asked, request))

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

    @property
    def pending(self) -> int:
        """How many of what claude asked have no answer yet."""
        return self._count

    def answered_within(self, seconds: float) -> bool:
        """Whether all that claude asked has its answer, once that long
        was waited for it at most."""
        patience = time.monotonic() + seconds
        while self._count and time.monotonic() < patience:
            time.sleep(0.05)
        return not self._count

    def _decide(self, claude: Answered) -> None:
        """Put each question and give claude its answer. One that cannot
        be put is refused: claude waits for an answer to each."""
        while True:
            waiting = self._waiting.get()
            if waiting is None:
                return
            try:
                if callable(waiting):
                    self._own(waiting)
                else:
                    self._answered(claude, *waiting)
            finally:
                with self._counting:
                    self._count -= 1

    def _answered(self, claude: Answered, asked: object, request: dict) -> None:
        """Put what claude asked and give it the answer."""
        try:
            claude.respond(asked, self._asker.decide(request))
        except Exception as error:  # noqa: BLE001
            self._page.note("chat", f"FAILED to ask, refused: {flat(repr(error))}")
            claude.refuse(asked, "the question could not be put")

    def _own(self, ask: Callable[[], None]) -> None:
        """Put what the chat itself asks. One that fails is said, the
        questions after it are still put."""
        try:
            ask()
        except Exception as error:  # noqa: BLE001
            self._page.note("chat", f"FAILED to ask: {flat(repr(error))}")
