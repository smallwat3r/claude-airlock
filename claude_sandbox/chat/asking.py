"""What claude asks the user while a turn runs: whether it may use a
tool, and the questions it has for them.

The one who listens to claude puts a question and waits. The line that
answers it is read by the one who reads every line, who may be reading
one already: a line that was being typed when the question came was meant
as a prompt, and is not taken for the answer.

What is allowed is what was read. The call is shown whole before it is
asked about, its input is given back as it was shown, and a rule to allow
such calls from now on is said in full before it can be taken."""

from __future__ import annotations

import threading
import time
from collections.abc import Callable

from ..events import clean, flat, labelled
from ..layout import WHAT_WIDTH, painted, prefixed
from ..transcript import call_details
from .console import Console, Page
from .reply import reply_lines

# What the question whether a tool may be used is answered with
YES = ("y", "yes")
ALWAYS = ("a", "always")
REFUSED = {"behavior": "deny", "message": "The user refused this call."}
# Of what a tool is asked to do, in the question whether it may
ABOUT_WIDTH = 200
# A rule longer than this is not offered: it could not be read whole
RULE_WIDTH = 500
# Seconds between two looks at whether there is still someone to ask
LOOK_EVERY = 0.2
# In colour, of the diff of an edit shown whole, the lines it takes out
# and those it puts in, by how they start
DIFF_STYLES = {"  diff: -": "31", "  diff: +": "32", "  diff: @": "36"}


class Question:
    """What the user is asked while a turn runs, and what they say to it."""

    def __init__(self, prompt: str, stale: bool):
        self.prompt = prompt
        # Whether a line was being typed when the question was put: that
        # line was meant as a prompt, and is not taken for the answer
        self.stale = stale
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
    if all(n.isdigit() and 1 <= int(n) <= len(options) for n in numbers):
        return ", ".join(str(options[int(n) - 1].get("label", "")) for n in numbers)
    return typed.strip()


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
        question.answer(line)
        # Over before the next line is read
        self._question = None
        self._console.ask(None)
        return True

    def give_up(self) -> None:
        """Leave the question that waits without an answer: the user left
        or interrupted the turn."""
        question = self._question
        if question:
            question.answer(None)

    def ask(self, prompt: str) -> str | None:
        """Put a question to the user and wait for what they say, none
        for no answer."""
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
        self._page.wrote = time.monotonic()
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
        name = tool.lower()
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
            lines = [labelled("question", flat(text))]
            for number, option in enumerate(options, 1):
                label, more = option.get("label", ""), option.get("description", "")
                lines.append(f"  {number}. {flat(label)}  {flat(more)}".rstrip())
            self._page.say(lines)
            typed = self.ask("answer (a number, several with commas, or in words): ")
            if typed is None:
                return REFUSED
            answers[text] = chosen(typed, options)
        return {"behavior": "allow", "updatedInput": {**tool_input, "answers": answers}}
