"""Signs that what a session read was written to instruct it: a page it
fetched, a file of the project, the output of a command or of a tool of a
server. Whoever wrote that can ask the session for anything, and a session
is not asked before it uses a tool (see the known limits of the README).

A sign is a way of writing, not proof: words that turn the reader against
its user, the markup a conversation is written in, text that is not
shown. What is found is said for the user to look at, nothing is kept
from the session: it had read the text before the launcher could. A text
can ask the same in words no pattern here knows, so nothing found does
not make what was read safe to follow.

Every pattern is bounded in what it repeats: the text is a stranger's to
write, and none may take more than a pass over it."""

from __future__ import annotations

import re
import unicodedata
from collections.abc import Callable, Iterable
from dataclasses import dataclass

from ..events import clean, flat

# Of a text, how much is looked at, well past what Claude Code gives the
# model of one result: what a call puts out beyond that is kept in a
# file, and is seen when that is read
MOST_SCANNED = 400_000
# Of what was found, how much is shown with what is around it: the
# lines it is on whole, with those next to them, for the user to read
# what was asked without opening what was read. Bounded all the same, a
# page can be one line of any length
EXCERPT_WIDTH = 1000
EXCERPT_BEFORE = 200
EXCERPT_LINES_BEFORE = 1
EXCERPT_LINES_AFTER = 4
# What a line is cut with, where it is not shown whole
CUT = "..."
# What starts each line shown of what was read, under the line that
# tells of the sign: no such line can pass for one of the trace's own
QUOTED = "| "
# What starts the line that tells of a sign
FLAG = "POSSIBLE INJECTION"
# Of where a sign was read, how much is said with it: a path or an
# address is the session's to write, and can be of any length
SOURCE_WIDTH = 200
# What an event names the signs found in what it tells of, for --json
# and for what went wrong
INJECTION = "injection"

# The line number a file is read with, ahead of what a line starts with
_NUMBERED = r"(?:[ \t]*\d+\t)?[ \t]*"
# What a session holds that is worth sending out
_SECRET = (
    r"(?:api[\s_-]?keys?|(?:access\s+|auth\w*\s+)?tokens?|passwords?|credentials?"  # noqa: S105
    r"|secrets?|private\s+keys?|ssh\s+keys?|\.env\b|environment\s+variables?"
    r"|cookies?)"
)
# What the name of a tag is made of when it is written to read as a part
# of the conversation that is not the page's to write: who speaks, then
# what it is. One of the two alone names much that is harmless
# (<context-param>, <user-name>, <warning>).
_SPEAKER = (
    r"(?:system|sys|ctx|context|admin|developer|operator|assistant|user|human"
    r"|tool|function|anthropic|claude|model|agent|security|safety|important"
    r"|urgent|priority|critical)"
)
_SPOKEN = (
    r"(?:warnings?|interruptions?|interrupts?|reminders?|overrides?"
    r"|instructions?|prompts?|messages?|notices?|alerts?|directives?"
    r"|commands?|updates?|polic(?:y|ies)|calls?|results?|quer(?:y|ies)"
    r"|turns?|notes?)"
)
# The tags Claude Code itself writes what it tells the model in, those
# whose word the model takes for the user's, the program's or another
# agent's: what a command of the user's is and said, what a hook, a task,
# a teammate or another session reported, what a fork is to do. Text in
# one of them passes for more than what was read. Not those that only
# wrap what is no one's word (the result of a call, what a language
# server or a webhook reported): nothing is gained by writing them.
_CLAUDE_CODE_TAGS = (
    r"(?:command[-_](?:name|message|args)"
    r"|local[-_]command[-_](?:stdout|stderr|caveat)"
    r"|bash[-_](?:input|stdout|stderr)"
    r"|user[-_]prompt[-_]submit[-_]hook|user[-_]memory[-_]input"
    r"|task[-_]notification|fork[-_]boilerplate"
    r"|teammate[-_]message|cross[-_]session[-_]message)"
)
# Characters that are not shown: the tags of Unicode, which spell ASCII
# unseen (each is the ASCII character of its place, TAG_BASE on, those
# from TAG_SHOWN on the ones that print), and those of no width. A flag
# of a region takes a few tags and a script a joiner here and there, a
# run of them is something written.
TAG_BASE = 0xE0000
TAG_SHOWN = TAG_BASE + 0x20
_NO_WIDTH = "\u200b-\u200f\u2060-\u2064\ufeff"
_TAG_RUN = re.compile("[\U000e0000-\U000e007f]{10,}")
_NO_WIDTH_RUN = re.compile(f"[{_NO_WIDTH}]{{8,}}")
# What splits a word or sets it off without a model reading it any
# other way: the marks of emphasis, a soft hyphen, and the characters of
# no width
_FILLERS = re.compile(f"[*`~^\u00b7\u2022\u00a6\u00ad{_NO_WIDTH}]+")

type Finder = Callable[[str], str | None]


@dataclass(frozen=True)
class Sign:
    """A way of writing that tells of text meant to instruct who reads
    it: what it is said as, and what finds it in a text, giving what is
    shown of the first place it is at or none."""

    name: str
    find: Finder
    # Whether it is looked for in the text as it is written, not as it
    # reads (see as_read): it is about what the reading leaves out
    as_written: bool = False
    # Whether a turn of line mode is stopped for it (see chat/guard.py):
    # markup and text that is not shown are no way to write prose, words
    # are, and a turn stopped for nothing costs more than a line to look
    # at
    stops: bool = False


def as_read(text: str) -> str:
    """A text as a model reads it, whatever was done to the way it is
    written to pass for something else: its letters in their plain form
    (a wide or a styled one is the letter it shows), and without what
    splits a word (see _FILLERS). There is no end to such ways, these
    are the cheap ones."""
    return _FILLERS.sub("", unicodedata.normalize("NFKC", text))


def _line_start(text: str, at: int) -> int:
    """Where the excerpt of what is found at a place starts: with the
    line that is EXCERPT_LINES_BEFORE ahead of its own, or as far back
    as a whole line is within EXCERPT_BEFORE, in the line when none is."""
    least = max(0, at - EXCERPT_BEFORE)
    start, edge = least, at
    for _ in range(EXCERPT_LINES_BEFORE + 1):
        cut = text.rfind("\n", least, edge)
        if cut < 0:
            return 0 if least == 0 else start
        start, edge = cut + 1, cut
    return start


def _line_end(text: str, at: int, most: int) -> int:
    """Where the excerpt of what ends at a place ends: with the line
    that is EXCERPT_LINES_AFTER past its own, no further than most."""
    edge = at
    for _ in range(EXCERPT_LINES_AFTER + 1):
        cut = text.find("\n", edge, most)
        if cut < 0:
            return min(most, len(text))
        edge = cut + 1
    return edge - 1


def _around(text: str, found: re.Match[str]) -> str:
    """What was found with the lines around it, each on a line of its
    own and none of them blank. A line that is not whole says so, and so
    does what was found when it is longer than an excerpt: the space
    within it can be as long as what was read."""
    start = _line_start(text, found.start())
    most = start + EXCERPT_WIDTH
    end = _line_end(text, min(found.end(), most), most)
    lines = [
        line.rstrip() for line in clean(text[start:end]).splitlines() if line.strip()
    ]
    # What was found shows, whatever is around it
    lines = lines or [flat(found.group()[:EXCERPT_WIDTH])]
    if start and text[start - 1] != "\n":
        lines[0] = CUT + lines[0]
    if end < len(text) and text[end] != "\n":
        lines[-1] += CUT
    return "\n".join(lines)


def _written(*patterns: str) -> Finder:
    """What finds the first place a text is written in one of some ways,
    whatever the case of its letters."""
    known = tuple(re.compile(pattern, re.IGNORECASE) for pattern in patterns)

    def find(text: str) -> str | None:
        matches = filter(None, (pattern.search(text) for pattern in known))
        first = min(matches, key=lambda match: match.start(), default=None)
        return _around(text, first) if first else None

    return find


def _hidden(text: str) -> str | None:
    """What a text holds that is not shown, none when it holds none."""
    tags = _TAG_RUN.search(text)
    if tags:
        spelled = "".join(
            chr(ord(tag) - TAG_BASE) for tag in tags.group() if ord(tag) >= TAG_SHOWN
        )
        said = flat(spelled)[:EXCERPT_WIDTH]
        return f'{len(tags.group())} tag characters that spell "{said}"'
    run = _NO_WIDTH_RUN.search(text)
    if run:
        return f"{len(run.group())} characters of no width in a row"
    return None


# Text that only speaks to the model that reads it is no sign: a file
# written for agents does, and says nothing of what it is after
SIGNS: tuple[Sign, ...] = (
    Sign(
        "tells the reader to drop its instructions",
        _written(
            r"\b(?:ignore|disregard|forget|override|bypass)\s+"
            r"(?:(?:all|any|every|the|your|these|those|of|my)\s+){0,3}"
            r"(?:(?:previous|prior|above|earlier|preceding|foregoing|existing"
            r"|original)\s+(?:(?:system|safety|developer|user)\s+)?"
            r"|(?:system|safety|developer)\s+)"
            r"(?:instructions?|prompts?|rules?|guidelines?|directives?"
            r"|constraints?)\b",
            r"\b(?:new|updated|revised|real|true)\s+(?:system\s+)?"
            r"(?:instructions?|prompt|directives?)\s*:",
            r"\byou\s+are\s+now\s+(?:in\s+)?(?:an?\s+)?"
            r"(?:developer|debug|admin|god|unrestricted|jailbr\w+|DAN)\b",
        ),
    ),
    Sign(
        "tells the reader to keep something from the user",
        _written(
            r"\b(?:do\s+not|don'?t|never|without)\s+"
            r"(?:tell(?:ing)?|inform(?:ing)?|mention(?:ing)?|reveal(?:ing)?"
            r"|alert(?:ing)?|notify(?:ing)?)\s+"
            r"(?:(?:this|it|that|anything)\s+)?(?:to\s+)?(?:the\s+|your\s+)?"
            r"(?:user|human|operator|developer)\b",
        ),
    ),
    Sign(
        "is written as a turn of the conversation",
        stops=True,
        find=_written(
            r"<\|(?:im_start|im_end|system|user|assistant|endoftext)\|>",
            # In capitals only, [inst] is an index in code
            r"(?-i:\[/?INST\]|<<SYS>>)",
            # The tags Claude Code and the API write a conversation in,
            # and any made up to read as theirs: a name of two parts, who
            # speaks and what it is
            r"</?(?:system|antml:\w{1,40})(?:\s[^<>]{0,200})?>",
            rf"</?{_CLAUDE_CODE_TAGS}(?:\s[^<>]{{0,200}})?>",
            # A call of a tool as the model writes one
            r"<invoke\s+name\s*=",
            rf"</?{_SPEAKER}[-_]{_SPOKEN}(?:[-_][^\W_]{{1,40}}){{0,3}}"
            r"(?:\s[^<>]{0,200})?/?>",
            # What Claude Code heads a notice of its own with
            r"\[system\s+notification\b",
            rf"(?m)^{_NUMBERED}(?:\[system\]"
            r"|system\s+(?:override|message|prompt|instructions?)\s*:)",
        ),
    ),
    Sign(
        "asks for secrets to be sent somewhere",
        _written(
            r"\b(?:send|post|upload|e-?mail|forward|transmit|exfiltrate|leak"
            r"|paste)\s+(?:(?:me|us|over|along|back)\s+)?"
            r"(?:your|the\s+user'?s|all|any|every|the\s+contents?\s+of)\s+"
            rf"(?:\S+\s+){{0,4}}?{_SECRET}\s+(?:\S+\s+){{0,3}}?to\b",
        ),
    ),
    Sign("holds text that is not shown", _hidden, as_written=True, stops=True),
)


@dataclass(frozen=True)
class Planted:
    """A sign found in a text, and where: the lines it was written on
    with those around them, or what the hidden text says."""

    sign: str
    excerpt: str
    # Whether a turn is stopped for it, see Sign
    stops: bool = False
    # Where it was read, as the call or the launcher names it: a file, a
    # page, the addresses of a command. Empty when none is named
    source: str = ""

    @property
    def where(self) -> str:
        """Where it was read as it is said, on one line and no longer
        than SOURCE_WIDTH, empty without a source."""
        named = flat(self.source)
        return named if len(named) <= SOURCE_WIDTH else named[:SOURCE_WIDTH] + CUT

    @property
    def shown(self) -> str:
        """The sign, where it was read when that is known, and under it
        what was found, each line of that marked as one of what was
        read."""
        where = f" in {self.where}" if self.source else ""
        quoted = (f"\n{QUOTED}{line}" for line in self.excerpt.splitlines())
        return f"{FLAG}{where}: {self.sign}:" + "".join(quoted)

    def fields(self) -> dict:
        """The sign as one of the values of the event it is of."""
        found = {"sign": self.sign, "excerpt": self.excerpt}
        return {**found, "source": self.source} if self.source else found


def planted(text: object, source: str = "") -> tuple[Planted, ...]:
    """The signs a text shows of being written to instruct who reads it,
    each once, with the first place it is found: in the text as it reads
    (see as_read), which is how what was found is shown too. Each with
    the file or the page the text was read in, when it is known. None
    for what is no text."""
    if not isinstance(text, str) or not text:
        return ()
    text = text[:MOST_SCANNED]
    read = as_read(text)
    found = ((sign, sign.find(text if sign.as_written else read)) for sign in SIGNS)
    return tuple(
        Planted(sign.name, excerpt, sign.stops, source)
        for sign, excerpt in found
        if excerpt
    )


def flagged(signs: Iterable[Planted]) -> dict:
    """The signs found as a value of the event that tells of them, no
    value when there are none."""
    found = [sign.fields() for sign in signs]
    return {INJECTION: found} if found else {}


def read_said(count: int) -> str:
    """How many of the things a session read show a sign, as it is said
    of the session as a whole."""
    return f"{count} of what it read may be written to instruct it"
