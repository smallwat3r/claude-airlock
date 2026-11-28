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
# Characters that are not shown, of whatever kind: the tags of Unicode,
# which spell ASCII unseen (each is the ASCII character of its place,
# TAG_BASE on, those from TAG_SHOWN to TAG_LAST the ones that print), the
# selectors of a variation, which spell bytes the same way (the first
# sixteen from SELECTOR_BASE on, the rest from MORE_SELECTORS_BASE), the
# soft hyphen, the joiners and the spaces of no width, the marks of
# direction, the fillers that stand for a letter and show none. One
# class for all of them: told apart, a text that takes one of each in
# turn would have no run of any. A flag of a region takes a few tags, an
# emoji a selector and a script a joiner here and there, a run of
# UNSHOWN_RUN of them is something written. Blanks between them, no more
# than UNSHOWN_BLANKS at a time, do not end a run: words written unseen
# a space apart show as nothing but spaces, and are one text.
TAG_BASE = 0xE0000
TAG_SHOWN = TAG_BASE + 0x20
TAG_LAST = TAG_BASE + 0x7E
SELECTOR_BASE = 0xFE00
SELECTORS = 16
MORE_SELECTORS_BASE = 0xE0100
MORE_SELECTORS = 240
UNSHOWN_RUN = 8
UNSHOWN_BLANKS = 16
_UNSHOWN = (
    "\u00ad\u034f\u061c\u115f\u1160\u17b4\u17b5\u180b-\u180f\u200b-\u200f"
    "\u202a-\u202e\u2060-\u206f\u3164\ufe00-\ufe0f\ufeff\uffa0\ufff0-\ufffb"
    "\U0001bca0-\U0001bca3\U0001d173-\U0001d17a\U000e0000-\U000e0fff"
)
_UNSHOWN_RUN = re.compile(
    f"[{_UNSHOWN}](?:\\s{{0,{UNSHOWN_BLANKS}}}[{_UNSHOWN}]){{{UNSHOWN_RUN - 1},}}"
)
# The apostrophes a text can be written with but the plain one a pattern
# looks for: a model reads a curly one as it reads that
_APOSTROPHES = re.compile("[\u2018\u2019\u02bc\u2032]")
# The controls but tab and line feed, which the trace drops from what it
# shows (see clean of events.py): a word split by one is shown whole, and
# is found so. Of them, those a pattern takes for a space between two
# words: dropped they join two words, kept they split one, and a text
# that has any is read both ways (see planted). Not a carriage return
# ahead of a line feed, which ends a line either way.
_CONTROLS = "\x00-\x08\x0b-\x1f\x7f-\x9f"
_SPACING = re.compile("[\x0b\x0c\x1c-\x1f\x85]|\r(?!\n)")
_NOT_SPACING = "\x00-\x08\x0e-\x1b\x7f-\x84\x86-\x9f"
# What splits a word or sets it off without a model reading it any
# other way: the marks of emphasis, the characters that are not shown and
# the controls. And the same with the controls that space words left in.
_FILLERS = re.compile(f"[*`~^\u00b7\u2022\u00a6{_UNSHOWN}{_CONTROLS}]+")
_FILLERS_SPACED = re.compile(f"[*`~^\u00b7\u2022\u00a6{_UNSHOWN}{_NOT_SPACING}]+")
# The marks of emphasis written with _ at the start or the end of a word,
# not those within one (snake_case, <system_warning>)
_UNDERLINED = re.compile(r"(?<!\w)_+(?=\w)|(?<=\w)_+(?!\w)")
# The same as the fillers but for what a path is written with, which is
# left where what was found is shown (see _as_shown): a ~ ahead of the
# first / of a path, a * next to a /, and a _ at either end of a name
_SET_OFF = re.compile(
    f"(?:[`^\u00b7\u2022\u00a6{_UNSHOWN}{_CONTROLS}]|~(?![\\w.-]{{0,64}}/)"
    "|(?<!/)\\*(?!/))+"
)

# What finds a sign in a text: where it is, for what is shown with the
# lines around it, or what to say of it, none when it is not there
type Finder = Callable[[str], re.Match[str] | str | None]


@dataclass(frozen=True)
class Sign:
    """A way of writing that tells of text meant to instruct who reads
    it: what it is said as, and what finds the first place it is at in a
    text."""

    name: str
    find: Finder
    # Whether it is looked for in the text as it is written, not as it
    # reads (see _as_read): it is about what the reading leaves out
    as_written: bool = False
    # Whether a turn of line mode is stopped for it (see chat/guard.py):
    # markup and text that is not shown are no way to write prose, words
    # are, and a turn stopped for nothing costs more than a line to look
    # at
    stops: bool = False


def _plain(text: str) -> str:
    """The letters of a text in their plain form, as a model reads them:
    a wide or a styled one is the letter it shows, a curly apostrophe
    the straight one. A text of ASCII is in that form already."""
    if text.isascii():
        return text
    return _APOSTROPHES.sub("'", unicodedata.normalize("NFKC", text))


def _as_read(plain: str, spaced: bool = False) -> str:
    """A text in its plain form (see _plain) as a model reads it,
    whatever was done to the way it is written to pass for something
    else: without what splits a word or sets it off (see _FILLERS and
    _UNDERLINED). Spaced, with the controls that a pattern takes for a
    space left in, see _CONTROLS. There is no end to such ways, these are
    the cheap ones."""
    read = (_FILLERS_SPACED if spaced else _FILLERS).sub("", plain)
    # Most texts have no _, which is quicker to tell than to look for
    return _UNDERLINED.sub("", read) if "_" in read else read


def _as_shown(plain: str) -> str:
    """A text in its plain form as it reads (see _as_read), with what a
    path is written with left in it: what is shown of a text is to say
    which file it names, and ~/.ssh without its ~ names another."""
    return _SET_OFF.sub("", plain)


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


def _excerpt(read: str, found: re.Match[str], shown: str) -> str:
    """What was found in a text as it reads, with the lines around it
    (see _around), as the same text with its paths left whole has them
    (see _as_shown). Looked for again there, which is a pass and no count
    of what the two differ by: the same find on the same line, unless a
    character of a path is within it, and then it is shown as it was
    found."""
    again = found.re.search(shown)
    if (
        again
        and again.group() == found.group()
        and shown.count("\n", 0, again.start()) == read.count("\n", 0, found.start())
    ):
        return _around(shown, again)
    return _around(read, found)


def _written(*patterns: str) -> Finder:
    """What finds the first place a text is written in one of some ways,
    whatever the case of its letters."""
    known = tuple(re.compile(pattern, re.IGNORECASE) for pattern in patterns)

    def find(text: str) -> re.Match[str] | None:
        matches = filter(None, (pattern.search(text) for pattern in known))
        return min(matches, key=lambda match: match.start(), default=None)

    return find


def _spelled(unshown: str) -> str:
    """What characters that are not shown spell, empty when nothing that
    reads: each tag the ASCII character of its place, each selector of a
    variation the byte of its place, the bytes read as UTF-8, and a blank
    between them as a space. No more of it than an excerpt."""
    spelled = bytearray()
    for character in unshown[: 4 * EXCERPT_WIDTH]:
        place = ord(character)
        if character.isspace():
            spelled.append(ord(" "))
        elif TAG_SHOWN <= place <= TAG_LAST:
            spelled.append(place - TAG_BASE)
        elif 0 <= place - SELECTOR_BASE < SELECTORS:
            spelled.append(place - SELECTOR_BASE)
        elif 0 <= place - MORE_SELECTORS_BASE < MORE_SELECTORS:
            spelled.append(place - MORE_SELECTORS_BASE + SELECTORS)
    read = flat(spelled.decode("utf-8", "ignore")).strip()
    return read[:EXCERPT_WIDTH] if any(map(str.isalnum, read)) else ""


def _hidden(text: str) -> str | None:
    """What a text holds that is not shown, none when it holds none: the
    first run of such characters, of whatever kinds they are and with
    the blanks between them, and what they spell when they spell
    something."""
    run = _UNSHOWN_RUN.search(text)
    if not run:
        return None
    blanks = sum(map(str.isspace, run.group()))
    said = f"{len(run.group()) - blanks} characters that are not shown in a row"
    if blanks:
        said += ", blanks between them"
    spelled = _spelled(run.group())
    return f'{said}, which spell "{spelled}"' if spelled else said


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


def _first_found(
    sign: Sign, readings: list[str]
) -> tuple[str, re.Match[str] | str | None]:
    """What finds a sign gives of the first of some readings of a text
    that has it, with that reading. None when none has it."""
    for read in readings:
        found = sign.find(read)
        if found is not None:
            return read, found
    return readings[0], None


def planted(text: object, source: str = "") -> tuple[Planted, ...]:
    """The signs a text shows of being written to instruct who reads it,
    each once, with the first place it is found: in the text as it reads
    (see _as_read), which is how what was found is shown too, but for the
    paths it names (see _as_shown). Each with the file or the page the
    text was read in, when it is known. None for what is no text."""
    if not isinstance(text, str) or not text:
        return ()
    text = text[:MOST_SCANNED]
    plain = _plain(text)
    # As it reads, and where it has controls that space words also with
    # those left in, see _CONTROLS: a second pass of a pattern at most
    readings = [_as_read(plain)]
    if _SPACING.search(plain):
        readings.append(_as_read(plain, spaced=True))
    # Made when the first sign is found: most texts show none
    shown: str | None = None
    signs = []
    for sign in SIGNS:
        read, found = _first_found(sign, [text] if sign.as_written else readings)
        if found is None:
            continue
        if isinstance(found, str):
            excerpt = found
        else:
            shown = _as_shown(plain) if shown is None else shown
            excerpt = _excerpt(read, found, shown)
        if excerpt:
            signs.append(Planted(sign.name, excerpt, sign.stops, source))
    return tuple(signs)


def flagged(signs: Iterable[Planted]) -> dict:
    """The signs found as a value of the event that tells of them, no
    value when there are none."""
    found = [sign.fields() for sign in signs]
    return {INJECTION: found} if found else {}


def read_said(count: int) -> str:
    """How many of the things a session read show a sign, as it is said
    of the session as a whole."""
    return f"{count} of what it read may be written to instruct it"
