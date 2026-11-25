"""The here-documents of a shell command, found so that a command is
shown without the text it feeds its programs.

A command is the session's to write, and is read no further than this:
where a here-document starts and where it ends. Read as bash reads it,
and only where that is certain: a line left out as what a here-document
holds, which the shell then runs as a command, would be a command no one
is shown. So the lines are the shell's (see command_lines of calls.py),
they are read as they were written and not as they are shown, and what is
not read for certain is left as it is."""

from __future__ import annotations

import bisect
import re
from dataclasses import dataclass

# What starts a here-document in a command: << or <<-, then the word that
# ends it, quoted or not. Not <<<, which is a here-string. The word is
# taken only when it ends where a shell ends it too, at a blank, an
# operator or the end of the line: of <<END.x a shell's word is END.x,
# and the line END then ends nothing.
_HEREDOC = re.compile(r"(?<!<)<<(?!<)(-?)[ \t]*(['\"]?)(\w+)\2(?=[ \t;&|()<>]|\Z)")
_HERE_STRING = "<<<"
# What a shell reads as it is, a << in it starts nothing: between quotes
# of either kind, those of $'' among them, and in the arithmetic of (( ))
_SINGLE, _DOUBLE, _ESCAPED = "'", '"', "$'"
_ARITHMETIC = "(("
# What cannot be read for certain, see _Command
_DOUBT = "?"
# What is read a character at a time, by what it is within: the rest of
# a line means nothing to where a here-document starts, and is passed
# over a run at a time. A command can be a line of megabytes.
_READ_AT = {
    "": re.compile(r"[#\[\]()\\<=$`'\"]"),
    _SINGLE: re.compile("'"),
    _ESCAPED: re.compile(r"['\\]"),
    _DOUBLE: re.compile(r"[\"\\$`]"),
    _ARITHMETIC: re.compile(r"['\"()\\$`]"),
}
# What a comment follows, at the start of a line or after one of these.
# After a ) it does where that ends commands, and not where it ends the
# $( ) or the arithmetic a word goes on after: the two are not told apart.
_BEFORE_COMMENT = " \t;&|()<>"
_ENDS_EITHER = ")"
# What has a word of a command stand for others, a << among them, where
# none is written: an alias, by its name anywhere in a line
_ALIAS = "alias"
# The one ${ } that is read: a name and no more
_PARAMETER = re.compile(r"\$\{\w+\}")
# What a subscript follows, as in the name[1<<2]=x a shell takes whole
_NAME_END = re.compile(r"\w")
# What a ( follows where it starts no commands: the list of name=( ), and
# a pattern such as @( ), which a shell that has them on takes whole
_BEFORE_LIST = "=?*+@!"
# What the two ( of an arithmetic do not follow: <(( )) is a process
# substitution of a subshell, whose commands a shell reads
_BEFORE_COMMANDS = "<>"
# What has a shell read the word after it as a pattern of its own kind,
# with ( ) and | that are none of a command: a word of its own, in [[ ]]
_REGEX = re.compile(r"(?<![^ \t])=~(?=[ \t]|\Z)")
# What a shell runs in a here-document whose word is not quoted, see
# _expanded: a $( ), a backquote, and the ${ } of bash that runs commands
_RUN = re.compile(r"\$\(|`|\$\{[ \t|]|\$\{\Z")


@dataclass(frozen=True)
class _Start:
    """A here-document a line starts, as the shell is told of it."""

    # The word that ends it, on a line of its own
    word: str
    # Whether that line can be indented with tabs (<<-)
    indented: bool
    # Whether the word is quoted: what the here-document holds is then as
    # it is written, else the shell reads it as between double quotes
    quoted: bool


class _Command:
    """A command as far as it has been read, a line at a time: what its
    last line ended within, a quote, the arithmetic of (( )) or the
    subscript of name[ ].

    Read as a shell does only so far. What is not read for certain puts
    the rest of the command in doubt, and nothing starts there any more:
    taken for a here-document, the lines after it that the shell runs
    would be left out as what it holds. In doubt, so shown, is what
    follows a << whose word is not a plain one, quoted as a whole or not
    at all (the shell makes its own word of <<\\END, <<'E N D', <<E"N"D
    and <<"$x"), a ${ } that is more than a name, a $[ ], a backquote, a
    $( ) between double quotes, in arithmetic or in a subscript, a quote
    in arithmetic, a (( that follows a < or a > or does not end in the
    )) of an arithmetic (those are subshells, and commands), the list of
    name=( ), a pattern such as @( ) and the word after =~ (the shell
    reads none of the three as it reads a command), a comment or a << in
    a subscript, a # right after a ) (a comment after a subshell, part
    of a word after a $( )), a \\ before a line break outside quotes (the
    next line goes on in the middle of this one, where a # starts no
    comment and a < may be the second of two), the name of an alias
    (one can stand for the << of a here-document), a ( or ) after a
    here-document on its line, and a line that starts a here-document
    and ends within a quote or a subscript: what it holds then starts
    after a line the shell still reads as command.

    What a shell was told before the command is not known here: an
    alias from before it can start a here-document all the same, where
    no line says so."""

    def __init__(self) -> None:
        self._within = ""
        # How many ( of an arithmetic are still open
        self._open = 0
        # How many [ of a subscript are, which can end on a later line
        self._subscripts = 0
        # The place of the line that follows a \ and what it has taken
        # as it is: a word goes on there, and a # starts no comment
        self._escaped = -1

    def doubt(self) -> None:
        """Put the rest of the command in doubt."""
        self._within = _DOUBT

    def starts(self, line: str) -> list[_Start]:
        """The here-documents a line starts, none when that is not
        certain, of this line or from here on."""
        starts: list[_Start] = []
        at = 0
        self._escaped = -1
        if _ALIAS in line:
            self._within = _DOUBT
        while self._within != _DOUBT:
            found = _READ_AT[self._within].search(line, at)
            if not found:
                break
            at = found.start()
            if self._within:
                at += self._step(line, at)
            else:
                at = self._read(line, at, starts)
        if starts and (self._within or self._subscripts):
            self._within = _DOUBT
        return [] if self._within == _DOUBT else starts

    def _read(self, line: str, at: int, starts: list[_Start]) -> int:
        """Read what is at a place of a line outside quotes and
        arithmetic, and say where the reading goes on, which is the end
        of the line for a comment. A here-document that starts there is
        added to those of the line."""
        char, before = line[at], line[at - 1 : at]
        comment = not before or (before in _BEFORE_COMMENT and at != self._escaped)
        if char == "#" and comment:
            if self._subscripts or before == _ENDS_EITHER:
                self._within = _DOUBT
            return len(line)
        if char == "\\" and at < len(line) - 1:
            self._escaped = at + 2
            return self._escaped
        if char == "[" and (self._subscripts or _NAME_END.match(before)):
            self._subscripts += 1
        elif char == "]":
            self._subscripts = max(0, self._subscripts - 1)
        elif self._unread(line, at, bool(starts)):
            self._within = _DOUBT
            return at
        elif line.startswith(_HERE_STRING, at):
            return at + len(_HERE_STRING)
        elif char == "<" and line.startswith("<<", at):
            found = _HEREDOC.match(line, at)
            if not found or self._subscripts:
                self._within = _DOUBT
                return at
            starts.append(_Start(found[3], bool(found[1]), bool(found[2])))
            return found.end()
        return at + self._step(line, at)

    def _unread(self, line: str, at: int, started: bool) -> bool:
        """Whether what is at a place of a line outside quotes is where
        the reading stops being certain: a ( or ) that the shell may not
        take for the start or the end of commands, a line that goes on
        with the next, a word it reads as a pattern."""
        char, before = line[at], line[at - 1 : at] or " "
        if char == "(":
            # After a here-document, a $( left open has the shell read
            # the next lines as its commands. In the list of name=( ), a
            # << is an error the shell goes on from, to run the next
            # lines.
            subshells = line.startswith(_ARITHMETIC, at) and before in _BEFORE_COMMANDS
            return started or subshells or before in _BEFORE_LIST
        if char == ")":
            # It may end the $( ) that holds the here-document
            return started
        if char == "\\":
            return at == len(line) - 1
        return bool(_REGEX.match(line, at))

    def _step(self, line: str, at: int) -> int:
        """Read what is at a place of a line, and say how far it goes."""
        char = line[at]
        within = self._within
        if within == _SINGLE:
            return self._quote(char)
        if char == "\\":
            # What follows it is as it is, the end of a quote too
            return 2
        if within == _ESCAPED:
            return self._quote(char)
        if char == "`":
            self._within = _DOUBT
            return 1
        if char == "$":
            return self._dollar(line, at)
        if within == _ARITHMETIC:
            return self._arithmetic(line, at)
        if within == _DOUBLE:
            self._within = "" if char == _DOUBLE else _DOUBLE
        elif char in (_SINGLE, _DOUBLE):
            self._within = char
        elif line.startswith(_ARITHMETIC, at):
            self._within, self._open = _ARITHMETIC, 2
            return 2
        return 1

    def _quote(self, char: str) -> int:
        """Read a character between single quotes, those of $'' too."""
        if char == _SINGLE:
            self._within = ""
        return 1

    def _arithmetic(self, line: str, at: int) -> int:
        """Read a character of an arithmetic, which ends with the ( that
        started it: at the first )) it would end early for a shell that
        counts them, and what follows would start what it does not. The
        two ) that end it are next to each other: with anything between
        them, even the end of the line, the shell reads two subshells,
        and their commands."""
        char = line[at]
        if char in (_SINGLE, _DOUBLE):
            self._within = _DOUBT
        elif char == "(":
            self._open += 1
        elif char == ")":
            self._open -= 1
            if not self._open:
                self._within = ""
            elif self._open == 1 and line[at + 1 : at + 2] != ")":
                self._within = _DOUBT
        return 1

    def _dollar(self, line: str, at: int) -> int:
        """Read a $ and what it starts, outside single quotes."""
        after = line[at + 1 : at + 2]
        if after == "{":
            named = _PARAMETER.match(line, at)
            if named:
                return named.end() - at
            self._within = _DOUBT
        elif after == "[":
            self._within = _DOUBT
        elif after == "(" and (self._within or self._subscripts):
            # Of $(( in arithmetic the ( are counted as any other there
            if self._within != _ARITHMETIC or line[at + 2 : at + 3] != "(":
                self._within = _DOUBT
        elif after == _SINGLE and not self._within:
            self._within = _ESCAPED
            return 2
        return 1


def _expanded(start: _Start, held: list[str]) -> bool:
    """Whether the shell does more with what a here-document holds than
    hand it on, so that where it ends, or what runs, is not told by its
    lines alone. One whose word is not quoted is read as between double
    quotes: a line that ends in a \\ goes on with the next, so the next
    may read as the end and not be it, or the two be the end together,
    and a $( ) or a backquote runs what it holds. And for a here-document
    in a $( ), bash takes a line that starts with the word and has a )
    after it for the end of the two."""
    for line in held:
        if not start.quoted and (line.endswith("\\") or _RUN.search(line)):
            return True
        if line.lstrip("\t").startswith(start.word) and ")" in line:
            return True
    return False


def without_heredocs(lines: list[str]) -> list[str]:
    """The lines of a command without what its here-documents hold, each
    said to be so many lines instead: a script fed to an interpreter is
    as a rule most of the command, and the line that starts it tells what
    it is given to. The lines are those a shell reads, as they were
    written. One whose end is not found, or that the shell does more with
    than hand it on (see _expanded), is left as it is with all that
    follows, and so is what only reads as one or is in doubt, see
    _Command."""
    # Where each line is, as it is and without the tabs <<- lets the word
    # that ends a here-document be indented with: a command is the
    # session's to write, its end is not looked for a line at a time
    plain: dict[str, list[int]] = {}
    tabbed: dict[str, list[int]] = {}
    for at, line in enumerate(lines):
        plain.setdefault(line, []).append(at)
        tabbed.setdefault(line.lstrip("\t"), []).append(at)
    shown: list[str] = []
    index = 0
    command = _Command()
    while index < len(lines):
        shown.append(lines[index])
        starts = command.starts(lines[index])
        index += 1
        for start in starts:
            found = (tabbed if start.indented else plain).get(start.word, [])
            later = bisect.bisect_left(found, index)
            end = found[later] if later < len(found) else len(lines)
            if end == len(lines) or _expanded(start, lines[index:end]):
                command.doubt()
                break
            body = end - index
            held = "1 line" if body == 1 else f"{body} lines"
            shown.append(f"... here-document of {held}, see --verbose")
            index = end + 1
    return shown
