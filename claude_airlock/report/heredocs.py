"""The here-documents of a shell command, found so that a command is
shown without the text it feeds its programs.

A command is the session's to write, and is read no further than this:
where a here-document starts and where it ends."""

from __future__ import annotations

import bisect
import re

# What starts a here-document in a command: << or <<-, then the word that
# ends it, quoted or not. Not <<<, which is a here-string. The word is
# taken only when it ends where a shell ends it too, at a blank, an
# operator or the end of the line: of <<END.x a shell's word is END.x,
# and the line END then ends nothing.
_HEREDOC = re.compile(r"(?<!<)<<(?!<)(-?)[ \t]*(['\"]?)(\w+)\2(?=[ \t;&|()<>]|\Z)")
# What a shell reads as it is, a << in it starts nothing: between quotes
# of either kind, those of $'' among them, and in the arithmetic of (( ))
_SINGLE, _DOUBLE, _ESCAPED = "'", '"', "$'"
_ARITHMETIC = "(("
# What cannot be read for certain, see _Command
_DOUBT = "?"
# What a comment follows, at the start of a line or after one of these
_BEFORE_COMMENT = " \t;&|()<>"
# The one ${ } that is read: a name and no more
_PARAMETER = re.compile(r"\$\{\w+\}")
# What a subscript follows, as in the name[1<<2]=x a shell takes whole
_NAME_END = re.compile(r"\w")


class _Command:
    """A command as far as it has been read, a line at a time: what its
    last line ended within, a quote or the arithmetic of (( )).

    Read as a shell does only so far. What is not read for certain puts
    the rest of the command in doubt, and nothing starts there any more:
    taken for a here-document, the lines after it that the shell runs
    would be left out as what it holds. In doubt, so shown, is what
    follows a ${ } that is more than a name, a $[ ], a backquote, a
    $( ) between double quotes or in arithmetic, a quote in arithmetic,
    the list of name=( ), a << in a subscript, a ( or ) after a
    here-document on its line, and a line that starts a here-document and does
    not end there (an open quote, a \\ before the line break): what it
    holds then starts after a line the shell still reads as command."""

    def __init__(self) -> None:
        self._within = ""
        # How many ( of an arithmetic are still open
        self._open = 0

    def starts(self, line: str) -> list[tuple[str, str]]:
        """The here-documents a line starts, each as whether its end can
        be indented (<<-) and the word that ends it."""
        starts: list[tuple[str, str]] = []
        # How many [ of a subscript are open, and whether the line ends
        # in a \ that has the next one read with it
        subscripts = 0
        continued = False
        at = 0
        while at < len(line) and self._within != _DOUBT:
            char = line[at]
            if self._within:
                pass
            elif char == "#" and (at == 0 or line[at - 1] in _BEFORE_COMMENT):
                break
            elif char == "[" and (subscripts or _NAME_END.match(line[at - 1 : at])):
                subscripts += 1
            elif char == "]":
                subscripts = max(0, subscripts - 1)
            elif (char in "()" and starts) or (
                char == "(" and line[at - 1 : at] == "="
            ):
                # After a here-document, a $( left open has the shell
                # read the next lines as its commands, and a ) may end
                # the one that holds it. In the list of name=( ), a << is
                # an error the shell goes on from, to run the next lines.
                self._within = _DOUBT
                break
            elif char == "\\":
                continued = at == len(line) - 1
            elif char == "<" and (found := _HEREDOC.match(line, at)):
                if subscripts:
                    self._within = _DOUBT
                starts.append((found[1], found[3]))
                at = found.end()
                continue
            at += self._step(line, at)
        if starts and (self._within or continued):
            self._within = _DOUBT
        return [] if self._within == _DOUBT else starts

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
            return self._arithmetic(char)
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

    def _arithmetic(self, char: str) -> int:
        """Read a character of an arithmetic, which ends with the ( that
        started it: at the first )) it would end early for a shell that
        counts them, and what follows would start what it does not."""
        if char in (_SINGLE, _DOUBLE):
            self._within = _DOUBT
        elif char in "()":
            self._open += 1 if char == "(" else -1
            if not self._open:
                self._within = ""
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
        elif after == "(" and self._within:
            # Of $(( in arithmetic the ( are counted as any other there
            if self._within != _ARITHMETIC or line[at + 2 : at + 3] != "(":
                self._within = _DOUBT
        elif after == _SINGLE and not self._within:
            self._within = _ESCAPED
            return 2
        return 1


def without_heredocs(lines: list[str]) -> list[str]:
    """The lines of a command without what its here-documents hold, each
    said to be so many lines instead: a script fed to an interpreter is
    as a rule most of the command, and the line that starts it tells what
    it is given to. One whose end is not found is left as it is, and so
    is what only reads as one or is in doubt, see _Command."""
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
        for dash, word in starts:
            found = (tabbed if dash else plain).get(word, [])
            later = bisect.bisect_left(found, index)
            if later < len(found):
                body = found[later] - index
                held = "1 line" if body == 1 else f"{body} lines"
                shown.append(f"... here-document of {held}, see --verbose")
                index = found[later] + 1
    return shown
