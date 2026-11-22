"""The here-documents of a shell command, found so that a command is
shown without the text it feeds its programs.

A command is the session's to write, and is read no further than this:
where a here-document starts and where it ends."""

from __future__ import annotations

import bisect
import re

# What starts a here-document in a command: << or <<-, then the word that
# ends it, quoted or not. Not <<<, which is a here-string.
_HEREDOC = re.compile(r"(?<!<)<<(?!<)(-?)\s*(['\"]?)(\w+)\2")
# What a shell reads as it is, a << in it starts nothing: between quotes
# of either kind, and in the arithmetic of (( ))
_SINGLE, _DOUBLE = "'", '"'
_ARITHMETIC, _ARITHMETIC_END = "((", "))"
# What a comment follows, at the start of a line or after one of these
_BEFORE_COMMENT = " \t;&|("


def heredoc_starts(line: str, within: str) -> tuple[list[tuple[str, str]], str]:
    """The here-documents a line of a command starts, each as whether
    its end can be indented (<<-) and the word that ends it, and what the
    line ends within: a quote, the arithmetic of (( )), or nothing. Not
    what is written within one of those or in a comment, where a shell
    starts none: taken for one, the lines after it that the shell runs
    would be left out as what it holds. Read as a shell does only so
    far: what is in doubt starts none, and is shown."""
    starts: list[tuple[str, str]] = []
    at = 0
    while at < len(line):
        char = line[at]
        if within == _SINGLE:
            if char == _SINGLE:
                within = ""
        elif within == _DOUBLE:
            if char == "\\":
                # What follows it is not the end of the quote
                at += 1
            elif char == _DOUBLE:
                within = ""
        elif within == _ARITHMETIC:
            if line.startswith(_ARITHMETIC_END, at):
                within = ""
                at += 1
        elif char == "\\":
            at += 1
        elif char in (_SINGLE, _DOUBLE):
            within = char
        elif line.startswith(_ARITHMETIC, at):
            within = _ARITHMETIC
            at += 1
        elif char == "#" and (at == 0 or line[at - 1] in _BEFORE_COMMENT):
            break
        else:
            found = _HEREDOC.match(line, at)
            if found:
                starts.append((found[1], found[3]))
                at = found.end() - 1
        at += 1
    return starts, within


def without_heredocs(lines: list[str]) -> list[str]:
    """The lines of a command without what its here-documents hold, each
    said to be so many lines instead: a script fed to an interpreter is
    as a rule most of the command, and the line that starts it tells what
    it is given to. One whose end is not found is left as it is, and so
    is what only reads as one, see heredoc_starts."""
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
    # What the lines shown so far end within, see heredoc_starts
    within = ""
    while index < len(lines):
        shown.append(lines[index])
        starts, within = heredoc_starts(lines[index], within)
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
