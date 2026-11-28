"""The programs a shell command runs, by the first word of each of its
commands: what --trace stats counts the commands of the sessions by.

A command is the session's to write and is read no further than its
words, as shlex splits them: what a variable, an alias or a function
stands for is not looked into, and a command the shell would not read is
taken a word at a time. Its lines are those the shell reads (see
command_lines of calls.py), without what its here-documents hold."""

from __future__ import annotations

import shlex
from collections.abc import Iterator

from ..events import flat
from .calls import command_lines
from .heredocs import heredocs_dropped

# Of how much of a program is kept, its name is the session's to write
PROGRAM_WIDTH = 40
# Of the words shlex splits a command into, those made of these alone end
# one command and start the next (&&, |, ;), and those made of these alone
# redirect, the word after them is a file (>, 2>&1 is 2 then >&1)
COMMAND_ENDS = frozenset("&|;()")
REDIRECTS = frozenset("<>&")
# Words of the shell after which a command starts, and programs that run
# the command that follows them
LEADING = frozenset(
    {"if", "then", "else", "elif", "do", "while", "until", "!", "{", "}"}
    | {"time", "exec", "command", "builtin", "nohup", "env"}
)
# Words of the shell that end what they are in, or start what has no
# command in its first words (for x in a b)
NO_COMMAND = frozenset({"fi", "done", "esac", "for", "case", "select", "function"})


def programs(command: str) -> Iterator[str]:
    """The programs a command runs, each time it runs one, by its name
    alone: the first word of each of its commands, past the variables set
    for it, the words of the shell and the options of what runs another,
    and not the file of a redirection."""
    starts, redirected = True, False
    for word in _words(command):
        if set(word) <= COMMAND_ENDS:
            starts, redirected = True, False
        elif set(word) <= REDIRECTS:
            redirected = True
        elif redirected:
            redirected = False
        elif not starts or _sets_variable(word):
            continue
        elif word in NO_COMMAND:
            starts = False
        else:
            program = word.rsplit("/", 1)[-1] or word
            if program not in LEADING and not word.startswith("-"):
                starts = False
                yield flat(program)[:PROGRAM_WIDTH]


def _words(command: str) -> list[str]:
    """The words of a command as shlex splits them, with each line ended
    as the shell ends it unless it goes on to the next."""
    read = "".join(
        line[:-1] if line.endswith("\\") else f"{line} ;\n"
        for line in heredocs_dropped(command_lines(command))
    )
    lexer = shlex.shlex(read, posix=True, punctuation_chars=True)
    lexer.whitespace_split = True
    try:
        return list(lexer)
    except ValueError:
        # A quote that is not closed
        return read.split()


def _sets_variable(word: str) -> bool:
    """Whether a word sets a variable for the command that follows."""
    name, sets, _ = word.partition("=")
    return bool(sets) and name.isidentifier()
