"""What a terminal makes of a text, and the escapes that erase a line
being typed and put its cursor back: counted from the text and how many
columns the terminal has, nothing here reads or writes one."""

from __future__ import annotations

import re
import unicodedata

from ..events import clean

# The escapes of colour, the only ones a head keeps
SGR = re.compile(r"\x1b\[[0-9;]{0,32}m")
# The control characters readline shows as a caret and a letter, ^[ for
# an escape, and that a terminal would act on as they are
_CARETED = re.compile(r"[\x00-\x08\x0b-\x1f\x7f]")


def uncounted(prompt: str) -> str:
    """A prompt as readline is given it: each escape of colour between
    the marks that tell it they take no column."""
    return SGR.sub(lambda escape: f"\x01{escape.group()}\x02", prompt)


# The categories of the characters that take no column: the marks put on
# the character before them, and those that only say how to format
NO_COLUMN = ("Mn", "Me", "Cf")


# The vowels and the final consonants of Hangul, which wcwidth gives no
# column: written after a first consonant, they are part of its syllable
JOINED = ((0x1160, 0x11FF), (0xD7B0, 0xD7FF))


def columns_of(text: str) -> int:
    """How many columns of a terminal a text takes, as wcwidth counts
    them for readline and a terminal for itself: two for the wide
    characters of East Asia, none for what is put on the one before or
    shows nothing. Counted too wide, a text would have more rows erased
    than it takes, those above it: what is counted is in part the
    session's choice. Where terminals differ, the fewer are counted."""
    return sum(
        (
            0
            if unicodedata.combining(c)
            or unicodedata.category(c) in NO_COLUMN
            or any(first <= ord(c) <= last for first, last in JOINED)
            else 2
            if unicodedata.east_asian_width(c) in "WF"
            else 1
        )
        for c in text
    )


# What a tab can take, to the next stop
TAB_COLUMNS = 8
# The categories of what one terminal shows wide and another does not,
# whatever Unicode says of its width: the symbols emoji are among, and
# what this Python does not know yet and a terminal may
MAYBE_WIDE = ("So", "Cn", "Co")
# The selector that has the character before it shown as an emoji, wide
EMOJI_SELECTOR = "\ufe0f"
# An escape of colour that ends every style
SGR_RESET = re.compile(r"\x1b\[0*m")


def columns_at_most(char: str) -> int:
    """How many columns a character takes in the terminal that gives it
    the most: for what must not be longer than a row, see first_row. Not
    how many it takes, which columns_of counts for what is erased, the
    fewest: the two err to opposite sides, each to the one that is safe
    for what it is used for."""
    if char == "\t":
        return TAB_COLUMNS
    if char == EMOJI_SELECTOR:
        return 1
    category = unicodedata.category(char)
    if unicodedata.combining(char) or category in ("Mn", "Me"):
        return 0
    if category in MAYBE_WIDE or unicodedata.east_asian_width(char) in "WFA":
        return 2
    return 1


def first_row(line: str, columns: int) -> str:
    """No more of a line than a row of a terminal of that many columns
    holds, whatever terminal it is: for a line of the head, which is
    erased with the prompt by the rows it takes. One the terminal
    wrapped would take more rows than are counted for it, see erased.
    A style of colour that is open where the line is cut is ended
    there."""
    room = max(1, columns)
    if len(line) <= room and line.isascii() and "\t" not in line and "\x1b" not in line:
        return line
    left = room
    styled = False
    at = 0
    while at < len(line):
        escape = SGR.match(line, at)
        if escape:
            styled = not SGR_RESET.fullmatch(escape.group())
            at = escape.end()
            continue
        taken = columns_at_most(line[at])
        # Never cut before its first character, however wide that is
        if taken > left and left < room:
            return line[:at] + ("\x1b[0m" if styled else "")
        left -= taken
        at += 1
    return line


def _rows_above(text: str, columns: int) -> int:
    """How many rows a prompt and what is typed after it take above
    the row their end is on. What ends at the edge has its end on the
    row after, as readline writes it."""
    rows = text.split("\n")
    return len(rows) - 1 + sum(columns_of(row) // columns for row in rows)


def erased(prompt: str, typed: str, columns: int) -> str:
    """The escapes that erase the line being typed with its prompt and
    the head of that, from the cursor at the end of typed: all the
    rows they take above it and all that is under it. A line longer
    than the terminal is wide takes more than one row, and so does
    what was pasted with its line breaks. Escapes of colour take no
    column."""
    columns = max(1, columns)
    *heads, prompt = SGR.sub("", prompt).split("\n")
    # A line of the head that ends at the edge takes no row more: its
    # break goes to the next row
    above = len(heads) + _rows_above(prompt + typed, columns)
    above += sum(max(0, columns_of(row) - 1) // columns for row in heads)
    up = f"\x1b[{above}A" if above else ""
    return f"{up}\r\x1b[J"


def cursor_back(prompt: str, typed: str, before: str, columns: int) -> str:
    """The escapes that follow a prompt and what was typed, written
    again: they leave the cursor where readline has it, after what is
    before it. A terminal keeps the cursor on the row of what ends at
    its edge until more is written, readline has it on the next: a
    space takes it there."""
    columns = max(1, columns)
    prompt = SGR.sub("", prompt).rpartition("\n")[2]
    whole, part = prompt + typed, prompt + before
    last = columns_of(whole.rpartition("\n")[2])
    out = " \r" if last and last % columns == 0 else ""
    if before == typed:
        return out
    up = _rows_above(whole, columns) - _rows_above(part, columns)
    across = columns_of(part.rpartition("\n")[2]) % columns
    out += f"\x1b[{up}A" if up else ""
    return out + "\r" + (f"\x1b[{across}C" if across else "")


def shown_typed(text: str) -> str:
    """What was typed or pasted as it is to be written to the terminal,
    as readline shows it: a control character as a caret and a letter,
    and nothing that clean takes out. The line itself keeps them, this
    is what is on the screen: a line piped in or pasted can hold the
    escapes that move the cursor, clear the screen or set its title."""
    careted = _CARETED.sub(lambda found: "^" + chr(ord(found[0]) ^ 0x40), text)
    return clean(careted)
