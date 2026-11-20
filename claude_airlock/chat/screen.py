"""What a terminal makes of a text, and the escapes that erase a line
being typed and put its cursor back: counted from the text and how many
columns the terminal has, nothing here reads or writes one."""

from __future__ import annotations

import re
import unicodedata

# The escapes of colour, the only ones a head keeps
SGR = re.compile(r"\x1b\[[0-9;]{0,32}m")


def uncounted(prompt: str) -> str:
    """A prompt as readline is given it: each escape of colour between
    the marks that tell it they take no column."""
    return SGR.sub(lambda escape: f"\x01{escape.group()}\x02", prompt)


def columns_of(text: str) -> int:
    """How many columns of a terminal a text takes: two for the wide
    characters of East Asia, none for what is put on the one before."""
    return sum(
        (
            0
            if unicodedata.combining(c)
            else 2
            if unicodedata.east_asian_width(c) in "WF"
            else 1
        )
        for c in text
    )


def rows_above(text: str, columns: int) -> int:
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
    above = len(heads) + rows_above(prompt + typed, columns)
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
    up = rows_above(whole, columns) - rows_above(part, columns)
    across = columns_of(part.rpartition("\n")[2]) % columns
    out += f"\x1b[{up}A" if up else ""
    return out + "\r" + (f"\x1b[{across}C" if across else "")
