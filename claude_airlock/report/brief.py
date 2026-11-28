"""How much of a text a trace shows: a line cut to a width, the first
few lines of many, both ends of an output, a count of tokens in a few
characters. What is shortened here is whole in --json."""

from __future__ import annotations

# Lines of one command, diff or output shown without --verbose, and of one
# prompt or reply: the conversation is context, what ran is the point
PREVIEW_LINES = 8
TALK_LINES = 3
PREVIEW_WIDTH = 200
# Of the output of a call or a hook, how many lines of its start and of
# its end are shown: when it failed, and with --verbose. The end comes
# first in worth, it is where a command says what went wrong. All of it
# is in --json.
FAILED_OUTPUT = (2, 6)
VERBOSE_OUTPUT = (10, 10)


def shortened(line: str) -> str:
    """A line cut to the width of a preview."""
    return line if len(line) <= PREVIEW_WIDTH else line[:PREVIEW_WIDTH] + "..."


def clip(lines: list[str], verbose: bool, limit: int = PREVIEW_LINES) -> list[str]:
    """Lines as shown: all of them with --verbose, else the first few."""
    if verbose:
        return lines
    shown = [shortened(line) for line in lines[:limit]]
    if len(lines) > limit:
        shown.append(f"... {len(lines) - limit} more lines, see --verbose")
    return shown


def clip_ends(lines: list[str], head: int, tail: int, hint: str) -> list[str]:
    """Lines of which both ends matter: the first and the last few, with
    how many were left out between them and where those are to be seen."""
    left_out = len(lines) - head - tail
    if left_out <= 0:
        return lines
    return [*lines[:head], f"... {left_out} more lines, {hint}", *lines[-tail:]]


def output_shown(lines: list[str], verbose: bool, failed: bool) -> list[str]:
    """Of the lines a call or a hook put out, those shown: the ends of
    them when it failed, more of them with --verbose, none otherwise.
    Never all of them, a command can put out thousands of lines."""
    if verbose:
        return clip_ends(lines, *VERBOSE_OUTPUT, "see --json")
    if not failed:
        return []
    ends = clip_ends(lines, *FAILED_OUTPUT, "see --verbose")
    return [shortened(line) for line in ends]


def lines_out(count: int) -> str:
    """How many lines a call or a hook put out, as its result says it."""
    return f"{count} line{'s' if count > 1 else ''} out"


def between(text: str, opening: str, closing: str) -> str | None:
    """What a text holds between the first of an opening tag and the
    closing one after it, none without the two. Found by where the one
    starts and the other then ends: a pattern that looks for the end from
    every start takes the square of the time over a text of starts
    without an end, which is a session's to write."""
    start = text.find(opening)
    end = text.find(closing, start + len(opening)) if start >= 0 else -1
    return text[start + len(opening) : end] if end >= 0 else None


def amount(count: int) -> str:
    """A number of tokens or of characters as shown: 950, 1.4k, 2.31M."""
    if count < 1000:
        return str(count)
    return f"{count / 1e3:.1f}k" if count < 1e6 else f"{count / 1e6:.2f}M"
