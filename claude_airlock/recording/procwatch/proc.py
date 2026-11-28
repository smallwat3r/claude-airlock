"""What /proc says of a process, as it is kept: when it started, its parent,
its program and its command line, each as long as the record keeps it.
The program and the command line are the session's to make as long as it
likes, gVisor tells them as they are, see gvisor.py."""

from __future__ import annotations

import os

# What is kept of a command line: so many arguments, of so many characters
# each and in all. A command line is the session's to make as long as it
# likes, and a few hundred long ones must not be what fills the record.
MOST_ARGUMENTS = 64
MOST_ARGUMENT = 512
MOST_COMMAND = 2048
# What stands for the rest of a command line that was cut
CUT = "..."
# What a process is as it is read, see process: when it started, its
# parent, its program and its command line
ProcessRead = tuple[str, int, str, list[str]]


def read(path: str) -> bytes:
    with open(path, "rb") as file:
        return file.read()


def process(pid: int) -> ProcessRead | None:
    """When a process started (in ticks, only good to compare), its
    parent, its program and its command line, none for one that is gone."""
    try:
        # After the name of the command, which can hold anything
        stat = read(f"/proc/{pid}/stat").rsplit(b")", 1)[1].split()
        started, parent = stat[19].decode(), int(stat[1])
        raw = read(f"/proc/{pid}/cmdline")
    except (OSError, IndexError, ValueError):
        return None
    try:
        program = os.readlink(f"/proc/{pid}/exe")
    except OSError:
        # A kernel thread, or one that is not the user's to look into
        program = ""
    return started, parent, kept_path(program), command_line(raw)


def kept_path(path: str) -> str:
    """A path as it is kept, of a program or of a file of secrets: its
    first MOST_ARGUMENT characters, and CUT in the place of the rest.
    Where a file is is the session's to choose, as long as a path."""
    return path[:MOST_ARGUMENT] + CUT if len(path) > MOST_ARGUMENT else path


def command_line(raw: bytes, cut: bool = False) -> list[str]:
    """A command line as it is kept, see MOST_COMMAND: its arguments from
    the first on, and CUT in the place of what there was no room for, or
    of what was not given, where raw is cut short itself (cut). Those
    past MOST_ARGUMENTS are not taken apart, a command line can hold
    hundreds of thousands."""
    given = raw.split(b"\0", MOST_ARGUMENTS)
    if given and not given[-1]:
        given.pop()
    argv: list[str] = []
    room = MOST_COMMAND
    cut |= len(given) > MOST_ARGUMENTS
    for argument in given[:MOST_ARGUMENTS]:
        if not room:
            cut = True
            break
        whole = argument.decode("utf-8", "replace")
        kept = whole[: min(MOST_ARGUMENT, room)]
        cut |= len(kept) < len(whole)
        argv.append(kept)
        room -= len(kept)
    return [*argv, CUT] if cut else argv
