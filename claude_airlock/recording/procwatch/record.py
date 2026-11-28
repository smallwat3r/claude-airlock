"""The record the watcher writes, a JSON object per line (see the package),
and what keeps it within its size: the launcher writes its records of a
session from outside the same way, see host_health.py."""

from __future__ import annotations

import enum
import json
import os
import time

# The record stops at this size, which bounds what a session can make the
# sidecar write
MOST_BYTES = 20 * 1024 * 1024
# Of that, what is kept for the connections and the sockets that wait for
# them, once the processes have used up the rest: which process made a
# connection is what the record is for, and a session that starts
# processes without end must not be rid of it that way
RESERVED = 4 * 1024 * 1024
# Of that again, what is kept for the record to say that it is full: its
# last line, whichever part filled first
LAST_WORD = 256


class Note(enum.StrEnum):
    """The notes a record can hold about itself, as the value of "note"
    in a line."""

    # The first line: the watcher got as far as watching
    STARTED = "started"
    # The record reached its size limit
    FULL = "full"
    # The watcher could not see which process holds a socket
    UNREADABLE = "unreadable"
    # The watcher is still there: said every HEARTBEAT_EVERY seconds, so
    # that a record that stops being written to for want of a watcher
    # (killed, crashed) is told from a session with nothing to note
    ALIVE = "alive"
    # Said aloud alone, as the last of what is said there of connections
    # and their processes, see MOST_ALOUD of watcher.py: the record has
    # the rest
    HUSHED = "hushed"
    # There were more sockets at once than are kept, see MOST_SOCKETS of
    # tables.py: the processes of the rest were not looked for
    TOO_MANY_SOCKETS = "too many sockets"
    # Lines that could not be written to the record (a full disk, which a
    # session can bring about), said once one can again: how many, from
    # when and until when, see Watch._write of watcher.py
    UNWRITTEN = "unwritten"
    # More files of secrets were seen open than are noted, see
    # MOST_OPENED: those past them were not
    TOO_MANY_OPENED = "too many opened"
    # Not the watcher's: the runtime began to tell the launcher what runs
    # in the session, see gvisor.py
    MONITORED = "monitored"


def stamped(**said: object) -> str:
    """A line of a record: what is said, and now."""
    return lined(time.time(), said)


def lined(when: float, said: dict) -> str:
    """A line of a record: what is said, and when it was so."""
    return json.dumps({"t": round(when, 3), **said}) + "\n"


class Room:
    """The room a record has, see MOST_BYTES, in two parts: what is not
    reserved (a process, how the session is doing, what is on the
    session's own loopback) leaves RESERVED for what is (a connection, a
    socket others can reach, a word of the watcher's own), a session must
    not be rid of those by what it makes the others fill. The record says
    that it is full when the first part is, and again as its last line
    when the reserved part is too, which a session can fill as well: one
    that ends without a word reads as a session with nothing more to
    note. The launcher's records from outside a session are kept the same
    way, see host_health.py."""

    def __init__(self) -> None:
        self._written = 0
        # Whether the part of what is not reserved is full, and whether
        # all of it is: nothing more is written then
        self._full = False
        self._ended = False

    def fitted(self, line: str, reserved: bool) -> str | None:
        """What to write of a line of a part: the line while there is
        room for it, the word that the record is full in its place once
        that part has filled, and nothing after that."""
        if self._ended or (self._full and not reserved):
            return None
        if reserved and self._written + len(line) > MOST_BYTES - LAST_WORD:
            self._ended = True
            return stamped(note=Note.FULL)
        if not reserved and self._written + len(line) > MOST_BYTES - RESERVED:
            self._full = True
            return stamped(note=Note.FULL)
        return line

    def took(self, line: str) -> None:
        """Count a line that was written."""
        self._written += len(line)


class LineFile:
    """The record as it is written: each line straight to its file, none
    held back to be written later, which would come out in the middle of
    another once it could. A line that cannot be written whole raises
    OSError, and what of it did go in is ended by the next line that is
    written, which starts with an end of line of its own: the part reads
    as a line that does not hold up, which the reader passes over, and
    the one after it is whole. Made with the given mode, and when new is
    set, only where there is no file yet: raises OSError otherwise."""

    def __init__(self, path: str, mode: int = 0o644, new: bool = False) -> None:
        flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_CLOEXEC
        self._file = os.open(path, flags | (os.O_EXCL if new else 0), mode)
        # Whether a line was cut short in the file, see write
        self._cut = False

    def write(self, line: str) -> None:
        data = ("\n" if self._cut else "").encode() + line.encode()
        while data:
            written = os.write(self._file, data)
            if not written:
                raise OSError("nothing could be written to the record")
            data = data[written:]
            self._cut = True
        self._cut = False

    def flush(self) -> None:
        """Nothing to do, every line is written as it comes."""

    def close(self) -> None:
        os.close(self._file)
