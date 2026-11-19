"""Reading a message of bytes front to back: a packet, a DNS answer, a
request to the SSH agent. What is read was written by a session, so a
message that is not what it was read as ends the read of that message,
nothing more."""

from __future__ import annotations


class NotThis(Exception):
    """The bytes are not the kind of message they were read as."""


class Cursor:
    """Reads a message front to back, in network byte order. Reading past
    its end raises NotThis: a truncated or foreign message ends the read
    of that message, nothing more."""

    def __init__(self, data: bytes, at: int = 0) -> None:
        self.data = data
        self.at = at

    def take(self, count: int) -> bytes:
        taken = self.data[self.at : self.at + count]
        if count < 0 or len(taken) < count:
            raise NotThis
        self.at += count
        return taken

    def number(self, size: int) -> int:
        return int.from_bytes(self.take(size), "big")

    def skip(self, count: int) -> None:
        self.take(count)

    def rest(self) -> bytes:
        return self.data[self.at :]
