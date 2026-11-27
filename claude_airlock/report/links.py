"""What ties the lines of a capture together: a number for each
connection, said ahead of every line that tells of it, and under it one
for each thing sent over it.

A connection has several lines. Followed as it happens, one when it
opens, one each time it is said to be still open, one for what became of
it. And in any trace one for each upload over it and for the answer that
came back, at the time each began: an answer shows long after the uploads
that followed the one it is to. By the destination alone they are not
told apart, a session keeps several connections to one place, and sends
dozens of requests over each.

So a connection is n2, wherever it is told of, and the eighth thing of
4 kB or more sent over it is n2.8, as is what came back for it: the
upload, its answer, the rest of an answer that paused, and the request to
the model that the upload carried (see wire.py). The numbers are given in
the order the connections are first told of, by one count for all the
captures of a trace or of what follows the sessions, so that none is used
twice in it. They tie lines together and are no more than that: another
trace of the same session may number them otherwise."""

from __future__ import annotations

import itertools
import math
from collections.abc import Iterator

from ..events import connection_link
from ..recording.pcap import Capture, Connection
from ..recording.uploads import Key, Upload


class Links:
    """The numbers the connections of one capture are told by, given as
    they are first asked for, see the module. With numbers, the count
    they are taken from when it is shared with other captures."""

    def __init__(self, numbers: Iterator[int] | None = None):
        self._numbers = itertools.count(1) if numbers is None else numbers
        # Each connection that has a number, by what it is, and held
        # for as long as its number is: no other can be taken for it
        self._given: dict[int, tuple[Connection, int]] = {}
        # Those of the connections that were not seen to open, by what
        # they are known by: the capture began later, or lost the packet
        self._unseen: dict[Key, int] = {}

    def of(self, connection: Connection) -> str:
        """What a connection is told by: n and its number."""
        known = id(connection)
        if known not in self._given:
            self._given[known] = (connection, next(self._numbers))
        return connection_link(self._given[known][1])

    def of_upload(self, capture: Capture, upload: Upload) -> str:
        """What an upload of the capture and what came back for it are
        told by: the number of the connection it went over, then which
        it is of the uploads over that connection that are worth a line.
        The number of the connection alone for one that is too short for
        a line."""
        connection = capture.connection_at(upload.key, upload.began)
        if connection is None:
            if upload.key not in self._unseen:
                self._unseen[upload.key] = next(self._numbers)
            over = connection_link(self._unseen[upload.key])
            since = -math.inf
        else:
            over, since = self.of(connection), connection.when
        parts = (capture.uploads, capture.elsewhere)
        place = next(filter(None, (part.place(upload, since) for part in parts)), 0)
        return f"{over}.{place}" if place else over


def links_of(links: Links | None) -> Links:
    """The numbers a capture is told by: those given, or its own from 1
    for a capture that is told of alone."""
    return Links() if links is None else links
