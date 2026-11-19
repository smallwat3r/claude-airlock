"""What the launcher kept of sessions, read once for whatever tells of it:
--trace, which shows every line, and the lines said when a session ends
(see digest.py), which say what is worth a look.

Of the sessions that ran in a span of time, what each asked the egress
proxy for, its capture and the record of its processes (see records.py).
And of a transcript, what it holds next to what the launcher copied of it
(see recorder.py)."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from functools import cached_property
from pathlib import Path

from ..recording.capture import session_capture
from ..recording.egress_log import ProxyRequest, logged_requests, requests_made
from ..recording.pcap import Capture
from ..recording.processes import ProcessRecord, session_record
from ..recording.recorder import Compared, compare
from ..recording.records import TracedSession, recorded_sessions
from ..settings import Host
from .entries import read_entries, unreadable_lines


@dataclass(frozen=True)
class Traced:
    """A session of the record with what its line names, as far as that
    is still kept: its capture, or the record of its processes. A session
    can have a line for each, under one name."""

    session: TracedSession
    capture: Capture | None = None
    processes: ProcessRecord | None = None


@dataclass(frozen=True)
class Recorded:
    """What the launcher kept of some sessions that ran in a span of
    time. Each part is read when it is first asked for, and once."""

    host: Host
    sessions: list[TracedSession]
    start: float
    end: float

    @classmethod
    def between(cls, host: Host, start: float, end: float) -> Recorded:
        """What is kept of this project's sessions that ran at some point
        between start and end."""
        return cls(host, recorded_sessions(host, start, end), start, end)

    @cached_property
    def traced(self) -> list[Traced]:
        """Each session with its capture and the record of its
        processes."""
        return [
            Traced(
                session,
                session_capture(self.host, session),
                session_record(self.host, session),
            )
            for session in self.sessions
        ]

    @cached_property
    def requests(self) -> list[tuple[ProxyRequest, TracedSession]] | None:
        """What the filtered sessions asked the egress proxy for in that
        time, each request with the session that made it. Empty without a
        filtered session, none when the proxy's log cannot be read."""
        if not self.filtered:
            return []
        logged = logged_requests(stderr=subprocess.DEVNULL)
        if logged is None:
            return None
        return list(requests_made(logged, self.filtered, self.start, self.end))

    @property
    def filtered(self) -> list[TracedSession]:
        """The sessions whose network was filtered."""
        return [session for session in self.sessions if session.ip]

    @property
    def captured(self) -> list[Traced]:
        """The sessions that were captured, one whose capture is no
        longer kept too."""
        return [found for found in self.traced if found.session.capture]

    @property
    def watched(self) -> list[tuple[TracedSession, ProcessRecord]]:
        """The sessions with a record of their processes that is still
        kept, each with that record."""
        return [
            (found.session, found.processes) for found in self.traced if found.processes
        ]

    @property
    def several(self) -> bool:
        """Whether more than one container is among them, so that what
        each did has to say which it is of."""
        return len({session.name for session in self.sessions}) > 1

    def processes_of(self, session: TracedSession) -> ProcessRecord | None:
        """The record of the processes of a session, none when there is
        no such record or it is no longer kept: the one of the same
        container that ran at the same time."""
        for noted, record in self.watched:
            if (
                noted.name == session.name
                and noted.start <= session.until
                and noted.until >= session.start
            ):
                return record
        return None


@dataclass(frozen=True)
class ReadTranscript:
    """A transcript as it is now, next to what the launcher copied of
    it."""

    path: Path
    entries: list[dict]
    compared: Compared

    @classmethod
    def read(cls, host: Host, path: Path) -> ReadTranscript:
        return cls(path, read_entries(path), compare(host, path))

    @property
    def known(self) -> list[dict]:
        """Its entries, those the launcher copied when it holds none: a
        transcript that is no longer there is still what it was."""
        return self.entries or self.compared.gone

    @property
    def unreadable(self) -> int:
        """How many of its lines cannot be read."""
        return unreadable_lines(self.entries)
