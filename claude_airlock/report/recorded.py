"""What the launcher kept of sessions, read once for whatever tells of it:
--trace, which shows every line, and the lines said when a session ends
(see digest.py), which say what is worth a look.

Of the sessions that ran in a span of time, what each asked the egress
proxy for, its capture and the record of its processes (see records.py).
And of a transcript, what it holds next to what the launcher copied of it
(see recorder.py)."""

from __future__ import annotations

import itertools
import subprocess
from dataclasses import dataclass
from functools import cached_property
from pathlib import Path

from ..recording.capture import session_capture
from ..recording.egress_log import ProxyLog, ProxyRequest, proxy_log, requests_made
from ..recording.pcap import Capture
from ..recording.processes import ProcessRecord, session_record
from ..recording.recorder import Compared, compare
from ..recording.records import TracedSession, recorded_sessions
from ..recording.started import stay_between
from ..settings import Host
from .entries import read_transcript, unreadable_lines
from .links import Links


@dataclass(frozen=True)
class Traced:
    """A session of the record with what its line names, as far as that
    is still kept: its capture, or the record of its processes. A session
    can have a line for each, under one name."""

    session: TracedSession
    capture: Capture | None = None
    processes: ProcessRecord | None = None
    # The numbers the connections of its capture are told by, see
    # links.py: none without a capture, and for one told of alone
    links: Links | None = None


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
    def stay(self) -> tuple[float, float]:
        """From when to when the sessions were there, the span of time
        itself and all of each session's stay: what a session did is
        looked for over the whole of it. A span is that of a transcript,
        from its first entry to its last, and a session does things
        after the last: a command left running reaches the network, or
        asks the SSH agent, while the user reads the reply. Cut at the
        last entry, that would be in no trace. By when each session is
        noted to have started and to be over (see stay_between), and by
        the end the record of the network has of it: not by an end that
        is only taken from the next session at its address, which may be
        long after, and another project's."""
        first, last = stay_between(self.host, self.start, self.end)
        ends = [session.end for session in self.sessions if session.end is not None]
        return (
            min([first, *(session.start for session in self.sessions)]),
            max([last, *ends]),
        )

    @cached_property
    def traced(self) -> list[Traced]:
        """Each session with its capture and the record of its
        processes. The connections of the captures are numbered by one
        count, see links.py."""
        numbers = itertools.count(1)
        found = []
        for session in self.sessions:
            capture = session_capture(self.host, session)
            links = Links(numbers) if capture else None
            record = session_record(self.host, session)
            found.append(Traced(session, capture, record, links))
        return found

    @cached_property
    def proxy_log(self) -> ProxyLog | None:
        """The egress proxy's log, read once. None without a filtered
        session, whose requests are all it is read for, and when it
        cannot be read."""
        return proxy_log(stderr=subprocess.DEVNULL) if self.filtered else None

    @cached_property
    def requests(self) -> list[tuple[ProxyRequest, TracedSession]] | None:
        """What the filtered sessions asked the egress proxy for in that
        time, each request with the session that made it. Empty without a
        filtered session, none when the proxy's log cannot be read."""
        if not self.filtered:
            return []
        if self.proxy_log is None:
            return None
        logged = self.proxy_log.requests
        return list(requests_made(logged, self.filtered, *self.stay))

    @property
    def log_begins(self) -> float | None:
        """When what is left of the proxy's log begins, where that is
        after a filtered session of these started: what the session asked
        before then is not in it, see ProxyLog. None when the log holds
        all of their time, as far as is known."""
        begins = self.proxy_log.begins if self.proxy_log else None
        started = min((session.start for session in self.filtered), default=None)
        if begins is None or started is None or begins <= started:
            return None
        return begins

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
    it, and whether it was read whole, see read_transcript."""

    path: Path
    entries: list[dict]
    compared: Compared
    whole: bool

    @classmethod
    def read(cls, host: Host, path: Path) -> ReadTranscript:
        entries, whole = read_transcript(path)
        return cls(path, entries, compare(host, path), whole)

    @property
    def known(self) -> list[dict]:
        """Its entries, those the launcher copied when it holds none: a
        transcript that is no longer there is still what it was."""
        return self.entries or self.compared.gone

    @property
    def unreadable(self) -> int:
        """How many of its lines cannot be read."""
        return unreadable_lines(self.entries)
