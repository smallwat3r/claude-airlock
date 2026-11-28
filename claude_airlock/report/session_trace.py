"""The trace of a session as trace.py makes it, with what it was made
from that its events do not hold, for what is made of traces: the stats
of several sessions, see stats.py."""

from __future__ import annotations

from dataclasses import dataclass

from ..events import Event
from .summary import Flagged


@dataclass(frozen=True)
class SessionTrace:
    """The trace of a session: its header and its events, with the
    entries its transcripts are known to hold, those of its subagents
    too, the project it ran in, and how many of what it read show signs
    of being planted and of its calls were flagged."""

    header: list[str]
    events: list[Event]
    entries: list[dict]
    project_dir: str
    planted: int
    flagged: Flagged
