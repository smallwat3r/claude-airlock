"""What the launchers noted of the sessions as they ran, as --trace, what
follows the sessions and the lines said when one ends show it: how the
sandbox of each was started (see started.py), the uses of the doors (see
door_events.py) and what a chat found changed in what Claude Code says
(see changes.py). One more such record is added here."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass

from ..events import Event
from ..recording.changes import change_event, change_events, change_record
from ..recording.doors import door_record
from ..recording.notes import NewNotes, Notes
from ..recording.started import start_event, start_events, start_record
from ..settings import Host
from .door_events import door_events, use_event

# Summary rows, each what it is about and what is said of it, and events
Noted = tuple[list[tuple[str, str]], list[Event]]


@dataclass(frozen=True)
class NoteKind:
    """One kind of thing the launchers note of the sessions."""

    # Where the notes are kept
    record: Callable[[Host], Notes]
    # How a note of it is shown, none for one that is not
    event: Callable[[dict], Event | None]
    # What gives the summary rows and the events between two times, of
    # one session when it is named
    between: Callable[[Host, float, float, str | None], Noted]


KINDS = (
    NoteKind(start_record, start_event, start_events),
    NoteKind(door_record, use_event, door_events),
    NoteKind(change_record, change_event, change_events),
)


def noted_events(
    host: Host, start: float, end: float, session: str | None = None
) -> Noted:
    """What was noted of this project's sessions between two times, as
    summary rows and as events. Of one session when it is named, by its
    container."""
    rows: list[tuple[str, str]] = []
    events: list[Event] = []
    for kind in KINDS:
        some_rows, some_events = kind.between(host, start, end, session)
        rows += some_rows
        events += some_events
    return rows, events


class NewlyNoted:
    """What is noted of this project's sessions from now on, of one
    session when it is named."""

    def __init__(self, host: Host, session: str | None = None):
        self._new = [
            (NewNotes(kind.record(host), host.project_dir, session), kind.event)
            for kind in KINDS
        ]

    def poll(self) -> list[Event]:
        """The events of what was noted since the last time."""
        events = (shown(note) for new, shown in self._new for note in new.poll())
        return [event for event in events if event]
