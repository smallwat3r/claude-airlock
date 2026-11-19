"""What the launchers noted of the sessions as they ran, as --trace, what
follows the sessions and the lines said when one ends show it: how the
sandbox of each was started (see started.py), the uses of the doors (see
door_events.py) and what a chat found changed in what Claude Code says
(see changes.py). One more such record is added here."""

from __future__ import annotations

from collections.abc import Callable

from .changes import change_event, change_events, change_record
from .door_events import door_events, use_event
from .doors import door_record
from .events import Event
from .notes import NewNotes, Notes
from .settings import Host
from .started import start_event, start_events, start_record

# Each record with how a note of it is shown, none for one that is not
RECORDS: tuple[tuple[Callable[[Host], Notes], Callable[[dict], Event | None]], ...] = (
    (start_record, start_event),
    (door_record, use_event),
    (change_record, change_event),
)
# What gives the summary rows and the events of each between two times
BETWEEN = (start_events, door_events, change_events)


def noted_events(
    host: Host, start: float, end: float, session: str | None = None
) -> tuple[list[tuple[str, str]], list[Event]]:
    """What was noted of this project's sessions between two times, as
    summary rows and as events. Of one session when it is named, by its
    container."""
    rows: list[tuple[str, str]] = []
    events: list[Event] = []
    for between in BETWEEN:
        some_rows, some_events = between(host, start, end, session)
        rows += some_rows
        events += some_events
    return rows, events


class NewlyNoted:
    """What is noted of this project's sessions from now on, of one
    session when it is named."""

    def __init__(self, host: Host, session: str | None = None):
        self._new = [
            (NewNotes(record(host), host.project_dir, session), shown)
            for record, shown in RECORDS
        ]

    def poll(self) -> list[Event]:
        """The events of what was noted since the last time."""
        events = (shown(note) for new, shown in self._new for note in new.poll())
        return [event for event in events if event]
