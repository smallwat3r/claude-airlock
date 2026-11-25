"""What the chats of line mode found changed in what Claude Code says
(see chat/drift.py), as --trace and the lines said when a session ends
show it. A transcript does not tell that a chat showed less than it did,
so the chat notes it in a record of the launcher's, see notes.py."""

from __future__ import annotations

from ..events import Event, Kind, Who, clean
from ..settings import Host
from .notes import Notes

# The notes kept, a chat adds a few at most (see MOST_SAID of drift.py)
KEPT_CHANGES = 1000


def change_record(host: Host) -> Notes:
    """The record of the changes that chats found."""
    return Notes(host.changes_file, KEPT_CHANGES)


def note_change(host: Host, session: str, what: str) -> None:
    """Add what a chat found changed to the record, for the session of
    that container."""
    change_record(host).add(host.project_dir, session, what=what)


def change_event(said: dict) -> Event:
    """A note of the record as an event. The record is the launcher's
    own, what it holds still comes from a session: it is cleaned like the
    rest. What changed is among its values as the change, the record's
    name for it is the one an event has for what it is."""
    change = clean(said.get("what", ""))
    fields = {"change": change}
    return Event(float(said["t"]), Who.CLAUDE, Kind.CHANGED, [change], fields)


def change_events(
    host: Host, start: float, end: float, session: str | None = None
) -> tuple[list[tuple[str, str]], list[Event]]:
    """What the chats of this project's sessions found changed between
    two times, as a summary row when there is any and as events. Of one
    session when it is named."""
    noted = change_record(host).read(host.project_dir, start, end, session)
    events = [change_event(said) for said in noted]
    if not events:
        return [], []
    said = f"CHANGED what it says, {len(events)} noted: line mode may have shown less"
    return [("claude code", said)], events
