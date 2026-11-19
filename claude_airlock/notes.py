"""What the launcher notes of the sessions as they run: a file of its
state directory with a line per note, each with when it was, the project
and the session it is of, by its container.

The uses of the doors are one (see doors.py), what a chat found changed in
what Claude Code says another (see changes.py). Such a file is the
launcher's own, never mounted into a session. It is still read with care,
a line that does not hold up is passed over: several launchers write it at
once, and what a note holds may have been chosen by a session."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass

from .files import append_kept, json_object


@dataclass(frozen=True)
class Notes:
    """A record of notes: its file, and how many lines of it are kept."""

    path: str
    kept: int

    def add(self, project: str, session: str, **said: object) -> None:
        """Add a note of a session to the record, the oldest go past
        what is kept."""
        note = {"t": round(time.time(), 3), "project": project, "session": session}
        # What is said of it does not stand in for when and whose it is
        append_kept(self.path, json.dumps({**said, **note}), self.kept)

    def read(
        self, project: str, start: float, end: float, session: str | None = None
    ) -> list[dict]:
        """The notes of a project's sessions between two times, in the
        order they were added. Those of one session when it is named."""
        found = []
        try:
            with open(self.path, encoding="utf-8", errors="replace") as record:
                for line in record:
                    said = json_object(line) or {}
                    try:
                        when = float(said["t"])
                    except (ValueError, KeyError, TypeError):
                        continue
                    if (
                        said.get("project") == project
                        and start <= when <= end
                        and session in (None, said.get("session"))
                    ):
                        found.append(said)
        except OSError:
            return []
        return found


class NewNotes:
    """The notes added to a record since it was last looked at, for what
    follows the sessions as they run. From when it is made: what was
    noted before is a trace's to show."""

    def __init__(self, notes: Notes, project: str, session: str | None = None):
        self._notes = notes
        self._project = project
        self._session = session
        # The time of the note given last, and how many of that very time
        # were given, several can be noted in one moment
        self._since = time.time()
        self._given = 0

    def poll(self) -> list[dict]:
        """The notes added since the last time."""
        new = []
        at_since = 0
        read = self._notes.read
        for note in read(self._project, self._since, float("inf"), self._session):
            when = float(note["t"])
            if when == self._since:
                at_since += 1
                if at_since <= self._given:
                    continue
                self._given = at_since
            elif when > self._since:
                self._since, self._given, at_since = when, 1, 1
            # One noted out of order is given, the place is kept
            new.append(note)
        return new
