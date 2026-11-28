"""The sessions of a project as a list of them tells of each, a line or
an object a session: when it last did something, how many prompts and
calls it has, whether its transcript was removed, and its title. What
--trace list shows, and the chat's /resume asks which of."""

from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from ..recording.recorder import compare
from ..settings import Host
from .entries import entry_times, prompts, read_entries, short_id, title, tool_calls


@dataclass(frozen=True)
class SessionRow:
    """A session as the list of them tells of it: its transcript, when it
    last did something, none when it says nowhere, how many prompts and
    calls it has, whether its transcript was removed, and its title."""

    path: Path
    last: datetime | None
    prompts: int
    calls: int
    removed: bool
    title: str

    @property
    def line(self) -> str:
        """The line of --trace list: the time, the start of the id
        (enough to name it to --trace), the size and the title."""
        when = f"{self.last:%Y-%m-%d %H:%M}" if self.last else ""
        removed = "REMOVED  " if self.removed else ""
        return (
            f"{when:16}  {short_id(self.path)}  {self.prompts:3d} prompts"
            f"  {self.calls:4d} calls  {removed}{self.title}"
        )

    def as_json(self) -> str:
        """The same as a JSON object on a line, with the whole id and the
        time as an event's, see event_json."""
        last = self.last.astimezone() if self.last else None
        return json.dumps(
            {
                "session": self.path.stem,
                "last": last.isoformat(timespec="milliseconds") if last else None,
                "prompts": self.prompts,
                "calls": self.calls,
                "removed": self.removed,
                "title": self.title,
            }
        )


def session_rows(files: list[Path], host: Host | None = None) -> list[SessionRow]:
    """Each session as the list of them tells of it, see SessionRow. In
    the order of when it last did something, the latest first, and one
    that has no time last."""
    rows = []
    for path in files:
        entries = read_entries(path)
        removed = False
        if not entries and host is not None:
            # No longer there: as the launcher copied it, and said so
            entries = compare(host, path).gone
            removed = bool(entries)
        times = entry_times(entries)
        rows.append(
            SessionRow(
                path,
                max(times) if times else None,
                len(prompts(entries)),
                len(tool_calls(entries)),
                removed,
                title(entries),
            )
        )
    # Stable: the files come the latest first, see copy_rank
    rows.sort(key=lambda row: row.last.timestamp() if row.last else 0.0, reverse=True)
    return rows
