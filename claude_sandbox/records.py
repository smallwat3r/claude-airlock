"""The launcher's record of the sessions whose network use can be traced:
a line per session in its state directory, with the address a filtered one
had on the internal network (see network.py), the file of its capture
(see capture.py) or the file of its processes (see processes.py). Written
as a session runs and ends, read by --trace.

The file is the launcher's own, never mounted into a session. It is still
read with care, a line that does not hold up is passed over: it is written
by several launchers at once, and may be cut off by one that was killed."""

from __future__ import annotations

import bisect
import dataclasses
import fcntl
import json
import math
import os
from dataclasses import dataclass
from datetime import datetime

from .settings import Host, private_dir

# The lines kept, the oldest go once there are more. Well past the captures
# that are kept (see capture.py) and what the egress proxy's log holds.
KEPT_SESSIONS = 1000


def _moment(value: object) -> float | None:
    """A time as seconds since the epoch, none for anything else or for
    one that could not be shown as a date."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    try:
        if not math.isfinite(value):
            return None
        datetime.fromtimestamp(value)
    except (ValueError, OverflowError, OSError):
        return None
    return float(value)


@dataclass(frozen=True)
class NetSession:
    """A session with a network record: its container's name, its project
    and when it started, with its address for a filtered one, and for a
    captured one the file of its capture and when it ended. A line of its
    own has the file of its processes."""

    name: str
    project: str
    start: float
    # On the filtered network, empty for a session that was not filtered
    ip: str = ""
    # A file of the captures directory, empty without a capture
    capture: str = ""
    # A file of the process records directory, empty without one
    processes: str = ""
    # Not known of a filtered session, whose line is written as it starts
    end: float | None = None
    # Until when it ran as far as the record tells, see recorded_sessions
    until: float = math.inf

    def as_line(self) -> str:
        """The session as its line of the record."""
        kept = {"name": self.name, "project": self.project, "start": self.start}
        if self.ip:
            kept["ip"] = self.ip
        if self.capture:
            kept["capture"] = self.capture
        if self.processes:
            kept["processes"] = self.processes
        if self.end is not None:
            kept["end"] = self.end
        return json.dumps(kept)

    @classmethod
    def from_line(cls, line: str) -> NetSession | None:
        """The session of a line of the record, none for a line that is
        not one: it has to say what ran, when, and where its network use
        is to be found."""
        try:
            said = json.loads(line)
        except (ValueError, RecursionError):
            return None
        if not isinstance(said, dict):
            return None
        name, project = said.get("name"), said.get("project")
        ip, capture = said.get("ip", ""), said.get("capture", "")
        processes = said.get("processes", "")
        start, end = _moment(said.get("start")), _moment(said.get("end"))
        if start is None or not (
            isinstance(name, str)
            and isinstance(project, str)
            and isinstance(ip, str)
            and isinstance(capture, str)
            and isinstance(processes, str)
        ):
            return None
        # Only ever a file of its directory, whatever the line says
        capture, processes = os.path.basename(capture), os.path.basename(processes)
        if (capture or processes) and end is None:
            return None
        if not ip and not capture and not processes:
            return None
        return cls(name, project, start, ip, capture, processes, end)


def append_kept(path: str, line: str, kept: int) -> None:
    """Add a line to one of the launcher's records, a file of its state
    directory for the user alone, and let go of the oldest lines past
    kept. Under a lock, launchers of other sessions write there too."""
    private_dir(os.path.dirname(path))
    descriptor = os.open(path, os.O_RDWR | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(descriptor, "a+", encoding="utf-8", errors="replace") as record:
        fcntl.flock(record, fcntl.LOCK_EX)
        record.write(line + "\n")
        record.flush()
        record.seek(0)
        lines = record.readlines()
        if len(lines) > kept:
            record.truncate(0)
            record.writelines(lines[-kept:])


def record_net_session(host: Host, session: NetSession) -> None:
    """Add a session to the record, the oldest go past KEPT_SESSIONS."""
    append_kept(host.net_sessions_file, session.as_line(), KEPT_SESSIONS)


def read_net_sessions(host: Host) -> list[NetSession]:
    """Every session of the record, none when nothing was recorded yet."""
    try:
        with open(host.net_sessions_file, encoding="utf-8", errors="replace") as record:
            sessions = [NetSession.from_line(line) for line in record]
    except FileNotFoundError:
        return []
    return [session for session in sessions if session]


def recorded_sessions(host: Host, start: float, end: float) -> list[NetSession]:
    """The sessions of this project with a network record that ran at some
    point between start and end. A filtered one, known by its address, ran
    until a later session was given the same address."""
    sessions = read_net_sessions(host)
    starts: dict[str, list[float]] = {}
    for session in sessions:
        if session.ip:
            starts.setdefault(session.ip, []).append(session.start)
    for same_address in starts.values():
        same_address.sort()
    found = []
    for session in sessions:
        if session.project != host.project_dir:
            continue
        until = session.end
        if until is None:
            later = starts.get(session.ip, [])
            at = bisect.bisect_right(later, session.start)
            until = later[at] if at < len(later) else math.inf
        if session.start <= end and until >= start:
            found.append(dataclasses.replace(session, until=until))
    return found
