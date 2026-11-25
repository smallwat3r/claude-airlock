"""The record of each use of the two doors a session can be given out of
the sandbox: the SSH agent (CLAUDE_AIRLOCK_SSH_AGENT=1) and the Docker
socket (CLAUDE_AIRLOCK_DOCKER_SOCKET), for --trace to show.

Both go to one file of the launcher's state directory, a line per use,
which names the project and the session. The agent's uses are noted by
ssh_agent.py, the socket's by socket_watch.py. How a use is shown is in
door_events.py."""

from __future__ import annotations

import enum
import json
import threading
from collections import Counter
from contextlib import suppress

from ..settings import Host
from .notes import Notes

# The lines kept, the oldest go once there are more
KEPT_USES = 5000
# No more lines than this are one session's, and no more of them say the
# same: the record is of all the sessions, and one that could fill it
# (asking the agent for its keys costs nothing) would be rid of what it,
# or another, did before. Past these a use is counted, see SessionUses.
MOST_SESSION_USES = 1000
MOST_ALIKE = 20
# What a session was refused has lines of its own, no more than this:
# asking for what is refused costs nothing either (a signature with a key
# the agent does not have), and any number of those must not use up the
# lines of what the session was let do after them
MOST_REFUSED = 200
# No more kinds than this are counted apart, the rest as one: a kind can
# be the session's to name (the method of a call to the Docker socket),
# and one counted for each name would grow with every call
MOST_KINDS = 16
OTHER_KINDS = "other"
# In a line of the record: the uses that were counted and not noted one
# by one, how many of each kind once the session is over
UNRECORDED = "unrecorded"
# In a line of the record, that a use was refused, and what is said ahead
# of a kind for those of it that were: they are counted apart
REFUSED = "refused"
# Who refused a request to the agent, when that was not the agent
BY_LAUNCHER = "launcher"


class Door(enum.StrEnum):
    """A way out of the sandbox a session can be given, as a use of it
    is noted."""

    SSH_AGENT = "ssh-agent"
    DOCKER = "docker"


class AgentUse(enum.StrEnum):
    """What the agent was asked: to sign, to list its keys, or something
    that is not a session's to ask."""

    SIGN = "sign"
    LIST = "list"
    OTHER = "other"


def door_record(host: Host) -> Notes:
    """The record of the uses of the doors."""
    return Notes(host.doors_file, KEPT_USES)


def note_use(host: Host, session: str, door: Door, **said: object) -> None:
    """Add a use of a door by a session of this project to the record,
    the oldest go past KEPT_USES."""
    door_record(host).add(host.project_dir, session, door=door.value, **said)


class SessionUses:
    """The uses one session makes of a door, noted as they come. Each is
    a line of the record until the session has MOST_SESSION_USES of them,
    or MOST_ALIKE that say the same. What it was refused is kept apart
    from what it was let do, with MOST_REFUSED lines of its own: neither
    uses up the lines of the other. From then on a use is counted by its
    kind, a refused one apart: a line says at once that this began, and
    one says how many there were of each kind when the session is over.
    Used from several threads at once."""

    def __init__(self, host: Host, session: str, door: Door) -> None:
        self._host = host
        self._session = session
        self._door = door
        self._lock = threading.Lock()
        # The lines there are of what was let through and of what was
        # refused, and what was counted of each without a line, by kind
        self._noted = {False: 0, True: 0}
        self._alike: Counter[str] = Counter()
        self._unrecorded: dict[bool, Counter[str]] = {False: Counter(), True: Counter()}

    def note(self, kind: str, *, refused: bool = False, **said: object) -> None:
        """Note a use, of a kind it is counted as when it is not noted
        on its own, and whether it was refused, which its line says.
        Raises OSError when the record cannot be written."""
        if refused:
            said[REFUSED] = True
        same = json.dumps(said, sort_keys=True, default=str)
        most = MOST_REFUSED if refused else MOST_SESSION_USES
        with self._lock:
            if self._noted[refused] >= most or self._alike[same] >= MOST_ALIKE:
                counted = self._unrecorded[refused]
                if not counted:
                    # Of which of the two: that the refusals are no
                    # longer noted says nothing of what was let through
                    which = {REFUSED: True} if refused else {}
                    note_use(
                        self._host, self._session, self._door, unrecorded=True, **which
                    )
                known = kind in counted
                apart = known or len(counted) < MOST_KINDS
                counted[kind if apart else OTHER_KINDS] += 1
                return
            self._noted[refused] += 1
            self._alike[same] += 1
            note_use(self._host, self._session, self._door, **said)

    def close(self) -> None:
        """Say how many uses were counted and not noted, if any were:
        of each kind, and apart how many of it were refused."""
        with self._lock:
            counted = dict(self._unrecorded[False])
            for kind, times in self._unrecorded[True].items():
                counted[f"{REFUSED} {kind}"] = times
            self._unrecorded = {False: Counter(), True: Counter()}
        if counted:
            # A full disk or the like: the line that said it began stays
            with suppress(OSError):
                note_use(self._host, self._session, self._door, unrecorded=counted)


def read_uses(
    host: Host, start: float, end: float, session: str | None = None
) -> list[dict]:
    """The uses of a door by this project's sessions between two times,
    in the order they were noted. Those of one session when it is named,
    by its container."""
    return door_record(host).read(host.project_dir, start, end, session)
