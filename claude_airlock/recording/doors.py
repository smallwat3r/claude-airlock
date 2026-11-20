"""The record of each use of the two doors a session can be given out of
the sandbox: the SSH agent (CLAUDE_AIRLOCK_SSH_AGENT=1) and the Docker
socket (CLAUDE_AIRLOCK_DOCKER_SOCKET), for --trace to show.

Both go to one file of the launcher's state directory, a line per use,
which names the project and the session. The agent's uses are noted by
ssh_agent.py, the socket's by socket_watch.py. How a use is shown is in
door_events.py."""

from __future__ import annotations

import enum

from ..settings import Host
from .notes import Notes

# The lines kept, the oldest go once there are more
KEPT_USES = 5000
# Who refused a request to the agent, when that was not the agent
BY_LAUNCHER = "launcher"


class Door(str, enum.Enum):
    """A way out of the sandbox a session can be given, as a use of it
    is noted."""

    SSH_AGENT = "ssh-agent"
    DOCKER = "docker"


class AgentUse(str, enum.Enum):
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


def read_uses(
    host: Host, start: float, end: float, session: str | None = None
) -> list[dict]:
    """The uses of a door by this project's sessions between two times,
    in the order they were noted. Those of one session when it is named,
    by its container."""
    return door_record(host).read(host.project_dir, start, end, session)
