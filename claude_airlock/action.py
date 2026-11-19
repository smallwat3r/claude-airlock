"""What the launcher is asked to do."""

from __future__ import annotations

import enum


class Action(enum.Enum):
    """What the launcher does, each but RUN by the option of its name:
    a session of claude unless told otherwise."""

    RUN = "run"
    HELP = "help"
    REBUILD = "rebuild"
    PRUNE = "prune"
    DOCKERFILE = "dockerfile"
    # A session that runs bash and no claude
    SHELL = "shell"
    # A session of claude behind a chat, see chat/
    LINE_MODE = "line-mode"
    NET_LOG = "net-log"
    NET_RELOAD = "net-reload"
    TRACE = "trace"

    @property
    def option(self) -> str:
        return "--" + self.value
