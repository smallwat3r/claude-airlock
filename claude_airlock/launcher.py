"""The launcher of a session as its records know it, and whether a session
is still going."""

from __future__ import annotations

import os
import subprocess
from dataclasses import dataclass
from pathlib import Path

from .docker import container_gone

# The seconds ps is given to say when a process started
PS_SECONDS = 10


def process_started(pid: int) -> str:
    """When a process started, as text that is only good to compare, empty
    when that cannot be told or there is no such process."""
    try:
        # Linux: in clock ticks since boot, the 22nd value of the line,
        # counted from behind the command, which can hold anything
        said = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8", errors="replace")
        return said.rsplit(")", 1)[1].split()[19]
    except (OSError, IndexError):
        pass
    try:
        listed = subprocess.run(
            ["ps", "-o", "lstart=", "-p", str(pid)],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            errors="replace",
            check=False,
            timeout=PS_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return " ".join(listed.stdout.split())


@dataclass(frozen=True)
class Launcher:
    """The launcher of a session as its records know it: by its process
    id, and by when that process started, which tells it from a later
    process that was given the same id. The start is empty when it could
    not be told, and in a record of an earlier version."""

    pid: int
    started: str = ""

    @classmethod
    def current(cls) -> Launcher:
        return cls(os.getpid(), process_started(os.getpid()))

    def as_fields(self) -> dict[str, object]:
        """The launcher as the fields of a record of the launcher's."""
        return {"pid": self.pid, "launched": self.started}

    @classmethod
    def from_fields(cls, fields: dict) -> Launcher:
        """The launcher of a record, see as_fields. Raises KeyError,
        ValueError or TypeError for a record without one."""
        # No start in a record of an earlier version
        return cls(int(fields["pid"]), str(fields.get("launched", "")))

    @property
    def alive(self) -> bool:
        # Zero and below would ask about process groups, not a process
        if self.pid <= 0:
            return False
        try:
            os.kill(self.pid, 0)
        except (ProcessLookupError, OverflowError):
            # Gone, or no process id at all
            return False
        except OSError:
            # Not ours to signal, so it exists
            pass
        started = process_started(self.pid)
        return not self.started or not started or started == self.started


def session_alive(launcher: Launcher, container: str) -> bool:
    """Whether a session is still going: its launcher or its container is
    there. The container can outlive a killed launcher. One docker says
    nothing of is taken to be there, see container_gone."""
    return launcher.alive or not container_gone(container)
