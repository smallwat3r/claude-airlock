"""Noticing that a session ran into its memory limit (CLAUDE_AIRLOCK_MEMORY).

The kernel then ends a process of the session, or the session itself, and
all that is left of it is an exit status of 137 from a container that is
removed as it ends. Docker says so as it happens, as an event of the
container: the launcher listens for those while a session runs, from
outside it, and says what it heard when the session is over.

That a session ran into its limit of processes (CLAUDE_AIRLOCK_PIDS) is no
event of docker's. The sidecar that notes the processes reads it from the
session's own count, see the procwatch package. Under a runtime where no
sidecar can, the launcher reads it from the cgroup of the container, see
host_health.py."""

from __future__ import annotations

import subprocess
import threading
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from dataclasses import dataclass

from ..docker import docker_popen
from ..settings import Settings

# The event of a container that ran out of memory, as docker names it
OUT_OF_MEMORY = "oom"


@dataclass
class LimitsHit:
    """What a session was heard to run into, to be said when it is over."""

    memory: str = ""
    # How often docker said a process of it was ended for want of memory
    out_of_memory: int = 0

    def lines(self) -> list[str]:
        if not self.out_of_memory:
            return []
        times = "" if self.out_of_memory == 1 else f" {self.out_of_memory} times"
        said = (
            f"ran into its memory limit of {self.memory}{times}, what it ran was"
            " ended for it: CLAUDE_AIRLOCK_MEMORY sets the limit"
        )
        return [said]


def listen(events: subprocess.Popen, hit: LimitsHit) -> None:
    for line in events.stdout or ():
        if line.strip() == OUT_OF_MEMORY:
            hit.out_of_memory += 1


@contextmanager
def limits_watched(settings: Settings, name: str) -> Iterator[LimitsHit]:
    """While a session runs, listen for what docker says of its container
    by that name. Gives what was heard, which is whole once the block is
    left. A docker that cannot be listened to is passed over: the session
    does not depend on it."""
    hit = LimitsHit(memory=settings.memory)
    try:
        events = docker_popen(
            "events",
            f"--filter=container={name}",
            f"--filter=event={OUT_OF_MEMORY}",
            "--format={{.Action}}",
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            errors="replace",
        )
    except OSError:
        yield hit
        return
    listener = threading.Thread(target=listen, args=(events, hit), daemon=True)
    listener.start()
    try:
        yield hit
    finally:
        # What docker said as the session ended is read first
        listener.join(0.3)
        _ended(events)
        listener.join(2.0)
        # Once the listener is done with it, which the end of docker sees
        # to: closed under a read, the close would wait for the read
        if events.stdout and not listener.is_alive():
            events.stdout.close()


def _ended(events: subprocess.Popen) -> None:
    """End what listens to docker, killed when it does not end when it
    is told to."""
    with suppress(OSError):
        events.terminate()
    try:
        events.wait(2.0)
    except subprocess.TimeoutExpired:
        with suppress(OSError):
            events.kill()
        with suppress(subprocess.TimeoutExpired):
            events.wait(2.0)
