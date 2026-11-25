"""What every check can ask for by name."""

from __future__ import annotations

import contextlib
import os
import socket
import tempfile
from collections.abc import Iterator

import pytest

# The processes one worker is given of the limit of a sandbox the checks
# run in, which makes 8 workers of the default limit of 512. Far more
# than a worker has at a time, with the launchers, fake dockers, shells
# and terminals its checks start: the rest is room for what else the
# session runs meanwhile, such as the same checks for another reviewer.
# Under gVisor, where the host counts slots that are not given back, one
# run took 380 of them on 24 workers and 220 on 8, three runs at once 990
# and 520.
PROCESSES_A_WORKER = 64


def pytest_xdist_auto_num_workers(config: pytest.Config) -> int | None:
    """How many workers --numprocesses=auto stands for. Inside a sandbox
    as many as its limit of processes (CLAUDE_AIRLOCK_PIDS) has room for,
    never more than there are cores: under gVisor a session that runs into
    that limit is ended as a whole. Anywhere else pytest-xdist counts the
    cores itself."""
    limit = os.environ.get("CLAUDE_AIRLOCK_PIDS", "")
    if not limit.isdigit():
        return None
    cores = os.process_cpu_count() or 1
    return max(1, min(cores, int(limit) // PROCESSES_A_WORKER))


@pytest.fixture
def cleanup() -> Iterator[contextlib.ExitStack]:
    """What a check leaves behind is undone through this when it is over,
    the last of it first: callback() for a call, enter_context() for what
    is entered, a patch for one."""
    with contextlib.ExitStack() as undone:
        yield undone


@pytest.fixture
def unix_socket(cleanup: contextlib.ExitStack) -> str:
    """The path of a Unix socket that is there, for what only needs one to
    exist. A short path, those of sockets are limited to about 100 bytes."""
    directory = cleanup.enter_context(tempfile.TemporaryDirectory(dir="/tmp"))
    path = os.path.join(directory, "docker.sock")
    cleanup.enter_context(socket.socket(socket.AF_UNIX)).bind(path)
    return path
