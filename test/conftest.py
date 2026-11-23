"""What every check can ask for by name."""

from __future__ import annotations

import contextlib
import os
import socket
import tempfile
from collections.abc import Iterator

import pytest


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
