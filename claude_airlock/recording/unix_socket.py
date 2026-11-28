"""A Unix socket the launcher waits on for one session, for what it puts
next to the session to connect to: the door in front of the SSH agent
(see ssh_agent.py), and the socket gVisor tells what runs to (see
gvisor.py). The user's alone: no session is given the directory it is in,
and nothing but the user and root is to connect to it."""

from __future__ import annotations

import hashlib
import os
import socket
from contextlib import suppress

from ..files import private_dir

# The path of a Unix socket has room for so many bytes on Linux, fewer on
# macOS, where binding to a longer one fails all the same
SOCKET_PATH = 107


class PrivateSocket:
    """A socket of a kind that waits for connections, in a directory of
    the user's alone and of mode 0600 itself, by a short name of the
    session's: the path of a socket cannot be long. Made anew, one a
    launcher of the same name and process id left is taken away first.
    Raises OSError when it cannot be made."""

    def __init__(
        self, directory: str, session: str, kind: socket.SocketKind, backlog: int
    ) -> None:
        name = hashlib.sha256(session.encode()).hexdigest()[:12]
        self.path = os.path.join(private_dir(directory), f"{name}-{os.getpid()}.sock")
        if len(self.path.encode()) > SOCKET_PATH:
            raise OSError(f"the path of its socket is too long: {self.path}")
        with suppress(FileNotFoundError):
            os.unlink(self.path)
        self._socket = socket.socket(socket.AF_UNIX, kind)
        try:
            self._socket.bind(self.path)
            os.chmod(self.path, 0o600)
            self._socket.listen(backlog)
        except OSError:
            self._socket.close()
            raise

    def accept(self) -> socket.socket | None:
        """The next connection, waited for: none once it is closed."""
        try:
            connection, _ = self._socket.accept()
        except OSError:
            return None
        return connection

    def close(self) -> None:
        """Stop waiting, and take the socket away."""
        # Shut first: closing alone leaves accept waiting
        with suppress(OSError):
            self._socket.shutdown(socket.SHUT_RDWR)
        self._socket.close()
        with suppress(OSError):
            os.unlink(self.path)
