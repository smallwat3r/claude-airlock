"""How the launcher ends while it has a session: Ctrl-C is the session's,
and a kill or a terminal that is gone ends the session first, then the
launcher as after any session."""

from __future__ import annotations

import signal
import threading
from collections.abc import Iterator
from contextlib import contextmanager

from ..docker import docker_ok
from ..errors import Fatal

# What tells the launcher to end: a kill, and a terminal that is gone (a
# closed window, a killed Emacs buffer)
END_SIGNALS = (signal.SIGTERM, signal.SIGHUP)
# Seconds between two tries to stop a session the launcher was told to end
STOP_EVERY = 0.5


@contextmanager
def interrupts_held() -> Iterator[None]:
    """Keep Ctrl-C from ending the launcher for as long as the block
    lasts: it has to outlive the session to collect what its sidecars
    recorded and to check what it left behind, and Ctrl-C twice is how
    Claude Code is left. Ctrl-C still reaches docker (same foreground
    process group) and ends the session there. Held with a handler, one
    that is ignored would be ignored by docker too."""
    previous = signal.signal(signal.SIGINT, lambda *_: None)
    try:
        yield
    finally:
        signal.signal(signal.SIGINT, previous)


class Ending:
    """The launcher being told to end while it has a session, see
    ending_passed_on."""

    def __init__(self, name: str) -> None:
        self._name = name
        # The signal that told it, none while none did
        self.signal: int | None = None
        self._over = threading.Event()
        # Whether docker was started to run the session
        self._ran = False

    def told(self, number: int, _frame: object) -> None:
        """The handler of the signals: the first one counts."""
        if self.signal is None:
            self.signal = number
            threading.Thread(target=self._stop_session, daemon=True).start()

    def _stop_session(self) -> None:
        # Until the session is over, not once: its container may not be
        # there yet, and is then started a moment later
        while not self._over.is_set():
            try:
                docker_ok("stop", self._name)
            except Fatal:
                return
            self._over.wait(STOP_EVERY)

    def started(self) -> None:
        """Docker was started to run the session, by whatever started it."""
        self._ran = True

    def session_over(self) -> None:
        self._over.set()

    @property
    def session_was_run(self) -> bool:
        """Whether docker was started to run the session: until then
        nothing of it can have changed a file. Not when the launcher was
        told to end first, nor when docker could not be started."""
        return self._ran

    def status(self, status: int) -> int:
        """What the launcher ends with: the session's status, or the way
        a shell reports the signal that ended it."""
        return status if self.signal is None else 128 + self.signal


@contextmanager
def ending_passed_on(name: str) -> Iterator[Ending]:
    """For as long as the block lasts, a signal that would end the
    launcher (see END_SIGNALS) ends the session of that name instead, and
    the launcher then ends as it does after any session: it collects what
    the sidecars recorded, checks what the session left behind and removes
    the proxies no session uses any more. Ended on the spot it would leave
    all of that for the next launch, the socket proxy and the host's
    Docker socket it holds included. A kill that cannot be handled still
    does, see report_unchecked_sessions and Sidecar.left_behind."""
    ending = Ending(name)
    previous = {number: signal.signal(number, ending.told) for number in END_SIGNALS}
    try:
        yield ending
    finally:
        ending.session_over()
        for number, handler in previous.items():
            signal.signal(number, handler)
