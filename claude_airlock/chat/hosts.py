"""Whether the session may reach a host its egress filter does not allow
(CLAUDE_AIRLOCK_NET_ASK): the question a chat puts for it.

The proxy holds the request and the launcher is told the host and port
(see sandbox/asked_hosts.py). The user is asked like for a tool claude
wants to use, one question at a time on the same thread (see Asked), and
the request goes through or is refused by what they say.

A yes or a no holds for that host at that port until the session ends, so
what is tried again is not asked about again, and another port of the
host is asked about apart: a yes to its HTTPS is none to its SSH. No answer, the user interrupted
the turn, pressed Ctrl-C at the question or is leaving, refuses the
request that waits and nothing more. A request of a command of the
user's is asked about while the command runs, see shell.py.
Where nobody is there to answer, lines that are not typed, the host is
refused."""

from __future__ import annotations

import functools
import math
import threading
import time
from collections.abc import Callable
from typing import TYPE_CHECKING, Protocol

from ..report.shown import PORT_USES
from .asking import ASKED_STYLE, Asked, Asker, said_yes
from .console import Page

if TYPE_CHECKING:
    from ..sandbox.asked_hosts import Destination

# The label of what a chat says about a host that is asked about
LABEL = "net"
# Seconds between two looks at the hosts that wait: each lists a directory,
# and a look is had after each thing claude says, thousands a second
LOOKS_APART = 0.1


def reached(asked: Destination) -> str:
    """A host at a port as the user is told of it, with what is at the
    port, so that they know what a yes opens."""
    use = PORT_USES.get(asked.port)
    return f"{asked.host} on port {asked.port}" + (f" ({use})" if use else "")


class Hosts(Protocol):
    """The hosts at a port a request of the session waits for an answer
    about, and where the answer goes: see AskedHosts."""

    def waiting(self) -> list[Destination]: ...

    def answer(self, asked: Destination, allowed: bool | None) -> None: ...


class HostQuestions:
    """Puts each host that waits to the user, once, and gives their
    answer to what holds the request. With before, what is done ahead of
    a question that is new: what the session did up to it is written, so
    the question comes under the command it is of."""

    def __init__(
        self,
        hosts: Hosts,
        page: Page,
        asker: Asker,
        asked: Asked,
        interactive: bool,
        before: Callable[[], None],
    ):
        self._hosts = hosts
        self._page = page
        self._asker = asker
        self._asked = asked
        # Whether somebody is there to answer
        self._interactive = interactive
        self._before = before
        # The hosts that are being asked about, or will be. Taken from on
        # the thread of the questions once one is answered
        self._put: set[Destination] = set()
        self._putting = threading.Lock()
        # When the hosts that wait were last listed
        self._looked = -math.inf

    def look(self) -> None:
        """Have the user asked about each host that waits since the
        last look, no sooner than LOOKS_APART after it. New is not asked
        about as the list is made: one that is answered meanwhile is
        still on it, and is no new request."""
        now = time.monotonic()
        if now - self._looked < LOOKS_APART:
            return
        self._looked = now
        with self._putting:
            put = set(self._put)
        new = [host for host in self._hosts.waiting() if host not in put]
        if not new:
            return
        self._before()
        for host in new:
            if not self._interactive:
                self._hosts.answer(host, False)
                refused = f"REFUSED {reached(host)}: not allowed, nobody to ask"
                self._page.note(LABEL, refused)
                continue
            with self._putting:
                self._put.add(host)
            self._asked.then(functools.partial(self._ask, host))

    def _ask(self, host: Destination) -> None:
        """Ask whether the session may reach a host at a port. Anything
        but a yes refuses it."""
        shown = reached(host)
        try:
            waits = f"a request for {shown} waits, the filter does not allow it."
            self._page.note(LABEL, f"{waits} Your answer holds for this session")
            typed = self._asker.ask(
                f"let the session reach {shown}? [y/N] ", ASKED_STYLE
            )
            allowed = said_yes(typed)
            self._hosts.answer(host, allowed)
            if allowed is None:
                said = f"not answered: the request for {shown} is refused"
            elif allowed:
                said = f"allowed {shown} until the session ends"
            else:
                said = f"REFUSED {shown} until the session ends"
            self._page.note(LABEL, said)
        finally:
            # Asked about again when a request waits for it again
            with self._putting:
                self._put.discard(host)
