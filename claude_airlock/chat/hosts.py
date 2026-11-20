"""Whether the session may reach a host its egress filter does not allow
(CLAUDE_AIRLOCK_NET_ASK): the question a chat puts for it.

The proxy holds the request and the launcher is told the host (see
sandbox/asked_hosts.py). The user is asked like for a tool claude wants
to use, one question at a time on the same thread (see Asked), and the
request goes through or is refused by what they say.

A yes or a no holds for that host until the session ends, so what is
tried again is not asked about again. No answer, the user interrupted
the turn or is leaving, refuses the request that waits and nothing more.
Where nobody is there to answer, lines that are not typed, the host is
refused."""

from __future__ import annotations

import functools
from collections.abc import Callable
from typing import Protocol

from .asking import ASKED_STYLE, YES, Asked, Asker
from .console import Page

# The label of what a chat says about a host that is asked about
LABEL = "net"


class Hosts(Protocol):
    """The hosts a request of the session waits for an answer about, and
    where the answer goes: see AskedHosts."""

    def waiting(self) -> list[str]: ...

    def answer(self, host: str, allowed: bool | None) -> None: ...


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
        # The hosts that are being asked about, or will be
        self._put: set[str] = set()

    def look(self) -> None:
        """Have the user asked about each host that waits since the
        last look."""
        new = [host for host in self._hosts.waiting() if host not in self._put]
        if not new:
            return
        self._before()
        for host in new:
            if not self._interactive:
                self._hosts.answer(host, False)
                self._page.note(LABEL, f"REFUSED {host}: not allowed, nobody to ask")
                continue
            self._put.add(host)
            self._asked.then(functools.partial(self._ask, host))

    def _ask(self, host: str) -> None:
        """Ask whether the session may reach a host. Anything but a yes
        refuses it."""
        try:
            waits = f"a request for {host} waits, the filter does not allow it."
            self._page.note(LABEL, f"{waits} Your answer holds for this session")
            typed = self._asker.ask(
                f"let the session reach {host}? [y/N] ", ASKED_STYLE
            )
            allowed = None if typed is None else typed.strip().lower() in YES
            self._hosts.answer(host, allowed)
            if allowed is None:
                said = f"not answered: the request for {host} is refused"
            elif allowed:
                said = f"allowed {host} until the session ends"
            else:
                said = f"REFUSED {host} until the session ends"
            self._page.note(LABEL, said)
        finally:
            # Asked about again when a request waits for it again
            self._put.discard(host)
