"""What claude does besides answering, said in a line each: a conversation
being compacted, a request to the API tried again, a task of its that
starts or ends, a limit of the account that is near, the MCP servers it
has and how each is."""

from __future__ import annotations

import time

from ..events import flat, labelled
from .console import Page
from .pipe import amount
from .turn import tokens

# Of what a task or an error is said to be about
ABOUT_WIDTH = 200
# The tasks remembered to name them when they end
MOST_TASKS = 1000
# How claude says an MCP server is when it can be used
CONNECTED = "connected"


def servers_line(servers: list[tuple[str, str]]) -> str:
    """The MCP servers of a session in a line: how many can be used, and
    each one that cannot with how it is (failed, needs-auth, pending). A
    server brings tools and instructions of its own, and one that is not
    there is a tool claude does not have."""
    if not servers:
        return "MCP servers: none any more"
    usable = sum(status == CONNECTED for _, status in servers)
    others = [f"{name} ({status})" for name, status in servers if status != CONNECTED]
    said = [f"{usable} connected"] if usable else []
    if others:
        said.append("NOT connected: " + ", ".join(others))
    return "MCP servers: " + ", ".join(said)


class Notices:
    def __init__(self, page: Page):
        self._page = page
        # What the tasks claude started are about, by their ids
        self._tasks: dict[str, str] = {}
        # What claude last said of the limits of the account
        self._limit = "allowed"
        # The MCP servers claude last said it has, as they were told
        self._servers: list[tuple[str, str]] = []

    @property
    def running(self) -> int:
        """How many of the tasks claude started have not ended: what it
        left to run goes on after its turn, and it takes up again when one
        ends."""
        return len(self._tasks)

    def system(self, message: dict) -> None:
        """Take in what claude says of the session while a turn runs."""
        subtype = message.get("subtype")
        if subtype == "status" and message.get("status") == "compacting":
            self._page.note("chat", "compacting the conversation")
        elif subtype == "compact_boundary":
            self._compacted(message.get("compact_metadata"))
        elif subtype == "api_retry":
            why = flat(message.get("error") or "")[:ABOUT_WIDTH]
            line = labelled("chat", f"the API did not answer, trying again  {why}")
            self._page.say([line.rstrip()])
        elif subtype == "task_started":
            self._task_started(message)
        elif subtype == "task_notification":
            self._task_ended(message)

    def servers(self, servers: list[tuple[str, str]]) -> None:
        """Say which MCP servers the session has, when that is another
        than what was said last: at its first turn, and when one of them
        comes or goes, the last one too."""
        if servers == self._servers:
            return
        self._servers = list(servers)
        self._page.note("chat", servers_line(servers)[:ABOUT_WIDTH])

    def cleared(self) -> None:
        self._page.note("chat", "a new conversation, the one before is cleared")

    def _compacted(self, given: object) -> None:
        about = given if isinstance(given, dict) else {}
        before = amount(about.get("pre_tokens"))
        after = amount(about.get("post_tokens"))
        sizes = ""
        if before is not None and after is not None:
            sizes = f", {tokens(before)} tokens to {tokens(after)}"
        self._page.note("chat", f"the conversation was compacted{sizes}")

    def _task_started(self, message: dict) -> None:
        """A task of claude's started: a subagent, or what it left to
        run."""
        task = message.get("task_id")
        if not isinstance(task, str):
            return
        about = flat(message.get("description") or "")[:ABOUT_WIDTH]
        if len(self._tasks) < MOST_TASKS:
            self._tasks[task] = about
        self._page.note("task", f"started: {about}".rstrip())

    def _task_ended(self, message: dict) -> None:
        task = message.get("task_id")
        if not isinstance(task, str):
            return
        about = self._tasks.pop(task, "")
        status = flat(message.get("status") or "ended")[:ABOUT_WIDTH]
        self._page.note("task", f"{status}: {about}".rstrip(": "))

    def limit(self, info: object) -> None:
        """Say what claude tells of the limits of the account, when it is
        not that all is well and not what was said last."""
        status = flat(info.get("status", "")) if isinstance(info, dict) else ""
        if status == self._limit:
            return
        self._limit = status
        if isinstance(info, dict) and status and status != "allowed":
            kind = flat(info.get("rateLimitType", "")).replace("_", " ")
            line = labelled("chat", f"usage limit: {status} {kind}").rstrip()
            reset = amount(info.get("resetsAt"))
            if reset:
                at = time.strftime("%H:%M", time.localtime(reset))
                line += f", resets at {at}"
            self._page.say([line])
