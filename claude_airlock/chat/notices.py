"""What claude does besides answering, said in a line each: a conversation
being compacted, a request to the API tried again, a task of its that
starts or ends, a limit of the account that is near, the MCP servers it
has and how each is."""

from __future__ import annotations

import time

from ..events import flat, labelled
from ..report.entries import measured
from .console import Page
from .tasks import Tasks, ended_line, started_line
from .turn import tokens

# Of what an error is said to be about, and of how a task is said to end
ABOUT_WIDTH = 200
# How claude says an MCP server is when it can be used
CONNECTED = "connected"


def _servers_line(servers: list[tuple[str, str]]) -> str:
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
    def __init__(self, page: Page, tasks: Tasks | None = None):
        self._page = page
        # The tasks claude started, told when one starts, gets further
        # and ends: what runs of them is asked of it, see tasks.py
        self._tasks = tasks or Tasks()
        # What claude last said of the limits of the account
        self._limit = "allowed"
        # The MCP servers claude last said it has, as they were told
        self._servers: list[tuple[str, str]] = []

    def system(self, message: dict) -> None:
        """Take in what claude says of the session while a turn runs."""
        match message.get("subtype"):
            case "status" if message.get("status") == "compacting":
                self._page.note("chat", "compacting the conversation")
            case "compact_boundary":
                self._compacted(message.get("compact_metadata"))
            case "api_retry":
                why = flat(message.get("error") or "")[:ABOUT_WIDTH]
                line = labelled("chat", f"the API did not answer, trying again  {why}")
                self._page.say([line.rstrip()])
            case "task_started":
                self._task_started(message)
            case "task_progress":
                # Said in the rows of its own, see Progress of tasks.py
                self._tasks.progressed(message)
            case "task_notification":
                self._task_ended(message)

    def servers(self, servers: list[tuple[str, str]]) -> None:
        """Say which MCP servers the session has, when that is another
        than what was said last: at its first turn, and when one of them
        comes or goes, the last one too."""
        if servers == self._servers:
            return
        self._servers = list(servers)
        self._page.note("chat", _servers_line(servers)[:ABOUT_WIDTH])

    def cleared(self) -> None:
        self._page.note("chat", "a new conversation, the one before is cleared")

    def _compacted(self, given: object) -> None:
        about = given if isinstance(given, dict) else {}
        before = measured(about.get("pre_tokens"))
        after = measured(about.get("post_tokens"))
        sizes = ""
        if before is not None and after is not None:
            sizes = f", {tokens(before)} tokens to {tokens(after)}"
        self._page.note("chat", f"the conversation was compacted{sizes}")

    def _task_started(self, message: dict) -> None:
        """A task of claude's started: a subagent, or what it left to
        run."""
        task = self._tasks.started(message)
        if task is not None:
            self._page.say([started_line(task, self._tasks.running)])

    def _task_ended(self, message: dict) -> None:
        """A task of claude's has ended, in the way claude says it did:
        completed, failed, stopped."""
        task = self._tasks.ended(message)
        if task is not None:
            status = flat(message.get("status") or "ended")[:ABOUT_WIDTH]
            self._page.say([ended_line(task, status, self._tasks.running)])

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
            reset = measured(info.get("resetsAt"))
            if reset:
                at = time.strftime("%H:%M", time.localtime(reset))
                line += f", resets at {at}"
            self._page.say([line])
