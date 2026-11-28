"""What claude does besides answering, said in a line each: a conversation
being compacted, a request to the API tried again, a task of its that
starts or ends, a call it refused without asking, a model it fell back
on, a plugin it installs, memories it saved, a message of another
session it holds, a limit of the account that is near, the MCP servers it
has and how each is.

What a trace tells too is told as the same event (see told.py), made of
what claude says over the pipe: the chat tells it as it comes, and passes
over what the transcript has of it later (see told_over_the_pipe). So is
what only the pipe says: a request of a subagent's to the API that is
tried again, and why a call was refused."""

from __future__ import annotations

import time
from collections.abc import Callable

from ..events import Event, Who, flat, labelled
from ..report.entries import measured
from ..report.told import (
    api_error_event,
    compacted_event,
    denied_event,
    fell_back_event,
    memory_saved_event,
)
from .console import Page
from .said import kept_name
from .tasks import Tasks, ended_line, started_line

# Of what an error is said to be about, and of how a task is said to end
ABOUT_WIDTH = 200
# How claude says an MCP server is when it can be used
CONNECTED = "connected"
# What claude says set off another model when the model refused the
# request, as told.py reads it too
REFUSAL = "refusal"
# What claude says of the session that a chat knows and says nothing of:
# the start of a turn, which Session takes in, and what Claude Code's own
# screen has and a chat has no use for, or has in another way (the
# transcript, the line at the end of a turn, the api_retry claude says
# with each api_error). Any other is new, see Drift
SYSTEM_PASSED_OVER = frozenset(
    {
        "init",
        "agents_killed",
        "api_error",
        "away_summary",
        "background_tasks_changed",
        "cloud_session_delta",
        "code_change_published",
        "commands_changed",
        "control_request_progress",
        "dev_intent",
        "elicitation_complete",
        "feedback_draft_queued",
        "file_attachments_missing",
        "file_snapshot",
        "files_persisted",
        "hook_progress",
        "hook_response",
        "hook_started",
        "informational",
        "inherited_asks_settled",
        "instruction_size_warning",
        "late_allow_not_run",
        "local_command_output",
        "memory_recall",
        "mirror_error",
        "model_consent_fallback",
        "model_refusal_fallback",
        "model_refusal_no_fallback",
        "notification",
        "per_turn_effort_changed",
        "permission_check_status",
        "permission_retry",
        "post_turn_summary",
        "scheduled_task_fire",
        "session_metadata",
        "session_state_changed",
        "session_title_changed",
        "session_writes_lost",
        "stop_hook_summary",
        "task_summary",
        "task_updated",
        "thinking",
        "thinking_tokens",
        "turn_duration",
        "turn_handoff_available",
        "turn_preempted",
        "ui_focus",
        "ui_invalidate",
        "ui_log",
        "ui_notify",
        "ui_notify_cancel",
        "ui_panes",
        "ui_placed",
        "ui_scroll",
        "ui_status",
        "ui_toast",
        "upgrade_relay_marker",
        "vcs_state_changed",
        "worker_shutting_down",
    }
)


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
        # What takes in each subtype of what claude says of the session
        self._takes: dict[str, Callable[[dict], None]] = {
            "status": self._status,
            "compact_boundary": self._compacted,
            "api_retry": self._retried,
            "task_started": self._task_started,
            # Said in the rows of its own, see Progress of tasks.py
            "task_progress": self._tasks.progressed,
            "task_notification": self._task_ended,
            "permission_denied": self._denied,
            "model_fallback": self._fell_back,
            "plugin_install": self._plugin,
            "memory_saved": self._remembered,
            "peer_message_hold": self._held,
        }
        # The subtypes of what claude says of the session that a chat
        # knows, see SYSTEM_PASSED_OVER
        self.known = SYSTEM_PASSED_OVER.union(self._takes)

    def system(self, message: dict) -> None:
        """Take in what claude says of the session while a turn runs."""
        subtype = message.get("subtype")
        take = self._takes.get(subtype) if isinstance(subtype, str) else None
        if take:
            take(message)

    def _status(self, message: dict) -> None:
        if message.get("status") == "compacting":
            self._page.note("chat", "compacting the conversation")

    def _told(self, event: Event | None) -> None:
        """Write an event as a trace has it, none for nothing to tell."""
        if event is not None:
            self._page.put(self._page.events([event]))

    def _retried(self, message: dict) -> None:
        """A request of claude's to the API is tried again (api_retry)."""
        self._told(api_error_event(message, time.time(), Who.CLAUDE))

    def call_progress(self, message: dict) -> None:
        """How a call of claude's goes on, as claude says while it runs
        (tool_progress): of it a chat says a request of a subagent's to
        the API that is tried again, once each time, which no transcript
        has. How long a call has run it says in its own way, see
        Heartbeat of turn.py."""
        retry = message.get("subagent_retry")
        if isinstance(retry, dict):
            self._told(api_error_event(retry, time.time(), Who.AGENT))

    def _denied(self, message: dict) -> None:
        """A call claude refused without asking the user, by a rule or its
        mode: the call and its result are in the transcript, why it was
        refused only here, and of a subagent's by whom."""
        who = Who.AGENT if message.get("agent_id") else Who.CLAUDE
        self._told(denied_event(message, time.time(), who))

    def _fell_back(self, message: dict) -> None:
        """Claude goes on with another model for the rest of the turn, the
        one it was given failed. Not when it refused the request, which
        the transcript says, see told_over_the_pipe."""
        if message.get("trigger") != REFUSAL:
            self._told(fell_back_event(message, time.time(), Who.CLAUDE))

    def _plugin(self, message: dict) -> None:
        """How the installing of a plugin goes, as claude says it: its
        error is the plugin's word, and is said as no more than a line."""
        status = kept_name(message.get("status"), ABOUT_WIDTH) or "?"
        name = kept_name(message.get("name"), ABOUT_WIDTH)
        error = kept_name(message.get("error"), ABOUT_WIDTH)
        said = f"plugin {name + ' ' if name else ''}install: {status}"
        self._page.note("chat", said + (f", {error}" if error else ""))

    def _remembered(self, message: dict) -> None:
        """Claude wrote memories of its own, the files it wrote them to."""
        self._told(memory_saved_event(message, time.time(), Who.CLAUDE))

    def _held(self, message: dict) -> None:
        """A message of another session for this one, which claude holds
        rather than gives the model, and what became of it. Whom it is
        from is what the sender says."""
        state = kept_name(message.get("state"), ABOUT_WIDTH) or "?"
        sender = kept_name(message.get("from_name"), ABOUT_WIDTH) or kept_name(
            message.get("from"), ABOUT_WIDTH
        )
        lane = kept_name(message.get("lane"), ABOUT_WIDTH)
        why = kept_name(message.get("cause") or message.get("outcome"), ABOUT_WIDTH)
        said = "a message of another session"
        said += f" said to be from {sender}" if sender else ""
        said += f" ({lane})" if lane else ""
        self._page.note("chat", f"{said}: {state}" + (f", {why}" if why else ""))

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

    def _compacted(self, message: dict) -> None:
        self._told(compacted_event(message, time.time(), Who.CLAUDE))

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
