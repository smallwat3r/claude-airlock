"""Entries of a transcript as Claude Code writes them, each at a second
of the same minute, and the events a trace makes of them in the project
/p."""

from __future__ import annotations

from claude_airlock.events import Event
from claude_airlock.recording.procwatch import Secrets
from claude_airlock.recording.secrets import session_secrets
from claude_airlock.report import summary, transcript
from claude_airlock.report.transcript import WalkOptions
from claude_airlock.settings import CONTAINER_HOME, Host, Settings

PROJECT = "/p"


def project_secrets(settings: Settings | None = None) -> Secrets:
    """The files of secrets of a session of the project with these
    settings, the defaults without, under the container's home."""
    host = Host(CONTAINER_HOME, PROJECT, CONTAINER_HOME, CONTAINER_HOME)
    return session_secrets(settings or Settings(), host, (PROJECT,))


# Those the events are made with, see events
SECRETS = project_secrets()


def at(second: int) -> str:
    return f"2026-01-02T10:00:{second:02d}Z"


def prompt(text: str, second: int = 0, **more) -> dict:
    return {
        "type": "user",
        "timestamp": at(second),
        "message": {"content": text},
        **more,
    }


def call(tool_id: str, name: str = "Bash", second: int = 1, **tool_input) -> dict:
    block = {"type": "tool_use", "id": tool_id, "name": name, "input": tool_input}
    return {
        "type": "assistant",
        "timestamp": at(second),
        "message": {"content": [block]},
    }


def result(tool_id: str, output: str = "", second: int = 2, **more) -> dict:
    block = {"type": "tool_result", "tool_use_id": tool_id, "content": output}
    failed = bool(more.pop("failed", False))
    return {
        "type": "user",
        "timestamp": at(second),
        "message": {"content": [{**block, "is_error": failed}]},
        **more,
    }


def attached(kind: str, second: int = 0, **given) -> dict:
    return {
        "type": "attachment",
        "timestamp": at(second),
        "attachment": {"type": kind, **given},
    }


def system(subtype: str, second: int = 0, **more) -> dict:
    """An entry of the system, as Claude Code writes one of a subtype."""
    return {
        "type": "system",
        "subtype": subtype,
        "timestamp": at(second),
        "uuid": f"u{second}",
        "isMeta": False,
        **more,
    }


def sent(text: str, kind: str, second: int = 0, **origin) -> dict:
    """A prompt that did not come from the user, as Claude Code writes
    one of an origin: what another session or a server sent it is meta,
    a task that ended is not."""
    meta = {} if kind == "task-notification" else {"isMeta": True}
    return {
        "type": "user",
        "timestamp": at(second),
        "message": {"role": "user", "content": text},
        "origin": {"kind": kind, **origin},
        **meta,
    }


def hook(kind: str, event: str, second: int = 0, **given) -> dict:
    """An attachment of a hook that ran on an event, named as the hooks of
    that event are unless it says (PostToolUse:Bash for those of a tool)."""
    named = {"hookName": event, "hookEvent": event, "toolUseID": f"h{second}"}
    return attached(kind, second, **{**named, **given})


def replied(*blocks: dict, second: int = 1) -> dict:
    """A reply of the model of these blocks."""
    return {
        "type": "assistant",
        "timestamp": at(second),
        "message": {"content": list(blocks)},
    }


# Where a skill given again is from, see given_texts
SKILL_PATH = "/home/me/.claude/skills/pdf/SKILL.md"


def given_texts(text: str = "", hook: str = "Branch: main") -> list[dict]:
    """An attachment of each kind given.py reads, as Claude Code writes
    it, each with the text, after what it holds of its own."""
    return [
        attached(
            "invoked_skills",
            skills=[
                {
                    "name": "pdf",
                    "path": SKILL_PATH,
                    "content": "Use pdftotext." + text,
                }
            ],
        ),
        attached(
            "mcp_resource",
            server="docs",
            uri="file:///a.md",
            name="a.md",
            content={
                "contents": [
                    {"uri": "file:///a.md", "text": "# A" + text},
                    # No text to read
                    {"uri": "file:///b.png", "blob": "AAAA"},
                ]
            },
        ),
        attached(
            "hook_additional_context",
            content=[hook, "Clean" + text],
            hookName="SessionStart",
            hookEvent="SessionStart",
            toolUseID="SessionStart",
        ),
        attached(
            "plugin_note", plugin="notes", rowUuid="r1", content=["Remember" + text]
        ),
        attached(
            "relevant_memories",
            memories=[
                {"path": "/p/.claude/memory/a.md", "content": "Use uv." + text},
                {"path": "/p/.claude/memory/b.md", "content": ""},
            ],
        ),
    ]


def step(step_id: str, second: int, **usage: int) -> dict:
    return {
        "type": "assistant",
        "timestamp": at(second),
        "message": {"id": step_id, "usage": usage, "content": []},
    }


def events(
    entries: list[dict], verbose: bool = False, secrets: Secrets | None = SECRETS
) -> list[Event]:
    """The events of a transcript that is all there, a call on a file of
    those secrets flagged, none without any."""
    options = WalkOptions(verbose, secrets=secrets)
    return transcript.left_events(entries, [], PROJECT, options)


def overview(entries: list[dict], planted: int = 0) -> dict[str, str]:
    """The session at a glance, as the header of its trace says it with
    so much of what it read showing a sign, see overview of summary.py."""
    figures = summary.session_figures(entries, PROJECT)
    return dict(summary.overview(entries, planted, figures))
