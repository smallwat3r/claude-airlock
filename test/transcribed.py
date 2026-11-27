"""Entries of a transcript as Claude Code writes them, each at a second
of the same minute, and the events a trace makes of them in the project
/p."""

from __future__ import annotations

from claude_airlock.events import Event
from claude_airlock.report import transcript
from claude_airlock.report.transcript import WalkOptions

PROJECT = "/p"


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


def events(entries: list[dict], verbose: bool = False) -> list[Event]:
    """The events of a transcript that is all there."""
    return transcript.left_events(entries, [], PROJECT, WalkOptions(verbose))
