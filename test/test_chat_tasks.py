#!/usr/bin/env python3
"""--line-mode: what claude does besides answering, its subagents and
how far they are."""

from __future__ import annotations

import re
import unittest.mock

from chat_harness import (
    USED,
    agent_started,
    got_on,
    lines_now,
    page,
    system,
    task_over,
    written,
)

from claude_airlock.chat import console, drift, notices
from claude_airlock.chat import said as saying
from claude_airlock.chat import tasks as tasking
from claude_airlock.events import labelled
from claude_airlock.report.layout import Layout


class NoticesTest:
    def test_what_claude_does_besides_answering_is_said(self):
        started = tasking.Tasks()
        said = notices.Notices(page(), started)
        with written() as lines:
            said.system(system("status", status="requesting"))
            said.system(system("status", status="compacting"))
            about = {"pre_tokens": 29232, "post_tokens": 7898}
            said.system(system("compact_boundary", compact_metadata=about))
            said.system(system("api_retry", error="overloaded\x1b[2J"))
            # Of a subagent, which its transcript does not have, as claude
            # says it once each time. Not how long a call has run
            retry = {"agent_id": "a1", "attempt": 1, "max_retries": 10}
            said.call_progress(
                {
                    "type": "tool_progress",
                    "subagent_retry": {**retry, "error_category": "rate_limit"},
                }
            )
            said.call_progress({"type": "tool_progress", "elapsed_time_seconds": 5})
            said.call_progress({"type": "tool_progress", "subagent_retry": "x"})
            said.system(system("task_started", task_id="a1", description="Run it"))
            still_running = started.running.others
            said.system(system("task_notification", task_id="a1", status="completed"))
            assert (still_running, started.running.others) == (1, 0)
            said.system(system("task_notification", task_id=["x"]))
            said.cleared()
        assert lines == [
            "# chat        compacting the conversation",
            "# chat        the conversation was compacted, 29.2k tokens to 7.9k",
            "# chat        the API did not answer, trying again  overloaded[2J",
            "# chat        the API did not answer a subagent, trying again  rate_limit",
            "# task        started: Run it",
            "# task        completed: Run it",
            "# chat        a new conversation, the one before is cleared",
        ]

    def test_what_claude_does_on_its_own_with_the_session_is_said(self):
        # As Claude Code sends them, which are new with it: each would
        # else be left out without a word
        said = notices.Notices(page())
        with written() as lines:
            said.system(
                system(
                    "permission_denied",
                    tool_name="Bash",
                    tool_use_id="t1",
                    decision_reason="denied by a rule\x1b[2J",
                    message="Permission to use Bash has been denied.",
                )
            )
            said.system(
                system(
                    "permission_denied",
                    tool_name="WebFetch",
                    agent_id="a1",
                    message="Permission denied.",
                )
            )
            said.system(
                system(
                    "model_fallback",
                    trigger="overloaded",
                    original_model="claude-opus-5-5",
                    fallback_model="claude-fable-5-2",
                    content="x",
                )
            )
            # Not a request the model refused, which the transcript says
            # (see told_over_the_pipe of followed.py)
            said.system(
                system(
                    "model_fallback",
                    trigger="refusal",
                    original_model="claude-opus-5-5",
                    fallback_model="claude-fable-5-2",
                )
            )
            said.system(system("plugin_install", status="started"))
            said.system(
                system("plugin_install", status="failed", name="m", error="no\nway")
            )
            paths = [f"/home/sandbox/.claude/memory/{n}.md" for n in range(5)]
            said.system(system("memory_saved", written_paths=paths, verb="Updated"))
            said.system(system("memory_saved", written_paths=paths[:1]))
            said.system(
                system(
                    "peer_message_hold",
                    state="held",
                    lane="socket",
                    **{"from": "uds:/tmp/x.sock"},
                    from_name="other",
                    cause="mode-mismatch",
                )
            )
            said.system(
                system(
                    "peer_message_hold",
                    state="dropped",
                    lane="bridge",
                    outcome="expired",
                    **{"from": ""},
                )
            )
            # What is not what it should be says no more than it holds
            said.system(system("memory_saved", written_paths="x", verb=["x"]))
            said.system(system("permission_denied", tool_name={"x": 1}))
        listed = ", ".join(paths[:3])
        other = "a message of another session"
        assert lines == [
            f"# {labelled('chat', said)}"
            for said in (
                "claude refused bash without asking: denied by a rule[2J",
                "claude refused webfetch of a subagent without asking: Permission denied.",
                "claude-opus-5-5 failed (overloaded), this turn goes on with claude-fable-5-2",
                "plugin install: started",
                "plugin m install: failed, no\\nway",
                f"claude updated 5 memories to {listed} and 2 more",
                f"claude saved 1 memory to {paths[0]}",
                f"{other} said to be from other (socket): held, mode-mismatch",
                f"{other} (bridge): dropped, expired",
                "claude saved 0 memories",
                "claude refused a tool without asking",
            )
        ]
        assert {"init", "hook_started", "memory_saved"} <= said.known

    def test_a_limit_of_the_account_is_said_once(self):
        said = notices.Notices(page())
        with written() as lines:
            said.limit(7)
            said.limit({"status": "allowed", "rateLimitType": "five_hour"})
            for _ in range(2):
                said.limit({"status": "allowed_warning", "rateLimitType": "five_hour"})
        assert lines == ["# chat        usage limit: allowed_warning five hour"]


class ServersTest:
    def test_the_mcp_servers_are_said_at_the_start_and_when_they_change(self):
        said = notices.Notices(page())
        servers = [("docs", "connected"), ("mail", "needs-auth"), ("db", "failed")]
        with written() as lines:
            said.servers([])
            said.servers(servers)
            said.servers(servers)
            said.servers([("docs", "connected"), ("mail", "connected")])
            said.servers([])
        others = "mail (needs-auth), db (failed)"
        assert lines == [
            f"# chat        MCP servers: 1 connected, NOT connected: {others}",
            "# chat        MCP servers: 2 connected",
            "# chat        MCP servers: none any more",
        ]


class TasksTest:
    def told(self) -> tuple[tasking.Tasks, notices.Notices]:
        """The tasks claude started, and what says them."""
        started = tasking.Tasks()
        return started, notices.Notices(page(), started)

    def test_a_subagent_is_said_with_its_kind_and_with_what_it_used(self):
        started, said = self.told()
        with written() as lines:
            said.system(agent_started("a1", "Map the code"))
            said.system(got_on("a1", 1, 19592, "Reading main.py"))
            (agent,) = started.running.agents
            said.system(task_over("a1", usage=USED))
            assert started.running == tasking.Running(ended=started.running.ended)
        assert (agent.about, agent.kind, agent.calls) == ("Map the code", "Explore", 1)
        # What it used in all is what claude says at its end, not what
        # it had used by its last call
        assert lines == [
            "# agent       started: Map the code (Explore)",
            "# agent       completed: Map the code, 2 calls, 20.5k tokens, 3s",
        ]

    def test_several_subagents_are_counted_as_they_start_and_end(self):
        _, said = self.told()
        with written() as lines:
            said.system(agent_started("a1", "Map the code"))
            said.system(agent_started("a2", "Read the docs", "general-purpose"))
            # Of no kind that claude names, and of no words
            said.system(agent_started("a3", "", ""))
            said.system(task_over("a2", usage=USED))
            said.system(task_over("a1", "failed", usage={"duration_ms": 61000}))
            said.system(task_over("a3", "stopped", usage=USED))
            # The one after them is a lot of its own, and not counted
            said.system(agent_started("a4", "", "Plan"))
            said.system(task_over("a4", usage={"tool_uses": 1}))
        used = "2 calls, 20.5k tokens, 3s"
        assert lines[:6] == [
            "# agent       started: Map the code (Explore)",
            "# agent       started: Read the docs (general-purpose)  2 running",
            "# agent       started:  3 running",
            f"# agent       completed: Read the docs, {used}  2 running, 1 ended",
            "# agent       failed: Map the code, 61s  1 running, 2 ended",
            f"# agent       stopped: {used}  all 3 ended",
        ]
        assert lines[6] == "# agent       started: Plan"
        # How long it ran is counted here when claude does not say
        assert re.fullmatch(r"# agent       completed: Plan, 1 call, \ds", lines[7])

    def test_a_subagent_that_is_said_to_end_again_is_the_same_one(self):
        started, said = self.told()
        with written() as lines:
            said.system(agent_started("a1", "Map the code"))
            said.system(agent_started("a2", "Read the docs"))
            said.system(task_over("a1", usage=USED))
            # As claude says of one whose report came after it ended
            later = {"total_tokens": 30000, "tool_uses": 5, "duration_ms": 9000}
            said.system(task_over("a1", usage=later))
            assert len(started.running.ended) == 1
            # One that claude takes up again runs, and has not ended
            said.system(agent_started("a1", "Map the code"))
            running = started.running
            assert (len(running.agents), running.ended) == (2, ())
        counted = "1 running, 1 ended"
        assert lines[2:] == [
            f"# agent       completed: Map the code, 2 calls, 20.5k tokens, 3s  {counted}",
            f"# agent       completed: Map the code, 5 calls, 30.0k tokens, 9s  {counted}",
            "# agent       started: Map the code (Explore)  2 running",
        ]
        # Of one that is not known, as before: it is no subagent to name
        with written() as lines:
            said.system(task_over("zz"))
        assert lines == ["# task        completed"]

    def test_a_task_is_a_subagent_by_its_kind_or_by_naming_one(self):
        started = tasking.Tasks()
        kinds = (
            {"task_type": "local_agent"},
            # As a version says it that does not say the kind of a task
            {"subagent_type": "Explore"},
            {"task_type": "local_bash"},
            {"task_type": "local_workflow", "subagent_type": "Explore"},
            {},
        )
        for at, kind in enumerate(kinds):
            started.started(system("task_started", task_id=f"t{at}", **kind))
        running = started.running
        assert [agent.kind for agent in running.agents] == ["", "Explore"]
        assert running.others == 3
        # One that does not say which it is, is none
        assert started.started(system("task_started", task_id=7)) is None
        assert started.ended(task_over(["x"])) is None
        assert started.running == running

    def test_what_a_subagent_started_for_itself_is_no_task_of_claudes(self):
        started, said = self.told()
        theirs = {"task_type": "local_bash", "description": "Run the tests"}
        with written() as lines:
            said.system(agent_started("a1", "Map the code"))
            # As Claude Code says of a command of a subagent that runs
            # for a while: in so many words, or by the task that began it
            said.system(
                system("task_started", task_id="b1", **theirs, parent_task_id="a1")
            )
            owned = {**theirs, "owned_by_subagent": True}
            said.system(system("task_started", task_id="b2", **owned))
            assert started.running.others == 0
            said.system(task_over("b1"))
            said.system(task_over("b2", "stopped"))
            # A subagent that a subagent started is one more of them
            said.system(agent_started("a2", "Read the docs", parent_task_id="a1"))
            assert len(started.running.agents) == 2
            # And a command of claude's own is a task of its
            said.system(system("task_started", task_id="b3", **theirs))
            assert started.running.others == 1
        assert lines == [
            "# agent       started: Map the code (Explore)",
            "# agent       started: Read the docs (Explore)  2 running",
            "# task        started: Run the tests",
        ]

    def test_how_far_a_subagent_is_follows_what_claude_says_of_it(self):
        started = tasking.Tasks()
        started.started(agent_started("a1", "Map the code"))

        def now() -> tasking.Task:
            (agent,) = started.running.agents
            return agent

        assert (now().calls, now().tokens, now().doing) == (None, None, "")
        started.progressed(got_on("a1", 1, 19592, "Reading main.py"))
        assert (now().calls, now().tokens) == (1, 19592)
        assert now().doing == "Reading main.py"
        # A call without words of its own: Claude Code then says what the
        # subagent is to do in their place, and the tool is what is said
        started.progressed(
            got_on("a1", 2, 19700, "Map the code", last_tool_name="Grep")
        )
        assert (now().calls, now().doing) == (2, "grep")
        # The status it gives itself is said before either, cleaned
        status = {"summary": "Half way\x1b[2J\nthere", "last_tool_name": "Read"}
        started.progressed(got_on("a1", 3, 19800, "Map the code", **status))
        assert now().doing == "Half way[2J\\nthere"
        # What says nothing new leaves what it was at
        started.progressed(got_on("a1", 4, 19900))
        assert (now().calls, now().doing) == (4, "Half way[2J\\nthere")
        # Not of one that is not known to run, or that is not said
        for unknown in ("zz", ["a1"], None):
            started.progressed(got_on(unknown, 9, 9))
        assert now().calls == 4
        # Nor of one that has ended
        started.ended(task_over("a1"))
        started.progressed(got_on("a1", 5, 20000))
        assert started.running.agents == ()

    def test_what_claude_no_longer_says_of_how_far_one_is_is_told(self):
        changed = drift.Drift()
        started = tasking.Tasks(changed)
        started.started(agent_started("a1", "Map the code"))
        started.progressed(got_on("a1", 2, 1500))
        assert changed.told(got_on("a1", 2, 1500), {"system"}) is None
        without = system("task_progress", task_id="a1", description="Reading")
        started.progressed(without)
        change = changed.told(without, {"system"})
        assert change is not None
        assert change.differs == ("no usage in system task_progress",)
        moved = {"tool_uses": "3", "tokens": 1600}
        other = system("task_progress", task_id="a1", usage=moved)
        started.progressed(other)
        change = changed.told(other, {"system"})
        assert change is not None
        assert change.differs == (
            "no usage.tool_uses in system task_progress",
            "no usage.total_tokens in system task_progress",
        )
        # What was known of it is kept, with what it is now at
        (agent,) = started.running.agents
        assert (agent.calls, agent.tokens, agent.doing) == (2, 1500, "Reading")
        # Nothing is asked of a task that is not known to run
        started.progressed(system("task_progress", task_id="zz"))
        assert changed.told(system("task_progress"), {"system"}) is None

    def test_no_more_tasks_are_kept_than_can_be_named(self):
        started = tasking.Tasks()
        with unittest.mock.patch.object(tasking, "MOST_TASKS", 2):
            for at in range(4):
                started.started(agent_started(f"a{at}", "Map the code"))
                theirs = {"task_id": f"b{at}", "owned_by_subagent": True}
                started.started(system("task_started", **theirs))
            assert len(started.running.agents) == 2
            assert len(started._theirs) == 2
            # One that runs can start anew, a subagent that is resumed
            started.progressed(got_on("a1", 3, 100))
            started.started(agent_started("a1", "Map the code"))
            assert [agent.calls for agent in started.running.agents] == [None, None]
            for at in range(4):
                started.ended(task_over(f"a{at}"))
            assert len(started.running.ended) == 2

    def test_an_id_that_cannot_be_kept_is_none_and_one_can_change_hands(self):
        started = tasking.Tasks()
        long = "a" * (saying.ID_WIDTH + 1)
        assert started.started(agent_started(long, "Map the code")) is None
        assert started.started(agent_started("", "Map the code")) is None
        assert started.ended(task_over(long)) is None
        assert started.running == tasking.Running()
        # What was a subagent's own and starts as a subagent is one
        started.started(system("task_started", task_id="x", owned_by_subagent=True))
        started.started(agent_started("x", "Map the code"))
        ended = started.ended(task_over("x"))
        assert ended is not None
        assert ended.agent
        assert started.running.agents == ()
        # Of a task that is no subagent, no figures are missed
        changed = drift.Drift()
        started = tasking.Tasks(changed)
        started.started(system("task_started", task_id="w", task_type="local_workflow"))
        without = system("task_progress", task_id="w")
        started.progressed(without)
        assert changed.told(without, {"system"}) is None

    def test_what_still_runs_is_said_in_words(self):
        agent = tasking.Task("Map the code", agent=True)

        def left(agents: int, others: int) -> str:
            return tasking.still_running(tasking.Running((agent,) * agents, (), others))

        assert left(0, 0) == ""
        assert left(1, 0) == "1 agent still runs"
        assert left(3, 0) == "3 agents still run"
        assert left(0, 1) == "1 task still runs"
        assert left(1, 1) == "1 agent and 1 task still run"
        assert left(2, 3) == "2 agents and 3 tasks still run"


class ProgressTest:
    # Three subagents that started 12, 5 and 5 seconds before 112
    MAP = tasking.Task(
        "Map the code", True, "Explore", 100.0, 12, 34500, "Reading a.py"
    )
    DOCS = tasking.Task("Read the docs", True, "", 107.0)
    DONE = tasking.Task("Run the tests", True, "", 107.0, 2, 20000, took=3.0)

    def test_one_subagent_is_said_in_a_row_and_several_are_counted_over_theirs(self):
        assert tasking.progress_rows(tasking.Running(), 112.0, 7) == []
        assert tasking.progress_rows(tasking.Running(others=2), 112.0, 7) == []
        alone = tasking.Running((self.MAP,))
        assert tasking.progress_rows(alone, 112.0, 7) == [
            "agent       Map the code: 12 calls, 34.5k tokens, 12s, Reading a.py"
        ]
        # With those of the lot that have ended, and what all of them used
        lot = tasking.Running((self.MAP, self.DOCS), (self.DONE,))
        assert tasking.progress_rows(lot, 112.0, 7) == [
            "agents      2 running, 1 ended: 14 calls, 54.5k tokens",
            "  Map the code: 12 calls, 34.5k tokens, 12s, Reading a.py",
            "  Read the docs: 5s",
        ]
        # The one of a lot that still runs is counted with it
        last = tasking.Running((self.DOCS,), (self.DONE,))
        assert tasking.progress_rows(last, 112.0, 7) == [
            "agents      1 running, 1 ended: 2 calls, 20.0k tokens",
            "  Read the docs: 5s",
        ]
        # Without the time where the rows are written again in their
        # place: they change when a subagent gets further, not by the clock
        assert tasking.progress_rows(lot, None, 7)[1:] == [
            "  Map the code: 12 calls, 34.5k tokens, Reading a.py",
            "  Read the docs",
        ]
        # Before any of them said how far it is
        fresh = tasking.Running((self.DOCS, self.DOCS))
        assert tasking.progress_rows(fresh, 107.0, 7)[0] == "agents      2 running"

    def test_no_more_rows_than_there_is_room_for(self):
        agents = tuple(tasking.Task(f"Part {n}", True, began=9.0) for n in range(1, 9))

        def rows(running: int, most: int) -> list[str]:
            return tasking.progress_rows(tasking.Running(agents[:running]), 12.0, most)

        # All of them where each has a row under the one that counts them
        assert rows(6, 7) == [
            "agents      6 running",
            *(f"  Part {n}: 3s" for n in range(1, 7)),
        ]
        # Else the first, and a row for how many have none
        assert rows(8, 7) == [
            "agents      8 running",
            *(f"  Part {n}: 3s" for n in range(1, 6)),
            "  and 3 more",
        ]
        assert rows(8, 3) == ["agents      8 running", "  Part 1: 3s", "  and 7 more"]
        # Only counted where that is all there is room for
        assert rows(8, 2) == rows(8, 1) == ["agents      8 running"]
        assert rows(1, 1) == ["agent       Part 1: 3s"]

    def test_what_a_subagent_is_to_do_is_cut_in_its_row_and_whole_in_full(self):
        about, doing = "Map " * 30, "Reading " * 20
        long = tasking.Task(
            about.strip(), True, "Explore", 100.0, 1, 900, doing.strip()
        )
        row = tasking.agent_row(long, 12.0)
        cut = about[: tasking.ROW_ABOUT - 1] + "~"
        assert len(cut) == tasking.ROW_ABOUT
        assert row.startswith(f"{cut}: 1 call, 900 tokens, 12s, Reading ")
        assert row.endswith("~")
        assert len(row) < tasking.ROW_ABOUT + tasking.ROW_DOING + 40
        # As /status says it, with the kind of subagent it is
        (whole,) = tasking.rows_in_full(tasking.Running((long,)), 112.4)
        figures = "1 call, 900 tokens, 12s"
        assert whole == f"{about.strip()} (Explore): {figures}, {doing.strip()}"
        # One of no words is said by its kind, or by its figures alone
        assert tasking.agent_row(tasking.Task("", True, "Plan"), 3.0) == "Plan: 3s"
        assert tasking.agent_row(tasking.Task("", True), 3.0) == "3s"
        colon = tasking.Task(": odd", True, calls=1.4)
        assert tasking.agent_row(colon, None) == ": odd: 1 call"
        # No more of them than can be read, and how many more there are
        many = tasking.Running((long,) * (tasking.MOST_IN_FULL + 3))
        said = tasking.rows_in_full(many, 112.4)
        assert len(said) == tasking.MOST_IN_FULL + 1
        assert said[-1] == "and 3 more"

    def at_a_terminal(self, height: int) -> tuple[console.Console, console.Page]:
        """A terminal of that many rows, and what is written to it."""
        terminal = console.Console("/nowhere")
        terminal._redrawn = True
        terminal.height = lambda: height
        return terminal, console.Page(terminal, Layout())

    def test_at_a_terminal_the_rows_are_above_the_status_in_their_place(self):
        terminal, shown = self.at_a_terminal(24)
        started = tasking.Tasks()
        progress = tasking.Progress(shown, lambda: started.running)
        with written() as lines:
            progress.show()
            assert terminal._working == []
            started.started(agent_started("a1", "Map the code"))
            progress.show()
            assert terminal._working == ["# agent       Map the code"]
            started.started(agent_started("a2", "Read the docs"))
            started.progressed(got_on("a1", 2, 1500, "Reading main.py"))
            progress.show()
            rows = [
                "# agents      2 running: 2 calls, 1.5k tokens",
                "#   Map the code: 2 calls, 1.5k tokens, Reading main.py",
                "#   Read the docs",
            ]
            assert terminal._working == rows
            # Under the line that says a turn still runs, which comes
            # and goes without them
            shown.working("working     5s, waiting for agent")
            assert terminal._working == ["# working     5s, waiting for agent", *rows]
            shown.working("")
            assert terminal._working == rows
            # One that has ended has no row, and is counted
            started.ended(task_over("a1", usage=USED))
            progress.show()
            assert terminal._working == [
                "# agents      1 running, 1 ended: 2 calls, 20.5k tokens",
                "#   Read the docs",
            ]
            started.ended(task_over("a2"))
            progress.show()
            assert terminal._working == []
        # Nothing of it is a line that stays
        assert lines == []

    def test_a_terminal_of_few_rows_has_fewer_of_them(self):
        started = tasking.Tasks()
        for at in range(8):
            started.started(agent_started(f"a{at}", f"Part {at}"))

        def rows(height: int) -> int:
            terminal, shown = self.at_a_terminal(height)
            tasking.Progress(shown, lambda: started.running).show()
            return len(terminal._working)

        assert rows(50) == tasking.MOST_ROWS
        assert rows(24) == tasking.MOST_ROWS
        assert rows(12) == 4
        # Counted in a row, however few there are
        assert rows(6) == rows(1) == 1

    def test_a_row_is_no_longer_than_the_terminal_is_wide(self):
        terminal = console.Console("/nowhere", columns=lambda: 40)
        terminal._redrawn = True
        shown = console.Page(terminal, Layout(compact=True))
        started = tasking.Tasks()
        started.started(agent_started("a1", "Map the code of the whole project"))
        started.progressed(got_on("a1", 12, 34500, "Reading src/main.py"))
        tasking.Progress(shown, lambda: started.running).show()
        (row,) = terminal._working
        # A column less than there are, as of every row of the head
        assert row == "# agent       Map the code of the whole"
        assert len(row) == 39

    def test_in_lines_the_rows_are_said_after_a_while_and_then_less_often(self):
        started = tasking.Tasks()
        held = [False]
        progress = tasking.Progress(page(), lambda: started.running, lambda: held[0])

        def said(lines: list[str]) -> int:
            """How often the rows were said so far."""
            return lines_now(lines).count("# agent ")

        with written() as lines:
            progress.show()
            started.started(agent_started("a1", "Map the code"))
            progress.show()
            # Not as it starts, which a line of its own says
            assert said(lines) == 0
            assert progress.since is not None
            progress.since -= tasking.SAID_EVERY
            progress.show()
            assert said(lines) == 1
            assert progress.wait == 2 * tasking.SAID_EVERY
            # Not again while it has got no further, however long
            progress.since -= 10 * tasking.SAID_EVERY
            progress.show()
            assert said(lines) == 1
            # Then as soon as it has, and less often from there on
            started.progressed(got_on("a1", 1, 900, "Reading main.py"))
            progress.show()
            assert said(lines) == 2
            assert progress.wait == tasking.SAID_MOST
            started.progressed(got_on("a1", 2, 950, "Reading main.py"))
            progress.show()
            assert said(lines) == 2
            # Not under a question that waits for its answer, nor into
            # a reply that is being written
            held[0] = True
            progress.since -= tasking.SAID_MOST
            progress.show()
            assert said(lines) == 2
            held[0] = False
            progress.show()
            assert said(lines) == 3
            assert progress.wait == tasking.SAID_MOST
            # The next lot is waited for from its start
            started.ended(task_over("a1"))
            progress.show()
            assert (progress.wait, progress.since) == (tasking.SAID_EVERY, None)
        assert re.fullmatch(r"# agent       Map the code: \ds", lines[0])
        assert re.search(r": 1 call, 900 tokens, \ds, Reading main\.py$", lines[1])
        assert re.search(r": 2 calls, 950 tokens, \ds, Reading main\.py$", lines[2])

    def test_in_lines_several_subagents_are_said_together(self):
        started = tasking.Tasks()
        progress = tasking.Progress(page(), lambda: started.running)
        with written() as lines:
            for at in range(1, 10):
                started.started(agent_started(f"a{at}", f"Part {at}"))
            progress.show()
            assert progress.since is not None
            progress.since -= tasking.SAID_EVERY
            progress.show()
        assert lines[0] == "# agents      9 running"
        assert [line[:10] for line in lines[1:6]] == [
            f"#   Part {at}" for at in range(1, 6)
        ]
        assert lines[6:] == ["#   and 4 more"]
