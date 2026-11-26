#!/usr/bin/env python3
"""--line-mode: the status above the prompt, and in full on /status."""

from __future__ import annotations

import io
import itertools
import re
import time
import unittest.mock
from datetime import datetime

from chat_harness import SESSION, page, written
from harness import LauncherTest

from claude_airlock.chat import console, drift, status, turn
from claude_airlock.chat import said as saying
from claude_airlock.chat import screen as screens
from claude_airlock.chat import tasks as tasking
from claude_airlock.recording import started
from claude_airlock.report.layout import Layout
from claude_airlock.sandbox.mounts import ExtraDir
from claude_airlock.sandbox.runtime import DOCKERS_OWN
from claude_airlock.settings import Settings, SocketAccess


def status_rows(
    session: saying.Session | None = None,
    usage: turn.Usage | None = None,
    limits: status.Limits | None = None,
    sandbox: status.Sandbox | None = None,
    room: int | None = None,
    running: tasking.Running = status.NOTHING,
    now: float | None = None,
) -> list[str]:
    """The status as the rows it is written on where there is so much
    room, all the room there is without. Of a session nothing is known
    of, and of a sandbox started as most are, unless given."""
    session = session or saying.Session()
    named = status.named_group(session, running)
    used = status.used_groups(
        session, usage or turn.Usage(), limits or status.Limits(), now
    )
    sandbox = sandbox or status.Sandbox("claude-test")
    rows = status.status_rows(sandbox.parts(), named, used, room)
    return [status.row_text(row) for row in rows]


class StatusTest(LauncherTest):
    def test_a_model_is_named_as_claude_code_names_it(self):
        assert status.display_name("claude-opus-5-5") == "Opus 5.5"
        assert status.display_name("claude-sonnet-4-5-20250929") == "Sonnet 4.5"
        assert status.display_name("claude-opus-4-6[1m]") == "Opus 4.6 (1M context)"
        assert status.display_name("claude-haiku-4") == "Haiku 4"
        assert status.display_name("something-else") == "something-else"

    def test_the_status_says_what_is_known_and_nothing_else(self):
        assert status_rows() == ["[claude-test] net:open"]
        session = saying.Session(model="claude-opus-5-5")
        usage = turn.Usage()
        limits = status.Limits()
        soon = int(time.time()) + 3600
        limits.heard(
            {"rateLimitType": "five_hour", "utilization": 0.42, "resetsAt": soon}
        )
        limits.heard({"rateLimitType": "seven_day", "utilization": 0.95})
        limits.heard({"rateLimitType": "overage", "utilization": 0.1})
        usage.step({"message": {"usage": {"input_tokens": 50_000}}})
        usage.parts(
            {"total_cost_usd": 0.5, "modelUsage": {"m": {"contextWindow": 200_000}}},
            "m",
        )
        reset = f"{datetime.fromtimestamp(soon):%H:%M}"
        # The sandbox first, the launcher's own word, then what claude
        # says: two spaces between what belongs together
        used = f"ctx:25%  5h:42% used {reset}  7d:95% used  $0.50"
        assert status_rows(session, usage, limits) == [
            f"[claude-test] net:open  Opus 5.5  {used}"
        ]
        # A limit nearly used up stands out in red, and is never left out
        groups = status.used_groups(session, usage, limits)
        assert [status.Part(status.RED, "7d:95% used", "7d:95%")] in groups

    def test_the_mode_is_said_when_it_changed_and_of_plan_always(self):
        def shown(session: saying.Session) -> str:
            return status_rows(session)[0]

        session = saying.Session()
        session.heard({"subtype": "init", "permissionMode": "bypassPermissions"})
        assert "mode:" not in shown(session)
        session.heard({"subtype": "status", "permissionMode": "acceptEdits\x1b[2J"})
        assert shown(session).endswith("  mode:acceptEdits[2J")
        session.heard({"subtype": "status", "permissionMode": "bypassPermissions"})
        assert "mode:" not in shown(session)
        # The one a prompt is not acted on in, started with or not
        planning = saying.Session()
        planning.heard({"subtype": "init", "permissionMode": "plan"})
        assert "mode:plan" in shown(planning)
        # It stands out, among what is dimmed: it changes what a prompt does
        assert status.named_group(planning) == [status.Part(status.BOLD, "mode:plan")]

    def test_the_sandbox_is_shown_as_the_session_was_started(self):
        settings = Settings(
            net_filter=True,
            ssh_agent=True,
            docker_socket=SocketAccess.FULL,
            shared_history=True,
        )
        dirs = [
            ExtraDir(str(self.home / "shared")),
            ExtraDir("/srv/data", read_only=True),
        ]
        with unittest.mock.patch.object(started, "has_socket_proxy", return_value=True):
            start = started.Start.of(settings, DOCKERS_OWN, "", dirs, ssh_agent=True)
        sandbox = status.Sandbox.started("claude-x", start, str(self.home))
        assert [part.text for part in sandbox.parts()] == [
            "[claude-x]",
            "net:filtered",
            "ssh-agent",
            "docker:full",
            "history:all",
            "dirs: ~/shared /srv/data (ro)",
        ]
        # Asked for, but the host has no Docker socket: no door
        with unittest.mock.patch.object(
            started, "has_socket_proxy", return_value=False
        ):
            start = started.Start.of(settings, DOCKERS_OWN, "", [], ssh_agent=False)
        sandbox = status.Sandbox.started("claude-x", start, str(self.home))
        assert sandbox.open == ("history:all",)
        # A filter that asks about the hosts it does not allow
        asking_filter = status.Sandbox("claude-x", net_filter=True, net_ask=True)
        assert [part.text for part in asking_filter.parts()] == [
            "[claude-x]",
            "net:ask",
        ]

    def test_it_heads_the_prompt_and_is_said_in_full_when_asked_for(self):
        shown = page()
        session, usage = saying.Session(), turn.Usage()
        line = status.StatusLine(shown, status.Sandbox("claude-test"), session, usage)
        with written() as lines:
            assert line.refresh() == ["[claude-test] net:open"]
            assert shown._console._head == ["[claude-test] net:open"]
            session.replied({"message": {"model": "claude-opus-5-5"}})
            line.show()
            assert shown._console._head == ["[claude-test] net:open  Opus 5.5"]
        assert lines == [
            "# status      what the status above the prompt says, in full:",
            "#   sandbox   claude-test, network open",
            "#   model     Opus 5.5",
        ]

    def test_the_limits_are_read_where_claude_now_says_them(self):
        # All the windows by name, the figures no longer beside the type
        limits = status.Limits()
        soon = int(time.time()) + 3600
        limits.heard(
            {
                "status": "allowed",
                "rateLimitType": "five_hour",
                "resetsAt": soon,
                "unifiedWindows": {
                    "five_hour": {"utilization": 0.24, "resetsAt": soon},
                    "seven_day": {"utilization": 0.22, "resetsAt": soon + 99},
                    "overage": {"utilization": 0.5},
                    "opus": "not a window",
                },
            }
        )
        reset = f"{datetime.fromtimestamp(soon):%H:%M}"
        assert status_rows(limits=limits) == [
            f"[claude-test] net:open  5h:24% used {reset}  7d:22% used"
        ]
        assert set(limits.windows) == {"five_hour", "seven_day"}
        # Not a set of windows: what is beside the type still counts
        limits.heard({"rateLimitType": "seven_day", "unifiedWindows": [1]})
        limits.heard({"rateLimitType": "seven_day", "utilization": 0.5})
        assert limits.windows["seven_day"]["used_percentage"] == 50.0

    def test_a_field_that_is_missed_is_said_once_with_the_shape_of_its_message(self):
        seen = drift.Drift()
        message = {"type": "result", "subtype": "success", "session_id": "secret"}
        message.update(usage={"output_tokens": 5}, model=7)
        assert seen.field(message, "usage", dict) == {"output_tokens": 5}
        assert seen.told(message, {"result"}) is None
        assert seen.field(message, "modelUsage", dict) is None
        # There, and not of its kind
        assert seen.field(message, "model", str) is None
        assert seen.field("no message", "model", str) is None
        change = seen.told(message, {"result"}, "2.1.0")
        assert change.differs == (
            "no modelUsage in result success",
            "no model in result success",
        )
        assert "CHANGED in what Claude Code 2.1.0 says: no modelUsage" in change.said
        # Its fields and their kinds, none of what they hold
        assert "usage: {output_tokens: int}" in change.shape
        assert "secret" not in change.said
        # Not said again, and what was missed of one message is not said
        # of the next
        seen.field(message, "modelUsage", dict)
        assert seen.told(message, {"result"}) is None
        assert seen.told({"type": "keep_alive"}, {"keep_alive"}) is None
        # What nobody asks about does not pile up
        for number in range(1000):
            seen.missed(f"field{number}")
        assert len(seen._missed) == drift.MOST_MISSED

    def test_a_message_of_no_known_kind_is_said_at_no_great_length(self):
        seen = drift.Drift()
        for message, what in (
            ({"type": "new_thing", "text": "x\x1b[2J"}, "does not know, new_thing"),
            ({"text": "x"}, "a message without a type"),
        ):
            said = seen.told(message, {"result"}).said
            assert what in said
            assert "\x1b" not in said
        # A type that is no name is none, and not looked up as one
        change = drift.Drift().told({"type": ["x"]}, {"result"})
        assert change.differs == ("a message without a type",)
        # Its version as the message says it, cleaned
        init = {"type": "system", "subtype": "init", "claude_code_version": "2\x1b[2J"}
        seen.missed("model")
        said = seen.told(init, {"system"}, "1.0").said
        assert "Claude Code 2[2J says: no model in system init" in said
        assert "\x1b" not in said
        said = seen.told({"type": "t" * 5000, "subtype": "s"}, ()).said
        assert len(said) < 400
        deep = {"type": "odd", "a": {"b": {"c": {"d": 1}}}}
        deep.update({f"field{n}": n for n in range(200)})
        said = seen.told(deep, ()).said
        assert "a: {b: {c: dict}}" in said
        assert len(said) < 700
        # Nor are changes without end
        many = [seen.told({"type": f"kind{n}"}, ()) for n in range(100)]
        assert len(list(filter(None, many))) < drift.MOST_SAID
        assert len(seen._said) == drift.MOST_SAID
        assert seen.told({"type": "one_more"}, ()) is None

    def test_no_limit_claude_tells_of_stops_the_status(self):
        limits = status.Limits()
        limits.heard({"rateLimitType": [], "utilization": 0.5})
        limits.heard({"rateLimitType": {"a": 1}})
        assert limits.windows == {}
        # A time no date can be made of
        limits.heard(
            {"rateLimitType": "five_hour", "utilization": 0.4, "resetsAt": 9e11}
        )
        assert status_rows(limits=limits) == ["[claude-test] net:open  5h:40% used"]

    def test_the_effort_is_shown_after_the_model_once_claude_said_it(self):
        session = saying.Session(model="claude-fable-5-2")

        def shown() -> str:
            return status_rows(session)[0]

        assert shown() == "[claude-test] net:open  Fable 5.2"
        session.settled({"effort": "high\x1b[2J", "model": "claude-fable-5-2"})
        assert shown() == "[claude-test] net:open  Fable 5.2 effort:high[2J"
        # A model that is told none, and what is no effort
        for none in (None, 3, ["high"]):
            session.settled({"effort": none})
            assert "effort" not in shown()
        init = {"subtype": "init", "session_id": SESSION, "fast_mode_state": "on"}
        session.heard(init)
        session.settled({"effort": "xhigh"})
        assert shown() == "[claude-test] net:open  Fable 5.2 effort:xhigh fast"
        session.heard({**init, "fast_mode_state": "off"})
        assert " fast" not in shown()

    def test_the_model_claude_goes_by_is_shown_before_the_first_turn(self):
        session = saying.Session()
        # As claude answers when asked for its settings, before any prompt
        session.settled({"effort": "medium", "model": "claude-fable-5-2"})
        assert status_rows(session) == [
            "[claude-test] net:open  Fable 5.2 effort:medium"
        ]
        # From its first turn on the model is the one a turn is said to be of
        init = {"subtype": "init", "session_id": SESSION, "model": "claude-opus-5-5"}
        session.heard(init)
        session.settled({"effort": "medium", "model": "claude-fable-5-2"})
        assert status_rows(session) == [
            "[claude-test] net:open  Opus 5.5 effort:medium"
        ]
        # What is no name is none, and a long one is not kept whole
        for none in (None, 7, ["claude-fable-5-2"]):
            unnamed = saying.Session()
            unnamed.settled({"model": none})
            assert unnamed.model == ""
        long = saying.Session()
        long.settled({"model": "m" * 900 + "\x1b[2J"})
        assert long.model == "m" * saying.NAME_KEPT

    def test_an_account_without_a_window_shows_none_of_it(self):
        # As claude says it of a plan that has no limit by the hour
        week = int(time.time()) + 3 * status.DAY
        limits = status.Limits()
        limits.heard(
            {
                "status": "allowed",
                "rateLimitType": "seven_day",
                "resetsAt": week,
                "unifiedWindows": {
                    "seven_day": {"utilization": 0.22, "resetsAt": week},
                    "seven_day_overage_included": {
                        "utilization": 0.43,
                        "resetsAt": week,
                    },
                },
            }
        )
        assert (
            limits.drift.told({"type": "rate_limit_event"}, {"rate_limit_event"})
            is None
        )

        def shown(model: str, chosen: str = "") -> str:
            session = saying.Session(model=model, chosen=chosen)
            return status_rows(session, limits=limits)[0]

        assert (
            shown("claude-haiku-5-5")
            == "[claude-test] net:open  Haiku 5.5  7d:22% used"
        )
        # The week of the one model, while it is the session's
        assert (
            shown("claude-fable-5-2")
            == "[claude-test] net:open  Fable 5.2  7d:22% used  fable:43% used"
        )
        assert "fable:43% used" in shown("claude-haiku-5-5", chosen="Fable 5.2")
        assert "fable:" not in shown("claude-fable-5-2", chosen="Opus 5.5")
        assert "fable:" not in shown("")

    def test_a_window_says_when_it_starts_again_once_it_matters(self):
        now = 1_800_000_000.0
        hour, week = now + 3600, now + 3 * status.DAY
        limits = status.Limits()
        limits.heard(
            {"rateLimitType": "five_hour", "utilization": 0.1, "resetsAt": hour}
        )
        limits.heard(
            {"rateLimitType": "seven_day", "utilization": 0.5, "resetsAt": week}
        )

        def texts(at: float = now) -> list[str]:
            groups = status.limit_groups(limits, "", at)
            return [" ".join(part.text for part in group) for group in groups]

        at = datetime.fromtimestamp(hour)
        on = datetime.fromtimestamp(week)
        assert texts() == [f"5h:10% used {at:%H:%M}", "7d:50% used"]
        # Far from used up, either gives way where there is no room,
        # when it starts again first
        ranks = [[part.rank for part in group] for group in status.limit_groups(limits)]
        assert ranks == [[status.Rank.LIMIT, status.Rank.RESET], [status.Rank.LIMIT]]
        # Nearly used up: when it starts again is what there is to wait for
        limits.heard({"rateLimitType": "seven_day", "utilization": 0.7})
        assert texts()[1] == f"7d:70% used {on:%a %H:%M}"
        # Past the limit, as claude says it of a turn that went on: in
        # red, and never left out, nor is when it starts again
        limits.heard({"rateLimitType": "seven_day", "utilization": 1.2})
        assert status.limit_groups(limits, "", now)[1] == [
            status.Part(status.RED, "7d:120% used", "7d:120%"),
            status.Part(status.RED, f"{on:%a %H:%M}"),
        ]
        # What no part of a window is changes nothing
        for odd in (-0.5, 50, float("nan")):
            limits.heard({"rateLimitType": "seven_day", "utilization": odd})
        assert limits.windows["seven_day"]["used_percentage"] == 120.0
        # Once it has started again nothing is known to be used of it
        assert texts(hour) == [f"7d:120% used {on:%a %H:%M}"]
        assert texts(week) == []

    def test_status_says_it_all_in_full_a_line_for_each_thing(self):
        now = 1_800_000_000.0
        week = now + 3 * status.DAY
        usage, limits = turn.Usage(), status.Limits()
        # Nothing known of the session yet: the sandbox, in the words
        # its start is said in, with all that is open to it
        sandbox = status.Sandbox(
            "claude-test",
            net_filter=True,
            net_ask=True,
            open=("ssh-agent", "connectors"),
            dirs=("~/shared", "/srv/data (ro)"),
        )
        network = "filtered to the allowed domains, you are asked about others"
        assert status.said_in_full(sandbox, saying.Session(), usage, limits) == [
            "status      what the status above the prompt says, in full:",
            f"  sandbox   claude-test, network {network}",
            "  open      ssh-agent, connectors",
            "  mounted   ~/shared, /srv/data (ro)",
        ]
        session = saying.Session(model="claude-fable-5-2", version="2.1.326")
        session.id, session.mode, session.effort, session.fast = (
            SESSION,
            "plan",
            "high",
            True,
        )
        windows = {
            "seven_day": {"utilization": 0.22, "resetsAt": week},
            "seven_day_overage_included": {"utilization": 0.43, "resetsAt": week},
        }
        limits.heard({"rateLimitType": "seven_day", "unifiedWindows": windows})
        usage.step({"message": {"usage": {"input_tokens": 50_000}}})
        usage.parts(
            {"total_cost_usd": 0.5, "modelUsage": {"m": {"contextWindow": 200_000}}},
            "m",
        )
        on = f"{datetime.fromtimestamp(week):%a %d %b %H:%M}"
        sandbox = status.Sandbox("claude-test")
        held = f"{turn.tokens(50_000)} of {turn.tokens(200_000)} tokens"
        two = tasking.Running(others=2)
        assert status.said_in_full(sandbox, session, usage, limits, two, now)[1:] == [
            "  sandbox   claude-test, network open",
            "  model     Fable 5.2, effort high, fast mode",
            "  mode      plan, claude plans and changes nothing",
            "  tasks     2 still run, claude goes on when one ends",
            f"  context   25% used, {held}",
            f"  limits    7d: 22% used, starts again {on}",
            f"            fable: 43% used, starts again {on}",
            "  cost      $0.50, as Claude Code counts it",
            f"  session   {SESSION}",
            "  version   Claude Code 2.1.326",
        ]
        # A mode that is not plan is its name, and one task is one
        session.mode = "acceptEdits"
        one = tasking.Running(others=1)
        said = status.said_in_full(sandbox, session, usage, limits, one, now)
        assert said[3:5] == [
            "  mode      acceptEdits",
            "  tasks     1 still runs, claude goes on when one ends",
        ]

    def test_the_model_chosen_with_model_is_shown_before_it_replies(self):
        session = saying.Session(model="claude-fable-5-2", chosen="Opus 5.5")
        assert status.named_group(session) == [status.Part(status.BOLD, "Opus 5.5")]

    def under_way(self, now: float) -> tuple[saying.Session, turn.Usage, status.Limits]:
        """A session with a figure for each thing the status shows: an
        eighth of its context used, the limit by the hour and the week
        of its model far from used up, the limit by the week nearly."""
        session = saying.Session(model="claude-fable-5-2", effort="high")
        usage, limits = turn.Usage(), status.Limits()
        week = now + 3 * status.DAY
        windows = {
            "five_hour": {"utilization": 0.4, "resetsAt": now + 3600},
            "seven_day": {"utilization": 0.72, "resetsAt": week},
            "seven_day_overage_included": {"utilization": 0.43, "resetsAt": week},
        }
        limits.heard({"rateLimitType": "five_hour", "unifiedWindows": windows})
        usage.step({"message": {"usage": {"input_tokens": 120_000}}})
        window = {"m": {"contextWindow": 1_000_000}}
        usage.parts({"total_cost_usd": 1.25, "modelUsage": window}, "m")
        return session, usage, limits

    def test_the_status_takes_two_rows_where_one_has_no_room_for_it(self):
        now = 1_800_000_000.0
        session, usage, limits = self.under_way(now)
        at = f"{datetime.fromtimestamp(now + 3600):%H:%M}"
        on = f"{datetime.fromtimestamp(now + 3 * status.DAY):%a %H:%M}"
        used = f"ctx:12%  5h:40% used {at}  7d:72% used {on}  fable:43% used  $1.25"
        whole = f"[claude-test] net:open  Fable 5.2 effort:high  {used}"

        def rows(room: int | None) -> list[str]:
            return status_rows(session, usage, limits, room=room, now=now)

        # In a file a line is as long as it is
        assert rows(None) == rows(len(whole)) == [whole]
        # Still one row, each part said the shorter way it has: a row
        # less above every prompt is worth more than a word
        terse = whole.replace(" used", "")
        assert rows(len(whole) - 1) == rows(len(terse)) == [terse]
        # Then the sandbox over the session, each said whole again
        session_row = f"Fable 5.2 effort:high  {used}"
        over = ["[claude-test] net:open", session_row]
        assert rows(len(terse) - 1) == rows(len(session_row)) == over
        # No room for the session on one row: how claude is set goes
        # next to the sandbox, whose row is mostly free, and nothing is
        # left out or said shorter
        beside = ["[claude-test] net:open  Fable 5.2 effort:high", used]
        assert rows(len(session_row) - 1) == rows(len(used)) == beside
        # Shorter still, that way loses less too: what was used is said
        # the shorter way, where under the sandbox alone parts of the
        # session would be left out
        assert rows(len(used) - 1) == [beside[0], used.replace(" used", "")]
        # Nothing to say of the session yet: the sandbox is all there is
        assert status_rows(room=30) == ["[claude-test] net:open"]
        # A sandbox whose row has no room for more as it is keeps it
        # to itself: nothing of the sandbox gives way for the model
        long = status.Sandbox(
            "claude-a-project-with-a-long-name",
            net_filter=True,
            open=("ssh-agent", "docker:full"),
            dirs=("~/shared",),
        )
        room = len(session_row) - 1
        opened = "net:filtered ssh-agent docker:full"
        assert status_rows(session, usage, limits, long, room, now=now) == [
            f"[claude-a-project-with-a-long-name] {opened} dirs: ~/shared",
            session_row.replace(" used", ""),
        ]
        # However much of the session is then left out: next to it the
        # model would be there for a name that is cut
        assert status_rows(session, usage, limits, long, 62, now=now) == [
            f"[claude-a-project-wi~] {opened}  ...",
            f"Fable 5.2  ctx:12%  5h:40%  7d:72% {on}  fable:43%  ...",
        ]

    def test_in_a_row_too_short_the_parts_give_way_the_least_needed_first(self):
        now = 1_800_000_000.0
        session, usage, limits = self.under_way(now)
        session.mode = "plan"
        used = status.used_groups(session, usage, limits, now)
        groups = [status.named_group(session), *used]
        at = f"{datetime.fromtimestamp(now + 3600):%H:%M}"
        on = f"{datetime.fromtimestamp(now + 3 * status.DAY):%a %H:%M}"

        def fitted(room: int) -> str:
            return status.row_text(status.fitted(groups, room))

        asked, week = "Fable 5.2 effort:high mode:plan", f"7d:72% {on}"
        whole = f"ctx:12%  5h:40% used {at}  7d:72% used {on}  fable:43% used  $1.25"
        steps = [
            f"{asked}  {whole}",
            # Each said the shorter way it has
            f"{asked}  ctx:12%  5h:40% {at}  {week}  fable:43%  $1.25",
            # What the session cost, and a mark for what is left out
            f"{asked}  ctx:12%  5h:40% {at}  {week}  fable:43%  ...",
            # When a limit that is far from used up starts again
            f"{asked}  ctx:12%  5h:40%  {week}  fable:43%  ...",
            # How the model is asked to work
            f"Fable 5.2 mode:plan  ctx:12%  5h:40%  {week}  fable:43%  ...",
            # The limits that are far from used up, the last first
            f"Fable 5.2 mode:plan  ctx:12%  5h:40%  {week}  ...",
            f"Fable 5.2 mode:plan  ctx:12%  {week}  ...",
            # How full a context is that is far from full
            f"Fable 5.2 mode:plan  {week}  ...",
        ]
        for wanted, shorter in itertools.pairwise(steps):
            assert fitted(len(wanted)) == wanted
            assert fitted(len(wanted) - 1) == shorter
        # The model, the mode and what is nearly used up, with when it
        # starts again, stay however little room there is
        assert fitted(10) == steps[-1]
        # A context that is nearly full stays too
        usage.step({"message": {"usage": {"input_tokens": 950_000}}})
        used = status.used_groups(session, usage, limits, now)
        groups = [status.named_group(session), *used]
        assert fitted(10) == f"Fable 5.2 mode:plan  ctx:95%  {week}  ..."

    def test_what_is_open_to_the_session_is_never_left_out(self):
        name = "claude-a-project-with-a-long-name"
        sandbox = status.Sandbox(
            name,
            net_filter=True,
            open=("ssh-agent", "docker:full"),
            dirs=("~/shared", "/srv/data (ro)"),
        )
        opened = "net:filtered ssh-agent docker:full"

        def fitted(room: int) -> str:
            return status.row_text(status.fitted([sandbox.parts()], room))

        whole = f"[{name}] {opened} dirs: ~/shared /srv/data (ro)"
        assert fitted(len(whole)) == whole
        # What is mounted by how many there are, then not at all
        counted = f"[{name}] {opened} dirs:2"
        assert fitted(len(whole) - 1) == fitted(len(counted)) == counted
        left_out = f"[{name}] {opened}  ..."
        assert fitted(len(counted) - 1) == fitted(len(left_out)) == left_out
        # Then the name is cut, and nothing else: no shorter than
        # tells it from another
        assert fitted(len(left_out) - 5) == f"[{name[:27]}~] {opened}  ..."
        assert fitted(10) == f"[claude-~] {opened}  ..."

    def test_the_status_is_made_for_the_page_as_wide_as_it_is_now(self):
        wide = [200]
        screen = console.Console("/nowhere", io.StringIO(), columns=lambda: wide[0])
        shown = console.Page(screen, Layout(compact=True))
        session, usage, limits = self.under_way(time.time())
        line = status.StatusLine(shown, status.Sandbox("claude-test"), session, usage)
        line.limits = limits
        assert len(line.refresh()) == 1
        # The terminal was made narrower since
        wide[0] = 80
        sandbox, said = line.refresh()
        assert sandbox == "[claude-test] net:open  Fable 5.2 effort:high"
        assert said.startswith("ctx:12%  5h:40% used ")
        assert said.endswith("  fable:43% used  $1.25")
        assert screen._head == [sandbox, said]
        assert max(map(len, screen._head)) < 80
        # In colour each part has its own, and takes no more room for it
        coloured = console.Page(screen, Layout(colour=True, compact=True))
        line = status.StatusLine(
            coloured, status.Sandbox("claude-test"), session, usage
        )
        line.limits = limits
        painted = line.refresh()
        assert painted[0] == (
            "\x1b[1;32m[claude-test]\x1b[0m \x1b[33mnet:open\x1b[0m"
            "  \x1b[1mFable 5.2\x1b[0m \x1b[2meffort:high\x1b[0m"
        )
        assert [screens.SGR.sub("", row) for row in painted] == [sandbox, said]

    def test_the_tasks_claude_left_to_run_are_counted_while_they_do(self):
        session = saying.Session(model="claude-fable-5-2")
        assert status_rows(session, running=tasking.Running(others=2)) == [
            "[claude-test] net:open  Fable 5.2 tasks:2"
        ]
        assert "tasks" not in status_rows(session)[0]
        running = [tasking.Running(others=1)]
        line = status.StatusLine(
            page(),
            status.Sandbox("claude-test"),
            session,
            turn.Usage(),
            running=lambda: running[0],
        )
        with written() as lines:
            assert line.refresh() == ["[claude-test] net:open  Fable 5.2 tasks:1"]
            line.show()
            running[0] = tasking.Running()
            assert line.refresh() == ["[claude-test] net:open  Fable 5.2"]
        assert "#   tasks     1 still runs, claude goes on when one ends" in lines

    def test_the_subagents_that_run_are_counted_apart_from_the_other_tasks(self):
        session = saying.Session(model="claude-fable-5-2")
        now = time.monotonic()
        mapping = tasking.Task(
            "Map the code", True, "Explore", now - 12, 3, 8100, "Reading a.py"
        )
        reading = tasking.Task("Read the docs", True, began=now - 5)
        done = tasking.Task("Run the tests", True, took=3.0)
        running = tasking.Running((mapping, reading), (done,), 1)
        assert status_rows(session, running=running) == [
            "[claude-test] net:open  Fable 5.2 agents:2 tasks:1"
        ]
        alone = tasking.Running((mapping,))
        assert status_rows(session, running=alone) == [
            "[claude-test] net:open  Fable 5.2 agents:1"
        ]
        # Neither gives way where there is no room: claude goes on by
        # itself when one of them ends
        usage, limits = turn.Usage(), status.Limits()
        usage.step({"message": {"usage": {"input_tokens": 50_000}}})
        usage.parts({"modelUsage": {"m": {"contextWindow": 200_000}}}, "m")
        narrow = status_rows(session, usage, room=32, running=running)
        assert narrow == ["[claude-test] net:open", "Fable 5.2 agents:2 tasks:1  ..."]
        # In full each subagent is said with how far it is
        sandbox = status.Sandbox("claude-test")
        said = status.said_in_full(sandbox, session, usage, limits, running)
        assert said[3] == (
            "  agents    2 still run, 1 ended, claude goes on when one ends"
        )
        first = r"            Map the code \(Explore\): 3 calls, 8\.1k tokens, 1\ds, Reading a\.py"
        assert re.fullmatch(first, said[4])
        assert re.fullmatch(r"            Read the docs: \d+s", said[5])
        assert said[6] == "  tasks     1 still runs, claude goes on when one ends"
        said = status.said_in_full(sandbox, session, usage, limits, alone)
        assert said[3].endswith("agents    1 still runs, claude goes on when one ends")
