#!/usr/bin/env python3
"""What Claude Code sends to the model, kept when CLAUDE_AIRLOCK_API_LOG is
on: the drop a session writes it to, what the launcher takes out of it and
notes, and how line mode and --trace show a request."""

from __future__ import annotations

import json
import os
import shlex
import sys
import time
from pathlib import Path
from unittest import mock

import pytest
from harness import LauncherTest, prompts_at

from claude_airlock import errors, settings
from claude_airlock.events import Kind, Who
from claude_airlock.files import try_lock_file
from claude_airlock.recording import api_calls, api_log, started
from claude_airlock.report import api_events, follow
from claude_airlock.report.layout import Layout
from claude_airlock.sandbox.runtime import DOCKERS_OWN

# The session Claude Code says the calls are of
SESSION = "8eade19a-9acf-4daf-bdff-a622fcdcfb52"
# The container of the sessions here
CONTAINER = "claude-proj"
USAGE = {
    "input_tokens": 2,
    "cache_creation_input_tokens": 515,
    "cache_read_input_tokens": 25988,
    "output_tokens": 25,
    "output_tokens_details": {"thinking_tokens": 0},
}


def request_body(**more: object) -> dict:
    """A request as Claude Code writes one out."""
    return {
        "model": "claude-haiku-5-5",
        "messages": [{"role": "user", "content": "hello"}],
        "system": [{"type": "text", "text": "You are Claude Code."}],
        "tools": [{"name": "Bash", "description": "Runs a command"}],
        "max_tokens": 128000,
        "stream": True,
        **more,
    }


def answer_body(message: str, **more: object) -> dict:
    """The answer to one, by the id of its message."""
    return {
        "model": "claude-haiku-5-5",
        "id": message,
        "role": "assistant",
        "content": [{"type": "text", "text": "pong"}],
        "stop_reason": "end_turn",
        "usage": USAGE,
        **more,
    }


def written(value: object) -> bytes:
    """A value as Claude Code writes it to a file."""
    return json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()


class ApiLogTest(LauncherTest):
    @pytest.fixture(autouse=True)
    def drop_made(self, sandbox: None) -> None:
        self.drop = self.work / "drop"
        self.drop.mkdir()
        self.bodies = self.state / "api-log"
        self.keeper = api_log.Keeper.of(
            self.host, CONTAINER, str(self.drop), time.time()
        )

    def call(
        self,
        number: int,
        request: object | None = None,
        answer: object | None = None,
        source: str = "sdk",
        **line: object,
    ) -> dict:
        """Leave a call in the drop as Claude Code does: the two files,
        and its line of the index. Returns that line."""
        said = {
            "timestamp": "2026-11-26T09:06:16.578Z",
            "session_id": SESSION,
            "query_source": source,
            "model": "claude-haiku-5-5",
            "request_id": f"req_{number}",
            "message_id": f"msg_{number}",
            "message_uuid": f"uuid-{number}",
            "request_file": f"body-{number}.request.json",
            "response_file": f"req_{number}.response.json",
            **line,
        }
        asked = request_body() if request is None else request
        answered = answer_body(f"msg_{number}") if answer is None else answer
        (self.drop / f"body-{number}.request.json").write_bytes(written(asked))
        (self.drop / f"req_{number}.response.json").write_bytes(written(answered))
        self.index(said)
        return said

    def index(self, said: object) -> None:
        with open(self.drop / api_log.INDEX, "ab") as index:
            index.write(written(said) + b"\n")

    def notes(self) -> list[dict]:
        record = api_calls.call_record(self.host)
        return record.read(self.host.project_dir, 0, time.time() + 60)

    def events(self) -> list:
        return api_events.call_events(self.host, 0, time.time() + 60)[1]

    def kept_dir(self) -> Path:
        """Where the bodies of the one session that kept some are."""
        (directory,) = self.bodies.iterdir()
        return directory

    def kept(self) -> list[str]:
        return sorted(
            str(file.relative_to(self.bodies)) for file in self.bodies.glob("*/*")
        )

    def test_a_session_is_not_given_a_drop_unless_asked(self):
        flags = self.launch().flags
        assert not [flag for flag in flags if "OTEL" in flag or "api-" in flag]
        assert not (self.state / "api-drop").exists()

    def test_a_session_is_given_a_drop_of_its_own_and_told_to_write_there(self):
        result = self.launch(CLAUDE_AIRLOCK_API_LOG="1")
        target = "/home/sandbox/.local/state/api-log"
        drop = self.state / "api-drop" / CONTAINER
        for flag in (
            f"--volume={drop}:{target}:z",
            f"--env=OTEL_LOG_RAW_API_BODIES=file:{target}",
            "--env=CLAUDE_AIRLOCK_API_LOG=1",
        ):
            assert flag in result.flags
        # Gone with the session, and for the user alone while it was there
        assert not drop.exists()
        assert (self.state / "api-drop").stat().st_mode & 0o777 == 0o700

    def test_what_a_session_leaves_in_its_drop_is_kept_and_said(self):
        drop = self.state / "api-drop" / CONTAINER
        line = {
            "session_id": SESSION,
            "query_source": "sdk",
            "model": "claude-haiku-5-5",
            "message_id": "msg_1",
            "request_file": "a.request.json",
            "response_file": "b.response.json",
        }

        def leave(name: str, value: dict) -> str:
            return f"printf '%s\\n' {shlex.quote(json.dumps(value))} > {name}"

        session = "; ".join(
            (
                f"cd {shlex.quote(str(drop))}",
                leave("a.request.json", request_body()),
                leave("b.response.json", answer_body("msg_1")),
                leave("index.jsonl", line),
            )
        )
        # The transcript ends while the session runs, as one does: what
        # the launcher takes once the session is over comes after it
        transcript = self.write_transcript(SESSION, prompts_at(time.time() - 5))
        stamp = self.work / "stamp.py"
        stamp.write_text(
            "import datetime, json, sys\n"
            "now = datetime.datetime.now(datetime.UTC).isoformat()\n"
            "said = {'type': 'user', 'timestamp': now, 'message': {'content': 'x'}}\n"
            "open(sys.argv[1], 'a').write(json.dumps(said) + '\\n')\n"
        )
        stamped = shlex.join([sys.executable, str(stamp), str(transcript)])
        session = f"{stamped}; {session}"
        result = self.launch(session=session, CLAUDE_AIRLOCK_API_LOG="1")
        assert result.status == 0, result.stderr
        [note] = self.notes()
        assert (note["session"], note["message_id"]) == (CONTAINER, "msg_1")
        assert note["usage"]["cache_read_input_tokens"] == 25988
        directory, _, number = note["kept"].partition("/")
        assert number == "000001"
        asked = json.loads(
            (self.bodies / directory / "000001.request.json").read_text()
        )
        assert asked == request_body()
        assert not drop.exists()
        assert "requests 1 to the model" in result.stderr
        assert f"requests bodies kept in {self.bodies / directory}" in result.stderr
        # Taken as the session ended, and still within its stay: a trace
        # of it has the request
        trace = self.launch("--trace").stdout
        assert "# requests    1 to the model" in trace
        assert "kept as 000001" in trace

    def test_a_drop_that_cannot_be_made_starts_no_session(self):
        (self.state).mkdir(parents=True, exist_ok=True)
        (self.state / "api-drop").write_text("in the way\n")
        result = self.launch(CLAUDE_AIRLOCK_API_LOG="1")
        self.assert_refused(result, "the requests to the model cannot be kept")

    def test_the_start_of_a_session_says_its_requests_are_kept(self):
        chosen = settings.Settings(net_log=False, proc_log=False, api_log=True)
        start = started.Start.of(chosen, DOCKERS_OWN, "image", [], ssh_agent=False)
        assert start.recorded == ("requests to the model",)

    def test_a_call_is_noted_with_what_it_measures_and_its_bodies_kept(self):
        asked = request_body()
        self.call(1, asked)
        self.keeper.look()
        [note] = self.notes()
        assert note["session"] == CONTAINER
        assert note["project"] == self.host.project_dir
        for name, value in (
            ("source", "sdk"),
            ("model", "claude-haiku-5-5"),
            ("claude_session", SESSION),
            ("request_id", "req_1"),
            ("message_id", "msg_1"),
            ("message_uuid", "uuid-1"),
            ("answered", True),
            ("sent", len(written(asked))),
            ("tools", len(written(asked["tools"]))),
            ("system", len(written(asked["system"]))),
            ("messages", len(written(asked["messages"]))),
            ("tool_count", 1),
            ("message_count", 1),
            ("stop", "end_turn"),
        ):
            assert note[name] == value, name
        assert note["usage"] == {
            "input_tokens": 2,
            "cache_creation_input_tokens": 515,
            "cache_read_input_tokens": 25988,
            "output_tokens": 25,
            "thinking_tokens": 0,
        }
        name = self.kept_dir().name
        assert note["kept"] == f"{name}/000001"
        assert self.kept() == [
            f"{name}/000001.request.json",
            f"{name}/000001.response.json",
        ]
        kept = Path(self.kept_dir(), "000001.request.json")
        assert kept.read_bytes() == written(asked)
        # For the user alone, as a transcript is
        assert kept.stat().st_mode & 0o777 == 0o600
        assert self.bodies.stat().st_mode & 0o777 == 0o700
        # And taken out of the drop
        assert sorted(os.listdir(self.drop)) == [api_log.INDEX]

    def test_calls_are_numbered_in_the_order_of_the_index(self):
        for number in (1, 2, 3):
            self.call(number)
        self.keeper.look()
        self.call(4)
        self.keeper.look()
        assert [note["message_id"] for note in self.notes()] == [
            "msg_1",
            "msg_2",
            "msg_3",
            "msg_4",
        ]
        assert [note["kept"][-6:] for note in self.notes()] == [
            "000001",
            "000002",
            "000003",
            "000004",
        ]

    def test_a_call_waits_for_its_answer_to_be_whole(self):
        self.call(1)
        answer = self.drop / "req_1.response.json"
        whole = answer.read_bytes()
        # The line of the index came first, the answer is half written
        answer.write_bytes(whole[:20])
        self.keeper.look()
        assert self.notes() == []
        answer.write_bytes(whole)
        self.keeper.look()
        [note] = self.notes()
        assert note["usage"]["output_tokens"] == 25

    def test_an_answer_that_never_reads_whole_is_not_waited_for_long(self):
        self.call(1)
        (self.drop / "req_1.response.json").write_bytes(b'{"usage": {"outp')
        self.call(2)
        with mock.patch.object(api_log, "ANSWER_WAIT", 0.0):
            self.keeper.look()
        first, second = self.notes()
        assert first["answered"] is True
        assert "usage" not in first
        assert first["received"] == 16
        assert second["usage"]["output_tokens"] == 25
        # Kept as it was found
        kept = Path(self.kept_dir(), "000001.response.json")
        assert kept.read_bytes() == b'{"usage": {"outp'

    def test_the_last_look_waits_for_nothing(self):
        self.call(1)
        (self.drop / "req_1.response.json").unlink()
        self.keeper.look()
        assert self.notes() == []
        self.keeper.look(last=True)
        [note] = self.notes()
        assert note["answered"] is True
        assert "received" not in note

    def test_a_name_that_is_a_path_is_not_followed(self):
        secret = self.home / "secret"
        secret.write_text('{"messages": ["a secret"]}')
        self.call(1, request_file="../home/secret")
        self.call(2, request_file=str(secret))
        self.call(3, request_file="..request.json/../../home/secret")
        self.keeper.look()
        notes = self.notes()
        assert len(notes) == 3
        assert all("sent" not in note for note in notes)
        assert "a secret" not in "".join(
            file.read_text() for file in self.bodies.glob("*/*")
        )

    def test_a_link_in_the_place_of_a_body_is_not_followed(self):
        secret = self.home / "secret"
        secret.write_text('{"messages": ["a secret"]}')
        self.call(1)
        request = self.drop / "body-1.request.json"
        request.unlink()
        request.symlink_to(secret)
        self.keeper.look()
        [note] = self.notes()
        assert "sent" not in note
        assert [Path(name).name for name in self.kept()] == ["000001.response.json"]
        # The link is let go of, not what it leads to
        assert not request.is_symlink()
        assert secret.exists()

    def test_a_body_that_is_too_long_is_neither_read_nor_kept(self):
        with mock.patch.object(api_log, "MOST_BODY", 64):
            self.call(1)
            self.keeper.look(last=True)
        [note] = self.notes()
        assert note["sent"] == len(written(request_body()))
        assert "messages" not in note
        assert "kept" not in note
        assert self.kept() == []
        [event] = self.events()
        assert "not read as a request" in event.details[0]
        assert "bodies NOT KEPT" in event.details[0]

    def test_a_body_of_too_many_values_is_kept_and_not_taken_apart(self):
        self.call(1, request=[[]] * 200)
        with mock.patch.object(api_log, "MOST_LINE_HELD", 1000):
            self.keeper.look(last=True)
        [note] = self.notes()
        assert "messages" not in note
        assert note["kept"]

    def test_a_body_that_is_no_request_is_noted_as_it_is(self):
        self.call(1, request=["not", "a", "request"], answer="nor an answer")
        self.call(2, request={"messages": "x", "tools": {"a": 1}, "system": None})
        self.call(3, answer={"usage": {"output_tokens": -1, "input_tokens": True}})
        self.keeper.look(last=True)
        first, second, third = self.notes()
        assert "messages" not in first
        assert "usage" not in first
        assert "tool_count" not in second
        assert "message_count" not in second
        assert second["messages"] == 3
        assert "usage" not in third
        assert len(self.events()) == 3

    def test_no_more_of_bodies_is_kept_of_a_session_than_there_is_room_for(self):
        one = len(written(request_body())) + len(written(answer_body("msg_1")))
        with mock.patch.object(api_log, "MOST_A_SESSION", one + 10):
            keeper = api_log.Keeper.of(
                self.host, CONTAINER, str(self.drop), time.time()
            )
        for number in (1, 2, 3):
            self.call(number)
        keeper.look()
        notes = self.notes()
        assert [bool(note.get("kept")) for note in notes] == [True, False, False]
        assert keeper.unkept == 2
        assert len(self.kept()) == 2
        # Noted all the same, with what each measures
        assert all(note["messages"] for note in notes)
        row = api_events.call_events(self.host, 0, time.time() + 60)[0][0]
        assert row[1].endswith("the bodies of 2 NOT KEPT")

    def test_calls_past_those_a_session_has_lines_for_are_counted(self):
        with mock.patch.object(api_calls, "MOST_SESSION_CALLS", 2):
            for number in range(1, 6):
                self.call(number)
            self.keeper.look()
            notes = self.notes()
            assert [note.get("message_id") for note in notes] == [
                "msg_1",
                "msg_2",
                None,
            ]
            # Said at once that it began
            assert notes[-1][api_calls.UNRECORDED] is True
            self.keeper.look(last=True)
        assert self.notes()[-1][api_calls.UNRECORDED] == 3
        assert len(self.kept()) == 4
        assert sorted(os.listdir(self.drop)) == [api_log.INDEX]
        rows, events = api_events.call_events(self.host, 0, time.time() + 60)
        assert rows[0][1].endswith("3 more NOT RECORDED one by one")
        assert "3 more requests NOT RECORDED one by one" in events[-1].details[0]
        assert events[-1].wrong

    def test_calls_past_those_that_can_wait_are_counted_and_let_go_of(self):
        with mock.patch.object(api_log, "MOST_WAITING", 2):
            for number in (1, 2, 3):
                self.call(number)
                # None of them has its answer yet
                (self.drop / f"req_{number}.response.json").write_bytes(b"{")
            self.keeper.look()
        assert [note.get(api_calls.UNRECORDED) for note in self.notes()] == [True]
        # Not left to be taken for a request that had no answer
        assert not (self.drop / "body-3.request.json").exists()
        self.keeper.look(last=True)
        notes = self.notes()
        assert [note.get("message_id") for note in notes[1:3]] == ["msg_1", "msg_2"]
        assert notes[-1][api_calls.UNRECORDED] == 1
        assert all(note.get("answered", True) for note in notes)

    def test_requests_left_in_the_drop_are_those_without_an_answer(self):
        self.call(1)
        asked = request_body(model="claude-opus-5-5")
        for name, when in (("late", 20), ("early", 10)):
            file = self.drop / f"{name}.request.json"
            file.write_bytes(written(asked))
            os.utime(file, (when, when))
        (self.drop / "notes.txt").write_text("not a request")
        self.keeper.look()
        assert len(self.notes()) == 1
        self.keeper.look(last=True)
        _, early, late = self.notes()
        for note in (early, late):
            assert note["answered"] is False
            assert note["model"] == "claude-opus-5-5"
            assert note["sent"] == len(written(asked))
        assert (early["kept"][-6:], late["kept"][-6:]) == ("000002", "000003")
        row = api_events.call_events(self.host, 0, time.time() + 60)[0][0]
        sent = len(written(request_body())) + 2 * len(written(asked))
        assert row == (
            "requests",
            f"3 to the model, {api_events.size(sent)} sent, 2 without an answer",
        )
        assert "NO ANSWER was noted" in self.events()[-1].details[0]

    def test_the_index_is_read_as_it_grows_and_a_line_once_it_is_whole(self):
        said = self.call(1)
        line = written({**said, "message_id": "msg_2"})
        with open(self.drop / api_log.INDEX, "ab") as index:
            index.write(line[:30])
        self.keeper.look()
        assert [note["message_id"] for note in self.notes()] == ["msg_1"]
        (self.drop / "body-1.request.json").write_bytes(written(request_body()))
        (self.drop / "req_1.response.json").write_bytes(written(answer_body("msg_2")))
        with open(self.drop / api_log.INDEX, "ab") as index:
            index.write(line[30:] + b"\n")
        self.keeper.look()
        assert [note["message_id"] for note in self.notes()] == ["msg_1", "msg_2"]

    def test_a_line_of_the_index_that_is_none_is_passed_over(self):
        with open(self.drop / api_log.INDEX, "wb") as index:
            index.write(b"not json\n[1, 2]\n{}\n\n")
            index.write(b'{"request_file": "' + b"x" * api_log.INDEX_LINE + b'"}\n')
        self.call(1)
        self.keeper.look()
        assert [note["message_id"] for note in self.notes()] == ["msg_1"]
        assert self.keeper.unread == 1

    def test_no_more_of_the_index_is_read_at_a_look_than_a_look_takes(self):
        for number in (1, 2, 3):
            self.call(number)
        with mock.patch.object(api_log, "MOST_INDEX_A_LOOK", 400):
            self.keeper.look()
            assert len(self.notes()) < 3
            self.keeper.look()
            self.keeper.look()
            self.keeper.look()
        assert len(self.notes()) == 3

    def test_an_index_written_anew_is_read_from_where_it_ends(self):
        self.call(1)
        self.keeper.look()
        (self.drop / api_log.INDEX).write_bytes(b"")
        self.keeper.look()
        self.call(2)
        self.keeper.look()
        assert [note["message_id"] for note in self.notes()] == ["msg_1", "msg_2"]

    def test_a_link_in_the_place_of_the_index_is_not_followed(self):
        elsewhere = self.work / "elsewhere"
        elsewhere.write_bytes(written({"request_file": "a.request.json"}) + b"\n")
        (self.drop / api_log.INDEX).symlink_to(elsewhere)
        (self.drop / "a.request.json").write_bytes(written(request_body()))
        self.keeper.look()
        assert self.notes() == []

    def test_what_the_index_says_is_cut_to_what_a_line_holds(self):
        self.call(1, model="m" * 5000, query_source=["a", "list"], session_id=7)
        self.keeper.look()
        [note] = self.notes()
        assert note["model"] == "m" * api_calls.NOTED_WIDTH
        assert "source" not in note
        assert "claude_session" not in note

    def test_a_call_that_cannot_be_kept_is_counted_and_the_next_is_taken(self):
        self.call(1)
        self.call(2)
        fails = mock.patch.object(
            api_log, "write_whole", side_effect=[OSError("disk full"), True, True]
        )
        with fails:
            self.keeper.look()
        assert (self.keeper.failed, self.keeper.problem) == (1, "disk full")
        assert [note["message_id"] for note in self.notes()] == ["msg_2"]
        # And is not taken for a request without an answer at the end
        self.keeper.look(last=True)
        assert len(self.notes()) == 1

    def test_the_drop_of_a_session_that_ended_without_its_launcher_goes(self):
        drops = self.state / "api-drop"
        names = self.state / "names"
        for directory in (drops / "claude-gone", drops / "claude-there", names):
            directory.mkdir(parents=True)
        (drops / "claude-gone" / "a.request.json").write_text("{}")
        (drops / CONTAINER).mkdir()
        (drops / CONTAINER / "stale.request.json").write_text("{}")
        # A launcher has the session of that name
        claims = [
            try_lock_file(str(names / name)) for name in ("claude-there", CONTAINER)
        ]
        assert None not in claims
        for claim in claims:
            self.cleanup.callback(os.close, claim)
        api_log.let_go_of_left_drops(self.host)
        assert sorted(os.listdir(drops)) == ["claude-proj", "claude-there"]
        # The one this launcher has is made anew, without what was left
        drop = api_log._fresh_drop(self.host, CONTAINER)
        assert os.listdir(drop) == []
        assert Path(drop).stat().st_mode & 0o777 == 0o700

    def test_no_more_of_bodies_is_read_of_a_session_than_there_is_room_for(self):
        one = len(written(request_body())) + len(written(answer_body("msg_1")))
        with mock.patch.object(api_log, "MOST_READ_A_SESSION", one + 10):
            keeper = api_log.Keeper.of(
                self.host, CONTAINER, str(self.drop), time.time()
            )
        for number in (1, 2):
            self.call(number)
        keeper.look(last=True)
        first, second = self.notes()
        assert first["kept"]
        assert first["messages"]
        # Noted by how long its files are, and no more
        assert second["sent"] == len(written(request_body()))
        assert second["received"] == len(written(answer_body("msg_2")))
        assert "messages" not in second
        assert "usage" not in second
        assert "kept" not in second

    def test_two_sessions_of_one_name_and_moment_keep_their_bodies_apart(self):
        moment = time.time()
        for _ in range(2):
            keeper = api_log.Keeper.of(self.host, CONTAINER, str(self.drop), moment)
            self.call(1)
            keeper.look(last=True)
            (self.drop / api_log.INDEX).unlink()
        first, second = self.notes()
        assert first["kept"] != second["kept"]
        assert len(self.kept()) == 4

    def test_what_was_kept_goes_also_once_the_setting_is_off(self):
        old = self.bodies / "claude-a-1"
        old.mkdir(parents=True)
        (old / "000001.request.json").write_text("{}")
        long_ago = time.time() - (api_log.KEPT_DAYS + 1) * 86400
        os.utime(old, (long_ago, long_ago))
        left = self.state / "api-drop" / "claude-gone"
        left.mkdir(parents=True)
        (left / "a.request.json").write_text("{}")
        assert self.launch().status == 0
        assert not old.exists()
        assert not left.exists()

    @pytest.mark.skipif(os.geteuid() == 0, reason="root reads what is closed")
    def test_a_drop_the_session_closed_is_taken_and_removed_all_the_same(self):
        drop = self.state / "api-drop" / CONTAINER
        line = {"message_id": "msg_1", "request_file": "a.request.json"}
        closed = "; ".join(
            (
                f"cd {shlex.quote(str(drop))}",
                f"printf '%s\\n' {shlex.quote(json.dumps(line))} > index.jsonl",
                f"printf %s {shlex.quote(json.dumps(request_body()))} > a.request.json",
                "mkdir -p d/e; chmod 500 d; chmod 0 .",
            )
        )
        result = self.launch(session=closed, CLAUDE_AIRLOCK_API_LOG="1")
        assert result.status == 0, result.stderr
        assert "cannot be removed" not in result.stderr
        assert "could not be taken" not in result.stderr
        assert not drop.exists()
        [note] = self.notes()
        assert (note["message_id"], note["message_count"]) == ("msg_1", 1)
        # And the next session of that name has a drop
        again = self.launch(CLAUDE_AIRLOCK_API_LOG="1")
        assert again.status == 0, again.stderr

    @pytest.mark.skipif(os.geteuid() == 0, reason="root reads what is closed")
    def test_a_drop_that_stays_closed_is_said_to_be(self):
        self.call(1)
        self.drop.chmod(0)
        self.cleanup.callback(self.drop.chmod, 0o700)
        with mock.patch.object(api_log, "_open_up"):
            self.keeper.look(last=True)
        assert self.keeper.closed
        assert self.notes() == []
        with mock.patch.object(api_log, "warn") as warned:
            api_log._say_what_is_missing(self.keeper)
        assert "could not be taken" in warned.call_args.args[0]

    def test_a_link_in_a_drop_is_not_what_is_opened_up(self):
        elsewhere = self.work / "elsewhere"
        elsewhere.mkdir(mode=0o500)
        (self.drop / "link").symlink_to(elsewhere)
        api_log._open_up(str(self.drop))
        assert elsewhere.stat().st_mode & 0o777 == 0o500
        assert api_log._removed(str(self.drop))
        assert elsewhere.exists()

    def test_a_drop_that_cannot_be_removed_is_put_aside_and_said(self):
        drops = self.state / "api-drop"
        (drops / CONTAINER).mkdir(parents=True)
        (drops / CONTAINER / "stuck").write_text("x")
        with (
            mock.patch.object(api_log, "_removed", return_value=False),
            mock.patch.object(api_log, "warn") as warned,
        ):
            drop = api_log._fresh_drop(self.host, CONTAINER)
        assert os.listdir(drop) == []
        [aside] = [name for name in os.listdir(drops) if name != CONTAINER]
        assert aside.endswith(api_log.ASIDE_SUFFIX)
        assert (drops / aside / "stuck").exists()
        assert str(drops / aside) in warned.call_args.args[0]

    def test_a_request_that_could_not_be_noted_leaves_its_number_to_no_other(self):
        self.call(1)
        self.call(2, request_file="")
        (self.drop / "body-2.request.json").unlink()
        add = api_calls.Notes.add
        problems = [OSError("disk full")]

        def add_once_the_disk_has_room(*args: object, **said: object) -> None:
            if problems:
                raise problems.pop()
            add(*args, **said)

        with mock.patch.object(api_calls.Notes, "add", add_once_the_disk_has_room):
            self.keeper.look()
        assert self.keeper.failed == 1
        self.keeper.look(last=True)
        [note] = self.notes()
        assert note["message_id"] == "msg_2"
        # Never next to the request of the one before
        assert note["kept"].endswith("/000002")
        assert [Path(name).name for name in self.kept()] == [
            "000001.request.json",
            "000001.response.json",
            "000002.response.json",
        ]

    def test_bodies_that_have_gone_are_said_to_be(self):
        self.call(1)
        self.keeper.look()
        [said] = self.notes()
        # As it is noted, nothing is asked of where the bodies are
        assert "kept as 000001" in api_events.call_event(said).details[0]
        api_log.shutil.rmtree(self.kept_dir())
        rows, [event] = api_events.call_events(self.host, 0, time.time() + 60)
        assert rows == [
            (
                "requests",
                "1 to the model, 223 B sent, the bodies of 1 NO LONGER KEPT",
            )
        ]
        assert event.details[0].endswith("bodies NO LONGER KEPT")
        assert (event.fields["kept"], event.fields[api_events.GONE]) == ("", True)

    def test_a_trace_of_a_session_that_still_runs_has_its_last_request(self):
        now = time.time()
        record = started.start_record(self.host)
        record.add(self.host.project_dir, CONTAINER, did=started.STARTED)
        # The answer is in the transcript a moment before it is noted
        self.write_transcript(SESSION, prompts_at(now - 5, now - 0.5))
        self.call(1)
        self.keeper.look()
        stdout = self.launch("--trace").stdout
        assert "# requests    1 to the model" in stdout
        # Not what was noted long after the transcript ends
        late = now - 0.5 - api_log.NOTED_WITHIN - 1
        self.write_transcript(SESSION, prompts_at(now - 60, late))
        assert "# requests" not in self.launch("--trace").stdout

    def test_what_is_kept_goes_after_some_days(self):
        old, recent = self.bodies / "claude-a-1", self.bodies / "claude-b-2"
        for directory in (old, recent):
            directory.mkdir(parents=True)
            (directory / "000001.request.json").write_text("{}")
        long_ago = time.time() - (api_log.KEPT_DAYS + 1) * 86400
        os.utime(old, (long_ago, long_ago))
        api_log.let_go_of_old_bodies(self.host)
        assert sorted(os.listdir(self.bodies)) == ["claude-b-2"]

    def test_the_oldest_of_what_is_kept_goes_past_what_is_kept_in_all(self):
        now = time.time()
        for age, name in enumerate(("claude-c-3", "claude-b-2", "claude-a-1")):
            directory = self.bodies / name
            directory.mkdir(parents=True)
            (directory / "000001.request.json").write_bytes(b"x" * 100)
            os.utime(directory, (now - age * 60, now - age * 60))
        with mock.patch.object(api_log, "MOST_KEPT", 250):
            api_log.let_go_of_old_bodies(self.host)
        assert sorted(os.listdir(self.bodies)) == ["claude-b-2", "claude-c-3"]

    def test_a_request_is_shown_in_a_line(self):
        self.call(1)
        self.call(2, source="agent:builtin:general-purpose")
        self.call(3, source="generate_session_title")
        self.call(4, source="repl_main_thread:outputStyle:custom")
        self.keeper.look()
        own, agent, besides, screen = self.events()
        assert (own.who, own.kind) == (Who.CLAUDE, Kind.REQUEST)
        assert own.details == [
            (
                "claude-haiku-5-5  sent 223 B: tools 48 B, system 47 B, messages 35 B"
                "  tokens: 26.5k in (26.0k cached), 25 out  end_turn  kept as 000001"
            )
        ]
        assert own.notes == []
        assert (agent.who, agent.notes) == (
            Who.AGENT,
            ["agent:builtin:general-purpose"],
        )
        assert (besides.who, besides.notes) == (
            Who.CLAUDE,
            ["for: generate_session_title"],
        )
        assert screen.notes == []
        assert own.fields["container"] == CONTAINER
        assert own.fields["cache_read_input_tokens"] == 25988
        assert own.fields["kept"].endswith("/000001")
        assert own.fields["message_uuid"] == "uuid-1"

    def test_what_a_note_holds_is_read_as_what_it_should_be(self):
        record = api_calls.call_record(self.host)
        record.add(
            self.host.project_dir,
            CONTAINER,
            model="evil\x1b[31m\nmodel",
            source=["agent:x"],
            sent="many",
            tools=-4,
            usage={"output_tokens": "a lot", "input_tokens": 3},
            stop=7,
            answered="yes",
            kept="../../../etc/000001",
        )
        record.add(self.host.project_dir, CONTAINER, kept="a/b/000001", answered=True)
        record.add(self.host.project_dir, CONTAINER, kept="../000001", withheld=True)
        first, second, third = self.events()
        assert first.who is Who.CLAUDE
        assert first.details == [
            (
                "evil[31m\\nmodel  sent: the request was NOT FOUND"
                "  NO ANSWER was noted  bodies NOT KEPT"
            )
        ]
        assert first.fields["kept"] == ""
        assert second.fields["kept"] == ""
        assert "the answer was not read" in second.details[0]
        assert third.fields["kept"] == ""
        assert "withheld by Claude Code" in third.details[0]
        assert "\x1b" not in "".join(Layout().events([first, second, third]))

    def test_a_request_is_placed_next_to_the_steps_of_its_transcript(self):
        self.call(1)
        self.call(2)
        self.call(3, session_id="another-session-of-the-project")
        (self.drop / "left.request.json").write_bytes(written(request_body()))
        self.keeper.look(last=True)
        events = self.events()
        api_events.place_calls(events, SESSION, {"msg_1"})
        step, besides, other, unanswered = events
        assert step.notes == []
        assert besides.notes == [api_events.NO_STEP]
        assert besides.fields["no_step"] is True
        assert other.notes == ["of session another-"]
        # Neither what had no answer nor what cannot be told
        assert unanswered.notes == []
        events = self.events()
        api_events.place_calls(events, SESSION, None)
        assert [event.notes for event in events[:2]] == [[], []]

    def test_the_trace_shows_the_requests_of_a_session(self):
        now = time.time()
        self.call(1)
        self.call(2, source="compact")
        self.keeper.look(last=True)
        step = {
            "type": "assistant",
            "timestamp": prompts_at(now + 1)[0]["timestamp"],
            "requestId": "req_1",
            "message": {"id": "msg_1", "content": [{"type": "text", "text": "pong"}]},
        }
        self.write_transcript(
            SESSION, [*prompts_at(now - 5), step, *prompts_at(now + 5)]
        )
        stdout = self.launch("--trace").stdout
        name = self.kept_dir().name
        for expected in (
            "# requests    2 to the model, 446 B sent",
            f"# requests    bodies kept in {self.bodies / name}",
            "claude   request     claude-haiku-5-5  sent 223 B: tools 48 B,",
            "kept as 000001\n",
            f"kept as 000002  for: compact  {api_events.NO_STEP}\n",
        ):
            assert expected in stdout, stdout
        only = self.launch("--trace", "--only", "request", "--json").stdout
        first, second = map(json.loads, only.splitlines())
        assert (first["what"], first["message_id"]) == ("request", "msg_1")
        assert first["kept"] == f"{name}/000001"
        assert "no_step" not in first
        assert second["no_step"] is True

    def test_a_request_is_followed_as_it_is_noted(self):
        follower = follow.Follower(self.host, verbose=False, container=CONTAINER)
        others = follow.Follower(self.host, verbose=False, container="claude-other")

        def followed(by: follow.Follower) -> list[str]:
            found = follow.Round()
            by._poll_notes(found)
            return [event.fields["message_id"] for _, event in found.events]

        # Not before the moment the following began
        time.sleep(0.01)
        self.call(1)
        self.keeper.look()
        assert followed(follower) == ["msg_1"]
        assert followed(follower) == []
        assert followed(others) == []

    def test_a_request_reads_back_as_it_was_noted(self):
        call = api_calls.Call(
            source="sdk",
            model="claude-haiku-5-5",
            claude_session=SESSION,
            request_id="req_1",
            message_id="msg_1",
            message_uuid="uuid-1",
            answered=True,
            sent=100,
            # None of something is a count too
            parts={api_calls.Part.TOOLS: 0, api_calls.Part.MESSAGES: 60},
            tool_count=0,
            message_count=3,
            received=40,
            used={api_calls.Tokens.INPUT: 0, api_calls.Tokens.OUTPUT: 7},
            stop="end_turn",
            kept="claude-proj-1/000001",
        )
        note = call.as_note()
        assert api_calls.Call.from_note(json.loads(json.dumps(note))) == call
        assert (note["tools"], note["tool_count"]) == (0, 0)
        # What says nothing has no place in a line
        assert api_calls.Call().as_note() == {"answered": False}
        assert api_calls.Call.from_note({}) == api_calls.Call()

    def test_what_a_request_was_made_for_is_told_by_its_name(self):
        origin = api_events.Origin
        for source, made_for in (
            ("sdk", origin.CONVERSATION),
            ("repl_main_thread", origin.CONVERSATION),
            ("repl_main_thread:outputStyle:custom", origin.CONVERSATION),
            ("", origin.CONVERSATION),
            ("agent:custom", origin.SUBAGENT),
            ("compact", origin.BESIDES),
            ("agent_summary", origin.BESIDES),
        ):
            assert origin.of(source) is made_for, source
        assert origin.SUBAGENT.who is Who.AGENT
        assert origin.BESIDES.who is Who.CLAUDE

    def test_a_file_of_a_request_is_named_by_its_kind_and_never_by_a_path(self):
        request, response = api_log.BodyKind.REQUEST, api_log.BodyKind.RESPONSE
        assert request.names("a-b_1.request.json") == "a-b_1.request.json"
        assert response.names("req_1.response.json") == "req_1.response.json"
        assert request.file_name("000001") == "000001.request.json"
        for name in (
            "req_1.response.json",
            "../a.request.json",
            "a/b.request.json",
            ".request.json",
            "a.request.json\n",
            "\u0661.request.json",
            "a" * 129 + ".request.json",
            7,
            None,
        ):
            assert request.names(name) == "", name

    def test_the_setting_is_read_as_a_switch(self):
        missing = str(self.work / "no-config")
        assert settings.load_settings({}, missing).api_log is False
        on = settings.load_settings({"CLAUDE_AIRLOCK_API_LOG": "1"}, missing)
        assert on.api_log is True
        with pytest.raises(errors.Fatal):
            settings.load_settings({"CLAUDE_AIRLOCK_API_LOG": "yes"}, missing)
