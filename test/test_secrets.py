#!/usr/bin/env python3
"""The files of secrets a process opens: which they are, how the watcher
sees one held open, and what the record and the trace say of it."""

from __future__ import annotations

import io
import json
import os
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

import pytest
from harness import LauncherTest

from claude_airlock import settings
from claude_airlock.events import Kind, Wrong
from claude_airlock.recording import host_health, processes, procwatch, secrets
from claude_airlock.report import net_events

HOME = "/home/sandbox"


PROJECT = "/home/me/proj"


def session_secrets(**about: object) -> procwatch.Secrets:
    host = settings.Host("/home/me", PROJECT, "/home/me/.config", "/s")
    rules = settings.Settings(**about)  # type: ignore[arg-type]
    return secrets.session_secrets(rules, host, [PROJECT, "/mnt/lib"])


def noted(*lines: dict) -> processes.ProcessRecord:
    record = processes.ProcessRecord()
    for line in lines:
        record.take(json.dumps(line))
    return record


class SecretsTest:
    def test_the_files_of_secrets_are_those_of_both_homes(self):
        rules = session_secrets()
        for home in (HOME, "/home/me"):
            assert rules.of(f"{home}/.claude/.credentials.json") == "claude"
            assert rules.of(f"{home}/.config/gh/hosts.yml") == "gh"
            assert rules.of(f"{home}/.git-credentials") == "git"
            assert rules.of(f"{home}/.ssh/id_ed25519") == "ssh"
            assert rules.of(f"{home}/.gnupg/private-keys-v1.d/x.key") == "gnupg"
            assert rules.of(f"{home}/.aws/credentials") == "cloud"
        assert rules.of("/home/me/proj/.env") == "hidden"
        assert rules.of("/home/me/proj/sub/.env.local") == "hidden"
        assert rules.of("/mnt/lib/.netrc") == "hidden"
        # Taken as the kernel names it, a link of /proc too
        assert rules.of(f"{HOME}/.ssh/../.ssh/id_rsa (deleted)") == "ssh"

    def test_what_holds_nothing_secret_is_not_one(self):
        rules = session_secrets()
        for path in (
            f"{HOME}/.ssh/known_hosts",
            f"{HOME}/.ssh/known_hosts.old",
            f"{HOME}/.ssh/config",
            f"{HOME}/.ssh/id_ed25519.pub",
            "/home/me/proj/.env.example",
            "/home/me/proj/main.go",
            "/home/me/.claude/settings.json",
            "socket:[812]",
            "pipe:[9]",
            "hosts.yml",
        ):
            assert rules.of(path) is None, path

    def test_a_hidden_name_is_one_only_where_such_files_are_hidden(self):
        rules = session_secrets()
        # A fixture a test makes, in /tmp or anywhere else not mounted,
        # was never kept from the session
        for path in (
            "/tmp/tmps80m58r2/home/proj/.env",
            "/tmp/.netrc",
            "/home/me/project/.env",
            f"{HOME}/.env",
        ):
            assert rules.of(path) is None, path
        # The rules the watcher is given keep where they are
        again = procwatch.Secrets.read(rules.as_json())
        assert again.of("/home/me/proj/.env") == "hidden"
        assert again.of("/tmp/x/.env") is None
        # The root of all, should one be given
        assert procwatch.Secrets(names={".env": "hidden"}, roots=["/"]).of("/a/.env")

    def test_a_hidden_name_is_found_as_the_session_names_its_place(self):
        # The image links the host's home to the container's, and the
        # kernel names a file a process holds by where the link leads: a
        # project under the home is under /home/sandbox in the session
        rules = procwatch.Secrets.read(session_secrets().as_json())
        assert rules.of(f"{HOME}/proj/.env") == "hidden"
        assert rules.of(f"{PROJECT}/.env") == "hidden"
        # Not a directory outside the home, which is where it is
        assert rules.of("/mnt/lib/.env") == "hidden"
        assert rules.of(f"{HOME}/lib/.env") is None
        assert rules.of(f"{HOME}/.env") is None

    def test_the_names_hidden_from_a_session_are_files_of_secrets(self):
        rules = session_secrets(shadow=("*.pem",))
        assert rules.of("/home/me/proj/certs/server.pem") == "hidden"
        assert b".pem" in (rules.markers() or ())

    def test_the_watcher_is_given_the_same_as_the_launcher_has(self):
        rules = session_secrets(shadow=("*.pem",))
        again = procwatch.Secrets.read(rules.as_json())
        assert again.as_json() == rules.as_json()
        assert again.of(f"{HOME}/.ssh/id_rsa") == "ssh"
        # What is not the launcher's is passed over
        assert procwatch.Secrets.read("[1]").of(f"{HOME}/.ssh/id_rsa") is None
        odd = procwatch.Secrets.read('{"files": {"/a": 1, "/b": "x"}, "passed": [2]}')
        assert (odd.of("/a"), odd.of("/b")) == (None, "x")

    def test_every_path_of_secrets_has_one_of_the_markers(self):
        rules = session_secrets()
        markers = rules.markers()
        assert markers is not None
        for path in (
            f"{HOME}/.claude/.credentials.json",
            "/home/me/.config/gh/hosts.yml",
            f"{HOME}/.ssh/id_rsa",
            "/x/.envrc",
            "/x/.env.production",
        ):
            assert any(marker in path.encode() for marker in markers), path
        # A pattern any name can match, or with a class, has none
        assert session_secrets(shadow=("*",)).markers() is None
        assert session_secrets(shadow=("key[0-9]",)).markers() is None

    def test_claude_code_opening_its_own_login_is_no_sign(self):
        assert secrets.own_login("claude", secrets.CLAUDE_PROGRAM)
        assert not secrets.own_login("claude", "/usr/bin/cat")
        assert not secrets.own_login("gh", secrets.CLAUDE_PROGRAM)
        assert secrets.said("gh") == "the login of gh"
        assert secrets.said("other") == "secrets (other)"


class OpenedOnceTest:
    def test_a_file_is_noted_once_for_each_process_until_it_is_another(self):
        opened = procwatch.OpenedOnce()
        assert opened.take(40, "/a") is procwatch.Telling.NEW
        assert opened.take(40, "/a") is procwatch.Telling.KNOWN
        assert opened.take(41, "/a") is procwatch.Telling.NEW
        opened.forget(40)
        assert opened.take(40, "/a") is procwatch.Telling.NEW

    def test_past_the_most_it_is_said_once_and_nothing_after(self):
        opened = procwatch.OpenedOnce()
        with mock.patch.object(procwatch, "MOST_OPENED", 2):
            told = [opened.take(pid, "/a") for pid in range(5)]
        assert told == [
            procwatch.Telling.NEW,
            procwatch.Telling.NEW,
            procwatch.Telling.TOO_MANY,
            procwatch.Telling.KNOWN,
            procwatch.Telling.KNOWN,
        ]
        assert opened.too_many


class WatcherTest(LauncherTest):
    def holding(self, pid: int, *paths: str) -> Path:
        """A /proc with a process that holds files open, each by a link
        of its descriptors, as the kernel has it."""
        proc = self.work / "proc"
        descriptors = proc / str(pid) / "fd"
        descriptors.mkdir(parents=True, exist_ok=True)
        for number, path in enumerate(paths, start=3):
            os.symlink(path, descriptors / str(number))
        return proc

    def watch(
        self, proc: Path, out: io.StringIO, aloud: io.StringIO | None = None
    ) -> procwatch.Watch:
        def read(pid: int) -> procwatch.ProcessRead:
            return "100", 7, "/usr/bin/cat", ["cat", "x"]

        return procwatch.Watch(
            out,
            read_process=read,
            secrets=session_secrets(),
            proc=str(proc),
            aloud=aloud or io.StringIO(),
        )

    def test_a_file_of_secrets_held_open_is_noted_once_and_said_aloud(self):
        login = f"{HOME}/.claude/.credentials.json"
        proc = self.holding(812, login, "socket:[4]", "/usr/lib/libc.so.6")
        out, aloud = io.StringIO(), io.StringIO()
        watch = self.watch(proc, out, aloud)
        watch._look_at_processes([812], 0.0)
        watch._look_at_processes([812], 0.1)
        said = [json.loads(line) for line in out.getvalue().splitlines()]
        assert [line for line in said if "opened" in line] == [
            {"t": said[-1]["t"], "opened": login, "secret": "claude", "pids": [812]}
        ]
        # The process first, for what follows the session to name it
        spoken = [json.loads(line) for line in aloud.getvalue().splitlines()]
        assert [list(line)[1] for line in spoken] == ["pid", "opened"]
        record = noted(*said)
        (opened,) = record.opened
        assert (opened.path, opened.kind, opened.pid) == (login, "claude", 812)

    def test_what_is_said_aloud_goes_to_the_file_given_and_not_the_output(self):
        login = f"{HOME}/.claude/.credentials.json"
        proc = self.holding(812, login)
        given = self.work / "aloud.jsonl"
        given.touch(mode=0o600)
        aloud = procwatch._aloud_to(str(given))
        self.cleanup.callback(aloud.close)
        watch = procwatch.Watch(
            io.StringIO(),
            read_process=lambda pid: ("100", 7, "/usr/bin/cat", ["cat", "x"]),
            secrets=session_secrets(),
            proc=str(proc),
            aloud=aloud,
        )
        output = io.StringIO()
        with redirect_stdout(output):
            watch._look_at_processes([812], 0.0)
        assert output.getvalue() == ""
        said = [json.loads(line) for line in given.read_text().splitlines()]
        assert [list(line)[1] for line in said] == ["pid", "opened"]
        # Never made by the watcher, nor through a link
        with pytest.raises(FileNotFoundError):
            procwatch._aloud_to(str(self.work / "none.jsonl"))
        (self.work / "link.jsonl").symlink_to(given)
        with pytest.raises(OSError, match="Too many levels of symbolic links"):
            procwatch._aloud_to(str(self.work / "link.jsonl"))

    def test_a_file_held_across_an_exec_is_noted_again_with_the_program(self):
        key = f"{HOME}/.ssh/id_rsa"
        proc = self.holding(812, key)
        out = io.StringIO()
        programs = iter(
            [("100", 7, "/bin/bash", ["bash"]), ("100", 7, "/usr/bin/scp", ["scp"])]
        )
        watch = procwatch.Watch(
            out,
            read_process=lambda pid: next(programs),
            secrets=session_secrets(),
            proc=str(proc),
            aloud=io.StringIO(),
        )
        watch._look_at_processes([812], 0.0)
        # Looked at again while young, by then it is scp
        watch._look_at_processes([812], 0.1)
        said = [json.loads(line) for line in out.getvalue().splitlines()]
        kept = [line.get("exe") or line.get("opened") for line in said]
        assert kept[-4:] == ["/bin/bash", key, "/usr/bin/scp", key]

    def test_no_more_files_are_noted_than_are_kept(self):
        proc = self.holding(812, *(f"{PROJECT}/{n}/.env" for n in range(5)))
        out = io.StringIO()
        watch = self.watch(proc, out)
        with mock.patch.object(procwatch, "MOST_OPENED", 2):
            watch._look_at_processes([812], 0.0)
        said = [json.loads(line) for line in out.getvalue().splitlines()]
        assert len([line for line in said if "opened" in line]) == 2
        assert said[-1]["note"] == procwatch.Note.TOO_MANY_OPENED
        assert noted(*said).too_many_opened

    def test_without_rules_no_descriptor_is_read(self):
        proc = self.holding(812, f"{HOME}/.ssh/id_rsa")
        out = io.StringIO()
        watch = procwatch.Watch(
            out,
            read_process=lambda pid: ("1", 7, "/bin/cat", ["cat"]),
            proc=str(proc),
            aloud=io.StringIO(),
        )
        watch._look_at_processes([812], 0.0)
        assert "opened" not in out.getvalue()


class RecordTest:
    def test_a_connection_told_without_its_port_is_found_by_where_it_went(self):
        record = noted(
            {"t": 1.0, "pid": 40, "ppid": 2, "exe": "/usr/bin/curl", "argv": ["curl"]},
            {"t": 2.0, "port": 0, "to": "203.0.113.9", "to_port": 443, "pids": [40]},
        )
        (made,) = record.holder(51000, "203.0.113.9", 443, 2.1)
        assert made.pid == 40
        assert record.holder(51000, "203.0.113.9", 443, 30.0) == []
        assert record.holder(51000, "203.0.113.10", 443, 2.1) == []

    def test_what_ran_is_known_of_a_record_from_outside_once_monitored(self):
        outside = {"t": 1.0, "note": "started", "outside": "gVisor (gv)", "beat": None}
        plain = noted(outside)
        assert not plain.processes_known
        assert plain.noted_processes(5.0, 6.0) is None
        told = noted(
            outside,
            {"t": 2.0, "note": "monitored"},
            {"t": 3.0, "pid": 40, "ppid": 2, "exe": "/bin/ls", "argv": ["ls"]},
            {"t": 4.0, "dropped": 3},
            {"t": 5.0, "dropped": 9},
        )
        assert told.processes_known
        assert told.monitored_from == 2.0
        assert told.dropped == 9
        assert told.noted_processes(2.5, 3.5) is True
        assert told.noted_processes(3.5, 3.9) is False
        # Before it was told of, not known
        assert told.noted_processes(1.5, 3.5) is None
        assert told.limit_ends_session


class ShownTest:
    def record(self) -> processes.ProcessRecord:
        return noted(
            {"t": 1.0, "note": "started"},
            {
                "t": 1.0,
                "pid": 2,
                "ppid": 1,
                "exe": secrets.CLAUDE_PROGRAM,
                "argv": ["claude"],
            },
            {"t": 2.0, "pid": 40, "ppid": 2, "exe": "/bin/cat", "argv": ["cat", "x"]},
            {
                "t": 3.0,
                "opened": f"{HOME}/.claude/.credentials.json",
                "secret": "claude",
                "pids": [2],
            },
            {
                "t": 4.0,
                "opened": f"{HOME}/.config/gh/hosts.yml",
                "secret": "gh",
                "pids": [40],
            },
            {
                "t": 5.0,
                "opened": f"{HOME}/.config/gh/hosts.yml",
                "secret": "gh",
                "pids": [41],
            },
        )

    def test_a_file_of_secrets_opened_is_what_went_wrong_with_its_process(self):
        events = net_events.opened_events(self.record())
        own, cat, unknown = events
        assert own.what == Kind.SECRET
        assert own.wrong is Wrong.NO
        assert own.details == [
            (
                f"{HOME}/.claude/.credentials.json, the login of Claude Code,"
                " opened by Claude Code itself"
            )
        ]
        assert cat.wrong is Wrong.THROUGHOUT
        assert cat.details == [
            f"{HOME}/.config/gh/hosts.yml, the login of gh, OPENED  by: [40] cat x < claude.exe"
        ]
        assert cat.fields["process"]["exe"] == "/bin/cat"
        assert cat.fields["secret"] == secrets.Kind.GH
        # A process the record does not have is not made up
        assert "by:" not in unknown.details[0]
        assert "process" not in unknown.fields
        # Of what is followed as it runs, Claude Code's own is left out
        assert len(net_events.opened_events(self.record(), own_too=False)) == 2
        assert len(net_events.opened_events(self.record(), past=2)) == 1

    def test_the_header_and_the_end_say_which_files_were_opened(self):
        record = self.record()
        assert net_events.opened_files(record) == [
            f"{HOME}/.config/gh/hosts.yml, the login of gh"
        ]
        summary = net_events.watched_summary(record, verbose=False)
        assert "  1 files of secrets OPENED by its processes" in summary

    def test_a_record_told_by_gvisor_says_so(self):
        record = noted(
            {"t": 1.0, "note": "started", "outside": "gVisor (gv)"},
            {"t": 2.0, "note": "monitored"},
            {"t": 3.0, "pid": 40, "ppid": 2, "exe": "/bin/ls", "argv": ["ls"]},
            {"t": 4.0, "dropped": 3},
        )
        summary = net_events.watched_summary(record, verbose=False)
        assert summary[0] == (
            "  processes 1 seen to run, as gVisor (gv) told, each one shown with --verbose"
        )
        assert summary[1] == (
            "  3 of what gVisor (gv) would have told COULD NOT BE TOLD,"
            " what ran then may be missing"
        )
        unmonitored = noted({"t": 1.0, "note": "started", "outside": "gVisor (gv)"})
        assert net_events.watched_summary(unmonitored, False)[0] == (
            "  processes not recorded under gVisor (gv), only memory and CPU use"
        )


class HostRecordTest(LauncherTest):
    def test_processes_leave_room_for_what_is_reserved(self):
        record = host_health.HealthRecord.begin(self.host, "claude-proj", "gVisor (gv)")
        line = {"pid": 1, "ppid": 0, "exe": "/x", "argv": ["x" * 100]}
        size = len(procwatch.lined(1.0, line))
        connection = {"port": 0, "to": "203.0.113.9", "to_port": 443, "pids": [1]}
        most = procwatch.RESERVED + 5 * size
        with mock.patch.object(procwatch, "MOST_BYTES", most):
            for _ in range(10):
                record.note_at(1.0, False, line)
            record.note_at(2.0, True, connection)
        read = processes.read_record(record.path)
        assert len(read.processes) < 10
        assert read.full
        assert read.holders
        # Each when it was so, not when it was written
        assert read.processes[0].when == 1.0

    def test_a_full_reserved_part_ends_with_a_word(self):
        record = host_health.HealthRecord.begin(self.host, "claude-proj", "gVisor (gv)")
        connection = {"port": 0, "to": "203.0.113.9", "to_port": 443, "pids": [1]}
        size = len(procwatch.lined(2.0, connection))
        most = procwatch.LAST_WORD + 20 * size
        with mock.patch.object(procwatch, "MOST_BYTES", most):
            for _ in range(40):
                record.note_at(2.0, True, connection)
        last = record.path.read_text(encoding="utf-8").splitlines()[-1]
        assert json.loads(last)["note"] == procwatch.Note.FULL
        assert record.path.stat().st_size <= most

    def test_a_line_cut_short_by_a_full_disk_is_ended_by_the_next(self):
        record = host_health.HealthRecord.begin(self.host, "claude-proj", "gVisor (gv)")
        written = os.write

        def cut(file: int, data: bytes) -> int:
            if len(data) > 10:
                return written(file, data[:10])
            raise OSError(28, "No space left on device")

        ran = {"ppid": 1, "exe": "/bin/sh", "argv": ["sh"]}
        with mock.patch.object(os, "write", cut):
            record.note_at(1.0, False, {"pid": 2, **ran})
        record.note_at(2.0, False, {"pid": 3, **ran})
        read = processes.read_record(record.path)
        assert [process.pid for process in read.processes] == [3]

    def test_what_is_told_once_the_record_is_kept_is_not_written(self):
        record = host_health.HealthRecord.begin(self.host, "claude-proj", "gVisor (gv)")
        record.keep(self.host, 3.0)
        kept = record.path.with_name(record.path.name.removesuffix(host_health.PART))
        before = kept.read_bytes()
        # As a thread still reading what gVisor told would
        record.note_at(4.0, True, {"port": 0, "to": "203.0.113.9", "to_port": 443})
        assert not record.path.exists()
        assert kept.read_bytes() == before
