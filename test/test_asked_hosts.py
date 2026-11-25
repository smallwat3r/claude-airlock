#!/usr/bin/env python3
"""CLAUDE_AIRLOCK_NET_ASK: the hosts the egress filter asks the user
about, as the launcher keeps them and as the proxy's helper reads them."""

from __future__ import annotations

import contextlib
import io
import json
import os
import stat
import subprocess
import threading
import time
from pathlib import Path
from unittest import mock

import pytest
from harness import ROOT, LauncherTest

from claude_airlock.launcher import Launcher
from claude_airlock.sandbox import asked_hosts
from claude_airlock.settings import Host, Settings

HELPER = ROOT / "docker" / "squid-ask-helper.sh"
ADDRESS = "172.20.0.7"


class AskedHostsTest(LauncherTest):
    @pytest.fixture(autouse=True)
    def asked_tree(self, sandbox: None) -> None:
        self.host = Host(str(self.home), str(self.project), "", str(self.work / "s"))
        self.root = Path(self.host.asked_hosts_dir)
        self.tree = self.root / ADDRESS

    def asked(self) -> asked_hosts.AskedHosts:
        """What is asked about for a session at ADDRESS."""
        asked = asked_hosts.AskedHosts(self.host, "claude-proj")
        assert asked.open(ADDRESS)
        return asked

    def helper(
        self, *requests: str, looks: int = 4, answers: int | None = None
    ) -> list[str]:
        """What the helper answers to the requests of squid, each a line.
        Squid goes on listening while a request waits, so it is only
        left once it answered them all, or so many of them."""
        helper = subprocess.Popen(
            ["bash", str(HELPER), str(self.root)],
            env={**os.environ, "ASK_EVERY": "0.05", "ASK_LOOKS": str(looks)},
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        assert helper.stdin
        assert helper.stdout
        assert helper.stderr
        ended = threading.Timer(30, helper.kill)
        ended.start()
        try:
            helper.stdin.write("".join(request + "\n" for request in requests))
            helper.stdin.flush()
            wanted = len(requests) if answers is None else answers
            said = [helper.stdout.readline().rstrip("\n") for _ in range(wanted)]
            helper.stdin.close()
            said += helper.stdout.read().splitlines()
            assert (helper.wait(), helper.stderr.read()) == (0, "")
        finally:
            ended.cancel()
            helper.stdout.close()
            helper.stderr.close()
        return sorted(said)

    def test_the_proxy_can_get_in_and_write_the_hosts_that_wait_alone(self):
        self.asked()
        modes = {
            path: stat.S_IMODE(path.stat().st_mode)
            for path in (self.root, self.tree, *sorted(self.tree.iterdir()))
            if path.is_dir()
        }
        assert modes == {
            self.root: 493,
            self.tree: 493,
            self.tree / "allowed": 493,
            self.tree / "refused": 493,
            self.tree / "waiting": 511,
        }
        # Nobody else on the host gets as far
        assert stat.S_IMODE(self.root.parent.stat().st_mode) == 448

    def test_only_what_could_be_a_host_is_taken_of_what_waits(self):
        asked = self.asked()
        for name in ("example.com", "b.example.com", "UPPER.com", ".hidden", "a b"):
            (self.tree / "waiting" / name).touch()
        (self.tree / "waiting" / "-dash.com").mkdir()
        assert asked.waiting() == ["b.example.com", "example.com"]
        # No more than the helper lets wait
        for number in range(20):
            (self.tree / "waiting" / f"h{number}.test").touch()
        assert len(asked.waiting()) == asked_hosts.MOST_WAITING

    def test_an_answer_is_kept_and_the_host_waits_no_more(self):
        asked = self.asked()
        for name in ("yes.test", "no.test", "later.test"):
            (self.tree / "waiting" / name).touch()
        asked.answer("yes.test", True)
        asked.answer("no.test", False)
        asked.answer("later.test", None)
        # Not a host, nothing is written for it anywhere
        asked.answer("../../owner", True)
        asked.answer("../owner", None)
        assert asked.waiting() == []
        kept = sorted(str(p.relative_to(self.tree)) for p in self.tree.rglob("*.test"))
        assert kept == ["allowed/yes.test", "refused/no.test"]
        assert (self.tree / "owner").exists()

    def test_nothing_is_asked_before_the_address_is_known_or_after_the_end(self):
        asked = asked_hosts.AskedHosts(self.host, "claude-proj")
        assert asked.waiting() == []
        asked.answer("example.com", True)
        assert not self.root.exists()
        # Not an address the helper takes
        assert not asked.open("fd00::7")
        assert not asked.open("../x")
        assert asked.open(ADDRESS)
        asked.answer("example.com", True)
        asked.close()
        assert list(self.root.iterdir()) == []
        assert asked.waiting() == []
        # A session that is over is not opened for
        assert not asked.open(ADDRESS)
        assert list(self.root.iterdir()) == []

    def test_what_another_session_was_allowed_at_the_address_is_dropped(self):
        first = self.asked()
        first.answer("example.com", True)
        self.asked()
        assert list((self.tree / "allowed").iterdir()) == []

    def test_what_a_session_that_is_over_left_is_dropped(self):
        self.asked().answer("example.com", True)
        # Of this launcher, which is still there
        asked_hosts.drop_left_behind(self.host)
        assert (self.tree / "allowed" / "example.com").exists()
        # Of a launcher that is gone, with its session
        gone = {"session": "claude-proj", **Launcher(2**22 + 1, "1").as_fields()}
        (self.tree / "owner").write_text(json.dumps(gone))
        # One without an owner, and one that was being made or dropped
        (self.root / "172.20.0.9" / "allowed").mkdir(parents=True)
        (self.root / ".left" / "172.20.0.3" / "allowed").mkdir(parents=True)
        asked_hosts.drop_left_behind(self.host)
        assert list(self.root.iterdir()) == []

    def test_the_address_is_waited_for_while_the_session_runs(self):
        filtered = Settings(net_filter=True, net_ask=True)
        with mock.patch.dict(os.environ, {"FAKE_IP": ADDRESS}):
            running = asked_hosts.hosts_asked(
                filtered, self.host, "claude-proj", "claude-proj", True
            )
            with running as asked:
                assert asked is not None
                patience = time.monotonic() + 10
                while not self.tree.exists() and time.monotonic() < patience:
                    time.sleep(0.05)
                assert (self.tree / "waiting").is_dir()
            assert list(self.root.iterdir()) == []
            # Not without the filter, and not where there is no place to ask
            for settings, chat in (
                (Settings(net_ask=True), True),
                (Settings(net_filter=True), True),
                (filtered, False),
            ):
                running = asked_hosts.hosts_asked(
                    settings, self.host, "claude-proj", "claude-proj", chat
                )
                with (
                    contextlib.redirect_stderr(io.StringIO()) as said,
                    running as asked,
                ):
                    assert asked is None
                # Said of the one that was to ask and cannot
                told = settings.net_filter and settings.net_ask
                assert ("line mode only" in said.getvalue()) == told

    def test_the_helper_refuses_for_a_session_that_does_not_ask(self):
        assert self.helper(
            f"0 {ADDRESS} example.com -", "1 172.20.0.8 example.com -"
        ) == ["0 ERR", "1 ERR"]
        assert not self.root.exists()

    def test_the_helper_answers_what_the_user_said(self):
        asked = self.asked()
        (self.tree / "waiting" / "seen.test").touch()
        asked.answer("yes.test", True)
        asked.answer("no.test", False)
        assert asked.waiting() == ["seen.test"]
        # The first two are not hosts the launcher was asked about, the
        # answers are still found: an answer may come ahead of a request
        (self.tree / "allowed" / "yes.test").touch()
        (self.tree / "refused" / "no.test").touch()
        answered = self.helper(
            f"0 {ADDRESS} yes.test -",
            f"1 {ADDRESS} no.test -",
            f"2 {ADDRESS} YES.test -",
            # Another session's answers are not this one's
            "3 172.20.0.8 yes.test -",
        )
        assert answered == ["0 OK", "1 ERR", "2 OK", "3 ERR"]

    def test_the_helper_holds_a_request_until_it_is_answered(self):
        asked = self.asked()

        def answer() -> None:
            patience = time.monotonic() + 10
            while time.monotonic() < patience:
                for host in asked.waiting():
                    asked.answer(host, host == "yes.test")
                time.sleep(0.02)

        answering = threading.Thread(target=answer, daemon=True)
        answering.start()
        said = self.helper(
            f"0 {ADDRESS} yes.test -", f"1 {ADDRESS} no.test -", looks=200
        )
        assert said == ["0 OK", "1 ERR"]
        assert asked.waiting() == []

    def test_the_helper_refuses_what_is_not_answered_and_asks_again(self):
        asked = self.asked()
        assert self.helper(f"0 {ADDRESS} slow.test -") == ["0 ERR"]
        # Not kept: the next request for it waits again
        assert asked.waiting() == []
        assert list((self.tree / "refused").iterdir()) == []

    def test_the_helper_takes_no_host_for_a_path(self):
        self.asked()
        outside = self.work / "outside"
        requests = [
            f"0 {ADDRESS} ../../outside -",
            f"1 {ADDRESS} ..%2F..%2Foutside -",
            f"2 {ADDRESS} /etc/passwd -",
            f"3 {ADDRESS} . -",
            f"4 {ADDRESS} -x.test -",
            f"5 {ADDRESS} [::1] -",
            f"6 {ADDRESS}",
            "7 ../.. example.com -",
            "8 172.20.0.7/allowed example.com -",
            "not-a-channel 172.20.0.7 example.com -",
        ]
        said = self.helper(*requests, answers=9)
        assert said == [f"{n} ERR" for n in range(9)]
        assert not outside.exists()
        assert list((self.tree / "waiting").iterdir()) == []

    def test_only_a_name_of_the_public_dns_is_asked_about(
        self, subtests: pytest.Subtests
    ):
        # Not what the proxy reaches without asking the DNS: an address
        # in any notation, the bare name of a container on its networks
        asked = self.asked()
        unasked = (
            "172.17.0.1",
            "169.254.169.254",
            "2130706433",
            "0x7f.1",
            "127.0.0.0x1",
            "claude-other",
            "localhost",
            "example.com.",
            "a..b.com",
            "-a.com",
            "a-.com",
            "example.com\n",
            "a" * 64 + ".com",
            ".".join(["a" * 60] * 5) + ".com",
        )
        for name in unasked:
            with subtests.test(name=name):
                assert not asked_hosts.is_host(name)
        lines = [name for name in unasked if "\n" not in name]
        requests = [f"{n} {ADDRESS} {name} -" for n, name in enumerate(lines)]
        said = self.helper(*requests)
        assert said == sorted(f"{n} ERR" for n in range(len(lines)))
        assert list((self.tree / "waiting").iterdir()) == []
        for name in ("example.com", "a-b.example.co.uk", "1.example.xn--p1ai"):
            with subtests.test(name=name):
                assert asked_hosts.is_host(name)
                asked.answer(name, True)
                assert self.helper(f"0 {ADDRESS} {name} -") == ["0 OK"]

    def test_the_helper_and_the_launcher_take_the_same_for_a_host(self):
        script = HELPER.read_text()
        assert f"HOST='{asked_hosts.HOST_PATTERN}'\n" in script
        assert f"LONGEST_HOST={asked_hosts.LONGEST_HOST}\n" in script

    def test_the_proxy_looks_no_host_up_before_it_is_allowed(
        self, subtests: pytest.Subtests
    ):
        # A rule is read left to right and a dst looks the host up, which
        # says the name to whoever serves its domain
        conf = (ROOT / "docker" / "squid.conf").read_text().splitlines()
        rules = [line.split() for line in conf if line.startswith("http_access")]
        looked_up = {"to_own", "!to_own", "to_private", "!to_private"}
        for rule in rules:
            with subtests.test(rule=rule):
                at = [n for n, word in enumerate(rule) if word in looked_up]
                if at:
                    assert rule[1] == "allow"
                    assert rule[2] in ("allowed", "confirmed")
                    assert min(at) > 2
        assert ["http_access", "allow", "allowed", "!to_own"] in rules
        # The proxy's own by every address that leads to it, the one of
        # "this host" too, which the kernel takes for its loopback
        (own,) = (line.split()[3:] for line in conf if line.startswith("acl to_own "))
        for network in ("0.0.0.0/8", "127.0.0.0/8", "169.254.0.0/16", "::/128", "::1"):
            assert network in own
        asked = ["http_access", "allow", "confirmed", "!to_own", "!to_private"]
        assert asked in rules

    def test_the_helper_lets_only_so_many_hosts_of_a_session_wait(self):
        self.asked()
        requests = [f"{n} {ADDRESS} h{n}.test -" for n in range(12)]
        seen: list[int] = []
        done = threading.Event()

        def look() -> None:
            while not done.wait(0.01):
                seen.append(len(list((self.tree / "waiting").iterdir())))

        looking = threading.Thread(target=look, daemon=True)
        looking.start()
        try:
            said = self.helper(*requests, looks=20)
        finally:
            done.set()
            looking.join()
        assert said == sorted(f"{n} ERR" for n in range(12))
        assert max(seen) == asked_hosts.MOST_WAITING


class AskingSessionTest(LauncherTest):
    def test_the_proxy_is_given_the_helper_and_where_the_answers_are(self):
        result = self.launch(CLAUDE_AIRLOCK_NET_FILTER="1")
        proxy = result.sidecar("claude-egress-proxy")
        helper = f"--volume={HELPER}:/etc/squid/ask-helper:ro,z"
        assert helper in proxy
        asked = self.state / "asked-hosts"
        assert f"--volume={asked}:/var/lib/claude-airlock/asked:z" in proxy
        assert stat.S_IMODE(asked.stat().st_mode) == 493
        # Never into the session, which could allow itself any host
        assert not [flag for flag in result.flags if "asked" in flag]

    def test_a_session_that_is_not_in_line_mode_is_told_it_is_not_asked_for(self):
        result = self.launch(
            CLAUDE_AIRLOCK_NET_FILTER="1", CLAUDE_AIRLOCK_NET_ASK="1", FAKE_IP=ADDRESS
        )
        assert result.status == 0, result.stderr
        assert "CLAUDE_AIRLOCK_NET_ASK asks in line mode only" in result.stderr
        # Nor is the session told to wait for an answer nobody is asked for
        assert not [flag for flag in result.flags if "NET_ASK" in flag]
        assert list((self.state / "asked-hosts").iterdir()) == []
        # Nothing to say without the filter, nor of a filter that does not ask
        for settings in (
            {"CLAUDE_AIRLOCK_NET_ASK": "1"},
            {"CLAUDE_AIRLOCK_NET_FILTER": "1"},
        ):
            (self.work / "log").unlink()
            result = self.launch(**settings)
            assert "NET_ASK" not in result.stderr
            assert not [f for f in result.flags if "NET_ASK" in f]
