#!/usr/bin/env python3
"""CLAUDE_AIRLOCK_NET_ASK: the hosts the egress filter asks the user
about, as the launcher keeps them and as the proxy's helper reads them."""

from __future__ import annotations

import contextlib
import io
import json
import os
import shutil
import stat
import subprocess
import threading
import time
from pathlib import Path
from unittest import mock

import pytest
from harness import ROOT, LauncherTest, mounted_copy

from claude_airlock.launcher import Launcher
from claude_airlock.sandbox import asked_hosts
from claude_airlock.settings import Host, Settings

At = asked_hosts.Destination

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

    def test_only_what_could_be_a_host_at_a_port_is_taken_of_what_waits(self):
        asked = self.asked()
        for name in (
            "example.com:443",
            "b.example.com:22",
            "UPPER.com:443",
            ".hidden:443",
            "a b:443",
            # A host alone, as a helper of before wrote it
            "example.org",
            "example.net:",
            "example.net:0443",
            "example.net:65536",
            "example.net:443:443",
        ):
            (self.tree / "waiting" / name).touch()
        (self.tree / "waiting" / "-dash.com:443").mkdir()
        assert asked.waiting() == [At("b.example.com", 22), At("example.com", 443)]
        # No more than the helper lets wait
        for number in range(20):
            (self.tree / "waiting" / f"h{number}.test:443").touch()
        assert len(asked.waiting()) == asked_hosts.MOST_WAITING

    def test_an_answer_is_kept_and_the_host_waits_no_more(self):
        asked = self.asked()
        for name in ("yes.test:443", "no.test:22", "later.test:80"):
            (self.tree / "waiting" / name).touch()
        asked.answer(At("yes.test", 443), True)
        asked.answer(At("no.test", 22), False)
        asked.answer(At("later.test", 80), None)
        # Not a host at a port, nothing is written for it anywhere
        asked.answer(At("../../owner", 443), True)
        asked.answer(At("../owner", 443), None)
        asked.answer(At("yes.test", 0), True)
        asked.answer(At("yes.test", 65536), True)
        assert asked.waiting() == []
        kept = sorted(str(p.relative_to(self.tree)) for p in self.tree.rglob("*.test*"))
        assert kept == ["allowed/yes.test:443", "refused/no.test:22"]
        assert (self.tree / "owner").exists()
        assert (self.tree / asked_hosts.BY_PORT).is_file()

    def test_nothing_is_asked_before_the_address_is_known_or_after_the_end(self):
        asked = asked_hosts.AskedHosts(self.host, "claude-proj")
        assert asked.waiting() == []
        asked.answer(At("example.com", 443), True)
        assert not self.root.exists()
        # Not an address the helper takes
        assert not asked.open("fd00::7")
        assert not asked.open("../x")
        assert asked.open(ADDRESS)
        asked.answer(At("example.com", 443), True)
        asked.close()
        assert list(self.root.iterdir()) == []
        assert asked.waiting() == []
        # A session that is over is not opened for
        assert not asked.open(ADDRESS)
        assert list(self.root.iterdir()) == []

    def test_what_another_session_was_allowed_at_the_address_is_dropped(self):
        first = self.asked()
        first.answer(At("example.com", 443), True)
        self.asked()
        assert list((self.tree / "allowed").iterdir()) == []

    def test_what_a_session_that_is_over_left_is_dropped(self):
        self.asked().answer(At("example.com", 443), True)
        # Of this launcher, which is still there
        asked_hosts.drop_left_behind(self.host)
        assert (self.tree / "allowed" / "example.com:443").exists()
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
            f"0 {ADDRESS} example.com 443", "1 172.20.0.8 example.com 443"
        ) == ["0 ERR", "1 ERR"]
        assert not self.root.exists()

    def test_the_helper_answers_what_the_user_said(self):
        asked = self.asked()
        (self.tree / "waiting" / "seen.test:443").touch()
        asked.answer(At("yes.test", 443), True)
        asked.answer(At("no.test", 443), False)
        assert asked.waiting() == [At("seen.test", 443)]
        # The first two are not hosts the launcher was asked about, the
        # answers are still found: an answer may come ahead of a request
        (self.tree / "allowed" / "yes.test:443").touch()
        (self.tree / "refused" / "no.test:443").touch()
        answered = self.helper(
            f"0 {ADDRESS} yes.test 443",
            f"1 {ADDRESS} no.test 443",
            f"2 {ADDRESS} YES.test 443",
            # Another session's answers are not this one's
            "3 172.20.0.8 yes.test 443",
        )
        assert answered == ["0 OK", "1 ERR", "2 OK", "3 ERR"]

    def test_the_helper_holds_a_request_until_it_is_answered(self):
        asked = self.asked()

        def answer() -> None:
            patience = time.monotonic() + 10
            while time.monotonic() < patience:
                for host in asked.waiting():
                    asked.answer(host, host == At("yes.test", 443))
                time.sleep(0.02)

        answering = threading.Thread(target=answer, daemon=True)
        answering.start()
        said = self.helper(
            f"0 {ADDRESS} yes.test 443", f"1 {ADDRESS} no.test 443", looks=200
        )
        assert said == ["0 OK", "1 ERR"]
        assert asked.waiting() == []

    def test_the_helper_refuses_what_is_not_answered_and_asks_again(self):
        asked = self.asked()
        assert self.helper(f"0 {ADDRESS} slow.test 443") == ["0 ERR"]
        # Not kept: the next request for it waits again
        assert asked.waiting() == []
        assert list((self.tree / "refused").iterdir()) == []

    def test_the_helper_takes_no_host_for_a_path(self):
        self.asked()
        outside = self.work / "outside"
        requests = [
            f"0 {ADDRESS} ../../outside 443",
            f"1 {ADDRESS} ..%2F..%2Foutside 443",
            f"2 {ADDRESS} /etc/passwd 443",
            f"3 {ADDRESS} . 443",
            f"4 {ADDRESS} -x.test 443",
            f"5 {ADDRESS} [::1] 443",
            f"6 {ADDRESS}",
            "7 ../.. example.com 443",
            "8 172.20.0.7/allowed example.com 443",
            # Nor a port for one, nor what is no port squid writes
            f"9 {ADDRESS} example.com ../../../outside",
            f"10 {ADDRESS} example.com 443/../../../../outside",
            f"11 {ADDRESS} example.com",
            f"12 {ADDRESS} example.com -",
            f"13 {ADDRESS} example.com 0",
            f"14 {ADDRESS} example.com 0443",
            f"15 {ADDRESS} example.com 65536",
            f"16 {ADDRESS} example.com 99999999999999999999",
            "not-a-channel 172.20.0.7 example.com 443",
        ]
        said = self.helper(*requests, answers=17)
        assert said == sorted(f"{n} ERR" for n in range(17))
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
        requests = [f"{n} {ADDRESS} {name} 443" for n, name in enumerate(lines)]
        said = self.helper(*requests)
        assert said == sorted(f"{n} ERR" for n in range(len(lines)))
        assert list((self.tree / "waiting").iterdir()) == []
        for name in ("example.com", "a-b.example.co.uk", "1.example.xn--p1ai"):
            with subtests.test(name=name):
                assert asked_hosts.is_host(name)
                asked.answer(At(name, 443), True)
                assert self.helper(f"0 {ADDRESS} {name} 443") == ["0 OK"]

    def test_the_helper_and_the_launcher_take_the_same_for_a_host(self):
        script = HELPER.read_text()
        assert f"HOST='{asked_hosts.HOST_PATTERN}'\n" in script
        assert f"LONGEST_HOST={asked_hosts.LONGEST_HOST}\n" in script
        assert f"PORT='{asked_hosts.PORT_PATTERN}'\n" in script
        assert f"HIGHEST_PORT={asked_hosts.HIGHEST_PORT}\n" in script
        assert f"BY_PORT={asked_hosts.BY_PORT}\n" in script

    def test_a_yes_is_for_the_port_it_was_given_alone(self):
        asked = self.asked()
        asked.answer(At("example.com", 443), True)
        asked.answer(At("example.com", 80), False)
        said = self.helper(
            f"0 {ADDRESS} example.com 443",
            f"1 {ADDRESS} example.com 80",
            # Not answered for, it waits, and is refused for want of one
            f"2 {ADDRESS} example.com 22",
        )
        assert said == ["0 OK", "1 ERR", "2 ERR"]
        assert asked.waiting() == []

    def test_what_is_written_of_a_host_and_port_is_taken_by_the_launcher(self):
        for name, asked in (
            ("example.com:443", At("example.com", 443)),
            ("a-b.example.co.uk:22", At("a-b.example.co.uk", 22)),
            ("x.test:65535", At("x.test", 65535)),
        ):
            assert At.named(name) == asked
            assert asked.file_name == name
        for name in (
            "example.com",
            "example.com:",
            ":443",
            "example.com:0",
            "example.com:0443",
            "example.com:65536",
            "example.com:443:443",
            "172.17.0.1:443",
            "claude-other:443",
            "example.com:44 3",
            "example.com:443\n",
        ):
            assert At.named(name) is None, name

    def test_a_directory_of_a_launcher_of_before_is_not_asked_for(self):
        # Made by a launcher that kept a host alone, for a session that
        # still runs: what it allowed is not taken for any port, and the
        # helper does not wait for an answer it would never write
        old = self.tree
        for kept in asked_hosts.Hosts:
            (old / kept).mkdir(parents=True)
        (old / "allowed" / "example.com").touch()
        started = time.monotonic()
        said = self.helper(f"0 {ADDRESS} example.com 443", looks=200)
        assert said == ["0 ERR"]
        assert time.monotonic() - started < 5
        assert list((old / "waiting").iterdir()) == []
        # Nor is such an answer taken in a directory of now
        shutil.rmtree(old)
        asked = self.asked()
        (self.tree / "allowed" / "example.com").touch()
        assert self.helper(f"0 {ADDRESS} example.com 443") == ["0 ERR"]
        assert asked.waiting() == []

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
        # Told the port as well as the host, which an answer is for
        (helper,) = (line for line in conf if line.startswith("external_acl_type"))
        assert " %>a %>rd %>rP /bin/bash /etc/squid/ask-helper" in helper

    def test_the_helper_lets_only_so_many_hosts_of_a_session_wait(self):
        self.asked()
        requests = [f"{n} {ADDRESS} h{n}.test 443" for n in range(12)]
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
        # A copy of the checkout's, see SharedProxyTest
        copy = mounted_copy(proxy, "/etc/squid/ask-helper")
        assert copy.is_relative_to(self.state / "proxy-files" / "claude-egress-proxy")
        assert copy.read_bytes() == HELPER.read_bytes()
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
