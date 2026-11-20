#!/usr/bin/env python3
"""The login of the host and of the sandboxed sessions is one: what either
side writes of it is carried to the other."""

from __future__ import annotations

import importlib
import os
import unittest

from harness import LauncherTest, settings

login = importlib.import_module("claude_airlock.sandbox.login")

LOGIN = ".credentials.json"


class LoginSessionTest(LauncherTest):
    """With the launcher run as a command, a session played by a shell."""

    def setUp(self):
        super().setUp()
        self.ours = self.home / ".claude" / LOGIN
        self.theirs = self.base / LOGIN

    def test_a_session_starts_with_the_hosts_login(self):
        self.ours.write_text("host")
        result = self.launch(session=f"cat '{self.theirs}' > '{self.work}/seen'")
        self.assertEqual(result.status, 0, result.stderr)
        self.assertEqual((self.work / "seen").read_text(), "host")
        self.assertEqual(self.theirs.stat().st_mode & 0o777, 0o600)
        # Carried, not mounted: a mount of the one file would not follow
        # the host's next renewal, which replaces the file
        self.assertFalse([flag for flag in result.flags if LOGIN in flag])

    def test_what_a_session_logs_in_with_is_the_hosts_while_it_runs(self):
        self.ours.write_text("before")
        # As Claude Code writes it: next to it, then renamed over it
        renew = f"printf %s renewed > '{self.theirs}.tmp' && mv '{self.theirs}.tmp' '{self.theirs}'"
        seen = f"sleep 1; cat '{self.ours}' > '{self.work}/seen'"
        self.launch(session=f"{renew}; {seen}")
        self.assertEqual((self.work / "seen").read_text(), "renewed")
        self.assertEqual(self.ours.stat().st_mode & 0o777, 0o600)

    def test_what_the_host_renews_reaches_a_running_session(self):
        self.ours.write_text("before")
        renew = f"printf %s renewed > '{self.ours}.tmp' && mv '{self.ours}.tmp' '{self.ours}'"
        seen = f"sleep 1; cat '{self.theirs}' > '{self.work}/seen'"
        self.launch(session=f"{renew}; {seen}")
        self.assertEqual((self.work / "seen").read_text(), "renewed")

    def test_what_a_session_writes_as_it_ends_is_not_lost(self):
        self.ours.write_text("before")
        self.launch(session=f"printf %s last > '{self.theirs}'")
        self.assertEqual(self.ours.read_text(), "last")

    def test_a_logout_in_a_session_is_the_hosts_too(self):
        self.ours.write_text("login")
        self.launch(session=f"rm '{self.theirs}'")
        self.assertFalse(self.ours.exists())

    def test_a_login_kept_in_the_sandbox_alone_is_carried_to_the_host(self):
        # macOS, where the host's own is in the Keychain
        self.launch(session=f"printf %s mine > '{self.theirs}'")
        self.assertEqual(self.ours.read_text(), "mine")
        self.launch(session="true")
        self.assertEqual(self.theirs.read_text(), "mine")


class LoginPairTest(LauncherTest):
    """Called directly, for what happens between two sessions."""

    def setUp(self):
        super().setUp()
        self.host = settings.detect_host({"HOME": str(self.home)})
        self.ours = self.home / ".claude" / LOGIN
        self.theirs = self.base / LOGIN
        self.base.mkdir(parents=True)
        self.pair = login.LoginPair(self.host)

    def settled(self, ours: str | None, theirs: str | None) -> None:
        self.pair.settle()
        for file, content in ((self.ours, ours), (self.theirs, theirs)):
            self.assertEqual(file.read_text() if file.exists() else None, content)

    def test_the_side_that_changed_is_the_one_kept(self):
        self.ours.write_text("one")
        self.settled("one", "one")
        # Whichever was written last: the host's is older here and newer below
        self.theirs.write_text("two")
        os.utime(self.ours, (2**31, 2**31))
        self.settled("two", "two")
        self.ours.write_text("three")
        os.utime(self.theirs, (2**31, 2**31))
        self.settled("three", "three")

    def test_a_logout_on_the_host_between_two_sessions_is_not_undone(self):
        self.ours.write_text("one")
        self.settled("one", "one")
        self.ours.unlink()
        login.LoginPair(self.host).settle()
        self.assertFalse(self.theirs.exists())
        self.assertFalse(self.ours.exists())

    def test_when_both_changed_the_one_written_last_is_kept(self):
        self.ours.write_text("one")
        self.settled("one", "one")
        self.ours.write_text("host")
        self.theirs.write_text("sandbox")
        os.utime(self.ours, (1, 1))
        self.settled("sandbox", "sandbox")

    def test_what_is_noted_is_not_the_login(self):
        self.ours.write_text("secret")
        self.settled("secret", "secret")
        noted = self.state / "login-synced"
        self.assertNotIn("secret", noted.read_text())
        self.assertEqual(noted.stat().st_mode & 0o777, 0o600)

    def test_a_link_left_in_the_sandbox_is_not_followed(self):
        elsewhere = self.home / "elsewhere"
        elsewhere.write_text("not a login")
        self.theirs.symlink_to(elsewhere)
        self.ours.write_text("login")
        self.pair.settle()
        # Neither read as the sandbox's login, nor written through
        self.assertEqual(self.ours.read_text(), "login")
        self.assertEqual(elsewhere.read_text(), "not a login")

    def test_a_look_that_fails_does_not_end_the_session(self):
        self.ours.write_text("login")
        self.base.chmod(0o500)
        self.addCleanup(self.base.chmod, 0o700)
        self.pair.settle_quietly()
        self.assertFalse(self.theirs.exists())


if __name__ == "__main__":
    unittest.main()
