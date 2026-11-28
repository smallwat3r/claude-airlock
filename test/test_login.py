#!/usr/bin/env python3
"""The login of the host and of the sandboxed sessions is one: what either
side writes of it is carried to the other."""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import unittest.mock
from pathlib import Path

import pytest
from harness import LauncherTest

from claude_airlock import files, settings
from claude_airlock.sandbox import login

LOGIN = ".credentials.json"
ITEM = "Claude Code-credentials"

# The security of macOS, for the one item of a login: the Keychain it is
# given last is a file it keeps the items in and writes anew with each
# change, as the real one is. Prints what is more than a line of text as
# hex digits, ends with 44 for an item that is not there, with 36 for all
# when FAKE_LOCKED is set, and takes no login while FAKE_FULL is. Each
# call is a line of FAKE_SECURITY_LOG.
FAKE_SECURITY = f"""#!{sys.executable}
import json, os, shlex, sys, time
args = sys.argv[1:]
if args == ["-i"]:
    args = shlex.split(sys.stdin.read())
with open(os.environ["FAKE_SECURITY_LOG"], "a") as log:
    log.write(json.dumps(sys.argv[1:2] + args[:1]) + "\\n")
if "FAKE_LOCKED" in os.environ:
    sys.exit(36)
keychain = args[-1]
with open(keychain) as kept:
    items = json.loads(kept.read() or "{{}}")
def option(name):
    return args[args.index(name) + 1]
def write():
    with open(keychain + ".new", "w") as kept:
        kept.write(json.dumps(items))
    os.replace(keychain + ".new", keychain)
key = option("-a") + " " + option("-s")
if args[0] == "add-generic-password":
    if "FAKE_FULL" in os.environ:
        sys.exit(1)
    items[key] = [option("-X"), time.strftime("%Y%m%d%H%M%S", time.gmtime())]
    write()
    sys.exit(0)
if key not in items:
    sys.exit(44)
if args[0] == "delete-generic-password":
    del items[key]
    write()
elif "-w" in args:
    held = bytes.fromhex(items[key][0])
    line = held.isascii() and held.decode().isprintable()
    print(held.decode() if line else held.hex())
else:
    print('    "mdat"<timedate>=0x00  "' + items[key][1] + 'Z\\\\000"')
"""


# A login as a session leaves one: only what reads as a login is carried
# from the sandbox to the host
RENEWED = '{"token":"renewed"}'


def renewed(login: Path) -> str:
    """The command that renews a login as Claude Code does: written next
    to it, then renamed over it."""
    return f"printf %s '{RENEWED}' > '{login}.tmp' && mv '{login}.tmp' '{login}'"


class LoginSessionTest(LauncherTest):
    """With the launcher run as a command, a session played by a shell."""

    @pytest.fixture(autouse=True)
    def logins(self, sandbox: None) -> None:
        self.ours = self.home / ".claude" / LOGIN
        self.theirs = self.base / LOGIN

    def test_a_session_starts_with_the_hosts_login(self):
        self.ours.write_text("host")
        result = self.launch(session=f"cat '{self.theirs}' > '{self.work}/seen'")
        assert result.status == 0, result.stderr
        assert (self.work / "seen").read_text() == "host"
        assert self.theirs.stat().st_mode & 511 == 384
        # Carried, not mounted: a mount of the one file would not follow
        # the host's next renewal, which replaces the file
        assert not [flag for flag in result.flags if LOGIN in flag]

    def test_what_a_session_logs_in_with_is_the_hosts_while_it_runs(self):
        self.ours.write_text("before")
        renew = renewed(self.theirs)
        seen = f"sleep 1; cat '{self.ours}' > '{self.work}/seen'"
        self.launch(session=f"{renew}; {seen}")
        assert (self.work / "seen").read_text() == RENEWED
        assert self.ours.stat().st_mode & 511 == 384

    def test_what_the_host_renews_reaches_a_running_session(self):
        self.ours.write_text("before")
        renew = renewed(self.ours)
        seen = f"sleep 1; cat '{self.theirs}' > '{self.work}/seen'"
        self.launch(session=f"{renew}; {seen}")
        assert (self.work / "seen").read_text() == RENEWED

    def test_what_a_session_writes_as_it_ends_is_not_lost(self):
        self.ours.write_text("before")
        self.launch(session=f"printf %s '{RENEWED}' > '{self.theirs}'")
        assert self.ours.read_text() == RENEWED

    def test_what_a_session_leaves_that_is_no_login_is_not_the_hosts(self):
        self.ours.write_text("before")
        self.launch(session=f"printf %s 'not a login' > '{self.theirs}'")
        assert self.ours.read_text() == "before"
        # The host's is put back, the next session starts logged in
        assert self.theirs.read_text() == "before"

    def test_a_logout_in_a_session_is_the_hosts_too(self):
        self.ours.write_text("login")
        self.launch(session=f"rm '{self.theirs}'")
        assert not self.ours.exists()

    def test_a_login_kept_in_the_sandbox_alone_is_carried_to_the_host(self):
        self.launch(session=f"printf %s '{RENEWED}' > '{self.theirs}'")
        assert self.ours.read_text() == RENEWED
        self.launch(session="true")
        assert self.theirs.read_text() == RENEWED


class LoginPairTest(LauncherTest):
    """Called directly, for what happens between two sessions."""

    @pytest.fixture(autouse=True)
    def login_pair(self, sandbox: None) -> None:
        self.host = settings.detect_host({"HOME": str(self.home)})
        self.ours = self.home / ".claude" / LOGIN
        self.theirs = self.base / LOGIN
        self.base.mkdir(parents=True)
        self.pair = login.LoginPair(self.host)

    def settled(self, ours: str | None, theirs: str | None) -> None:
        self.pair.settle()
        for file, content in ((self.ours, ours), (self.theirs, theirs)):
            assert (file.read_text() if file.exists() else None) == content

    def test_the_side_that_changed_is_the_one_kept(self):
        self.ours.write_text("one")
        self.settled("one", "one")
        # Whichever was written last: the host's is older here and newer below
        self.theirs.write_text(RENEWED)
        os.utime(self.ours, (2**31, 2**31))
        self.settled(RENEWED, RENEWED)
        self.ours.write_text("three")
        os.utime(self.theirs, (2**31, 2**31))
        self.settled("three", "three")

    def test_a_logout_on_the_host_between_two_sessions_is_not_undone(self):
        self.ours.write_text("one")
        self.settled("one", "one")
        self.ours.unlink()
        login.LoginPair(self.host).settle()
        assert not self.theirs.exists()
        assert not self.ours.exists()

    def test_when_both_changed_the_one_written_last_is_kept(self):
        self.ours.write_text("one")
        self.settled("one", "one")
        self.ours.write_text("host")
        self.theirs.write_text(RENEWED)
        os.utime(self.ours, (1, 1))
        self.settled(RENEWED, RENEWED)

    def test_only_what_reads_as_a_login_is_carried_to_the_host(
        self, subtests: pytest.Subtests
    ):
        self.ours.write_text("host")
        self.settled("host", "host")
        account = {"accessToken": "a", "refreshToken": "r", "expiresAt": 1}
        unfit = (
            "not json",
            "[1, 2]",
            '{"claudeAiOauth": "text"}',
            '{"claudeAiOauth": {"accessToken": ""}}',
            json.dumps({"claudeAiOauth": {**account, "refreshToken": 7}}),
            "[" * 100_000,
        )
        for content in unfit:
            with subtests.test(content=content[:40]):
                self.theirs.write_text(content)
                # Whichever was written last
                os.utime(self.ours, (1, 1))
                self.settled("host", "host")
        fit = json.dumps({"claudeAiOauth": account, "other": {}})
        self.theirs.write_text(fit)
        self.settled(fit, fit)

    def test_the_logins_to_the_mcp_servers_stay_where_they_are(self):
        def held(file: Path) -> dict:
            return json.loads(file.read_text())

        account = {"accessToken": "a", "refreshToken": "r"}
        of_host = {"github": {"accessToken": "the host's"}}
        self.ours.write_text(
            json.dumps({"claudeAiOauth": account, "mcpOAuth": of_host})
        )
        self.pair.settle()
        # The session is logged in, and has nothing of the host's servers
        assert held(self.theirs) == {"claudeAiOauth": account}
        assert "the host's" not in self.theirs.read_text()
        # What a session renews is the host's, what it logs into is not,
        # and the host keeps its own
        renewed = {**account, "accessToken": "b"}
        of_session = {"evil": {"accessToken": "a session's"}}
        self.theirs.write_text(
            json.dumps({"claudeAiOauth": renewed, "mcpOAuth": of_session})
        )
        os.utime(self.ours, (1, 1))
        self.pair.settle()
        assert held(self.ours) == {"claudeAiOauth": renewed, "mcpOAuth": of_host}
        assert held(self.theirs)["mcpOAuth"] == of_session
        # One that only logs into a server changes nothing on the host
        before = self.ours.stat().st_mtime_ns
        self.theirs.write_text(json.dumps({"claudeAiOauth": renewed, "mcpOAuth": {}}))
        self.pair.settle()
        assert self.ours.stat().st_mtime_ns == before
        # And a logout on the host leaves a session what it logged into
        self.theirs.write_text(
            json.dumps({"claudeAiOauth": renewed, "mcpOAuth": of_session})
        )
        self.pair.settle()
        self.ours.write_text(json.dumps({"mcpOAuth": of_host}))
        login.LoginPair(self.host).settle()
        assert held(self.theirs) == {"mcpOAuth": of_session}
        assert held(self.ours) == {"mcpOAuth": of_host}

    def test_a_login_is_read_again_only_once_its_file_changed(self):
        self.ours.write_text(RENEWED)
        self.settled(RENEWED, RENEWED)
        reads = unittest.mock.Mock(wraps=login.open_plain)
        # Long enough after both were written for what was read to stand
        later = time.time_ns() + 2 * files.STAMP_SETTLES_NS
        with (
            unittest.mock.patch.object(login, "open_plain", reads),
            unittest.mock.patch.object(login.time, "time_ns", return_value=later),
        ):
            self.pair.settle()
            assert reads.call_count == 2
            self.pair.settle()
            assert reads.call_count == 2
            # Written again in place as long as it was, and given back when
            # it was written: what the system sets of it tells it apart
            written = self.ours.stat()
            renewed = RENEWED.replace("renewed", "again!!")
            self.ours.write_text(renewed)
            os.utime(self.ours, ns=(written.st_atime_ns, written.st_mtime_ns))
            assert self.ours.stat().st_ino == written.st_ino
            self.settled(renewed, renewed)
            # And one put in its place
            replaced = self.work / "replaced"
            replaced.write_text(RENEWED)
            replaced.replace(self.theirs)
            self.settled(RENEWED, RENEWED)

    def test_a_login_written_again_with_its_old_stamp_is_not_written_over(self):
        # Renewed in place as long as it was, and given back when it was
        # written, as an inode reused by a rename can leave it: what the
        # system sets of it tells it from the one read, and the other
        # side's login does not go over it
        self.ours.write_text(RENEWED)
        store = login.LoginFile(str(self.ours))
        read = store.read()
        written = self.ours.stat()
        renewed = RENEWED.replace("renewed", "again!!")
        self.ours.write_text(renewed)
        os.utime(self.ours, ns=(written.st_atime_ns, written.st_mtime_ns))
        assert self.ours.stat().st_ino == written.st_ino
        assert not store.unchanged(read)
        assert not login.Held(store, read).take(login.Login(b'{"token":"other"}'))
        assert self.ours.read_text() == renewed

    def test_a_login_read_as_it_was_written_is_read_again(self):
        # Within the time a file system keeps such times by, a file written
        # again can have all of its stamp the same: it is read at every look
        self.ours.write_text(RENEWED)
        reads = unittest.mock.Mock(wraps=login.open_plain)
        with unittest.mock.patch.object(login, "open_plain", reads):
            self.settled(RENEWED, RENEWED)
            self.pair.settle()
        assert reads.call_count == 4

    def test_what_is_no_login_in_the_sandbox_alone_is_dropped(self):
        self.theirs.write_text("not a login")
        self.pair.settle()
        assert not self.ours.exists()
        assert not self.theirs.exists()

    def test_what_is_noted_is_not_the_login(self):
        self.ours.write_text("secret")
        self.settled("secret", "secret")
        noted = self.state / "login-synced"
        assert "secret" not in noted.read_text()
        assert noted.stat().st_mode & 511 == 384

    def test_a_link_left_in_the_sandbox_is_not_followed(self):
        elsewhere = self.home / "elsewhere"
        elsewhere.write_text("not a login")
        self.theirs.symlink_to(elsewhere)
        self.ours.write_text("login")
        self.pair.settle()
        # Neither read as the sandbox's login, nor written through
        assert self.ours.read_text() == "login"
        assert elsewhere.read_text() == "not a login"

    def test_a_look_that_fails_does_not_end_the_session(self):
        self.ours.write_text("login")
        self.base.chmod(0o500)
        self.cleanup.callback(self.base.chmod, 0o700)
        self.pair.settle_quietly()
        assert not self.theirs.exists()


class KeychainTest(LauncherTest):
    """On macOS the host's login is in the Keychain, here that of a
    security of our own (see FAKE_SECURITY)."""

    @pytest.fixture(autouse=True)
    def keychain_made(self, sandbox: None) -> None:
        self.keychain = self.home / "Library" / "Keychains" / "login.keychain-db"
        self.keychain.parent.mkdir(parents=True)
        self.keychain.touch()
        self.security = self.work / "bin" / "security"
        self.security.write_text(FAKE_SECURITY)
        self.security.chmod(0o755)
        self.asked = self.work / "security-log"
        self.env = {"USER": "me", "FAKE_SECURITY_LOG": str(self.asked)}
        self.cleanup.enter_context(unittest.mock.patch.dict(os.environ, self.env))
        self.host = settings.detect_host({"HOME": str(self.home)})
        self.ours = self.home / ".claude" / LOGIN
        self.theirs = self.base / LOGIN
        self.base.mkdir(parents=True)
        self.pair = login.LoginPair(self.host)

    def item(self) -> list[str]:
        return ["-a", "me", "-s", ITEM]

    def keep(self, content: str) -> None:
        """Have the Keychain hold a login, as Claude Code writes it."""
        add = ["add-generic-password", "-U", *self.item(), "-X"]
        hexed = content.encode().hex()
        subprocess.run(["security", *add, hexed, str(self.keychain)], check=True)

    def kept(self) -> str | None:
        """What the Keychain holds as the login, as Claude Code reads it."""
        find = ["security", "find-generic-password", *self.item(), "-w"]
        found = subprocess.run(
            [*find, str(self.keychain)], capture_output=True, text=True, check=False
        )
        return found.stdout.rstrip("\n") if found.returncode == 0 else None

    def times_asked(self) -> int:
        return len(self.asked.read_text().splitlines())

    def launch(self, *args, **env):
        return super().launch(*args, **self.env, **env)

    def test_a_session_starts_with_the_login_of_the_keychain(self):
        self.keep('{"token":"host"}')
        self.launch(session=f"cat '{self.theirs}' > '{self.work}/seen'")
        assert (self.work / "seen").read_text() == '{"token":"host"}'
        # The Keychain stays where the host's login is
        assert not self.ours.exists()

    def test_what_a_session_logs_in_with_is_in_the_keychain_while_it_runs(self):
        self.keep('{"token":"before"}')
        # On several lines, which security would print as hex digits and
        # Claude Code on the host could then not read
        renew = f"printf '{{\\n \"token\": \"renewed\"\\n}}\\n' > '{self.theirs}'"
        seen = f"sleep 1; cat '{self.keychain}' > '{self.work}/seen'"
        self.launch(session=f"{renew}; {seen}")
        assert self.kept() == '{"token":"renewed"}'
        held = json.loads((self.work / "seen").read_text())[f"me {ITEM}"][0]
        assert bytes.fromhex(held) == b'{"token":"renewed"}'
        # What says the same is the same: not carried back over the
        # session's own
        assert "\n" in self.theirs.read_text()
        assert not self.ours.exists()

    def test_what_the_host_renews_in_the_keychain_reaches_a_running_session(self):
        self.keep('{"token":"before"}')
        hexed = b'{"token":"renewed"}'.hex()
        add = f"security add-generic-password -U -a me -s '{ITEM}' -X {hexed}"
        seen = f"sleep 1; cat '{self.theirs}' > '{self.work}/seen'"
        self.launch(session=f"{add} '{self.keychain}'; {seen}")
        assert (self.work / "seen").read_text() == '{"token":"renewed"}'

    def test_a_login_security_prints_as_hex_digits_is_read_all_the_same(self):
        self.keep('{\n "token": "host"\n}\n')
        self.pair.settle()
        assert self.theirs.read_text() == '{\n "token": "host"\n}\n'

    def test_a_logout_in_a_session_is_of_the_keychain_too(self):
        self.keep('{"token":"host"}')
        self.launch(session=f"rm '{self.theirs}'")
        assert self.kept() is None

    def test_a_logout_on_the_host_is_the_sessions_too(self):
        self.keep('{"token":"host"}')
        self.pair.settle()
        assert self.theirs.exists()
        delete = ["security", "delete-generic-password", *self.item()]
        subprocess.run([*delete, str(self.keychain)], check=True)
        self.pair.settle()
        assert not self.theirs.exists()

    def test_a_first_login_in_the_sandbox_goes_to_the_keychain(self):
        self.theirs.write_text('{"token":"mine"}')
        self.pair.settle()
        assert self.kept() == '{"token":"mine"}'
        assert not self.ours.exists()

    def test_a_locked_keychain_is_not_a_logout(self):
        self.keep('{"token":"host"}')
        self.pair.settle()
        with unittest.mock.patch.dict(os.environ, {"FAKE_LOCKED": "1"}):
            # Another item was written, so the Keychain is asked again
            os.utime(self.keychain, (1, 1))
            self.pair.settle_quietly()
            assert self.theirs.read_text() == '{"token":"host"}'
            # Nor asked again at once: each time could ask the user
            asked = self.times_asked()
            self.pair.settle_quietly()
            assert self.times_asked() == asked

    def test_a_login_the_keychain_did_not_take_is_not_lost(self):
        self.keep('{"token":"old"}')
        self.pair.settle()
        self.theirs.write_text('{"token":"renewed"}')
        with unittest.mock.patch.dict(os.environ, {"FAKE_FULL": "1"}):
            self.pair.settle()
        # Not taken for carried: the old one would then be the host's
        # own change, and replace the session's
        login.LoginPair(self.host).settle()
        assert self.theirs.read_text() == '{"token":"renewed"}'
        assert self.kept() == '{"token":"renewed"}'

    def test_the_keychain_is_asked_once_for_as_long_as_it_is_the_same(self):
        self.keep('{"token":"host"}')
        self.pair.settle()
        asked = self.times_asked()
        self.pair.settle()
        self.pair.settle()
        assert self.times_asked() == asked

    def test_a_login_too_long_to_type_is_written_all_the_same(self):
        long = json.dumps({"token": "t" * 4000}, separators=(",", ":"))
        self.theirs.write_text(long)
        self.pair.settle()
        assert self.kept() == long

    def test_the_login_is_typed_to_security_where_it_can_be(self):
        # Not among its arguments, which every process of the host reads
        self.theirs.write_text('{"token":"mine"}')
        self.pair.settle()
        calls = [json.loads(line) for line in self.asked.read_text().splitlines()]
        assert ["-i", "add-generic-password"] in calls

    def test_a_keychain_at_a_path_not_in_ascii_is_written_all_the_same(self):
        # security is typed to in ASCII, such a path is among its arguments
        elsewhere = self.work / "jos\u00e9" / "login.keychain-db"
        elsewhere.parent.mkdir()
        elsewhere.touch()
        kept = login.Keychain(str(elsewhere), "me")
        assert kept.write(b'{"token":"mine"}')
        assert kept.read().content == b'{"token":"mine"}'
        calls = [json.loads(line) for line in self.asked.read_text().splitlines()]
        assert ["-i", "add-generic-password"] not in calls

    def test_a_login_in_the_hosts_file_is_the_hosts_when_the_keychain_has_none(self):
        # Where Claude Code keeps it when the Keychain refused it
        self.ours.write_text('{"token":"file"}')
        self.pair.settle()
        assert self.theirs.read_text() == '{"token":"file"}'
        self.theirs.write_text('{"token":"renewed"}')
        self.pair.settle()
        assert self.ours.read_text() == '{"token":"renewed"}'
        assert self.kept() is None

    def test_when_both_changed_the_one_written_last_is_kept(self):
        self.keep('{"token":"host"}')
        self.theirs.write_text('{"token":"sandbox"}')
        os.utime(self.theirs, (1, 1))
        self.pair.settle()
        assert self.theirs.read_text() == '{"token":"host"}'

    def test_a_home_without_a_keychain_keeps_its_login_in_the_file(self):
        self.keychain.unlink()
        self.theirs.write_text('{"token":"mine"}')
        login.LoginPair(self.host).settle()
        assert self.ours.read_text() == '{"token":"mine"}'
        assert not self.asked.exists()
